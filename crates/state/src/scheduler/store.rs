use serde_json::json;
use sqlx::{Row, Sqlite, Transaction};

use super::{
  AcceptedDeliveryBaseline, CapabilityProfileSnapshot, CreateScheduledJob,
  DEFAULT_OCCURRENCE_STEPS, DeliveryTargetSnapshot, IdempotencyDecision, MAX_CONTEXT_BYTES,
  MAX_DELIVERY_TARGETS, MAX_SNAPSHOT_BYTES, MaterializationOutcome, PrincipalKey,
  ScheduleMutationIdempotency, ScheduleSpec, ScheduledJob, ScheduledJobDefinition,
  ScheduledJobListPage, ScheduledJobMutation, ScheduledJobStatus, StateError,
  TransactionalMutationOutcome, UpdateAcceptedDeliveryBaseline, UpdateExecutionBaseline,
  UpdateScheduledJob, Value, invalid_json, invalid_occurrence, invalid_value, materialized_run,
  positive_u32, scheduler_error, validate_text,
};
use crate::StateStore;

impl StateStore {
  /// Creates a job, current schedule, resolved targets, and empty execution baseline atomically.
  ///
  /// # Errors
  /// Returns an error when the request is invalid or `SQLite` rejects the transaction.
  pub async fn create_scheduled_job(&self, request: &CreateScheduledJob) -> Result<(), StateError> {
    let next_run_at = validate_create_request(request)?;
    let mut transaction = self.pool.begin().await.map_err(scheduler_error)?;
    insert_scheduled_job(&mut transaction, request, next_run_at).await?;
    transaction.commit().await.map_err(scheduler_error)
  }

  /// Replaces mutable job snapshots and its current schedule using generation CAS.
  ///
  /// Pre-execution work from the prior generation is cancelled in the same transaction. Creator
  /// and owner principal keys remain immutable.
  ///
  /// # Errors
  /// Returns an error for invalid snapshots, stale generation, expired once schedule, or storage
  /// failure.
  pub async fn update_scheduled_job(
    &self,
    request: &UpdateScheduledJob,
  ) -> Result<i64, StateError> {
    validate_update_request(request)?;
    let mut transaction = self.pool.begin().await.map_err(scheduler_error)?;
    apply_update(&mut transaction, request).await?;
    transaction.commit().await.map_err(scheduler_error)?;
    Ok(request.expected_generation + 1)
  }

  /// Applies a typed scheduler mutation and records its exact response in one transaction.
  ///
  /// The operation component of the idempotency scope is derived from the typed mutation. This
  /// method only coordinates durable state; authorization and tool exposure belong to issue 03.
  ///
  /// # Errors
  /// Returns an error when the idempotency contract or mutation is invalid, or when `SQLite`
  /// rejects the transaction. Any error rolls back both the claim and mutation.
  pub async fn apply_idempotent_schedule_mutation(
    &self,
    mutation: &ScheduledJobMutation,
    idempotency: &ScheduleMutationIdempotency,
  ) -> Result<TransactionalMutationOutcome, StateError> {
    validate_mutation_idempotency(mutation, idempotency)?;
    let mut transaction = self.pool.begin().await.map_err(scheduler_error)?;
    let decision = claim_idempotency_in_transaction(
      &mut transaction,
      &idempotency.principal,
      mutation.operation(),
      &idempotency.request_id,
      &idempotency.digest_algorithm,
      &idempotency.request_digest,
      mutation.now(),
    )
    .await?;
    match decision {
      IdempotencyDecision::Claimed => {
        apply_typed_mutation(&mut transaction, mutation).await?;
        complete_idempotency_in_transaction(
          &mut transaction,
          &idempotency.principal,
          mutation.operation(),
          idempotency,
          mutation.now(),
        )
        .await?;
        transaction.commit().await.map_err(scheduler_error)?;
        Ok(TransactionalMutationOutcome::Applied(
          idempotency.response_json.clone(),
        ))
      }
      IdempotencyDecision::Replay(response) => {
        transaction.commit().await.map_err(scheduler_error)?;
        Ok(TransactionalMutationOutcome::Replay(response))
      }
      IdempotencyDecision::InProgress => {
        transaction.commit().await.map_err(scheduler_error)?;
        Ok(TransactionalMutationOutcome::InProgress)
      }
      IdempotencyDecision::Conflict => {
        transaction.commit().await.map_err(scheduler_error)?;
        Ok(TransactionalMutationOutcome::Conflict)
      }
    }
  }

  /// Reads the durable job and current schedule snapshot.
  ///
  /// # Errors
  /// Returns an error when persisted state is invalid or `SQLite` cannot execute the query.
  pub async fn get_scheduled_job(&self, job_id: &str) -> Result<Option<ScheduledJob>, StateError> {
    let row = sqlx::query(
      "select j.job_id, j.definition_version, j.definition_json, j.creator_kind, j.creator_provider, j.creator_tenant, j.creator_subject, j.owner_kind, j.owner_provider, j.owner_tenant, j.owner_subject, j.capability_schema_version, j.capability_digest, j.capability_json, j.status, j.generation, s.schedule_id, s.generation as schedule_generation, s.kind, s.canonical_spec, s.timezone, s.once_at, s.anchor_at, s.interval_seconds, s.next_run_at from scheduled_jobs j join schedules s on s.job_id = j.job_id where j.job_id = ?1",
    )
    .bind(job_id)
    .fetch_optional(&self.pool)
    .await
    .map_err(scheduler_error)?;
    row.map(|row| scheduled_job_from_row(&row)).transpose()
  }

  /// Lists one stable cursor page of jobs owned by the complete principal key and status.
  ///
  /// # Errors
  /// Returns an error for an invalid principal, cursor, limit, or storage failure.
  pub async fn list_scheduled_jobs_by_owner(
    &self,
    owner: &PrincipalKey,
    status: ScheduledJobStatus,
    after_job_id: Option<&str>,
    limit: u32,
  ) -> Result<ScheduledJobListPage, StateError> {
    owner.validate().map_err(invalid_value)?;
    if limit == 0 || limit > 100 {
      return Err(StateError::InvalidSchedulerState {
        reason: "owner list limit must be between 1 and 100".to_owned(),
      });
    }
    if let Some(cursor) = after_job_id {
      validate_text("owner list cursor", cursor).map_err(invalid_value)?;
    }
    let fetch_limit = i64::from(limit) + 1;
    let mut job_ids: Vec<String> = sqlx::query_scalar(
      "select job_id from scheduled_jobs indexed by idx_scheduled_jobs_owner_status where owner_kind = ?1 and owner_provider = ?2 and owner_tenant = ?3 and owner_subject = ?4 and status = ?5 and job_id > coalesce(?6, '') order by job_id limit ?7",
    )
    .bind(owner.kind())
    .bind(owner.provider())
    .bind(owner.tenant())
    .bind(owner.subject())
    .bind(status.as_str())
    .bind(after_job_id)
    .bind(fetch_limit)
    .fetch_all(&self.pool)
    .await
    .map_err(scheduler_error)?;
    let has_more = job_ids.len() > limit as usize;
    if has_more {
      job_ids.pop();
    }
    let next_cursor = has_more.then(|| job_ids.last().cloned()).flatten();
    Ok(ScheduledJobListPage {
      job_ids,
      next_cursor,
    })
  }

  /// Reads the accepted baseline matching the complete delivery identity tuple.
  ///
  /// # Errors
  /// Returns an error for invalid identity fields, versions, or storage failure.
  #[allow(clippy::too_many_arguments)]
  pub async fn get_accepted_delivery_baseline(
    &self,
    job_id: &str,
    target_identity_digest: &str,
    delivery_policy_version: i64,
    render_version: i64,
    hash_algorithm: &str,
  ) -> Result<Option<AcceptedDeliveryBaseline>, StateError> {
    for (field, value) in [
      ("job id", job_id),
      ("target identity digest", target_identity_digest),
      ("delivery hash algorithm", hash_algorithm),
    ] {
      validate_text(field, value).map_err(invalid_value)?;
    }
    if delivery_policy_version <= 0 || render_version <= 0 {
      return Err(StateError::InvalidSchedulerState {
        reason: "delivery baseline identity versions must be positive".to_owned(),
      });
    }
    let row = sqlx::query(
      "select accepted_payload_digest, source_delivery_id, source_run_id, source_result_hash, accepted_at, baseline_version from scheduled_delivery_baselines where job_id = ?1 and target_identity_digest = ?2 and delivery_policy_version = ?3 and render_version = ?4 and hash_algorithm = ?5",
    )
    .bind(job_id)
    .bind(target_identity_digest)
    .bind(delivery_policy_version)
    .bind(render_version)
    .bind(hash_algorithm)
    .fetch_optional(&self.pool)
    .await
    .map_err(scheduler_error)?;
    row
      .map(|row| {
        Ok(AcceptedDeliveryBaseline {
          accepted_payload_digest: row
            .try_get("accepted_payload_digest")
            .map_err(scheduler_error)?,
          source_delivery_id: row.try_get("source_delivery_id").map_err(scheduler_error)?,
          source_run_id: row.try_get("source_run_id").map_err(scheduler_error)?,
          source_result_hash: row.try_get("source_result_hash").map_err(scheduler_error)?,
          accepted_at: row.try_get("accepted_at").map_err(scheduler_error)?,
          baseline_version: row.try_get("baseline_version").map_err(scheduler_error)?,
        })
      })
      .transpose()
  }

  /// Lists active due jobs that are not blocked by overlap-forbid state.
  ///
  /// # Errors
  /// Returns an error when `SQLite` cannot execute the query.
  pub async fn list_due_scheduled_jobs(
    &self,
    now: i64,
    limit: u32,
  ) -> Result<Vec<String>, StateError> {
    sqlx::query_scalar(
      "select s.job_id from schedules s join scheduled_jobs j on j.job_id = s.job_id where j.status = 'active' and s.next_run_at <= ?1 and not exists (select 1 from scheduled_runs r where r.job_id = s.job_id and r.overlap_slot = 1) order by s.next_run_at, s.job_id limit ?2",
    )
    .bind(now)
    .bind(i64::from(limit))
    .fetch_all(&self.pool)
    .await
    .map_err(scheduler_error)
  }

  /// Pauses a matching job generation and cancels pre-execution work.
  ///
  /// # Errors
  /// Returns a generation conflict or storage error.
  pub async fn pause_scheduled_job(
    &self,
    job_id: &str,
    expected_generation: i64,
    now: i64,
  ) -> Result<i64, StateError> {
    self
      .set_job_inactive(job_id, expected_generation, "paused", now)
      .await
  }

  /// Soft-deletes a matching job generation and cancels pre-execution work.
  ///
  /// # Errors
  /// Returns a generation conflict or storage error.
  pub async fn delete_scheduled_job(
    &self,
    job_id: &str,
    expected_generation: i64,
    now: i64,
  ) -> Result<i64, StateError> {
    self
      .set_job_inactive(job_id, expected_generation, "deleted", now)
      .await
  }

  async fn set_job_inactive(
    &self,
    job_id: &str,
    expected_generation: i64,
    status: &'static str,
    now: i64,
  ) -> Result<i64, StateError> {
    let mut transaction = self.pool.begin().await.map_err(scheduler_error)?;
    apply_inactive(&mut transaction, job_id, expected_generation, status, now).await?;
    transaction.commit().await.map_err(scheduler_error)?;
    Ok(expected_generation + 1)
  }

  /// Resumes a paused generation without replaying its paused window.
  ///
  /// # Errors
  /// Returns a generation conflict, expired-once error, occurrence error, or storage error.
  pub async fn resume_scheduled_job(
    &self,
    job_id: &str,
    expected_generation: i64,
    now: i64,
  ) -> Result<i64, StateError> {
    let mut transaction = self.pool.begin().await.map_err(scheduler_error)?;
    apply_resume(&mut transaction, job_id, expected_generation, now).await?;
    transaction.commit().await.map_err(scheduler_error)?;
    Ok(expected_generation + 1)
  }

  /// Atomically materializes one due coalesced occurrence as a pending immutable run snapshot.
  ///
  /// # Errors
  /// Returns an error for invalid persisted state, exhausted occurrence search, generation races,
  /// or storage failures.
  pub async fn materialize_due_schedule(
    &self,
    job_id: &str,
    expected_generation: i64,
    now: i64,
  ) -> Result<MaterializationOutcome, StateError> {
    let mut transaction = self.pool.begin().await.map_err(scheduler_error)?;
    let row = sqlx::query(
      "select j.definition_version, j.definition_json, j.capability_schema_version, j.capability_digest, j.capability_json, j.status, j.generation, s.schedule_id, s.generation as schedule_generation, s.kind, s.canonical_spec, s.timezone, s.once_at, s.anchor_at, s.interval_seconds, s.next_run_at from scheduled_jobs j join schedules s on s.job_id = j.job_id where j.job_id = ?1",
    )
    .bind(job_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(scheduler_error)?;
    let Some(row) = row else {
      return Ok(MaterializationOutcome::NotDue);
    };
    let status: String = row.try_get("status").map_err(scheduler_error)?;
    let generation: i64 = row.try_get("generation").map_err(scheduler_error)?;
    let next_run_at: Option<i64> = row.try_get("next_run_at").map_err(scheduler_error)?;
    if status != "active"
      || generation != expected_generation
      || next_run_at.is_none_or(|due| due > now)
    {
      return Ok(MaterializationOutcome::NotDue);
    }
    let blocked: i64 = sqlx::query_scalar(
      "select exists(select 1 from scheduled_runs where job_id = ?1 and overlap_slot = 1)",
    )
    .bind(job_id)
    .fetch_one(&mut *transaction)
    .await
    .map_err(scheduler_error)?;
    if blocked != 0 {
      return Ok(MaterializationOutcome::Blocked);
    }
    let due = required_due(next_run_at)?;
    let schedule = schedule_from_row(&row)?;
    let window = schedule
      .coalesce(due, now, DEFAULT_OCCURRENCE_STEPS)
      .map_err(invalid_occurrence)?;
    let snapshots = load_materialization_snapshots(&mut transaction, job_id).await?;
    let run_id = format!("scheduled:{job_id}:{}", window.scheduled_for);
    let inserted = sqlx::query(
      "insert into scheduled_runs (run_id, job_id, schedule_id, job_generation, schedule_generation, scheduled_for, coalesced_through, skipped_count, skipped_count_saturated, definition_version, definition_json, capability_schema_version, capability_digest, capability_json, targets_json, execution_baseline_json, state, overlap_slot, created_at, updated_at) values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, 'pending', 1, ?17, ?17) on conflict(job_id, scheduled_for) do nothing",
    )
    .bind(&run_id)
    .bind(job_id)
    .bind(row.try_get::<String, _>("schedule_id").map_err(scheduler_error)?)
    .bind(generation)
    .bind(row.try_get::<i64, _>("schedule_generation").map_err(scheduler_error)?)
    .bind(window.scheduled_for)
    .bind(window.coalesced_through)
    .bind(i64::from(window.skipped_count))
    .bind(i64::from(window.skipped_count_saturated))
    .bind(row.try_get::<i64, _>("definition_version").map_err(scheduler_error)?)
    .bind(row.try_get::<String, _>("definition_json").map_err(scheduler_error)?)
    .bind(row.try_get::<i64, _>("capability_schema_version").map_err(scheduler_error)?)
    .bind(row.try_get::<String, _>("capability_digest").map_err(scheduler_error)?)
    .bind(row.try_get::<String, _>("capability_json").map_err(scheduler_error)?)
    .bind(snapshots.targets_json)
    .bind(snapshots.execution_baseline_json)
    .bind(now)
    .execute(&mut *transaction)
    .await
    .map_err(scheduler_error)?;
    if inserted.rows_affected() == 0 {
      return Ok(MaterializationOutcome::AlreadyMaterialized);
    }
    if window.next_run_at.is_some() {
      let updated = sqlx::query(
        "update schedules set next_run_at = ?1, updated_at = ?2 where job_id = ?3 and next_run_at = ?4 and exists (select 1 from scheduled_jobs where job_id = ?3 and status = 'active' and generation = ?5)",
      )
      .bind(window.next_run_at)
      .bind(now)
      .bind(job_id)
      .bind(window.scheduled_for)
      .bind(generation)
      .execute(&mut *transaction)
      .await
      .map_err(scheduler_error)?;
      if updated.rows_affected() != 1 {
        return Err(StateError::SchedulerGenerationConflict);
      }
    } else {
      sqlx::query("update schedules set next_run_at = null, updated_at = ?1 where job_id = ?2")
        .bind(now)
        .bind(job_id)
        .execute(&mut *transaction)
        .await
        .map_err(scheduler_error)?;
      sqlx::query(
        "update scheduled_jobs set status = 'completed', updated_at = ?1 where job_id = ?2 and generation = ?3 and status = 'active'",
      )
      .bind(now)
      .bind(job_id)
      .bind(generation)
      .execute(&mut *transaction)
      .await
      .map_err(scheduler_error)?;
    }
    transaction.commit().await.map_err(scheduler_error)?;
    Ok(materialized_run(run_id, job_id, window))
  }

  /// Claims a digest-bound idempotency request or returns its stable prior disposition.
  ///
  /// # Errors
  /// Returns an error when `SQLite` cannot persist or read the record, or completed state is corrupt.
  pub async fn claim_schedule_idempotency(
    &self,
    operation: &str,
    idempotency: &ScheduleMutationIdempotency,
    now: i64,
  ) -> Result<IdempotencyDecision, StateError> {
    validate_idempotency_request(
      operation,
      &idempotency.request_id,
      &idempotency.digest_algorithm,
      &idempotency.request_digest,
    )?;
    let scope = canonical_idempotency_scope(&idempotency.principal, operation);
    let inserted = sqlx::query(
      "insert into idempotency_keys (scope, key, status, request_digest, digest_algorithm, created_at, updated_at) values (?1, ?2, 'claimed', ?3, ?4, datetime(?5, 'unixepoch'), datetime(?5, 'unixepoch')) on conflict(scope, key) do nothing",
    )
    .bind(&scope)
    .bind(&idempotency.request_id)
    .bind(&idempotency.request_digest)
    .bind(&idempotency.digest_algorithm)
    .bind(now)
    .execute(&self.pool)
    .await
    .map_err(scheduler_error)?;
    if inserted.rows_affected() == 1 {
      return Ok(IdempotencyDecision::Claimed);
    }
    let row = sqlx::query(
      "select status, request_digest, digest_algorithm, response_json from idempotency_keys where scope = ?1 and key = ?2",
    )
    .bind(&scope)
    .bind(&idempotency.request_id)
    .fetch_one(&self.pool)
    .await
    .map_err(scheduler_error)?;
    let persisted_digest: Option<String> =
      row.try_get("request_digest").map_err(scheduler_error)?;
    let persisted_algorithm: Option<String> =
      row.try_get("digest_algorithm").map_err(scheduler_error)?;
    if persisted_digest.as_deref() != Some(idempotency.request_digest.as_str())
      || persisted_algorithm.as_deref() != Some(idempotency.digest_algorithm.as_str())
    {
      return Ok(IdempotencyDecision::Conflict);
    }
    let status: String = row.try_get("status").map_err(scheduler_error)?;
    if status == "completed" {
      return row
        .try_get::<Option<String>, _>("response_json")
        .map_err(scheduler_error)?
        .map(IdempotencyDecision::Replay)
        .ok_or_else(|| StateError::InvalidSchedulerState {
          reason: "completed idempotency record has no response".to_owned(),
        });
    }
    Ok(IdempotencyDecision::InProgress)
  }

  /// Completes a matching claimed idempotency record with its exact bounded response.
  ///
  /// # Errors
  /// Returns an error when the response is invalid or `SQLite` rejects the update.
  pub async fn complete_schedule_idempotency(
    &self,
    operation: &str,
    idempotency: &ScheduleMutationIdempotency,
    now: i64,
  ) -> Result<bool, StateError> {
    validate_idempotency_request(
      operation,
      &idempotency.request_id,
      &idempotency.digest_algorithm,
      &idempotency.request_digest,
    )?;
    if idempotency.response_json.len() > MAX_SNAPSHOT_BYTES
      || serde_json::from_str::<Value>(&idempotency.response_json).is_err()
    {
      return Err(StateError::InvalidSchedulerState {
        reason: "idempotency response must be bounded valid JSON".to_owned(),
      });
    }
    let scope = canonical_idempotency_scope(&idempotency.principal, operation);
    let result = sqlx::query(
      "update idempotency_keys set status = 'completed', response_json = ?1, response_ref = null, updated_at = datetime(?2, 'unixepoch') where scope = ?3 and key = ?4 and status = 'claimed' and digest_algorithm = ?5 and request_digest = ?6",
    )
    .bind(&idempotency.response_json)
    .bind(now)
    .bind(scope)
    .bind(&idempotency.request_id)
    .bind(&idempotency.digest_algorithm)
    .bind(&idempotency.request_digest)
    .execute(&self.pool)
    .await
    .map_err(scheduler_error)?;
    Ok(result.rows_affected() == 1)
  }

  /// Applies an execution-success baseline CAS primitive for the future run terminal transaction.
  ///
  /// This primitive does not decide whether a run is successful; issue 06 owns that business
  /// transition and must call this only from its terminal transaction boundary.
  ///
  /// # Errors
  /// Returns an error for invalid bounded values or a storage failure.
  pub async fn compare_and_swap_execution_baseline(
    &self,
    update: &UpdateExecutionBaseline,
  ) -> Result<bool, StateError> {
    let mut transaction = self.pool.begin().await.map_err(scheduler_error)?;
    let updated =
      compare_and_swap_execution_baseline_in_transaction(&mut transaction, update).await?;
    transaction.commit().await.map_err(scheduler_error)?;
    Ok(updated)
  }

  /// Applies an accepted-delivery baseline CAS in its own transaction.
  ///
  /// # Errors
  /// Returns an error for invalid bounded identity fields or a storage failure.
  pub async fn compare_and_swap_accepted_delivery_baseline(
    &self,
    update: &UpdateAcceptedDeliveryBaseline,
  ) -> Result<bool, StateError> {
    let mut transaction = self.pool.begin().await.map_err(scheduler_error)?;
    let updated =
      compare_and_swap_accepted_delivery_baseline_in_transaction(&mut transaction, update).await?;
    transaction.commit().await.map_err(scheduler_error)?;
    Ok(updated)
  }
}

pub(crate) async fn compare_and_swap_execution_baseline_in_transaction(
  transaction: &mut Transaction<'_, Sqlite>,
  update: &UpdateExecutionBaseline,
) -> Result<bool, StateError> {
  validate_text("execution hash algorithm", &update.hash_algorithm).map_err(invalid_value)?;
  validate_text("execution result hash", &update.result_hash).map_err(invalid_value)?;
  validate_text("source run id", &update.source_run_id).map_err(invalid_value)?;
  if update.previous_success_context.len() > MAX_CONTEXT_BYTES || update.expected_version < 0 {
    return Err(StateError::InvalidSchedulerState {
      reason: "invalid execution baseline CAS".to_owned(),
    });
  }
  let result = sqlx::query(
      "update scheduled_execution_baselines set baseline_version = baseline_version + 1, hash_algorithm = ?1, result_hash = ?2, previous_success_context = ?3, source_run_id = ?4, completed_at = ?5 where job_id = ?6 and baseline_version = ?7",
    )
    .bind(&update.hash_algorithm)
    .bind(&update.result_hash)
    .bind(&update.previous_success_context)
    .bind(&update.source_run_id)
    .bind(update.completed_at)
    .bind(&update.job_id)
    .bind(update.expected_version)
    .execute(&mut **transaction)
    .await
    .map_err(scheduler_error)?;
  Ok(result.rows_affected() == 1)
}

pub(crate) async fn compare_and_swap_accepted_delivery_baseline_in_transaction(
  transaction: &mut Transaction<'_, Sqlite>,
  update: &UpdateAcceptedDeliveryBaseline,
) -> Result<bool, StateError> {
  validate_accepted_delivery_baseline(update)?;
  let result = sqlx::query(
      "insert into scheduled_delivery_baselines (job_id, target_identity_digest, delivery_policy_version, render_version, hash_algorithm, accepted_payload_digest, source_delivery_id, source_run_id, source_result_hash, accepted_at, baseline_version) select ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 1 where ?11 = 0 on conflict(job_id, target_identity_digest, delivery_policy_version, render_version, hash_algorithm) do update set accepted_payload_digest = excluded.accepted_payload_digest, source_delivery_id = excluded.source_delivery_id, source_run_id = excluded.source_run_id, source_result_hash = excluded.source_result_hash, accepted_at = excluded.accepted_at, baseline_version = scheduled_delivery_baselines.baseline_version + 1 where scheduled_delivery_baselines.baseline_version = ?11",
    )
    .bind(&update.job_id)
    .bind(&update.target_identity_digest)
    .bind(update.delivery_policy_version)
    .bind(update.render_version)
    .bind(&update.hash_algorithm)
    .bind(&update.accepted_payload_digest)
    .bind(&update.source_delivery_id)
    .bind(&update.source_run_id)
    .bind(&update.source_result_hash)
    .bind(update.accepted_at)
    .bind(update.expected_version)
    .execute(&mut **transaction)
    .await
    .map_err(scheduler_error)?;
  Ok(result.rows_affected() == 1)
}

fn scheduled_job_from_row(row: &sqlx::sqlite::SqliteRow) -> Result<ScheduledJob, StateError> {
  let definition_version =
    positive_u32(row.try_get("definition_version").map_err(scheduler_error)?)?;
  let capability_schema_version = positive_u32(
    row
      .try_get("capability_schema_version")
      .map_err(scheduler_error)?,
  )?;
  let definition = ScheduledJobDefinition::new(
    definition_version,
    row
      .try_get::<String, _>("definition_json")
      .map_err(scheduler_error)?,
  )
  .map_err(invalid_value)?;
  let creator = PrincipalKey::new(
    row
      .try_get::<String, _>("creator_kind")
      .map_err(scheduler_error)?,
    row
      .try_get::<String, _>("creator_provider")
      .map_err(scheduler_error)?,
    row
      .try_get::<String, _>("creator_tenant")
      .map_err(scheduler_error)?,
    row
      .try_get::<String, _>("creator_subject")
      .map_err(scheduler_error)?,
  )
  .map_err(invalid_value)?;
  let owner = PrincipalKey::new(
    row
      .try_get::<String, _>("owner_kind")
      .map_err(scheduler_error)?,
    row
      .try_get::<String, _>("owner_provider")
      .map_err(scheduler_error)?,
    row
      .try_get::<String, _>("owner_tenant")
      .map_err(scheduler_error)?,
    row
      .try_get::<String, _>("owner_subject")
      .map_err(scheduler_error)?,
  )
  .map_err(invalid_value)?;
  let capability = CapabilityProfileSnapshot::new(
    capability_schema_version,
    row
      .try_get::<String, _>("capability_digest")
      .map_err(scheduler_error)?,
    row
      .try_get::<String, _>("capability_json")
      .map_err(scheduler_error)?,
  )
  .map_err(invalid_value)?;
  Ok(ScheduledJob {
    job_id: row.try_get("job_id").map_err(scheduler_error)?,
    definition,
    creator,
    owner,
    capability,
    status: ScheduledJobStatus::parse(
      &row
        .try_get::<String, _>("status")
        .map_err(scheduler_error)?,
    )?,
    generation: row.try_get("generation").map_err(scheduler_error)?,
    schedule_id: row.try_get("schedule_id").map_err(scheduler_error)?,
    schedule_generation: row
      .try_get("schedule_generation")
      .map_err(scheduler_error)?,
    schedule: schedule_from_row(row)?,
    next_run_at: row.try_get("next_run_at").map_err(scheduler_error)?,
  })
}

fn schedule_from_row(row: &sqlx::sqlite::SqliteRow) -> Result<ScheduleSpec, StateError> {
  let canonical_spec: String = row.try_get("canonical_spec").map_err(scheduler_error)?;
  let timezone: Option<String> = row.try_get("timezone").map_err(scheduler_error)?;
  ScheduleSpec::from_storage(
    &row.try_get::<String, _>("kind").map_err(scheduler_error)?,
    &canonical_spec,
    timezone.as_deref(),
    row.try_get("once_at").map_err(scheduler_error)?,
    row.try_get("anchor_at").map_err(scheduler_error)?,
    row.try_get("interval_seconds").map_err(scheduler_error)?,
  )
}

struct MaterializationSnapshots {
  targets_json: String,
  execution_baseline_json: String,
}

async fn load_materialization_snapshots(
  transaction: &mut Transaction<'_, Sqlite>,
  job_id: &str,
) -> Result<MaterializationSnapshots, StateError> {
  let target_rows = sqlx::query(
    "select provider, connector, tenant, kind, address_json, resolver_version, resolver_digest, identity_digest from scheduled_job_delivery_targets where job_id = ?1 order by ordinal",
  )
  .bind(job_id)
  .fetch_all(&mut **transaction)
  .await
  .map_err(scheduler_error)?;
  let targets: Vec<Value> = target_rows
    .iter()
    .map(target_snapshot_json)
    .collect::<Result<_, StateError>>()?;
  validate_serialized_targets(&targets)?;
  let baseline = sqlx::query(
    "select baseline_version, hash_algorithm, result_hash, previous_success_context, source_run_id, completed_at from scheduled_execution_baselines where job_id = ?1",
  )
  .bind(job_id)
  .fetch_one(&mut **transaction)
  .await
  .map_err(scheduler_error)?;
  let baseline = json!({
    "baseline_version": baseline.try_get::<i64, _>("baseline_version").map_err(scheduler_error)?,
    "hash_algorithm": baseline.try_get::<Option<String>, _>("hash_algorithm").map_err(scheduler_error)?,
    "result_hash": baseline.try_get::<Option<String>, _>("result_hash").map_err(scheduler_error)?,
    "previous_success_context": baseline.try_get::<Option<String>, _>("previous_success_context").map_err(scheduler_error)?,
    "source_run_id": baseline.try_get::<Option<String>, _>("source_run_id").map_err(scheduler_error)?,
    "completed_at": baseline.try_get::<Option<i64>, _>("completed_at").map_err(scheduler_error)?,
  });
  Ok(MaterializationSnapshots {
    targets_json: serialize_targets(&targets)?,
    execution_baseline_json: baseline.to_string(),
  })
}

async fn replace_delivery_targets(
  transaction: &mut Transaction<'_, Sqlite>,
  job_id: &str,
  targets: &[DeliveryTargetSnapshot],
) -> Result<(), StateError> {
  sqlx::query("delete from scheduled_job_delivery_targets where job_id = ?1")
    .bind(job_id)
    .execute(&mut **transaction)
    .await
    .map_err(scheduler_error)?;
  for (ordinal, target) in targets.iter().enumerate() {
    let ordinal = i64::try_from(ordinal).map_err(|_| StateError::InvalidSchedulerState {
      reason: "too many delivery targets".to_owned(),
    })?;
    sqlx::query(
      "insert into scheduled_job_delivery_targets (target_id, job_id, ordinal, provider, connector, tenant, kind, address_json, resolver_version, resolver_digest, identity_digest) values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
    )
    .bind(&target.target_id)
    .bind(job_id)
    .bind(ordinal)
    .bind(&target.provider)
    .bind(&target.connector)
    .bind(&target.tenant)
    .bind(&target.kind)
    .bind(&target.address_json)
    .bind(i64::from(target.resolver_version))
    .bind(&target.resolver_digest)
    .bind(&target.identity_digest)
    .execute(&mut **transaction)
    .await
    .map_err(scheduler_error)?;
  }
  Ok(())
}

fn validate_create_request(request: &CreateScheduledJob) -> Result<i64, StateError> {
  validate_text("job id", &request.job_id).map_err(invalid_value)?;
  validate_text("schedule id", &request.schedule_id).map_err(invalid_value)?;
  request.creator.validate().map_err(invalid_value)?;
  request.owner.validate().map_err(invalid_value)?;
  request.definition.validate().map_err(invalid_value)?;
  request.capability.validate().map_err(invalid_value)?;
  request
    .schedule
    .validate_for_create(request.now)
    .map_err(invalid_value)?;
  validate_delivery_targets(&request.targets)?;
  request
    .schedule
    .first_after_create(request.now)
    .map_err(invalid_occurrence)
}

async fn insert_scheduled_job(
  transaction: &mut Transaction<'_, Sqlite>,
  request: &CreateScheduledJob,
  next_run_at: i64,
) -> Result<(), StateError> {
  sqlx::query(
    "insert into scheduled_jobs (job_id, definition_version, definition_json, creator_kind, creator_provider, creator_tenant, creator_subject, owner_kind, owner_provider, owner_tenant, owner_subject, status, generation, capability_schema_version, capability_digest, capability_json, created_at, updated_at) values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 'active', 0, ?12, ?13, ?14, ?15, ?15)",
  )
  .bind(&request.job_id)
  .bind(i64::from(request.definition.version))
  .bind(&request.definition.canonical_json)
  .bind(&request.creator.kind)
  .bind(&request.creator.provider)
  .bind(&request.creator.tenant)
  .bind(&request.creator.subject)
  .bind(&request.owner.kind)
  .bind(&request.owner.provider)
  .bind(&request.owner.tenant)
  .bind(&request.owner.subject)
  .bind(i64::from(request.capability.schema_version))
  .bind(&request.capability.digest)
  .bind(&request.capability.canonical_json)
  .bind(request.now)
  .execute(&mut **transaction)
  .await
  .map_err(scheduler_error)?;
  let (kind, canonical_spec, timezone, once_at, anchor_at, interval_seconds) =
    request.schedule.storage_parts();
  sqlx::query(
    "insert into schedules (schedule_id, job_id, kind, canonical_spec, timezone, once_at, anchor_at, interval_seconds, next_run_at, created_at, updated_at) values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10)",
  )
  .bind(&request.schedule_id)
  .bind(&request.job_id)
  .bind(kind)
  .bind(canonical_spec)
  .bind(timezone)
  .bind(once_at)
  .bind(anchor_at)
  .bind(interval_seconds)
  .bind(next_run_at)
  .bind(request.now)
  .execute(&mut **transaction)
  .await
  .map_err(scheduler_error)?;
  replace_delivery_targets(transaction, &request.job_id, &request.targets).await?;
  sqlx::query("insert into scheduled_execution_baselines (job_id) values (?1)")
    .bind(&request.job_id)
    .execute(&mut **transaction)
    .await
    .map(|_| ())
    .map_err(scheduler_error)
}

async fn apply_update(
  transaction: &mut Transaction<'_, Sqlite>,
  request: &UpdateScheduledJob,
) -> Result<(), StateError> {
  let status: Option<String> = sqlx::query_scalar(
    "select status from scheduled_jobs where job_id = ?1 and generation = ?2 and status in ('active', 'paused')",
  )
  .bind(&request.job_id)
  .bind(request.expected_generation)
  .fetch_optional(&mut **transaction)
  .await
  .map_err(scheduler_error)?;
  let status = status.ok_or(StateError::SchedulerGenerationConflict)?;
  let next_run_at = if status == "active" {
    Some(
      request
        .schedule
        .first_after_create(request.now)
        .map_err(invalid_occurrence)?,
    )
  } else {
    None
  };
  let updated = sqlx::query(
    "update scheduled_jobs set definition_version = ?1, definition_json = ?2, capability_schema_version = ?3, capability_digest = ?4, capability_json = ?5, generation = generation + 1, updated_at = ?6 where job_id = ?7 and generation = ?8 and status = ?9",
  )
  .bind(i64::from(request.definition.version))
  .bind(&request.definition.canonical_json)
  .bind(i64::from(request.capability.schema_version))
  .bind(&request.capability.digest)
  .bind(&request.capability.canonical_json)
  .bind(request.now)
  .bind(&request.job_id)
  .bind(request.expected_generation)
  .bind(&status)
  .execute(&mut **transaction)
  .await
  .map_err(scheduler_error)?;
  if updated.rows_affected() != 1 {
    return Err(StateError::SchedulerGenerationConflict);
  }
  cancel_pre_execution_runs(
    transaction,
    &request.job_id,
    request.expected_generation,
    request.now,
  )
  .await?;
  let (kind, canonical_spec, timezone, once_at, anchor_at, interval_seconds) =
    request.schedule.storage_parts();
  sqlx::query(
    "update schedules set kind = ?1, canonical_spec = ?2, timezone = ?3, once_at = ?4, anchor_at = ?5, interval_seconds = ?6, next_run_at = ?7, generation = generation + 1, updated_at = ?8 where job_id = ?9",
  )
  .bind(kind)
  .bind(canonical_spec)
  .bind(timezone)
  .bind(once_at)
  .bind(anchor_at)
  .bind(interval_seconds)
  .bind(next_run_at)
  .bind(request.now)
  .bind(&request.job_id)
  .execute(&mut **transaction)
  .await
  .map_err(scheduler_error)?;
  replace_delivery_targets(transaction, &request.job_id, &request.targets).await
}

async fn apply_inactive(
  transaction: &mut Transaction<'_, Sqlite>,
  job_id: &str,
  expected_generation: i64,
  status: &'static str,
  now: i64,
) -> Result<(), StateError> {
  let deleted_at = (status == "deleted").then_some(now);
  let updated = sqlx::query(
    "update scheduled_jobs set status = ?1, generation = generation + 1, updated_at = ?2, deleted_at = ?3 where job_id = ?4 and generation = ?5 and (status in ('active', 'paused') or (?1 = 'deleted' and status = 'completed'))",
  )
  .bind(status)
  .bind(now)
  .bind(deleted_at)
  .bind(job_id)
  .bind(expected_generation)
  .execute(&mut **transaction)
  .await
  .map_err(scheduler_error)?;
  if updated.rows_affected() != 1 {
    return Err(StateError::SchedulerGenerationConflict);
  }
  cancel_pre_execution_runs(transaction, job_id, expected_generation, now).await?;
  sqlx::query("update schedules set generation = generation + 1, updated_at = ?1 where job_id = ?2")
    .bind(now)
    .bind(job_id)
    .execute(&mut **transaction)
    .await
    .map(|_| ())
    .map_err(scheduler_error)
}

async fn apply_resume(
  transaction: &mut Transaction<'_, Sqlite>,
  job_id: &str,
  expected_generation: i64,
  now: i64,
) -> Result<(), StateError> {
  let row = sqlx::query(
    "select s.kind, s.canonical_spec, s.timezone, s.once_at, s.anchor_at, s.interval_seconds from schedules s join scheduled_jobs j on j.job_id = s.job_id where j.job_id = ?1 and j.status = 'paused' and j.generation = ?2",
  )
  .bind(job_id)
  .bind(expected_generation)
  .fetch_optional(&mut **transaction)
  .await
  .map_err(scheduler_error)?
  .ok_or(StateError::SchedulerGenerationConflict)?;
  let schedule = schedule_from_row(&row)?;
  let next_run_at = schedule.next_after(now).map_err(|error| {
    if matches!(schedule, ScheduleSpec::Once { .. }) {
      StateError::ScheduledOnceExpired
    } else {
      invalid_occurrence(error)
    }
  })?;
  sqlx::query(
    "update scheduled_jobs set status = 'active', generation = generation + 1, updated_at = ?1 where job_id = ?2 and generation = ?3 and status = 'paused'",
  )
  .bind(now)
  .bind(job_id)
  .bind(expected_generation)
  .execute(&mut **transaction)
  .await
  .map_err(scheduler_error)?;
  sqlx::query("update schedules set next_run_at = ?1, generation = generation + 1, updated_at = ?2 where job_id = ?3")
    .bind(next_run_at)
    .bind(now)
    .bind(job_id)
    .execute(&mut **transaction)
    .await
    .map(|_| ())
    .map_err(scheduler_error)
}

async fn apply_typed_mutation(
  transaction: &mut Transaction<'_, Sqlite>,
  mutation: &ScheduledJobMutation,
) -> Result<(), StateError> {
  match mutation {
    ScheduledJobMutation::Create(request) => {
      let next_run_at = validate_create_request(request)?;
      insert_scheduled_job(transaction, request, next_run_at).await
    }
    ScheduledJobMutation::Update(request) => {
      validate_update_request(request)?;
      apply_update(transaction, request).await
    }
    ScheduledJobMutation::Pause {
      job_id,
      expected_generation,
      now,
    } => {
      validate_lifecycle_mutation(job_id, *expected_generation)?;
      apply_inactive(transaction, job_id, *expected_generation, "paused", *now).await
    }
    ScheduledJobMutation::Resume {
      job_id,
      expected_generation,
      now,
    } => {
      validate_lifecycle_mutation(job_id, *expected_generation)?;
      apply_resume(transaction, job_id, *expected_generation, *now).await
    }
    ScheduledJobMutation::Delete {
      job_id,
      expected_generation,
      now,
    } => {
      validate_lifecycle_mutation(job_id, *expected_generation)?;
      apply_inactive(transaction, job_id, *expected_generation, "deleted", *now).await
    }
  }
}

fn validate_lifecycle_mutation(job_id: &str, expected_generation: i64) -> Result<(), StateError> {
  validate_text("job id", job_id).map_err(invalid_value)?;
  if expected_generation < 0 {
    return Err(StateError::InvalidSchedulerState {
      reason: "expected generation must not be negative".to_owned(),
    });
  }
  Ok(())
}

fn validate_mutation_idempotency(
  mutation: &ScheduledJobMutation,
  idempotency: &ScheduleMutationIdempotency,
) -> Result<(), StateError> {
  validate_idempotency_request(
    mutation.operation(),
    &idempotency.request_id,
    &idempotency.digest_algorithm,
    &idempotency.request_digest,
  )?;
  if idempotency.response_json.len() > MAX_SNAPSHOT_BYTES
    || serde_json::from_str::<Value>(&idempotency.response_json).is_err()
  {
    return Err(StateError::InvalidSchedulerState {
      reason: "idempotency response must be bounded valid JSON".to_owned(),
    });
  }
  Ok(())
}

async fn claim_idempotency_in_transaction(
  transaction: &mut Transaction<'_, Sqlite>,
  principal: &PrincipalKey,
  operation: &str,
  request_id: &str,
  digest_algorithm: &str,
  request_digest: &str,
  now: i64,
) -> Result<IdempotencyDecision, StateError> {
  let scope = canonical_idempotency_scope(principal, operation);
  let inserted = sqlx::query(
    "insert into idempotency_keys (scope, key, status, request_digest, digest_algorithm, created_at, updated_at) values (?1, ?2, 'claimed', ?3, ?4, datetime(?5, 'unixepoch'), datetime(?5, 'unixepoch')) on conflict(scope, key) do nothing",
  )
  .bind(&scope)
  .bind(request_id)
  .bind(request_digest)
  .bind(digest_algorithm)
  .bind(now)
  .execute(&mut **transaction)
  .await
  .map_err(scheduler_error)?;
  if inserted.rows_affected() == 1 {
    return Ok(IdempotencyDecision::Claimed);
  }
  read_idempotency_decision(
    transaction,
    &scope,
    request_id,
    digest_algorithm,
    request_digest,
  )
  .await
}

async fn read_idempotency_decision(
  transaction: &mut Transaction<'_, Sqlite>,
  scope: &str,
  request_id: &str,
  digest_algorithm: &str,
  request_digest: &str,
) -> Result<IdempotencyDecision, StateError> {
  let row = sqlx::query(
    "select status, request_digest, digest_algorithm, response_json from idempotency_keys where scope = ?1 and key = ?2",
  )
  .bind(scope)
  .bind(request_id)
  .fetch_one(&mut **transaction)
  .await
  .map_err(scheduler_error)?;
  let persisted_digest: Option<String> = row.try_get("request_digest").map_err(scheduler_error)?;
  let persisted_algorithm: Option<String> =
    row.try_get("digest_algorithm").map_err(scheduler_error)?;
  if persisted_digest.as_deref() != Some(request_digest)
    || persisted_algorithm.as_deref() != Some(digest_algorithm)
  {
    return Ok(IdempotencyDecision::Conflict);
  }
  if row
    .try_get::<String, _>("status")
    .map_err(scheduler_error)?
    != "completed"
  {
    return Ok(IdempotencyDecision::InProgress);
  }
  row
    .try_get::<Option<String>, _>("response_json")
    .map_err(scheduler_error)?
    .map(IdempotencyDecision::Replay)
    .ok_or_else(|| StateError::InvalidSchedulerState {
      reason: "completed idempotency record has no response".to_owned(),
    })
}

async fn complete_idempotency_in_transaction(
  transaction: &mut Transaction<'_, Sqlite>,
  principal: &PrincipalKey,
  operation: &str,
  idempotency: &ScheduleMutationIdempotency,
  now: i64,
) -> Result<(), StateError> {
  let scope = canonical_idempotency_scope(principal, operation);
  let result = sqlx::query(
    "update idempotency_keys set status = 'completed', response_json = ?1, response_ref = null, updated_at = datetime(?2, 'unixepoch') where scope = ?3 and key = ?4 and status = 'claimed' and digest_algorithm = ?5 and request_digest = ?6",
  )
  .bind(&idempotency.response_json)
  .bind(now)
  .bind(scope)
  .bind(&idempotency.request_id)
  .bind(&idempotency.digest_algorithm)
  .bind(&idempotency.request_digest)
  .execute(&mut **transaction)
  .await
  .map_err(scheduler_error)?;
  if result.rows_affected() != 1 {
    return Err(StateError::InvalidSchedulerState {
      reason: "idempotency claim changed before completion".to_owned(),
    });
  }
  Ok(())
}

async fn cancel_pre_execution_runs(
  transaction: &mut Transaction<'_, Sqlite>,
  job_id: &str,
  generation: i64,
  now: i64,
) -> Result<(), StateError> {
  sqlx::query(
    "update scheduled_runs set state = 'cancelled', overlap_slot = null, lease_owner = null, lease_expires_at = null, updated_at = ?1 where job_id = ?2 and job_generation = ?3 and state in ('pending', 'leased')",
  )
  .bind(now)
  .bind(job_id)
  .bind(generation)
  .execute(&mut **transaction)
  .await
  .map(|_| ())
  .map_err(scheduler_error)
}

fn validate_update_request(request: &UpdateScheduledJob) -> Result<(), StateError> {
  validate_text("job id", &request.job_id).map_err(invalid_value)?;
  request
    .schedule
    .validate_for_create(request.now)
    .map_err(invalid_value)?;
  request.definition.validate().map_err(invalid_value)?;
  request.capability.validate().map_err(invalid_value)?;
  if request.expected_generation < 0 {
    return Err(StateError::InvalidSchedulerState {
      reason: "invalid update generation".to_owned(),
    });
  }
  validate_delivery_targets(&request.targets)
}

fn validate_delivery_targets(targets: &[DeliveryTargetSnapshot]) -> Result<(), StateError> {
  if targets.is_empty() || targets.len() > MAX_DELIVERY_TARGETS {
    return Err(StateError::InvalidSchedulerState {
      reason: format!("resolved delivery targets must contain 1..={MAX_DELIVERY_TARGETS} entries"),
    });
  }
  let values = targets
    .iter()
    .map(|target| {
      target.validate().map_err(invalid_value)?;
      Ok(json!({
        "provider": target.provider,
        "connector": target.connector,
        "tenant": target.tenant,
        "kind": target.kind,
        "address": serde_json::from_str::<Value>(&target.address_json).map_err(invalid_json)?,
        "resolver_version": target.resolver_version,
        "resolver_digest": target.resolver_digest,
        "identity_digest": target.identity_digest,
      }))
    })
    .collect::<Result<Vec<_>, StateError>>()?;
  validate_serialized_targets(&values)
}

fn validate_serialized_targets(targets: &[Value]) -> Result<(), StateError> {
  if targets.is_empty() || targets.len() > MAX_DELIVERY_TARGETS {
    return Err(StateError::InvalidSchedulerState {
      reason: format!("resolved delivery targets must contain 1..={MAX_DELIVERY_TARGETS} entries"),
    });
  }
  serialize_targets(targets).map(|_| ())
}

fn serialize_targets(targets: &[Value]) -> Result<String, StateError> {
  let serialized = serde_json::to_string(targets).map_err(invalid_json)?;
  if serialized.len() > MAX_SNAPSHOT_BYTES {
    return Err(StateError::InvalidSchedulerState {
      reason: "serialized delivery targets exceed the durable snapshot bound".to_owned(),
    });
  }
  Ok(serialized)
}

fn validate_accepted_delivery_baseline(
  update: &UpdateAcceptedDeliveryBaseline,
) -> Result<(), StateError> {
  for (field, value) in [
    ("job id", update.job_id.as_str()),
    (
      "target identity digest",
      update.target_identity_digest.as_str(),
    ),
    ("delivery hash algorithm", update.hash_algorithm.as_str()),
    (
      "accepted payload digest",
      update.accepted_payload_digest.as_str(),
    ),
    ("source delivery id", update.source_delivery_id.as_str()),
    ("source run id", update.source_run_id.as_str()),
    ("source result hash", update.source_result_hash.as_str()),
  ] {
    validate_text(field, value).map_err(invalid_value)?;
  }
  if update.delivery_policy_version <= 0
    || update.render_version <= 0
    || update.expected_version < 0
  {
    return Err(StateError::InvalidSchedulerState {
      reason: "invalid accepted delivery baseline versions".to_owned(),
    });
  }
  Ok(())
}

fn validate_idempotency_request(
  operation: &str,
  request_id: &str,
  digest_algorithm: &str,
  request_digest: &str,
) -> Result<(), StateError> {
  for (field, value) in [
    ("schedule operation", operation),
    ("schedule request id", request_id),
    ("request digest algorithm", digest_algorithm),
    ("request digest", request_digest),
  ] {
    validate_text(field, value).map_err(invalid_value)?;
  }
  Ok(())
}

fn canonical_idempotency_scope(principal: &PrincipalKey, operation: &str) -> String {
  json!({
    "kind": principal.kind,
    "operation": operation,
    "provider": principal.provider,
    "subject": principal.subject,
    "tenant": principal.tenant,
  })
  .to_string()
}

fn target_snapshot_json(target: &sqlx::sqlite::SqliteRow) -> Result<Value, StateError> {
  let address_json: String = target.try_get("address_json").map_err(scheduler_error)?;
  Ok(json!({
    "provider": target.try_get::<String, _>("provider").map_err(scheduler_error)?,
    "connector": target.try_get::<String, _>("connector").map_err(scheduler_error)?,
    "tenant": target.try_get::<String, _>("tenant").map_err(scheduler_error)?,
    "kind": target.try_get::<String, _>("kind").map_err(scheduler_error)?,
    "address": serde_json::from_str::<Value>(&address_json).map_err(invalid_json)?,
    "resolver_version": target.try_get::<i64, _>("resolver_version").map_err(scheduler_error)?,
    "resolver_digest": target.try_get::<String, _>("resolver_digest").map_err(scheduler_error)?,
    "identity_digest": target.try_get::<String, _>("identity_digest").map_err(scheduler_error)?,
  }))
}

fn required_due(next_run_at: Option<i64>) -> Result<i64, StateError> {
  next_run_at.ok_or_else(|| StateError::InvalidSchedulerState {
    reason: "due schedule has no next occurrence".to_owned(),
  })
}

#[cfg(test)]
mod tests {
  use tempfile::tempdir;

  use super::{
    CapabilityProfileSnapshot, CreateScheduledJob, DeliveryTargetSnapshot, MaterializationOutcome,
    PrincipalKey, ScheduleSpec, ScheduledJobDefinition, StateError, StateStore,
    UpdateAcceptedDeliveryBaseline, UpdateExecutionBaseline,
    compare_and_swap_accepted_delivery_baseline_in_transaction,
    compare_and_swap_execution_baseline_in_transaction,
  };

  #[tokio::test]
  async fn test_scheduler_busy_error_is_classified_as_transient() {
    let temp = tempdir().expect("create tempdir");
    let state_dir = temp.path().join("state");
    let store = StateStore::initialize(&state_dir, None)
      .await
      .expect("initialize store");
    store
      .set_storage_contention_timeout_for_tests(0)
      .await
      .expect("disable busy wait");
    let lock = store
      .acquire_exclusive_storage_lock_for_tests()
      .await
      .expect("acquire lock");
    let request = CreateScheduledJob {
      job_id: "busy".to_owned(),
      schedule_id: "schedule-busy".to_owned(),
      definition: ScheduledJobDefinition::new(1, "{}").expect("definition"),
      creator: PrincipalKey::new("user", "test", "tenant", "creator").expect("creator"),
      owner: PrincipalKey::new("user", "test", "tenant", "owner").expect("owner"),
      capability: CapabilityProfileSnapshot::new(1, "profile", "{}").expect("profile"),
      targets: vec![
        DeliveryTargetSnapshot::new(
          "none", "none", "none", "none", "none", "{}", 1, "resolver", "identity",
        )
        .expect("target"),
      ],
      schedule: ScheduleSpec::once(2),
      now: 1,
    };
    let error = store
      .create_scheduled_job(&request)
      .await
      .expect_err("scheduler write should be busy");
    assert!(matches!(error, StateError::Scheduler { .. }));
    assert!(error.is_transient_storage_contention());
    lock.release().await.expect("release lock");
  }

  #[tokio::test]
  #[allow(clippy::too_many_lines)]
  async fn test_terminal_state_and_baseline_cas_share_commit_and_rollback_boundaries() {
    let temp = tempdir().expect("create tempdir");
    let state_dir = temp.path().join("state");
    let store = StateStore::initialize(&state_dir, None)
      .await
      .expect("initialize store");
    let request = CreateScheduledJob {
      job_id: "terminal-transaction".to_owned(),
      schedule_id: "schedule-terminal-transaction".to_owned(),
      definition: ScheduledJobDefinition::new(1, "{}").expect("definition"),
      creator: PrincipalKey::new("user", "test", "tenant", "creator").expect("creator"),
      owner: PrincipalKey::new("user", "test", "tenant", "owner").expect("owner"),
      capability: CapabilityProfileSnapshot::new(1, "profile", "{}").expect("profile"),
      targets: vec![
        DeliveryTargetSnapshot::new(
          "none", "none", "none", "none", "none", "{}", 1, "resolver", "identity",
        )
        .expect("target"),
      ],
      schedule: ScheduleSpec::once(2),
      now: 1,
    };
    store
      .create_scheduled_job(&request)
      .await
      .expect("create job");
    let MaterializationOutcome::Created(run) = store
      .materialize_due_schedule("terminal-transaction", 0, 2)
      .await
      .expect("materialize")
    else {
      panic!("expected materialized run");
    };
    let execution = UpdateExecutionBaseline {
      job_id: "terminal-transaction".to_owned(),
      expected_version: 0,
      hash_algorithm: "sha256-v1".to_owned(),
      result_hash: "result".to_owned(),
      previous_success_context: "context".to_owned(),
      source_run_id: run.run_id.clone(),
      completed_at: 3,
    };

    let mut transaction = store
      .pool
      .begin()
      .await
      .expect("begin rollback transaction");
    sqlx::query("update scheduled_runs set state = 'succeeded', overlap_slot = null, result_hash_algorithm = 'sha256-v1', result_hash = 'result' where run_id = ?1")
      .bind(&run.run_id)
      .execute(&mut *transaction)
      .await
      .expect("set terminal state");
    assert!(
      compare_and_swap_execution_baseline_in_transaction(&mut transaction, &execution)
        .await
        .expect("execution CAS")
    );
    transaction.rollback().await.expect("rollback");
    let rolled_back: (String, i64) = sqlx::query_as(
      "select state, (select baseline_version from scheduled_execution_baselines where job_id = 'terminal-transaction') from scheduled_runs where run_id = ?1",
    )
    .bind(&run.run_id)
    .fetch_one(&store.pool)
    .await
    .expect("read rolled back state");
    assert_eq!(rolled_back, ("pending".to_owned(), 0));

    let mut transaction = store.pool.begin().await.expect("begin commit transaction");
    sqlx::query("update scheduled_runs set state = 'succeeded', overlap_slot = null, result_hash_algorithm = 'sha256-v1', result_hash = 'result' where run_id = ?1")
      .bind(&run.run_id)
      .execute(&mut *transaction)
      .await
      .expect("set terminal state");
    assert!(
      compare_and_swap_execution_baseline_in_transaction(&mut transaction, &execution)
        .await
        .expect("execution CAS")
    );
    transaction.commit().await.expect("commit");
    let committed: (String, i64) = sqlx::query_as(
      "select state, (select baseline_version from scheduled_execution_baselines where job_id = 'terminal-transaction') from scheduled_runs where run_id = ?1",
    )
    .bind(&run.run_id)
    .fetch_one(&store.pool)
    .await
    .expect("read committed state");
    assert_eq!(committed, ("succeeded".to_owned(), 1));

    let accepted = UpdateAcceptedDeliveryBaseline {
      job_id: "terminal-transaction".to_owned(),
      target_identity_digest: "identity".to_owned(),
      delivery_policy_version: 1,
      render_version: 1,
      hash_algorithm: "sha256-v1".to_owned(),
      accepted_payload_digest: "payload".to_owned(),
      source_delivery_id: "delivery-transaction".to_owned(),
      source_run_id: run.run_id.clone(),
      source_result_hash: "result".to_owned(),
      accepted_at: 4,
      expected_version: 0,
    };
    let mut transaction = store.pool.begin().await.expect("begin delivery rollback");
    sqlx::query("insert into scheduled_run_deliveries (delivery_id, run_id, job_id, target_identity_digest, target_json, state, delivery_policy_version, render_version, hash_algorithm, payload_digest, expected_baseline_version, created_at, updated_at) values (?1, ?2, 'terminal-transaction', 'identity', '{}', 'delivered', 1, 1, 'sha256-v1', 'payload', 0, 4, 4)")
      .bind(&accepted.source_delivery_id)
      .bind(&run.run_id)
      .execute(&mut *transaction)
      .await
      .expect("insert delivery");
    assert!(
      compare_and_swap_accepted_delivery_baseline_in_transaction(&mut transaction, &accepted)
        .await
        .expect("accepted CAS")
    );
    transaction.rollback().await.expect("rollback delivery");
    let rolled_back: (i64, i64) = sqlx::query_as(
      "select (select count(*) from scheduled_run_deliveries where delivery_id = 'delivery-transaction'), (select count(*) from scheduled_delivery_baselines where job_id = 'terminal-transaction')",
    )
    .fetch_one(&store.pool)
    .await
    .expect("read delivery rollback");
    assert_eq!(rolled_back, (0, 0));

    let mut transaction = store.pool.begin().await.expect("begin delivery commit");
    sqlx::query("insert into scheduled_run_deliveries (delivery_id, run_id, job_id, target_identity_digest, target_json, state, delivery_policy_version, render_version, hash_algorithm, payload_digest, expected_baseline_version, created_at, updated_at) values (?1, ?2, 'terminal-transaction', 'identity', '{}', 'delivered', 1, 1, 'sha256-v1', 'payload', 0, 4, 4)")
      .bind(&accepted.source_delivery_id)
      .bind(&run.run_id)
      .execute(&mut *transaction)
      .await
      .expect("insert delivery");
    assert!(
      compare_and_swap_accepted_delivery_baseline_in_transaction(&mut transaction, &accepted)
        .await
        .expect("accepted CAS")
    );
    transaction.commit().await.expect("commit delivery");
    let committed: (i64, i64) = sqlx::query_as(
      "select (select count(*) from scheduled_run_deliveries where delivery_id = 'delivery-transaction'), (select baseline_version from scheduled_delivery_baselines where job_id = 'terminal-transaction')",
    )
    .fetch_one(&store.pool)
    .await
    .expect("read committed delivery");
    assert_eq!(committed, (1, 1));
  }
}
