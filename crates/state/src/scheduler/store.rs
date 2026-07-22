use std::fmt::Write as _;
use std::str::FromStr;

use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::sqlite::SqliteRow;
use sqlx::{Row, Sqlite, Transaction};

use super::{
  AcceptedDeliveryBaseline, AcceptedDeliveryBaselineIdentity, AttestedExecutionProfileSnapshot,
  CapabilityProfileSnapshot, ClaimedScheduledDelivery, ClaimedScheduledRun, CreateScheduledJob,
  DEFAULT_OCCURRENCE_STEPS, DELIVERY_PAYLOAD_HASH_ALGORITHM, DELIVERY_PAYLOAD_SCHEMA_VERSION,
  DeliveryPayloadSnapshot, DeliveryTargetSnapshot, ExpiredRunReclaimOutcome, IdempotencyDecision,
  LateEvidenceAppendOutcome, MAX_CONTEXT_BYTES, MAX_DELIVERY_TARGETS, MAX_SNAPSHOT_BYTES,
  MaterializationOutcome, PreflightFailureDisposition, PreparedScheduledDelivery, PrincipalKey,
  RunLeaseBinding, ScheduleAuditSummary, ScheduleMutationAudit, ScheduleMutationIdempotency,
  ScheduleSpec, ScheduledDeliveryAuthority, ScheduledDeliveryBinding, ScheduledDeliveryFailure,
  ScheduledDeliveryRenderInput, ScheduledDeliveryRetentionReport, ScheduledDeliveryState,
  ScheduledDeliveryWork, ScheduledExecutionDisposition, ScheduledExecutionTerminal, ScheduledJob,
  ScheduledJobDefinition, ScheduledJobListPage, ScheduledJobMutation, ScheduledJobStatus,
  ScheduledRunExecutionOutcome, ScheduledRunLateEvidenceKind, ScheduledRunResult,
  ScheduledRunSuccessOutcome, SkippedNoneBaselinePolicy, StateError, TransactionalMutationOutcome,
  UpdateExecutionBaseline, UpdateScheduledJob, Value, invalid_json, invalid_occurrence,
  invalid_value, materialized_run, positive_u32, scheduler_error, validate_lowercase_sha256,
  validate_text,
};
use crate::StateStore;

const DELIVERY_POLICY_VERSION_V1: i64 = 1;
const MAX_DELIVERY_INTENT_RUN_ID_BYTES: usize = 1050;
const MAX_DELIVERY_INTENT_KEY_BYTES: usize = 70 + (MAX_DELIVERY_INTENT_RUN_ID_BYTES * 2);
const MAX_DELIVERY_INTENT_ID_BYTES: usize = "intent:".len() + MAX_DELIVERY_INTENT_KEY_BYTES;
const MAX_DELIVERY_ERROR_MESSAGE_BYTES: usize = 4 * 1024;
const READINESS_REJECTION_MESSAGE: &str =
  "provider rejected exact delivery target during readiness";

impl StateStore {
  /// Reads delivery authority for runtime lifecycle tests.
  ///
  /// # Errors
  /// Returns an error when `SQLite` cannot read the delivery rows.
  #[cfg(any(test, feature = "test-support"))]
  pub async fn scheduled_delivery_authority_for_tests(
    &self,
    delivery_id: &str,
  ) -> Result<(String, i64, i64, i64), StateError> {
    sqlx::query_as(
      "select state, attempt, fence, (select count(*) from scheduled_delivery_attempts where delivery_id = ?1) from scheduled_run_deliveries where delivery_id = ?1",
    )
    .bind(delivery_id)
    .fetch_one(&self.pool)
    .await
    .map_err(scheduler_error)
  }

  /// Reads run state for runtime lifecycle tests.
  ///
  /// # Errors
  /// Returns an error when `SQLite` cannot read the run.
  #[cfg(any(test, feature = "test-support"))]
  pub async fn scheduled_run_state_for_tests(&self, run_id: &str) -> Result<String, StateError> {
    sqlx::query_scalar("select state from scheduled_runs where run_id = ?1")
      .bind(run_id)
      .fetch_one(&self.pool)
      .await
      .map_err(scheduler_error)
  }

  /// Reads the parent run state for a scheduled delivery lifecycle test.
  ///
  /// # Errors
  /// Returns an error when `SQLite` cannot read the delivery or run.
  #[cfg(any(test, feature = "test-support"))]
  pub async fn scheduled_delivery_run_state_for_tests(
    &self,
    delivery_id: &str,
  ) -> Result<String, StateError> {
    sqlx::query_scalar(
      "select run.state from scheduled_run_deliveries delivery join scheduled_runs run on run.run_id = delivery.run_id and run.job_id = delivery.job_id where delivery.delivery_id = ?1",
    )
    .bind(delivery_id)
    .fetch_one(&self.pool)
    .await
    .map_err(scheduler_error)
  }

  /// Reads the provider receipt for runtime lifecycle tests.
  ///
  /// # Errors
  /// Returns an error when `SQLite` cannot read the delivery.
  #[cfg(any(test, feature = "test-support"))]
  pub async fn scheduled_delivery_receipt_for_tests(
    &self,
    delivery_id: &str,
  ) -> Result<Option<String>, StateError> {
    sqlx::query_scalar(
      "select provider_receipt from scheduled_run_deliveries where delivery_id = ?1",
    )
    .bind(delivery_id)
    .fetch_one(&self.pool)
    .await
    .map_err(scheduler_error)
  }

  /// Reads the active delivery lease expiry for heartbeat tests.
  ///
  /// # Errors
  /// Returns an error when `SQLite` cannot read the delivery row.
  #[cfg(any(test, feature = "test-support"))]
  pub async fn scheduled_delivery_lease_for_tests(
    &self,
    delivery_id: &str,
  ) -> Result<Option<i64>, StateError> {
    sqlx::query_scalar(
      "select lease_expires_at from scheduled_run_deliveries where delivery_id = ?1",
    )
    .bind(delivery_id)
    .fetch_one(&self.pool)
    .await
    .map_err(scheduler_error)
  }

  /// Reads scheduler authority counts for cross-pool lifecycle tests.
  ///
  /// # Errors
  /// Returns an error when `SQLite` cannot read the test authority rows.
  #[cfg(any(test, feature = "test-support"))]
  pub async fn scheduled_execution_authority_counts_for_tests(
    &self,
    run_id: &str,
    job_id: &str,
  ) -> Result<(i64, i64, i64, i64), StateError> {
    sqlx::query_as(
      "select (select count(*) from scheduled_run_result_artifacts where run_id = ?1), (select count(*) from scheduled_run_deliveries where run_id = ?1), (select baseline_version from scheduled_execution_baselines where job_id = ?2), (select count(*) from scheduled_run_late_evidence where run_id = ?1)",
    )
    .bind(run_id)
    .bind(job_id)
    .fetch_one(&self.pool)
    .await
    .map_err(scheduler_error)
  }

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
    self
      .apply_idempotent_schedule_mutation_with_audit(mutation, idempotency, None)
      .await
  }

  /// Applies a typed scheduler mutation and writes its sanitized audit record atomically.
  ///
  /// # Errors
  /// Returns an error when the mutation, idempotency, or audit contract is invalid, or when
  /// `SQLite` rejects the transaction.
  pub async fn apply_idempotent_schedule_mutation_with_audit(
    &self,
    mutation: &ScheduledJobMutation,
    idempotency: &ScheduleMutationIdempotency,
    audit: Option<&ScheduleMutationAudit>,
  ) -> Result<TransactionalMutationOutcome, StateError> {
    validate_mutation_idempotency(mutation, idempotency)?;
    if let Some(audit) = audit {
      validate_mutation_audit(mutation, idempotency, audit)?;
    }
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
        if let Some(audit) = audit {
          insert_mutation_audit(&mut transaction, audit).await?;
        }
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

  /// Appends a sanitized schedule decision audit outside a mutation transaction.
  ///
  /// # Errors
  /// Returns an error when the audit contract is invalid or `SQLite` rejects the transaction.
  pub async fn append_schedule_audit(
    &self,
    audit: &ScheduleMutationAudit,
  ) -> Result<(), StateError> {
    validate_schedule_audit(audit)?;
    let mut transaction = self.pool.begin().await.map_err(scheduler_error)?;
    insert_mutation_audit(&mut transaction, audit).await?;
    transaction.commit().await.map_err(scheduler_error)
  }

  /// Lists sanitized schedule audit outcomes for one correlation identifier.
  ///
  /// # Errors
  /// Returns an error when the correlation identifier is invalid or `SQLite` cannot execute the
  /// query.
  pub async fn list_schedule_audit_summaries(
    &self,
    correlation_id: &str,
  ) -> Result<Vec<ScheduleAuditSummary>, StateError> {
    validate_text("audit correlation id", correlation_id).map_err(invalid_value)?;
    let rows = sqlx::query(
      "select audit_id, operation, outcome, decision, reason, error_code, idempotency_outcome from schedule_mutation_audit where correlation_id = ?1 order by audit_id",
    )
    .bind(correlation_id)
    .fetch_all(&self.pool)
    .await
    .map_err(scheduler_error)?;
    rows
      .into_iter()
      .map(|row| {
        Ok(ScheduleAuditSummary {
          audit_id: row.try_get("audit_id").map_err(scheduler_error)?,
          operation: row.try_get("operation").map_err(scheduler_error)?,
          outcome: row.try_get("outcome").map_err(scheduler_error)?,
          decision: row.try_get("decision").map_err(scheduler_error)?,
          reason: row.try_get("reason").map_err(scheduler_error)?,
          error_code: row.try_get("error_code").map_err(scheduler_error)?,
          idempotency_outcome: row
            .try_get("idempotency_outcome")
            .map_err(scheduler_error)?,
        })
      })
      .collect()
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

  /// Reads one durable job only when its complete owner key matches.
  ///
  /// # Errors
  /// Returns an error when the owner or job id is invalid, persisted state is invalid, or `SQLite`
  /// cannot execute the query.
  pub async fn get_scheduled_job_by_owner(
    &self,
    owner: &PrincipalKey,
    job_id: &str,
  ) -> Result<Option<ScheduledJob>, StateError> {
    owner.validate().map_err(invalid_value)?;
    validate_text("job id", job_id).map_err(invalid_value)?;
    let row = sqlx::query(
      "select j.job_id, j.definition_version, j.definition_json, j.creator_kind, j.creator_provider, j.creator_tenant, j.creator_subject, j.owner_kind, j.owner_provider, j.owner_tenant, j.owner_subject, j.capability_schema_version, j.capability_digest, j.capability_json, j.status, j.generation, s.schedule_id, s.generation as schedule_generation, s.kind, s.canonical_spec, s.timezone, s.once_at, s.anchor_at, s.interval_seconds, s.next_run_at from scheduled_jobs j join schedules s on s.job_id = j.job_id where j.job_id = ?1 and j.owner_kind = ?2 and j.owner_provider = ?3 and j.owner_tenant = ?4 and j.owner_subject = ?5",
    )
    .bind(job_id)
    .bind(owner.kind())
    .bind(owner.provider())
    .bind(owner.tenant())
    .bind(owner.subject())
    .fetch_optional(&self.pool)
    .await
    .map_err(scheduler_error)?;
    row.map(|row| scheduled_job_from_row(&row)).transpose()
  }

  /// Reads the ordered durable delivery target snapshots for one scheduled job.
  ///
  /// # Errors
  /// Returns an error when persisted target state is invalid or `SQLite` cannot execute the query.
  pub async fn get_scheduled_job_delivery_targets(
    &self,
    job_id: &str,
  ) -> Result<Vec<DeliveryTargetSnapshot>, StateError> {
    validate_text("job id", job_id).map_err(invalid_value)?;
    let rows = sqlx::query(
      "select target_id, provider, connector, tenant, kind, address_json, resolver_version, resolver_digest, identity_digest from scheduled_job_delivery_targets where job_id = ?1 order by ordinal",
    )
    .bind(job_id)
    .fetch_all(&self.pool)
    .await
    .map_err(scheduler_error)?;
    rows
      .into_iter()
      .map(|row| {
        let resolver_version = positive_u32(
          row
            .try_get::<i64, _>("resolver_version")
            .map_err(scheduler_error)?,
        )?;
        DeliveryTargetSnapshot::new(
          row
            .try_get::<String, _>("target_id")
            .map_err(scheduler_error)?,
          row
            .try_get::<String, _>("provider")
            .map_err(scheduler_error)?,
          row
            .try_get::<String, _>("connector")
            .map_err(scheduler_error)?,
          row
            .try_get::<String, _>("tenant")
            .map_err(scheduler_error)?,
          row.try_get::<String, _>("kind").map_err(scheduler_error)?,
          row
            .try_get::<String, _>("address_json")
            .map_err(scheduler_error)?,
          resolver_version,
          row
            .try_get::<String, _>("resolver_digest")
            .map_err(scheduler_error)?,
          row
            .try_get::<String, _>("identity_digest")
            .map_err(scheduler_error)?,
        )
        .map_err(invalid_value)
      })
      .collect()
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
    identity: &AcceptedDeliveryBaselineIdentity,
  ) -> Result<Option<AcceptedDeliveryBaseline>, StateError> {
    identity.validate().map_err(invalid_value)?;
    let row = sqlx::query(
      "select accepted_payload_digest, source_delivery_id, source_run_id, source_result_id, source_result_hash, accepted_at, baseline_version from scheduled_delivery_baselines where job_id = ?1 and target_identity_digest = ?2 and target_snapshot_digest_algorithm = ?3 and target_snapshot_digest = ?4 and delivery_policy_version = ?5 and render_version = ?6 and hash_algorithm = ?7",
    )
    .bind(&identity.job_id)
    .bind(&identity.target_identity_digest)
    .bind(&identity.target_snapshot_digest_algorithm)
    .bind(&identity.target_snapshot_digest)
    .bind(identity.delivery_policy_version)
    .bind(identity.render_version)
    .bind(&identity.hash_algorithm)
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
          source_result_id: row.try_get("source_result_id").map_err(scheduler_error)?,
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

  /// Claims the oldest eligible pending run and creates its durable attempt atomically.
  ///
  /// # Errors
  /// Returns an error for an invalid lease, exhausted counters, or storage failure.
  pub async fn claim_next_scheduled_run(
    &self,
    lease_owner: &str,
    now: i64,
    lease_expires_at: i64,
  ) -> Result<Option<ClaimedScheduledRun>, StateError> {
    validate_text("scheduled run lease owner", lease_owner).map_err(invalid_value)?;
    if lease_expires_at <= now {
      return Err(StateError::InvalidSchedulerState {
        reason: "scheduled run lease must expire after claim time".to_owned(),
      });
    }
    let mut transaction = self.pool.begin().await.map_err(scheduler_error)?;
    let row = sqlx::query(
      "update scheduled_runs set state = 'leased', attempt = attempt + 1, fence = fence + 1, next_attempt_at = null, lease_owner = ?1, lease_expires_at = ?2, updated_at = ?3 where run_id = (select run_id from scheduled_runs indexed by idx_scheduled_runs_claim where state = 'pending' and (next_attempt_at is null or next_attempt_at <= ?3) and attempt < 9223372036854775807 and fence < 9223372036854775807 order by scheduled_for, run_id limit 1) and state = 'pending' and (next_attempt_at is null or next_attempt_at <= ?3) and attempt < 9223372036854775807 and fence < 9223372036854775807 returning run_id, job_id, schedule_id, job_generation, schedule_generation, scheduled_for, coalesced_through, definition_version, definition_json, capability_schema_version, capability_digest, capability_json, targets_json, execution_baseline_json, attempt, fence",
    )
    .bind(lease_owner)
    .bind(lease_expires_at)
    .bind(now)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(scheduler_error)?;
    let Some(row) = row else {
      let exhausted: i64 = sqlx::query_scalar(
        "select exists(select 1 from scheduled_runs where state = 'pending' and (next_attempt_at is null or next_attempt_at <= ?1) and (attempt = 9223372036854775807 or fence = 9223372036854775807))",
      )
      .bind(now)
      .fetch_one(&mut *transaction)
      .await
      .map_err(scheduler_error)?;
      if exhausted != 0 {
        return Err(StateError::ScheduledRunCounterExhausted);
      }
      transaction.commit().await.map_err(scheduler_error)?;
      return Ok(None);
    };
    let run_id: String = row.try_get("run_id").map_err(scheduler_error)?;
    let job_id: String = row.try_get("job_id").map_err(scheduler_error)?;
    let attempt: i64 = row.try_get("attempt").map_err(scheduler_error)?;
    let fence: i64 = row.try_get("fence").map_err(scheduler_error)?;
    sqlx::query(
      "insert into scheduled_run_attempts (run_id, job_id, attempt, fence, lease_owner, state, claimed_at, lease_expires_at) values (?1, ?2, ?3, ?4, ?5, 'leased', ?6, ?7)",
    )
    .bind(&run_id)
    .bind(&job_id)
    .bind(attempt)
    .bind(fence)
    .bind(lease_owner)
    .bind(now)
    .bind(lease_expires_at)
    .execute(&mut *transaction)
    .await
    .map_err(scheduler_error)?;
    let execution_baseline_json = row
      .try_get::<Option<String>, _>("execution_baseline_json")
      .map_err(scheduler_error)?
      .ok_or_else(|| StateError::InvalidSchedulerState {
        reason: "materialized run is missing its execution baseline snapshot".to_owned(),
      })?;
    let claimed = ClaimedScheduledRun {
      binding: RunLeaseBinding {
        run_id,
        job_id,
        attempt,
        fence,
        lease_owner: lease_owner.to_owned(),
      },
      schedule_id: row.try_get("schedule_id").map_err(scheduler_error)?,
      job_generation: row.try_get("job_generation").map_err(scheduler_error)?,
      schedule_generation: row
        .try_get("schedule_generation")
        .map_err(scheduler_error)?,
      scheduled_for: row.try_get("scheduled_for").map_err(scheduler_error)?,
      coalesced_through: row.try_get("coalesced_through").map_err(scheduler_error)?,
      definition_version: positive_u32(
        row.try_get("definition_version").map_err(scheduler_error)?,
      )?,
      definition_json: row.try_get("definition_json").map_err(scheduler_error)?,
      capability_schema_version: positive_u32(
        row
          .try_get("capability_schema_version")
          .map_err(scheduler_error)?,
      )?,
      capability_digest: row.try_get("capability_digest").map_err(scheduler_error)?,
      capability_json: row.try_get("capability_json").map_err(scheduler_error)?,
      targets_json: row.try_get("targets_json").map_err(scheduler_error)?,
      execution_baseline_json,
    };
    transaction.commit().await.map_err(scheduler_error)?;
    Ok(Some(claimed))
  }

  /// Extends a live scheduled-run lease using its complete owner and fencing binding.
  ///
  /// # Errors
  /// Returns `ScheduledRunLostLease` when the binding is stale or already expired.
  pub async fn heartbeat_scheduled_run(
    &self,
    binding: &RunLeaseBinding,
    now: i64,
    lease_expires_at: i64,
  ) -> Result<(), StateError> {
    validate_lease_binding(binding)?;
    if lease_expires_at <= now {
      return Err(StateError::InvalidSchedulerState {
        reason: "scheduled run heartbeat must extend beyond now".to_owned(),
      });
    }
    let mut transaction = self.pool.begin().await.map_err(scheduler_error)?;
    let run = sqlx::query(
      "update scheduled_runs set lease_expires_at = ?1, updated_at = ?2 where run_id = ?3 and job_id = ?4 and attempt = ?5 and fence = ?6 and lease_owner = ?7 and state in ('leased', 'executing') and lease_expires_at > ?2 and ?1 > lease_expires_at",
    )
    .bind(lease_expires_at)
    .bind(now)
    .bind(binding.run_id())
    .bind(binding.job_id())
    .bind(binding.attempt())
    .bind(binding.fence())
    .bind(binding.lease_owner())
    .execute(&mut *transaction)
    .await
    .map_err(scheduler_error)?;
    if run.rows_affected() != 1 {
      return Err(StateError::ScheduledRunLostLease);
    }
    let attempt = sqlx::query(
      "update scheduled_run_attempts set lease_expires_at = ?1 where run_id = ?2 and job_id = ?3 and attempt = ?4 and fence = ?5 and lease_owner = ?6 and state in ('leased', 'executing') and lease_expires_at > ?7 and ?1 > lease_expires_at",
    )
    .bind(lease_expires_at)
    .bind(binding.run_id())
    .bind(binding.job_id())
    .bind(binding.attempt())
    .bind(binding.fence())
    .bind(binding.lease_owner())
    .bind(now)
    .execute(&mut *transaction)
    .await
    .map_err(scheduler_error)?;
    if attempt.rows_affected() != 1 {
      return Err(StateError::ScheduledRunLostLease);
    }
    transaction.commit().await.map_err(scheduler_error)
  }

  /// Persists preflight attestation before changing a leased run to executing.
  ///
  /// # Errors
  /// Returns `ScheduledRunLostLease` for a stale binding or an invalid-state error for the profile.
  pub async fn mark_scheduled_run_executing(
    &self,
    binding: &RunLeaseBinding,
    profile: &AttestedExecutionProfileSnapshot,
    now: i64,
  ) -> Result<(), StateError> {
    validate_lease_binding(binding)?;
    profile.validate().map_err(invalid_value)?;
    let mut transaction = self.pool.begin().await.map_err(scheduler_error)?;
    let run = sqlx::query(
      "update scheduled_runs set state = 'executing', updated_at = ?1 where run_id = ?2 and job_id = ?3 and attempt = ?4 and fence = ?5 and lease_owner = ?6 and state = 'leased' and lease_expires_at > ?1",
    )
    .bind(now)
    .bind(binding.run_id())
    .bind(binding.job_id())
    .bind(binding.attempt())
    .bind(binding.fence())
    .bind(binding.lease_owner())
    .execute(&mut *transaction)
    .await
    .map_err(scheduler_error)?;
    if run.rows_affected() != 1 {
      return Err(StateError::ScheduledRunLostLease);
    }
    let attempt = sqlx::query(
      "update scheduled_run_attempts set state = 'executing', preflight_completed_at = ?1, executing_at = ?1, attested_profile_schema_version = ?2, attested_profile_json = ?3, attested_profile_hash_algorithm = ?4, attested_profile_digest = ?5 where run_id = ?6 and job_id = ?7 and attempt = ?8 and fence = ?9 and lease_owner = ?10 and state = 'leased' and lease_expires_at > ?1",
    )
    .bind(now)
    .bind(i64::from(profile.schema_version))
    .bind(&profile.canonical_json)
    .bind(&profile.hash_algorithm)
    .bind(&profile.digest)
    .bind(binding.run_id())
    .bind(binding.job_id())
    .bind(binding.attempt())
    .bind(binding.fence())
    .bind(binding.lease_owner())
    .execute(&mut *transaction)
    .await
    .map_err(scheduler_error)?;
    if attempt.rows_affected() != 1 {
      return Err(StateError::ScheduledRunLostLease);
    }
    transaction.commit().await.map_err(scheduler_error)
  }

  /// Loads and validates the immutable target snapshot carried by a delivery intent.
  ///
  /// The database enforces the intent's natural identity. This read boundary independently
  /// verifies the derived snapshot digest before a later delivery stage may use the target.
  ///
  /// # Errors
  /// Returns an error when the identifier is invalid, the intent does not exist, the persisted
  /// target is malformed, or its derived digest does not match its canonical bytes.
  pub async fn load_scheduled_delivery_intent_target_snapshot(
    &self,
    delivery_id: &str,
  ) -> Result<String, StateError> {
    if delivery_id.is_empty() || delivery_id.len() > MAX_DELIVERY_INTENT_ID_BYTES {
      return Err(StateError::InvalidSchedulerState {
        reason: "scheduled delivery intent id exceeds its dedicated bound".to_owned(),
      });
    }
    let row = sqlx::query(
      "select run_id, target_json, target_identity_digest, delivery_policy_version, target_snapshot_digest_algorithm, target_snapshot_digest, intent_key from scheduled_run_deliveries where delivery_id = ?1 and authority_kind = 'intent_v1'",
    )
    .bind(delivery_id)
    .fetch_optional(&self.pool)
    .await
    .map_err(scheduler_error)?
    .ok_or_else(|| StateError::InvalidSchedulerState {
      reason: "scheduled delivery intent does not exist".to_owned(),
    })?;
    let run_id: String = row.try_get("run_id").map_err(scheduler_error)?;
    let target_json: String = row.try_get("target_json").map_err(scheduler_error)?;
    let target_identity_digest: String = row
      .try_get("target_identity_digest")
      .map_err(scheduler_error)?;
    let delivery_policy_version: i64 = row
      .try_get("delivery_policy_version")
      .map_err(scheduler_error)?;
    if delivery_policy_version != DELIVERY_POLICY_VERSION_V1 {
      return Err(StateError::InvalidSchedulerState {
        reason: "scheduled delivery intent has an unsupported policy version".to_owned(),
      });
    }
    let expected_key = delivery_intent_key(&run_id, &target_identity_digest)?;
    let intent_key: String = row.try_get("intent_key").map_err(scheduler_error)?;
    if intent_key != expected_key || delivery_id != format!("intent:{expected_key}") {
      return Err(StateError::InvalidSchedulerState {
        reason: "scheduled delivery intent natural identity mismatch".to_owned(),
      });
    }
    validate_delivery_intent_target_snapshot(
      &target_json,
      &target_identity_digest,
      row
        .try_get("target_snapshot_digest_algorithm")
        .map_err(scheduler_error)?,
      row
        .try_get("target_snapshot_digest")
        .map_err(scheduler_error)?,
    )?;
    Ok(target_json)
  }

  /// Reads the next accepted result that still needs its exact delivery payload frozen.
  ///
  /// This is a read-only recovery boundary. Concurrent preparers may observe the same input;
  /// `prepare_scheduled_delivery` provides the idempotent immutable compare-and-set authority.
  ///
  /// # Errors
  /// Returns an error when persisted result authority is invalid or storage fails.
  pub async fn next_scheduled_delivery_render_input(
    &self,
  ) -> Result<Option<ScheduledDeliveryRenderInput>, StateError> {
    let row = sqlx::query(
      "select delivery.delivery_id, artifact.result_json from scheduled_run_deliveries delivery join scheduled_runs run on run.run_id = delivery.run_id and run.job_id = delivery.job_id join scheduled_run_result_artifacts artifact on artifact.artifact_id = delivery.result_artifact_id and artifact.run_id = delivery.run_id and artifact.job_id = delivery.job_id and artifact.accepted_attempt = delivery.result_attempt and artifact.accepted_fence = delivery.result_fence where delivery.state = 'pending' and delivery.authority_kind = 'intent_v1' and delivery.payload_snapshot is null and run.state = 'succeeded' and run.result_artifact_id = delivery.result_artifact_id order by delivery.created_at, delivery.delivery_id limit 1",
    )
    .fetch_optional(&self.pool)
    .await
    .map_err(scheduler_error)?;
    let Some(row) = row else {
      return Ok(None);
    };
    let delivery_id: String = row.try_get("delivery_id").map_err(scheduler_error)?;
    let result_json: String = row.try_get("result_json").map_err(scheduler_error)?;
    Ok(Some(ScheduledDeliveryRenderInput::new(
      delivery_id,
      delivery_body_from_result_json(&result_json)?,
    )))
  }

  /// Freezes the exact UTF-8 payload for an issue-06 delivery intent.
  ///
  /// A `none` target is completed locally as `skipped_none`; no provider client is involved.
  /// For non-`none` targets the baseline read is advisory: the claim transaction repeats the
  /// complete identity-and-digest comparison immediately before any provider write.
  /// Repeating the same preparation is idempotent, while different bytes or versions conflict
  /// with the immutable payload authority.
  ///
  /// # Errors
  /// Returns an error for invalid input, a missing intent, immutable payload conflict, baseline
  /// generation conflict, or storage failure.
  #[allow(clippy::too_many_arguments)]
  pub async fn prepare_scheduled_delivery(
    &self,
    delivery_id: &str,
    content_type: &str,
    body: &str,
    render_version: u32,
    now: i64,
    skipped_none_policy: SkippedNoneBaselinePolicy,
  ) -> Result<PreparedScheduledDelivery, StateError> {
    validate_delivery_preparation(delivery_id, content_type, body, render_version, now)?;
    let payload_digest = sha256_hex(body.as_bytes());
    let mut transaction = self.pool.begin().await.map_err(scheduler_error)?;
    let row = sqlx::query(
      "select d.delivery_id, d.run_id, d.job_id, d.target_identity_digest, d.target_json, d.state, d.delivery_policy_version, d.render_version, d.payload_schema_version, d.content_type, d.hash_algorithm, d.payload_digest, d.payload_snapshot, d.payload_created_at, d.expected_baseline_version, d.result_artifact_id, d.target_snapshot_digest_algorithm, d.target_snapshot_digest, d.target_snapshot_version, d.created_at, a.result_hash from scheduled_run_deliveries d join scheduled_run_result_artifacts a on a.artifact_id = d.result_artifact_id and a.run_id = d.run_id and a.job_id = d.job_id where d.delivery_id = ?1 and d.authority_kind = 'intent_v1'",
    )
    .bind(delivery_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(scheduler_error)?
    .ok_or_else(|| StateError::InvalidSchedulerState {
      reason: "scheduled delivery intent does not exist".to_owned(),
    })?;
    let (skipped_none, target_snapshot_version) = delivery_target_metadata(&row)?;
    if let Some(prepared) = existing_prepared_delivery(&row, body, content_type, render_version)? {
      transaction.commit().await.map_err(scheduler_error)?;
      return Ok(prepared);
    }
    let state: String = row.try_get("state").map_err(scheduler_error)?;
    if state != "pending" {
      return Err(StateError::ScheduledDeliveryPayloadConflict);
    }
    let target_identity_digest: String = row
      .try_get("target_identity_digest")
      .map_err(scheduler_error)?;
    let target_snapshot_digest: String = row
      .try_get("target_snapshot_digest")
      .map_err(scheduler_error)?;
    let delivery_policy_version: i64 = row
      .try_get("delivery_policy_version")
      .map_err(scheduler_error)?;
    let (expected_baseline_version, _) = delivery_baseline_decision(
      &mut transaction,
      &row,
      render_version,
      &payload_digest,
      skipped_none,
    )
    .await?;
    let updated = sqlx::query(
      "update scheduled_run_deliveries set state = case when ?1 then 'skipped_none' else 'pending' end, render_version = ?2, payload_schema_version = ?3, content_type = ?4, hash_algorithm = ?5, payload_digest = ?6, payload_snapshot = ?7, payload_created_at = ?10, expected_baseline_version = ?8, target_snapshot_version = ?9, provider_outcome = case when ?1 then 'skipped_none' end, updated_at = ?10 where delivery_id = ?11 and authority_kind = 'intent_v1' and state = 'pending' and payload_snapshot is null",
    )
    .bind(skipped_none)
    .bind(i64::from(render_version))
    .bind(i64::from(DELIVERY_PAYLOAD_SCHEMA_VERSION))
    .bind(content_type)
    .bind(DELIVERY_PAYLOAD_HASH_ALGORITHM)
    .bind(&payload_digest)
    .bind(body.as_bytes())
    .bind(expected_baseline_version)
    .bind(i64::from(target_snapshot_version))
    .bind(now)
    .bind(delivery_id)
    .execute(&mut *transaction)
    .await
    .map_err(scheduler_error)?;
    if updated.rows_affected() != 1 {
      return Err(StateError::ScheduledDeliveryPayloadConflict);
    }
    if skipped_none
      && skipped_none_policy == SkippedNoneBaselinePolicy::Accept
      && !advance_accepted_delivery_baseline_in_transaction(&mut transaction, delivery_id, now)
        .await?
    {
      return Err(StateError::ScheduledDeliveryBaselineConflict);
    }
    let snapshot = DeliveryPayloadSnapshot::from_durable_parts(
      delivery_id.to_owned(),
      row.try_get("run_id").map_err(scheduler_error)?,
      row.try_get("result_artifact_id").map_err(scheduler_error)?,
      content_type.to_owned(),
      body.to_owned(),
      payload_digest,
      target_identity_digest,
      target_snapshot_digest,
      target_snapshot_version,
      positive_u32(delivery_policy_version)?,
      render_version,
      now,
    )
    .map_err(invalid_value)?;
    transaction.commit().await.map_err(scheduler_error)?;
    if skipped_none {
      Ok(PreparedScheduledDelivery::SkippedNone(snapshot))
    } else {
      Ok(PreparedScheduledDelivery::Pending(snapshot))
    }
  }

  /// Identifies whether due delivery work needs provider readiness without mutating authority.
  ///
  /// # Errors
  /// Returns an error for invalid time or storage failure.
  pub async fn peek_scheduled_delivery_work(
    &self,
    now: i64,
  ) -> Result<ScheduledDeliveryWork, StateError> {
    if now < 0 {
      return Err(StateError::InvalidSchedulerState {
        reason: "scheduled delivery readiness time must be nonnegative".to_owned(),
      });
    }
    let pending = sqlx::query(
      "select candidate.delivery_id, candidate.state, candidate.target_json, candidate.target_identity_digest, candidate.target_snapshot_digest_algorithm, candidate.target_snapshot_digest, candidate.payload_digest, candidate.intent_key, exists(select 1 from scheduled_delivery_baselines baseline where baseline.job_id = candidate.job_id and baseline.target_identity_digest = candidate.target_identity_digest and baseline.target_snapshot_digest_algorithm = candidate.target_snapshot_digest_algorithm and baseline.target_snapshot_digest = candidate.target_snapshot_digest and baseline.delivery_policy_version = candidate.delivery_policy_version and baseline.render_version = candidate.render_version and baseline.hash_algorithm = candidate.hash_algorithm and baseline.accepted_payload_digest = candidate.payload_digest) as unchanged from scheduled_run_deliveries candidate where ((candidate.state = 'failed_retryable' and candidate.next_attempt_at <= ?1) or (candidate.state = 'pending' and candidate.updated_at <= ?1)) and candidate.authority_kind = 'intent_v1' and candidate.payload_snapshot is not null and not exists (select 1 from scheduled_run_deliveries active where active.state = 'sending' and active.delivery_id <> candidate.delivery_id and active.job_id = candidate.job_id and active.target_identity_digest = candidate.target_identity_digest and active.target_snapshot_digest = candidate.target_snapshot_digest and active.delivery_policy_version = candidate.delivery_policy_version and active.render_version = candidate.render_version and active.hash_algorithm = candidate.hash_algorithm) order by case candidate.state when 'failed_retryable' then 0 else 1 end, case candidate.state when 'failed_retryable' then candidate.next_attempt_at else candidate.created_at end, candidate.delivery_id limit 1",
    )
    .bind(now)
    .fetch_optional(&self.pool)
    .await
    .map_err(scheduler_error)?;
    let Some(pending) = pending else {
      return Ok(ScheduledDeliveryWork::Idle);
    };
    let authority = scheduled_delivery_authority_from_row(&pending)?;
    if authority.source_state() == ScheduledDeliveryState::Pending
      && pending
        .try_get::<i64, _>("unchanged")
        .map_err(scheduler_error)?
        != 0
    {
      Ok(ScheduledDeliveryWork::SkipUnchanged(authority))
    } else {
      Ok(ScheduledDeliveryWork::ProviderRequired(authority))
    }
  }

  /// Atomically skips the oldest pending payload only when it exactly matches its accepted baseline.
  ///
  /// # Errors
  /// Returns an error for invalid time or storage failure.
  pub async fn skip_scheduled_delivery_unchanged(
    &self,
    authority: &ScheduledDeliveryAuthority,
    now: i64,
  ) -> Result<bool, StateError> {
    validate_scheduled_delivery_authority(authority)?;
    if now < 0 {
      return Err(StateError::InvalidSchedulerState {
        reason: "scheduled delivery skip time must be nonnegative".to_owned(),
      });
    }
    sqlx::query_scalar::<_, String>(
      "update scheduled_run_deliveries set state = 'skipped_unchanged', claimed_baseline_version = (select baseline.baseline_version from scheduled_delivery_baselines baseline where baseline.job_id = scheduled_run_deliveries.job_id and baseline.target_identity_digest = scheduled_run_deliveries.target_identity_digest and baseline.target_snapshot_digest_algorithm = scheduled_run_deliveries.target_snapshot_digest_algorithm and baseline.target_snapshot_digest = scheduled_run_deliveries.target_snapshot_digest and baseline.delivery_policy_version = scheduled_run_deliveries.delivery_policy_version and baseline.render_version = scheduled_run_deliveries.render_version and baseline.hash_algorithm = scheduled_run_deliveries.hash_algorithm and baseline.accepted_payload_digest = scheduled_run_deliveries.payload_digest), provider_outcome = 'skipped_unchanged', next_attempt_at = null, lease_owner = null, lease_expires_at = null, updated_at = ?1 where delivery_id = ?2 and state = 'pending' and ?3 = 'pending' and authority_kind = 'intent_v1' and payload_snapshot is not null and target_json = ?4 and target_snapshot_digest = ?5 and payload_digest = ?6 and intent_key = ?7 and updated_at <= ?1 and not exists (select 1 from scheduled_run_deliveries active where active.state = 'sending' and active.delivery_id <> scheduled_run_deliveries.delivery_id and active.job_id = scheduled_run_deliveries.job_id and active.target_identity_digest = scheduled_run_deliveries.target_identity_digest and active.target_snapshot_digest = scheduled_run_deliveries.target_snapshot_digest and active.delivery_policy_version = scheduled_run_deliveries.delivery_policy_version and active.render_version = scheduled_run_deliveries.render_version and active.hash_algorithm = scheduled_run_deliveries.hash_algorithm) and exists (select 1 from scheduled_delivery_baselines baseline where baseline.job_id = scheduled_run_deliveries.job_id and baseline.target_identity_digest = scheduled_run_deliveries.target_identity_digest and baseline.target_snapshot_digest_algorithm = scheduled_run_deliveries.target_snapshot_digest_algorithm and baseline.target_snapshot_digest = scheduled_run_deliveries.target_snapshot_digest and baseline.delivery_policy_version = scheduled_run_deliveries.delivery_policy_version and baseline.render_version = scheduled_run_deliveries.render_version and baseline.hash_algorithm = scheduled_run_deliveries.hash_algorithm and baseline.accepted_payload_digest = scheduled_run_deliveries.payload_digest) returning delivery_id",
    )
    .bind(now)
    .bind(authority.delivery_id())
    .bind(authority.source_state().as_str())
    .bind(authority.target_json())
    .bind(authority.target_digest())
    .bind(authority.payload_digest())
    .bind(authority.intent_key())
    .fetch_optional(&self.pool)
    .await
    .map(|delivery| delivery.is_some())
    .map_err(scheduler_error)
  }

  /// Terminally rejects exactly the due delivery authority checked by provider readiness.
  ///
  /// This transition creates no provider attempt and cannot advance an accepted baseline. A stale
  /// readiness result for a different state, target, payload, or intent binding is a no-op.
  ///
  /// # Errors
  /// Returns an error for invalid authority, invalid redacted evidence, time, or storage failure.
  pub async fn reject_scheduled_delivery_readiness(
    &self,
    authority: &ScheduledDeliveryAuthority,
    error_kind: &str,
    now: i64,
  ) -> Result<bool, StateError> {
    validate_scheduled_delivery_authority(authority)?;
    validate_delivery_error(error_kind, Some(READINESS_REJECTION_MESSAGE))?;
    if now < 0 {
      return Err(StateError::InvalidSchedulerState {
        reason: "scheduled delivery readiness rejection time must be nonnegative".to_owned(),
      });
    }
    sqlx::query_scalar::<_, String>(
      "update scheduled_run_deliveries set state = 'failed_terminal', next_attempt_at = null, lease_owner = null, lease_expires_at = null, provider_receipt = null, provider_outcome = 'confirmed_no_write_terminal', error_kind = ?1, error_message = ?2, updated_at = ?3 where delivery_id = ?4 and state = ?5 and authority_kind = 'intent_v1' and payload_snapshot is not null and target_json = ?6 and target_snapshot_digest = ?7 and payload_digest = ?8 and intent_key = ?9 and updated_at <= ?3 and (?5 = 'pending' or (?5 = 'failed_retryable' and next_attempt_at <= ?3)) returning delivery_id",
    )
    .bind(error_kind)
    .bind(READINESS_REJECTION_MESSAGE)
    .bind(now)
    .bind(authority.delivery_id())
    .bind(authority.source_state().as_str())
    .bind(authority.target_json())
    .bind(authority.target_digest())
    .bind(authority.payload_digest())
    .bind(authority.intent_key())
    .fetch_optional(&self.pool)
    .await
    .map(|delivery| delivery.is_some())
    .map_err(scheduler_error)
  }

  /// Atomically rechecks the accepted baseline, then either skips an exact match without an
  /// attempt or claims the oldest changed payload and records the claim-time baseline generation.
  ///
  /// # Errors
  /// Returns an error for an invalid lease, exhausted counters, or storage failure.
  pub async fn claim_next_scheduled_delivery(
    &self,
    lease_owner: &str,
    now: i64,
    lease_expires_at: i64,
  ) -> Result<Option<ClaimedScheduledDelivery>, StateError> {
    validate_text("scheduled delivery lease owner", lease_owner).map_err(invalid_value)?;
    if now < 0 || lease_expires_at <= now {
      return Err(StateError::InvalidSchedulerState {
        reason: "scheduled delivery lease must expire after claim time".to_owned(),
      });
    }
    let mut transaction = self.pool.begin().await.map_err(scheduler_error)?;
    let skipped = sqlx::query_scalar::<_, String>(
      "update scheduled_run_deliveries set state = 'skipped_unchanged', claimed_baseline_version = (select baseline.baseline_version from scheduled_delivery_baselines baseline where baseline.job_id = scheduled_run_deliveries.job_id and baseline.target_identity_digest = scheduled_run_deliveries.target_identity_digest and baseline.target_snapshot_digest_algorithm = scheduled_run_deliveries.target_snapshot_digest_algorithm and baseline.target_snapshot_digest = scheduled_run_deliveries.target_snapshot_digest and baseline.delivery_policy_version = scheduled_run_deliveries.delivery_policy_version and baseline.render_version = scheduled_run_deliveries.render_version and baseline.hash_algorithm = scheduled_run_deliveries.hash_algorithm and baseline.accepted_payload_digest = scheduled_run_deliveries.payload_digest), provider_outcome = 'skipped_unchanged', updated_at = ?1 where delivery_id = (select candidate.delivery_id from scheduled_run_deliveries candidate where candidate.state = 'pending' and candidate.authority_kind = 'intent_v1' and candidate.payload_snapshot is not null and candidate.updated_at <= ?1 and not exists (select 1 from scheduled_run_deliveries active where active.state = 'sending' and active.job_id = candidate.job_id and active.target_identity_digest = candidate.target_identity_digest and active.target_snapshot_digest = candidate.target_snapshot_digest and active.delivery_policy_version = candidate.delivery_policy_version and active.render_version = candidate.render_version and active.hash_algorithm = candidate.hash_algorithm) order by candidate.created_at, candidate.delivery_id limit 1) and state = 'pending' and updated_at <= ?1 and exists (select 1 from scheduled_delivery_baselines baseline where baseline.job_id = scheduled_run_deliveries.job_id and baseline.target_identity_digest = scheduled_run_deliveries.target_identity_digest and baseline.target_snapshot_digest_algorithm = scheduled_run_deliveries.target_snapshot_digest_algorithm and baseline.target_snapshot_digest = scheduled_run_deliveries.target_snapshot_digest and baseline.delivery_policy_version = scheduled_run_deliveries.delivery_policy_version and baseline.render_version = scheduled_run_deliveries.render_version and baseline.hash_algorithm = scheduled_run_deliveries.hash_algorithm and baseline.accepted_payload_digest = scheduled_run_deliveries.payload_digest) returning delivery_id",
    )
    .bind(now)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(scheduler_error)?;
    if skipped.is_some() {
      transaction.commit().await.map_err(scheduler_error)?;
      return Ok(None);
    }
    let row = sqlx::query(
      "update scheduled_run_deliveries set state = 'sending', attempt = attempt + 1, fence = fence + 1, lease_owner = ?1, lease_expires_at = ?2, idempotency_key = coalesce(idempotency_key, 'delivery-v1:' || lower(hex(cast(delivery_id as blob))) || ':' || payload_digest), claimed_baseline_version = coalesce((select baseline.baseline_version from scheduled_delivery_baselines baseline where baseline.job_id = scheduled_run_deliveries.job_id and baseline.target_identity_digest = scheduled_run_deliveries.target_identity_digest and baseline.target_snapshot_digest_algorithm = scheduled_run_deliveries.target_snapshot_digest_algorithm and baseline.target_snapshot_digest = scheduled_run_deliveries.target_snapshot_digest and baseline.delivery_policy_version = scheduled_run_deliveries.delivery_policy_version and baseline.render_version = scheduled_run_deliveries.render_version and baseline.hash_algorithm = scheduled_run_deliveries.hash_algorithm), 0), updated_at = ?3 where delivery_id = (select candidate.delivery_id from scheduled_run_deliveries candidate where candidate.state = 'pending' and candidate.authority_kind = 'intent_v1' and candidate.payload_snapshot is not null and candidate.attempt < 9223372036854775807 and candidate.fence < 9223372036854775807 and candidate.updated_at <= ?3 and not exists (select 1 from scheduled_run_deliveries active where active.state = 'sending' and active.job_id = candidate.job_id and active.target_identity_digest = candidate.target_identity_digest and active.target_snapshot_digest = candidate.target_snapshot_digest and active.delivery_policy_version = candidate.delivery_policy_version and active.render_version = candidate.render_version and active.hash_algorithm = candidate.hash_algorithm) order by candidate.created_at, candidate.delivery_id limit 1) and state = 'pending' and updated_at <= ?3 and not exists (select 1 from scheduled_delivery_baselines baseline where baseline.job_id = scheduled_run_deliveries.job_id and baseline.target_identity_digest = scheduled_run_deliveries.target_identity_digest and baseline.target_snapshot_digest_algorithm = scheduled_run_deliveries.target_snapshot_digest_algorithm and baseline.target_snapshot_digest = scheduled_run_deliveries.target_snapshot_digest and baseline.delivery_policy_version = scheduled_run_deliveries.delivery_policy_version and baseline.render_version = scheduled_run_deliveries.render_version and baseline.hash_algorithm = scheduled_run_deliveries.hash_algorithm and baseline.accepted_payload_digest = scheduled_run_deliveries.payload_digest) returning delivery_id, run_id, result_artifact_id, content_type, payload_schema_version, hash_algorithm, payload_snapshot, payload_digest, payload_created_at, target_json, target_identity_digest, target_snapshot_digest_algorithm, target_snapshot_digest, target_snapshot_version, delivery_policy_version, render_version, attempt, fence, lease_owner, idempotency_key, claimed_baseline_version",
    )
    .bind(lease_owner)
    .bind(lease_expires_at)
    .bind(now)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(scheduler_error)?;
    let Some(row) = row else {
      let exhausted: i64 = sqlx::query_scalar(
        "select exists(select 1 from scheduled_run_deliveries where state = 'pending' and authority_kind = 'intent_v1' and payload_snapshot is not null and (attempt = 9223372036854775807 or fence = 9223372036854775807))",
      )
      .fetch_one(&mut *transaction)
      .await
      .map_err(scheduler_error)?;
      transaction.commit().await.map_err(scheduler_error)?;
      if exhausted != 0 {
        return Err(StateError::ScheduledDeliveryCounterExhausted);
      }
      return Ok(None);
    };
    let binding = ScheduledDeliveryBinding::new(
      row.try_get("delivery_id").map_err(scheduler_error)?,
      row.try_get("attempt").map_err(scheduler_error)?,
      row.try_get("fence").map_err(scheduler_error)?,
      row.try_get("lease_owner").map_err(scheduler_error)?,
      row.try_get("idempotency_key").map_err(scheduler_error)?,
    );
    let inserted = sqlx::query(
      "insert into scheduled_delivery_attempts (delivery_id, attempt, fence, lease_owner, lease_expires_at, idempotency_key, claimed_baseline_version, state, started_at) values (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'sending', ?8)",
    )
    .bind(binding.delivery_id())
    .bind(binding.attempt())
    .bind(binding.fence())
    .bind(binding.lease_owner())
    .bind(lease_expires_at)
    .bind(binding.idempotency_key())
    .bind(
      row
        .try_get::<i64, _>("claimed_baseline_version")
        .map_err(scheduler_error)?,
    )
    .bind(now)
    .execute(&mut *transaction)
    .await
    .map_err(scheduler_error)?;
    if inserted.rows_affected() != 1 {
      return Err(StateError::ScheduledDeliveryLostLease);
    }
    let payload = delivery_payload_from_row(&row)?;
    let target_json: String = row.try_get("target_json").map_err(scheduler_error)?;
    validate_delivery_intent_target_snapshot(
      &target_json,
      row
        .try_get("target_identity_digest")
        .map_err(scheduler_error)?,
      row
        .try_get("target_snapshot_digest_algorithm")
        .map_err(scheduler_error)?,
      row
        .try_get("target_snapshot_digest")
        .map_err(scheduler_error)?,
    )?;
    transaction.commit().await.map_err(scheduler_error)?;
    Ok(Some(ClaimedScheduledDelivery {
      binding,
      payload,
      target_json,
    }))
  }

  /// Claims only the exact immutable delivery authority previously returned by readiness peek.
  ///
  /// A changed, no-longer-due, blocked, or already-claimed row returns `None`; it never falls
  /// through to another delivery.
  ///
  /// # Errors
  /// Returns an error for invalid authority, lease, exhausted counters, or storage failure.
  pub async fn claim_scheduled_delivery(
    &self,
    authority: &ScheduledDeliveryAuthority,
    lease_owner: &str,
    now: i64,
    lease_expires_at: i64,
  ) -> Result<Option<ClaimedScheduledDelivery>, StateError> {
    validate_text("scheduled delivery lease owner", lease_owner).map_err(invalid_value)?;
    validate_scheduled_delivery_authority(authority)?;
    if now < 0 || lease_expires_at <= now {
      return Err(StateError::InvalidSchedulerState {
        reason: "scheduled delivery lease must expire after claim time".to_owned(),
      });
    }
    let mut transaction = self.pool.begin().await.map_err(scheduler_error)?;
    if authority.source_state() == ScheduledDeliveryState::FailedRetryable
      && !requeue_exact_retryable_delivery(&mut transaction, authority, now).await?
    {
      transaction.commit().await.map_err(scheduler_error)?;
      return Ok(None);
    }
    let row = sqlx::query(
      "update scheduled_run_deliveries set state = 'sending', attempt = attempt + 1, fence = fence + 1, lease_owner = ?1, lease_expires_at = ?2, next_attempt_at = null, idempotency_key = coalesce(idempotency_key, 'delivery-v1:' || lower(hex(cast(delivery_id as blob))) || ':' || payload_digest), claimed_baseline_version = coalesce((select baseline.baseline_version from scheduled_delivery_baselines baseline where baseline.job_id = scheduled_run_deliveries.job_id and baseline.target_identity_digest = scheduled_run_deliveries.target_identity_digest and baseline.target_snapshot_digest_algorithm = scheduled_run_deliveries.target_snapshot_digest_algorithm and baseline.target_snapshot_digest = scheduled_run_deliveries.target_snapshot_digest and baseline.delivery_policy_version = scheduled_run_deliveries.delivery_policy_version and baseline.render_version = scheduled_run_deliveries.render_version and baseline.hash_algorithm = scheduled_run_deliveries.hash_algorithm), 0), provider_outcome = null, error_kind = null, error_message = null, updated_at = ?3 where delivery_id = ?4 and state = 'pending' and authority_kind = 'intent_v1' and payload_snapshot is not null and target_json = ?5 and target_snapshot_digest = ?6 and payload_digest = ?7 and intent_key = ?8 and attempt < 9223372036854775807 and fence < 9223372036854775807 and updated_at <= ?3 and not exists (select 1 from scheduled_run_deliveries active where active.state = 'sending' and active.delivery_id <> scheduled_run_deliveries.delivery_id and active.job_id = scheduled_run_deliveries.job_id and active.target_identity_digest = scheduled_run_deliveries.target_identity_digest and active.target_snapshot_digest = scheduled_run_deliveries.target_snapshot_digest and active.delivery_policy_version = scheduled_run_deliveries.delivery_policy_version and active.render_version = scheduled_run_deliveries.render_version and active.hash_algorithm = scheduled_run_deliveries.hash_algorithm) and not exists (select 1 from scheduled_delivery_baselines baseline where baseline.job_id = scheduled_run_deliveries.job_id and baseline.target_identity_digest = scheduled_run_deliveries.target_identity_digest and baseline.target_snapshot_digest_algorithm = scheduled_run_deliveries.target_snapshot_digest_algorithm and baseline.target_snapshot_digest = scheduled_run_deliveries.target_snapshot_digest and baseline.delivery_policy_version = scheduled_run_deliveries.delivery_policy_version and baseline.render_version = scheduled_run_deliveries.render_version and baseline.hash_algorithm = scheduled_run_deliveries.hash_algorithm and baseline.accepted_payload_digest = scheduled_run_deliveries.payload_digest) returning delivery_id, run_id, result_artifact_id, content_type, payload_schema_version, hash_algorithm, payload_snapshot, payload_digest, payload_created_at, target_json, target_identity_digest, target_snapshot_digest_algorithm, target_snapshot_digest, target_snapshot_version, delivery_policy_version, render_version, attempt, fence, lease_owner, idempotency_key, claimed_baseline_version",
    )
    .bind(lease_owner)
    .bind(lease_expires_at)
    .bind(now)
    .bind(authority.delivery_id())
    .bind(authority.target_json())
    .bind(authority.target_digest())
    .bind(authority.payload_digest())
    .bind(authority.intent_key())
    .fetch_optional(&mut *transaction)
    .await
    .map_err(scheduler_error)?;
    let Some(row) = row else {
      let exhausted: i64 = sqlx::query_scalar(
        "select exists(select 1 from scheduled_run_deliveries where delivery_id = ?1 and state = ?2 and (attempt = 9223372036854775807 or fence = 9223372036854775807))",
      )
      .bind(authority.delivery_id())
      .bind("pending")
      .fetch_one(&mut *transaction)
      .await
      .map_err(scheduler_error)?;
      transaction.commit().await.map_err(scheduler_error)?;
      if exhausted != 0 {
        return Err(StateError::ScheduledDeliveryCounterExhausted);
      }
      return Ok(None);
    };
    let binding = ScheduledDeliveryBinding::new(
      row.try_get("delivery_id").map_err(scheduler_error)?,
      row.try_get("attempt").map_err(scheduler_error)?,
      row.try_get("fence").map_err(scheduler_error)?,
      row.try_get("lease_owner").map_err(scheduler_error)?,
      row.try_get("idempotency_key").map_err(scheduler_error)?,
    );
    let inserted = sqlx::query(
      "insert into scheduled_delivery_attempts (delivery_id, attempt, fence, lease_owner, lease_expires_at, idempotency_key, claimed_baseline_version, state, started_at) values (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'sending', ?8)",
    )
    .bind(binding.delivery_id())
    .bind(binding.attempt())
    .bind(binding.fence())
    .bind(binding.lease_owner())
    .bind(lease_expires_at)
    .bind(binding.idempotency_key())
    .bind(
      row
        .try_get::<i64, _>("claimed_baseline_version")
        .map_err(scheduler_error)?,
    )
    .bind(now)
    .execute(&mut *transaction)
    .await
    .map_err(scheduler_error)?;
    if inserted.rows_affected() != 1 {
      return Err(StateError::ScheduledDeliveryLostLease);
    }
    let payload = delivery_payload_from_row(&row)?;
    let target_json: String = row.try_get("target_json").map_err(scheduler_error)?;
    validate_delivery_intent_target_snapshot(
      &target_json,
      row
        .try_get("target_identity_digest")
        .map_err(scheduler_error)?,
      row
        .try_get("target_snapshot_digest_algorithm")
        .map_err(scheduler_error)?,
      row
        .try_get("target_snapshot_digest")
        .map_err(scheduler_error)?,
    )?;
    transaction.commit().await.map_err(scheduler_error)?;
    Ok(Some(ClaimedScheduledDelivery {
      binding,
      payload,
      target_json,
    }))
  }

  /// Extends the current delivery attempt lease using strict owner/fence authority.
  ///
  /// # Errors
  /// Returns `ScheduledDeliveryLostLease` for stale authority or a storage error.
  pub async fn heartbeat_scheduled_delivery(
    &self,
    binding: &ScheduledDeliveryBinding,
    now: i64,
    lease_expires_at: i64,
  ) -> Result<(), StateError> {
    validate_delivery_binding(binding)?;
    if lease_expires_at <= now {
      return Err(StateError::InvalidSchedulerState {
        reason: "scheduled delivery heartbeat must extend its lease".to_owned(),
      });
    }
    let mut transaction = self.pool.begin().await.map_err(scheduler_error)?;
    let delivery = sqlx::query(
      "update scheduled_run_deliveries set lease_expires_at = ?1, updated_at = ?2 where delivery_id = ?3 and state = 'sending' and attempt = ?4 and fence = ?5 and lease_owner = ?6 and idempotency_key = ?7 and lease_expires_at > ?2 and lease_expires_at < ?1 and updated_at <= ?2",
    )
    .bind(lease_expires_at)
    .bind(now)
    .bind(binding.delivery_id())
    .bind(binding.attempt())
    .bind(binding.fence())
    .bind(binding.lease_owner())
    .bind(binding.idempotency_key())
    .execute(&mut *transaction)
    .await
    .map_err(scheduler_error)?;
    let attempt = sqlx::query(
      "update scheduled_delivery_attempts set lease_expires_at = ?1 where delivery_id = ?2 and attempt = ?3 and fence = ?4 and lease_owner = ?5 and idempotency_key = ?6 and state = 'sending' and lease_expires_at > ?7 and lease_expires_at < ?1",
    )
    .bind(lease_expires_at)
    .bind(binding.delivery_id())
    .bind(binding.attempt())
    .bind(binding.fence())
    .bind(binding.lease_owner())
    .bind(binding.idempotency_key())
    .bind(now)
    .execute(&mut *transaction)
    .await
    .map_err(scheduler_error)?;
    if delivery.rows_affected() != 1 || attempt.rows_affected() != 1 {
      return Err(StateError::ScheduledDeliveryLostLease);
    }
    transaction.commit().await.map_err(scheduler_error)
  }

  /// Converts expired in-flight sends to durable unknown outcomes without retrying them.
  ///
  /// The exact attempt and fence are copied from the claimed delivery into the attempt CAS. Once
  /// reclaimed, the same delivery cannot become pending again, while a later occurrence for the
  /// same baseline identity is no longer blocked by the active-send uniqueness guard.
  ///
  /// # Errors
  /// Returns an error for an invalid limit, inconsistent delivery/attempt authority, or storage
  /// failure.
  pub async fn reclaim_expired_scheduled_deliveries(
    &self,
    now: i64,
    limit: u32,
  ) -> Result<u64, StateError> {
    if now < 0 || limit == 0 {
      return Err(StateError::InvalidSchedulerState {
        reason: "scheduled delivery reclaim requires nonnegative time and positive limit"
          .to_owned(),
      });
    }
    let mut transaction = self.pool.begin().await.map_err(scheduler_error)?;
    let mut reclaimed = 0_u64;
    for _ in 0..limit {
      let row = sqlx::query(
        "select delivery_id, attempt, fence, lease_owner, idempotency_key, lease_expires_at from scheduled_run_deliveries where state = 'sending' and authority_kind = 'intent_v1' and lease_expires_at <= ?1 and updated_at <= ?1 order by lease_expires_at, delivery_id limit 1",
      )
      .bind(now)
      .fetch_optional(&mut *transaction)
      .await
      .map_err(scheduler_error)?;
      let Some(row) = row else {
        break;
      };
      let delivery_id: String = row.try_get("delivery_id").map_err(scheduler_error)?;
      let attempt: i64 = row.try_get("attempt").map_err(scheduler_error)?;
      let fence: i64 = row.try_get("fence").map_err(scheduler_error)?;
      let lease_owner: String = row.try_get("lease_owner").map_err(scheduler_error)?;
      let idempotency_key: String = row.try_get("idempotency_key").map_err(scheduler_error)?;
      let lease_expires_at: i64 = row.try_get("lease_expires_at").map_err(scheduler_error)?;
      let delivery = sqlx::query(
        "update scheduled_run_deliveries set state = 'delivery_unknown', lease_owner = null, lease_expires_at = null, provider_outcome = 'ambiguous_post_write', error_kind = 'delivery_lease_expired', error_message = 'provider write outcome is unknown after delivery lease expiry', updated_at = ?1 where delivery_id = ?2 and attempt = ?3 and fence = ?4 and lease_owner = ?5 and idempotency_key = ?6 and lease_expires_at = ?7 and state = 'sending' and authority_kind = 'intent_v1' and lease_expires_at <= ?1 and updated_at <= ?1",
      )
      .bind(now)
      .bind(&delivery_id)
      .bind(attempt)
      .bind(fence)
      .bind(&lease_owner)
      .bind(&idempotency_key)
      .bind(lease_expires_at)
      .execute(&mut *transaction)
      .await
      .map_err(scheduler_error)?;
      let updated = sqlx::query(
        "update scheduled_delivery_attempts set state = 'delivery_unknown', provider_outcome = 'ambiguous_post_write', error_kind = 'delivery_lease_expired', error_message = 'provider write outcome is unknown after delivery lease expiry', completed_at = ?1 where delivery_id = ?2 and attempt = ?3 and fence = ?4 and lease_owner = ?5 and idempotency_key = ?6 and lease_expires_at = ?7 and state = 'sending' and lease_expires_at <= ?1 and started_at <= ?1",
      )
      .bind(now)
      .bind(&delivery_id)
      .bind(attempt)
      .bind(fence)
      .bind(&lease_owner)
      .bind(&idempotency_key)
      .bind(lease_expires_at)
      .execute(&mut *transaction)
      .await
      .map_err(scheduler_error)?;
      if delivery.rows_affected() != 1 || updated.rows_affected() != 1 {
        return Err(StateError::ScheduledDeliveryLostLease);
      }
      reclaimed += 1;
    }
    transaction.commit().await.map_err(scheduler_error)?;
    Ok(reclaimed)
  }

  /// Commits confirmed provider success and advances the accepted baseline atomically.
  ///
  /// # Errors
  /// Returns an error for stale ownership, invalid receipt, baseline conflict, or storage failure.
  pub async fn complete_scheduled_delivery_delivered(
    &self,
    binding: &ScheduledDeliveryBinding,
    provider_receipt: &str,
    completed_at: i64,
  ) -> Result<(), StateError> {
    validate_delivery_binding(binding)?;
    validate_text("scheduled delivery provider receipt", provider_receipt)
      .map_err(invalid_value)?;
    let mut transaction = self.pool.begin().await.map_err(scheduler_error)?;
    transition_delivery_terminal(
      &mut transaction,
      binding,
      "delivered",
      "confirmed_success",
      Some(provider_receipt),
      None,
      None,
      None,
      completed_at,
    )
    .await?;
    if !advance_accepted_delivery_baseline_in_transaction(
      &mut transaction,
      binding.delivery_id(),
      completed_at,
    )
    .await?
    {
      return Err(StateError::ScheduledDeliveryBaselineConflict);
    }
    transaction.commit().await.map_err(scheduler_error)
  }

  /// Commits a classified provider failure without changing payload or accepted baseline.
  ///
  /// # Errors
  /// Returns an error for stale ownership, invalid classification, or storage failure.
  pub async fn complete_scheduled_delivery_failure(
    &self,
    binding: &ScheduledDeliveryBinding,
    failure: &ScheduledDeliveryFailure,
    completed_at: i64,
  ) -> Result<(), StateError> {
    validate_delivery_binding(binding)?;
    let (state, outcome, error_kind, message, next_attempt_at) = match failure {
      ScheduledDeliveryFailure::ConfirmedNoWriteRetryable {
        error_kind,
        redacted_message,
        next_attempt_at,
      } => {
        if *next_attempt_at <= completed_at {
          return Err(StateError::InvalidSchedulerState {
            reason: "scheduled delivery retry must be deferred".to_owned(),
          });
        }
        (
          "failed_retryable",
          "confirmed_no_write_retryable",
          error_kind,
          redacted_message.as_deref(),
          Some(*next_attempt_at),
        )
      }
      ScheduledDeliveryFailure::ConfirmedNoWriteTerminal {
        error_kind,
        redacted_message,
      } => (
        "failed_terminal",
        "confirmed_no_write_terminal",
        error_kind,
        redacted_message.as_deref(),
        None,
      ),
      ScheduledDeliveryFailure::AmbiguousPostWrite {
        error_kind,
        redacted_message,
      } => (
        "delivery_unknown",
        "ambiguous_post_write",
        error_kind,
        redacted_message.as_deref(),
        None,
      ),
    };
    validate_delivery_error(error_kind, message)?;
    let mut transaction = self.pool.begin().await.map_err(scheduler_error)?;
    transition_delivery_terminal(
      &mut transaction,
      binding,
      state,
      outcome,
      None,
      Some(error_kind),
      message,
      next_attempt_at,
      completed_at,
    )
    .await?;
    transaction.commit().await.map_err(scheduler_error)
  }

  /// Moves due confirmed-no-write failures back to pending for a new fenced claim.
  ///
  /// # Errors
  /// Returns an error when the limit is invalid or storage fails.
  pub async fn requeue_due_scheduled_deliveries(
    &self,
    now: i64,
    limit: u32,
  ) -> Result<u64, StateError> {
    if limit == 0 {
      return Err(StateError::InvalidSchedulerState {
        reason: "scheduled delivery requeue limit must be positive".to_owned(),
      });
    }
    sqlx::query(
      "update scheduled_run_deliveries set state = 'pending', next_attempt_at = null, claimed_baseline_version = null, provider_outcome = null, error_kind = null, error_message = null, updated_at = ?1 where delivery_id in (select delivery_id from scheduled_run_deliveries where state = 'failed_retryable' and next_attempt_at <= ?1 order by next_attempt_at, delivery_id limit ?2)",
    )
    .bind(now)
    .bind(i64::from(limit))
    .execute(&self.pool)
    .await
    .map(|result| result.rows_affected())
    .map_err(scheduler_error)
  }

  /// Prunes one succeeded run's accepted terminal delivery evidence under durable audit authority.
  ///
  /// Delivery baselines remain job-owned and continue to participate in unchanged-payload
  /// decisions. The latest execution-success baseline is an independent retention boundary and
  /// makes its source run ineligible for this operation.
  ///
  /// # Errors
  /// Returns `ScheduledDeliveryRetentionConflict` unless every delivery is an accepted retention
  /// terminal with immutable payload authority and the run is not the latest execution baseline.
  pub async fn prune_scheduled_delivery_history(
    &self,
    operation_id: &str,
    run_id: &str,
    now: i64,
  ) -> Result<ScheduledDeliveryRetentionReport, StateError> {
    validate_delivery_retention_request(operation_id, run_id, now)?;
    let mut transaction = self.pool.begin().await.map_err(scheduler_error)?;
    let rows = sqlx::query(
      "select delivery.delivery_id, delivery.job_id, delivery.state, delivery.payload_digest from scheduled_run_deliveries delivery join scheduled_runs run on run.run_id = delivery.run_id and run.job_id = delivery.job_id where delivery.run_id = ?1 and delivery.authority_kind = 'intent_v1' and delivery.payload_snapshot is not null and delivery.state in ('delivered', 'failed_terminal', 'skipped_none', 'skipped_unchanged') and delivery.updated_at <= ?2 and run.state = 'succeeded' and run.result_artifact_id is not null and run.updated_at <= ?2 and not exists (select 1 from scheduled_execution_baselines baseline where baseline.source_run_id = run.run_id and baseline.job_id = run.job_id) order by delivery.delivery_id",
    )
    .bind(run_id)
    .bind(now)
    .fetch_all(&mut *transaction)
    .await
    .map_err(scheduler_error)?;
    let total_deliveries: i64 =
      sqlx::query_scalar("select count(*) from scheduled_run_deliveries where run_id = ?1")
        .bind(run_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(scheduler_error)?;
    if rows.is_empty() || i64::try_from(rows.len()).ok() != Some(total_deliveries) {
      return Err(StateError::ScheduledDeliveryRetentionConflict);
    }
    for row in &rows {
      sqlx::query(
        "insert into scheduled_delivery_retention_audit (operation_id, delivery_id, run_id, job_id, delivery_state, payload_digest, authorized_at) values (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
      )
      .bind(operation_id)
      .bind(row.try_get::<String, _>("delivery_id").map_err(scheduler_error)?)
      .bind(run_id)
      .bind(row.try_get::<String, _>("job_id").map_err(scheduler_error)?)
      .bind(row.try_get::<String, _>("state").map_err(scheduler_error)?)
      .bind(row.try_get::<String, _>("payload_digest").map_err(scheduler_error)?)
      .bind(now)
      .execute(&mut *transaction)
      .await
      .map_err(scheduler_error)?;
    }
    let delivery_attempts = sqlx::query(
      "delete from scheduled_delivery_attempts where delivery_id in (select delivery_id from scheduled_run_deliveries where run_id = ?1)",
    )
    .bind(run_id)
    .execute(&mut *transaction)
    .await
    .map_err(scheduler_error)?
    .rows_affected();
    let deliveries = sqlx::query("delete from scheduled_run_deliveries where run_id = ?1")
      .bind(run_id)
      .execute(&mut *transaction)
      .await
      .map_err(scheduler_error)?
      .rows_affected();
    let late_evidence = sqlx::query("delete from scheduled_run_late_evidence where run_id = ?1")
      .bind(run_id)
      .execute(&mut *transaction)
      .await
      .map_err(scheduler_error)?
      .rows_affected();
    let result_artifacts =
      sqlx::query("delete from scheduled_run_result_artifacts where run_id = ?1")
        .bind(run_id)
        .execute(&mut *transaction)
        .await
        .map_err(scheduler_error)?
        .rows_affected();
    let run_attempts = sqlx::query("delete from scheduled_run_attempts where run_id = ?1")
      .bind(run_id)
      .execute(&mut *transaction)
      .await
      .map_err(scheduler_error)?
      .rows_affected();
    let runs = sqlx::query("delete from scheduled_runs where run_id = ?1")
      .bind(run_id)
      .execute(&mut *transaction)
      .await
      .map_err(scheduler_error)?
      .rows_affected();
    if deliveries != u64::try_from(total_deliveries).unwrap_or(u64::MAX)
      || result_artifacts != 1
      || runs != 1
    {
      return Err(StateError::ScheduledDeliveryRetentionConflict);
    }
    sqlx::query(
      "update scheduled_delivery_retention_audit set attempts_deleted = ?1, completed_at = ?2 where operation_id = ?3 and run_id = ?4 and completed_at is null",
    )
    .bind(i64::try_from(delivery_attempts).unwrap_or(i64::MAX))
    .bind(now)
    .bind(operation_id)
    .bind(run_id)
    .execute(&mut *transaction)
    .await
    .map_err(scheduler_error)?;
    transaction.commit().await.map_err(scheduler_error)?;
    Ok(ScheduledDeliveryRetentionReport {
      delivery_attempts,
      deliveries,
      late_evidence,
      run_attempts,
      result_artifacts,
      runs,
    })
  }

  /// Atomically accepts a live execution result, advances its execution baseline, and records
  /// immutable delivery intents derived from the materialized run snapshot.
  ///
  /// A stale or repeated binding can only append bounded late evidence. It cannot change result,
  /// baseline, delivery, attempt, or run authority.
  ///
  /// # Errors
  /// Returns an error for invalid result data, malformed persisted snapshots, authority conflicts,
  /// or storage failures. Every current-binding error rolls back the complete success transaction.
  #[allow(
    clippy::too_many_lines,
    reason = "keeps the ordered terminal authority transaction auditable in one scope"
  )]
  pub async fn complete_scheduled_run_success(
    &self,
    binding: &RunLeaseBinding,
    result: &ScheduledRunResult,
    completed_at: i64,
  ) -> Result<ScheduledRunSuccessOutcome, StateError> {
    validate_lease_binding(binding)?;
    if completed_at < 0 {
      return Err(StateError::InvalidSchedulerState {
        reason: "scheduled completion timestamp must be nonnegative".to_owned(),
      });
    }
    validate_text("scheduled result summary", &result.summary).map_err(invalid_value)?;
    if result.previous_success_context.len() > MAX_CONTEXT_BYTES {
      return Err(StateError::InvalidSchedulerState {
        reason: "scheduled result previous success context exceeds its storage bound".to_owned(),
      });
    }
    let result_json = json!({
      "schema_version": 1,
      "summary": result.summary,
    })
    .to_string();
    let result_hash = sha256_hex(result_json.as_bytes());
    let artifact_id = format!(
      "result:{}",
      digest_identity(&[
        "scheduled-result-artifact-v1",
        binding.run_id(),
        &binding.attempt().to_string(),
        &binding.fence().to_string(),
      ])
    );
    let mut transaction = self.pool.begin().await.map_err(scheduler_error)?;
    let row = sqlx::query(
      "select r.targets_json, r.execution_baseline_json, r.lease_expires_at, a.claimed_at, a.executing_at from scheduled_runs r join scheduled_run_attempts a on a.run_id = r.run_id and a.job_id = r.job_id and a.attempt = r.attempt and a.fence = r.fence and a.lease_owner = r.lease_owner where r.run_id = ?1 and r.job_id = ?2 and r.attempt = ?3 and r.fence = ?4 and r.lease_owner = ?5 and r.state = 'executing' and a.state = 'executing' and r.lease_expires_at > ?6 and a.lease_expires_at > ?6",
    )
    .bind(binding.run_id())
    .bind(binding.job_id())
    .bind(binding.attempt())
    .bind(binding.fence())
    .bind(binding.lease_owner())
    .bind(completed_at)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(scheduler_error)?;
    let Some(row) = row else {
      let evidence = append_late_evidence_in_transaction(
        &mut transaction,
        binding,
        ScheduledRunLateEvidenceKind::CompletionAfterLeaseLoss,
        &result_hash,
        completed_at,
      )
      .await?;
      transaction.commit().await.map_err(scheduler_error)?;
      return Ok(ScheduledRunSuccessOutcome::LateEvidence(evidence));
    };
    let claimed_at: i64 = row.try_get("claimed_at").map_err(scheduler_error)?;
    let executing_at: i64 = row
      .try_get::<Option<i64>, _>("executing_at")
      .map_err(scheduler_error)?
      .ok_or_else(|| StateError::InvalidSchedulerState {
        reason: "executing scheduled attempt has no execution timestamp".to_owned(),
      })?;
    if completed_at < claimed_at || completed_at < executing_at {
      return Err(StateError::InvalidSchedulerState {
        reason: "scheduled completion precedes its accepted execution".to_owned(),
      });
    }
    let delivery_policy_version = DELIVERY_POLICY_VERSION_V1;
    let targets_json: String = row.try_get("targets_json").map_err(scheduler_error)?;
    let targets = delivery_intent_targets(&targets_json)?;
    let execution_baseline_json: String = row
      .try_get::<Option<String>, _>("execution_baseline_json")
      .map_err(scheduler_error)?
      .ok_or_else(|| StateError::InvalidSchedulerState {
        reason: "materialized run has no execution baseline snapshot".to_owned(),
      })?;
    let expected_baseline_version = execution_baseline_version(&execution_baseline_json)?;

    let artifact_insert = sqlx::query(
      "insert into scheduled_run_result_artifacts (artifact_id, run_id, job_id, accepted_attempt, accepted_fence, schema_version, result_json, hash_algorithm, result_hash, previous_success_context, completed_at, provenance, provenance_version) values (?1, ?2, ?3, ?4, ?5, 1, ?6, 'sha256-v1', ?7, ?8, ?9, 'native', 1)",
    )
    .bind(&artifact_id)
    .bind(binding.run_id())
    .bind(binding.job_id())
    .bind(binding.attempt())
    .bind(binding.fence())
    .bind(&result_json)
    .bind(&result_hash)
    .bind(&result.previous_success_context)
    .bind(completed_at)
    .execute(&mut *transaction)
    .await
    .map_err(completion_storage_error);
    if let Err(error) = artifact_insert {
      if matches!(error, StateError::ScheduledRunCompletionConflict) {
        return self
          .resolve_scheduled_run_completion_conflict(
            transaction,
            binding,
            &result_hash,
            completed_at,
          )
          .await;
      }
      return Err(error);
    }

    let baseline = UpdateExecutionBaseline {
      job_id: binding.job_id().to_owned(),
      expected_version: expected_baseline_version,
      hash_algorithm: "sha256-v1".to_owned(),
      result_hash: result_hash.clone(),
      previous_success_context: result.previous_success_context.clone(),
      source_run_id: binding.run_id().to_owned(),
      completed_at,
    };
    if !compare_and_swap_execution_baseline_in_transaction(&mut transaction, &baseline).await? {
      return self
        .resolve_scheduled_run_completion_conflict(transaction, binding, &result_hash, completed_at)
        .await;
    }

    for target in targets {
      let intent_key = delivery_intent_key(binding.run_id(), &target.identity_digest)?;
      let delivery_id = format!("intent:{intent_key}");
      let intent_insert = sqlx::query(
        "insert into scheduled_run_deliveries (delivery_id, run_id, job_id, target_identity_digest, target_json, state, attempt, fence, delivery_policy_version, result_artifact_id, result_attempt, result_fence, target_snapshot_digest_algorithm, target_snapshot_digest, intent_key, authority_kind, created_at, updated_at) values (?1, ?2, ?3, ?4, ?5, 'pending', 0, 0, ?6, ?7, ?8, ?9, 'sha256-v1', ?10, ?11, 'intent_v1', ?12, ?12) returning target_json, target_identity_digest, target_snapshot_digest_algorithm, target_snapshot_digest",
      )
      .bind(delivery_id)
      .bind(binding.run_id())
      .bind(binding.job_id())
      .bind(target.identity_digest)
      .bind(target.canonical_json)
      .bind(delivery_policy_version)
      .bind(&artifact_id)
      .bind(binding.attempt())
      .bind(binding.fence())
      .bind(target.snapshot_digest)
      .bind(intent_key)
      .bind(completed_at)
      .fetch_one(&mut *transaction)
      .await
      .map_err(completion_storage_error);
      let intent = match intent_insert {
        Ok(intent) => intent,
        Err(StateError::ScheduledRunCompletionConflict) => {
          return self
            .resolve_scheduled_run_completion_conflict(
              transaction,
              binding,
              &result_hash,
              completed_at,
            )
            .await;
        }
        Err(error) => return Err(error),
      };
      validate_delivery_intent_target_snapshot(
        intent.try_get("target_json").map_err(scheduler_error)?,
        intent
          .try_get("target_identity_digest")
          .map_err(scheduler_error)?,
        intent
          .try_get("target_snapshot_digest_algorithm")
          .map_err(scheduler_error)?,
        intent
          .try_get("target_snapshot_digest")
          .map_err(scheduler_error)?,
      )?;
    }

    let attempt = sqlx::query(
      "update scheduled_run_attempts set state = 'succeeded', completed_at = ?1 where run_id = ?2 and job_id = ?3 and attempt = ?4 and fence = ?5 and lease_owner = ?6 and state = 'executing' and lease_expires_at > ?1",
    )
    .bind(completed_at)
    .bind(binding.run_id())
    .bind(binding.job_id())
    .bind(binding.attempt())
    .bind(binding.fence())
    .bind(binding.lease_owner())
    .execute(&mut *transaction)
    .await
    .map_err(scheduler_error)?;
    if attempt.rows_affected() != 1 {
      return self
        .resolve_scheduled_run_completion_conflict(transaction, binding, &result_hash, completed_at)
        .await;
    }
    let run = sqlx::query(
      "update scheduled_runs set state = 'succeeded', overlap_slot = null, lease_owner = null, lease_expires_at = null, result_artifact_id = ?1, result_context = ?2, result_hash_algorithm = 'sha256-v1', result_hash = ?3, updated_at = ?4 where run_id = ?5 and job_id = ?6 and attempt = ?7 and fence = ?8 and lease_owner = ?9 and state = 'executing' and lease_expires_at > ?4",
    )
    .bind(&artifact_id)
    .bind(&result.previous_success_context)
    .bind(&result_hash)
    .bind(completed_at)
    .bind(binding.run_id())
    .bind(binding.job_id())
    .bind(binding.attempt())
    .bind(binding.fence())
    .bind(binding.lease_owner())
    .execute(&mut *transaction)
    .await
    .map_err(completion_storage_error);
    if matches!(run, Err(StateError::ScheduledRunCompletionConflict)) {
      return self
        .resolve_scheduled_run_completion_conflict(transaction, binding, &result_hash, completed_at)
        .await;
    }
    let run = run?;
    if run.rows_affected() != 1 {
      return self
        .resolve_scheduled_run_completion_conflict(transaction, binding, &result_hash, completed_at)
        .await;
    }
    transaction.commit().await.map_err(scheduler_error)?;
    Ok(ScheduledRunSuccessOutcome::Committed)
  }

  async fn resolve_scheduled_run_completion_conflict(
    &self,
    transaction: Transaction<'_, Sqlite>,
    binding: &RunLeaseBinding,
    evidence_sha256: &str,
    observed_at: i64,
  ) -> Result<ScheduledRunSuccessOutcome, StateError> {
    transaction.rollback().await.map_err(scheduler_error)?;
    let mut transaction = self.pool.begin().await.map_err(scheduler_error)?;
    let remains_current: i64 = sqlx::query_scalar(
      "select exists(select 1 from scheduled_runs r join scheduled_run_attempts a on a.run_id = r.run_id and a.job_id = r.job_id and a.attempt = r.attempt and a.fence = r.fence and a.lease_owner = r.lease_owner where r.run_id = ?1 and r.job_id = ?2 and r.attempt = ?3 and r.fence = ?4 and r.lease_owner = ?5 and r.state = 'executing' and a.state = 'executing' and r.lease_expires_at > ?6 and a.lease_expires_at > ?6)",
    )
    .bind(binding.run_id())
    .bind(binding.job_id())
    .bind(binding.attempt())
    .bind(binding.fence())
    .bind(binding.lease_owner())
    .bind(observed_at)
    .fetch_one(&mut *transaction)
    .await
    .map_err(scheduler_error)?;
    if remains_current != 0 {
      transaction.commit().await.map_err(scheduler_error)?;
      return Err(StateError::ScheduledRunCompletionConflict);
    }
    let evidence = append_late_evidence_in_transaction(
      &mut transaction,
      binding,
      ScheduledRunLateEvidenceKind::CompletionAfterLeaseLoss,
      evidence_sha256,
      observed_at,
    )
    .await?;
    transaction.commit().await.map_err(scheduler_error)?;
    Ok(ScheduledRunSuccessOutcome::LateEvidence(evidence))
  }

  /// Records a preflight failure without allowing the run to enter executing.
  ///
  /// # Errors
  /// Returns `ScheduledRunLostLease` for a stale binding or an error for invalid retry data.
  pub async fn record_scheduled_run_preflight_failure(
    &self,
    binding: &RunLeaseBinding,
    disposition: PreflightFailureDisposition,
    error_kind: &str,
    error_message: &str,
    now: i64,
  ) -> Result<(), StateError> {
    validate_lease_binding(binding)?;
    validate_text("scheduled preflight error kind", error_kind).map_err(invalid_value)?;
    if error_message.len() > MAX_CONTEXT_BYTES {
      return Err(StateError::InvalidSchedulerState {
        reason: "scheduled preflight error exceeds its storage bound".to_owned(),
      });
    }
    let (run_state, attempt_state, retry_at, overlap_slot) = match disposition {
      PreflightFailureDisposition::RetryAt(retry_at) if retry_at > now => {
        ("pending", "retry_scheduled", Some(retry_at), Some(1_i64))
      }
      PreflightFailureDisposition::RetryAt(_) => {
        return Err(StateError::InvalidSchedulerState {
          reason: "scheduled preflight retry must be later than now".to_owned(),
        });
      }
      PreflightFailureDisposition::Fail => ("failed", "preflight_rejected", None, None),
    };
    let mut transaction = self.pool.begin().await.map_err(scheduler_error)?;
    let run = sqlx::query(
      "update scheduled_runs set state = ?1, next_attempt_at = ?2, lease_owner = null, lease_expires_at = null, overlap_slot = ?3, error_kind = case when ?1 = 'failed' then ?4 else null end, error_message = case when ?1 = 'failed' then ?5 else null end, updated_at = ?6 where run_id = ?7 and job_id = ?8 and attempt = ?9 and fence = ?10 and lease_owner = ?11 and state = 'leased' and lease_expires_at > ?6",
    )
    .bind(run_state)
    .bind(retry_at)
    .bind(overlap_slot)
    .bind(error_kind)
    .bind(error_message)
    .bind(now)
    .bind(binding.run_id())
    .bind(binding.job_id())
    .bind(binding.attempt())
    .bind(binding.fence())
    .bind(binding.lease_owner())
    .execute(&mut *transaction)
    .await
    .map_err(scheduler_error)?;
    if run.rows_affected() != 1 {
      return Err(StateError::ScheduledRunLostLease);
    }
    let attempt = sqlx::query(
      "update scheduled_run_attempts set state = ?1, preflight_completed_at = ?2, completed_at = ?2, error_kind = ?3, error_message = ?4 where run_id = ?5 and job_id = ?6 and attempt = ?7 and fence = ?8 and lease_owner = ?9 and state = 'leased' and lease_expires_at > ?2",
    )
    .bind(attempt_state)
    .bind(now)
    .bind(error_kind)
    .bind(error_message)
    .bind(binding.run_id())
    .bind(binding.job_id())
    .bind(binding.attempt())
    .bind(binding.fence())
    .bind(binding.lease_owner())
    .execute(&mut *transaction)
    .await
    .map_err(scheduler_error)?;
    if attempt.rows_affected() != 1 {
      return Err(StateError::ScheduledRunLostLease);
    }
    transaction.commit().await.map_err(scheduler_error)
  }

  /// Records a fenced execution failure, retry, or terminal uncertainty atomically.
  ///
  /// Post-dispatch retries require a current, hash-valid, version-one side-effect-free attestation.
  /// A stale binding can only append diagnostic late evidence.
  ///
  /// # Errors
  /// Returns an error for invalid policy data, malformed persisted authority, or storage failure.
  pub async fn record_scheduled_run_execution_outcome(
    &self,
    binding: &RunLeaseBinding,
    disposition: ScheduledExecutionDisposition,
    error_kind: &str,
    error_message: &str,
    now: i64,
  ) -> Result<ScheduledRunExecutionOutcome, StateError> {
    validate_lease_binding(binding)?;
    validate_text("scheduled execution error kind", error_kind).map_err(invalid_value)?;
    if error_message.len() > MAX_CONTEXT_BYTES {
      return Err(StateError::InvalidSchedulerState {
        reason: "scheduled execution error exceeds its storage bound".to_owned(),
      });
    }
    if let ScheduledExecutionDisposition::RetryAt {
      retry_at,
      max_attempts,
      ..
    } = disposition
      && (retry_at <= now || max_attempts <= 0)
    {
      return Err(StateError::InvalidSchedulerState {
        reason: "invalid scheduled execution retry policy".to_owned(),
      });
    }

    let evidence_sha256 = sha256_hex(
      format!(
        "scheduled-execution-outcome-v1\n{}\n{}\n{}\n{}",
        binding.run_id(),
        binding.attempt(),
        error_kind,
        error_message
      )
      .as_bytes(),
    );
    let mut transaction = self.pool.begin().await.map_err(scheduler_error)?;
    let row = sqlx::query(
      "select r.schedule_id, r.job_generation, r.schedule_generation, r.scheduled_for, r.coalesced_through, r.definition_version, r.definition_json, r.capability_schema_version, r.capability_digest, r.capability_json, r.targets_json, r.execution_baseline_json, a.attested_profile_schema_version, a.attested_profile_json, a.attested_profile_hash_algorithm, a.attested_profile_digest from scheduled_runs r join scheduled_run_attempts a on a.run_id = r.run_id and a.job_id = r.job_id and a.attempt = r.attempt and a.fence = r.fence and a.lease_owner = r.lease_owner where r.run_id = ?1 and r.job_id = ?2 and r.attempt = ?3 and r.fence = ?4 and r.lease_owner = ?5 and r.state = 'executing' and a.state = 'executing' and r.lease_expires_at > ?6 and a.lease_expires_at > ?6",
    )
    .bind(binding.run_id())
    .bind(binding.job_id())
    .bind(binding.attempt())
    .bind(binding.fence())
    .bind(binding.lease_owner())
    .bind(now)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(scheduler_error)?;
    let Some(row) = row else {
      let evidence = append_late_evidence_in_transaction(
        &mut transaction,
        binding,
        ScheduledRunLateEvidenceKind::CompletionAfterLeaseLoss,
        &evidence_sha256,
        now,
      )
      .await?;
      transaction.commit().await.map_err(scheduler_error)?;
      return Ok(ScheduledRunExecutionOutcome::LateEvidence(evidence));
    };

    let transition = execution_outcome_transition(binding, disposition, &row, now)?;
    let run = sqlx::query(
      "update scheduled_runs set state = ?1, next_attempt_at = ?2, lease_owner = null, lease_expires_at = null, overlap_slot = ?3, error_kind = case when ?1 = 'pending' then null else ?4 end, error_message = case when ?1 = 'pending' then null else ?5 end, updated_at = ?6 where run_id = ?7 and job_id = ?8 and attempt = ?9 and fence = ?10 and lease_owner = ?11 and state = 'executing' and lease_expires_at > ?6",
    )
    .bind(transition.run_state)
    .bind(transition.retry_at)
    .bind(transition.overlap_slot)
    .bind(error_kind)
    .bind(error_message)
    .bind(now)
    .bind(binding.run_id())
    .bind(binding.job_id())
    .bind(binding.attempt())
    .bind(binding.fence())
    .bind(binding.lease_owner())
    .execute(&mut *transaction)
    .await
    .map_err(scheduler_error)?;
    if run.rows_affected() != 1 {
      return Err(StateError::ScheduledRunLostLease);
    }
    let attempt = sqlx::query(
      "update scheduled_run_attempts set state = ?1, completed_at = ?2, error_kind = ?3, error_message = ?4 where run_id = ?5 and job_id = ?6 and attempt = ?7 and fence = ?8 and lease_owner = ?9 and state = 'executing' and lease_expires_at > ?2",
    )
    .bind(transition.attempt_state)
    .bind(now)
    .bind(error_kind)
    .bind(error_message)
    .bind(binding.run_id())
    .bind(binding.job_id())
    .bind(binding.attempt())
    .bind(binding.fence())
    .bind(binding.lease_owner())
    .execute(&mut *transaction)
    .await
    .map_err(scheduler_error)?;
    if attempt.rows_affected() != 1 {
      return Err(StateError::ScheduledRunLostLease);
    }
    transaction.commit().await.map_err(scheduler_error)?;
    Ok(transition.outcome)
  }

  /// Reclaims one expired lease without retrying an execution of unknown convergence.
  ///
  /// # Errors
  /// Returns an error for invalid retry policy or storage failure.
  pub async fn reclaim_next_expired_scheduled_run(
    &self,
    now: i64,
    max_attempts: i64,
    next_attempt_at: i64,
  ) -> Result<ExpiredRunReclaimOutcome, StateError> {
    if max_attempts <= 0 || next_attempt_at <= now {
      return Err(StateError::InvalidSchedulerState {
        reason: "invalid scheduled run reclaim policy".to_owned(),
      });
    }
    let mut transaction = self.pool.begin().await.map_err(scheduler_error)?;
    let row = sqlx::query(
      "select r.run_id, r.job_id, r.attempt, r.fence, r.lease_owner, r.state, r.schedule_id, r.job_generation, r.schedule_generation, r.scheduled_for, r.coalesced_through, r.definition_version, r.definition_json, r.capability_schema_version, r.capability_digest, r.capability_json, r.targets_json, r.execution_baseline_json, a.attested_profile_schema_version, a.attested_profile_json, a.attested_profile_hash_algorithm, a.attested_profile_digest from scheduled_runs r indexed by idx_scheduled_runs_recovery join scheduled_run_attempts a on a.run_id = r.run_id and a.job_id = r.job_id and a.attempt = r.attempt and a.fence = r.fence and a.lease_owner = r.lease_owner and a.state = r.state where r.state in ('leased', 'executing') and r.lease_expires_at <= ?1 and a.lease_expires_at <= ?1 order by r.lease_expires_at, r.run_id limit 1",
    )
    .bind(now)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(scheduler_error)?;
    let Some(row) = row else {
      transaction.commit().await.map_err(scheduler_error)?;
      return Ok(ExpiredRunReclaimOutcome::Idle);
    };
    let run_id: String = row.try_get("run_id").map_err(scheduler_error)?;
    let job_id: String = row.try_get("job_id").map_err(scheduler_error)?;
    let attempt: i64 = row.try_get("attempt").map_err(scheduler_error)?;
    let fence: i64 = row.try_get("fence").map_err(scheduler_error)?;
    let lease_owner: String = row.try_get("lease_owner").map_err(scheduler_error)?;
    let state: String = row.try_get("state").map_err(scheduler_error)?;
    let binding = RunLeaseBinding {
      run_id: run_id.clone(),
      job_id: job_id.clone(),
      attempt,
      fence,
      lease_owner: lease_owner.clone(),
    };
    let safe_execution_retry =
      state == "executing" && persisted_profile_allows_recovery(&binding, &row)?;
    let transition = expired_reclaim_transition(
      &state,
      &run_id,
      attempt,
      fence,
      max_attempts,
      safe_execution_retry,
    );
    let retry_at = (transition.run_state == "pending").then_some(next_attempt_at);
    let updated = sqlx::query(
      "update scheduled_runs set state = ?1, next_attempt_at = ?2, lease_owner = null, lease_expires_at = null, overlap_slot = ?3, error_kind = case when ?1 in ('failed', 'outcome_unknown') then ?4 else null end, error_message = case when ?1 in ('failed', 'outcome_unknown') then ?4 else null end, updated_at = ?5 where run_id = ?6 and job_id = ?7 and attempt = ?8 and fence = ?9 and lease_owner = ?10 and state = ?11 and lease_expires_at <= ?5",
    )
    .bind(transition.run_state)
    .bind(retry_at)
    .bind(transition.overlap_slot)
    .bind(transition.error_kind)
    .bind(now)
    .bind(&run_id)
    .bind(&job_id)
    .bind(attempt)
    .bind(fence)
    .bind(&lease_owner)
    .bind(&state)
    .execute(&mut *transaction)
    .await
    .map_err(scheduler_error)?;
    if updated.rows_affected() != 1 {
      return Err(StateError::ScheduledRunLostLease);
    }
    let attempt_updated = sqlx::query(
      "update scheduled_run_attempts set state = ?1, completed_at = ?2, error_kind = ?3, error_message = ?3 where run_id = ?4 and job_id = ?5 and attempt = ?6 and fence = ?7 and lease_owner = ?8 and state = ?9 and lease_expires_at <= ?2",
    )
    .bind(transition.attempt_state)
    .bind(now)
    .bind(transition.error_kind)
    .bind(&run_id)
    .bind(&job_id)
    .bind(attempt)
    .bind(fence)
    .bind(&lease_owner)
    .bind(&state)
    .execute(&mut *transaction)
    .await
    .map_err(scheduler_error)?;
    if attempt_updated.rows_affected() != 1 {
      return Err(StateError::ScheduledRunLostLease);
    }
    transaction.commit().await.map_err(scheduler_error)?;
    Ok(transition.outcome)
  }

  /// Appends bounded typed evidence produced after a worker has lost its lease.
  ///
  /// This evidence is diagnostic only and cannot transition a run or accepted result authority.
  ///
  /// # Errors
  /// Returns an error for an invalid digest, unknown attempt binding, or storage failure.
  pub async fn append_scheduled_run_late_evidence(
    &self,
    binding: &RunLeaseBinding,
    kind: ScheduledRunLateEvidenceKind,
    evidence_sha256: &str,
    observed_at: i64,
  ) -> Result<LateEvidenceAppendOutcome, StateError> {
    validate_lease_binding(binding)?;
    if evidence_sha256.len() != 64
      || !evidence_sha256
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
      return Err(StateError::InvalidSchedulerState {
        reason: "scheduled late evidence digest must be lowercase sha256".to_owned(),
      });
    }
    let mut transaction = self.pool.begin().await.map_err(scheduler_error)?;
    let outcome = append_late_evidence_in_transaction(
      &mut transaction,
      binding,
      kind,
      evidence_sha256,
      observed_at,
    )
    .await?;
    transaction.commit().await.map_err(scheduler_error)?;
    Ok(outcome)
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
      "update scheduled_execution_baselines set baseline_version = baseline_version + 1, hash_algorithm = ?1, result_hash = ?2, previous_success_context = ?3, source_run_id = ?4, completed_at = ?5 where job_id = ?6 and baseline_version = ?7 and baseline_version < 9223372036854775807",
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

fn validate_delivery_preparation(
  delivery_id: &str,
  content_type: &str,
  body: &str,
  render_version: u32,
  now: i64,
) -> Result<(), StateError> {
  validate_text("scheduled delivery id", delivery_id).map_err(invalid_value)?;
  validate_text("scheduled delivery content type", content_type).map_err(invalid_value)?;
  if body.is_empty() || body.len() > MAX_SNAPSHOT_BYTES || render_version == 0 || now < 0 {
    return Err(StateError::InvalidSchedulerState {
      reason: "invalid scheduled delivery payload preparation".to_owned(),
    });
  }
  Ok(())
}

async fn delivery_baseline_decision(
  transaction: &mut Transaction<'_, Sqlite>,
  delivery: &SqliteRow,
  render_version: u32,
  payload_digest: &str,
  skipped_none: bool,
) -> Result<(i64, bool), StateError> {
  let baseline = sqlx::query(
    "select baseline_version, accepted_payload_digest from scheduled_delivery_baselines where job_id = ?1 and target_identity_digest = ?2 and target_snapshot_digest_algorithm = ?3 and target_snapshot_digest = ?4 and delivery_policy_version = ?5 and render_version = ?6 and hash_algorithm = ?7",
  )
  .bind(delivery.try_get::<String, _>("job_id").map_err(scheduler_error)?)
  .bind(
    delivery
      .try_get::<String, _>("target_identity_digest")
      .map_err(scheduler_error)?,
  )
  .bind(
    delivery
      .try_get::<String, _>("target_snapshot_digest_algorithm")
      .map_err(scheduler_error)?,
  )
  .bind(
    delivery
      .try_get::<String, _>("target_snapshot_digest")
      .map_err(scheduler_error)?,
  )
  .bind(
    delivery
      .try_get::<i64, _>("delivery_policy_version")
      .map_err(scheduler_error)?,
  )
  .bind(i64::from(render_version))
  .bind(DELIVERY_PAYLOAD_HASH_ALGORITHM)
  .fetch_optional(&mut **transaction)
  .await
  .map_err(scheduler_error)?;
  let version = baseline
    .as_ref()
    .map(|row| row.try_get("baseline_version").map_err(scheduler_error))
    .transpose()?
    .unwrap_or(0);
  let unchanged = !skipped_none
    && baseline
      .as_ref()
      .map(|row| {
        row
          .try_get::<String, _>("accepted_payload_digest")
          .map(|accepted| accepted == payload_digest)
          .map_err(scheduler_error)
      })
      .transpose()?
      .unwrap_or(false);
  Ok((version, unchanged))
}

fn validate_delivery_retention_request(
  operation_id: &str,
  run_id: &str,
  now: i64,
) -> Result<(), StateError> {
  validate_text("scheduled delivery retention operation", operation_id).map_err(invalid_value)?;
  validate_text("scheduled delivery retention run id", run_id).map_err(invalid_value)?;
  if now < 0 {
    return Err(StateError::InvalidSchedulerState {
      reason: "scheduled delivery retention timestamp must be nonnegative".to_owned(),
    });
  }
  Ok(())
}

fn delivery_target_metadata(row: &SqliteRow) -> Result<(bool, u32), StateError> {
  let target_json: String = row.try_get("target_json").map_err(scheduler_error)?;
  let target: Value = serde_json::from_str(&target_json).map_err(invalid_json)?;
  let target_kind = target.get("kind").and_then(Value::as_str).ok_or_else(|| {
    StateError::InvalidSchedulerState {
      reason: "scheduled delivery target has no kind".to_owned(),
    }
  })?;
  let target_snapshot_version = target
    .get("resolver_version")
    .and_then(Value::as_i64)
    .map(positive_u32)
    .transpose()?
    .ok_or_else(|| StateError::InvalidSchedulerState {
      reason: "scheduled delivery target has no resolver version".to_owned(),
    })?;
  Ok((target_kind == "none", target_snapshot_version))
}

fn existing_prepared_delivery(
  row: &SqliteRow,
  body: &str,
  content_type: &str,
  render_version: u32,
) -> Result<Option<PreparedScheduledDelivery>, StateError> {
  let existing_payload: Option<Vec<u8>> =
    row.try_get("payload_snapshot").map_err(scheduler_error)?;
  if existing_payload.is_none() {
    return Ok(None);
  }
  let snapshot = delivery_payload_from_row(row)?;
  if snapshot.body() != body
    || snapshot.content_type() != content_type
    || snapshot.render_version() != render_version
  {
    return Err(StateError::ScheduledDeliveryPayloadConflict);
  }
  let state: String = row.try_get("state").map_err(scheduler_error)?;
  match state.as_str() {
    "pending" => Ok(Some(PreparedScheduledDelivery::Pending(snapshot))),
    "skipped_none" => Ok(Some(PreparedScheduledDelivery::SkippedNone(snapshot))),
    "skipped_unchanged" => Ok(Some(PreparedScheduledDelivery::SkippedUnchanged(snapshot))),
    _ => Err(StateError::ScheduledDeliveryPayloadConflict),
  }
}

fn delivery_payload_from_row(row: &SqliteRow) -> Result<DeliveryPayloadSnapshot, StateError> {
  let payload: Vec<u8> = row.try_get("payload_snapshot").map_err(scheduler_error)?;
  let body = String::from_utf8(payload).map_err(|_| StateError::InvalidSchedulerState {
    reason: "scheduled delivery payload is not valid UTF-8".to_owned(),
  })?;
  let persisted_digest: String = row.try_get("payload_digest").map_err(scheduler_error)?;
  if sha256_hex(body.as_bytes()) != persisted_digest {
    return Err(StateError::InvalidSchedulerState {
      reason: "scheduled delivery payload digest mismatch".to_owned(),
    });
  }
  let schema_version = positive_u32(
    row
      .try_get::<i64, _>("payload_schema_version")
      .map_err(scheduler_error)?,
  )?;
  if schema_version != DELIVERY_PAYLOAD_SCHEMA_VERSION {
    return Err(StateError::InvalidSchedulerState {
      reason: "unsupported scheduled delivery payload schema".to_owned(),
    });
  }
  let hash_algorithm: String = row.try_get("hash_algorithm").map_err(scheduler_error)?;
  if hash_algorithm != DELIVERY_PAYLOAD_HASH_ALGORITHM {
    return Err(StateError::InvalidSchedulerState {
      reason: "unsupported scheduled delivery payload hash algorithm".to_owned(),
    });
  }
  DeliveryPayloadSnapshot::from_durable_parts(
    row.try_get("delivery_id").map_err(scheduler_error)?,
    row.try_get("run_id").map_err(scheduler_error)?,
    row.try_get("result_artifact_id").map_err(scheduler_error)?,
    row.try_get("content_type").map_err(scheduler_error)?,
    body,
    persisted_digest,
    row
      .try_get("target_identity_digest")
      .map_err(scheduler_error)?,
    row
      .try_get("target_snapshot_digest")
      .map_err(scheduler_error)?,
    positive_u32(
      row
        .try_get::<i64, _>("target_snapshot_version")
        .map_err(scheduler_error)?,
    )?,
    positive_u32(
      row
        .try_get::<i64, _>("delivery_policy_version")
        .map_err(scheduler_error)?,
    )?,
    positive_u32(
      row
        .try_get::<i64, _>("render_version")
        .map_err(scheduler_error)?,
    )?,
    row.try_get("payload_created_at").map_err(scheduler_error)?,
  )
  .map_err(invalid_value)
}

fn delivery_body_from_result_json(result_json: &str) -> Result<String, StateError> {
  let Value::Object(mut result) = serde_json::from_str(result_json).map_err(invalid_json)? else {
    return Err(StateError::InvalidSchedulerState {
      reason: "scheduled result artifact is not an object".to_owned(),
    });
  };
  if result.len() != 2
    || result
      .remove("schema_version")
      .and_then(|value| value.as_u64())
      != Some(1)
  {
    return Err(StateError::InvalidSchedulerState {
      reason: "scheduled result artifact has an unsupported schema".to_owned(),
    });
  }
  let Some(Value::String(body)) = result.remove("summary") else {
    return Err(StateError::InvalidSchedulerState {
      reason: "scheduled result artifact has no summary".to_owned(),
    });
  };
  validate_text("scheduled result summary", &body).map_err(invalid_value)?;
  Ok(body)
}

fn validate_delivery_binding(binding: &ScheduledDeliveryBinding) -> Result<(), StateError> {
  validate_text("scheduled delivery id", binding.delivery_id()).map_err(invalid_value)?;
  validate_text("scheduled delivery lease owner", binding.lease_owner()).map_err(invalid_value)?;
  validate_text(
    "scheduled delivery idempotency key",
    binding.idempotency_key(),
  )
  .map_err(invalid_value)?;
  if binding.attempt() <= 0 || binding.fence() <= 0 {
    return Err(StateError::InvalidSchedulerState {
      reason: "invalid scheduled delivery binding counters".to_owned(),
    });
  }
  Ok(())
}

fn validate_delivery_error(error_kind: &str, message: Option<&str>) -> Result<(), StateError> {
  validate_text("scheduled delivery error kind", error_kind).map_err(invalid_value)?;
  if message.is_some_and(|message| message.len() > MAX_DELIVERY_ERROR_MESSAGE_BYTES) {
    return Err(StateError::InvalidSchedulerState {
      reason: "scheduled delivery error message exceeds its storage bound".to_owned(),
    });
  }
  Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn transition_delivery_terminal(
  transaction: &mut Transaction<'_, Sqlite>,
  binding: &ScheduledDeliveryBinding,
  state: &str,
  provider_outcome: &str,
  provider_receipt: Option<&str>,
  error_kind: Option<&str>,
  error_message: Option<&str>,
  next_attempt_at: Option<i64>,
  completed_at: i64,
) -> Result<(), StateError> {
  if completed_at < 0 {
    return Err(StateError::InvalidSchedulerState {
      reason: "scheduled delivery completion timestamp must be nonnegative".to_owned(),
    });
  }
  let delivery = sqlx::query(
    "update scheduled_run_deliveries set state = ?1, next_attempt_at = ?2, lease_owner = null, lease_expires_at = null, provider_receipt = ?3, provider_outcome = ?4, error_kind = ?5, error_message = ?6, updated_at = ?7 where delivery_id = ?8 and state = 'sending' and attempt = ?9 and fence = ?10 and lease_owner = ?11 and idempotency_key = ?12 and lease_expires_at > ?7 and updated_at <= ?7",
  )
  .bind(state)
  .bind(next_attempt_at)
  .bind(provider_receipt)
  .bind(provider_outcome)
  .bind(error_kind)
  .bind(error_message)
  .bind(completed_at)
  .bind(binding.delivery_id())
  .bind(binding.attempt())
  .bind(binding.fence())
  .bind(binding.lease_owner())
  .bind(binding.idempotency_key())
  .execute(&mut **transaction)
  .await
  .map_err(scheduler_error)?;
  let attempt = sqlx::query(
    "update scheduled_delivery_attempts set state = ?1, provider_receipt = ?2, provider_outcome = ?3, error_kind = ?4, error_message = ?5, completed_at = ?6 where delivery_id = ?7 and attempt = ?8 and fence = ?9 and lease_owner = ?10 and idempotency_key = ?11 and state = 'sending' and lease_expires_at > ?6 and started_at <= ?6",
  )
  .bind(state)
  .bind(provider_receipt)
  .bind(provider_outcome)
  .bind(error_kind)
  .bind(error_message)
  .bind(completed_at)
  .bind(binding.delivery_id())
  .bind(binding.attempt())
  .bind(binding.fence())
  .bind(binding.lease_owner())
  .bind(binding.idempotency_key())
  .execute(&mut **transaction)
  .await
  .map_err(scheduler_error)?;
  if delivery.rows_affected() != 1 || attempt.rows_affected() != 1 {
    return Err(StateError::ScheduledDeliveryLostLease);
  }
  Ok(())
}

async fn advance_accepted_delivery_baseline_in_transaction(
  transaction: &mut Transaction<'_, Sqlite>,
  delivery_id: &str,
  accepted_at: i64,
) -> Result<bool, StateError> {
  let expected_version: i64 = sqlx::query_scalar(
    "select case when delivery.state = 'skipped_none' then delivery.expected_baseline_version else attempt.claimed_baseline_version end from scheduled_run_deliveries delivery left join scheduled_delivery_attempts attempt on attempt.delivery_id = delivery.delivery_id and attempt.attempt = delivery.attempt and attempt.fence = delivery.fence where delivery.delivery_id = ?1 and delivery.authority_kind = 'intent_v1' and delivery.payload_snapshot is not null and ((delivery.state = 'skipped_none' and json_extract(delivery.target_json, '$.kind') = 'none' and delivery.claimed_baseline_version is null) or (delivery.state = 'delivered' and delivery.claimed_baseline_version = attempt.claimed_baseline_version and attempt.state = 'delivered'))",
  )
  .bind(delivery_id)
  .fetch_optional(&mut **transaction)
  .await
  .map_err(scheduler_error)?
  .ok_or_else(|| StateError::InvalidSchedulerState {
    reason: "scheduled delivery is not accepted terminal authority".to_owned(),
  })?;
  let result = sqlx::query(
    "insert into scheduled_delivery_baselines (job_id, target_identity_digest, target_snapshot_digest_algorithm, target_snapshot_digest, delivery_policy_version, render_version, hash_algorithm, accepted_payload_digest, source_delivery_id, source_run_id, source_result_id, source_result_hash, accepted_at, baseline_version) select delivery.job_id, delivery.target_identity_digest, delivery.target_snapshot_digest_algorithm, delivery.target_snapshot_digest, delivery.delivery_policy_version, delivery.render_version, delivery.hash_algorithm, delivery.payload_digest, delivery.delivery_id, delivery.run_id, delivery.result_artifact_id, artifact.result_hash, ?2, 1 from scheduled_run_deliveries delivery join scheduled_run_result_artifacts artifact on artifact.artifact_id = delivery.result_artifact_id and artifact.run_id = delivery.run_id and artifact.job_id = delivery.job_id where delivery.delivery_id = ?1 and delivery.authority_kind = 'intent_v1' and delivery.payload_snapshot is not null and (delivery.state = 'delivered' or (delivery.state = 'skipped_none' and json_extract(delivery.target_json, '$.kind') = 'none')) and (?3 = 0 or (?3 < 9223372036854775807 and exists (select 1 from scheduled_delivery_baselines baseline where baseline.job_id = delivery.job_id and baseline.target_identity_digest = delivery.target_identity_digest and baseline.target_snapshot_digest_algorithm = delivery.target_snapshot_digest_algorithm and baseline.target_snapshot_digest = delivery.target_snapshot_digest and baseline.delivery_policy_version = delivery.delivery_policy_version and baseline.render_version = delivery.render_version and baseline.hash_algorithm = delivery.hash_algorithm and baseline.baseline_version = ?3 and baseline.baseline_version < 9223372036854775807))) on conflict(job_id, target_identity_digest, target_snapshot_digest_algorithm, target_snapshot_digest, delivery_policy_version, render_version, hash_algorithm) do update set accepted_payload_digest = excluded.accepted_payload_digest, source_delivery_id = excluded.source_delivery_id, source_run_id = excluded.source_run_id, source_result_id = excluded.source_result_id, source_result_hash = excluded.source_result_hash, accepted_at = excluded.accepted_at, baseline_version = case when scheduled_delivery_baselines.baseline_version < 9223372036854775807 then scheduled_delivery_baselines.baseline_version + 1 else scheduled_delivery_baselines.baseline_version end where ?3 < 9223372036854775807 and scheduled_delivery_baselines.baseline_version = ?3 and scheduled_delivery_baselines.baseline_version < 9223372036854775807",
  )
  .bind(delivery_id)
  .bind(accepted_at)
  .bind(expected_version)
  .execute(&mut **transaction)
  .await
  .map_err(scheduler_error)?;
  Ok(result.rows_affected() == 1)
}

async fn append_late_evidence_in_transaction(
  transaction: &mut Transaction<'_, Sqlite>,
  binding: &RunLeaseBinding,
  kind: ScheduledRunLateEvidenceKind,
  evidence_sha256: &str,
  observed_at: i64,
) -> Result<LateEvidenceAppendOutcome, StateError> {
  let duplicate: i64 = sqlx::query_scalar(
    "select exists(select 1 from scheduled_run_late_evidence where run_id = ?1 and attempt = ?2 and fence = ?3 and evidence_kind = ?4 and hash_algorithm = 'sha256-v1' and evidence_digest = ?5)",
  )
  .bind(binding.run_id())
  .bind(binding.attempt())
  .bind(binding.fence())
  .bind(kind.as_str())
  .bind(evidence_sha256)
  .fetch_one(&mut **transaction)
  .await
  .map_err(scheduler_error)?;
  if duplicate != 0 {
    return Ok(LateEvidenceAppendOutcome::Duplicate);
  }
  let evidence_count: i64 = sqlx::query_scalar(
    "select count(*) from scheduled_run_late_evidence where run_id = ?1 and attempt = ?2",
  )
  .bind(binding.run_id())
  .bind(binding.attempt())
  .fetch_one(&mut **transaction)
  .await
  .map_err(scheduler_error)?;
  if evidence_count >= 32 {
    return Ok(LateEvidenceAppendOutcome::QuotaExceeded);
  }
  sqlx::query(
    "insert into scheduled_run_late_evidence (evidence_id, run_id, attempt, fence, evidence_kind, hash_algorithm, evidence_digest, redacted_message, observed_at) values ('late:' || lower(hex(randomblob(16))), ?1, ?2, ?3, ?4, 'sha256-v1', ?5, null, ?6)",
  )
  .bind(binding.run_id())
  .bind(binding.attempt())
  .bind(binding.fence())
  .bind(kind.as_str())
  .bind(evidence_sha256)
  .bind(observed_at)
  .execute(&mut **transaction)
  .await
  .map_err(scheduler_error)?;
  Ok(LateEvidenceAppendOutcome::Recorded)
}

fn completion_storage_error(error: sqlx::Error) -> StateError {
  let is_constraint = error.as_database_error().is_some_and(|database| {
    database.is_unique_violation()
      || matches!(
        database.code().as_deref(),
        Some("19" | "275" | "787" | "1299" | "1555" | "1811" | "2067")
      )
  });
  if is_constraint {
    StateError::ScheduledRunCompletionConflict
  } else {
    scheduler_error(error)
  }
}

struct DeliveryIntentTarget {
  identity_digest: String,
  canonical_json: String,
  snapshot_digest: String,
}

fn delivery_intent_targets(targets_json: &str) -> Result<Vec<DeliveryIntentTarget>, StateError> {
  let targets: Vec<Value> = serde_json::from_str(targets_json).map_err(invalid_json)?;
  if targets.is_empty() || targets.len() > MAX_DELIVERY_TARGETS {
    return Err(StateError::InvalidSchedulerState {
      reason: format!(
        "materialized delivery targets must contain 1..={MAX_DELIVERY_TARGETS} entries"
      ),
    });
  }
  if serde_json::to_string(&targets).map_err(invalid_json)? != targets_json {
    return Err(StateError::InvalidSchedulerState {
      reason: "materialized delivery targets must use canonical JSON encoding".to_owned(),
    });
  }
  let mut identities = Vec::with_capacity(targets.len());
  let mut prepared = Vec::with_capacity(targets.len());
  for target in targets {
    let object = target
      .as_object()
      .ok_or_else(|| StateError::InvalidSchedulerState {
        reason: "materialized delivery target must be an object".to_owned(),
      })?;
    for field in [
      "provider",
      "connector",
      "tenant",
      "kind",
      "resolver_digest",
      "identity_digest",
    ] {
      let value = object.get(field).and_then(Value::as_str).ok_or_else(|| {
        StateError::InvalidSchedulerState {
          reason: format!("materialized delivery target has no {field}"),
        }
      })?;
      validate_text("materialized delivery target field", value).map_err(invalid_value)?;
    }
    if object
      .get("resolver_version")
      .and_then(Value::as_u64)
      .is_none_or(|version| version == 0 || version > u64::from(u32::MAX))
      || !object.contains_key("address")
    {
      return Err(StateError::InvalidSchedulerState {
        reason: "materialized delivery target has an invalid resolver snapshot".to_owned(),
      });
    }
    let identity_digest = object["identity_digest"]
      .as_str()
      .expect("validated identity digest")
      .to_owned();
    if identities.contains(&identity_digest) {
      return Err(StateError::InvalidSchedulerState {
        reason: "materialized delivery target identities must be unique".to_owned(),
      });
    }
    identities.push(identity_digest.clone());
    let canonical_json = serde_json::to_string(&target).map_err(invalid_json)?;
    let snapshot_digest = sha256_hex(canonical_json.as_bytes());
    prepared.push(DeliveryIntentTarget {
      identity_digest,
      canonical_json,
      snapshot_digest,
    });
  }
  Ok(prepared)
}

fn validate_delivery_intent_target_snapshot(
  target_json: &str,
  target_identity_digest: &str,
  digest_algorithm: &str,
  snapshot_digest: &str,
) -> Result<(), StateError> {
  if digest_algorithm != "sha256-v1" {
    return Err(StateError::InvalidSchedulerState {
      reason: "scheduled delivery intent has an unsupported target snapshot digest algorithm"
        .to_owned(),
    });
  }
  let target: Value = serde_json::from_str(target_json).map_err(invalid_json)?;
  if serde_json::to_string(&target).map_err(invalid_json)? != target_json
    || target
      .as_object()
      .and_then(|object| object.get("identity_digest"))
      .and_then(Value::as_str)
      != Some(target_identity_digest)
  {
    return Err(StateError::InvalidSchedulerState {
      reason: "scheduled delivery intent target snapshot identity is invalid".to_owned(),
    });
  }
  if sha256_hex(target_json.as_bytes()) != snapshot_digest {
    return Err(StateError::InvalidSchedulerState {
      reason: "scheduled delivery intent target snapshot digest mismatch".to_owned(),
    });
  }
  Ok(())
}

fn delivery_intent_key(run_id: &str, target_identity_digest: &str) -> Result<String, StateError> {
  if run_id.is_empty() || run_id.len() > MAX_DELIVERY_INTENT_RUN_ID_BYTES {
    return Err(StateError::InvalidSchedulerState {
      reason: "scheduled delivery intent run id exceeds its dedicated bound".to_owned(),
    });
  }
  if target_identity_digest.len() != 64
    || !target_identity_digest
      .bytes()
      .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
  {
    return Err(StateError::InvalidSchedulerState {
      reason: "scheduled delivery intent target identity must be lowercase sha256".to_owned(),
    });
  }
  let mut key = String::with_capacity(70 + (run_id.len() * 2));
  key.push_str("v1:");
  for byte in run_id.as_bytes() {
    write!(&mut key, "{byte:02x}").expect("writing to String cannot fail");
  }
  key.push(':');
  key.push_str(target_identity_digest);
  key.push_str(":1");
  debug_assert!(key.len() <= MAX_DELIVERY_INTENT_KEY_BYTES);
  Ok(key)
}

fn scheduled_delivery_authority_from_row(
  row: &SqliteRow,
) -> Result<ScheduledDeliveryAuthority, StateError> {
  let delivery_id: String = row.try_get("delivery_id").map_err(scheduler_error)?;
  let source_state = ScheduledDeliveryState::from_str(
    row
      .try_get::<String, _>("state")
      .map_err(scheduler_error)?
      .as_str(),
  )?;
  if !matches!(
    source_state,
    ScheduledDeliveryState::Pending | ScheduledDeliveryState::FailedRetryable
  ) {
    return Err(StateError::InvalidSchedulerState {
      reason: "scheduled delivery readiness selected a non-dispatchable state".to_owned(),
    });
  }
  let target_json: String = row.try_get("target_json").map_err(scheduler_error)?;
  let target_identity_digest: String = row
    .try_get("target_identity_digest")
    .map_err(scheduler_error)?;
  let target_digest: String = row
    .try_get("target_snapshot_digest")
    .map_err(scheduler_error)?;
  validate_delivery_intent_target_snapshot(
    &target_json,
    &target_identity_digest,
    row
      .try_get("target_snapshot_digest_algorithm")
      .map_err(scheduler_error)?,
    &target_digest,
  )?;
  let payload_digest: String = row.try_get("payload_digest").map_err(scheduler_error)?;
  validate_lowercase_sha256(
    "scheduled delivery readiness payload digest",
    &payload_digest,
  )
  .map_err(invalid_value)?;
  let intent_key: String = row.try_get("intent_key").map_err(scheduler_error)?;
  let binding_digest = sha256_hex(intent_key.as_bytes());
  Ok(ScheduledDeliveryAuthority::new(
    delivery_id,
    source_state,
    target_json,
    target_digest,
    payload_digest,
    binding_digest,
    intent_key,
  ))
}

async fn requeue_exact_retryable_delivery(
  transaction: &mut Transaction<'_, Sqlite>,
  authority: &ScheduledDeliveryAuthority,
  now: i64,
) -> Result<bool, StateError> {
  let requeued = sqlx::query(
    "update scheduled_run_deliveries set state = 'pending', next_attempt_at = null, claimed_baseline_version = null, provider_outcome = null, error_kind = null, error_message = null, updated_at = ?1 where delivery_id = ?2 and state = 'failed_retryable' and authority_kind = 'intent_v1' and payload_snapshot is not null and target_json = ?3 and target_snapshot_digest = ?4 and payload_digest = ?5 and intent_key = ?6 and next_attempt_at <= ?1 and attempt < 9223372036854775807 and fence < 9223372036854775807 and not exists (select 1 from scheduled_run_deliveries active where active.state = 'sending' and active.delivery_id <> scheduled_run_deliveries.delivery_id and active.job_id = scheduled_run_deliveries.job_id and active.target_identity_digest = scheduled_run_deliveries.target_identity_digest and active.target_snapshot_digest = scheduled_run_deliveries.target_snapshot_digest and active.delivery_policy_version = scheduled_run_deliveries.delivery_policy_version and active.render_version = scheduled_run_deliveries.render_version and active.hash_algorithm = scheduled_run_deliveries.hash_algorithm) and not exists (select 1 from scheduled_delivery_baselines baseline where baseline.job_id = scheduled_run_deliveries.job_id and baseline.target_identity_digest = scheduled_run_deliveries.target_identity_digest and baseline.target_snapshot_digest_algorithm = scheduled_run_deliveries.target_snapshot_digest_algorithm and baseline.target_snapshot_digest = scheduled_run_deliveries.target_snapshot_digest and baseline.delivery_policy_version = scheduled_run_deliveries.delivery_policy_version and baseline.render_version = scheduled_run_deliveries.render_version and baseline.hash_algorithm = scheduled_run_deliveries.hash_algorithm and baseline.accepted_payload_digest = scheduled_run_deliveries.payload_digest)",
  )
  .bind(now)
  .bind(authority.delivery_id())
  .bind(authority.target_json())
  .bind(authority.target_digest())
  .bind(authority.payload_digest())
  .bind(authority.intent_key())
  .execute(&mut **transaction)
  .await
  .map_err(scheduler_error)?;
  if requeued.rows_affected() == 1 {
    return Ok(true);
  }
  let exhausted: i64 = sqlx::query_scalar(
    "select exists(select 1 from scheduled_run_deliveries where delivery_id = ?1 and state = 'failed_retryable' and target_json = ?2 and target_snapshot_digest = ?3 and payload_digest = ?4 and intent_key = ?5 and next_attempt_at <= ?6 and (attempt = 9223372036854775807 or fence = 9223372036854775807))",
  )
  .bind(authority.delivery_id())
  .bind(authority.target_json())
  .bind(authority.target_digest())
  .bind(authority.payload_digest())
  .bind(authority.intent_key())
  .bind(now)
  .fetch_one(&mut **transaction)
  .await
  .map_err(scheduler_error)?;
  if exhausted != 0 {
    return Err(StateError::ScheduledDeliveryCounterExhausted);
  }
  Ok(false)
}

fn validate_scheduled_delivery_authority(
  authority: &ScheduledDeliveryAuthority,
) -> Result<(), StateError> {
  validate_text("scheduled delivery authority id", authority.delivery_id())
    .map_err(invalid_value)?;
  if !matches!(
    authority.source_state(),
    ScheduledDeliveryState::Pending | ScheduledDeliveryState::FailedRetryable
  ) || sha256_hex(authority.intent_key().as_bytes()) != authority.binding_digest()
  {
    return Err(StateError::InvalidSchedulerState {
      reason: "scheduled delivery readiness authority is invalid".to_owned(),
    });
  }
  validate_lowercase_sha256(
    "scheduled delivery readiness target digest",
    authority.target_digest(),
  )
  .map_err(invalid_value)?;
  validate_lowercase_sha256(
    "scheduled delivery readiness payload digest",
    authority.payload_digest(),
  )
  .map_err(invalid_value)
}

fn execution_baseline_version(snapshot_json: &str) -> Result<i64, StateError> {
  let snapshot: Value = serde_json::from_str(snapshot_json).map_err(invalid_json)?;
  if serde_json::to_string(&snapshot).map_err(invalid_json)? != snapshot_json {
    return Err(StateError::InvalidSchedulerState {
      reason: "materialized execution baseline must use canonical JSON encoding".to_owned(),
    });
  }
  snapshot
    .get("baseline_version")
    .and_then(Value::as_i64)
    .filter(|version| *version >= 0)
    .ok_or_else(|| StateError::InvalidSchedulerState {
      reason: "materialized execution baseline has no valid version".to_owned(),
    })
}

fn digest_identity(parts: &[&str]) -> String {
  let mut digest = Sha256::new();
  for part in parts {
    digest.update(
      u64::try_from(part.len())
        .expect("bounded scheduler identity part fits u64")
        .to_be_bytes(),
    );
    digest.update(part.as_bytes());
  }
  hex_digest(digest.finalize())
}

fn sha256_hex(value: &[u8]) -> String {
  hex_digest(Sha256::digest(value))
}

fn hex_digest(digest: impl AsRef<[u8]>) -> String {
  let mut encoded = String::with_capacity(64);
  for byte in digest.as_ref() {
    write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
  }
  encoded
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

struct ExpiredReclaimTransition {
  run_state: &'static str,
  attempt_state: &'static str,
  overlap_slot: Option<i64>,
  error_kind: &'static str,
  outcome: ExpiredRunReclaimOutcome,
}

fn expired_reclaim_transition(
  state: &str,
  run_id: &str,
  attempt: i64,
  fence: i64,
  max_attempts: i64,
  safe_execution_retry: bool,
) -> ExpiredReclaimTransition {
  if state == "executing" && !safe_execution_retry {
    return ExpiredReclaimTransition {
      run_state: "outcome_unknown",
      attempt_state: "outcome_unknown",
      overlap_slot: Some(1),
      error_kind: "execution_lease_expired",
      outcome: ExpiredRunReclaimOutcome::OutcomeUnknown {
        run_id: run_id.to_owned(),
        attempt,
        fence,
      },
    };
  }
  if attempt < max_attempts {
    let (attempt_state, error_kind) = if state == "executing" {
      ("lease_expired", "safe_execution_lease_expired")
    } else {
      ("lease_expired", "preflight_lease_expired")
    };
    return ExpiredReclaimTransition {
      run_state: "pending",
      attempt_state,
      overlap_slot: Some(1),
      error_kind,
      outcome: ExpiredRunReclaimOutcome::Retried {
        run_id: run_id.to_owned(),
        attempt,
        fence,
      },
    };
  }
  let (attempt_state, error_kind) = if state == "executing" {
    ("lease_expired", "safe_execution_lease_exhausted")
  } else {
    ("lease_expired", "preflight_lease_exhausted")
  };
  ExpiredReclaimTransition {
    run_state: "failed",
    attempt_state,
    overlap_slot: None,
    error_kind,
    outcome: ExpiredRunReclaimOutcome::Failed {
      run_id: run_id.to_owned(),
      attempt,
      fence,
    },
  }
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

fn validate_lease_binding(binding: &RunLeaseBinding) -> Result<(), StateError> {
  validate_text("scheduled run id", binding.run_id()).map_err(invalid_value)?;
  validate_text("scheduled run job id", binding.job_id()).map_err(invalid_value)?;
  validate_text("scheduled run lease owner", binding.lease_owner()).map_err(invalid_value)?;
  if binding.attempt() <= 0 || binding.fence() <= 0 {
    return Err(StateError::InvalidSchedulerState {
      reason: "scheduled run attempt and fence must be positive".to_owned(),
    });
  }
  Ok(())
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

fn validate_mutation_audit(
  mutation: &ScheduledJobMutation,
  idempotency: &ScheduleMutationIdempotency,
  audit: &ScheduleMutationAudit,
) -> Result<(), StateError> {
  validate_schedule_audit(audit)?;
  let job_id = match mutation {
    ScheduledJobMutation::Create(request) => &request.job_id,
    ScheduledJobMutation::Update(request) => &request.job_id,
    ScheduledJobMutation::Pause { job_id, .. }
    | ScheduledJobMutation::Resume { job_id, .. }
    | ScheduledJobMutation::Delete { job_id, .. } => job_id,
  };
  if audit.principal.as_ref() != Some(&idempotency.principal)
    || audit.operation != mutation.operation()
    || audit.job_id.as_deref() != Some(job_id)
    || audit.request_id != idempotency.request_id
    || audit.outcome != "applied"
    || audit.decision != "allow"
    || audit.occurred_at != mutation.now()
  {
    return Err(StateError::InvalidSchedulerState {
      reason: "schedule mutation audit does not match the authorized mutation".to_owned(),
    });
  }
  Ok(())
}

fn validate_schedule_audit(audit: &ScheduleMutationAudit) -> Result<(), StateError> {
  for (field, value) in [
    ("audit id", Some(audit.audit_id.as_str())),
    ("audit operation", Some(audit.operation.as_str())),
    ("audit request id", Some(audit.request_id.as_str())),
    ("audit outcome", Some(audit.outcome.as_str())),
    ("audit decision", Some(audit.decision.as_str())),
    ("audit correlation id", Some(audit.correlation_id.as_str())),
    ("audit job id", audit.job_id.as_deref()),
    ("audit reason", audit.reason.as_deref()),
    ("audit error code", audit.error_code.as_deref()),
  ] {
    if let Some(value) = value {
      validate_text(field, value).map_err(invalid_value)?;
    }
  }
  if let Some(principal) = &audit.principal {
    principal.validate().map_err(invalid_value)?;
  }
  if audit.latency_ms < 0
    || !matches!(audit.decision.as_str(), "allow" | "deny" | "error")
    || !matches!(
      audit.outcome.as_str(),
      "applied"
        | "replay"
        | "conflict"
        | "in_progress"
        | "denied"
        | "not_visible"
        | "validation"
        | "resolver_unavailable"
        | "resolver_not_allowed"
        | "resolver_timeout"
        | "capability_unavailable"
        | "capability_invalid"
        | "stale_generation"
        | "expired_not_resumable"
        | "storage_busy"
        | "storage_internal"
    )
  {
    return Err(StateError::InvalidSchedulerState {
      reason: "invalid schedule audit outcome".to_owned(),
    });
  }
  Ok(())
}

async fn insert_mutation_audit(
  transaction: &mut Transaction<'_, Sqlite>,
  audit: &ScheduleMutationAudit,
) -> Result<(), StateError> {
  sqlx::query(
    "insert into schedule_mutation_audit (audit_id, principal_kind, principal_provider, principal_tenant, principal_subject, operation, job_id, request_id, outcome, decision, reason, error_code, old_generation, new_generation, resolver_provider, target_kind, resolver_version, resolver_digest, capability_version, capability_digest, idempotency_outcome, latency_ms, correlation_id, occurred_at) values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24)",
  )
  .bind(&audit.audit_id)
  .bind(audit.principal.as_ref().map(PrincipalKey::kind))
  .bind(audit.principal.as_ref().map(PrincipalKey::provider))
  .bind(audit.principal.as_ref().map(PrincipalKey::tenant))
  .bind(audit.principal.as_ref().map(PrincipalKey::subject))
  .bind(&audit.operation)
  .bind(&audit.job_id)
  .bind(&audit.request_id)
  .bind(&audit.outcome)
  .bind(&audit.decision)
  .bind(&audit.reason)
  .bind(&audit.error_code)
  .bind(audit.old_generation)
  .bind(audit.new_generation)
  .bind(&audit.resolver_provider)
  .bind(&audit.target_kind)
  .bind(audit.resolver_version)
  .bind(&audit.resolver_digest)
  .bind(audit.capability_version)
  .bind(&audit.capability_digest)
  .bind(&audit.idempotency_outcome)
  .bind(audit.latency_ms)
  .bind(&audit.correlation_id)
  .bind(audit.occurred_at)
  .execute(&mut **transaction)
  .await
  .map(|_| ())
  .map_err(scheduler_error)
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
  let leased_runs: i64 = sqlx::query_scalar(
    "select count(*) from scheduled_runs where job_id = ?1 and job_generation = ?2 and state = 'leased'",
  )
  .bind(job_id)
  .bind(generation)
  .fetch_one(&mut **transaction)
  .await
  .map_err(scheduler_error)?;
  let cancelled_attempts = sqlx::query(
    "update scheduled_run_attempts set state = 'cancelled', completed_at = ?1 where state = 'leased' and exists (select 1 from scheduled_runs r where r.run_id = scheduled_run_attempts.run_id and r.job_id = scheduled_run_attempts.job_id and r.attempt = scheduled_run_attempts.attempt and r.fence = scheduled_run_attempts.fence and r.lease_owner = scheduled_run_attempts.lease_owner and r.job_id = ?2 and r.job_generation = ?3 and r.state = 'leased')",
  )
  .bind(now)
  .bind(job_id)
  .bind(generation)
  .execute(&mut **transaction)
  .await
  .map_err(scheduler_error)?;
  if i64::try_from(cancelled_attempts.rows_affected()).ok() != Some(leased_runs) {
    return Err(StateError::InvalidSchedulerState {
      reason: "leased scheduled run is missing its current attempt authority".to_owned(),
    });
  }
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

struct ExecutionOutcomeTransition {
  run_state: &'static str,
  attempt_state: &'static str,
  retry_at: Option<i64>,
  overlap_slot: Option<i64>,
  outcome: ScheduledRunExecutionOutcome,
}

fn execution_outcome_transition(
  binding: &RunLeaseBinding,
  disposition: ScheduledExecutionDisposition,
  row: &sqlx::sqlite::SqliteRow,
  now: i64,
) -> Result<ExecutionOutcomeTransition, StateError> {
  let terminal = match disposition {
    ScheduledExecutionDisposition::Terminal(terminal) => terminal,
    ScheduledExecutionDisposition::RetryAt {
      retry_at,
      deadline_at,
      max_attempts,
      transport: super::TransportConvergence::Converged,
      exhausted,
    } => {
      if !persisted_profile_allows_retry(binding, row)? {
        ScheduledExecutionTerminal::OutcomeUnknown
      } else if binding.attempt() >= max_attempts || now >= deadline_at || retry_at > deadline_at {
        exhausted
      } else {
        return Ok(ExecutionOutcomeTransition {
          run_state: "pending",
          attempt_state: "retry_scheduled",
          retry_at: Some(retry_at),
          overlap_slot: Some(1),
          outcome: ScheduledRunExecutionOutcome::Retried,
        });
      }
    }
  };
  let (run_state, attempt_state) = match terminal {
    ScheduledExecutionTerminal::Failed => ("failed", "failed"),
    ScheduledExecutionTerminal::TimedOut => ("timed_out", "timed_out"),
    ScheduledExecutionTerminal::Cancelled => ("cancelled", "cancelled"),
    ScheduledExecutionTerminal::OutcomeUnknown => ("outcome_unknown", "outcome_unknown"),
  };
  let overlap_slot = (terminal == ScheduledExecutionTerminal::OutcomeUnknown).then_some(1_i64);
  Ok(ExecutionOutcomeTransition {
    run_state,
    attempt_state,
    retry_at: None,
    overlap_slot,
    outcome: ScheduledRunExecutionOutcome::Terminal(terminal),
  })
}

fn persisted_profile_allows_retry(
  binding: &RunLeaseBinding,
  row: &sqlx::sqlite::SqliteRow,
) -> Result<bool, StateError> {
  let schema_version = row
    .try_get::<Option<i64>, _>("attested_profile_schema_version")
    .map_err(scheduler_error)?;
  let canonical_json = row
    .try_get::<Option<String>, _>("attested_profile_json")
    .map_err(scheduler_error)?;
  let hash_algorithm = row
    .try_get::<Option<String>, _>("attested_profile_hash_algorithm")
    .map_err(scheduler_error)?;
  let digest = row
    .try_get::<Option<String>, _>("attested_profile_digest")
    .map_err(scheduler_error)?;
  let (Some(canonical_json), Some(digest)) = (canonical_json, digest) else {
    return Ok(false);
  };
  if schema_version != Some(1) || hash_algorithm.as_deref() != Some("sha256-v1") {
    return Ok(false);
  }
  let profile: Value = serde_json::from_str(&canonical_json).map_err(invalid_json)?;
  let Some(nonce) = profile.pointer("/authority/nonce").and_then(Value::as_str) else {
    return Ok(false);
  };
  let claim = ClaimedScheduledRun {
    binding: binding.clone(),
    schedule_id: row.try_get("schedule_id").map_err(scheduler_error)?,
    job_generation: row.try_get("job_generation").map_err(scheduler_error)?,
    schedule_generation: row
      .try_get("schedule_generation")
      .map_err(scheduler_error)?,
    scheduled_for: row.try_get("scheduled_for").map_err(scheduler_error)?,
    coalesced_through: row.try_get("coalesced_through").map_err(scheduler_error)?,
    definition_version: positive_u32(row.try_get("definition_version").map_err(scheduler_error)?)?,
    definition_json: row.try_get("definition_json").map_err(scheduler_error)?,
    capability_schema_version: positive_u32(
      row
        .try_get("capability_schema_version")
        .map_err(scheduler_error)?,
    )?,
    capability_digest: row.try_get("capability_digest").map_err(scheduler_error)?,
    capability_json: row.try_get("capability_json").map_err(scheduler_error)?,
    targets_json: row.try_get("targets_json").map_err(scheduler_error)?,
    execution_baseline_json: row
      .try_get::<Option<String>, _>("execution_baseline_json")
      .map_err(scheduler_error)?
      .ok_or_else(|| StateError::InvalidSchedulerState {
        reason: "materialized run is missing its execution baseline snapshot".to_owned(),
      })?,
  };
  let Ok(authority) = super::ScheduledPrepareAuthority::for_claim(&claim, nonce) else {
    return Ok(false);
  };
  Ok(authority.attestation_matches(&canonical_json, &digest, true))
}

fn persisted_profile_allows_recovery(
  binding: &RunLeaseBinding,
  row: &sqlx::sqlite::SqliteRow,
) -> Result<bool, StateError> {
  let schema_version = row
    .try_get::<Option<i64>, _>("attested_profile_schema_version")
    .map_err(scheduler_error)?;
  let canonical_json = row
    .try_get::<Option<String>, _>("attested_profile_json")
    .map_err(scheduler_error)?;
  let hash_algorithm = row
    .try_get::<Option<String>, _>("attested_profile_hash_algorithm")
    .map_err(scheduler_error)?;
  let digest = row
    .try_get::<Option<String>, _>("attested_profile_digest")
    .map_err(scheduler_error)?;
  let (Some(canonical_json), Some(digest)) = (canonical_json, digest) else {
    return Ok(false);
  };
  if schema_version != Some(2) || hash_algorithm.as_deref() != Some("sha256-v1") {
    return Ok(false);
  }
  let profile: Value = serde_json::from_str(&canonical_json).map_err(invalid_json)?;
  let Some(nonce) = profile.pointer("/authority/nonce").and_then(Value::as_str) else {
    return Ok(false);
  };
  let claim = ClaimedScheduledRun {
    binding: binding.clone(),
    schedule_id: row.try_get("schedule_id").map_err(scheduler_error)?,
    job_generation: row.try_get("job_generation").map_err(scheduler_error)?,
    schedule_generation: row
      .try_get("schedule_generation")
      .map_err(scheduler_error)?,
    scheduled_for: row.try_get("scheduled_for").map_err(scheduler_error)?,
    coalesced_through: row.try_get("coalesced_through").map_err(scheduler_error)?,
    definition_version: positive_u32(row.try_get("definition_version").map_err(scheduler_error)?)?,
    definition_json: row.try_get("definition_json").map_err(scheduler_error)?,
    capability_schema_version: positive_u32(
      row
        .try_get("capability_schema_version")
        .map_err(scheduler_error)?,
    )?,
    capability_digest: row.try_get("capability_digest").map_err(scheduler_error)?,
    capability_json: row.try_get("capability_json").map_err(scheduler_error)?,
    targets_json: row.try_get("targets_json").map_err(scheduler_error)?,
    execution_baseline_json: row
      .try_get::<Option<String>, _>("execution_baseline_json")
      .map_err(scheduler_error)?
      .ok_or_else(|| StateError::InvalidSchedulerState {
        reason: "materialized run is missing its execution baseline snapshot".to_owned(),
      })?,
  };
  let Ok(authority) = super::ScheduledPrepareAuthority::for_claim(&claim, nonce) else {
    return Ok(false);
  };
  Ok(authority.recovery_attestation_matches(&canonical_json, &digest))
}

#[cfg(test)]
mod tests {
  use tempfile::tempdir;

  use super::{
    AttestedExecutionProfileSnapshot, CapabilityProfileSnapshot, CreateScheduledJob,
    DeliveryTargetSnapshot, MAX_DELIVERY_INTENT_KEY_BYTES, MAX_DELIVERY_INTENT_RUN_ID_BYTES,
    MaterializationOutcome, PrincipalKey, ScheduleMutationAudit, ScheduleMutationIdempotency,
    ScheduleSpec, ScheduledJobDefinition, ScheduledJobMutation, StateError, StateStore,
    TransactionalMutationOutcome, UpdateExecutionBaseline, canonical_idempotency_scope,
    compare_and_swap_execution_baseline_in_transaction, delivery_intent_key,
  };

  const TEST_TARGET_IDENTITY: &str =
    "0000000000000000000000000000000000000000000000000000000000000001";

  #[test]
  fn test_delivery_intent_key_is_unambiguous_and_enforces_its_byte_bound() {
    let first_identity = "1".repeat(64);
    let second_identity = "2".repeat(64);
    let unicode = delivery_intent_key("scheduled:作业:110", &first_identity)
      .expect("encode colon and Unicode run id");
    assert!(unicode.starts_with("v1:7363686564756c65643a"));
    assert_eq!(
      unicode,
      delivery_intent_key("scheduled:作业:110", &first_identity).expect("stable key")
    );
    assert_ne!(
      delivery_intent_key("scheduled:a:b:110", &first_identity).expect("first pair"),
      delivery_intent_key("scheduled:a:110", &second_identity).expect("second pair")
    );

    let maximum_run_id = "r".repeat(MAX_DELIVERY_INTENT_RUN_ID_BYTES);
    let maximum_key =
      delivery_intent_key(&maximum_run_id, &first_identity).expect("maximum run id");
    assert_eq!(maximum_key.len(), MAX_DELIVERY_INTENT_KEY_BYTES);
    assert!(matches!(
      delivery_intent_key(
        &"r".repeat(MAX_DELIVERY_INTENT_RUN_ID_BYTES + 1),
        &first_identity
      ),
      Err(StateError::InvalidSchedulerState { reason })
        if reason == "scheduled delivery intent run id exceeds its dedicated bound"
    ));
  }

  fn audited_create_fixture(
    job_id: &str,
    definition_json: &str,
    address_json: &str,
    at: i64,
    now: i64,
  ) -> (
    ScheduledJobMutation,
    ScheduleMutationIdempotency,
    ScheduleMutationAudit,
  ) {
    let owner = PrincipalKey::new("user", "test", "tenant", "owner").expect("owner");
    let request_id = format!("request-{job_id}");
    let mutation = ScheduledJobMutation::Create(Box::new(CreateScheduledJob {
      job_id: job_id.to_owned(),
      schedule_id: format!("schedule-{job_id}"),
      definition: ScheduledJobDefinition::new(1, definition_json).expect("definition"),
      creator: owner.clone(),
      owner: owner.clone(),
      capability: CapabilityProfileSnapshot::new(1, "profile", "{}").expect("profile"),
      targets: vec![
        DeliveryTargetSnapshot::new(
          format!("target-{job_id}"),
          "test",
          "test",
          "tenant",
          "channel",
          address_json,
          1,
          "resolver",
          TEST_TARGET_IDENTITY,
        )
        .expect("target"),
      ],
      schedule: ScheduleSpec::once(at),
      now,
    }));
    let idempotency = ScheduleMutationIdempotency {
      principal: owner.clone(),
      request_id: request_id.clone(),
      digest_algorithm: "sha256-v1".to_owned(),
      request_digest: format!("digest-{job_id}"),
      response_json: format!(r#"{{"job_id":"{job_id}"}}"#),
    };
    let audit = ScheduleMutationAudit {
      audit_id: format!("audit-{job_id}"),
      principal: Some(owner),
      operation: "create".to_owned(),
      job_id: Some(job_id.to_owned()),
      request_id: request_id.clone(),
      outcome: "applied".to_owned(),
      decision: "allow".to_owned(),
      reason: None,
      error_code: None,
      old_generation: None,
      new_generation: Some(0),
      resolver_provider: Some("test".to_owned()),
      target_kind: Some("channel".to_owned()),
      resolver_version: Some(1),
      resolver_digest: Some("resolver".to_owned()),
      capability_version: Some(1),
      capability_digest: Some("profile".to_owned()),
      idempotency_outcome: Some("applied".to_owned()),
      latency_ms: 0,
      correlation_id: request_id,
      occurred_at: now,
    };
    (mutation, idempotency, audit)
  }

  #[tokio::test]
  async fn test_audited_idempotent_mutation_commits_once_with_schedule() {
    let temp = tempdir().expect("create tempdir");
    let store = StateStore::initialize(&temp.path().join("state"), None)
      .await
      .expect("initialize store");
    let owner = PrincipalKey::new("user", "test", "tenant", "owner").expect("owner");
    let mutation = ScheduledJobMutation::Create(Box::new(CreateScheduledJob {
      job_id: "audited".to_owned(),
      schedule_id: "schedule-audited".to_owned(),
      definition: ScheduledJobDefinition::new(1, "{}").expect("definition"),
      creator: owner.clone(),
      owner: owner.clone(),
      capability: CapabilityProfileSnapshot::new(1, "profile", "{}").expect("profile"),
      targets: vec![
        DeliveryTargetSnapshot::new(
          "none",
          "none",
          "none",
          "tenant",
          "none",
          "{}",
          1,
          "resolver",
          TEST_TARGET_IDENTITY,
        )
        .expect("target"),
      ],
      schedule: ScheduleSpec::once(2),
      now: 1,
    }));
    let idempotency = ScheduleMutationIdempotency {
      principal: owner.clone(),
      request_id: "request-1".to_owned(),
      digest_algorithm: "sha256-v1".to_owned(),
      request_digest: "digest".to_owned(),
      response_json: r#"{"job_id":"audited"}"#.to_owned(),
    };
    let audit = ScheduleMutationAudit {
      audit_id: "audit-1".to_owned(),
      principal: Some(owner),
      operation: "create".to_owned(),
      job_id: Some("audited".to_owned()),
      request_id: "request-1".to_owned(),
      outcome: "applied".to_owned(),
      decision: "allow".to_owned(),
      reason: None,
      error_code: None,
      old_generation: None,
      new_generation: Some(0),
      resolver_provider: Some("none".to_owned()),
      target_kind: Some("none".to_owned()),
      resolver_version: Some(1),
      resolver_digest: Some("resolver".to_owned()),
      capability_version: Some(1),
      capability_digest: Some("profile".to_owned()),
      idempotency_outcome: Some("applied".to_owned()),
      latency_ms: 0,
      correlation_id: "request-1".to_owned(),
      occurred_at: 1,
    };

    let applied = store
      .apply_idempotent_schedule_mutation_with_audit(&mutation, &idempotency, Some(&audit))
      .await
      .expect("apply mutation");
    assert!(matches!(applied, TransactionalMutationOutcome::Applied(_)));
    let replay = store
      .apply_idempotent_schedule_mutation_with_audit(&mutation, &idempotency, Some(&audit))
      .await
      .expect("replay mutation");
    assert!(matches!(replay, TransactionalMutationOutcome::Replay(_)));

    let counts: (i64, i64) = sqlx::query_as(
      "select (select count(*) from scheduled_jobs where job_id = 'audited'), (select count(*) from schedule_mutation_audit where audit_id = 'audit-1')",
    )
    .fetch_one(&store.pool)
    .await
    .expect("read committed rows");
    assert_eq!(counts, (1, 1));
  }

  #[tokio::test]
  async fn test_failed_mutation_rolls_back_idempotency_and_applied_audit() {
    let temp = tempdir().expect("create tempdir");
    let store = StateStore::initialize(&temp.path().join("state"), None)
      .await
      .expect("initialize store");
    let (mutation, idempotency, audit) = audited_create_fixture("rollback", "{}", "{}", 1, 1);

    store
      .apply_idempotent_schedule_mutation_with_audit(&mutation, &idempotency, Some(&audit))
      .await
      .expect_err("expired once schedule must fail");

    let counts: (i64, i64, i64) = sqlx::query_as(
      "select (select count(*) from scheduled_jobs where job_id = 'rollback'), (select count(*) from idempotency_keys where key = 'request-rollback'), (select count(*) from schedule_mutation_audit where audit_id = 'audit-rollback')",
    )
    .fetch_one(&store.pool)
    .await
    .expect("read rolled back rows");
    assert_eq!(counts, (0, 0, 0));
  }

  #[tokio::test]
  async fn test_claimed_idempotency_returns_in_progress_without_applied_audit() {
    let temp = tempdir().expect("create tempdir");
    let store = StateStore::initialize(&temp.path().join("state"), None)
      .await
      .expect("initialize store");
    let (mutation, idempotency, audit) = audited_create_fixture("in-progress", "{}", "{}", 2, 1);
    let scope = canonical_idempotency_scope(&idempotency.principal, "create");
    sqlx::query(
      "insert into idempotency_keys (scope, key, status, request_digest, digest_algorithm, created_at, updated_at) values (?1, ?2, 'claimed', ?3, ?4, datetime(1, 'unixepoch'), datetime(1, 'unixepoch'))",
    )
    .bind(scope)
    .bind(&idempotency.request_id)
    .bind(&idempotency.request_digest)
    .bind(&idempotency.digest_algorithm)
    .execute(&store.pool)
    .await
    .expect("seed claimed idempotency");

    let outcome = store
      .apply_idempotent_schedule_mutation_with_audit(&mutation, &idempotency, Some(&audit))
      .await
      .expect("read in-progress outcome");
    assert!(matches!(outcome, TransactionalMutationOutcome::InProgress));
    let count: i64 = sqlx::query_scalar(
      "select count(*) from schedule_mutation_audit where audit_id = 'audit-in-progress'",
    )
    .fetch_one(&store.pool)
    .await
    .expect("read audit count");
    assert_eq!(count, 0);
  }

  #[tokio::test]
  async fn test_schedule_audit_excludes_instruction_target_address_and_secret_payloads() {
    const INSTRUCTION_MARKER: &str = "private-instruction-marker";
    const ADDRESS_MARKER: &str = "private-target-marker";
    const SECRET_MARKER: &str = "private-token-marker";
    let temp = tempdir().expect("create tempdir");
    let store = StateStore::initialize(&temp.path().join("state"), None)
      .await
      .expect("initialize store");
    let definition = format!(r#"{{"instruction":"{INSTRUCTION_MARKER} {SECRET_MARKER}"}}"#);
    let address = format!(r#"{{"channel_id":"{ADDRESS_MARKER}"}}"#);
    let (mutation, idempotency, audit) =
      audited_create_fixture("sanitized", &definition, &address, 2, 1);

    store
      .apply_idempotent_schedule_mutation_with_audit(&mutation, &idempotency, Some(&audit))
      .await
      .expect("apply audited mutation");
    let audit_text: String = sqlx::query_scalar(
      "select coalesce(audit_id, '') || '|' || coalesce(principal_kind, '') || '|' || coalesce(principal_provider, '') || '|' || coalesce(principal_tenant, '') || '|' || coalesce(principal_subject, '') || '|' || operation || '|' || coalesce(job_id, '') || '|' || request_id || '|' || outcome || '|' || decision || '|' || coalesce(reason, '') || '|' || coalesce(error_code, '') || '|' || coalesce(resolver_provider, '') || '|' || coalesce(target_kind, '') || '|' || coalesce(resolver_digest, '') || '|' || coalesce(capability_digest, '') || '|' || coalesce(idempotency_outcome, '') || '|' || correlation_id from schedule_mutation_audit where audit_id = 'audit-sanitized'",
    )
    .fetch_one(&store.pool)
    .await
    .expect("read sanitized audit");
    for marker in [INSTRUCTION_MARKER, ADDRESS_MARKER, SECRET_MARKER] {
      assert!(!audit_text.contains(marker), "audit leaked {marker}");
    }
    let columns: Vec<String> =
      sqlx::query_scalar("select name from pragma_table_info('schedule_mutation_audit')")
        .fetch_all(&store.pool)
        .await
        .expect("read audit columns");
    for forbidden in ["instruction", "address", "payload", "token", "secret"] {
      assert!(
        columns.iter().all(|column| !column.contains(forbidden)),
        "audit schema contains forbidden payload column: {forbidden}"
      );
    }
  }

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
          "none",
          "none",
          "none",
          "none",
          "none",
          "{}",
          1,
          "resolver",
          TEST_TARGET_IDENTITY,
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
          "none",
          "none",
          "none",
          "none",
          "none",
          "{}",
          1,
          "resolver",
          TEST_TARGET_IDENTITY,
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
    let claim = store
      .claim_next_scheduled_run("worker", 2, 10)
      .await
      .expect("claim")
      .expect("claimed run");
    let profile = AttestedExecutionProfileSnapshot::new(1, "{}", "sha256-v1", "profile")
      .expect("attested profile");
    store
      .mark_scheduled_run_executing(&claim.binding, &profile, 3)
      .await
      .expect("mark executing");

    let mut transaction = store
      .pool
      .begin()
      .await
      .expect("begin rollback transaction");
    sqlx::query("insert into scheduled_run_result_artifacts (artifact_id, run_id, job_id, accepted_attempt, accepted_fence, schema_version, result_json, hash_algorithm, result_hash, previous_success_context, completed_at) values ('result-artifact', ?1, 'terminal-transaction', ?2, ?3, 1, '{}', 'sha256-v1', 'result', 'context', 3)")
      .bind(&run.run_id)
      .bind(claim.binding.attempt())
      .bind(claim.binding.fence())
      .execute(&mut *transaction)
      .await
      .expect("insert result artifact");
    sqlx::query("update scheduled_run_attempts set state = 'succeeded', completed_at = 3 where run_id = ?1 and attempt = ?2")
      .bind(&run.run_id)
      .bind(claim.binding.attempt())
      .execute(&mut *transaction)
      .await
      .expect("complete attempt");
    sqlx::query("update scheduled_runs set state = 'succeeded', overlap_slot = null, lease_owner = null, lease_expires_at = null, result_artifact_id = 'result-artifact', result_context = 'context', result_hash_algorithm = 'sha256-v1', result_hash = 'result' where run_id = ?1")
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
    assert_eq!(rolled_back, ("executing".to_owned(), 0));

    let mut transaction = store.pool.begin().await.expect("begin commit transaction");
    sqlx::query("insert into scheduled_run_result_artifacts (artifact_id, run_id, job_id, accepted_attempt, accepted_fence, schema_version, result_json, hash_algorithm, result_hash, previous_success_context, completed_at) values ('result-artifact', ?1, 'terminal-transaction', ?2, ?3, 1, '{}', 'sha256-v1', 'result', 'context', 3)")
      .bind(&run.run_id)
      .bind(claim.binding.attempt())
      .bind(claim.binding.fence())
      .execute(&mut *transaction)
      .await
      .expect("insert result artifact");
    sqlx::query("update scheduled_run_attempts set state = 'succeeded', completed_at = 3 where run_id = ?1 and attempt = ?2")
      .bind(&run.run_id)
      .bind(claim.binding.attempt())
      .execute(&mut *transaction)
      .await
      .expect("complete attempt");
    sqlx::query("update scheduled_runs set state = 'succeeded', overlap_slot = null, lease_owner = null, lease_expires_at = null, result_artifact_id = 'result-artifact', result_context = 'context', result_hash_algorithm = 'sha256-v1', result_hash = 'result' where run_id = ?1")
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
  }
}
