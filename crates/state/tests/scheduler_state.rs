use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;

use codeoff_state::{
  AttestedExecutionProfileSnapshot, CapabilityProfileSnapshot, ClaimedScheduledRun,
  CreateScheduledJob, DeliveryTargetSnapshot, ExpiredRunReclaimOutcome, LateEvidenceAppendOutcome,
  MaterializationOutcome, OccurrenceError, PreflightFailureDisposition, PrincipalKey,
  ScheduleMutationIdempotency, ScheduleSpec, ScheduledJobDefinition, ScheduledJobMutation,
  ScheduledJobStatus, ScheduledRunLateEvidenceKind, StateError, StateStore, StateValueError,
  TransactionalMutationOutcome, UpdateAcceptedDeliveryBaseline, UpdateExecutionBaseline,
  UpdateScheduledJob,
};
use sqlx::Row;
use sqlx::SqlitePool;
use sqlx::migrate::Migrator;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use tempfile::tempdir;
use tokio::sync::Barrier;

fn database_url(state_dir: &Path) -> String {
  format!("sqlite://{}", state_dir.join("codeoff.db").display())
}

fn target(job: &str) -> DeliveryTargetSnapshot {
  DeliveryTargetSnapshot::new(
    format!("target-{job}"),
    "none",
    "none",
    "none",
    "none",
    "{}",
    1,
    "resolver-v1",
    "none-v1",
  )
  .expect("target")
}

fn owner() -> PrincipalKey {
  PrincipalKey::new("user", "slack", "workspace", "U1").expect("principal")
}

fn create_request(job: &str, schedule: ScheduleSpec, now: i64) -> CreateScheduledJob {
  CreateScheduledJob {
    job_id: job.to_owned(),
    schedule_id: format!("schedule-{job}"),
    definition: ScheduledJobDefinition::new(1, r#"{"prompt":"check"}"#).expect("definition"),
    creator: owner(),
    owner: owner(),
    capability: CapabilityProfileSnapshot::new(1, "profile-v1", r#"{"tools":["github.read"]}"#)
      .expect("capability"),
    targets: vec![target(job)],
    schedule,
    now,
  }
}

fn mutation_idempotency(request_id: &str, digest: &str) -> ScheduleMutationIdempotency {
  ScheduleMutationIdempotency {
    principal: owner(),
    request_id: request_id.to_owned(),
    digest_algorithm: "sha256-v1".to_owned(),
    request_digest: digest.to_owned(),
    response_json: r#"{"job_id":"stable"}"#.to_owned(),
  }
}

#[test]
fn test_fixed_interval_uses_anchor_without_drift() {
  let schedule = ScheduleSpec::fixed_interval(100, 30).expect("valid interval");
  assert_eq!(schedule.next_after(100).expect("next occurrence"), 130);
  assert_eq!(schedule.next_after(189).expect("next occurrence"), 190);
}

#[test]
fn test_cron_rejects_seconds_and_preserves_dst_utc_order() {
  assert!(ScheduleSpec::cron("0 0 0 * * *", "UTC").is_err());
  let schedule = ScheduleSpec::cron("30 1 * * *", "America/New_York").expect("valid cron");
  let first = schedule.next_after(1_730_611_799).expect("first overlap");
  let second = schedule.next_after(first).expect("second overlap");
  assert_eq!(first, 1_730_611_800);
  // Croner resolves the repeated wall-clock minute once, then advances to the next local day.
  assert_eq!(second, 1_730_701_800);

  let spring = ScheduleSpec::cron("30 2 * * *", "America/New_York").expect("spring cron");
  // Croner advances a nonexistent 02:30 wall time to the first valid instant after the gap.
  assert_eq!(
    spring.next_after(1_710_028_800).expect("after gap"),
    1_710_054_000
  );
}

#[test]
fn test_cron_outside_bundled_timezone_range_returns_error_without_panicking() {
  let schedule = ScheduleSpec::cron("* * * * *", "UTC").expect("valid cron");
  let result = std::panic::catch_unwind(|| schedule.next_after(253_402_300_800));
  assert!(matches!(
    result,
    Ok(Err(OccurrenceError::ArithmeticOverflow))
  ));
}

#[test]
fn test_occurrence_search_is_bounded() {
  let schedule = ScheduleSpec::cron("* * * * *", "UTC").expect("valid cron");
  let error = schedule
    .coalesce(60, 10_000, 10)
    .expect_err("bounded search must stop");
  assert_eq!(error, OccurrenceError::SearchExhausted);

  let interval = ScheduleSpec::fixed_interval(0, 1).expect("valid interval");
  let saturated = interval
    .coalesce(1, i64::from(u32::MAX) + 10, 1)
    .expect("fixed intervals coalesce arithmetically");
  assert_eq!(saturated.skipped_count, u32::MAX);
  assert!(saturated.skipped_count_saturated);
}

#[test]
fn test_durable_snapshots_reject_oversize_and_forbidden_keys_but_not_instruction_text() {
  let oversized = format!(r#"{{"instruction":"{}"}}"#, "x".repeat(256 * 1024));
  assert!(matches!(
    ScheduledJobDefinition::new(1, oversized),
    Err(StateValueError::TooLarge { .. })
  ));
  for fixture in [
    r#"{"token":"live"}"#,
    r#"{"nested":{"private-key":"live"}}"#,
    r#"{"event_id":"Ev123"}"#,
    r#"{"origin":{"thread":"live"}}"#,
  ] {
    assert!(matches!(
      ScheduledJobDefinition::new(1, fixture),
      Err(StateValueError::ForbiddenDurableData { .. })
    ));
  }
  assert!(
    ScheduledJobDefinition::new(
      1,
      r#"{"instruction":"Check whether the prose mentions token, password, or Slack event_id"}"#,
    )
    .is_ok()
  );
}

#[tokio::test]
async fn test_delivery_target_count_and_aggregate_snapshot_bounds_are_enforced() {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state");
  let store = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize state store");
  let mut too_many = create_request("too-many-targets", ScheduleSpec::once(110), 100);
  too_many.targets = (0..33)
    .map(|index| {
      DeliveryTargetSnapshot::new(
        format!("target-{index}"),
        "none",
        "none",
        "none",
        "none",
        "{}",
        1,
        "resolver-v1",
        format!("identity-{index}"),
      )
      .expect("target")
    })
    .collect();
  assert!(store.create_scheduled_job(&too_many).await.is_err());

  let mut aggregate = create_request("large-targets", ScheduleSpec::once(110), 100);
  aggregate.targets = (0..32)
    .map(|index| {
      DeliveryTargetSnapshot::new(
        format!("large-target-{index}"),
        "none",
        "none",
        "none",
        "none",
        format!(r#"{{"address":"{}"}}"#, "x".repeat(8_200)),
        1,
        "resolver-v1",
        format!("large-identity-{index}"),
      )
      .expect("target")
    })
    .collect();
  assert!(store.create_scheduled_job(&aggregate).await.is_err());
}

#[tokio::test]
async fn test_initialize_adds_scheduler_tables_and_constraints() {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state");
  StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize state store");

  let pool = SqlitePool::connect(&database_url(&state_dir))
    .await
    .expect("connect database");
  let tables: Vec<String> = sqlx::query_scalar(
    "select name from sqlite_master where type = 'table' and (name like 'scheduled_%' or name = 'schedules') order by name",
  )
  .fetch_all(&pool)
  .await
  .expect("query scheduler tables");

  for table in [
    "scheduled_delivery_baselines",
    "scheduled_execution_baselines",
    "scheduled_job_delivery_targets",
    "scheduled_jobs",
    "scheduled_run_deliveries",
    "scheduled_run_attempts",
    "scheduled_run_late_evidence",
    "scheduled_run_result_artifacts",
    "scheduled_runs",
    "schedules",
  ] {
    assert!(tables.iter().any(|name| name == table), "missing {table}");
  }
}

#[tokio::test]
async fn test_once_materialization_is_atomic_snapshot_and_completes_job() {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state");
  let store = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize state store");
  store
    .create_scheduled_job(&create_request("once", ScheduleSpec::once(110), 100))
    .await
    .expect("create job");

  assert_eq!(
    store
      .materialize_due_schedule("once", 0, 109)
      .await
      .expect("not due"),
    MaterializationOutcome::NotDue
  );
  let MaterializationOutcome::Created(run) = store
    .materialize_due_schedule("once", 0, 110)
    .await
    .expect("materialize")
  else {
    panic!("expected created run");
  };
  assert_eq!(run.scheduled_for, 110);
  assert_eq!(run.state.as_str(), "pending");

  let job = store
    .get_scheduled_job("once")
    .await
    .expect("get job")
    .expect("job exists");
  assert_eq!(job.status, ScheduledJobStatus::Completed);
  assert_eq!(job.next_run_at, None);

  let pool = SqlitePool::connect(&database_url(&state_dir))
    .await
    .expect("connect database");
  let snapshots: (i64, i64, i64) = sqlx::query_as(
    "select json_valid(definition_json), json_valid(targets_json), json_valid(execution_baseline_json) from scheduled_runs where run_id = ?1",
  )
  .bind(run.run_id)
  .fetch_one(&pool)
  .await
  .expect("read snapshots");
  assert_eq!(snapshots, (1, 1, 1));
}

#[tokio::test]
async fn test_interval_coalesces_and_overlap_forbid_blocks_next_run() {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state");
  let store = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize state store");
  let schedule = ScheduleSpec::fixed_interval(110, 30).expect("interval");
  store
    .create_scheduled_job(&create_request("interval", schedule, 100))
    .await
    .expect("create job");

  let MaterializationOutcome::Created(run) = store
    .materialize_due_schedule("interval", 0, 191)
    .await
    .expect("materialize")
  else {
    panic!("expected created run");
  };
  assert_eq!(run.scheduled_for, 110);
  assert_eq!(run.coalesced_through, 170);
  assert_eq!(run.skipped_count, 2);
  assert_eq!(
    store
      .materialize_due_schedule("interval", 0, 200)
      .await
      .expect("blocked"),
    MaterializationOutcome::Blocked
  );
  assert!(
    store
      .list_due_scheduled_jobs(200, 10)
      .await
      .expect("due")
      .is_empty()
  );
}

#[tokio::test]
async fn test_pause_resume_and_update_use_generation_cas() {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state");
  let store = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize state store");
  let schedule = ScheduleSpec::fixed_interval(110, 30).expect("interval");
  store
    .create_scheduled_job(&create_request("lifecycle", schedule, 100))
    .await
    .expect("create job");
  store
    .materialize_due_schedule("lifecycle", 0, 110)
    .await
    .expect("materialize");

  assert_eq!(
    store
      .pause_scheduled_job("lifecycle", 0, 111)
      .await
      .expect("pause"),
    1
  );
  assert!(matches!(
    store.pause_scheduled_job("lifecycle", 0, 112).await,
    Err(StateError::SchedulerGenerationConflict)
  ));
  assert_eq!(
    store
      .resume_scheduled_job("lifecycle", 1, 200)
      .await
      .expect("resume"),
    2
  );
  let updated = UpdateScheduledJob {
    job_id: "lifecycle".to_owned(),
    expected_generation: 2,
    definition: ScheduledJobDefinition::new(2, r#"{"prompt":"updated"}"#).expect("definition"),
    capability: CapabilityProfileSnapshot::new(2, "profile-v2", r#"{"tools":[]}"#)
      .expect("capability"),
    targets: vec![target("updated")],
    schedule: ScheduleSpec::fixed_interval(250, 60).expect("updated interval"),
    now: 210,
  };
  assert_eq!(
    store.update_scheduled_job(&updated).await.expect("update"),
    3
  );
  let job = store
    .get_scheduled_job("lifecycle")
    .await
    .expect("get job")
    .expect("job");
  assert_eq!(job.generation, 3);
  assert_eq!(job.definition.version(), 2);
  assert_eq!(job.next_run_at, Some(250));
}

#[tokio::test]
async fn test_idempotent_mutation_commits_mutation_and_exact_response_together() {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state");
  let store = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize state store");
  let mutation = ScheduledJobMutation::Create(Box::new(create_request(
    "transactional",
    ScheduleSpec::once(110),
    100,
  )));
  let idempotency = mutation_idempotency("transactional-create", "digest-a");
  assert_eq!(
    store
      .apply_idempotent_schedule_mutation(&mutation, &idempotency)
      .await
      .expect("apply mutation"),
    TransactionalMutationOutcome::Applied(idempotency.response_json.clone())
  );
  assert_eq!(
    store
      .apply_idempotent_schedule_mutation(&mutation, &idempotency)
      .await
      .expect("replay mutation"),
    TransactionalMutationOutcome::Replay(idempotency.response_json.clone())
  );
  let conflicting = mutation_idempotency("transactional-create", "digest-b");
  assert_eq!(
    store
      .apply_idempotent_schedule_mutation(&mutation, &conflicting)
      .await
      .expect("conflict mutation"),
    TransactionalMutationOutcome::Conflict
  );
  assert!(
    store
      .get_scheduled_job("transactional")
      .await
      .expect("get job")
      .is_some()
  );
}

#[tokio::test]
async fn test_failed_idempotent_mutation_rolls_back_claim_and_completed_record() {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state");
  let store = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize state store");
  let request = create_request("rollback", ScheduleSpec::once(110), 100);
  store
    .create_scheduled_job(&request)
    .await
    .expect("create conflicting job");
  let mutation = ScheduledJobMutation::Create(Box::new(request));
  let idempotency = mutation_idempotency("rollback-request", "rollback-digest");
  assert!(
    store
      .apply_idempotent_schedule_mutation(&mutation, &idempotency)
      .await
      .is_err()
  );

  let pool = SqlitePool::connect(&database_url(&state_dir))
    .await
    .expect("connect database");
  let records: i64 =
    sqlx::query_scalar("select count(*) from idempotency_keys where key = 'rollback-request'")
      .fetch_one(&pool)
      .await
      .expect("count idempotency records");
  assert_eq!(records, 0);
}

#[tokio::test]
async fn test_idempotent_typed_lifecycle_mutation_and_in_progress_result() {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state");
  let store = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize state store");
  store
    .create_scheduled_job(&create_request(
      "typed-lifecycle",
      ScheduleSpec::fixed_interval(110, 30).expect("interval"),
      100,
    ))
    .await
    .expect("create job");
  let mutation = ScheduledJobMutation::Pause {
    job_id: "typed-lifecycle".to_owned(),
    expected_generation: 0,
    now: 101,
  };
  let idempotency = mutation_idempotency("pause-request", "pause-digest");
  let pool = SqlitePool::connect(&database_url(&state_dir))
    .await
    .expect("connect database");
  sqlx::query(
    r#"insert into idempotency_keys (scope, key, status, request_digest, digest_algorithm) values ('{"kind":"user","operation":"pause","provider":"slack","subject":"U1","tenant":"workspace"}', 'pause-request', 'claimed', 'pause-digest', 'sha256-v1')"#,
  )
  .execute(&pool)
  .await
  .expect("insert in-progress fixture");
  assert_eq!(
    store
      .apply_idempotent_schedule_mutation(&mutation, &idempotency)
      .await
      .expect("in progress result"),
    TransactionalMutationOutcome::InProgress
  );
  let independent = mutation_idempotency("pause-request-2", "pause-digest-2");
  assert_eq!(
    store
      .apply_idempotent_schedule_mutation(&mutation, &independent)
      .await
      .expect("apply pause"),
    TransactionalMutationOutcome::Applied(independent.response_json)
  );
  assert_eq!(
    store
      .get_scheduled_job("typed-lifecycle")
      .await
      .expect("get job")
      .expect("job")
      .status,
    ScheduledJobStatus::Paused
  );
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn test_current_schema_upgrades_forward_and_repeated_initialize_is_safe() {
  let temp = tempdir().expect("create tempdir");
  let old_migrations = temp.path().join("old-migrations");
  std::fs::create_dir(&old_migrations).expect("create migration fixture");
  let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
  for entry in std::fs::read_dir(source).expect("read migrations") {
    let entry = entry.expect("migration entry");
    if !matches!(
      entry.file_name().to_str(),
      Some("20260721030000_scheduler_execution_hardening.sql")
    ) {
      std::fs::copy(entry.path(), old_migrations.join(entry.file_name()))
        .expect("copy historical migration");
    }
  }

  let state_dir = temp.path().join("state");
  std::fs::create_dir(&state_dir).expect("create state dir");
  let options = SqliteConnectOptions::from_str(&database_url(&state_dir))
    .expect("database options")
    .create_if_missing(true);
  let pool = SqlitePoolOptions::new()
    .max_connections(1)
    .connect_with(options)
    .await
    .expect("connect old database");
  Migrator::new(old_migrations)
    .await
    .expect("load historical migrator")
    .run(&pool)
    .await
    .expect("run historical migrations");
  sqlx::query(
    "insert into idempotency_keys (scope, key, status, response_ref) values ('legacy', 'preserved', 'completed', 'legacy-ref')",
  )
  .execute(&pool)
  .await
  .expect("insert representative legacy idempotency row");
  for (ordinal, (label, state)) in [
    ("pending", "pending"),
    ("leased", "leased"),
    ("executing", "executing"),
    ("succeeded-valid", "succeeded"),
    ("succeeded-matching", "succeeded"),
    ("succeeded-invalid", "succeeded"),
  ]
  .into_iter()
  .enumerate()
  {
    let job_id = format!("upgrade-{label}");
    let schedule_id = format!("schedule-{label}");
    sqlx::query("insert into scheduled_jobs (job_id, definition_version, definition_json, creator_kind, creator_provider, creator_tenant, creator_subject, owner_kind, owner_provider, owner_tenant, owner_subject, status, generation, capability_schema_version, capability_digest, capability_json, created_at, updated_at) values (?1, 1, '{}', 'user', 'test', 'tenant', 'creator', 'user', 'test', 'tenant', 'owner', 'active', 0, 1, 'profile', '{}', 100, 100)")
      .bind(&job_id)
      .execute(&pool)
      .await
      .expect("seed parent job");
    sqlx::query("insert into schedules (schedule_id, job_id, kind, canonical_spec, once_at, next_run_at, created_at, updated_at) values (?1, ?2, 'once', '200', 200, 200, 100, 100)")
      .bind(&schedule_id)
      .bind(&job_id)
      .execute(&pool)
      .await
      .expect("seed parent schedule");
    sqlx::query("insert into scheduled_execution_baselines (job_id) values (?1)")
      .bind(&job_id)
      .execute(&pool)
      .await
      .expect("seed parent baseline");
    let run_id = format!("upgrade-run-{label}");
    let overlap_slot = (state != "succeeded").then_some(1_i64);
    let lease_owner = matches!(state, "leased" | "executing").then_some("legacy-worker");
    let lease_expires_at = lease_owner.map(|_| 200_i64);
    let has_legacy_result = matches!(label, "succeeded-valid" | "succeeded-matching");
    let result_context = has_legacy_result.then_some("legacy context");
    let result_hash_algorithm = has_legacy_result.then_some("legacy-digest-v1");
    let result_hash = has_legacy_result.then_some(label);
    let has_current_attempt =
      matches!(state, "leased" | "executing") || label == "succeeded-matching";
    let attempt = i64::from(has_current_attempt);
    let fence = attempt * 2;
    sqlx::query("insert into scheduled_runs (run_id, job_id, schedule_id, job_generation, schedule_generation, scheduled_for, coalesced_through, definition_version, definition_json, capability_schema_version, capability_digest, capability_json, targets_json, state, attempt, fence, lease_owner, lease_expires_at, overlap_slot, result_context, result_hash_algorithm, result_hash, created_at, updated_at) values (?1, ?2, ?3, 0, 0, ?4, ?4, 1, '{}', 1, 'profile', '{}', '[{}]', ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, 100, 100)")
      .bind(run_id)
      .bind(&job_id)
      .bind(&schedule_id)
      .bind(110 + i64::try_from(ordinal).expect("ordinal"))
      .bind(state)
      .bind(attempt)
      .bind(fence)
      .bind(lease_owner)
      .bind(lease_expires_at)
      .bind(overlap_slot)
      .bind(result_context)
      .bind(result_hash_algorithm)
      .bind(result_hash)
      .execute(&pool)
      .await
      .expect("seed parent run");
    if has_current_attempt {
      let attested = (state != "leased").then_some(r#"{"legacy_test":true}"#);
      sqlx::query("insert into scheduled_run_attempts (run_id, job_id, attempt, fence, lease_owner, state, claimed_at, lease_expires_at, preflight_completed_at, executing_at, completed_at, attested_profile_schema_version, attested_profile_json, attested_profile_hash_algorithm, attested_profile_digest) values (?1, ?2, 1, 2, 'legacy-worker', ?3, 90, 200, ?4, ?4, ?5, ?6, ?7, ?8, ?9)")
        .bind(format!("upgrade-run-{label}"))
        .bind(&job_id)
        .bind(state)
        .bind((state != "leased").then_some(100_i64))
        .bind((state == "succeeded").then_some(100_i64))
        .bind(attested.map(|_| 1_i64))
        .bind(attested)
        .bind(attested.map(|_| "sha256-v1"))
        .bind(attested.map(|_| "attested"))
        .execute(&pool)
        .await
        .expect("seed parent current attempt");
    }
  }
  pool.close().await;

  StateStore::initialize(&state_dir, None)
    .await
    .expect("upgrade current schema");
  StateStore::initialize(&state_dir, None)
    .await
    .expect("repeat upgraded initialize");
  let pool = SqlitePool::connect(&database_url(&state_dir))
    .await
    .expect("connect upgraded database");
  let scheduler_migrations: i64 = sqlx::query_scalar(
    "select count(*) from _sqlx_migrations where version in (20260721020000, 20260721030000) and success = true",
  )
  .fetch_one(&pool)
  .await
  .expect("query scheduler migration");
  assert_eq!(scheduler_migrations, 2);
  let upgraded: Vec<(String, String, i64)> = sqlx::query_as(
    "select r.run_id, r.state, (select count(*) from scheduled_run_attempts a where a.run_id = r.run_id) from scheduled_runs r where r.run_id like 'upgrade-run-%' order by r.run_id",
  )
  .fetch_all(&pool)
  .await
  .expect("read upgraded runs");
  assert_eq!(
    upgraded,
    vec![
      (
        "upgrade-run-executing".to_owned(),
        "outcome_unknown".to_owned(),
        1
      ),
      ("upgrade-run-leased".to_owned(), "pending".to_owned(), 1),
      ("upgrade-run-pending".to_owned(), "pending".to_owned(), 0),
      (
        "upgrade-run-succeeded-invalid".to_owned(),
        "outcome_unknown".to_owned(),
        1
      ),
      (
        "upgrade-run-succeeded-matching".to_owned(),
        "succeeded".to_owned(),
        1
      ),
      (
        "upgrade-run-succeeded-valid".to_owned(),
        "succeeded".to_owned(),
        1
      ),
    ]
  );
  let legacy_artifacts: Vec<(String, String, String, String, String)> = sqlx::query_as(
    "select r.run_id, r.result_artifact_id, a.provenance, a.hash_algorithm, a.previous_success_context from scheduled_runs r join scheduled_run_result_artifacts a on a.artifact_id = r.result_artifact_id where r.run_id like 'upgrade-run-succeeded-%' order by r.run_id",
  )
  .fetch_all(&pool)
  .await
  .expect("read migrated legacy artifacts");
  assert_eq!(legacy_artifacts.len(), 2);
  for (run_id, artifact_id, provenance, hash_algorithm, context) in legacy_artifacts {
    assert_eq!(artifact_id, format!("legacy-result:{run_id}"));
    assert_eq!(provenance, "legacy");
    assert_eq!(hash_algorithm, "legacy-digest-v1");
    assert_eq!(context, "legacy context");
  }
  let foreign_key_errors: i64 = sqlx::query_scalar("select count(*) from pragma_foreign_key_check")
    .fetch_one(&pool)
    .await
    .expect("check upgraded foreign keys");
  assert_eq!(foreign_key_errors, 0);
  let legacy: (String, Option<String>, Option<String>, Option<String>) = sqlx::query_as(
    "select status, response_ref, request_digest, response_json from idempotency_keys where scope = 'legacy' and key = 'preserved'",
  )
  .fetch_one(&pool)
  .await
  .expect("read preserved legacy idempotency row");
  assert_eq!(
    legacy,
    (
      "completed".to_owned(),
      Some("legacy-ref".to_owned()),
      None,
      None
    )
  );
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn test_execution_hardening_migration_rejects_mismatched_current_attempt() {
  let temp = tempdir().expect("create tempdir");
  let old_migrations = temp.path().join("old-migrations");
  std::fs::create_dir(&old_migrations).expect("create migration fixture");
  let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
  for entry in std::fs::read_dir(source).expect("read migrations") {
    let entry = entry.expect("migration entry");
    if entry.file_name() != "20260721030000_scheduler_execution_hardening.sql" {
      std::fs::copy(entry.path(), old_migrations.join(entry.file_name()))
        .expect("copy parent migration");
    }
  }
  let state_dir = temp.path().join("state");
  std::fs::create_dir(&state_dir).expect("create state dir");
  let options = SqliteConnectOptions::from_str(&database_url(&state_dir))
    .expect("database options")
    .create_if_missing(true);
  let pool = SqlitePoolOptions::new()
    .max_connections(1)
    .connect_with(options)
    .await
    .expect("connect parent database");
  Migrator::new(old_migrations)
    .await
    .expect("load parent migrator")
    .run(&pool)
    .await
    .expect("run parent migrations");
  sqlx::query("insert into scheduled_jobs (job_id, definition_version, definition_json, creator_kind, creator_provider, creator_tenant, creator_subject, owner_kind, owner_provider, owner_tenant, owner_subject, status, generation, capability_schema_version, capability_digest, capability_json, created_at, updated_at) values ('mismatch', 1, '{}', 'user', 'test', 'tenant', 'creator', 'user', 'test', 'tenant', 'owner', 'active', 0, 1, 'profile', '{}', 100, 100)")
    .execute(&pool)
    .await
    .expect("seed job");
  sqlx::query("insert into schedules (schedule_id, job_id, kind, canonical_spec, once_at, next_run_at, created_at, updated_at) values ('schedule-mismatch', 'mismatch', 'once', '200', 200, 200, 100, 100)")
    .execute(&pool)
    .await
    .expect("seed schedule");
  sqlx::query("insert into scheduled_execution_baselines (job_id) values ('mismatch')")
    .execute(&pool)
    .await
    .expect("seed baseline");
  sqlx::query("insert into scheduled_runs (run_id, job_id, schedule_id, job_generation, schedule_generation, scheduled_for, coalesced_through, definition_version, definition_json, capability_schema_version, capability_digest, capability_json, targets_json, state, attempt, fence, lease_owner, lease_expires_at, overlap_slot, created_at, updated_at) values ('mismatch-run', 'mismatch', 'schedule-mismatch', 0, 0, 110, 110, 1, '{}', 1, 'profile', '{}', '[{}]', 'leased', 1, 2, 'worker', 200, 1, 100, 100)")
    .execute(&pool)
    .await
    .expect("seed run");
  sqlx::query("insert into scheduled_run_attempts (run_id, job_id, attempt, fence, lease_owner, state, claimed_at, lease_expires_at) values ('mismatch-run', 'mismatch', 1, 3, 'worker', 'leased', 100, 200)")
    .execute(&pool)
    .await
    .expect("seed mismatched attempt");
  pool.close().await;

  assert!(matches!(
    StateStore::initialize(&state_dir, None).await,
    Err(StateError::Migrate { .. })
  ));
  let pool = SqlitePool::connect(&database_url(&state_dir))
    .await
    .expect("reopen rejected database");
  let unchanged: (String, i64, i64, String) = sqlx::query_as(
    "select r.state, r.fence, a.fence, a.state from scheduled_runs r join scheduled_run_attempts a on a.run_id = r.run_id where r.run_id = 'mismatch-run'",
  )
  .fetch_one(&pool)
  .await
  .expect("read rolled back mismatch");
  assert_eq!(unchanged, ("leased".to_owned(), 2, 3, "leased".to_owned()));
  let hardening_applied: i64 = sqlx::query_scalar(
    "select count(*) from _sqlx_migrations where version = 20260721030000 and success = true",
  )
  .fetch_one(&pool)
  .await
  .expect("read hardening migration state");
  assert_eq!(hardening_applied, 0);
}

#[tokio::test]
async fn test_two_independent_stores_materialize_only_one_logical_occurrence() {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state");
  let first = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize first store");
  let second = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize second store");
  first
    .create_scheduled_job(&create_request("race", ScheduleSpec::once(110), 100))
    .await
    .expect("create job");
  let barrier = Arc::new(Barrier::new(3));
  let first_task = tokio::spawn(materialize_after_barrier(first, Arc::clone(&barrier)));
  let second_task = tokio::spawn(materialize_after_barrier(second, Arc::clone(&barrier)));
  barrier.wait().await;
  let results = [
    first_task.await.expect("first task"),
    second_task.await.expect("second task"),
  ];

  assert_eq!(
    results
      .iter()
      .filter(|result| matches!(result, Ok(MaterializationOutcome::Created(_))))
      .count(),
    1
  );
  for result in &results {
    if let Err(error) = result {
      assert!(
        error.is_transient_storage_contention(),
        "unexpected error: {error}"
      );
    }
  }
  let pool = SqlitePool::connect(&database_url(&state_dir))
    .await
    .expect("connect database");
  let runs: i64 = sqlx::query_scalar(
    "select count(*) from scheduled_runs where job_id = 'race' and scheduled_for = 110",
  )
  .fetch_one(&pool)
  .await
  .expect("count runs");
  assert_eq!(runs, 1);
}

async fn materialize_after_barrier(
  store: StateStore,
  barrier: Arc<Barrier>,
) -> Result<MaterializationOutcome, StateError> {
  barrier.wait().await;
  store.materialize_due_schedule("race", 0, 110).await
}

#[tokio::test]
async fn test_two_independent_stores_claim_one_run_and_create_one_bound_attempt() {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state");
  let first = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize first store");
  let second = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize second store");
  first
    .create_scheduled_job(&create_request("claim-race", ScheduleSpec::once(110), 100))
    .await
    .expect("create job");
  first
    .materialize_due_schedule("claim-race", 0, 110)
    .await
    .expect("materialize");

  let barrier = Arc::new(Barrier::new(3));
  let first_task = tokio::spawn(claim_after_barrier(first, "worker-a", Arc::clone(&barrier)));
  let second_task = tokio::spawn(claim_after_barrier(
    second,
    "worker-b",
    Arc::clone(&barrier),
  ));
  barrier.wait().await;
  let results = [
    first_task.await.expect("first claim task"),
    second_task.await.expect("second claim task"),
  ];
  let claims = results
    .iter()
    .filter_map(|result| result.as_ref().ok().and_then(Option::as_ref))
    .collect::<Vec<_>>();
  assert_eq!(claims.len(), 1);
  for result in &results {
    if let Err(error) = result {
      assert!(
        error.is_transient_storage_contention(),
        "unexpected claim error: {error}"
      );
    }
  }
  let claim = claims[0];
  assert_eq!(claim.binding.attempt(), 1);
  assert_eq!(claim.binding.fence(), 1);

  let pool = SqlitePool::connect(&database_url(&state_dir))
    .await
    .expect("connect database");
  let persisted: (i64, i64, i64, String) = sqlx::query_as(
    "select (select count(*) from scheduled_run_attempts where run_id = ?1), attempt, fence, lease_owner from scheduled_runs where run_id = ?1",
  )
  .bind(claim.binding.run_id())
  .fetch_one(&pool)
  .await
  .expect("read claimed run");
  assert_eq!(persisted, (1, 1, 1, claim.binding.lease_owner().to_owned()));
}

async fn claim_after_barrier(
  store: StateStore,
  owner: &'static str,
  barrier: Arc<Barrier>,
) -> Result<Option<ClaimedScheduledRun>, StateError> {
  barrier.wait().await;
  store.claim_next_scheduled_run(owner, 111, 141).await
}

#[tokio::test]
async fn test_claim_reports_attempt_and_fence_counter_exhaustion_without_mutation() {
  assert_counter_exhaustion(true).await;
  assert_counter_exhaustion(false).await;
}

async fn assert_counter_exhaustion(exhaust_attempt: bool) {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state");
  let store = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize store");
  let job_id = if exhaust_attempt {
    "attempt-exhausted"
  } else {
    "fence-exhausted"
  };
  store
    .create_scheduled_job(&create_request(job_id, ScheduleSpec::once(110), 100))
    .await
    .expect("create job");
  let MaterializationOutcome::Created(run) = store
    .materialize_due_schedule(job_id, 0, 110)
    .await
    .expect("materialize")
  else {
    panic!("expected run");
  };
  let pool = SqlitePool::connect(&database_url(&state_dir))
    .await
    .expect("connect database");
  let (attempt, fence) = if exhaust_attempt {
    (i64::MAX, 7_i64)
  } else {
    (7_i64, i64::MAX)
  };
  sqlx::query("update scheduled_runs set attempt = ?1, fence = ?2 where run_id = ?3")
    .bind(attempt)
    .bind(fence)
    .bind(&run.run_id)
    .execute(&pool)
    .await
    .expect("seed exhausted counter");
  assert!(matches!(
    store.claim_next_scheduled_run("worker", 111, 141).await,
    Err(StateError::ScheduledRunCounterExhausted)
  ));
  let unchanged: (String, i64, i64, Option<String>, i64) = sqlx::query_as(
    "select state, attempt, fence, lease_owner, (select count(*) from scheduled_run_attempts where run_id = ?1) from scheduled_runs where run_id = ?1",
  )
  .bind(&run.run_id)
  .fetch_one(&pool)
  .await
  .expect("read unchanged run");
  assert_eq!(unchanged, ("pending".to_owned(), attempt, fence, None, 0));
}

#[tokio::test]
async fn test_claim_increments_attempt_and_fence_independently_and_attests_before_executing() {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state");
  let store = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize state store");
  store
    .create_scheduled_job(&create_request(
      "claim-counters",
      ScheduleSpec::once(110),
      100,
    ))
    .await
    .expect("create job");
  let MaterializationOutcome::Created(run) = store
    .materialize_due_schedule("claim-counters", 0, 110)
    .await
    .expect("materialize")
  else {
    panic!("expected run");
  };
  let pool = SqlitePool::connect(&database_url(&state_dir))
    .await
    .expect("connect database");
  sqlx::query("update scheduled_runs set attempt = 4, fence = 9 where run_id = ?1")
    .bind(&run.run_id)
    .execute(&pool)
    .await
    .expect("seed independent counters");

  let claim = store
    .claim_next_scheduled_run("worker", 111, 141)
    .await
    .expect("claim")
    .expect("claimed run");
  assert_eq!(claim.binding.attempt(), 5);
  assert_eq!(claim.binding.fence(), 10);
  let profile = AttestedExecutionProfileSnapshot::new(
    1,
    r#"{"codex_version":"test","tools":["github.read"]}"#,
    "sha256-v1",
    "profile-digest",
  )
  .expect("profile");
  store
    .mark_scheduled_run_executing(&claim.binding, &profile, 112)
    .await
    .expect("mark executing");
  store
    .heartbeat_scheduled_run(&claim.binding, 120, 160)
    .await
    .expect("heartbeat");

  let persisted: (String, String, i64, String, i64) = sqlx::query_as(
    "select r.state, a.state, a.executing_at, a.attested_profile_digest, r.lease_expires_at from scheduled_runs r join scheduled_run_attempts a on a.run_id = r.run_id and a.attempt = r.attempt where r.run_id = ?1",
  )
  .bind(run.run_id)
  .fetch_one(&pool)
  .await
  .expect("read executing state");
  assert_eq!(
    persisted,
    (
      "executing".to_owned(),
      "executing".to_owned(),
      112,
      "profile-digest".to_owned(),
      160,
    )
  );
  assert!(matches!(
    store
      .heartbeat_scheduled_run(&claim.binding, 160, 180)
      .await,
    Err(StateError::ScheduledRunLostLease)
  ));
  let expiries: (i64, i64) = sqlx::query_as(
    "select r.lease_expires_at, a.lease_expires_at from scheduled_runs r join scheduled_run_attempts a on a.run_id = r.run_id and a.attempt = r.attempt where r.run_id = ?1",
  )
  .bind(claim.binding.run_id())
  .fetch_one(&pool)
  .await
  .expect("read unchanged expiries");
  assert_eq!(expiries, (160, 160));
}

#[tokio::test]
async fn test_two_independent_stores_cannot_apply_equal_heartbeat_extension() {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state");
  let first = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize first store");
  let second = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize second store");
  first
    .create_scheduled_job(&create_request(
      "heartbeat-race",
      ScheduleSpec::once(110),
      100,
    ))
    .await
    .expect("create job");
  first
    .materialize_due_schedule("heartbeat-race", 0, 110)
    .await
    .expect("materialize");
  let claim = first
    .claim_next_scheduled_run("worker", 111, 140)
    .await
    .expect("claim")
    .expect("claimed run");
  let barrier = Arc::new(Barrier::new(3));
  let first_task = tokio::spawn(heartbeat_after_barrier(
    first,
    claim.binding.clone(),
    Arc::clone(&barrier),
  ));
  let second_task = tokio::spawn(heartbeat_after_barrier(
    second,
    claim.binding.clone(),
    Arc::clone(&barrier),
  ));
  barrier.wait().await;
  let outcomes = [
    first_task.await.expect("first heartbeat task"),
    second_task.await.expect("second heartbeat task"),
  ];
  assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
  for outcome in outcomes.iter().filter(|outcome| outcome.is_err()) {
    let error = outcome.as_ref().expect_err("error outcome");
    assert!(
      error.is_transient_storage_contention() || matches!(error, StateError::ScheduledRunLostLease)
    );
  }
  let pool = SqlitePool::connect(&database_url(&state_dir))
    .await
    .expect("connect database");
  let expiries: (i64, i64) = sqlx::query_as(
    "select r.lease_expires_at, a.lease_expires_at from scheduled_runs r join scheduled_run_attempts a on a.run_id = r.run_id and a.attempt = r.attempt where r.run_id = ?1",
  )
  .bind(claim.binding.run_id())
  .fetch_one(&pool)
  .await
  .expect("read heartbeat expiries");
  assert_eq!(expiries, (180, 180));
}

async fn heartbeat_after_barrier(
  store: StateStore,
  binding: codeoff_state::RunLeaseBinding,
  barrier: Arc<Barrier>,
) -> Result<(), StateError> {
  barrier.wait().await;
  store.heartbeat_scheduled_run(&binding, 120, 180).await
}

#[tokio::test]
async fn test_preflight_failure_never_executes_and_expired_lease_has_one_reclaimer() {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state");
  let first = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize first store");
  let second = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize second store");
  let request = create_request("reclaim-race", ScheduleSpec::once(110), 100);
  first
    .create_scheduled_job(&request)
    .await
    .expect("create job");
  first
    .materialize_due_schedule("reclaim-race", 0, 110)
    .await
    .expect("materialize");
  let first_claim = first
    .claim_next_scheduled_run("worker-a", 111, 120)
    .await
    .expect("claim")
    .expect("claimed run");

  let barrier = Arc::new(Barrier::new(3));
  let first_task = tokio::spawn(reclaim_after_barrier(first, Arc::clone(&barrier)));
  let second_task = tokio::spawn(reclaim_after_barrier(second, Arc::clone(&barrier)));
  barrier.wait().await;
  let outcomes = [
    first_task.await.expect("first reclaim task"),
    second_task.await.expect("second reclaim task"),
  ];
  assert_eq!(
    outcomes
      .iter()
      .filter(|outcome| matches!(outcome, Ok(ExpiredRunReclaimOutcome::Retried { .. })))
      .count(),
    1
  );
  for outcome in &outcomes {
    if let Err(error) = outcome {
      assert!(
        error.is_transient_storage_contention()
          || matches!(error, StateError::ScheduledRunLostLease),
        "unexpected reclaim error: {error}"
      );
    }
  }
  let profile = AttestedExecutionProfileSnapshot::new(
    1,
    r#"{"codex_version":"test"}"#,
    "sha256-v1",
    "profile-digest",
  )
  .expect("profile");
  assert!(matches!(
    StateStore::initialize(&state_dir, None)
      .await
      .expect("reopen")
      .mark_scheduled_run_executing(&first_claim.binding, &profile, 122)
      .await,
    Err(StateError::ScheduledRunLostLease)
  ));

  let store = StateStore::initialize(&state_dir, None)
    .await
    .expect("reopen store");
  let second_claim = store
    .claim_next_scheduled_run("worker-b", 130, 160)
    .await
    .expect("claim retry")
    .expect("retried run");
  store
    .record_scheduled_run_preflight_failure(
      &second_claim.binding,
      PreflightFailureDisposition::RetryAt(170),
      "executor_unavailable",
      "executor unavailable",
      140,
    )
    .await
    .expect("record preflight retry");
  let pool = SqlitePool::connect(&database_url(&state_dir))
    .await
    .expect("connect database");
  let states: (String, String, Option<i64>, i64) = sqlx::query_as(
    "select r.state, a.state, r.next_attempt_at, r.overlap_slot from scheduled_runs r join scheduled_run_attempts a on a.run_id = r.run_id and a.attempt = r.attempt where r.run_id = ?1",
  )
  .bind(second_claim.binding.run_id())
  .fetch_one(&pool)
  .await
  .expect("read retry states");
  assert_eq!(
    states,
    (
      "pending".to_owned(),
      "retry_scheduled".to_owned(),
      Some(170),
      1,
    )
  );
}

async fn reclaim_after_barrier(
  store: StateStore,
  barrier: Arc<Barrier>,
) -> Result<ExpiredRunReclaimOutcome, StateError> {
  barrier.wait().await;
  store.reclaim_next_expired_scheduled_run(121, 3, 130).await
}

#[tokio::test]
async fn test_expired_executing_run_becomes_outcome_unknown_and_keeps_overlap() {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state");
  let store = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize store");
  store
    .create_scheduled_job(&create_request("unknown", ScheduleSpec::once(110), 100))
    .await
    .expect("create job");
  store
    .materialize_due_schedule("unknown", 0, 110)
    .await
    .expect("materialize");
  let claim = store
    .claim_next_scheduled_run("worker", 111, 120)
    .await
    .expect("claim")
    .expect("claimed run");
  let profile = AttestedExecutionProfileSnapshot::new(
    1,
    r#"{"codex_version":"test"}"#,
    "sha256-v1",
    "profile-digest",
  )
  .expect("profile");
  store
    .mark_scheduled_run_executing(&claim.binding, &profile, 112)
    .await
    .expect("executing");
  assert!(matches!(
    store
      .reclaim_next_expired_scheduled_run(121, 3, 130)
      .await
      .expect("reclaim"),
    ExpiredRunReclaimOutcome::OutcomeUnknown { .. }
  ));
  let pool = SqlitePool::connect(&database_url(&state_dir))
    .await
    .expect("connect database");
  let states: (String, String, i64) = sqlx::query_as(
    "select r.state, a.state, r.overlap_slot from scheduled_runs r join scheduled_run_attempts a on a.run_id = r.run_id and a.attempt = r.attempt where r.run_id = ?1",
  )
  .bind(claim.binding.run_id())
  .fetch_one(&pool)
  .await
  .expect("read unknown states");
  assert_eq!(
    states,
    (
      "outcome_unknown".to_owned(),
      "outcome_unknown".to_owned(),
      1
    )
  );
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn test_late_evidence_is_typed_bounded_and_quota_safe_across_two_stores() {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state");
  let first = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize first store");
  let second = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize second store");
  first
    .create_scheduled_job(&create_request(
      "late-evidence",
      ScheduleSpec::once(110),
      100,
    ))
    .await
    .expect("create job");
  first
    .materialize_due_schedule("late-evidence", 0, 110)
    .await
    .expect("materialize");
  let claim = first
    .claim_next_scheduled_run("worker", 111, 120)
    .await
    .expect("claim")
    .expect("claimed run");
  first
    .reclaim_next_expired_scheduled_run(121, 1, 130)
    .await
    .expect("reclaim");
  assert!(matches!(
    first
      .append_scheduled_run_late_evidence(
        &claim.binding,
        ScheduledRunLateEvidenceKind::CompletionAfterLeaseLoss,
        &"f".repeat(65),
        122,
      )
      .await,
    Err(StateError::InvalidSchedulerState { .. })
  ));
  let pool = SqlitePool::connect(&database_url(&state_dir))
    .await
    .expect("connect database");
  assert!(
    sqlx::query("insert into scheduled_run_late_evidence (evidence_id, run_id, attempt, fence, evidence_kind, hash_algorithm, evidence_digest, observed_at) values (?1, ?2, ?3, ?4, 'completion_after_lease_loss', 'sha256-v1', 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc', 122)")
      .bind("x".repeat(129))
      .bind(claim.binding.run_id())
      .bind(claim.binding.attempt())
      .bind(claim.binding.fence())
      .execute(&pool)
      .await
      .is_err()
  );
  for ordinal in 0..31 {
    let digest = format!("{ordinal:064x}");
    assert_eq!(
      first
        .append_scheduled_run_late_evidence(
          &claim.binding,
          ScheduledRunLateEvidenceKind::CompletionAfterLeaseLoss,
          &digest,
          122 + ordinal,
        )
        .await
        .expect("append evidence"),
      LateEvidenceAppendOutcome::Recorded
    );
  }
  let duplicate = format!("{:064x}", 0);
  assert_eq!(
    first
      .append_scheduled_run_late_evidence(
        &claim.binding,
        ScheduledRunLateEvidenceKind::CompletionAfterLeaseLoss,
        &duplicate,
        200,
      )
      .await
      .expect("dedupe evidence"),
    LateEvidenceAppendOutcome::Duplicate
  );

  let barrier = Arc::new(Barrier::new(3));
  let first_task = tokio::spawn(late_evidence_after_barrier(
    first,
    claim.binding.clone(),
    31,
    Arc::clone(&barrier),
  ));
  let second_task = tokio::spawn(late_evidence_after_barrier(
    second,
    claim.binding.clone(),
    32,
    Arc::clone(&barrier),
  ));
  barrier.wait().await;
  let outcomes = [
    first_task.await.expect("first evidence task"),
    second_task.await.expect("second evidence task"),
  ];
  assert_eq!(
    outcomes
      .iter()
      .filter(|outcome| matches!(outcome, Ok(LateEvidenceAppendOutcome::Recorded)))
      .count(),
    1
  );
  for outcome in outcomes.iter().filter(|outcome| outcome.is_err()) {
    assert!(
      outcome
        .as_ref()
        .expect_err("error outcome")
        .is_transient_storage_contention()
    );
  }
  let store = StateStore::initialize(&state_dir, None)
    .await
    .expect("reopen store");
  assert_eq!(
    store
      .append_scheduled_run_late_evidence(
        &claim.binding,
        ScheduledRunLateEvidenceKind::HeartbeatAfterLeaseLoss,
        &format!("{:064x}", 100),
        201,
      )
      .await
      .expect("quota outcome"),
    LateEvidenceAppendOutcome::QuotaExceeded
  );

  for statement in [
    "insert into scheduled_run_late_evidence (evidence_id, run_id, attempt, fence, evidence_kind, hash_algorithm, evidence_digest, observed_at) values ('unknown-kind', ?1, ?2, ?3, 'raw_final_output', 'sha256-v1', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 202)",
    "insert into scheduled_run_late_evidence (evidence_id, run_id, attempt, fence, evidence_kind, hash_algorithm, evidence_digest, redacted_message, observed_at) values ('secret-message', ?1, ?2, ?3, 'completion_after_lease_loss', 'sha256-v1', 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 'secret payload', 202)",
  ] {
    assert!(
      sqlx::query(statement)
        .bind(claim.binding.run_id())
        .bind(claim.binding.attempt())
        .bind(claim.binding.fence())
        .execute(&pool)
        .await
        .is_err()
    );
  }
  let authority: (String, i64, i64, i64) = sqlx::query_as(
    "select state, (select count(*) from scheduled_run_result_artifacts where run_id = ?1), (select baseline_version from scheduled_execution_baselines where job_id = 'late-evidence'), (select count(*) from scheduled_run_deliveries where run_id = ?1) from scheduled_runs where run_id = ?1",
  )
  .bind(claim.binding.run_id())
  .fetch_one(&pool)
  .await
  .expect("read unchanged authority");
  assert_eq!(authority, ("failed".to_owned(), 0, 0, 0));
}

async fn late_evidence_after_barrier(
  store: StateStore,
  binding: codeoff_state::RunLeaseBinding,
  ordinal: u64,
  barrier: Arc<Barrier>,
) -> Result<LateEvidenceAppendOutcome, StateError> {
  barrier.wait().await;
  store
    .append_scheduled_run_late_evidence(
      &binding,
      ScheduledRunLateEvidenceKind::CompletionAfterLeaseLoss,
      &format!("{ordinal:064x}"),
      200,
    )
    .await
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn test_result_artifact_is_single_immutable_and_bound_to_accepted_attempt() {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state");
  let store = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize store");
  let profile = AttestedExecutionProfileSnapshot::new(
    1,
    r#"{"codex_version":"test"}"#,
    "sha256-v1",
    "profile-digest",
  )
  .expect("profile");
  let mut claims = Vec::new();
  for job in ["artifact-a", "artifact-b"] {
    store
      .create_scheduled_job(&create_request(job, ScheduleSpec::once(110), 100))
      .await
      .expect("create job");
    store
      .materialize_due_schedule(job, 0, 110)
      .await
      .expect("materialize");
    let claim = store
      .claim_next_scheduled_run(job, 111, 141)
      .await
      .expect("claim")
      .expect("claimed run");
    store
      .mark_scheduled_run_executing(&claim.binding, &profile, 112)
      .await
      .expect("executing");
    claims.push(claim);
  }
  let pool = SqlitePool::connect(&database_url(&state_dir))
    .await
    .expect("connect database");
  for (ordinal, claim) in claims.iter().enumerate() {
    sqlx::query(
      "insert into scheduled_run_result_artifacts (artifact_id, run_id, job_id, accepted_attempt, accepted_fence, schema_version, result_json, hash_algorithm, result_hash, previous_success_context, completed_at) values (?1, ?2, ?3, ?4, ?5, 1, '{}', 'sha256-v1', ?6, 'summary', 120)",
    )
    .bind(format!("artifact-{ordinal}"))
    .bind(claim.binding.run_id())
    .bind(claim.binding.job_id())
    .bind(claim.binding.attempt())
    .bind(claim.binding.fence())
    .bind(format!("hash-{ordinal}"))
    .execute(&pool)
    .await
    .expect("insert accepted artifact");
  }
  assert!(
    sqlx::query(
      "insert into scheduled_run_result_artifacts (artifact_id, run_id, job_id, accepted_attempt, accepted_fence, schema_version, result_json, hash_algorithm, result_hash, previous_success_context, completed_at) values ('duplicate', ?1, ?2, ?3, ?4, 1, '{}', 'sha256-v1', 'different', 'summary', 121)",
    )
    .bind(claims[0].binding.run_id())
    .bind(claims[0].binding.job_id())
    .bind(claims[0].binding.attempt())
    .bind(claims[0].binding.fence())
    .execute(&pool)
    .await
    .is_err()
  );
  assert!(
    sqlx::query("update scheduled_run_result_artifacts set result_json = '{\"changed\":true}' where artifact_id = 'artifact-0'")
      .execute(&pool)
      .await
      .is_err()
  );
  assert!(
    sqlx::query("delete from scheduled_run_result_artifacts where artifact_id = 'artifact-0'")
      .execute(&pool)
      .await
      .is_err()
  );
  assert!(
    sqlx::query("insert or replace into scheduled_run_result_artifacts (artifact_id, run_id, job_id, accepted_attempt, accepted_fence, schema_version, result_json, hash_algorithm, result_hash, previous_success_context, completed_at) values ('replacement', ?1, ?2, ?3, ?4, 1, '{}', 'sha256-v1', 'replacement', 'summary', 121)")
      .bind(claims[0].binding.run_id())
      .bind(claims[0].binding.job_id())
      .bind(claims[0].binding.attempt())
      .bind(claims[0].binding.fence())
      .execute(&pool)
      .await
      .is_err()
  );
  assert!(
    sqlx::query("insert into scheduled_runs (run_id, job_id, schedule_id, job_generation, schedule_generation, scheduled_for, coalesced_through, definition_version, definition_json, capability_schema_version, capability_digest, capability_json, targets_json, state, overlap_slot, result_artifact_id, created_at, updated_at) select 'artifact-cross-insert', job_id, schedule_id, job_generation, schedule_generation, scheduled_for + 1, coalesced_through + 1, definition_version, definition_json, capability_schema_version, capability_digest, capability_json, targets_json, 'failed', null, 'artifact-1', created_at, updated_at from scheduled_runs where run_id = ?1")
      .bind(claims[0].binding.run_id())
      .execute(&pool)
      .await
      .is_err()
  );
  assert!(
    sqlx::query("insert into scheduled_runs (run_id, job_id, schedule_id, job_generation, schedule_generation, scheduled_for, coalesced_through, definition_version, definition_json, capability_schema_version, capability_digest, capability_json, targets_json, state, overlap_slot, created_at, updated_at) select 'legacy-success-insert', job_id, schedule_id, job_generation, schedule_generation, scheduled_for + 2, coalesced_through + 2, definition_version, definition_json, capability_schema_version, capability_digest, capability_json, targets_json, 'succeeded', null, created_at, updated_at from scheduled_runs where run_id = ?1")
      .bind(claims[0].binding.run_id())
      .execute(&pool)
      .await
      .is_err()
  );
  sqlx::query("update scheduled_runs set result_artifact_id = 'artifact-0' where run_id = ?1")
    .bind(claims[0].binding.run_id())
    .execute(&pool)
    .await
    .expect("bind own artifact");
  assert!(
    sqlx::query("update scheduled_runs set result_artifact_id = 'artifact-1' where run_id = ?1")
      .bind(claims[0].binding.run_id())
      .execute(&pool)
      .await
      .is_err()
  );
  assert!(
    sqlx::query("update scheduled_runs set result_artifact_id = null where run_id = ?1")
      .bind(claims[0].binding.run_id())
      .execute(&pool)
      .await
      .is_err()
  );
  assert!(
    sqlx::query("update scheduled_runs set state = 'succeeded', overlap_slot = null, lease_owner = null, lease_expires_at = null, result_context = 'summary', result_hash_algorithm = 'sha256-v1', result_hash = 'hash-1' where run_id = ?1")
      .bind(claims[1].binding.run_id())
      .execute(&pool)
      .await
      .is_err()
  );
  for statement in [
    "update scheduled_runs set state = 'succeeded', overlap_slot = null, lease_owner = null, lease_expires_at = null, result_context = 'summary', result_hash_algorithm = 'sha256-v1', result_hash = 'wrong' where run_id = ?1",
    "update scheduled_runs set state = 'succeeded', overlap_slot = null, lease_owner = null, lease_expires_at = null, result_context = 'wrong', result_hash_algorithm = 'sha256-v1', result_hash = 'hash-0' where run_id = ?1",
  ] {
    assert!(
      sqlx::query(statement)
        .bind(claims[0].binding.run_id())
        .execute(&pool)
        .await
        .is_err()
    );
  }
  sqlx::query("update scheduled_run_attempts set state = 'succeeded', completed_at = 120 where run_id = ?1 and attempt = ?2")
    .bind(claims[0].binding.run_id())
    .bind(claims[0].binding.attempt())
    .execute(&pool)
    .await
    .expect("complete accepted attempt");
  sqlx::query("update scheduled_runs set state = 'succeeded', overlap_slot = null, lease_owner = null, lease_expires_at = null, result_context = 'summary', result_hash_algorithm = 'sha256-v1', result_hash = 'hash-0' where run_id = ?1")
    .bind(claims[0].binding.run_id())
    .execute(&pool)
    .await
    .expect("accept matching artifact");
  for statement in [
    "update scheduled_runs set result_context = 'changed' where run_id = ?1",
    "update scheduled_runs set result_hash = 'changed' where run_id = ?1",
    "update scheduled_runs set result_artifact_id = null where run_id = ?1",
  ] {
    assert!(
      sqlx::query(statement)
        .bind(claims[0].binding.run_id())
        .execute(&pool)
        .await
        .is_err()
    );
  }
}

#[tokio::test]
async fn test_two_independent_stores_reject_different_digest_race() {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state");
  let first = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize first store");
  let second = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize second store");
  let mutation = ScheduledJobMutation::Create(Box::new(create_request(
    "different-digest-race",
    ScheduleSpec::once(110),
    100,
  )));
  let barrier = Arc::new(Barrier::new(3));
  let first_task = tokio::spawn(apply_mutation_after_barrier(
    first,
    mutation.clone(),
    mutation_idempotency("different-digest-race", "digest-a"),
    Arc::clone(&barrier),
  ));
  let second_task = tokio::spawn(apply_mutation_after_barrier(
    second,
    mutation,
    mutation_idempotency("different-digest-race", "digest-b"),
    Arc::clone(&barrier),
  ));
  barrier.wait().await;
  let outcomes = [
    first_task
      .await
      .expect("first task")
      .expect("first outcome"),
    second_task
      .await
      .expect("second task")
      .expect("second outcome"),
  ];
  assert!(
    outcomes
      .iter()
      .any(|outcome| { matches!(outcome, TransactionalMutationOutcome::Applied(_)) })
  );
  assert!(outcomes.contains(&TransactionalMutationOutcome::Conflict));
}

#[tokio::test]
async fn test_two_independent_stores_converge_on_one_transactional_mutation_response() {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state");
  let first = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize first store");
  let second = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize second store");
  let mutation = ScheduledJobMutation::Create(Box::new(create_request(
    "transaction-race",
    ScheduleSpec::once(110),
    100,
  )));
  let idempotency = mutation_idempotency("transaction-race-request", "transaction-race-digest");
  let barrier = Arc::new(Barrier::new(3));
  let first_task = tokio::spawn(apply_mutation_after_barrier(
    first,
    mutation.clone(),
    idempotency.clone(),
    Arc::clone(&barrier),
  ));
  let second_task = tokio::spawn(apply_mutation_after_barrier(
    second,
    mutation,
    idempotency.clone(),
    Arc::clone(&barrier),
  ));
  barrier.wait().await;
  let outcomes = [
    first_task
      .await
      .expect("first task")
      .expect("first outcome"),
    second_task
      .await
      .expect("second task")
      .expect("second outcome"),
  ];
  assert!(outcomes.contains(&TransactionalMutationOutcome::Applied(
    idempotency.response_json.clone()
  )));
  assert!(outcomes.contains(&TransactionalMutationOutcome::Replay(
    idempotency.response_json
  )));
}

async fn apply_mutation_after_barrier(
  store: StateStore,
  mutation: ScheduledJobMutation,
  idempotency: ScheduleMutationIdempotency,
  barrier: Arc<Barrier>,
) -> Result<TransactionalMutationOutcome, StateError> {
  barrier.wait().await;
  for _ in 0..3 {
    match store
      .apply_idempotent_schedule_mutation(&mutation, &idempotency)
      .await
    {
      Err(error) if error.is_transient_storage_contention() => {}
      result => return result,
    }
  }
  store
    .apply_idempotent_schedule_mutation(&mutation, &idempotency)
    .await
}

#[tokio::test]
async fn test_due_query_uses_due_index_and_overlap_index_is_enforced() {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state");
  let store = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize store");
  store
    .create_scheduled_job(&create_request(
      "indexes",
      ScheduleSpec::fixed_interval(110, 30).expect("interval"),
      100,
    ))
    .await
    .expect("create job");
  let MaterializationOutcome::Created(run) = store
    .materialize_due_schedule("indexes", 0, 110)
    .await
    .expect("materialize")
  else {
    panic!("expected run");
  };

  let pool = SqlitePool::connect(&database_url(&state_dir))
    .await
    .expect("connect database");
  let plan = sqlx::query(
    "explain query plan select s.job_id from schedules s join scheduled_jobs j on j.job_id = s.job_id where j.status = 'active' and s.next_run_at <= 200 and not exists (select 1 from scheduled_runs r where r.job_id = s.job_id and r.overlap_slot = 1) order by s.next_run_at, s.job_id limit 10",
  )
  .fetch_all(&pool)
  .await
  .expect("query plan");
  assert!(plan.iter().any(|row| {
    row
      .try_get::<String, _>("detail")
      .is_ok_and(|detail| detail.contains("idx_schedules_due"))
  }));
  assert!(plan.iter().any(|row| {
    row
      .try_get::<String, _>("detail")
      .is_ok_and(|detail| detail.contains("idx_scheduled_runs_active_overlap"))
  }));

  let duplicate = sqlx::query(
    "insert into scheduled_runs (run_id, job_id, schedule_id, job_generation, schedule_generation, scheduled_for, coalesced_through, definition_version, definition_json, capability_schema_version, capability_digest, capability_json, targets_json, state, overlap_slot, created_at, updated_at) select 'duplicate-active', job_id, schedule_id, job_generation, schedule_generation, scheduled_for + 30, coalesced_through + 30, definition_version, definition_json, capability_schema_version, capability_digest, capability_json, targets_json, 'pending', 1, created_at, updated_at from scheduled_runs where run_id = ?1",
  )
  .bind(run.run_id)
  .execute(&pool)
  .await;
  assert!(
    duplicate.is_err(),
    "overlap partial unique index must reject a second blocker"
  );

  for (query, expected_index) in [
    (
      "explain query plan select run_id from scheduled_runs where job_id = 'indexes' order by scheduled_for desc limit 20",
      "idx_scheduled_runs_history",
    ),
    (
      "explain query plan select run_id from scheduled_runs where state = 'leased' and lease_expires_at <= 200 order by lease_expires_at, run_id limit 20",
      "idx_scheduled_runs_recovery",
    ),
    (
      "explain query plan select run_id from scheduled_runs where state = 'pending' and next_attempt_at <= 200 order by next_attempt_at, run_id limit 20",
      "idx_scheduled_runs_retry",
    ),
    (
      "explain query plan select delivery_id from scheduled_run_deliveries where state = 'leased' and lease_expires_at <= 200 order by lease_expires_at, delivery_id limit 20",
      "idx_scheduled_deliveries_recovery",
    ),
    (
      "explain query plan select delivery_id from scheduled_run_deliveries where state = 'pending' and next_attempt_at <= 200 order by next_attempt_at, delivery_id limit 20",
      "idx_scheduled_deliveries_retry",
    ),
  ] {
    let plan = sqlx::query(query)
      .fetch_all(&pool)
      .await
      .expect("index query plan");
    assert!(
      plan.iter().any(|row| {
        row
          .try_get::<String, _>("detail")
          .is_ok_and(|detail| detail.contains(expected_index))
      }),
      "expected query plan to use {expected_index}"
    );
  }
}

#[tokio::test]
async fn test_owner_list_isolated_cursor_bounded_and_uses_owner_status_index() {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state");
  let store = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize store");
  let owner_a = PrincipalKey::new("service", "github", "org-a", "bot").expect("owner a");
  let owner_b = PrincipalKey::new("service", "github", "org-b", "bot").expect("owner b");
  for (job, owner) in [
    ("owner-a-1", owner_a.clone()),
    ("owner-a-2", owner_a.clone()),
    ("owner-a-paused", owner_a.clone()),
    ("owner-b-1", owner_b.clone()),
  ] {
    let mut request = create_request(job, ScheduleSpec::once(200), 100);
    request.owner = owner;
    store
      .create_scheduled_job(&request)
      .await
      .expect("create job");
  }
  store
    .pause_scheduled_job("owner-a-paused", 0, 101)
    .await
    .expect("pause job");

  let first = store
    .list_scheduled_jobs_by_owner(&owner_a, ScheduledJobStatus::Active, None, 1)
    .await
    .expect("first page");
  assert_eq!(first.job_ids, ["owner-a-1"]);
  let second = store
    .list_scheduled_jobs_by_owner(
      &owner_a,
      ScheduledJobStatus::Active,
      first.next_cursor.as_deref(),
      1,
    )
    .await
    .expect("second page");
  assert_eq!(second.job_ids, ["owner-a-2"]);
  assert!(second.next_cursor.is_none());
  assert!(
    store
      .list_scheduled_jobs_by_owner(&owner_a, ScheduledJobStatus::Active, None, 0)
      .await
      .is_err()
  );
  assert!(
    store
      .list_scheduled_jobs_by_owner(&owner_a, ScheduledJobStatus::Active, None, 101)
      .await
      .is_err()
  );

  assert!(
    store
      .get_scheduled_job_by_owner(&owner_a, "owner-a-1")
      .await
      .expect("exact owner query")
      .is_some()
  );
  for other in [
    owner_b,
    PrincipalKey::new("user", "github", "org-a", "bot").expect("other kind"),
    PrincipalKey::new("service", "slack", "org-a", "bot").expect("other provider"),
    PrincipalKey::new("service", "github", "org-a", "other").expect("other subject"),
  ] {
    assert!(
      store
        .get_scheduled_job_by_owner(&other, "owner-a-1")
        .await
        .expect("owner scoped query")
        .is_none()
    );
  }

  let pool = SqlitePool::connect(&database_url(&state_dir))
    .await
    .expect("connect database");
  let plan = sqlx::query(
    "explain query plan select job_id from scheduled_jobs indexed by idx_scheduled_jobs_owner_status where owner_kind = 'service' and owner_provider = 'github' and owner_tenant = 'org-a' and owner_subject = 'bot' and status = 'active' and job_id > '' order by job_id limit 2",
  )
  .fetch_all(&pool)
  .await
  .expect("owner list plan");
  assert!(plan.iter().any(|row| {
    row
      .try_get::<String, _>("detail")
      .is_ok_and(|detail| detail.contains("idx_scheduled_jobs_owner_status"))
  }));
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn test_execution_and_accepted_delivery_baselines_are_independent_cas_records() {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state");
  let store = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize store");
  store
    .create_scheduled_job(&create_request("baselines", ScheduleSpec::once(110), 100))
    .await
    .expect("create job");
  let MaterializationOutcome::Created(run) = store
    .materialize_due_schedule("baselines", 0, 110)
    .await
    .expect("materialize")
  else {
    panic!("expected run");
  };
  let execution = UpdateExecutionBaseline {
    job_id: "baselines".to_owned(),
    expected_version: 0,
    hash_algorithm: "sha256-utf8-exact-v1".to_owned(),
    result_hash: "result-a".to_owned(),
    previous_success_context: "bounded context".to_owned(),
    source_run_id: run.run_id.clone(),
    completed_at: 111,
  };
  assert!(
    store
      .compare_and_swap_execution_baseline(&execution)
      .await
      .expect("execution CAS")
  );
  assert!(
    !store
      .compare_and_swap_execution_baseline(&execution)
      .await
      .expect("stale execution CAS")
  );

  let pool = SqlitePool::connect(&database_url(&state_dir))
    .await
    .expect("connect database");
  sqlx::query(
    "insert into scheduled_run_deliveries (delivery_id, run_id, job_id, target_identity_digest, target_json, state, delivery_policy_version, render_version, hash_algorithm, payload_digest, expected_baseline_version, created_at, updated_at) values ('delivery-a', ?1, 'baselines', 'none-v1', '{}', 'delivered', 1, 1, 'sha256-utf8-exact-v1', 'payload-a', 0, 112, 112)",
  )
  .bind(&run.run_id)
  .execute(&pool)
  .await
  .expect("insert delivery fixture");
  let accepted = UpdateAcceptedDeliveryBaseline {
    job_id: "baselines".to_owned(),
    target_identity_digest: "none-v1".to_owned(),
    delivery_policy_version: 1,
    render_version: 1,
    hash_algorithm: "sha256-utf8-exact-v1".to_owned(),
    accepted_payload_digest: "payload-a".to_owned(),
    source_delivery_id: "delivery-a".to_owned(),
    source_run_id: run.run_id,
    source_result_hash: "result-a".to_owned(),
    accepted_at: 112,
    expected_version: 0,
  };
  let mut nonzero_first_create = accepted.clone();
  nonzero_first_create.expected_version = 1;
  assert!(
    !store
      .compare_and_swap_accepted_delivery_baseline(&nonzero_first_create)
      .await
      .expect("nonzero first-create CAS")
  );
  assert!(
    store
      .compare_and_swap_accepted_delivery_baseline(&accepted)
      .await
      .expect("accepted CAS")
  );
  assert!(
    !store
      .compare_and_swap_accepted_delivery_baseline(&accepted)
      .await
      .expect("stale accepted CAS")
  );
  let versions: (i64, i64) = sqlx::query_as(
    "select (select baseline_version from scheduled_execution_baselines where job_id = 'baselines'), (select baseline_version from scheduled_delivery_baselines where job_id = 'baselines')",
  )
  .fetch_one(&pool)
  .await
  .expect("read baseline versions");
  assert_eq!(versions, (1, 1));
  let baseline = store
    .get_accepted_delivery_baseline("baselines", "none-v1", 1, 1, "sha256-utf8-exact-v1")
    .await
    .expect("read accepted baseline")
    .expect("accepted baseline");
  assert_eq!(baseline.accepted_payload_digest, "payload-a");
  assert!(
    store
      .get_accepted_delivery_baseline(
        "baselines",
        "different-target",
        1,
        1,
        "sha256-utf8-exact-v1",
      )
      .await
      .expect("read different baseline")
      .is_none()
  );
}

#[tokio::test]
async fn test_two_independent_stores_allow_one_accepted_baseline_first_create() {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state");
  let first = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize first store");
  let second = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize second store");
  first
    .create_scheduled_job(&create_request(
      "accepted-race",
      ScheduleSpec::once(110),
      100,
    ))
    .await
    .expect("create job");
  let MaterializationOutcome::Created(run) = first
    .materialize_due_schedule("accepted-race", 0, 110)
    .await
    .expect("materialize")
  else {
    panic!("expected run");
  };
  let pool = SqlitePool::connect(&database_url(&state_dir))
    .await
    .expect("connect database");
  sqlx::query(
    "insert into scheduled_run_deliveries (delivery_id, run_id, job_id, target_identity_digest, target_json, state, delivery_policy_version, render_version, hash_algorithm, payload_digest, expected_baseline_version, created_at, updated_at) values ('accepted-race-delivery', ?1, 'accepted-race', 'identity', '{}', 'delivered', 1, 1, 'sha256-v1', 'payload', 0, 111, 111)",
  )
  .bind(&run.run_id)
  .execute(&pool)
  .await
  .expect("insert delivery");
  let update = UpdateAcceptedDeliveryBaseline {
    job_id: "accepted-race".to_owned(),
    target_identity_digest: "identity".to_owned(),
    delivery_policy_version: 1,
    render_version: 1,
    hash_algorithm: "sha256-v1".to_owned(),
    accepted_payload_digest: "payload".to_owned(),
    source_delivery_id: "accepted-race-delivery".to_owned(),
    source_run_id: run.run_id,
    source_result_hash: "result".to_owned(),
    accepted_at: 111,
    expected_version: 0,
  };
  let barrier = Arc::new(Barrier::new(3));
  let first_task = tokio::spawn(accepted_cas_after_barrier(
    first,
    update.clone(),
    Arc::clone(&barrier),
  ));
  let second_task = tokio::spawn(accepted_cas_after_barrier(
    second,
    update,
    Arc::clone(&barrier),
  ));
  barrier.wait().await;
  let outcomes = [
    first_task.await.expect("first task").expect("first CAS"),
    second_task.await.expect("second task").expect("second CAS"),
  ];
  assert_eq!(outcomes.iter().filter(|outcome| **outcome).count(), 1);
  let version: i64 = sqlx::query_scalar(
    "select baseline_version from scheduled_delivery_baselines where job_id = 'accepted-race'",
  )
  .fetch_one(&pool)
  .await
  .expect("read baseline version");
  assert_eq!(version, 1);
}

async fn accepted_cas_after_barrier(
  store: StateStore,
  update: UpdateAcceptedDeliveryBaseline,
  barrier: Arc<Barrier>,
) -> Result<bool, StateError> {
  barrier.wait().await;
  for _ in 0..3 {
    match store
      .compare_and_swap_accepted_delivery_baseline(&update)
      .await
    {
      Err(error) if error.is_transient_storage_contention() => {}
      result => return result,
    }
  }
  store
    .compare_and_swap_accepted_delivery_baseline(&update)
    .await
}

#[tokio::test]
async fn test_schema_rejects_cross_job_ownership_and_invalid_run_delivery_states() {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state");
  let store = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize store");
  for job in ["ownership-a", "ownership-b"] {
    store
      .create_scheduled_job(&create_request(job, ScheduleSpec::once(110), 100))
      .await
      .expect("create job");
  }
  let MaterializationOutcome::Created(run) = store
    .materialize_due_schedule("ownership-a", 0, 110)
    .await
    .expect("materialize")
  else {
    panic!("expected run");
  };
  let pool = SqlitePool::connect(&database_url(&state_dir))
    .await
    .expect("connect database");

  for statement in [
    "update scheduled_runs set lease_owner = 'worker' where run_id = ?1",
    "update scheduled_runs set lease_owner = 'worker', lease_expires_at = 120 where run_id = ?1",
    "update scheduled_runs set state = 'leased' where run_id = ?1",
    "update scheduled_runs set state = 'executing' where run_id = ?1",
    "update scheduled_runs set result_hash_algorithm = 'sha256-v1', result_hash = 'result' where run_id = ?1",
    "update scheduled_runs set next_attempt_at = 120, state = 'executing' where run_id = ?1",
  ] {
    assert!(
      sqlx::query(statement)
        .bind(&run.run_id)
        .execute(&pool)
        .await
        .is_err(),
      "state invariant must reject {statement}"
    );
  }
  assert!(
    sqlx::query(
      "insert into scheduled_runs (run_id, job_id, schedule_id, job_generation, schedule_generation, scheduled_for, coalesced_through, definition_version, definition_json, capability_schema_version, capability_digest, capability_json, targets_json, state, overlap_slot, created_at, updated_at) select 'cross-job-run', 'ownership-b', schedule_id, job_generation, schedule_generation, scheduled_for + 1, coalesced_through + 1, definition_version, definition_json, capability_schema_version, capability_digest, capability_json, targets_json, 'pending', 1, created_at, updated_at from scheduled_runs where run_id = ?1",
    )
    .bind(&run.run_id)
    .execute(&pool)
    .await
    .is_err()
  );
  sqlx::query(
    "insert into scheduled_run_deliveries (delivery_id, run_id, job_id, target_identity_digest, target_json, state, delivery_policy_version, render_version, hash_algorithm, payload_digest, expected_baseline_version, created_at, updated_at) values ('lease-delivery', ?1, 'ownership-a', 'identity', '{}', 'pending', 1, 1, 'sha256-v1', 'payload', 0, 111, 111)",
  )
  .bind(&run.run_id)
  .execute(&pool)
  .await
  .expect("insert valid pending delivery");
  for statement in [
    "update scheduled_run_deliveries set state = 'leased' where delivery_id = 'lease-delivery'",
    "update scheduled_run_deliveries set state = 'sending' where delivery_id = 'lease-delivery'",
    "update scheduled_run_deliveries set lease_owner = 'worker', lease_expires_at = 120 where delivery_id = 'lease-delivery'",
  ] {
    assert!(
      sqlx::query(statement).execute(&pool).await.is_err(),
      "delivery lease invariant must reject {statement}"
    );
  }
  assert!(
    sqlx::query(
      "insert into scheduled_run_deliveries (delivery_id, run_id, job_id, target_identity_digest, target_json, state, delivery_policy_version, render_version, hash_algorithm, payload_digest, expected_baseline_version, created_at, updated_at) values ('cross-job-delivery', ?1, 'ownership-b', 'identity', '{}', 'pending', 1, 1, 'sha256-v1', 'payload', 0, 111, 111)",
    )
    .bind(&run.run_id)
    .execute(&pool)
    .await
    .is_err()
  );
  assert!(
    sqlx::query(
      "update scheduled_execution_baselines set baseline_version = 1, hash_algorithm = 'sha256-v1', result_hash = 'result', source_run_id = ?1, completed_at = 111 where job_id = 'ownership-b'",
    )
    .bind(&run.run_id)
    .execute(&pool)
    .await
    .is_err()
  );
}

#[tokio::test]
async fn test_pause_racing_materialization_leaves_no_old_generation_pre_execution_run() {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state");
  let materializer = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize materializer");
  let lifecycle = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize lifecycle store");
  materializer
    .create_scheduled_job(&create_request(
      "lifecycle-race",
      ScheduleSpec::fixed_interval(110, 30).expect("interval"),
      100,
    ))
    .await
    .expect("create job");
  let barrier = Arc::new(Barrier::new(3));
  let materialize_barrier = Arc::clone(&barrier);
  let materialize_task = tokio::spawn(async move {
    materialize_barrier.wait().await;
    materializer
      .materialize_due_schedule("lifecycle-race", 0, 110)
      .await
  });
  let pause_barrier = Arc::clone(&barrier);
  let pause_task = tokio::spawn(async move {
    pause_barrier.wait().await;
    pause_with_contention_retry(&lifecycle).await
  });
  barrier.wait().await;
  let materialize_result = materialize_task.await.expect("materialize task");
  if let Err(error) = materialize_result {
    assert!(
      error.is_transient_storage_contention(),
      "unexpected error: {error}"
    );
  }
  assert_eq!(pause_task.await.expect("pause task").expect("pause"), 1);

  let pool = SqlitePool::connect(&database_url(&state_dir))
    .await
    .expect("connect database");
  let old_pre_execution: i64 = sqlx::query_scalar(
    "select count(*) from scheduled_runs where job_id = 'lifecycle-race' and job_generation = 0 and state in ('pending', 'leased')",
  )
  .fetch_one(&pool)
  .await
  .expect("count old work");
  assert_eq!(old_pre_execution, 0);
}

async fn pause_with_contention_retry(store: &StateStore) -> Result<i64, StateError> {
  for _ in 0..3 {
    match store.pause_scheduled_job("lifecycle-race", 0, 111).await {
      Err(error) if error.is_transient_storage_contention() => {}
      result => return result,
    }
  }
  store.pause_scheduled_job("lifecycle-race", 0, 111).await
}

#[tokio::test]
async fn test_claim_racing_pause_or_delete_leaves_no_active_attempt() {
  run_claim_inactive_race(false).await;
  run_claim_inactive_race(true).await;
}

async fn run_claim_inactive_race(delete: bool) {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state");
  let claimant = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize claimant");
  let lifecycle = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize lifecycle store");
  let job_id = if delete {
    "claim-delete"
  } else {
    "claim-pause"
  };
  let schedule = ScheduleSpec::fixed_interval(110, 30).expect("interval");
  claimant
    .create_scheduled_job(&create_request(job_id, schedule, 100))
    .await
    .expect("create job");
  claimant
    .materialize_due_schedule(job_id, 0, 110)
    .await
    .expect("materialize");
  let barrier = Arc::new(Barrier::new(3));
  let claim_barrier = Arc::clone(&barrier);
  let claim_task = tokio::spawn(async move {
    claim_barrier.wait().await;
    claimant.claim_next_scheduled_run("worker", 111, 141).await
  });
  let lifecycle_barrier = Arc::clone(&barrier);
  let owned_job_id = job_id.to_owned();
  let lifecycle_task = tokio::spawn(async move {
    lifecycle_barrier.wait().await;
    inactive_with_contention_retry(&lifecycle, &owned_job_id, delete).await
  });
  barrier.wait().await;
  if let Err(error) = claim_task.await.expect("claim task") {
    assert!(error.is_transient_storage_contention());
  }
  lifecycle_task
    .await
    .expect("lifecycle task")
    .expect("inactive mutation");

  let pool = SqlitePool::connect(&database_url(&state_dir))
    .await
    .expect("connect database");
  let active: (i64, i64) = sqlx::query_as(
    "select (select count(*) from scheduled_runs where job_id = ?1 and state = 'leased'), (select count(*) from scheduled_run_attempts where job_id = ?1 and state = 'leased')",
  )
  .bind(job_id)
  .fetch_one(&pool)
  .await
  .expect("read active state");
  assert_eq!(active, (0, 0));
  let orphaned: i64 = sqlx::query_scalar(
    "select count(*) from scheduled_run_attempts a join scheduled_runs r on r.run_id = a.run_id where r.job_id = ?1 and r.state = 'cancelled' and a.state != 'cancelled'",
  )
  .bind(job_id)
  .fetch_one(&pool)
  .await
  .expect("read cancelled attempt state");
  assert_eq!(orphaned, 0);
}

async fn inactive_with_contention_retry(
  store: &StateStore,
  job_id: &str,
  delete: bool,
) -> Result<i64, StateError> {
  for _ in 0..3 {
    let result = if delete {
      store.delete_scheduled_job(job_id, 0, 112).await
    } else {
      store.pause_scheduled_job(job_id, 0, 112).await
    };
    match result {
      Err(error) if error.is_transient_storage_contention() => {}
      result => return result,
    }
  }
  if delete {
    store.delete_scheduled_job(job_id, 0, 112).await
  } else {
    store.pause_scheduled_job(job_id, 0, 112).await
  }
}

#[tokio::test]
async fn test_update_delete_race_has_one_generation_winner() {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state");
  let updater = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize updater");
  let deleter = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize deleter");
  updater
    .create_scheduled_job(&create_request(
      "update-delete-race",
      ScheduleSpec::once(200),
      100,
    ))
    .await
    .expect("create job");
  let update = UpdateScheduledJob {
    job_id: "update-delete-race".to_owned(),
    expected_generation: 0,
    definition: ScheduledJobDefinition::new(2, r#"{"prompt":"updated"}"#).expect("definition"),
    capability: CapabilityProfileSnapshot::new(2, "profile-v2", r#"{"tools":[]}"#)
      .expect("capability"),
    targets: vec![target("update-delete-race-updated")],
    schedule: ScheduleSpec::once(300),
    now: 110,
  };
  let barrier = Arc::new(Barrier::new(3));
  let update_barrier = Arc::clone(&barrier);
  let update_task = tokio::spawn(async move {
    update_barrier.wait().await;
    for _ in 0..3 {
      match updater.update_scheduled_job(&update).await {
        Err(error) if error.is_transient_storage_contention() => {}
        result => return result,
      }
    }
    updater.update_scheduled_job(&update).await
  });
  let delete_barrier = Arc::clone(&barrier);
  let delete_task = tokio::spawn(async move {
    delete_barrier.wait().await;
    for _ in 0..3 {
      match deleter
        .delete_scheduled_job("update-delete-race", 0, 110)
        .await
      {
        Err(error) if error.is_transient_storage_contention() => {}
        result => return result,
      }
    }
    deleter
      .delete_scheduled_job("update-delete-race", 0, 110)
      .await
  });
  barrier.wait().await;
  let outcomes = [
    update_task.await.expect("update task"),
    delete_task.await.expect("delete task"),
  ];
  assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
  let job = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize reader")
    .get_scheduled_job("update-delete-race")
    .await
    .expect("read job")
    .expect("job");
  assert_eq!(job.generation, 1);
}
