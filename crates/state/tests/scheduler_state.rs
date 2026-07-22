use std::fmt::Write as _;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use codeoff_state::{
  AttestedExecutionProfileSnapshot, CapabilityProfileSnapshot, ClaimedScheduledRun,
  CreateScheduledJob, DeliveryTargetSnapshot, ExpiredRunReclaimOutcome, LateEvidenceAppendOutcome,
  MaterializationOutcome, OccurrenceError, PreflightFailureDisposition, PrincipalKey,
  ScheduleMutationIdempotency, ScheduleSpec, ScheduledDeliveryState, ScheduledExecutionDisposition,
  ScheduledExecutionTerminal, ScheduledJobDefinition, ScheduledJobMutation, ScheduledJobStatus,
  ScheduledPrepareAuthority, ScheduledRunExecutionOutcome, ScheduledRunLateEvidenceKind,
  ScheduledRunResult, ScheduledRunSuccessOutcome, StateError, StateStore, StateValueError,
  TransactionalMutationOutcome, TransportConvergence, UpdateAcceptedDeliveryBaseline,
  UpdateExecutionBaseline, UpdateScheduledJob,
};
use sha2::{Digest, Sha256};
use sqlx::Row;
use sqlx::SqlitePool;
use sqlx::migrate::Migrator;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use tempfile::tempdir;
use tokio::sync::Barrier;

type LegacyDeliveryMigrationRow = (
  String,
  i64,
  Option<i64>,
  Option<String>,
  Option<i64>,
  i64,
  Option<String>,
  Option<String>,
  String,
  Option<String>,
  Option<Vec<u8>>,
);
type DeliveryIntentAuthorityRow = (
  String,
  String,
  String,
  i64,
  i64,
  i64,
  Option<i64>,
  Option<String>,
  Option<Vec<u8>>,
  String,
);

const NONE_TARGET_IDENTITY: &str =
  "0000000000000000000000000000000000000000000000000000000000000001";
const SLACK_TARGET_IDENTITY: &str =
  "0000000000000000000000000000000000000000000000000000000000000002";

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
    NONE_TARGET_IDENTITY,
  )
  .expect("target")
}

fn second_target(job: &str) -> DeliveryTargetSnapshot {
  DeliveryTargetSnapshot::new(
    format!("target-{job}-second"),
    "slack",
    "slack-primary",
    "workspace",
    "channel",
    r#"{"channel_id":"C1"}"#,
    1,
    "resolver-v1",
    SLACK_TARGET_IDENTITY,
  )
  .expect("second target")
}

fn test_sha256_hex(value: &str) -> String {
  let mut digest = Sha256::new();
  digest.update(value.as_bytes());
  let mut encoded = String::with_capacity(64);
  for byte in digest.finalize() {
    write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
  }
  encoded
}

fn test_intent_key(run_id: &str, target_identity_digest: &str) -> String {
  let mut key = String::with_capacity(70 + (run_id.len() * 2));
  key.push_str("v1:");
  for byte in run_id.as_bytes() {
    write!(&mut key, "{byte:02x}").expect("writing to String cannot fail");
  }
  write!(&mut key, ":{target_identity_digest}:1").expect("writing to String cannot fail");
  key
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
fn test_scheduled_run_result_is_typed_and_bounded() {
  assert_eq!(
    ScheduledDeliveryState::from_str("intent").expect("intent state"),
    ScheduledDeliveryState::Intent
  );
  assert!(ScheduledRunResult::new("", "context").is_err());
  assert!(ScheduledRunResult::new("summary", "x".repeat(65_537)).is_err());
  assert!(ScheduledRunResult::new("x".repeat(65_537), "context").is_err());
  assert!(ScheduledRunResult::new("summary", "").is_ok());
}

#[test]
fn test_delivery_target_identity_requires_lowercase_sha256_at_construction() {
  for invalid in [
    "identity",
    "A000000000000000000000000000000000000000000000000000000000000000",
    "g000000000000000000000000000000000000000000000000000000000000000",
  ] {
    assert!(matches!(
      DeliveryTargetSnapshot::new(
        "target", "none", "none", "tenant", "none", "{}", 1, "resolver", invalid,
      ),
      Err(StateValueError::InvalidSha256 {
        field: "target identity digest"
      })
    ));
  }
  assert_eq!(target("valid").identity_digest(), NONE_TARGET_IDENTITY);
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
        test_sha256_hex(&format!("identity-{index}")),
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
        test_sha256_hex(&format!("large-identity-{index}")),
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
      Some(
        "20260721030000_scheduler_execution_hardening.sql"
          | "20260721040000_scheduler_delivery_intents.sql"
      )
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
    ("succeeded-empty", "succeeded"),
    ("succeeded-collision", "succeeded"),
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
    let has_legacy_result = matches!(
      label,
      "succeeded-valid" | "succeeded-matching" | "succeeded-collision"
    );
    let result_context = if label == "succeeded-empty" {
      Some("")
    } else {
      has_legacy_result.then_some("legacy context")
    };
    let result_hash_algorithm = if label == "succeeded-empty" {
      Some("")
    } else {
      has_legacy_result.then_some("legacy-digest-v1")
    };
    let result_hash = if label == "succeeded-empty" {
      Some("")
    } else {
      has_legacy_result.then_some(label)
    };
    let has_current_attempt =
      matches!(state, "leased" | "executing") || label == "succeeded-matching";
    let attempt = i64::from(has_current_attempt);
    let fence = attempt * 2;
    sqlx::query("insert into scheduled_runs (run_id, job_id, schedule_id, job_generation, schedule_generation, scheduled_for, coalesced_through, definition_version, definition_json, capability_schema_version, capability_digest, capability_json, targets_json, state, attempt, fence, lease_owner, lease_expires_at, overlap_slot, result_context, result_hash_algorithm, result_hash, created_at, updated_at) values (?1, ?2, ?3, 0, 0, ?4, ?4, 1, '{}', 1, 'profile', '{}', '[{\"identity_digest\":\"0000000000000000000000000000000000000000000000000000000000000001\"}]', ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, 100, 100)")
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
  sqlx::query("insert into scheduled_run_result_artifacts (artifact_id, run_id, job_id, accepted_attempt, accepted_fence, schema_version, result_json, hash_algorithm, result_hash, previous_success_context, completed_at) values ('legacy-result:upgrade-run-succeeded-collision', 'upgrade-run-executing', 'upgrade-executing', 1, 2, 1, '{}', 'sha256-v1', 'collision-owner', 'collision-owner', 100)")
    .execute(&pool)
    .await
    .expect("seed legacy artifact id collision");
  sqlx::query("update scheduled_execution_baselines set baseline_version = 3, hash_algorithm = 'legacy-digest-v1', result_hash = 'succeeded-invalid', previous_success_context = 'invalid context', source_run_id = 'upgrade-run-succeeded-invalid', completed_at = 100 where job_id = 'upgrade-succeeded-invalid'")
    .execute(&pool)
    .await
    .expect("seed invalid legacy baseline");
  sqlx::query("update scheduled_execution_baselines set baseline_version = 4, hash_algorithm = 'legacy-digest-v1', result_hash = 'succeeded-valid', previous_success_context = 'legacy context', source_run_id = 'upgrade-run-succeeded-valid', completed_at = 100 where job_id = 'upgrade-succeeded-valid'")
    .execute(&pool)
    .await
    .expect("seed valid legacy baseline");
  sqlx::query("insert into scheduled_runs (run_id, job_id, schedule_id, job_generation, schedule_generation, scheduled_for, coalesced_through, definition_version, definition_json, capability_schema_version, capability_digest, capability_json, targets_json, execution_baseline_json, state, overlap_slot, created_at, updated_at) values ('upgrade-run-after-invalid', 'upgrade-succeeded-invalid', 'schedule-succeeded-invalid', 0, 0, 150, 150, 1, '{}', 1, 'profile', '{}', '[{\"identity_digest\":\"0000000000000000000000000000000000000000000000000000000000000001\"}]', '{\"baseline_version\":3,\"hash_algorithm\":\"legacy-digest-v1\",\"result_hash\":\"succeeded-invalid\",\"previous_success_context\":\"invalid context\",\"source_run_id\":\"upgrade-run-succeeded-invalid\",\"completed_at\":100}', 'pending', 1, 100, 100)")
    .execute(&pool)
    .await
    .expect("seed pending run with invalid baseline snapshot");
  sqlx::query("insert into scheduled_runs (run_id, job_id, schedule_id, job_generation, schedule_generation, scheduled_for, coalesced_through, definition_version, definition_json, capability_schema_version, capability_digest, capability_json, targets_json, execution_baseline_json, state, overlap_slot, created_at, updated_at) values ('upgrade-run-after-valid', 'upgrade-succeeded-valid', 'schedule-succeeded-valid', 0, 0, 151, 151, 1, '{}', 1, 'profile', '{}', '[{\"identity_digest\":\"0000000000000000000000000000000000000000000000000000000000000001\"}]', '{\"baseline_version\":4,\"hash_algorithm\":\"legacy-digest-v1\",\"result_hash\":\"succeeded-valid\",\"previous_success_context\":\"legacy context\",\"source_run_id\":\"upgrade-run-succeeded-valid\",\"completed_at\":100}', 'pending', 1, 100, 100)")
    .execute(&pool)
    .await
    .expect("seed pending run with valid baseline snapshot");
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
        "upgrade-run-after-invalid".to_owned(),
        "pending".to_owned(),
        0
      ),
      (
        "upgrade-run-after-valid".to_owned(),
        "pending".to_owned(),
        0
      ),
      (
        "upgrade-run-executing".to_owned(),
        "outcome_unknown".to_owned(),
        1
      ),
      ("upgrade-run-leased".to_owned(), "pending".to_owned(), 1),
      ("upgrade-run-pending".to_owned(), "pending".to_owned(), 0),
      (
        "upgrade-run-succeeded-collision".to_owned(),
        "failed".to_owned(),
        1
      ),
      (
        "upgrade-run-succeeded-empty".to_owned(),
        "failed".to_owned(),
        1
      ),
      (
        "upgrade-run-succeeded-invalid".to_owned(),
        "failed".to_owned(),
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
  let invalid_baseline: (i64, Option<String>, Option<String>, Option<String>) = sqlx::query_as(
    "select baseline_version, source_run_id, result_hash, previous_success_context from scheduled_execution_baselines where job_id = 'upgrade-succeeded-invalid'",
  )
  .fetch_one(&pool)
  .await
  .expect("read invalid baseline quarantine");
  assert_eq!(invalid_baseline, (4, None, None, None));
  let valid_baseline: (i64, Option<String>, Option<String>) = sqlx::query_as(
    "select baseline_version, source_run_id, previous_success_context from scheduled_execution_baselines where job_id = 'upgrade-succeeded-valid'",
  )
  .fetch_one(&pool)
  .await
  .expect("read preserved valid baseline");
  assert_eq!(
    valid_baseline,
    (
      4,
      Some("upgrade-run-succeeded-valid".to_owned()),
      Some("legacy context".to_owned())
    )
  );
  let pending_snapshot: (String, Option<String>, Option<String>, i64) = sqlx::query_as(
    "select state, json_extract(execution_baseline_json, '$.source_run_id'), json_extract(execution_baseline_json, '$.previous_success_context'), json_extract(execution_baseline_json, '$.baseline_version') from scheduled_runs where run_id = 'upgrade-run-after-invalid'",
  )
  .fetch_one(&pool)
  .await
  .expect("read quarantined pending snapshot");
  assert_eq!(pending_snapshot, ("pending".to_owned(), None, None, 4));
  let valid_snapshot: (String, Option<String>, Option<String>, i64) = sqlx::query_as(
    "select state, json_extract(execution_baseline_json, '$.source_run_id'), json_extract(execution_baseline_json, '$.previous_success_context'), json_extract(execution_baseline_json, '$.baseline_version') from scheduled_runs where run_id = 'upgrade-run-after-valid'",
  )
  .fetch_one(&pool)
  .await
  .expect("read preserved valid snapshot");
  assert_eq!(
    valid_snapshot,
    (
      "pending".to_owned(),
      Some("upgrade-run-succeeded-valid".to_owned()),
      Some("legacy context".to_owned()),
      4
    )
  );
  let invalid_terminal: (String, Option<i64>, Option<i64>, Option<String>, String) =
    sqlx::query_as(
      "select state, overlap_slot, next_attempt_at, lease_owner, error_kind from scheduled_runs where run_id = 'upgrade-run-succeeded-invalid'",
    )
    .fetch_one(&pool)
    .await
    .expect("read invalid terminal state");
  assert_eq!(
    invalid_terminal,
    (
      "failed".to_owned(),
      None,
      None,
      None,
      "legacy_result_unverified".to_owned()
    )
  );
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
    if entry.file_name() != "20260721030000_scheduler_execution_hardening.sql"
      && entry.file_name() != "20260721040000_scheduler_delivery_intents.sql"
    {
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
  sqlx::query("insert into scheduled_runs (run_id, job_id, schedule_id, job_generation, schedule_generation, scheduled_for, coalesced_through, definition_version, definition_json, capability_schema_version, capability_digest, capability_json, targets_json, state, attempt, fence, lease_owner, lease_expires_at, overlap_slot, created_at, updated_at) values ('mismatch-run', 'mismatch', 'schedule-mismatch', 0, 0, 110, 110, 1, '{}', 1, 'profile', '{}', '[{\"identity_digest\":\"0000000000000000000000000000000000000000000000000000000000000001\"}]', 'leased', 1, 2, 'worker', 200, 1, 100, 100)")
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
#[allow(clippy::too_many_lines)]
async fn test_execution_hardening_migration_rejects_exhausted_invalid_baseline() {
  let temp = tempdir().expect("create tempdir");
  let old_migrations = temp.path().join("old-migrations");
  std::fs::create_dir(&old_migrations).expect("create migration fixture");
  let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
  for entry in std::fs::read_dir(source).expect("read migrations") {
    let entry = entry.expect("migration entry");
    if entry.file_name() != "20260721030000_scheduler_execution_hardening.sql"
      && entry.file_name() != "20260721040000_scheduler_delivery_intents.sql"
    {
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
  sqlx::query("insert into scheduled_jobs (job_id, definition_version, definition_json, creator_kind, creator_provider, creator_tenant, creator_subject, owner_kind, owner_provider, owner_tenant, owner_subject, status, generation, capability_schema_version, capability_digest, capability_json, created_at, updated_at) values ('baseline-max', 1, '{}', 'user', 'test', 'tenant', 'creator', 'user', 'test', 'tenant', 'owner', 'active', 0, 1, 'profile', '{}', 100, 100)")
    .execute(&pool)
    .await
    .expect("seed job");
  sqlx::query("insert into schedules (schedule_id, job_id, kind, canonical_spec, once_at, next_run_at, created_at, updated_at) values ('schedule-baseline-max', 'baseline-max', 'once', '200', 200, 200, 100, 100)")
    .execute(&pool)
    .await
    .expect("seed schedule");
  sqlx::query("insert into scheduled_execution_baselines (job_id) values ('baseline-max')")
    .execute(&pool)
    .await
    .expect("seed baseline");
  sqlx::query("insert into scheduled_runs (run_id, job_id, schedule_id, job_generation, schedule_generation, scheduled_for, coalesced_through, definition_version, definition_json, capability_schema_version, capability_digest, capability_json, targets_json, state, overlap_slot, created_at, updated_at) values ('baseline-max-run', 'baseline-max', 'schedule-baseline-max', 0, 0, 110, 110, 1, '{}', 1, 'profile', '{}', '[{\"identity_digest\":\"0000000000000000000000000000000000000000000000000000000000000001\"}]', 'succeeded', null, 100, 100)")
    .execute(&pool)
    .await
    .expect("seed invalid success");
  sqlx::query("update scheduled_execution_baselines set baseline_version = 9223372036854775807, hash_algorithm = 'legacy-v1', result_hash = 'invalid', previous_success_context = 'invalid', source_run_id = 'baseline-max-run', completed_at = 100 where job_id = 'baseline-max'")
    .execute(&pool)
    .await
    .expect("seed exhausted invalid baseline");
  pool.close().await;

  assert!(matches!(
    StateStore::initialize(&state_dir, None).await,
    Err(StateError::Migrate { .. })
  ));
  let pool = SqlitePool::connect(&database_url(&state_dir))
    .await
    .expect("reopen rejected database");
  let unchanged: (i64, Option<String>, String) = sqlx::query_as(
    "select b.baseline_version, b.source_run_id, r.state from scheduled_execution_baselines b join scheduled_runs r on r.run_id = b.source_run_id where b.job_id = 'baseline-max'",
  )
  .fetch_one(&pool)
  .await
  .expect("read rolled back baseline");
  assert_eq!(
    unchanged,
    (
      i64::MAX,
      Some("baseline-max-run".to_owned()),
      "succeeded".to_owned()
    )
  );
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn test_delivery_intent_migration_preserves_all_legacy_states_and_baselines() {
  let temp = tempdir().expect("create tempdir");
  let parent_migrations = temp.path().join("parent-migrations");
  std::fs::create_dir(&parent_migrations).expect("create migration fixture");
  let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
  for entry in std::fs::read_dir(source).expect("read migrations") {
    let entry = entry.expect("migration entry");
    if entry.file_name() != "20260721040000_scheduler_delivery_intents.sql" {
      std::fs::copy(entry.path(), parent_migrations.join(entry.file_name()))
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
  Migrator::new(parent_migrations)
    .await
    .expect("load parent migrator")
    .run(&pool)
    .await
    .expect("run parent migrations");
  sqlx::query("insert into scheduled_jobs (job_id, definition_version, definition_json, creator_kind, creator_provider, creator_tenant, creator_subject, owner_kind, owner_provider, owner_tenant, owner_subject, status, generation, capability_schema_version, capability_digest, capability_json, created_at, updated_at) values ('delivery-upgrade', 1, '{}', 'user', 'test', 'tenant', 'creator', 'user', 'test', 'tenant', 'owner', 'active', 0, 1, 'profile', '{}', 100, 100)")
    .execute(&pool)
    .await
    .expect("seed job");
  sqlx::query("insert into schedules (schedule_id, job_id, kind, canonical_spec, once_at, next_run_at, created_at, updated_at) values ('schedule-delivery-upgrade', 'delivery-upgrade', 'once', '200', 200, 200, 100, 100)")
    .execute(&pool)
    .await
    .expect("seed schedule");
  sqlx::query("insert into scheduled_execution_baselines (job_id) values ('delivery-upgrade')")
    .execute(&pool)
    .await
    .expect("seed execution baseline");
  sqlx::query("insert into scheduled_runs (run_id, job_id, schedule_id, job_generation, schedule_generation, scheduled_for, coalesced_through, definition_version, definition_json, capability_schema_version, capability_digest, capability_json, targets_json, execution_baseline_json, state, overlap_slot, created_at, updated_at) values ('delivery-upgrade-run', 'delivery-upgrade', 'schedule-delivery-upgrade', 0, 0, 110, 110, 1, '{}', 1, 'profile', '{}', '[{\"identity_digest\":\"0000000000000000000000000000000000000000000000000000000000000001\"}]', '{\"baseline_version\":0,\"completed_at\":null,\"hash_algorithm\":null,\"previous_success_context\":null,\"result_hash\":null,\"source_run_id\":null}', 'pending', 1, 100, 100)")
    .execute(&pool)
    .await
    .expect("seed run");
  for (ordinal, state) in [
    "pending",
    "leased",
    "sending",
    "delivered",
    "failed",
    "delivery_unknown",
    "skipped",
  ]
  .into_iter()
  .enumerate()
  {
    let ordinal = i64::try_from(ordinal).expect("ordinal");
    let active = matches!(state, "leased" | "sending");
    let next_attempt_at = (state == "pending").then_some(150_i64);
    let provider_receipt = (state == "delivered").then_some("receipt");
    let error_message = matches!(state, "failed" | "delivery_unknown").then_some("error");
    sqlx::query("insert into scheduled_run_deliveries (delivery_id, run_id, job_id, target_identity_digest, target_json, state, attempt, next_attempt_at, lease_owner, lease_expires_at, fence, provider_receipt, error_message, delivery_policy_version, render_version, hash_algorithm, payload_digest, expected_baseline_version, created_at, updated_at) values (?1, 'delivery-upgrade-run', 'delivery-upgrade', ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 1, ?12, ?13, ?14, ?15, 100, 101)")
      .bind(format!("legacy-{state}"))
      .bind(format!("identity-{state}"))
      .bind(format!(r#"{{"state":"{state}"}}"#))
      .bind(state)
      .bind(ordinal)
      .bind(next_attempt_at)
      .bind(active.then_some("worker"))
      .bind(active.then_some(200_i64))
      .bind(ordinal + 10)
      .bind(provider_receipt)
      .bind(error_message)
      .bind(ordinal + 1)
      .bind(format!("hash-{state}"))
      .bind(format!("payload-{state}"))
      .bind(ordinal)
      .execute(&pool)
      .await
      .expect("seed legacy delivery");
  }
  sqlx::query("insert into scheduled_delivery_baselines (job_id, target_identity_digest, delivery_policy_version, render_version, hash_algorithm, accepted_payload_digest, source_delivery_id, source_run_id, source_result_hash, accepted_at, baseline_version) values ('delivery-upgrade', 'identity-delivered', 1, 4, 'hash-delivered', 'payload-delivered', 'legacy-delivered', 'delivery-upgrade-run', 'result', 101, 3)")
    .execute(&pool)
    .await
    .expect("seed delivery baseline");
  let deliveries_before: String = sqlx::query_scalar(
    "select json_group_array(json_object('delivery_id', delivery_id, 'run_id', run_id, 'job_id', job_id, 'target_identity_digest', target_identity_digest, 'target_json', json(target_json), 'state', state, 'attempt', attempt, 'next_attempt_at', next_attempt_at, 'lease_owner', lease_owner, 'lease_expires_at', lease_expires_at, 'fence', fence, 'provider_receipt', provider_receipt, 'error_message', error_message, 'delivery_policy_version', delivery_policy_version, 'render_version', render_version, 'hash_algorithm', hash_algorithm, 'payload_digest', payload_digest, 'expected_baseline_version', expected_baseline_version, 'created_at', created_at, 'updated_at', updated_at)) from (select * from scheduled_run_deliveries order by delivery_id)",
  )
  .fetch_one(&pool)
  .await
  .expect("snapshot parent deliveries");
  let baselines_before: String = sqlx::query_scalar(
    "select json_group_array(json_object('job_id', job_id, 'target_identity_digest', target_identity_digest, 'delivery_policy_version', delivery_policy_version, 'render_version', render_version, 'hash_algorithm', hash_algorithm, 'accepted_payload_digest', accepted_payload_digest, 'source_delivery_id', source_delivery_id, 'source_run_id', source_run_id, 'source_result_hash', source_result_hash, 'accepted_at', accepted_at, 'baseline_version', baseline_version)) from (select * from scheduled_delivery_baselines order by job_id, target_identity_digest, delivery_policy_version, render_version, hash_algorithm)",
  )
  .fetch_one(&pool)
  .await
  .expect("snapshot parent baselines");
  pool.close().await;

  StateStore::initialize(&state_dir, None)
    .await
    .expect("upgrade delivery schema");
  StateStore::initialize(&state_dir, None)
    .await
    .expect("repeat upgraded initialize");
  let pool = SqlitePool::connect(&database_url(&state_dir))
    .await
    .expect("connect upgraded database");
  let deliveries_after: String = sqlx::query_scalar(
    "select json_group_array(json_object('delivery_id', delivery_id, 'run_id', run_id, 'job_id', job_id, 'target_identity_digest', target_identity_digest, 'target_json', json(target_json), 'state', state, 'attempt', attempt, 'next_attempt_at', next_attempt_at, 'lease_owner', lease_owner, 'lease_expires_at', lease_expires_at, 'fence', fence, 'provider_receipt', provider_receipt, 'error_message', error_message, 'delivery_policy_version', delivery_policy_version, 'render_version', render_version, 'hash_algorithm', hash_algorithm, 'payload_digest', payload_digest, 'expected_baseline_version', expected_baseline_version, 'created_at', created_at, 'updated_at', updated_at)) from (select * from scheduled_run_deliveries order by delivery_id)",
  )
  .fetch_one(&pool)
  .await
  .expect("snapshot upgraded deliveries");
  let baselines_after: String = sqlx::query_scalar(
    "select json_group_array(json_object('job_id', job_id, 'target_identity_digest', target_identity_digest, 'delivery_policy_version', delivery_policy_version, 'render_version', render_version, 'hash_algorithm', hash_algorithm, 'accepted_payload_digest', accepted_payload_digest, 'source_delivery_id', source_delivery_id, 'source_run_id', source_run_id, 'source_result_hash', source_result_hash, 'accepted_at', accepted_at, 'baseline_version', baseline_version)) from (select * from scheduled_delivery_baselines order by job_id, target_identity_digest, delivery_policy_version, render_version, hash_algorithm)",
  )
  .fetch_one(&pool)
  .await
  .expect("snapshot upgraded baselines");
  assert_eq!(deliveries_after, deliveries_before);
  assert_eq!(baselines_after, baselines_before);
  let rows: Vec<LegacyDeliveryMigrationRow> = sqlx::query_as(
    "select state, attempt, next_attempt_at, lease_owner, lease_expires_at, fence, provider_receipt, error_message, authority_kind, intent_key, payload_snapshot from scheduled_run_deliveries order by delivery_id",
  )
  .fetch_all(&pool)
  .await
  .expect("read upgraded deliveries");
  assert_eq!(rows.len(), 7);
  for row in &rows {
    assert_eq!(row.8, "legacy");
    assert_eq!(row.9, None);
    assert_eq!(row.10, None);
  }
  let baseline: (String, String, i64) = sqlx::query_as(
    "select source_delivery_id, accepted_payload_digest, baseline_version from scheduled_delivery_baselines where job_id = 'delivery-upgrade'",
  )
  .fetch_one(&pool)
  .await
  .expect("read preserved baseline");
  assert_eq!(
    baseline,
    (
      "legacy-delivered".to_owned(),
      "payload-delivered".to_owned(),
      3
    )
  );
  let foreign_key_errors: i64 = sqlx::query_scalar("select count(*) from pragma_foreign_key_check")
    .fetch_one(&pool)
    .await
    .expect("check upgraded foreign keys");
  assert_eq!(foreign_key_errors, 0);
  let migration_applied: i64 = sqlx::query_scalar(
    "select count(*) from _sqlx_migrations where version = 20260721040000 and success = true",
  )
  .fetch_one(&pool)
  .await
  .expect("read migration state");
  assert_eq!(migration_applied, 1);
}

#[tokio::test]
async fn test_delivery_intent_migration_rolls_back_on_invalid_parent_foreign_key() {
  let temp = tempdir().expect("create tempdir");
  let parent_migrations = temp.path().join("parent-migrations");
  std::fs::create_dir(&parent_migrations).expect("create migration fixture");
  let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
  for entry in std::fs::read_dir(source).expect("read migrations") {
    let entry = entry.expect("migration entry");
    if entry.file_name() != "20260721040000_scheduler_delivery_intents.sql" {
      std::fs::copy(entry.path(), parent_migrations.join(entry.file_name()))
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
  Migrator::new(parent_migrations)
    .await
    .expect("load parent migrator")
    .run(&pool)
    .await
    .expect("run parent migrations");
  sqlx::query("pragma foreign_keys = off")
    .execute(&pool)
    .await
    .expect("disable fixture foreign keys");
  sqlx::query("insert into scheduled_run_deliveries (delivery_id, run_id, job_id, target_identity_digest, target_json, state, delivery_policy_version, render_version, hash_algorithm, payload_digest, expected_baseline_version, created_at, updated_at) values ('dangling', 'missing-run', 'missing-job', 'identity', '{}', 'pending', 1, 1, 'sha256-v1', 'payload', 0, 100, 100)")
    .execute(&pool)
    .await
    .expect("seed invalid parent row");
  sqlx::query("pragma foreign_keys = on")
    .execute(&pool)
    .await
    .expect("restore foreign keys");
  pool.close().await;

  assert!(matches!(
    StateStore::initialize(&state_dir, None).await,
    Err(StateError::Migrate { .. })
  ));
  let pool = SqlitePool::connect(&database_url(&state_dir))
    .await
    .expect("reopen rejected database");
  let unchanged: (String, String) = sqlx::query_as(
    "select delivery_id, run_id from scheduled_run_deliveries where delivery_id = 'dangling'",
  )
  .fetch_one(&pool)
  .await
  .expect("read rolled back delivery");
  assert_eq!(unchanged, ("dangling".to_owned(), "missing-run".to_owned()));
  let migration_applied: i64 = sqlx::query_scalar(
    "select count(*) from _sqlx_migrations where version = 20260721040000 and success = true",
  )
  .fetch_one(&pool)
  .await
  .expect("read migration state");
  assert_eq!(migration_applied, 0);
}

#[tokio::test]
async fn test_delivery_intent_migration_rolls_back_on_invalid_existing_target_identities() {
  let temp = tempdir().expect("create tempdir");
  let parent_migrations = temp.path().join("parent-migrations");
  std::fs::create_dir(&parent_migrations).expect("create migration fixture");
  let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
  for entry in std::fs::read_dir(source).expect("read migrations") {
    let entry = entry.expect("migration entry");
    if entry.file_name() != "20260721040000_scheduler_delivery_intents.sql" {
      std::fs::copy(entry.path(), parent_migrations.join(entry.file_name()))
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
  Migrator::new(parent_migrations)
    .await
    .expect("load parent migrator")
    .run(&pool)
    .await
    .expect("run parent migrations");
  sqlx::query("insert into scheduled_jobs (job_id, definition_version, definition_json, creator_kind, creator_provider, creator_tenant, creator_subject, owner_kind, owner_provider, owner_tenant, owner_subject, status, generation, capability_schema_version, capability_digest, capability_json, created_at, updated_at) values ('invalid-identity-upgrade', 1, '{}', 'user', 'test', 'tenant', 'creator', 'user', 'test', 'tenant', 'owner', 'active', 0, 1, 'profile', '{}', 100, 100)")
    .execute(&pool)
    .await
    .expect("seed job");
  sqlx::query("insert into schedules (schedule_id, job_id, kind, canonical_spec, once_at, next_run_at, created_at, updated_at) values ('schedule-invalid-identity-upgrade', 'invalid-identity-upgrade', 'once', '200', 200, 200, 100, 100)")
    .execute(&pool)
    .await
    .expect("seed schedule");
  sqlx::query(
    "insert into scheduled_execution_baselines (job_id) values ('invalid-identity-upgrade')",
  )
  .execute(&pool)
  .await
  .expect("seed baseline");
  sqlx::query("insert into scheduled_job_delivery_targets (target_id, job_id, ordinal, provider, connector, tenant, kind, address_json, resolver_version, resolver_digest, identity_digest) values ('invalid-target', 'invalid-identity-upgrade', 0, 'none', 'none', 'tenant', 'none', '{}', 1, 'resolver', 'not-a-sha')")
    .execute(&pool)
    .await
    .expect("seed invalid job target");
  sqlx::query("insert into scheduled_runs (run_id, job_id, schedule_id, job_generation, schedule_generation, scheduled_for, coalesced_through, definition_version, definition_json, capability_schema_version, capability_digest, capability_json, targets_json, state, overlap_slot, created_at, updated_at) values ('invalid-identity-run', 'invalid-identity-upgrade', 'schedule-invalid-identity-upgrade', 0, 0, 110, 110, 1, '{}', 1, 'profile', '{}', '[{\"identity_digest\":\"also-not-a-sha\"}]', 'pending', 1, 100, 100)")
    .execute(&pool)
    .await
    .expect("seed invalid run target");
  pool.close().await;

  assert!(matches!(
    StateStore::initialize(&state_dir, None).await,
    Err(StateError::Migrate { .. })
  ));
  let pool = SqlitePool::connect(&database_url(&state_dir))
    .await
    .expect("reopen rejected database");
  let unchanged: (String, String) = sqlx::query_as(
    "select (select identity_digest from scheduled_job_delivery_targets where target_id = 'invalid-target'), (select json_extract(targets_json, '$[0].identity_digest') from scheduled_runs where run_id = 'invalid-identity-run')",
  )
  .fetch_one(&pool)
  .await
  .expect("read rolled back invalid identities");
  assert_eq!(
    unchanged,
    ("not-a-sha".to_owned(), "also-not-a-sha".to_owned())
  );
  let migration_applied: i64 = sqlx::query_scalar(
    "select count(*) from _sqlx_migrations where version = 20260721040000 and success = true",
  )
  .fetch_one(&pool)
  .await
  .expect("read migration state");
  assert_eq!(migration_applied, 0);
}

#[tokio::test]
async fn test_delivery_intent_migration_rolls_back_on_existing_blob_target_identity() {
  let temp = tempdir().expect("create tempdir");
  let parent_migrations = temp.path().join("parent-migrations");
  std::fs::create_dir(&parent_migrations).expect("create migration fixture");
  let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
  for entry in std::fs::read_dir(source).expect("read migrations") {
    let entry = entry.expect("migration entry");
    if entry.file_name() != "20260721040000_scheduler_delivery_intents.sql" {
      std::fs::copy(entry.path(), parent_migrations.join(entry.file_name()))
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
  Migrator::new(parent_migrations)
    .await
    .expect("load parent migrator")
    .run(&pool)
    .await
    .expect("run parent migrations");
  sqlx::query("insert into scheduled_jobs (job_id, definition_version, definition_json, creator_kind, creator_provider, creator_tenant, creator_subject, owner_kind, owner_provider, owner_tenant, owner_subject, status, generation, capability_schema_version, capability_digest, capability_json, created_at, updated_at) values ('blob-identity-upgrade', 1, '{}', 'user', 'test', 'tenant', 'creator', 'user', 'test', 'tenant', 'owner', 'active', 0, 1, 'profile', '{}', 100, 100)")
    .execute(&pool)
    .await
    .expect("seed job");
  sqlx::query("insert into scheduled_job_delivery_targets (target_id, job_id, ordinal, provider, connector, tenant, kind, address_json, resolver_version, resolver_digest, identity_digest) values ('blob-target', 'blob-identity-upgrade', 0, 'none', 'none', 'tenant', 'none', '{}', 1, 'resolver', zeroblob(64))")
    .execute(&pool)
    .await
    .expect("seed blob target identity");
  pool.close().await;

  assert!(matches!(
    StateStore::initialize(&state_dir, None).await,
    Err(StateError::Migrate { .. })
  ));
  let pool = SqlitePool::connect(&database_url(&state_dir))
    .await
    .expect("reopen rejected database");
  let unchanged: (String, i64) = sqlx::query_as(
    "select typeof(identity_digest), length(identity_digest) from scheduled_job_delivery_targets where target_id = 'blob-target'",
  )
  .fetch_one(&pool)
  .await
  .expect("read rolled back blob identity");
  assert_eq!(unchanged, ("blob".to_owned(), 64));
  let migration_applied: i64 = sqlx::query_scalar(
    "select count(*) from _sqlx_migrations where version = 20260721040000 and success = true",
  )
  .fetch_one(&pool)
  .await
  .expect("read migration state");
  assert_eq!(migration_applied, 0);
}

#[tokio::test]
async fn test_current_schema_rejects_future_invalid_job_and_run_target_identities() {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state");
  let store = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize store");
  let job_id = "future-identity-guard";
  store
    .create_scheduled_job(&create_request(job_id, ScheduleSpec::once(110), 100))
    .await
    .expect("create job");
  let MaterializationOutcome::Created(run) = store
    .materialize_due_schedule(job_id, 0, 110)
    .await
    .expect("materialize")
  else {
    panic!("expected materialized run");
  };
  let pool = SqlitePool::connect(&database_url(&state_dir))
    .await
    .expect("connect database");
  assert!(
    sqlx::query(
      "update scheduled_job_delivery_targets set identity_digest = 'invalid' where job_id = ?1"
    )
    .bind(job_id)
    .execute(&pool)
    .await
    .is_err()
  );
  assert!(
    sqlx::query(
      "update scheduled_job_delivery_targets set identity_digest = zeroblob(64) where job_id = ?1"
    )
    .bind(job_id)
    .execute(&pool)
    .await
    .is_err()
  );
  assert!(
    sqlx::query("insert into scheduled_job_delivery_targets (target_id, job_id, ordinal, provider, connector, tenant, kind, address_json, resolver_version, resolver_digest, identity_digest) values ('future-invalid-target', ?1, 1, 'none', 'none', 'tenant', 'none', '{}', 1, 'resolver', 'invalid')")
      .bind(job_id)
      .execute(&pool)
      .await
      .is_err()
  );
  assert!(
    sqlx::query("insert into scheduled_job_delivery_targets (target_id, job_id, ordinal, provider, connector, tenant, kind, address_json, resolver_version, resolver_digest, identity_digest) values ('future-blob-target', ?1, 1, 'none', 'none', 'tenant', 'none', '{}', 1, 'resolver', zeroblob(64))")
      .bind(job_id)
      .execute(&pool)
      .await
      .is_err()
  );
  assert!(
    sqlx::query("update scheduled_runs set targets_json = '[{\"identity_digest\":\"invalid\"}]' where run_id = ?1")
      .bind(&run.run_id)
      .execute(&pool)
      .await
      .is_err()
  );
  assert!(
    sqlx::query("insert into scheduled_runs (run_id, job_id, schedule_id, job_generation, schedule_generation, scheduled_for, coalesced_through, definition_version, definition_json, capability_schema_version, capability_digest, capability_json, targets_json, state, overlap_slot, created_at, updated_at) select 'future-invalid-run', job_id, schedule_id, job_generation, schedule_generation, scheduled_for + 1, coalesced_through + 1, definition_version, definition_json, capability_schema_version, capability_digest, capability_json, '[{\"identity_digest\":\"invalid\"}]', 'failed', null, created_at, updated_at from scheduled_runs where run_id = ?1")
      .bind(&run.run_id)
      .execute(&pool)
      .await
      .is_err()
  );
  let preserved: (String, String, i64, i64, i64) = sqlx::query_as(
    "select (select identity_digest from scheduled_job_delivery_targets where job_id = ?1 and ordinal = 0), (select json_extract(targets_json, '$[0].identity_digest') from scheduled_runs where run_id = ?2), (select count(*) from scheduled_job_delivery_targets where target_id = 'future-invalid-target'), (select count(*) from scheduled_job_delivery_targets where target_id = 'future-blob-target'), (select count(*) from scheduled_runs where run_id = 'future-invalid-run')",
  )
  .bind(job_id)
  .bind(&run.run_id)
  .fetch_one(&pool)
  .await
  .expect("read preserved target identities");
  assert_eq!(
    preserved,
    (
      NONE_TARGET_IDENTITY.to_owned(),
      NONE_TARGET_IDENTITY.to_owned(),
      0,
      0,
      0
    )
  );
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
#[allow(clippy::too_many_lines)]
async fn test_execution_retry_requires_persisted_side_effect_free_attestation_and_live_fence() {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state");
  let store = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize state store");
  for (job, scheduled_for) in [
    ("safe-retry", 110),
    ("unsafe-retry", 111),
    ("late-retry", 112),
  ] {
    let mut request = create_request(job, ScheduleSpec::once(scheduled_for), 100);
    request.definition = ScheduledJobDefinition::new(
      1,
      format!(r#"{{"instruction":"execute {job}","previous_success":{{"kind":"none"}},"schema_version":1}}"#),
    )
    .expect("execution definition");
    store
      .create_scheduled_job(&request)
      .await
      .expect("create job");
    store
      .materialize_due_schedule(job, 0, scheduled_for)
      .await
      .expect("materialize");
  }
  let safe = store
    .claim_next_scheduled_run("worker", 113, 150)
    .await
    .expect("claim safe")
    .expect("safe run");
  let safe_authority =
    ScheduledPrepareAuthority::for_claim(&safe, "1".repeat(64)).expect("safe authority");
  let profile_json = safe_authority.attestation_json(true);
  for changed in [
    {
      let mut changed = safe.clone();
      changed.definition_json = changed
        .definition_json
        .replace("execute safe-retry", "execute changed");
      changed
    },
    {
      let mut changed = safe.clone();
      changed.capability_json = r#"{"tools":["github.write"]}"#.to_owned();
      changed
    },
    {
      let mut changed = safe.clone();
      changed.targets_json = changed
        .targets_json
        .replace(NONE_TARGET_IDENTITY, SLACK_TARGET_IDENTITY);
      changed
    },
    {
      let mut changed = safe.clone();
      changed.execution_baseline_json = changed
        .execution_baseline_json
        .replace(r#""baseline_version":0"#, r#""baseline_version":1"#);
      changed
    },
  ] {
    let changed_authority =
      ScheduledPrepareAuthority::for_claim(&changed, "1".repeat(64)).expect("changed authority");
    assert_ne!(changed_authority.digest(), safe_authority.digest());
    assert!(!changed_authority.attestation_matches(
      &profile_json,
      &test_sha256_hex(&profile_json),
      false,
    ));
  }
  assert_ne!(
    ScheduledPrepareAuthority::for_claim(&safe, "9".repeat(64))
      .expect("new nonce")
      .digest(),
    safe_authority.digest(),
  );
  let profile = AttestedExecutionProfileSnapshot::new(
    1,
    &profile_json,
    "sha256-v1",
    test_sha256_hex(&profile_json),
  )
  .expect("safe profile");
  store
    .mark_scheduled_run_executing(&safe.binding, &profile, 114)
    .await
    .expect("execute safe");
  assert_eq!(
    store
      .record_scheduled_run_execution_outcome(
        &safe.binding,
        ScheduledExecutionDisposition::RetryAt {
          retry_at: 120,
          deadline_at: 140,
          max_attempts: 3,
          transport: TransportConvergence::Converged,
          exhausted: ScheduledExecutionTerminal::Failed,
        },
        "interrupted",
        "known cancelled transport",
        115,
      )
      .await
      .expect("schedule safe retry"),
    ScheduledRunExecutionOutcome::Retried
  );

  let unsafe_claim = store
    .claim_next_scheduled_run("worker", 116, 150)
    .await
    .expect("claim unsafe")
    .expect("unsafe run");
  let unsafe_profile = AttestedExecutionProfileSnapshot::new(
    1,
    &profile_json,
    "sha256-v1",
    test_sha256_hex(&profile_json),
  )
  .expect("persistable mismatched profile");
  store
    .mark_scheduled_run_executing(&unsafe_claim.binding, &unsafe_profile, 117)
    .await
    .expect("execute unsafe");
  assert_eq!(
    store
      .record_scheduled_run_execution_outcome(
        &unsafe_claim.binding,
        ScheduledExecutionDisposition::RetryAt {
          retry_at: 121,
          deadline_at: 140,
          max_attempts: 3,
          transport: TransportConvergence::Converged,
          exhausted: ScheduledExecutionTerminal::Failed,
        },
        "interrupted",
        "untrusted attestation",
        118,
      )
      .await
      .expect("refuse unsafe retry"),
    ScheduledRunExecutionOutcome::Terminal(ScheduledExecutionTerminal::OutcomeUnknown)
  );

  let late = store
    .claim_next_scheduled_run("worker", 119, 130)
    .await
    .expect("claim late")
    .expect("late run");
  let late_authority =
    ScheduledPrepareAuthority::for_claim(&late, "2".repeat(64)).expect("late authority");
  let late_profile_json = late_authority.attestation_json(true);
  let late_profile = AttestedExecutionProfileSnapshot::new(
    1,
    &late_profile_json,
    "sha256-v1",
    test_sha256_hex(&late_profile_json),
  )
  .expect("late profile");
  store
    .mark_scheduled_run_executing(&late.binding, &late_profile, 120)
    .await
    .expect("execute late");
  assert!(matches!(
    store
      .record_scheduled_run_execution_outcome(
        &late.binding,
        ScheduledExecutionDisposition::Terminal(ScheduledExecutionTerminal::Failed),
        "turn_failed",
        "finished after lease loss",
        130,
      )
      .await
      .expect("append late evidence"),
    ScheduledRunExecutionOutcome::LateEvidence(LateEvidenceAppendOutcome::Recorded)
  ));

  let replay = store
    .claim_next_scheduled_run("worker", 131, 150)
    .await
    .expect("claim retry for replay")
    .expect("safe run retry");
  assert_eq!(replay.binding.attempt(), 2);
  store
    .mark_scheduled_run_executing(&replay.binding, &profile, 132)
    .await
    .expect("persist stale-attempt attestation");
  assert_eq!(
    store
      .record_scheduled_run_execution_outcome(
        &replay.binding,
        ScheduledExecutionDisposition::RetryAt {
          retry_at: 140,
          deadline_at: 145,
          max_attempts: 3,
          transport: TransportConvergence::Converged,
          exhausted: ScheduledExecutionTerminal::Failed,
        },
        "interrupted",
        "replayed nonce and attempt authority",
        133,
      )
      .await
      .expect("reject replayed authority"),
    ScheduledRunExecutionOutcome::Terminal(ScheduledExecutionTerminal::OutcomeUnknown)
  );

  let pool = SqlitePool::connect(&database_url(&state_dir))
    .await
    .expect("connect database");
  let states: Vec<(String, String, Option<i64>)> = sqlx::query_as(
    "select job_id, state, overlap_slot from scheduled_runs where job_id in ('safe-retry', 'unsafe-retry', 'late-retry') order by job_id",
  )
  .fetch_all(&pool)
  .await
  .expect("read states");
  assert_eq!(
    states,
    vec![
      ("late-retry".to_owned(), "executing".to_owned(), Some(1)),
      (
        "safe-retry".to_owned(),
        "outcome_unknown".to_owned(),
        Some(1),
      ),
      (
        "unsafe-retry".to_owned(),
        "outcome_unknown".to_owned(),
        Some(1),
      ),
    ]
  );
}

#[tokio::test]
async fn test_prepare_authority_covers_all_immutable_claim_metadata() {
  let temp = tempdir().expect("create tempdir");
  let store = StateStore::initialize(&temp.path().join("state"), None)
    .await
    .expect("initialize state store");
  let mut request = create_request("authority-metadata", ScheduleSpec::once(110), 100);
  request.definition = ScheduledJobDefinition::new(
    1,
    r#"{"instruction":"execute metadata","previous_success":{"kind":"none"},"schema_version":1}"#,
  )
  .expect("execution definition");
  store
    .create_scheduled_job(&request)
    .await
    .expect("create job");
  store
    .materialize_due_schedule("authority-metadata", 0, 110)
    .await
    .expect("materialize");
  let claim = store
    .claim_next_scheduled_run("worker", 111, 150)
    .await
    .expect("claim")
    .expect("claimed run");
  let nonce = "7".repeat(64);
  let authority = ScheduledPrepareAuthority::for_claim(&claim, &nonce).expect("authority");
  let attestation = authority.attestation_json(true);
  let attestation_digest = test_sha256_hex(&attestation);
  let mutations = [
    {
      let mut changed = claim.clone();
      changed.schedule_id.push_str("-changed");
      ("schedule_id", changed)
    },
    {
      let mut changed = claim.clone();
      changed.job_generation += 1;
      ("job_generation", changed)
    },
    {
      let mut changed = claim.clone();
      changed.schedule_generation += 1;
      ("schedule_generation", changed)
    },
    {
      let mut changed = claim.clone();
      changed.scheduled_for += 1;
      ("scheduled_for", changed)
    },
    {
      let mut changed = claim.clone();
      changed.coalesced_through += 1;
      ("coalesced_through", changed)
    },
    {
      let mut changed = claim.clone();
      changed.definition_version += 1;
      ("definition_version", changed)
    },
    {
      let mut changed = claim.clone();
      changed.capability_schema_version += 1;
      ("capability_schema_version", changed)
    },
  ];
  for (field, changed) in mutations {
    let changed_authority = ScheduledPrepareAuthority::for_claim(&changed, &nonce)
      .unwrap_or_else(|error| panic!("{field} authority: {error}"));
    assert_ne!(
      changed_authority.digest(),
      authority.digest(),
      "{field} must alter authority",
    );
    assert_ne!(
      changed_authority.canonical_json(),
      authority.canonical_json(),
      "{field} must alter canonical authority bytes",
    );
    assert!(
      !changed_authority.attestation_matches(&attestation, &attestation_digest, false),
      "{field} must reject the original attestation",
    );
  }
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

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn test_complete_success_atomically_persists_result_baseline_and_exact_delivery_intents() {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state");
  let store = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize store");
  let job_id = "complete:成功";
  let mut request = create_request(job_id, ScheduleSpec::once(110), 100);
  request.definition =
    ScheduledJobDefinition::new(2, r#"{"prompt":"check","schema_version":2}"#).expect("definition");
  request.targets.push(second_target(job_id));
  store
    .create_scheduled_job(&request)
    .await
    .expect("create job");
  store
    .materialize_due_schedule(job_id, 0, 110)
    .await
    .expect("materialize");
  let claim = store
    .claim_next_scheduled_run("worker", 111, 200)
    .await
    .expect("claim")
    .expect("claimed run");
  let profile =
    AttestedExecutionProfileSnapshot::new(1, "{}", "sha256-v1", "profile").expect("profile");
  store
    .mark_scheduled_run_executing(&claim.binding, &profile, 112)
    .await
    .expect("mark executing");
  let pool = SqlitePool::connect(&database_url(&state_dir))
    .await
    .expect("connect mutable job database");
  sqlx::query("update scheduled_job_delivery_targets set identity_digest = case ordinal when 0 then '0000000000000000000000000000000000000000000000000000000000000003' else '0000000000000000000000000000000000000000000000000000000000000004' end, address_json = '{\"mutated\":true}' where job_id = ?1")
    .bind(job_id)
    .execute(&pool)
    .await
    .expect("mutate current job targets after materialization");
  pool.close().await;
  let result =
    ScheduledRunResult::new("completed summary", "bounded previous context").expect("result");
  assert_eq!(
    store
      .complete_scheduled_run_success(&claim.binding, &result, 120)
      .await
      .expect("complete success"),
    ScheduledRunSuccessOutcome::Committed
  );

  let pool = SqlitePool::connect(&database_url(&state_dir))
    .await
    .expect("connect database");
  let authority: (String, String, i64, i64, i64, i64) = sqlx::query_as(
    "select r.state, a.state, b.baseline_version, (select count(*) from scheduled_run_result_artifacts x where x.run_id = r.run_id), (select count(*) from scheduled_run_deliveries d where d.run_id = r.run_id), (select count(*) from scheduled_delivery_baselines db where db.job_id = r.job_id) from scheduled_runs r join scheduled_run_attempts a on a.run_id = r.run_id and a.attempt = r.attempt join scheduled_execution_baselines b on b.job_id = r.job_id where r.run_id = ?1",
  )
  .bind(claim.binding.run_id())
  .fetch_one(&pool)
  .await
  .expect("read success authority");
  assert_eq!(
    authority,
    ("succeeded".to_owned(), "succeeded".to_owned(), 1, 1, 2, 0)
  );
  let intents: Vec<DeliveryIntentAuthorityRow> = sqlx::query_as(
    "select state, authority_kind, target_identity_digest, attempt, fence, delivery_policy_version, render_version, payload_digest, payload_snapshot, target_snapshot_digest_algorithm from scheduled_run_deliveries where run_id = ?1 order by target_identity_digest",
  )
  .bind(claim.binding.run_id())
  .fetch_all(&pool)
  .await
  .expect("read intents");
  assert_eq!(intents.len(), 2);
  assert_eq!(intents[0].2, NONE_TARGET_IDENTITY);
  assert_eq!(intents[1].2, SLACK_TARGET_IDENTITY);
  for intent in intents {
    assert_eq!(intent.0, "intent");
    assert_eq!(intent.1, "intent_v1");
    assert_eq!((intent.3, intent.4, intent.5), (0, 0, 1));
    assert_eq!((intent.6, intent.7, intent.8), (None, None, None));
    assert_eq!(intent.9, "sha256-v1");
  }
  let delivery_id: String = sqlx::query_scalar(
    "select delivery_id from scheduled_run_deliveries where run_id = ?1 order by delivery_id limit 1",
  )
  .bind(claim.binding.run_id())
  .fetch_one(&pool)
  .await
  .expect("read delivery intent id");
  let target_snapshot = store
    .load_scheduled_delivery_intent_target_snapshot(&delivery_id)
    .await
    .expect("validate intent target snapshot");
  assert!(target_snapshot.contains("identity_digest"));
  assert!(
    sqlx::query("update scheduled_run_deliveries set target_json = '{}' where run_id = ?1 limit 1")
      .bind(claim.binding.run_id())
      .execute(&pool)
      .await
      .is_err()
  );
  assert!(
    sqlx::query(
      "update scheduled_run_deliveries set state = 'pending', render_version = 1, hash_algorithm = 'sha256-v1', payload_digest = 'payload', expected_baseline_version = 0 where run_id = ?1 limit 1"
    )
    .bind(claim.binding.run_id())
    .execute(&pool)
    .await
    .is_err(),
    "intent enrichment requires immutable payload bytes"
  );
  sqlx::query(
    "update scheduled_run_deliveries set state = 'pending', render_version = 1, hash_algorithm = 'sha256-v1', payload_digest = 'payload-v1', payload_snapshot = ?1, expected_baseline_version = 0, updated_at = 121 where delivery_id = ?2",
  )
  .bind(b"rendered payload".as_slice())
  .bind(&delivery_id)
  .execute(&pool)
  .await
  .expect("enrich intent exactly once");
  assert!(
    sqlx::query(
      "update scheduled_run_deliveries set payload_snapshot = ?1, payload_digest = 'payload-v2', updated_at = 122 where delivery_id = ?2"
    )
    .bind(b"rewritten payload".as_slice())
    .bind(&delivery_id)
    .execute(&pool)
    .await
    .is_err(),
    "enriched payload cannot be rewritten"
  );
  assert!(
    sqlx::query(
      "update scheduled_run_deliveries set payload_snapshot = null, payload_digest = null, updated_at = 122 where delivery_id = ?1"
    )
    .bind(&delivery_id)
    .execute(&pool)
    .await
    .is_err(),
    "enriched payload cannot be cleared"
  );
  assert!(
    sqlx::query("update scheduled_run_deliveries set state = 'intent' where delivery_id = ?1")
      .bind(&delivery_id)
      .execute(&pool)
      .await
      .is_err(),
    "pending intent cannot return to intent state"
  );
  assert!(
    sqlx::query("delete from scheduled_run_deliveries where delivery_id = ?1")
      .bind(&delivery_id)
      .execute(&pool)
      .await
      .is_err(),
    "intent authority cannot be deleted"
  );
  assert!(
    sqlx::query(
      "insert or replace into scheduled_run_deliveries select * from scheduled_run_deliveries where delivery_id = ?1"
    )
    .bind(&delivery_id)
    .execute(&pool)
    .await
    .is_err(),
    "intent authority cannot be replaced"
  );
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn test_direct_delivery_intents_require_database_verifiable_authority() {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state");
  let store = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize store");
  let job_id = "direct-intent-authority";
  store
    .create_scheduled_job(&create_request(job_id, ScheduleSpec::once(110), 100))
    .await
    .expect("create job");
  store
    .materialize_due_schedule(job_id, 0, 110)
    .await
    .expect("materialize");
  let claim = store
    .claim_next_scheduled_run("worker", 111, 200)
    .await
    .expect("claim")
    .expect("claimed run");
  let profile =
    AttestedExecutionProfileSnapshot::new(1, "{}", "sha256-v1", "profile").expect("profile");
  store
    .mark_scheduled_run_executing(&claim.binding, &profile, 112)
    .await
    .expect("mark executing");
  let pool = SqlitePool::connect(&database_url(&state_dir))
    .await
    .expect("connect database");
  let artifact_id = "direct-intent-artifact";
  sqlx::query(
    "insert into scheduled_run_result_artifacts (artifact_id, run_id, job_id, accepted_attempt, accepted_fence, schema_version, result_json, hash_algorithm, result_hash, previous_success_context, completed_at, provenance, provenance_version) values (?1, ?2, ?3, ?4, ?5, 1, '{\"schema_version\":1,\"summary\":\"direct\"}', 'sha256-v1', 'direct-result', '', 113, 'native', 1)",
  )
  .bind(artifact_id)
  .bind(claim.binding.run_id())
  .bind(job_id)
  .bind(claim.binding.attempt())
  .bind(claim.binding.fence())
  .execute(&pool)
  .await
  .expect("insert native result artifact");
  let target_json: String = sqlx::query_scalar(
    "select json_extract(targets_json, '$[0]') from scheduled_runs where run_id = ?1",
  )
  .bind(claim.binding.run_id())
  .fetch_one(&pool)
  .await
  .expect("read target snapshot");
  let identity = NONE_TARGET_IDENTITY;
  let natural_key = test_intent_key(claim.binding.run_id(), identity);
  let natural_delivery_id = format!("intent:{natural_key}");
  let target_snapshot_digest = test_sha256_hex(&target_json);
  let nullable_authority = [
    (
      "artifact",
      None,
      Some(claim.binding.attempt()),
      Some(claim.binding.fence()),
      Some("sha256-v1"),
      Some(target_snapshot_digest.as_str()),
      Some(natural_key.as_str()),
    ),
    (
      "result attempt",
      Some(artifact_id),
      None,
      Some(claim.binding.fence()),
      Some("sha256-v1"),
      Some(target_snapshot_digest.as_str()),
      Some(natural_key.as_str()),
    ),
    (
      "result fence",
      Some(artifact_id),
      Some(claim.binding.attempt()),
      None,
      Some("sha256-v1"),
      Some(target_snapshot_digest.as_str()),
      Some(natural_key.as_str()),
    ),
    (
      "snapshot algorithm",
      Some(artifact_id),
      Some(claim.binding.attempt()),
      Some(claim.binding.fence()),
      None,
      Some(target_snapshot_digest.as_str()),
      Some(natural_key.as_str()),
    ),
    (
      "snapshot digest",
      Some(artifact_id),
      Some(claim.binding.attempt()),
      Some(claim.binding.fence()),
      Some("sha256-v1"),
      None,
      Some(natural_key.as_str()),
    ),
    (
      "intent key",
      Some(artifact_id),
      Some(claim.binding.attempt()),
      Some(claim.binding.fence()),
      Some("sha256-v1"),
      Some(target_snapshot_digest.as_str()),
      None,
    ),
  ];
  for (field, artifact, result_attempt, result_fence, algorithm, digest, intent_key) in
    nullable_authority
  {
    let insert = sqlx::query(
      "insert into scheduled_run_deliveries (delivery_id, run_id, job_id, target_identity_digest, target_json, state, attempt, fence, delivery_policy_version, result_artifact_id, result_attempt, result_fence, target_snapshot_digest_algorithm, target_snapshot_digest, intent_key, authority_kind, created_at, updated_at) values (?1, ?2, ?3, ?4, ?5, 'intent', 0, 0, 1, ?6, ?7, ?8, ?9, ?10, ?11, 'intent_v1', 114, 114)",
    )
    .bind(&natural_delivery_id)
    .bind(claim.binding.run_id())
    .bind(job_id)
    .bind(identity)
    .bind(&target_json)
    .bind(artifact)
    .bind(result_attempt)
    .bind(result_fence)
    .bind(algorithm)
    .bind(digest)
    .bind(intent_key)
    .execute(&pool)
    .await;
    assert!(insert.is_err(), "NULL {field} must be rejected");
  }
  assert!(
    sqlx::query(
      "insert into scheduled_run_deliveries (delivery_id, run_id, job_id, target_identity_digest, target_json, state, attempt, fence, delivery_policy_version, render_version, hash_algorithm, payload_digest, payload_snapshot, expected_baseline_version, result_artifact_id, result_attempt, result_fence, target_snapshot_digest_algorithm, target_snapshot_digest, intent_key, authority_kind, created_at, updated_at) values (?1, ?2, ?3, ?4, ?5, 'pending', 0, 0, 1, 1, 'sha256-v1', 'payload', ?6, 0, ?7, ?8, ?9, 'sha256-v1', ?10, ?11, 'intent_v1', 114, 114)"
    )
    .bind(&natural_delivery_id)
    .bind(claim.binding.run_id())
    .bind(job_id)
    .bind(identity)
    .bind(&target_json)
    .bind(b"rendered payload".as_slice())
    .bind(artifact_id)
    .bind(claim.binding.attempt())
    .bind(claim.binding.fence())
    .bind(&target_snapshot_digest)
    .bind(&natural_key)
    .execute(&pool)
    .await
    .is_err(),
    "direct pending intent insert must be rejected even with a complete payload"
  );
  let mut foreign_target: serde_json::Value =
    serde_json::from_str(&target_json).expect("parse target");
  foreign_target["address"] = serde_json::json!({"foreign": true});
  let foreign_target = serde_json::to_string(&foreign_target).expect("serialize foreign target");
  let invalid = [
    (
      "policy-2",
      2,
      identity,
      target_json.as_str(),
      format!(
        "{}:2",
        test_intent_key(claim.binding.run_id(), identity).trim_end_matches(":1")
      ),
      format!(
        "intent:{}:2",
        test_intent_key(claim.binding.run_id(), identity).trim_end_matches(":1")
      ),
    ),
    (
      "empty-target",
      1,
      identity,
      "{}",
      natural_key.clone(),
      natural_delivery_id.clone(),
    ),
    (
      "foreign-target",
      1,
      identity,
      foreign_target.as_str(),
      natural_key.clone(),
      natural_delivery_id.clone(),
    ),
    (
      "identity-mismatch",
      1,
      SLACK_TARGET_IDENTITY,
      target_json.as_str(),
      test_intent_key(claim.binding.run_id(), SLACK_TARGET_IDENTITY),
      format!(
        "intent:{}",
        test_intent_key(claim.binding.run_id(), SLACK_TARGET_IDENTITY)
      ),
    ),
    (
      "key-mismatch",
      1,
      identity,
      target_json.as_str(),
      "v1:wrong:key:1".to_owned(),
      "intent:v1:wrong:key:1".to_owned(),
    ),
    (
      "delivery-id-mismatch",
      1,
      identity,
      target_json.as_str(),
      natural_key.clone(),
      "intent:wrong".to_owned(),
    ),
  ];
  for (name, policy, target_identity, candidate_target, intent_key, delivery_id) in invalid {
    let insert = sqlx::query(
      "insert into scheduled_run_deliveries (delivery_id, run_id, job_id, target_identity_digest, target_json, state, attempt, fence, delivery_policy_version, result_artifact_id, result_attempt, result_fence, target_snapshot_digest_algorithm, target_snapshot_digest, intent_key, authority_kind, created_at, updated_at) values (?1, ?2, ?3, ?4, ?5, 'intent', 0, 0, ?6, ?7, ?8, ?9, 'sha256-v1', ?10, ?11, 'intent_v1', 114, 114)",
    )
    .bind(delivery_id)
    .bind(claim.binding.run_id())
    .bind(job_id)
    .bind(target_identity)
    .bind(candidate_target)
    .bind(policy)
    .bind(artifact_id)
    .bind(claim.binding.attempt())
    .bind(claim.binding.fence())
    .bind(test_sha256_hex(candidate_target))
    .bind(intent_key)
    .execute(&pool)
    .await;
    assert!(insert.is_err(), "{name} intent must be rejected");
  }

  sqlx::query(
    "insert into scheduled_run_deliveries (delivery_id, run_id, job_id, target_identity_digest, target_json, state, attempt, fence, delivery_policy_version, result_artifact_id, result_attempt, result_fence, target_snapshot_digest_algorithm, target_snapshot_digest, intent_key, authority_kind, created_at, updated_at) values (?1, ?2, ?3, ?4, ?5, 'intent', 0, 0, 1, ?6, ?7, ?8, 'sha256-v1', ?9, ?10, 'intent_v1', 114, 114)",
  )
  .bind(&natural_delivery_id)
  .bind(claim.binding.run_id())
  .bind(job_id)
  .bind(identity)
  .bind(&target_json)
  .bind(artifact_id)
  .bind(claim.binding.attempt())
  .bind(claim.binding.fence())
  .bind("0".repeat(64))
  .bind(&natural_key)
  .execute(&pool)
  .await
  .expect("database accepts non-authoritative derived digest metadata");
  assert!(matches!(
    store
      .load_scheduled_delivery_intent_target_snapshot(&natural_delivery_id)
      .await,
    Err(StateError::InvalidSchedulerState { reason })
      if reason == "scheduled delivery intent target snapshot digest mismatch"
  ));
  let legacy_delivery_id = "legacy-update-collision";
  sqlx::query(
    "insert into scheduled_run_deliveries (delivery_id, run_id, job_id, target_identity_digest, target_json, state, delivery_policy_version, render_version, hash_algorithm, payload_digest, payload_snapshot, expected_baseline_version, created_at, updated_at) values (?1, ?2, ?3, 'legacy-identity', '{}', 'pending', 1, 1, 'sha256-v1', 'legacy-payload', ?4, 0, 115, 115)",
  )
  .bind(legacy_delivery_id)
  .bind(claim.binding.run_id())
  .bind(job_id)
  .bind(b"legacy payload".as_slice())
  .execute(&pool)
  .await
  .expect("insert legacy update source");
  let collision_updates = [
    (
      "delivery id",
      "update or replace scheduled_run_deliveries set delivery_id = ?1 where delivery_id = ?2",
      natural_delivery_id.as_str(),
    ),
    (
      "intent key",
      "update or replace scheduled_run_deliveries set intent_key = ?1 where delivery_id = ?2",
      natural_key.as_str(),
    ),
    (
      "natural tuple",
      "update or replace scheduled_run_deliveries set target_identity_digest = ?1 where delivery_id = ?2",
      identity,
    ),
  ];
  for (collision, statement, value) in collision_updates {
    assert!(
      sqlx::query(statement)
        .bind(value)
        .bind(legacy_delivery_id)
        .execute(&pool)
        .await
        .is_err(),
      "UPDATE OR REPLACE {collision} collision must be rejected"
    );
    let preserved: (i64, String) = sqlx::query_as(
      "select count(*), (select target_identity_digest from scheduled_run_deliveries where delivery_id = ?1) from scheduled_run_deliveries where delivery_id in (?1, ?2)",
    )
    .bind(legacy_delivery_id)
    .bind(&natural_delivery_id)
    .fetch_one(&pool)
    .await
    .expect("read preserved collision rows");
    assert_eq!(preserved, (2, "legacy-identity".to_owned()));
  }
  assert!(
    sqlx::query(
      "insert or replace into scheduled_run_deliveries (delivery_id, run_id, job_id, target_identity_digest, target_json, state, delivery_policy_version, render_version, hash_algorithm, payload_digest, payload_snapshot, expected_baseline_version, created_at, updated_at) values (?1, ?2, ?3, 'legacy-replacement', '{}', 'pending', 1, 1, 'sha256-v1', 'replacement', ?4, 0, 115, 115)"
    )
    .bind(&natural_delivery_id)
    .bind(claim.binding.run_id())
    .bind(job_id)
    .bind(b"replacement".as_slice())
    .execute(&pool)
    .await
    .is_err(),
    "OR REPLACE cannot remove intent authority even while its run remains executing"
  );
}

#[tokio::test]
async fn test_delivery_intent_run_id_byte_bound_accepts_generated_schema_maximum() {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state");
  let store = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize store");
  let job_id = "😀".repeat(255);
  let scheduled_for = 1_000_000_000_000_000_000;
  let mut request = create_request(
    &job_id,
    ScheduleSpec::once(scheduled_for),
    scheduled_for - 1,
  );
  request.schedule_id = "schedule-run-id-bound".to_owned();
  request.targets = vec![target("run-id-bound")];
  store
    .create_scheduled_job(&request)
    .await
    .expect("create maximum-width job id");
  store
    .materialize_due_schedule(&job_id, 0, scheduled_for)
    .await
    .expect("materialize maximum-width run id");
  let claim = store
    .claim_next_scheduled_run("worker", scheduled_for, scheduled_for + 100)
    .await
    .expect("claim")
    .expect("claimed maximum-width run");
  assert_eq!(claim.binding.run_id().len(), 1050);
  let profile =
    AttestedExecutionProfileSnapshot::new(1, "{}", "sha256-v1", "profile").expect("profile");
  store
    .mark_scheduled_run_executing(&claim.binding, &profile, scheduled_for + 1)
    .await
    .expect("mark executing");
  let result = ScheduledRunResult::new("bounded run id", "context").expect("result");
  assert_eq!(
    store
      .complete_scheduled_run_success(&claim.binding, &result, scheduled_for + 2)
      .await
      .expect("complete schema-maximum run id"),
    ScheduledRunSuccessOutcome::Committed
  );
  let pool = SqlitePool::connect(&database_url(&state_dir))
    .await
    .expect("connect database");
  let delivery_id: String =
    sqlx::query_scalar("select delivery_id from scheduled_run_deliveries where run_id = ?1")
      .bind(claim.binding.run_id())
      .fetch_one(&pool)
      .await
      .expect("read maximum-bound delivery intent");
  store
    .load_scheduled_delivery_intent_target_snapshot(&delivery_id)
    .await
    .expect("load maximum-bound intent snapshot");
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn test_complete_success_baseline_and_insert_conflicts_roll_back_all_authority() {
  for conflict in ["baseline", "artifact", "delivery"] {
    let temp = tempdir().expect("create tempdir");
    let state_dir = temp.path().join("state");
    let store = StateStore::initialize(&state_dir, None)
      .await
      .expect("initialize store");
    let job_id = format!("success-conflict-{conflict}");
    store
      .create_scheduled_job(&create_request(&job_id, ScheduleSpec::once(110), 100))
      .await
      .expect("create job");
    store
      .materialize_due_schedule(&job_id, 0, 110)
      .await
      .expect("materialize");
    let claim = store
      .claim_next_scheduled_run("worker", 111, 200)
      .await
      .expect("claim")
      .expect("claimed run");
    let profile =
      AttestedExecutionProfileSnapshot::new(1, "{}", "sha256-v1", "profile").expect("profile");
    store
      .mark_scheduled_run_executing(&claim.binding, &profile, 112)
      .await
      .expect("mark executing");
    let pool = SqlitePool::connect(&database_url(&state_dir))
      .await
      .expect("connect database");
    match conflict {
      "baseline" => {
        sqlx::query(
          "update scheduled_execution_baselines set baseline_version = 1 where job_id = ?1",
        )
        .bind(&job_id)
        .execute(&pool)
        .await
        .expect("advance baseline");
      }
      "artifact" => {
        sqlx::query("insert into scheduled_run_result_artifacts (artifact_id, run_id, job_id, accepted_attempt, accepted_fence, schema_version, result_json, hash_algorithm, result_hash, previous_success_context, completed_at) values ('preexisting', ?1, ?2, ?3, ?4, 1, '{\"schema_version\":1,\"summary\":\"other\"}', 'sha256-v1', 'other', 'other', 119)")
          .bind(claim.binding.run_id())
          .bind(&job_id)
          .bind(claim.binding.attempt())
          .bind(claim.binding.fence())
          .execute(&pool)
          .await
          .expect("seed artifact collision");
      }
      "delivery" => {
        let target_json: String = sqlx::query_scalar(
          "select json_extract(targets_json, '$[0]') from scheduled_runs where run_id = ?1",
        )
        .bind(claim.binding.run_id())
        .fetch_one(&pool)
        .await
        .expect("read target snapshot");
        let target: serde_json::Value =
          serde_json::from_str(&target_json).expect("parse target snapshot");
        let identity = target["identity_digest"].as_str().expect("identity digest");
        let intent_key = test_intent_key(claim.binding.run_id(), identity);
        sqlx::query("insert into scheduled_run_deliveries (delivery_id, run_id, job_id, target_identity_digest, target_json, state, delivery_policy_version, render_version, hash_algorithm, payload_digest, expected_baseline_version, created_at, updated_at) values (?1, ?2, ?3, 'collision', '{}', 'pending', 1, 1, 'sha256-v1', 'collision', 0, 119, 119)")
          .bind(format!("intent:{intent_key}"))
          .bind(claim.binding.run_id())
          .bind(&job_id)
          .execute(&pool)
          .await
          .expect("seed delivery id collision");
      }
      _ => unreachable!(),
    }
    let result = ScheduledRunResult::new("completed summary", "context").expect("result");
    assert!(matches!(
      store
        .complete_scheduled_run_success(&claim.binding, &result, 120)
        .await,
      Err(StateError::ScheduledRunCompletionConflict)
    ));
    let unchanged: (String, String, i64, i64, i64) = sqlx::query_as(
      "select r.state, a.state, b.baseline_version, (select count(*) from scheduled_run_result_artifacts x where x.run_id = r.run_id), (select count(*) from scheduled_run_deliveries d where d.run_id = r.run_id and d.authority_kind = 'intent_v1') from scheduled_runs r join scheduled_run_attempts a on a.run_id = r.run_id and a.attempt = r.attempt join scheduled_execution_baselines b on b.job_id = r.job_id where r.run_id = ?1",
    )
    .bind(claim.binding.run_id())
    .fetch_one(&pool)
    .await
    .expect("read rolled back authority");
    let expected_artifacts = i64::from(conflict == "artifact");
    let expected_baseline = i64::from(conflict == "baseline");
    assert_eq!(
      unchanged,
      (
        "executing".to_owned(),
        "executing".to_owned(),
        expected_baseline,
        expected_artifacts,
        0
      )
    );
  }
}

#[tokio::test]
async fn test_two_stores_complete_one_success_and_record_repeated_completion_as_late_evidence() {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state");
  let first = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize first store");
  let second = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize second store");
  let claim = prepare_executing_run(&first, "success-race", 200).await;
  let result = ScheduledRunResult::new("completed summary", "context").expect("result");
  let barrier = Arc::new(Barrier::new(3));
  let first_task = tokio::spawn(complete_success_after_barrier(
    first,
    claim.binding.clone(),
    result.clone(),
    Arc::clone(&barrier),
    120,
  ));
  let second_task = tokio::spawn(complete_success_after_barrier(
    second,
    claim.binding.clone(),
    result,
    Arc::clone(&barrier),
    120,
  ));
  barrier.wait().await;
  let outcomes = [
    first_task.await.expect("first completion task"),
    second_task.await.expect("second completion task"),
  ];
  assert_eq!(
    outcomes
      .iter()
      .filter(|outcome| matches!(outcome, Ok(ScheduledRunSuccessOutcome::Committed)))
      .count(),
    1
  );
  assert_eq!(
    outcomes
      .iter()
      .filter(|outcome| matches!(
        outcome,
        Ok(ScheduledRunSuccessOutcome::LateEvidence(
          LateEvidenceAppendOutcome::Recorded
        ))
      ))
      .count(),
    1,
    "completion outcomes: {outcomes:?}"
  );
  let pool = SqlitePool::connect(&database_url(&state_dir))
    .await
    .expect("connect database");
  let authority: (String, i64, i64, i64, i64) = sqlx::query_as(
    "select state, (select count(*) from scheduled_run_result_artifacts where run_id = ?1), (select baseline_version from scheduled_execution_baselines where job_id = 'success-race'), (select count(*) from scheduled_run_deliveries where run_id = ?1 and authority_kind = 'intent_v1'), (select count(*) from scheduled_run_late_evidence where run_id = ?1) from scheduled_runs where run_id = ?1",
  )
  .bind(claim.binding.run_id())
  .fetch_one(&pool)
  .await
  .expect("read converged success");
  assert_eq!(authority, ("succeeded".to_owned(), 1, 1, 1, 1));
}

#[tokio::test]
async fn test_success_racing_expired_reclaim_commits_one_complete_authority_outcome() {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state");
  let completer = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize completer");
  let reclaimer = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize reclaimer");
  let claim = prepare_executing_run(&completer, "success-reclaim-race", 121).await;
  let result = ScheduledRunResult::new("completed summary", "context").expect("result");
  let barrier = Arc::new(Barrier::new(3));
  let completion_task = tokio::spawn(complete_success_after_barrier(
    completer,
    claim.binding.clone(),
    result,
    Arc::clone(&barrier),
    120,
  ));
  let reclaim_task = tokio::spawn(success_reclaim_after_barrier(
    reclaimer,
    Arc::clone(&barrier),
    122,
  ));
  barrier.wait().await;
  let completion = completion_task.await.expect("completion task");
  let reclaim = reclaim_task.await.expect("reclaim task");
  let pool = SqlitePool::connect(&database_url(&state_dir))
    .await
    .expect("connect database");
  let authority: (String, i64, i64, i64, i64) = sqlx::query_as(
    "select state, (select count(*) from scheduled_run_result_artifacts where run_id = ?1), (select baseline_version from scheduled_execution_baselines where job_id = 'success-reclaim-race'), (select count(*) from scheduled_run_deliveries where run_id = ?1 and authority_kind = 'intent_v1'), (select count(*) from scheduled_run_late_evidence where run_id = ?1) from scheduled_runs where run_id = ?1",
  )
  .bind(claim.binding.run_id())
  .fetch_one(&pool)
  .await
  .expect("read race authority");
  match authority.0.as_str() {
    "succeeded" => {
      assert_eq!(authority, ("succeeded".to_owned(), 1, 1, 1, 0));
      assert!(matches!(
        completion,
        Ok(ScheduledRunSuccessOutcome::Committed)
      ));
      assert!(
        matches!(
          &reclaim,
          Ok(ExpiredRunReclaimOutcome::Idle) | Err(StateError::ScheduledRunLostLease)
        ),
        "reclaim outcome: {reclaim:?}"
      );
    }
    "outcome_unknown" => {
      assert_eq!(
        authority,
        ("outcome_unknown".to_owned(), 0, 0, 0, 1),
        "completion={completion:?} reclaim={reclaim:?}"
      );
      assert!(matches!(
        completion,
        Ok(ScheduledRunSuccessOutcome::LateEvidence(
          LateEvidenceAppendOutcome::Recorded
        ))
      ));
      assert!(matches!(
        reclaim,
        Ok(ExpiredRunReclaimOutcome::OutcomeUnknown { .. })
      ));
    }
    state => panic!("unexpected race state {state}"),
  }
}

#[tokio::test]
async fn test_stale_fence_completion_only_records_late_evidence() {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state");
  let store = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize store");
  store
    .create_scheduled_job(&create_request(
      "stale-completion",
      ScheduleSpec::once(110),
      100,
    ))
    .await
    .expect("create job");
  store
    .materialize_due_schedule("stale-completion", 0, 110)
    .await
    .expect("materialize");
  let stale = store
    .claim_next_scheduled_run("worker-a", 111, 120)
    .await
    .expect("first claim")
    .expect("claimed run");
  assert!(matches!(
    store
      .reclaim_next_expired_scheduled_run(121, 3, 130)
      .await
      .expect("reclaim"),
    ExpiredRunReclaimOutcome::Retried { .. }
  ));
  let current = store
    .claim_next_scheduled_run("worker-b", 130, 200)
    .await
    .expect("second claim")
    .expect("claimed run");
  let result = ScheduledRunResult::new("late summary", "late context").expect("result");
  assert_eq!(
    store
      .complete_scheduled_run_success(&stale.binding, &result, 140)
      .await
      .expect("late completion"),
    ScheduledRunSuccessOutcome::LateEvidence(LateEvidenceAppendOutcome::Recorded)
  );
  let pool = SqlitePool::connect(&database_url(&state_dir))
    .await
    .expect("connect database");
  let authority: (String, i64, i64, i64, i64, i64) = sqlx::query_as(
    "select state, attempt, fence, (select count(*) from scheduled_run_result_artifacts where run_id = ?1), (select count(*) from scheduled_run_deliveries where run_id = ?1), (select count(*) from scheduled_run_late_evidence where run_id = ?1) from scheduled_runs where run_id = ?1",
  )
  .bind(current.binding.run_id())
  .fetch_one(&pool)
  .await
  .expect("read current authority");
  assert_eq!(
    authority,
    (
      "leased".to_owned(),
      current.binding.attempt(),
      current.binding.fence(),
      0,
      0,
      1
    )
  );
}

async fn prepare_executing_run(
  store: &StateStore,
  job_id: &str,
  lease_expires_at: i64,
) -> ClaimedScheduledRun {
  store
    .create_scheduled_job(&create_request(job_id, ScheduleSpec::once(110), 100))
    .await
    .expect("create job");
  store
    .materialize_due_schedule(job_id, 0, 110)
    .await
    .expect("materialize");
  let claim = store
    .claim_next_scheduled_run("worker", 111, lease_expires_at)
    .await
    .expect("claim")
    .expect("claimed run");
  let profile =
    AttestedExecutionProfileSnapshot::new(1, "{}", "sha256-v1", "profile").expect("profile");
  store
    .mark_scheduled_run_executing(&claim.binding, &profile, 112)
    .await
    .expect("mark executing");
  claim
}

async fn complete_success_after_barrier(
  store: StateStore,
  binding: codeoff_state::RunLeaseBinding,
  result: ScheduledRunResult,
  barrier: Arc<Barrier>,
  completed_at: i64,
) -> Result<ScheduledRunSuccessOutcome, StateError> {
  barrier.wait().await;
  for _ in 0..20 {
    match store
      .complete_scheduled_run_success(&binding, &result, completed_at)
      .await
    {
      Err(error) if error.is_transient_storage_contention() => {
        tokio::time::sleep(Duration::from_millis(5)).await;
      }
      outcome => return outcome,
    }
  }
  store
    .complete_scheduled_run_success(&binding, &result, completed_at)
    .await
}

async fn success_reclaim_after_barrier(
  store: StateStore,
  barrier: Arc<Barrier>,
  now: i64,
) -> Result<ExpiredRunReclaimOutcome, StateError> {
  barrier.wait().await;
  for _ in 0..20 {
    match store
      .reclaim_next_expired_scheduled_run(now, 3, now + 10)
      .await
    {
      Err(error) if error.is_transient_storage_contention() => {
        tokio::time::sleep(Duration::from_millis(5)).await;
      }
      outcome => return outcome,
    }
  }
  store
    .reclaim_next_expired_scheduled_run(now, 3, now + 10)
    .await
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
  for job in ["artifact-a", "artifact-b", "artifact-schema"] {
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
    if ordinal == 0 {
      assert!(
        sqlx::query("insert into scheduled_run_result_artifacts (artifact_id, run_id, job_id, accepted_attempt, accepted_fence, schema_version, result_json, hash_algorithm, result_hash, previous_success_context, completed_at) values ('schema-999', ?1, ?2, ?3, ?4, 999, '{}', 'sha256-v1', 'schema-999', 'summary', 119)")
          .bind(claim.binding.run_id())
          .bind(claim.binding.job_id())
          .bind(claim.binding.attempt())
          .bind(claim.binding.fence())
          .execute(&pool)
          .await
          .is_err()
      );
    }
    if ordinal == 2 {
      continue;
    }
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
  sqlx::query("drop trigger trg_scheduled_run_result_artifacts_acceptance")
    .execute(&pool)
    .await
    .expect("simulate immediate-parent schema artifact");
  sqlx::query("insert into scheduled_run_result_artifacts (artifact_id, run_id, job_id, accepted_attempt, accepted_fence, schema_version, result_json, hash_algorithm, result_hash, previous_success_context, completed_at, provenance, provenance_version) values ('schema-existing', ?1, ?2, ?3, ?4, 999, '{}', 'sha256-v1', 'schema-existing', 'summary', 120, 'native', 1)")
    .bind(claims[2].binding.run_id())
    .bind(claims[2].binding.job_id())
    .bind(claims[2].binding.attempt())
    .bind(claims[2].binding.fence())
    .execute(&pool)
    .await
    .expect("seed immediate-parent schema artifact");
  assert!(
    sqlx::query(
      "update scheduled_runs set result_artifact_id = 'schema-existing' where run_id = ?1"
    )
    .bind(claims[2].binding.run_id())
    .execute(&pool)
    .await
    .is_err()
  );
  sqlx::query("update scheduled_run_attempts set state = 'succeeded', completed_at = 120 where run_id = ?1 and attempt = ?2")
    .bind(claims[2].binding.run_id())
    .bind(claims[2].binding.attempt())
    .execute(&pool)
    .await
    .expect("complete schema test attempt");
  assert!(
    sqlx::query("update scheduled_runs set state = 'succeeded', overlap_slot = null, lease_owner = null, lease_expires_at = null, result_artifact_id = 'schema-existing', result_context = 'summary', result_hash_algorithm = 'sha256-v1', result_hash = 'schema-existing' where run_id = ?1")
      .bind(claims[2].binding.run_id())
      .execute(&pool)
      .await
      .is_err()
  );
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
