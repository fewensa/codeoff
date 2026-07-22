use std::fmt::Write as _;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use codeoff_state::{
  AcceptedDeliveryBaselineIdentity, AttestedExecutionProfileSnapshot, CapabilityProfileSnapshot,
  ClaimedScheduledDelivery, ClaimedScheduledRun, CreateScheduledJob, DeliveryTargetSnapshot,
  ExpiredRunReclaimOutcome, LateEvidenceAppendOutcome, MaterializationOutcome, OccurrenceError,
  PreflightFailureDisposition, PreparedScheduledDelivery, PrincipalKey,
  ScheduleMutationIdempotency, ScheduleSpec, ScheduledDeliveryFailure, ScheduledDeliveryState,
  ScheduledDeliveryUnknownAction, ScheduledDeliveryWork, ScheduledExecutionDisposition,
  ScheduledExecutionTerminal, ScheduledJobDefinition, ScheduledJobMutation, ScheduledJobStatus,
  ScheduledPrepareAuthority, ScheduledRunExecutionOutcome, ScheduledRunLateEvidenceKind,
  ScheduledRunResult, ScheduledRunState, ScheduledRunSuccessOutcome,
  SchedulerOperatorMutationOutcome, SchedulerOperatorRequest, SkippedNoneBaselinePolicy,
  StateError, StateStore, StateValueError, TransactionalMutationOutcome, TransportConvergence,
  UpdateScheduledJob,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::Row;
use sqlx::SqlitePool;
use sqlx::migrate::Migrator;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use tempfile::tempdir;
use tokio::sync::Barrier;

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
type LegacyDeliveryRow = (
  String,
  String,
  Option<String>,
  Option<String>,
  Option<String>,
  Option<Vec<u8>>,
);
type QuarantinedDeliveryRow = (
  String,
  String,
  String,
  Option<String>,
  Option<String>,
  Option<Vec<u8>>,
  Option<i64>,
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

fn operator_provider_receipt(
  provider: &str,
  tenant: &str,
  target_kind: &str,
  conversation_id: &str,
  message_id: &str,
) -> String {
  json!({
    "conversation_id": conversation_id,
    "message_id": message_id,
    "provider": provider,
    "receipt_version": 1,
    "target_kind": target_kind,
    "tenant": tenant,
    "thread_id": null,
  })
  .to_string()
}

fn operator_delivery_evidence(
  kind: &str,
  evidence_id: &str,
  provider: &str,
  tenant: &str,
  target_kind: &str,
  provider_receipt: Option<&str>,
) -> (String, String) {
  let evidence = if let Some(provider_receipt) = provider_receipt {
    json!({
      "evidence_id": evidence_id,
      "evidence_version": 1,
      "kind": kind,
      "provider": provider,
      "receipt_digest": test_sha256_hex(provider_receipt),
      "target_kind": target_kind,
      "tenant": tenant,
    })
  } else {
    json!({
      "evidence_id": evidence_id,
      "evidence_version": 1,
      "kind": kind,
      "provider": provider,
      "target_kind": target_kind,
      "tenant": tenant,
    })
  }
  .to_string();
  let digest = test_sha256_hex(&evidence);
  (evidence, digest)
}

fn recovery_capability_profile_json() -> String {
  let tools = json!(["issue_read", "list_issues", "search_issues", "search_orgs"]);
  let canonical = json!({
    "app_server_schema_sha256": "1".repeat(64),
    "codex_program_sha256": "2".repeat(64),
    "codex_version": "test-codex",
    "config_revision": "test-config-v1",
    "config_sha256": "3".repeat(64),
    "credential_deny_policy_revision": "test-deny-v1",
    "credential_isolation_revision": "test-isolation-v1",
    "credential_reference": "test-read-only-credential",
    "github_mcp_artifact_sha256": "4".repeat(64),
    "github_mcp_endpoint_identity": "test-github-mcp",
    "github_mcp_version": "test-mcp",
    "github_tools": tools,
    "negative_test_revision": "test-negative-v1",
    "output_schema_revision": "test-output-v1",
    "permission_policy_revision": "test-read-only-v1",
  });
  let profile_sha256 = test_sha256_hex(&canonical.to_string());
  json!({
    "app_server_schema_sha256": "1".repeat(64),
    "attested_at_unix_seconds": 100,
    "codex_program_sha256": "2".repeat(64),
    "codex_version": "test-codex",
    "config_revision": "test-config-v1",
    "config_sha256": "3".repeat(64),
    "credential_deny_policy_revision": "test-deny-v1",
    "credential_isolation_revision": "test-isolation-v1",
    "credential_reference": "test-read-only-credential",
    "github_mcp_artifact_sha256": "4".repeat(64),
    "github_mcp_endpoint_identity": "test-github-mcp",
    "github_mcp_version": "test-mcp",
    "github_tools": ["issue_read", "list_issues", "search_issues", "search_orgs"],
    "negative_test_revision": "test-negative-v1",
    "output_schema_revision": "test-output-v1",
    "permission_policy_revision": "test-read-only-v1",
    "profile_sha256": profile_sha256,
  })
  .to_string()
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
  assert!(ScheduledDeliveryState::from_str("intent").is_err());
  assert_eq!(
    ScheduledDeliveryState::from_str("failed_retryable").expect("frozen state"),
    ScheduledDeliveryState::FailedRetryable
  );
  assert_eq!(
    ScheduledDeliveryState::from_str("skipped_unchanged").expect("frozen state"),
    ScheduledDeliveryState::SkippedUnchanged
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
    "scheduled_delivery_legacy_baseline_audit",
    "scheduled_delivery_retention_audit",
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
          | "20260722000000_scheduler_delivery_authority.sql"
          | "20260722010000_scheduler_delivery_readiness.sql"
          | "20260722020000_scheduler_operator.sql"
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
      && entry.file_name() != "20260722000000_scheduler_delivery_authority.sql"
      && entry.file_name() != "20260722010000_scheduler_delivery_readiness.sql"
      && entry.file_name() != "20260722020000_scheduler_operator.sql"
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
      && entry.file_name() != "20260722000000_scheduler_delivery_authority.sql"
      && entry.file_name() != "20260722010000_scheduler_delivery_readiness.sql"
      && entry.file_name() != "20260722020000_scheduler_operator.sql"
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
async fn test_delivery_authority_migration_quarantines_unverifiable_issue_06_payload() {
  let temp = tempdir().expect("create tempdir");
  let parent_migrations = temp.path().join("issue-06-migrations");
  std::fs::create_dir(&parent_migrations).expect("create migration fixture");
  let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
  for entry in std::fs::read_dir(source).expect("read migrations") {
    let entry = entry.expect("migration entry");
    if entry.file_name() != "20260722000000_scheduler_delivery_authority.sql"
      && entry.file_name() != "20260722010000_scheduler_delivery_readiness.sql"
      && entry.file_name() != "20260722020000_scheduler_operator.sql"
    {
      std::fs::copy(entry.path(), parent_migrations.join(entry.file_name()))
        .expect("copy issue-06 migration");
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
    .expect("connect issue-06 database");
  Migrator::new(parent_migrations)
    .await
    .expect("load issue-06 migrator")
    .run(&pool)
    .await
    .expect("run issue-06 migrations");
  sqlx::query("insert into scheduled_jobs (job_id, definition_version, definition_json, creator_kind, creator_provider, creator_tenant, creator_subject, owner_kind, owner_provider, owner_tenant, owner_subject, status, generation, capability_schema_version, capability_digest, capability_json, created_at, updated_at) values ('issue-06-payload', 1, '{}', 'user', 'test', 'tenant', 'creator', 'user', 'test', 'tenant', 'owner', 'active', 0, 1, 'profile', '{}', 100, 100)")
    .execute(&pool)
    .await
    .expect("seed job");
  sqlx::query("insert into schedules (schedule_id, job_id, kind, canonical_spec, once_at, next_run_at, created_at, updated_at) values ('schedule-issue-06-payload', 'issue-06-payload', 'once', '200', 200, 200, 100, 100)")
    .execute(&pool)
    .await
    .expect("seed schedule");
  sqlx::query("insert into scheduled_execution_baselines (job_id) values ('issue-06-payload')")
    .execute(&pool)
    .await
    .expect("seed execution baseline");
  sqlx::query("insert into scheduled_runs (run_id, job_id, schedule_id, job_generation, schedule_generation, scheduled_for, coalesced_through, definition_version, definition_json, capability_schema_version, capability_digest, capability_json, targets_json, state, overlap_slot, created_at, updated_at) values ('issue-06-payload-run', 'issue-06-payload', 'schedule-issue-06-payload', 0, 0, 110, 110, 1, '{}', 1, 'profile', '{}', '[{\"identity_digest\":\"0000000000000000000000000000000000000000000000000000000000000002\"}]', 'pending', 1, 100, 100)")
    .execute(&pool)
    .await
    .expect("seed run");
  let issue_06_target = format!(
    r#"{{"provider":"slack","connector":"slack-primary","tenant":"workspace","kind":"channel","address":{{"channel_id":"C1"}},"resolver_digest":"resolver-v1","identity_digest":"{SLACK_TARGET_IDENTITY}"}}"#,
  );
  let issue_06_targets = format!("[{issue_06_target}]");
  sqlx::query("update scheduled_runs set targets_json = ?1, state = 'leased', attempt = 1, fence = 1, lease_owner = 'issue-06-worker', lease_expires_at = 300, updated_at = 101 where run_id = 'issue-06-payload-run'")
    .bind(&issue_06_targets)
    .execute(&pool)
    .await
    .expect("claim issue-06 run");
  sqlx::query("insert into scheduled_run_attempts (run_id, job_id, attempt, fence, lease_owner, state, claimed_at, lease_expires_at) values ('issue-06-payload-run', 'issue-06-payload', 1, 1, 'issue-06-worker', 'leased', 101, 300)")
    .execute(&pool)
    .await
    .expect("seed issue-06 attempt");
  sqlx::query("update scheduled_runs set state = 'executing', updated_at = 102 where run_id = 'issue-06-payload-run'")
    .execute(&pool)
    .await
    .expect("execute issue-06 run");
  sqlx::query("update scheduled_run_attempts set state = 'executing', preflight_completed_at = 102, executing_at = 102, attested_profile_schema_version = 1, attested_profile_json = '{}', attested_profile_hash_algorithm = 'sha256-v1', attested_profile_digest = 'profile' where run_id = 'issue-06-payload-run' and attempt = 1")
    .execute(&pool)
    .await
    .expect("attest issue-06 attempt");
  sqlx::query("insert into scheduled_run_result_artifacts (artifact_id, run_id, job_id, accepted_attempt, accepted_fence, schema_version, result_json, hash_algorithm, result_hash, previous_success_context, completed_at, provenance, provenance_version) values ('issue-06-result', 'issue-06-payload-run', 'issue-06-payload', 1, 1, 1, '{}', 'sha256-v1', 'result', '', 103, 'native', 1)")
    .execute(&pool)
    .await
    .expect("seed issue-06 result artifact");
  let intent_key = test_intent_key("issue-06-payload-run", SLACK_TARGET_IDENTITY);
  let intent_delivery_id = format!("intent:{intent_key}");
  let target_snapshot_digest = test_sha256_hex(&issue_06_target);
  sqlx::query("insert into scheduled_run_deliveries (delivery_id, run_id, job_id, target_identity_digest, target_json, state, attempt, fence, delivery_policy_version, result_artifact_id, result_attempt, result_fence, target_snapshot_digest_algorithm, target_snapshot_digest, intent_key, authority_kind, created_at, updated_at) values (?1, 'issue-06-payload-run', 'issue-06-payload', ?2, ?3, 'intent', 0, 0, 1, 'issue-06-result', 1, 1, 'sha256-v1', ?4, ?5, 'intent_v1', 103, 103)")
    .bind(&intent_delivery_id)
    .bind(SLACK_TARGET_IDENTITY)
    .bind(&issue_06_target)
    .bind(&target_snapshot_digest)
    .bind(&intent_key)
    .execute(&pool)
    .await
    .expect("seed unrendered issue-06 intent");
  let exact_legacy_bytes = "Cafe\u{301}  \n".as_bytes();
  let issue_06_claimed_digest = test_sha256_hex("Cafe\u{301}  \n");
  sqlx::query("update scheduled_run_deliveries set state = 'pending', render_version = 1, hash_algorithm = 'sha256-v1', payload_digest = ?1, payload_snapshot = ?2, expected_baseline_version = 0, updated_at = 104 where delivery_id = ?3")
    .bind(&issue_06_claimed_digest)
    .bind(exact_legacy_bytes)
    .bind(&intent_delivery_id)
    .execute(&pool)
    .await
    .expect("enrich issue-06 intent without resolver version");
  sqlx::query("insert into scheduled_run_deliveries (delivery_id, run_id, job_id, target_identity_digest, target_json, state, delivery_policy_version, render_version, hash_algorithm, payload_digest, payload_snapshot, expected_baseline_version, created_at, updated_at) values ('legacy-rendered', 'issue-06-payload-run', 'issue-06-payload', '0000000000000000000000000000000000000000000000000000000000000002', '{\"kind\":\"slack\"}', 'pending', 1, 1, 'legacy-unconstrained', 'not-a-sha256', ?1, 0, 100, 101)")
    .bind(exact_legacy_bytes)
    .execute(&pool)
    .await
    .expect("seed rendered issue-06 payload");
  let delivered_identity = "0000000000000000000000000000000000000000000000000000000000000003";
  sqlx::query("insert into scheduled_run_deliveries (delivery_id, run_id, job_id, target_identity_digest, target_json, state, delivery_policy_version, render_version, hash_algorithm, payload_digest, payload_snapshot, expected_baseline_version, provider_receipt, created_at, updated_at) values ('legacy-delivered-rendered', 'issue-06-payload-run', 'issue-06-payload', ?1, '{\"kind\":\"slack\"}', 'delivered', 1, 1, 'sha256-utf8-exact-v1', ?2, ?3, 0, 'legacy-receipt', 100, 105)")
    .bind(delivered_identity)
    .bind(&issue_06_claimed_digest)
    .bind(exact_legacy_bytes)
    .execute(&pool)
    .await
    .expect("seed delivered legacy payload with unverified exact claim");
  pool.close().await;

  StateStore::initialize(&state_dir, None)
    .await
    .expect("upgrade issue-06 database");
  StateStore::initialize(&state_dir, None)
    .await
    .expect("repeat forward-only initialization");
  let pool = SqlitePool::connect(&database_url(&state_dir))
    .await
    .expect("connect upgraded database");
  let authority: QuarantinedDeliveryRow = sqlx::query_as(
    "select state, provider_outcome, error_kind, hash_algorithm, payload_digest, payload_snapshot, target_snapshot_version from scheduled_run_deliveries where delivery_id = 'legacy-rendered'",
  )
  .fetch_one(&pool)
  .await
  .expect("read quarantined authority");
  assert_eq!(authority.0, "failed_terminal");
  assert_eq!(authority.1, "confirmed_no_write_terminal");
  assert_eq!(authority.2, "legacy_payload_digest_unverified");
  assert!(authority.3.is_none());
  assert!(authority.4.is_none());
  assert!(authority.5.is_none());
  assert!(authority.6.is_none());
  let quarantined_intent: QuarantinedDeliveryRow = sqlx::query_as(
    "select state, provider_outcome, error_kind, hash_algorithm, payload_digest, payload_snapshot, target_snapshot_version from scheduled_run_deliveries where delivery_id = ?1",
  )
  .bind(&intent_delivery_id)
  .fetch_one(&pool)
  .await
  .expect("read quarantined issue-06 intent");
  assert_eq!(quarantined_intent.0, "failed_terminal");
  assert_eq!(quarantined_intent.1, "confirmed_no_write_terminal");
  assert_eq!(quarantined_intent.2, "legacy_payload_digest_unverified");
  assert!(quarantined_intent.3.is_none());
  assert!(quarantined_intent.4.is_none());
  assert!(quarantined_intent.5.is_none());
  assert!(quarantined_intent.6.is_none());
  let delivered_legacy: (String, String, Option<String>, Option<String>, Option<Vec<u8>>) =
    sqlx::query_as(
      "select state, provider_outcome, hash_algorithm, payload_digest, payload_snapshot from scheduled_run_deliveries where delivery_id = 'legacy-delivered-rendered'",
    )
    .fetch_one(&pool)
    .await
    .expect("read delivered legacy quarantine");
  assert_eq!(delivered_legacy.0, "delivered");
  assert_eq!(delivered_legacy.1, "confirmed_success");
  assert!(delivered_legacy.2.is_none());
  assert!(delivered_legacy.3.is_none());
  assert!(delivered_legacy.4.is_none());
  let falsely_relabelled: i64 = sqlx::query_scalar(
    "select count(*) from scheduled_run_deliveries where hash_algorithm = 'sha256-utf8-exact-v1'",
  )
  .fetch_one(&pool)
  .await
  .expect("scan false exact-digest labels");
  assert_eq!(falsely_relabelled, 0);
  let migration_count: i64 = sqlx::query_scalar(
    "select count(*) from _sqlx_migrations where version = 20260722000000 and success = true",
  )
  .fetch_one(&pool)
  .await
  .expect("read migration ledger");
  assert_eq!(migration_count, 1);
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn test_delivery_authority_migration_conservatively_maps_legacy_states_and_baselines() {
  let temp = tempdir().expect("create tempdir");
  let parent_migrations = temp.path().join("parent-migrations");
  std::fs::create_dir(&parent_migrations).expect("create migration fixture");
  let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
  for entry in std::fs::read_dir(source).expect("read migrations") {
    let entry = entry.expect("migration entry");
    if entry.file_name() != "20260721040000_scheduler_delivery_intents.sql"
      && entry.file_name() != "20260722000000_scheduler_delivery_authority.sql"
      && entry.file_name() != "20260722010000_scheduler_delivery_readiness.sql"
      && entry.file_name() != "20260722020000_scheduler_operator.sql"
    {
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
  sqlx::query("insert into scheduled_job_delivery_targets (target_id, job_id, ordinal, provider, connector, tenant, kind, address_json, resolver_version, resolver_digest, identity_digest) values ('target-delivery-upgrade', 'delivery-upgrade', 0, 'slack', 'slack-primary', 'workspace', 'channel', '{\"channel_id\":\"C1\"}', 1, 'resolver-v1', ?1)")
    .bind(SLACK_TARGET_IDENTITY)
    .execute(&pool)
    .await
    .expect("seed supported target");
  sqlx::query("insert into scheduled_runs (run_id, job_id, schedule_id, job_generation, schedule_generation, scheduled_for, coalesced_through, definition_version, definition_json, capability_schema_version, capability_digest, capability_json, targets_json, execution_baseline_json, state, overlap_slot, created_at, updated_at) values ('delivery-upgrade-run', 'delivery-upgrade', 'schedule-delivery-upgrade', 0, 0, 110, 110, 1, '{}', 1, 'profile', '{}', '[{\"identity_digest\":\"0000000000000000000000000000000000000000000000000000000000000002\"}]', '{\"baseline_version\":0,\"completed_at\":null,\"hash_algorithm\":null,\"previous_success_context\":null,\"result_hash\":null,\"source_run_id\":null}', 'pending', 1, 100, 100)")
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
      .bind(if state == "delivered" {
        SLACK_TARGET_IDENTITY.to_owned()
      } else {
        format!("identity-{state}")
      })
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
  let legacy_exact_body = "legacy exact payload  \n";
  let legacy_claimed_digest = test_sha256_hex(legacy_exact_body);
  sqlx::query("insert into scheduled_delivery_baselines (job_id, target_identity_digest, delivery_policy_version, render_version, hash_algorithm, accepted_payload_digest, source_delivery_id, source_run_id, source_result_hash, accepted_at, baseline_version) values ('delivery-upgrade', ?1, 1, 1, 'sha256-utf8-exact-v1', ?2, 'legacy-delivered', 'delivery-upgrade-run', 'result', -1, 3)")
    .bind(SLACK_TARGET_IDENTITY)
    .bind(&legacy_claimed_digest)
    .execute(&pool)
    .await
    .expect("seed delivery baseline");
  pool.close().await;

  let upgraded = StateStore::initialize(&state_dir, None)
    .await
    .expect("upgrade delivery schema");
  StateStore::initialize(&state_dir, None)
    .await
    .expect("repeat upgraded initialize");
  let pool = SqlitePool::connect(&database_url(&state_dir))
    .await
    .expect("connect upgraded database");
  let rows: Vec<LegacyDeliveryRow> = sqlx::query_as(
    "select delivery_id, state, provider_outcome, error_kind, lease_owner, payload_snapshot from scheduled_run_deliveries order by delivery_id",
  )
  .fetch_all(&pool)
  .await
  .expect("read upgraded deliveries");
  assert_eq!(rows.len(), 7);
  assert_eq!(rows[0].0, "legacy-delivered");
  assert_eq!(
    (&rows[0].1, rows[0].2.as_deref()),
    (&"delivered".to_owned(), Some("confirmed_success"))
  );
  for row in [&rows[1], &rows[2], &rows[5]] {
    assert_eq!(row.1, "delivery_unknown");
    assert_eq!(row.2.as_deref(), Some("ambiguous_post_write"));
    assert!(row.3.is_some());
  }
  for row in [&rows[3], &rows[4], &rows[6]] {
    assert_eq!(row.1, "failed_terminal");
    assert_eq!(row.2.as_deref(), Some("confirmed_no_write_terminal"));
    assert!(row.3.is_some());
  }
  assert!(rows.iter().all(|row| row.4.is_none() && row.5.is_none()));
  let active_baselines: i64 = sqlx::query_scalar(
    "select count(*) from scheduled_delivery_baselines where job_id = 'delivery-upgrade'",
  )
  .fetch_one(&pool)
  .await
  .expect("count active baselines");
  assert_eq!(active_baselines, 0);
  let baseline: (String, String, String, String, i64, i64) = sqlx::query_as(
    "select source_delivery_id, claimed_payload_digest, claimed_hash_algorithm, quarantine_reason, claimed_baseline_version, accepted_at from scheduled_delivery_legacy_baseline_audit where job_id = 'delivery-upgrade'",
  )
  .fetch_one(&pool)
  .await
  .expect("read quarantined baseline");
  assert_eq!(
    baseline,
    (
      "legacy-delivered".to_owned(),
      legacy_claimed_digest,
      "sha256-utf8-exact-v1".to_owned(),
      "pre_authority_baseline_unverified".to_owned(),
      3,
      -1
    )
  );
  assert_eq!(
    upgraded
      .pause_scheduled_job("delivery-upgrade", 0, 150)
      .await
      .expect("pause legacy pending run"),
    1
  );
  assert_eq!(
    upgraded
      .resume_scheduled_job("delivery-upgrade", 1, 151)
      .await
      .expect("resume upgraded job"),
    2
  );
  let MaterializationOutcome::Created(post_upgrade_run) = upgraded
    .materialize_due_schedule("delivery-upgrade", 2, 200)
    .await
    .expect("materialize post-upgrade run")
  else {
    panic!("post-upgrade run must materialize");
  };
  let post_upgrade_claim = upgraded
    .claim_next_scheduled_run("post-upgrade-worker", 201, 300)
    .await
    .expect("claim post-upgrade run")
    .expect("post-upgrade claim");
  let profile =
    AttestedExecutionProfileSnapshot::new(1, "{}", "sha256-v1", "profile").expect("profile");
  upgraded
    .mark_scheduled_run_executing(&post_upgrade_claim.binding, &profile, 202)
    .await
    .expect("execute post-upgrade run");
  upgraded
    .complete_scheduled_run_success(
      &post_upgrade_claim.binding,
      &ScheduledRunResult::new("post-upgrade", "").expect("result"),
      203,
    )
    .await
    .expect("complete post-upgrade run");
  let post_upgrade_delivery: String =
    sqlx::query_scalar("select delivery_id from scheduled_run_deliveries where run_id = ?1")
      .bind(&post_upgrade_run.run_id)
      .fetch_one(&pool)
      .await
      .expect("post-upgrade delivery");
  assert!(matches!(
    upgraded
      .prepare_scheduled_delivery(
        &post_upgrade_delivery,
        "text/plain; charset=utf-8",
        legacy_exact_body,
        1,
        204,
        SkippedNoneBaselinePolicy::DoNotAdvance,
      )
      .await
      .expect("prepare first exact post-upgrade payload"),
    PreparedScheduledDelivery::Pending(_)
  ));
  assert!(
    upgraded
      .claim_next_scheduled_delivery("post-upgrade-delivery", 205, 300)
      .await
      .expect("claim first exact post-upgrade payload")
      .is_some(),
    "quarantined legacy baseline must never suppress the first exact payload"
  );
  let foreign_key_errors: i64 = sqlx::query_scalar("select count(*) from pragma_foreign_key_check")
    .fetch_one(&pool)
    .await
    .expect("check upgraded foreign keys");
  assert_eq!(foreign_key_errors, 0);
  let migration_applied: i64 = sqlx::query_scalar(
    "select count(*) from _sqlx_migrations where version in (20260721040000, 20260722000000) and success = true",
  )
  .fetch_one(&pool)
  .await
  .expect("read migration state");
  assert_eq!(migration_applied, 2);
}

#[tokio::test]
async fn test_delivery_intent_migration_rolls_back_on_invalid_parent_foreign_key() {
  let temp = tempdir().expect("create tempdir");
  let parent_migrations = temp.path().join("parent-migrations");
  std::fs::create_dir(&parent_migrations).expect("create migration fixture");
  let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
  for entry in std::fs::read_dir(source).expect("read migrations") {
    let entry = entry.expect("migration entry");
    if entry.file_name() != "20260721040000_scheduler_delivery_intents.sql"
      && entry.file_name() != "20260722000000_scheduler_delivery_authority.sql"
      && entry.file_name() != "20260722010000_scheduler_delivery_readiness.sql"
      && entry.file_name() != "20260722020000_scheduler_operator.sql"
    {
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
    if entry.file_name() != "20260721040000_scheduler_delivery_intents.sql"
      && entry.file_name() != "20260722000000_scheduler_delivery_authority.sql"
      && entry.file_name() != "20260722010000_scheduler_delivery_readiness.sql"
      && entry.file_name() != "20260722020000_scheduler_operator.sql"
    {
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
    if entry.file_name() != "20260721040000_scheduler_delivery_intents.sql"
      && entry.file_name() != "20260722000000_scheduler_delivery_authority.sql"
      && entry.file_name() != "20260722010000_scheduler_delivery_readiness.sql"
      && entry.file_name() != "20260722020000_scheduler_operator.sql"
    {
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
async fn test_recovery_attestation_fails_closed_for_legacy_tampered_and_stale_profiles() {
  let temp = tempdir().expect("create tempdir");
  let store = StateStore::initialize(&temp.path().join("state"), None)
    .await
    .expect("initialize state store");
  for (job_id, scheduled_for) in [("recovery-profile-a", 110), ("recovery-profile-b", 111)] {
    let mut request = create_request(job_id, ScheduleSpec::once(scheduled_for), 100);
    request.definition = ScheduledJobDefinition::new(
      1,
      format!(
        r#"{{"instruction":"execute {job_id}","previous_success":{{"kind":"none"}},"schema_version":1}}"#
      ),
    )
    .expect("definition");
    store
      .create_scheduled_job(&request)
      .await
      .expect("create job");
    store
      .materialize_due_schedule(job_id, 0, scheduled_for)
      .await
      .expect("materialize");
  }
  let first = store
    .claim_next_scheduled_run("worker-a", 112, 150)
    .await
    .expect("claim first")
    .expect("first run");
  let second = store
    .claim_next_scheduled_run("worker-b", 112, 150)
    .await
    .expect("claim second")
    .expect("second run");
  let first_authority =
    ScheduledPrepareAuthority::for_claim(&first, "a".repeat(64)).expect("first authority");
  let second_authority =
    ScheduledPrepareAuthority::for_claim(&second, "b".repeat(64)).expect("second authority");
  let valid = first_authority
    .recovery_attestation_json(&recovery_capability_profile_json())
    .expect("valid recovery profile");
  let valid_digest = test_sha256_hex(&valid);
  assert!(first_authority.recovery_attestation_matches(&valid, &valid_digest));
  assert!(!second_authority.recovery_attestation_matches(&valid, &valid_digest));
  assert!(!first_authority.recovery_attestation_matches(
    &first_authority.attestation_json(true),
    &test_sha256_hex(&first_authority.attestation_json(true)),
  ));
  assert!(!first_authority.recovery_attestation_matches(&valid, &"0".repeat(64)));

  let mut tampered: serde_json::Value = serde_json::from_str(&valid).expect("profile json");
  tampered["execution_surface"]["network_access"] = json!(true);
  let tampered = tampered.to_string();
  assert!(!first_authority.recovery_attestation_matches(&tampered, &test_sha256_hex(&tampered),));
  let mut incomplete: serde_json::Value = serde_json::from_str(&valid).expect("profile json");
  incomplete["capability_profile"]
    .as_object_mut()
    .expect("capability object")
    .remove("github_tools");
  let incomplete = incomplete.to_string();
  assert!(
    !first_authority.recovery_attestation_matches(&incomplete, &test_sha256_hex(&incomplete),)
  );
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
    assert_eq!(intent.0, "pending");
    assert_eq!(intent.1, "intent_v1");
    assert_eq!((intent.3, intent.4, intent.5), (0, 0, 1));
    assert_eq!((intent.6, intent.7, intent.8), (None, None, None));
    assert_eq!(intent.9, "sha256-v1");
  }
  let delivery_id: String = sqlx::query_scalar(
    "select delivery_id from scheduled_run_deliveries where run_id = ?1 and target_identity_digest = ?2",
  )
  .bind(claim.binding.run_id())
  .bind(SLACK_TARGET_IDENTITY)
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
  let PreparedScheduledDelivery::Pending(_) = store
    .prepare_scheduled_delivery(
      &delivery_id,
      "text/plain; charset=utf-8",
      "rendered payload",
      1,
      121,
      SkippedNoneBaselinePolicy::DoNotAdvance,
    )
    .await
    .expect("enrich intent exactly once")
  else {
    panic!("Slack delivery must remain pending");
  };
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
      "insert into scheduled_run_deliveries (delivery_id, run_id, job_id, target_identity_digest, target_json, state, attempt, fence, delivery_policy_version, result_artifact_id, result_attempt, result_fence, target_snapshot_digest_algorithm, target_snapshot_digest, intent_key, authority_kind, created_at, updated_at) values (?1, ?2, ?3, ?4, ?5, 'pending', 0, 0, 1, ?6, ?7, ?8, ?9, ?10, ?11, 'intent_v1', 114, 114)",
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
      "insert into scheduled_run_deliveries (delivery_id, run_id, job_id, target_identity_digest, target_json, state, attempt, fence, delivery_policy_version, result_artifact_id, result_attempt, result_fence, target_snapshot_digest_algorithm, target_snapshot_digest, intent_key, authority_kind, created_at, updated_at) values (?1, ?2, ?3, ?4, ?5, 'pending', 0, 0, ?6, ?7, ?8, ?9, 'sha256-v1', ?10, ?11, 'intent_v1', 114, 114)",
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
    "insert into scheduled_run_deliveries (delivery_id, run_id, job_id, target_identity_digest, target_json, state, attempt, fence, delivery_policy_version, result_artifact_id, result_attempt, result_fence, target_snapshot_digest_algorithm, target_snapshot_digest, intent_key, authority_kind, created_at, updated_at) values (?1, ?2, ?3, ?4, ?5, 'pending', 0, 0, 1, ?6, ?7, ?8, 'sha256-v1', ?9, ?10, 'intent_v1', 114, 114)",
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
    "insert into scheduled_run_deliveries (delivery_id, run_id, job_id, target_identity_digest, target_json, state, delivery_policy_version, created_at, updated_at) values (?1, ?2, ?3, 'legacy-identity', '{}', 'pending', 1, 115, 115)",
  )
  .bind(legacy_delivery_id)
  .bind(claim.binding.run_id())
  .bind(job_id)
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
      "insert or replace into scheduled_run_deliveries (delivery_id, run_id, job_id, target_identity_digest, target_json, state, delivery_policy_version, created_at, updated_at) values (?1, ?2, ?3, 'legacy-replacement', '{}', 'pending', 1, 115, 115)"
    )
    .bind(&natural_delivery_id)
    .bind(claim.binding.run_id())
    .bind(job_id)
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
        sqlx::query("insert into scheduled_run_deliveries (delivery_id, run_id, job_id, target_identity_digest, target_json, state, delivery_policy_version, created_at, updated_at) values (?1, ?2, ?3, 'collision', '{}', 'pending', 1, 119, 119)")
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

async fn complete_due_run(
  store: &StateStore,
  job_id: &str,
  due_at: i64,
  completed_at: i64,
) -> ClaimedScheduledRun {
  store
    .materialize_due_schedule(job_id, 0, due_at)
    .await
    .expect("materialize occurrence");
  let claim = store
    .claim_next_scheduled_run("occurrence-worker", completed_at - 2, completed_at + 100)
    .await
    .expect("claim occurrence")
    .expect("due occurrence");
  let profile =
    AttestedExecutionProfileSnapshot::new(1, "{}", "sha256-v1", "profile").expect("profile");
  store
    .mark_scheduled_run_executing(&claim.binding, &profile, completed_at - 1)
    .await
    .expect("execute occurrence");
  store
    .complete_scheduled_run_success(
      &claim.binding,
      &ScheduledRunResult::new(format!("result-{completed_at}"), "").expect("result"),
      completed_at,
    )
    .await
    .expect("complete occurrence");
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
    1,
    "unexpected reclaim outcomes: {outcomes:?}",
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
async fn test_expired_safe_executing_run_has_one_reclaimer_and_stale_completion_is_evidence() {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state");
  let first = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize first store");
  let second = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize second store");
  let mut request = create_request("safe-executing-reclaim", ScheduleSpec::once(110), 100);
  request.definition = ScheduledJobDefinition::new(
    1,
    r#"{"instruction":"check issues","previous_success":{"kind":"none"},"schema_version":1}"#,
  )
  .expect("execution definition");
  first
    .create_scheduled_job(&request)
    .await
    .expect("create job");
  first
    .materialize_due_schedule("safe-executing-reclaim", 0, 110)
    .await
    .expect("materialize");
  let stale = first
    .claim_next_scheduled_run("worker-a", 111, 120)
    .await
    .expect("claim")
    .expect("claimed run");
  let authority = ScheduledPrepareAuthority::for_claim(&stale, "8".repeat(64)).expect("authority");
  let attestation = authority
    .recovery_attestation_json(&recovery_capability_profile_json())
    .expect("complete recovery attestation");
  assert!(authority.recovery_attestation_matches(&attestation, &test_sha256_hex(&attestation),));
  let profile = AttestedExecutionProfileSnapshot::new(
    2,
    &attestation,
    "sha256-v1",
    test_sha256_hex(&attestation),
  )
  .expect("profile");
  first
    .mark_scheduled_run_executing(&stale.binding, &profile, 112)
    .await
    .expect("mark executing");

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
    1,
    "safe executing reclaim outcomes: {outcomes:?}",
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

  let store = StateStore::initialize(&state_dir, None)
    .await
    .expect("reopen store");
  let current = store
    .claim_next_scheduled_run("worker-b", 130, 200)
    .await
    .expect("claim retry")
    .expect("retried run");
  assert_eq!(current.binding.attempt(), stale.binding.attempt() + 1);
  assert!(current.binding.fence() > stale.binding.fence());
  let result = ScheduledRunResult::new("accepted result", "context").expect("result");
  assert_eq!(
    store
      .complete_scheduled_run_success(&stale.binding, &result, 140)
      .await
      .expect("stale completion"),
    ScheduledRunSuccessOutcome::LateEvidence(LateEvidenceAppendOutcome::Recorded)
  );
  let current_authority =
    ScheduledPrepareAuthority::for_claim(&current, "9".repeat(64)).expect("current authority");
  let current_attestation = current_authority
    .recovery_attestation_json(&recovery_capability_profile_json())
    .expect("current recovery attestation");
  store
    .mark_scheduled_run_executing(
      &current.binding,
      &AttestedExecutionProfileSnapshot::new(
        2,
        &current_attestation,
        "sha256-v1",
        test_sha256_hex(&current_attestation),
      )
      .expect("current profile"),
      131,
    )
    .await
    .expect("mark current executing");
  assert_eq!(
    store
      .complete_scheduled_run_success(&current.binding, &result, 141)
      .await
      .expect("complete current"),
    ScheduledRunSuccessOutcome::Committed
  );
  let pool = SqlitePool::connect(&database_url(&state_dir))
    .await
    .expect("connect database");
  let counts: (i64, i64, i64) = sqlx::query_as(
    "select (select count(*) from scheduled_run_result_artifacts where run_id = ?1), (select count(*) from scheduled_run_late_evidence where run_id = ?1), (select count(*) from scheduled_runs where run_id = ?1 and state = 'succeeded')",
  )
  .bind(current.binding.run_id())
  .fetch_one(&pool)
  .await
  .expect("read outcome counts");
  assert_eq!(counts, (1, 1, 1));
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn test_operator_run_retry_is_conclusive_idempotent_audited_and_bounded() {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state");
  let store = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize store");
  store
    .create_scheduled_job(&create_request(
      "operator-run-retry",
      ScheduleSpec::once(110),
      100,
    ))
    .await
    .expect("create job");
  store
    .materialize_due_schedule("operator-run-retry", 0, 110)
    .await
    .expect("materialize");
  let claim = store
    .claim_next_scheduled_run("worker", 111, 150)
    .await
    .expect("claim")
    .expect("run");
  store
    .record_scheduled_run_preflight_failure(
      &claim.binding,
      PreflightFailureDisposition::Fail,
      "preflight_failed",
      "preflight failed",
      112,
    )
    .await
    .expect("terminal failure");
  let bypass_pool = SqlitePool::connect(&database_url(&state_dir))
    .await
    .expect("connect bypass database");
  assert!(
    sqlx::query(
      "update scheduled_runs set state = 'pending', next_attempt_at = 120, updated_at = 113 where run_id = ?1 and state = 'failed'",
    )
    .bind(claim.binding.run_id())
    .execute(&bypass_pool)
    .await
    .is_err(),
    "direct SQL must not bypass run operator authority"
  );
  let request = SchedulerOperatorRequest::for_run_retry(
    owner(),
    "retry-request",
    claim.binding.run_id(),
    claim.binding.attempt(),
    claim.binding.fence(),
    ScheduledRunState::Failed,
    120,
    113,
  )
  .expect("operator request");
  let stale_request = SchedulerOperatorRequest::for_run_retry(
    owner(),
    "stale-retry-request",
    claim.binding.run_id(),
    claim.binding.attempt(),
    claim.binding.fence() + 1,
    ScheduledRunState::Failed,
    120,
    113,
  )
  .expect("stale operator request");
  assert_eq!(
    store
      .operator_retry_scheduled_run(
        &stale_request,
        claim.binding.run_id(),
        claim.binding.attempt(),
        claim.binding.fence() + 1,
        120,
      )
      .await
      .expect("reject stale retry"),
    SchedulerOperatorMutationOutcome::Conflict
  );
  assert_eq!(
    store
      .operator_retry_scheduled_run(
        &request,
        claim.binding.run_id(),
        claim.binding.attempt(),
        claim.binding.fence(),
        120,
      )
      .await
      .expect("apply retry"),
    SchedulerOperatorMutationOutcome::Applied
  );
  assert_eq!(
    store
      .operator_retry_scheduled_run(
        &request,
        claim.binding.run_id(),
        claim.binding.attempt(),
        claim.binding.fence(),
        120,
      )
      .await
      .expect("replay retry"),
    SchedulerOperatorMutationOutcome::Replay
  );
  let actions = store
    .list_scheduler_operator_actions("run", claim.binding.run_id(), 10)
    .await
    .expect("list audit");
  assert_eq!(actions.len(), 1);
  assert!(actions[0].consumed);
  let mut conflicting_request = request.clone();
  conflicting_request.request_digest = "f".repeat(64);
  assert_eq!(
    store
      .operator_retry_scheduled_run(
        &conflicting_request,
        claim.binding.run_id(),
        claim.binding.attempt(),
        claim.binding.fence(),
        120,
      )
      .await
      .expect("conflicting replay"),
    SchedulerOperatorMutationOutcome::Conflict
  );
  let projections = store
    .list_scheduled_run_operator_projections(None, 10)
    .await
    .expect("list runs");
  assert_eq!(projections.len(), 1);
  assert_eq!(projections[0].state, ScheduledRunState::Pending);
  assert_eq!(projections[0].next_attempt_at, Some(120));
  assert!(
    store
      .list_scheduled_run_operator_projections(None, 101)
      .await
      .is_err()
  );

  let pool = SqlitePool::connect(&database_url(&state_dir))
    .await
    .expect("connect database");
  assert!(
    sqlx::query("update scheduler_operator_actions set action = 'retry_run'")
      .execute(&pool)
      .await
      .is_err()
  );
  assert!(
    sqlx::query("delete from scheduler_operator_actions")
      .execute(&pool)
      .await
      .is_err()
  );
  assert!(
    sqlx::query("update scheduler_operator_action_consumptions set consumed_at = consumed_at")
      .execute(&pool)
      .await
      .is_err()
  );
  assert!(
    sqlx::query("delete from scheduler_operator_action_consumptions")
      .execute(&pool)
      .await
      .is_err()
  );

  store
    .create_scheduled_job(&create_request(
      "operator-run-unknown",
      ScheduleSpec::once(130),
      100,
    ))
    .await
    .expect("create unknown job");
  store
    .materialize_due_schedule("operator-run-unknown", 0, 130)
    .await
    .expect("materialize unknown");
  let unknown = store
    .claim_next_scheduled_run("unknown-worker", 131, 140)
    .await
    .expect("claim unknown")
    .expect("unknown run");
  let profile =
    AttestedExecutionProfileSnapshot::new(1, "{}", "sha256-v1", "profile").expect("profile");
  store
    .mark_scheduled_run_executing(&unknown.binding, &profile, 132)
    .await
    .expect("execute unknown");
  assert!(matches!(
    store
      .reclaim_next_expired_scheduled_run(141, 3, 150)
      .await
      .expect("reclaim unknown"),
    ExpiredRunReclaimOutcome::OutcomeUnknown { .. }
  ));
  let invalid_unknown_request = SchedulerOperatorRequest::for_run_retry(
    owner(),
    "retry-unknown",
    unknown.binding.run_id(),
    unknown.binding.attempt(),
    unknown.binding.fence(),
    ScheduledRunState::Failed,
    150,
    142,
  )
  .expect("syntactically valid retry request");
  assert_eq!(
    store
      .operator_retry_scheduled_run(
        &invalid_unknown_request,
        unknown.binding.run_id(),
        unknown.binding.attempt(),
        unknown.binding.fence(),
        150,
      )
      .await
      .expect("reject unknown retry"),
    SchedulerOperatorMutationOutcome::Conflict
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
async fn test_skipped_none_advances_only_accepted_delivery_baseline_with_exact_payload() {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state");
  let store = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize store");
  let claim = prepare_executing_run(&store, "baselines", 200).await;
  let result = ScheduledRunResult::new("delivery body", "bounded context").expect("result");
  store
    .complete_scheduled_run_success(&claim.binding, &result, 120)
    .await
    .expect("complete run");
  let pool = SqlitePool::connect(&database_url(&state_dir))
    .await
    .expect("connect database");
  let delivery_id: String =
    sqlx::query_scalar("select delivery_id from scheduled_run_deliveries where run_id = ?1")
      .bind(claim.binding.run_id())
      .fetch_one(&pool)
      .await
      .expect("read delivery intent");
  let body = "line one\nline two  \n";
  let PreparedScheduledDelivery::SkippedNone(payload) = store
    .prepare_scheduled_delivery(
      &delivery_id,
      "text/markdown; charset=utf-8",
      body,
      1,
      121,
      SkippedNoneBaselinePolicy::Accept,
    )
    .await
    .expect("prepare none delivery")
  else {
    panic!("none target must skip without a provider");
  };
  assert_eq!(payload.body().as_bytes(), body.as_bytes());
  assert_eq!(payload.digest(), test_sha256_hex(body).as_str());
  assert!(payload.result_id().strip_prefix("result:").is_some());
  let identity = AcceptedDeliveryBaselineIdentity {
    job_id: "baselines".to_owned(),
    target_identity_digest: payload.target_identity_digest().to_owned(),
    target_snapshot_digest_algorithm: "sha256-v1".to_owned(),
    target_snapshot_digest: payload.target_snapshot_digest().to_owned(),
    delivery_policy_version: 1,
    render_version: 1,
    hash_algorithm: "sha256-utf8-exact-v1".to_owned(),
  };
  let versions: (i64, i64) = sqlx::query_as(
    "select (select baseline_version from scheduled_execution_baselines where job_id = 'baselines'), (select baseline_version from scheduled_delivery_baselines where job_id = 'baselines')",
  )
  .fetch_one(&pool)
  .await
  .expect("read baseline versions");
  assert_eq!(versions, (1, 1));
  let baseline = store
    .get_accepted_delivery_baseline(&identity)
    .await
    .expect("read accepted baseline")
    .expect("accepted baseline");
  assert_eq!(baseline.accepted_payload_digest, payload.digest());
  assert_eq!(baseline.source_delivery_id, delivery_id);
  assert_eq!(
    baseline.source_result_id.as_deref(),
    Some(payload.result_id())
  );
  let state: String =
    sqlx::query_scalar("select state from scheduled_run_deliveries where delivery_id = ?1")
      .bind(payload.delivery_id())
      .fetch_one(&pool)
      .await
      .expect("read skipped state");
  assert_eq!(state, "skipped_none");
  assert!(
    store
      .claim_next_scheduled_delivery("must-not-start-slack", 122, 150)
      .await
      .expect("claim queue")
      .is_none()
  );
}

#[tokio::test]
async fn test_schema_rejects_non_none_skipped_none_without_baseline_or_retention_authority() {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state");
  let store = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize store");
  let mut request = create_request("skipped-none-schema-guard", ScheduleSpec::once(110), 100);
  request.targets = vec![second_target("skipped-none-schema-guard")];
  store
    .create_scheduled_job(&request)
    .await
    .expect("create job");
  let run = complete_due_run(&store, "skipped-none-schema-guard", 110, 120).await;
  let pool = SqlitePool::connect(&database_url(&state_dir))
    .await
    .expect("connect database");
  let delivery_id: String =
    sqlx::query_scalar("select delivery_id from scheduled_run_deliveries where run_id = ?1")
      .bind(run.binding.run_id())
      .fetch_one(&pool)
      .await
      .expect("delivery id");
  assert!(matches!(
    store
      .prepare_scheduled_delivery(
        &delivery_id,
        "text/markdown; charset=utf-8",
        "non-none body",
        1,
        121,
        SkippedNoneBaselinePolicy::Accept,
      )
      .await
      .expect("prepare Slack delivery"),
    PreparedScheduledDelivery::Pending(_)
  ));
  let rejected = sqlx::query(
    "update scheduled_run_deliveries set state = 'skipped_none', provider_outcome = 'skipped_none', updated_at = 122 where delivery_id = ?1",
  )
  .bind(&delivery_id)
  .execute(&pool)
  .await
  .expect_err("non-none target cannot enter skipped_none");
  assert!(
    rejected
      .to_string()
      .contains("skipped none delivery requires exact none policy authority")
  );
  let authority: (String, i64, i64) = sqlx::query_as(
    "select state, (select count(*) from scheduled_delivery_baselines), (select count(*) from scheduled_delivery_retention_audit) from scheduled_run_deliveries where delivery_id = ?1",
  )
  .bind(&delivery_id)
  .fetch_one(&pool)
  .await
  .expect("unchanged authority");
  assert_eq!(authority, ("pending".to_owned(), 0, 0));
}

async fn assert_direct_readiness_rejection_is_blocked(pool: &SqlitePool, delivery_id: &str) {
  let bypass = sqlx::query(
    "update scheduled_run_deliveries set state = 'failed_terminal', provider_outcome = 'confirmed_no_write_terminal', error_kind = 'target_rejected', updated_at = 130 where delivery_id = ?1",
  )
  .bind(delivery_id)
  .execute(pool)
  .await
  .expect_err("direct terminal bypass must be rejected");
  assert!(
    bypass
      .to_string()
      .contains("readiness rejection requires exact unclaimed delivery authority")
  );
}

#[tokio::test]
async fn test_readiness_rejection_cas_terminalizes_pending_and_due_retry_without_new_attempt() {
  for (suffix, make_retryable, expected_attempts) in [("pending", false, 0), ("retryable", true, 1)]
  {
    let temp = tempdir().expect("create tempdir");
    let state_dir = temp.path().join("state");
    let store = StateStore::initialize(&state_dir, None)
      .await
      .expect("initialize store");
    let job_id = format!("readiness-rejection-{suffix}");
    let mut request = create_request(&job_id, ScheduleSpec::once(110), 100);
    request.targets = vec![second_target(&job_id)];
    store
      .create_scheduled_job(&request)
      .await
      .expect("create job");
    let run = complete_due_run(&store, &job_id, 110, 120).await;
    let pool = SqlitePool::connect(&database_url(&state_dir))
      .await
      .expect("connect database");
    let delivery_id: String =
      sqlx::query_scalar("select delivery_id from scheduled_run_deliveries where run_id = ?1")
        .bind(run.binding.run_id())
        .fetch_one(&pool)
        .await
        .expect("delivery id");
    store
      .prepare_scheduled_delivery(
        &delivery_id,
        "text/markdown; charset=utf-8",
        "body",
        1,
        121,
        SkippedNoneBaselinePolicy::DoNotAdvance,
      )
      .await
      .expect("prepare");
    if !make_retryable {
      assert_direct_readiness_rejection_is_blocked(&pool, &delivery_id).await;
    }
    if make_retryable {
      let claim = store
        .claim_next_scheduled_delivery("first-attempt", 122, 200)
        .await
        .expect("claim")
        .expect("delivery claim");
      store
        .complete_scheduled_delivery_failure(
          &claim.binding,
          &ScheduledDeliveryFailure::ConfirmedNoWriteRetryable {
            error_kind: "transient".to_owned(),
            redacted_message: None,
            next_attempt_at: 130,
          },
          123,
        )
        .await
        .expect("retryable failure");
    }
    let ScheduledDeliveryWork::ProviderRequired(authority) =
      store.peek_scheduled_delivery_work(130).await.expect("work")
    else {
      panic!("provider work must be due");
    };
    assert!(
      store
        .reject_scheduled_delivery_readiness(&authority, "target_rejected", 130,)
        .await
        .expect("reject exact authority")
    );
    assert!(
      !store
        .reject_scheduled_delivery_readiness(&authority, "target_rejected", 131,)
        .await
        .expect("stale authority is a no-op")
    );
    let final_authority: (String, i64, i64, i64) = sqlx::query_as(
      "select state, attempt, fence, (select count(*) from scheduled_delivery_attempts where delivery_id = ?1) from scheduled_run_deliveries where delivery_id = ?1",
    )
    .bind(&delivery_id)
    .fetch_one(&pool)
    .await
    .expect("authority");
    assert_eq!(
      final_authority,
      (
        "failed_terminal".to_owned(),
        expected_attempts,
        expected_attempts,
        expected_attempts,
      )
    );
  }
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn test_exact_unchanged_payload_skips_and_survives_audited_history_retention() {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state");
  let store = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize store");
  let mut request = create_request(
    "unchanged-retention",
    ScheduleSpec::fixed_interval(110, 10).expect("interval"),
    100,
  );
  request.targets = vec![second_target("unchanged-retention")];
  store
    .create_scheduled_job(&request)
    .await
    .expect("create job");
  let pool = SqlitePool::connect(&database_url(&state_dir))
    .await
    .expect("connect database");
  let exact_body = "\u{00e9}|e\u{0301}|tail  \n";

  let first_run = complete_due_run(&store, "unchanged-retention", 110, 120).await;
  let first_delivery: String =
    sqlx::query_scalar("select delivery_id from scheduled_run_deliveries where run_id = ?1")
      .bind(first_run.binding.run_id())
      .fetch_one(&pool)
      .await
      .expect("first delivery");
  let PreparedScheduledDelivery::Pending(first_payload) = store
    .prepare_scheduled_delivery(
      &first_delivery,
      "text/plain; charset=utf-8",
      exact_body,
      1,
      121,
      SkippedNoneBaselinePolicy::DoNotAdvance,
    )
    .await
    .expect("prepare first payload")
  else {
    panic!("first exact payload must be sent");
  };
  assert_eq!(first_payload.body().as_bytes(), exact_body.as_bytes());
  assert_eq!(first_payload.digest(), test_sha256_hex(exact_body));
  let first_claim = store
    .claim_next_scheduled_delivery("delivery-worker", 122, 200)
    .await
    .expect("claim first delivery")
    .expect("first delivery claim");
  store
    .complete_scheduled_delivery_delivered(&first_claim.binding, "receipt-1", 123)
    .await
    .expect("accept first delivery");
  let identity = AcceptedDeliveryBaselineIdentity {
    job_id: "unchanged-retention".to_owned(),
    target_identity_digest: first_payload.target_identity_digest().to_owned(),
    target_snapshot_digest_algorithm: "sha256-v1".to_owned(),
    target_snapshot_digest: first_payload.target_snapshot_digest().to_owned(),
    delivery_policy_version: 1,
    render_version: 1,
    hash_algorithm: "sha256-utf8-exact-v1".to_owned(),
  };

  let second_run = complete_due_run(&store, "unchanged-retention", 120, 130).await;
  let second_delivery: String =
    sqlx::query_scalar("select delivery_id from scheduled_run_deliveries where run_id = ?1")
      .bind(second_run.binding.run_id())
      .fetch_one(&pool)
      .await
      .expect("second delivery");
  let PreparedScheduledDelivery::Pending(second_payload) = store
    .prepare_scheduled_delivery(
      &second_delivery,
      "text/plain; charset=utf-8",
      exact_body,
      1,
      131,
      SkippedNoneBaselinePolicy::DoNotAdvance,
    )
    .await
    .expect("prepare unchanged payload")
  else {
    panic!("prepare is advisory and must leave exact matches pending");
  };
  assert_eq!(second_payload.digest(), first_payload.digest());
  assert!(
    store
      .claim_next_scheduled_delivery("must-skip-at-claim", 132, 200)
      .await
      .expect("claim-time unchanged decision")
      .is_none()
  );
  let skipped_authority: (String, String, i64) = sqlx::query_as(
    "select state, provider_outcome, (select count(*) from scheduled_delivery_attempts where delivery_id = ?1) from scheduled_run_deliveries where delivery_id = ?1",
  )
  .bind(&second_delivery)
  .fetch_one(&pool)
  .await
  .expect("read skipped authority");
  assert_eq!(
    skipped_authority,
    (
      "skipped_unchanged".to_owned(),
      "skipped_unchanged".to_owned(),
      0
    )
  );
  let baseline_before_retention = store
    .get_accepted_delivery_baseline(&identity)
    .await
    .expect("read baseline")
    .expect("accepted baseline");
  assert_eq!(baseline_before_retention.baseline_version, 1);
  assert_eq!(baseline_before_retention.source_delivery_id, first_delivery);
  assert!(
    sqlx::query("delete from scheduled_run_deliveries where delivery_id = ?1")
      .bind(&first_delivery)
      .execute(&pool)
      .await
      .is_err()
  );

  let retained = store
    .prune_scheduled_delivery_history("retention-operation-1", first_run.binding.run_id(), 132)
    .await
    .expect("prune first history");
  assert_eq!(retained.deliveries, 1);
  assert_eq!(retained.delivery_attempts, 1);
  assert_eq!(retained.result_artifacts, 1);
  assert_eq!(retained.runs, 1);
  let baseline_after_retention = store
    .get_accepted_delivery_baseline(&identity)
    .await
    .expect("read retained baseline")
    .expect("retained baseline");
  assert_eq!(baseline_after_retention, baseline_before_retention);
  let deleted_history: (i64, i64, i64, i64) = sqlx::query_as(
    "select (select count(*) from scheduled_runs where run_id = ?1), (select count(*) from scheduled_run_result_artifacts where run_id = ?1), (select count(*) from scheduled_run_deliveries where run_id = ?1), (select count(*) from scheduled_delivery_attempts where delivery_id = ?2)",
  )
  .bind(first_run.binding.run_id())
  .bind(&first_delivery)
  .fetch_one(&pool)
  .await
  .expect("read pruned history");
  assert_eq!(deleted_history, (0, 0, 0, 0));
  let audit: (i64, i64) = sqlx::query_as(
    "select attempts_deleted, completed_at from scheduled_delivery_retention_audit where operation_id = 'retention-operation-1' and delivery_id = ?1",
  )
  .bind(&first_delivery)
  .fetch_one(&pool)
  .await
  .expect("read retention audit");
  assert_eq!(audit, (1, 132));
  assert!(
    sqlx::query(
      "delete from scheduled_delivery_retention_audit where operation_id = 'retention-operation-1' and delivery_id = ?1",
    )
    .bind(&first_delivery)
    .execute(&pool)
    .await
    .is_err()
  );

  let third_run = complete_due_run(&store, "unchanged-retention", 130, 140).await;
  let third_delivery: String =
    sqlx::query_scalar("select delivery_id from scheduled_run_deliveries where run_id = ?1")
      .bind(third_run.binding.run_id())
      .fetch_one(&pool)
      .await
      .expect("third delivery");
  assert!(matches!(
    store
      .prepare_scheduled_delivery(
        &third_delivery,
        "text/plain; charset=utf-8",
        exact_body,
        1,
        141,
        SkippedNoneBaselinePolicy::DoNotAdvance,
      )
      .await
      .expect("prepare retained-baseline match"),
    PreparedScheduledDelivery::Pending(_)
  ));
  assert!(
    store
      .claim_next_scheduled_delivery("must-skip-retained-baseline", 142, 200)
      .await
      .expect("claim retained-baseline match")
      .is_none()
  );
  let third_baseline_version: i64 = sqlx::query_scalar(
    "select baseline_version from scheduled_delivery_baselines where job_id = 'unchanged-retention'",
  )
  .fetch_one(&pool)
  .await
  .expect("read unchanged baseline version");
  assert_eq!(third_baseline_version, 1);

  let fourth_run = complete_due_run(&store, "unchanged-retention", 140, 150).await;
  let fourth_delivery: String =
    sqlx::query_scalar("select delivery_id from scheduled_run_deliveries where run_id = ?1")
      .bind(fourth_run.binding.run_id())
      .fetch_one(&pool)
      .await
      .expect("fourth delivery");
  let changed_body = "e\u{0301}|e\u{0301}|tail  \n";
  let PreparedScheduledDelivery::Pending(changed_payload) = store
    .prepare_scheduled_delivery(
      &fourth_delivery,
      "text/plain; charset=utf-8",
      changed_body,
      1,
      151,
      SkippedNoneBaselinePolicy::DoNotAdvance,
    )
    .await
    .expect("prepare normalization-changed payload")
  else {
    panic!("different UTF-8 bytes must remain sendable");
  };
  assert_ne!(changed_payload.digest(), first_payload.digest());
  assert!(
    sqlx::query(
      "update scheduled_run_deliveries set state = 'skipped_unchanged', provider_outcome = 'skipped_unchanged' where delivery_id = ?1",
    )
    .bind(&fourth_delivery)
    .execute(&pool)
    .await
    .is_err()
  );
  let changed_claim = store
    .claim_next_scheduled_delivery("changed-worker", 152, 200)
    .await
    .expect("claim changed payload")
    .expect("changed delivery");
  store
    .complete_scheduled_delivery_failure(
      &changed_claim.binding,
      &ScheduledDeliveryFailure::ConfirmedNoWriteTerminal {
        error_kind: "provider_rejected".to_owned(),
        redacted_message: None,
      },
      153,
    )
    .await
    .expect("record terminal no-write failure");
  let baseline_after_failure: i64 = sqlx::query_scalar(
    "select baseline_version from scheduled_delivery_baselines where job_id = 'unchanged-retention'",
  )
  .fetch_one(&pool)
  .await
  .expect("read baseline after failure");
  assert_eq!(baseline_after_failure, 1);
}

#[tokio::test]
async fn test_claim_time_baseline_skips_second_prepared_equal_payload_across_pools() {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state");
  let first = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize first store");
  let second = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize second store");
  let mut request = create_request(
    "claim-time-equal",
    ScheduleSpec::fixed_interval(110, 10).expect("interval"),
    100,
  );
  request.targets = vec![second_target("claim-time-equal")];
  first
    .create_scheduled_job(&request)
    .await
    .expect("create job");
  let first_run = complete_due_run(&first, "claim-time-equal", 110, 120).await;
  let second_run = complete_due_run(&first, "claim-time-equal", 120, 130).await;
  let pool = SqlitePool::connect(&database_url(&state_dir))
    .await
    .expect("connect database");
  let first_delivery: String =
    sqlx::query_scalar("select delivery_id from scheduled_run_deliveries where run_id = ?1")
      .bind(first_run.binding.run_id())
      .fetch_one(&pool)
      .await
      .expect("first delivery");
  let second_delivery: String =
    sqlx::query_scalar("select delivery_id from scheduled_run_deliveries where run_id = ?1")
      .bind(second_run.binding.run_id())
      .fetch_one(&pool)
      .await
      .expect("second delivery");
  for (store, delivery_id, prepared_at) in [
    (&first, first_delivery.as_str(), 131),
    (&second, second_delivery.as_str(), 132),
  ] {
    assert!(matches!(
      store
        .prepare_scheduled_delivery(
          delivery_id,
          "text/plain; charset=utf-8",
          "same exact payload",
          1,
          prepared_at,
          SkippedNoneBaselinePolicy::DoNotAdvance,
        )
        .await
        .expect("prepare equal payload"),
      PreparedScheduledDelivery::Pending(_)
    ));
  }
  let first_claim = first
    .claim_next_scheduled_delivery("equal-worker-a", 133, 200)
    .await
    .expect("claim first equal payload")
    .expect("first provider write");
  assert_eq!(first_claim.binding.delivery_id(), first_delivery);
  first
    .complete_scheduled_delivery_delivered(&first_claim.binding, "equal-receipt", 134)
    .await
    .expect("accept first equal payload");
  assert!(
    second
      .claim_next_scheduled_delivery("equal-worker-b", 135, 200)
      .await
      .expect("claim-time equal comparison")
      .is_none(),
    "the second preprepared equal payload must not reach the provider"
  );
  let authority: (String, i64, i64, i64) = sqlx::query_as(
    "select state, claimed_baseline_version, (select count(*) from scheduled_delivery_attempts where delivery_id = ?1), (select baseline_version from scheduled_delivery_baselines where job_id = 'claim-time-equal') from scheduled_run_deliveries where delivery_id = ?1",
  )
  .bind(&second_delivery)
  .fetch_one(&pool)
  .await
  .expect("read equal claim authority");
  assert_eq!(authority, ("skipped_unchanged".to_owned(), 1, 0, 1));
}

#[tokio::test]
async fn test_claim_time_baseline_rebases_second_prepared_different_payload_across_pools() {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state");
  let first = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize first store");
  let second = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize second store");
  let mut request = create_request(
    "claim-time-different",
    ScheduleSpec::fixed_interval(110, 10).expect("interval"),
    100,
  );
  request.targets = vec![second_target("claim-time-different")];
  first
    .create_scheduled_job(&request)
    .await
    .expect("create job");
  let first_run = complete_due_run(&first, "claim-time-different", 110, 120).await;
  let second_run = complete_due_run(&first, "claim-time-different", 120, 130).await;
  let pool = SqlitePool::connect(&database_url(&state_dir))
    .await
    .expect("connect database");
  let first_delivery: String =
    sqlx::query_scalar("select delivery_id from scheduled_run_deliveries where run_id = ?1")
      .bind(first_run.binding.run_id())
      .fetch_one(&pool)
      .await
      .expect("first delivery");
  let second_delivery: String =
    sqlx::query_scalar("select delivery_id from scheduled_run_deliveries where run_id = ?1")
      .bind(second_run.binding.run_id())
      .fetch_one(&pool)
      .await
      .expect("second delivery");
  for (store, delivery_id, body, prepared_at) in [
    (&first, first_delivery.as_str(), "payload A", 131),
    (&second, second_delivery.as_str(), "payload B", 132),
  ] {
    assert!(matches!(
      store
        .prepare_scheduled_delivery(
          delivery_id,
          "text/plain; charset=utf-8",
          body,
          1,
          prepared_at,
          SkippedNoneBaselinePolicy::DoNotAdvance,
        )
        .await
        .expect("prepare different payload"),
      PreparedScheduledDelivery::Pending(_)
    ));
  }
  let first_claim = first
    .claim_next_scheduled_delivery("different-worker-a", 133, 200)
    .await
    .expect("claim payload A")
    .expect("payload A provider write");
  first
    .complete_scheduled_delivery_delivered(&first_claim.binding, "receipt-a", 134)
    .await
    .expect("accept payload A");
  let second_claim = second
    .claim_next_scheduled_delivery("different-worker-b", 135, 200)
    .await
    .expect("claim payload B")
    .expect("changed payload B remains sendable");
  assert_eq!(second_claim.binding.delivery_id(), second_delivery);
  let claim_authority: (i64, i64, i64) = sqlx::query_as(
    "select delivery.expected_baseline_version, delivery.claimed_baseline_version, attempt.claimed_baseline_version from scheduled_run_deliveries delivery join scheduled_delivery_attempts attempt on attempt.delivery_id = delivery.delivery_id and attempt.attempt = delivery.attempt where delivery.delivery_id = ?1",
  )
  .bind(&second_delivery)
  .fetch_one(&pool)
  .await
  .expect("read rebased claim authority");
  assert_eq!(claim_authority, (0, 1, 1));
  second
    .complete_scheduled_delivery_delivered(&second_claim.binding, "receipt-b", 136)
    .await
    .expect("claim-time baseline CAS accepts payload B");
  let baseline: (String, i64) = sqlx::query_as(
    "select accepted_payload_digest, baseline_version from scheduled_delivery_baselines where job_id = 'claim-time-different'",
  )
  .fetch_one(&pool)
  .await
  .expect("read payload B baseline");
  assert_eq!(baseline, (test_sha256_hex("payload B"), 2));
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn test_delivery_baseline_generation_exhaustion_is_typed_and_atomic() {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state");
  let store = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize store");
  let pool = SqlitePool::connect(&database_url(&state_dir))
    .await
    .expect("connect database");

  let delivered_job = "delivery-baseline-max";
  let mut request = create_request(delivered_job, ScheduleSpec::once(110), 100);
  request.targets = vec![second_target(delivered_job)];
  store
    .create_scheduled_job(&request)
    .await
    .expect("create delivered max job");
  let delivered_run = complete_due_run(&store, delivered_job, 110, 120).await;
  let delivered_id: String =
    sqlx::query_scalar("select delivery_id from scheduled_run_deliveries where run_id = ?1")
      .bind(delivered_run.binding.run_id())
      .fetch_one(&pool)
      .await
      .expect("delivered max id");
  let PreparedScheduledDelivery::Pending(delivered_payload) = store
    .prepare_scheduled_delivery(
      &delivered_id,
      "text/plain; charset=utf-8",
      "new payload at max",
      1,
      121,
      SkippedNoneBaselinePolicy::DoNotAdvance,
    )
    .await
    .expect("prepare delivered max payload")
  else {
    panic!("delivered max fixture must remain pending");
  };
  sqlx::query(
    "insert into scheduled_delivery_baselines (job_id, target_identity_digest, target_snapshot_digest_algorithm, target_snapshot_digest, delivery_policy_version, render_version, hash_algorithm, accepted_payload_digest, source_delivery_id, source_run_id, source_result_id, source_result_hash, accepted_at, baseline_version) values (?1, ?2, 'sha256-v1', ?3, 1, 1, 'sha256-utf8-exact-v1', ?4, 'prior-delivery', 'prior-run', null, 'prior-result', 121, 9223372036854775807)",
  )
  .bind(delivered_job)
  .bind(delivered_payload.target_identity_digest())
  .bind(delivered_payload.target_snapshot_digest())
  .bind(test_sha256_hex("prior payload"))
  .execute(&pool)
  .await
  .expect("seed max delivered baseline");
  assert!(
    sqlx::query(
      "update scheduled_delivery_baselines set baseline_version = cast(1.5 as real) where job_id = ?1",
    )
    .bind(delivered_job)
    .execute(&pool)
    .await
    .is_err(),
    "active baseline authority must reject REAL generations"
  );
  assert!(
    sqlx::query(
      "insert into scheduled_delivery_baselines (job_id, target_identity_digest, target_snapshot_digest_algorithm, target_snapshot_digest, delivery_policy_version, render_version, hash_algorithm, accepted_payload_digest, source_delivery_id, source_run_id, source_result_hash, accepted_at, baseline_version) values (?1, ?2, 'sha256-v1', ?3, 1, 2, 'sha256-utf8-exact-v1', ?4, 'real-delivery', 'real-run', 'real-result', 121, cast(1.5 as real))",
    )
    .bind(delivered_job)
    .bind(delivered_payload.target_identity_digest())
    .bind(delivered_payload.target_snapshot_digest())
    .bind(test_sha256_hex("real payload"))
    .execute(&pool)
    .await
    .is_err(),
    "new REAL baseline authority must be rejected"
  );
  let delivered_claim = store
    .claim_next_scheduled_delivery("max-delivery-worker", 122, 200)
    .await
    .expect("claim delivered max payload")
    .expect("delivered max claim");
  let before_delivered: (String, i64, String, Option<i64>, i64) = sqlx::query_as(
    "select delivery.state, delivery.updated_at, attempt.state, attempt.completed_at, baseline.baseline_version from scheduled_run_deliveries delivery join scheduled_delivery_attempts attempt on attempt.delivery_id = delivery.delivery_id and attempt.attempt = delivery.attempt join scheduled_delivery_baselines baseline on baseline.job_id = delivery.job_id where delivery.delivery_id = ?1",
  )
  .bind(&delivered_id)
  .fetch_one(&pool)
  .await
  .expect("read pre-completion max authority");
  assert!(matches!(
    store
      .complete_scheduled_delivery_delivered(&delivered_claim.binding, "must-rollback", 123)
      .await,
    Err(StateError::ScheduledDeliveryBaselineConflict)
  ));
  let after_delivered: (String, i64, String, Option<i64>, i64) = sqlx::query_as(
    "select delivery.state, delivery.updated_at, attempt.state, attempt.completed_at, baseline.baseline_version from scheduled_run_deliveries delivery join scheduled_delivery_attempts attempt on attempt.delivery_id = delivery.delivery_id and attempt.attempt = delivery.attempt join scheduled_delivery_baselines baseline on baseline.job_id = delivery.job_id where delivery.delivery_id = ?1",
  )
  .bind(&delivered_id)
  .fetch_one(&pool)
  .await
  .expect("read rolled-back max authority");
  assert_eq!(after_delivered, before_delivered);
  assert_eq!(after_delivered.0, "sending");
  assert_eq!(after_delivered.2, "sending");
  assert_eq!(after_delivered.4, i64::MAX);

  let skipped_none_job = "skipped-none-baseline-max";
  store
    .create_scheduled_job(&create_request(
      skipped_none_job,
      ScheduleSpec::once(210),
      200,
    ))
    .await
    .expect("create skipped-none max job");
  let skipped_none_run = complete_due_run(&store, skipped_none_job, 210, 220).await;
  let skipped_none_id: String =
    sqlx::query_scalar("select delivery_id from scheduled_run_deliveries where run_id = ?1")
      .bind(skipped_none_run.binding.run_id())
      .fetch_one(&pool)
      .await
      .expect("skipped-none max id");
  let skipped_none_target: (String, String) = sqlx::query_as(
    "select target_identity_digest, target_json from scheduled_run_deliveries where delivery_id = ?1",
  )
  .bind(&skipped_none_id)
  .fetch_one(&pool)
  .await
  .expect("skipped-none target authority");
  sqlx::query(
    "insert into scheduled_delivery_baselines (job_id, target_identity_digest, target_snapshot_digest_algorithm, target_snapshot_digest, delivery_policy_version, render_version, hash_algorithm, accepted_payload_digest, source_delivery_id, source_run_id, source_result_id, source_result_hash, accepted_at, baseline_version) values (?1, ?2, 'sha256-v1', ?3, 1, 1, 'sha256-utf8-exact-v1', ?4, 'prior-none-delivery', 'prior-none-run', null, 'prior-none-result', 221, 9223372036854775807)",
  )
  .bind(skipped_none_job)
  .bind(&skipped_none_target.0)
  .bind(test_sha256_hex(&skipped_none_target.1))
  .bind(test_sha256_hex("prior none payload"))
  .execute(&pool)
  .await
  .expect("seed skipped-none max baseline");
  let before_skipped_none: (String, i64, Option<Vec<u8>>, i64) = sqlx::query_as(
    "select delivery.state, delivery.updated_at, delivery.payload_snapshot, baseline.baseline_version from scheduled_run_deliveries delivery join scheduled_delivery_baselines baseline on baseline.job_id = delivery.job_id where delivery.delivery_id = ?1",
  )
  .bind(&skipped_none_id)
  .fetch_one(&pool)
  .await
  .expect("read pre-prepare skipped-none authority");
  assert!(matches!(
    store
      .prepare_scheduled_delivery(
        &skipped_none_id,
        "text/plain; charset=utf-8",
        "none payload at max",
        1,
        221,
        SkippedNoneBaselinePolicy::Accept,
      )
      .await,
    Err(StateError::ScheduledDeliveryBaselineConflict)
  ));
  let after_skipped_none: (String, i64, Option<Vec<u8>>, i64) = sqlx::query_as(
    "select delivery.state, delivery.updated_at, delivery.payload_snapshot, baseline.baseline_version from scheduled_run_deliveries delivery join scheduled_delivery_baselines baseline on baseline.job_id = delivery.job_id where delivery.delivery_id = ?1",
  )
  .bind(&skipped_none_id)
  .fetch_one(&pool)
  .await
  .expect("read rolled-back skipped-none authority");
  assert_eq!(after_skipped_none, before_skipped_none);
  assert_eq!(after_skipped_none.0, "pending");
  assert!(after_skipped_none.2.is_none());
  assert_eq!(after_skipped_none.3, i64::MAX);

  let unchanged_job = "unchanged-baseline-max";
  let mut request = create_request(unchanged_job, ScheduleSpec::once(310), 300);
  request.targets = vec![second_target(unchanged_job)];
  store
    .create_scheduled_job(&request)
    .await
    .expect("create unchanged max job");
  let unchanged_run = complete_due_run(&store, unchanged_job, 310, 320).await;
  let unchanged_id: String =
    sqlx::query_scalar("select delivery_id from scheduled_run_deliveries where run_id = ?1")
      .bind(unchanged_run.binding.run_id())
      .fetch_one(&pool)
      .await
      .expect("unchanged max id");
  let PreparedScheduledDelivery::Pending(unchanged_payload) = store
    .prepare_scheduled_delivery(
      &unchanged_id,
      "text/plain; charset=utf-8",
      "exact unchanged at max",
      1,
      321,
      SkippedNoneBaselinePolicy::DoNotAdvance,
    )
    .await
    .expect("prepare unchanged max payload")
  else {
    panic!("prepare remains advisory");
  };
  sqlx::query(
    "insert into scheduled_delivery_baselines (job_id, target_identity_digest, target_snapshot_digest_algorithm, target_snapshot_digest, delivery_policy_version, render_version, hash_algorithm, accepted_payload_digest, source_delivery_id, source_run_id, source_result_id, source_result_hash, accepted_at, baseline_version) values (?1, ?2, 'sha256-v1', ?3, 1, 1, 'sha256-utf8-exact-v1', ?4, 'prior-unchanged-delivery', 'prior-unchanged-run', null, 'prior-unchanged-result', 321, 9223372036854775807)",
  )
  .bind(unchanged_job)
  .bind(unchanged_payload.target_identity_digest())
  .bind(unchanged_payload.target_snapshot_digest())
  .bind(unchanged_payload.digest())
  .execute(&pool)
  .await
  .expect("seed exact max baseline");
  assert!(
    store
      .claim_next_scheduled_delivery("unchanged-max-worker", 322, 400)
      .await
      .expect("claim-time exact max comparison")
      .is_none()
  );
  let unchanged_authority: (String, i64, i64, i64) = sqlx::query_as(
    "select delivery.state, delivery.claimed_baseline_version, (select count(*) from scheduled_delivery_attempts where delivery_id = ?1), baseline.baseline_version from scheduled_run_deliveries delivery join scheduled_delivery_baselines baseline on baseline.job_id = delivery.job_id where delivery.delivery_id = ?1",
  )
  .bind(&unchanged_id)
  .fetch_one(&pool)
  .await
  .expect("read unchanged max authority");
  assert_eq!(
    unchanged_authority,
    ("skipped_unchanged".to_owned(), i64::MAX, 0, i64::MAX)
  );
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn test_retention_guards_reject_dynamic_nonterminal_and_latest_source_deletes() {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state");
  let store = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize store");
  let pool = SqlitePool::connect(&database_url(&state_dir))
    .await
    .expect("connect database");

  for (job_id, terminal) in [
    ("retention-sending", "sending"),
    ("retention-unknown", "delivery_unknown"),
    ("retention-pending", "pending"),
  ] {
    let mut request = create_request(job_id, ScheduleSpec::once(110), 100);
    request.targets = vec![second_target(job_id)];
    store
      .create_scheduled_job(&request)
      .await
      .expect("create retention fixture job");
    let run = complete_due_run(&store, job_id, 110, 120).await;
    let delivery_id: String =
      sqlx::query_scalar("select delivery_id from scheduled_run_deliveries where run_id = ?1")
        .bind(run.binding.run_id())
        .fetch_one(&pool)
        .await
        .expect("retention fixture delivery");
    store
      .prepare_scheduled_delivery(
        &delivery_id,
        "text/plain; charset=utf-8",
        job_id,
        1,
        121,
        SkippedNoneBaselinePolicy::DoNotAdvance,
      )
      .await
      .expect("prepare retention fixture");
    if terminal != "pending" {
      let claim = store
        .claim_next_scheduled_delivery(&format!("{job_id}-worker"), 122, 200)
        .await
        .expect("claim retention fixture")
        .expect("claimed retention fixture");
      if terminal == "delivery_unknown" {
        store
          .complete_scheduled_delivery_failure(
            &claim.binding,
            &ScheduledDeliveryFailure::AmbiguousPostWrite {
              error_kind: "retention_unknown".to_owned(),
              redacted_message: None,
            },
            123,
          )
          .await
          .expect("make retention fixture unknown");
      }
    }
    assert!(matches!(
      store
        .prune_scheduled_delivery_history(&format!("prune-{terminal}"), run.binding.run_id(), 130,)
        .await,
      Err(StateError::ScheduledDeliveryRetentionConflict)
    ));
    assert!(
      sqlx::query(
        "insert into scheduled_delivery_retention_audit (operation_id, delivery_id, run_id, job_id, delivery_state, payload_digest, authorized_at) select ?1, delivery_id, run_id, job_id, state, payload_digest, 130 from scheduled_run_deliveries where delivery_id = ?2",
      )
      .bind(format!("direct-{terminal}"))
      .bind(&delivery_id)
      .execute(&pool)
      .await
      .is_err(),
      "{terminal} must not mint retention authority"
    );
    if terminal != "pending" {
      assert!(
        sqlx::query("delete from scheduled_delivery_attempts where delivery_id = ?1")
          .bind(&delivery_id)
          .execute(&pool)
          .await
          .is_err(),
        "{terminal} attempt delete must fail in its own transaction"
      );
    }
    assert!(
      sqlx::query("delete from scheduled_run_deliveries where delivery_id = ?1")
        .bind(&delivery_id)
        .execute(&pool)
        .await
        .is_err(),
      "{terminal} delivery delete must fail in its own transaction"
    );
    assert!(
      sqlx::query("delete from scheduled_run_result_artifacts where run_id = ?1")
        .bind(run.binding.run_id())
        .execute(&pool)
        .await
        .is_err(),
      "{terminal} result delete must fail in its own transaction"
    );
    let preserved: (i64, i64, i64, i64) = sqlx::query_as(
      "select (select count(*) from scheduled_run_deliveries where delivery_id = ?1), (select count(*) from scheduled_delivery_attempts where delivery_id = ?1), (select count(*) from scheduled_run_result_artifacts where run_id = ?2), (select count(*) from scheduled_delivery_retention_audit where run_id = ?2)",
    )
    .bind(&delivery_id)
    .bind(run.binding.run_id())
    .fetch_one(&pool)
    .await
    .expect("read preserved nonterminal authority");
    assert_eq!(
      preserved,
      (1, i64::from(terminal != "pending"), 1, 0),
      "{terminal} direct delete attempts must leave no partial deletion or audit authority"
    );
    if terminal == "pending" {
      let cleanup_claim = store
        .claim_next_scheduled_delivery("pending-fixture-cleanup", 131, 200)
        .await
        .expect("claim preserved pending fixture")
        .expect("pending fixture cleanup claim");
      assert_eq!(cleanup_claim.binding.delivery_id(), delivery_id);
      store
        .complete_scheduled_delivery_failure(
          &cleanup_claim.binding,
          &ScheduledDeliveryFailure::ConfirmedNoWriteTerminal {
            error_kind: "test_fixture_complete".to_owned(),
            redacted_message: None,
          },
          132,
        )
        .await
        .expect("complete preserved pending fixture");
    }
  }

  let latest_job = "retention-latest-source";
  let mut request = create_request(latest_job, ScheduleSpec::once(110), 100);
  request.targets = vec![second_target(latest_job)];
  store
    .create_scheduled_job(&request)
    .await
    .expect("create latest-source job");
  let latest_run = complete_due_run(&store, latest_job, 110, 120).await;
  let latest_delivery: String =
    sqlx::query_scalar("select delivery_id from scheduled_run_deliveries where run_id = ?1")
      .bind(latest_run.binding.run_id())
      .fetch_one(&pool)
      .await
      .expect("latest-source delivery");
  store
    .prepare_scheduled_delivery(
      &latest_delivery,
      "text/plain; charset=utf-8",
      "latest source payload",
      1,
      121,
      SkippedNoneBaselinePolicy::DoNotAdvance,
    )
    .await
    .expect("prepare latest-source delivery");
  let latest_claim = store
    .claim_next_scheduled_delivery("latest-source-worker", 122, 200)
    .await
    .expect("claim latest-source delivery")
    .expect("latest-source claim");
  store
    .complete_scheduled_delivery_delivered(&latest_claim.binding, "latest-receipt", 123)
    .await
    .expect("complete latest-source delivery");
  assert!(matches!(
    store
      .prune_scheduled_delivery_history("prune-latest-source", latest_run.binding.run_id(), 130,)
      .await,
    Err(StateError::ScheduledDeliveryRetentionConflict)
  ));
  assert!(
    sqlx::query(
      "insert into scheduled_delivery_retention_audit (operation_id, delivery_id, run_id, job_id, delivery_state, payload_digest, authorized_at) select 'direct-latest-source', delivery_id, run_id, job_id, state, payload_digest, 130 from scheduled_run_deliveries where delivery_id = ?1",
    )
    .bind(&latest_delivery)
    .execute(&pool)
    .await
    .is_err(),
    "current execution baseline source must not mint retention authority"
  );
  for statement in [
    "delete from scheduled_delivery_attempts where delivery_id = ?1",
    "delete from scheduled_run_deliveries where delivery_id = ?1",
    "delete from scheduled_run_result_artifacts where run_id = ?1",
  ] {
    let value = if statement.contains("result_artifacts") {
      latest_run.binding.run_id()
    } else {
      latest_delivery.as_str()
    };
    assert!(
      sqlx::query(statement)
        .bind(value)
        .execute(&pool)
        .await
        .is_err(),
      "latest-source delete guard must reject {statement}"
    );
  }
  let latest_preserved: (i64, i64, i64, i64, i64) = sqlx::query_as(
    "select (select count(*) from scheduled_run_deliveries where delivery_id = ?1), (select count(*) from scheduled_delivery_attempts where delivery_id = ?1), (select count(*) from scheduled_run_result_artifacts where run_id = ?2), (select count(*) from scheduled_delivery_retention_audit where run_id = ?2), (select count(*) from scheduled_delivery_baselines where job_id = ?3)",
  )
  .bind(&latest_delivery)
  .bind(latest_run.binding.run_id())
  .bind(latest_job)
  .fetch_one(&pool)
  .await
  .expect("read preserved latest-source authority");
  assert_eq!(latest_preserved, (1, 1, 1, 0, 1));

  let dynamic_job = "retention-dynamic-source";
  let mut request = create_request(
    dynamic_job,
    ScheduleSpec::fixed_interval(210, 10).expect("interval"),
    200,
  );
  request.targets = vec![second_target(dynamic_job)];
  store
    .create_scheduled_job(&request)
    .await
    .expect("create dynamic-source job");
  let first_dynamic_run = complete_due_run(&store, dynamic_job, 210, 220).await;
  let first_dynamic_delivery: String =
    sqlx::query_scalar("select delivery_id from scheduled_run_deliveries where run_id = ?1")
      .bind(first_dynamic_run.binding.run_id())
      .fetch_one(&pool)
      .await
      .expect("first dynamic delivery");
  store
    .prepare_scheduled_delivery(
      &first_dynamic_delivery,
      "text/plain; charset=utf-8",
      "dynamic source payload",
      1,
      221,
      SkippedNoneBaselinePolicy::DoNotAdvance,
    )
    .await
    .expect("prepare first dynamic delivery");
  let first_dynamic_claim = store
    .claim_next_scheduled_delivery("dynamic-source-worker", 222, 300)
    .await
    .expect("claim first dynamic delivery")
    .expect("first dynamic claim");
  store
    .complete_scheduled_delivery_delivered(&first_dynamic_claim.binding, "dynamic-receipt", 223)
    .await
    .expect("complete first dynamic delivery");
  let _second_dynamic_run = complete_due_run(&store, dynamic_job, 220, 230).await;
  sqlx::query(
    "insert into scheduled_delivery_retention_audit (operation_id, delivery_id, run_id, job_id, delivery_state, payload_digest, authorized_at) select 'dynamic-authority', delivery_id, run_id, job_id, state, payload_digest, 231 from scheduled_run_deliveries where delivery_id = ?1",
  )
  .bind(&first_dynamic_delivery)
  .execute(&pool)
  .await
  .expect("mint authority while first run is not execution baseline source");
  sqlx::query(
    "update scheduled_execution_baselines set hash_algorithm = artifact.hash_algorithm, result_hash = artifact.result_hash, previous_success_context = artifact.previous_success_context, source_run_id = artifact.run_id, completed_at = artifact.completed_at from scheduled_run_result_artifacts artifact where scheduled_execution_baselines.job_id = ?1 and artifact.run_id = ?2 and artifact.job_id = scheduled_execution_baselines.job_id",
  )
  .bind(dynamic_job)
  .bind(first_dynamic_run.binding.run_id())
  .execute(&pool)
  .await
  .expect("make already-authorized run the current execution baseline source");
  for statement in [
    "delete from scheduled_delivery_attempts where delivery_id = ?1",
    "delete from scheduled_run_deliveries where delivery_id = ?1",
    "delete from scheduled_run_result_artifacts where run_id = ?1",
  ] {
    let value = if statement.contains("result_artifacts") {
      first_dynamic_run.binding.run_id()
    } else {
      first_dynamic_delivery.as_str()
    };
    assert!(
      sqlx::query(statement)
        .bind(value)
        .execute(&pool)
        .await
        .is_err(),
      "dynamic latest-source guard must reject preauthorized {statement}"
    );
  }
  let dynamic_preserved: (i64, i64, i64, i64, Option<i64>) = sqlx::query_as(
    "select (select count(*) from scheduled_run_deliveries where delivery_id = ?1), (select count(*) from scheduled_delivery_attempts where delivery_id = ?1), (select count(*) from scheduled_run_result_artifacts where run_id = ?2), (select count(*) from scheduled_delivery_baselines where job_id = ?3), (select completed_at from scheduled_delivery_retention_audit where operation_id = 'dynamic-authority' and delivery_id = ?1)",
  )
  .bind(&first_dynamic_delivery)
  .bind(first_dynamic_run.binding.run_id())
  .bind(dynamic_job)
  .fetch_one(&pool)
  .await
  .expect("read dynamically preserved source authority");
  assert_eq!(dynamic_preserved, (1, 1, 1, 1, None));
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn test_two_independent_stores_claim_once_and_reject_stale_delivery_fence() {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state");
  let first = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize first store");
  let second = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize second store");
  let mut request = create_request("delivery-race", ScheduleSpec::once(110), 100);
  request.targets = vec![second_target("delivery-race")];
  first
    .create_scheduled_job(&request)
    .await
    .expect("create job");
  first
    .materialize_due_schedule("delivery-race", 0, 110)
    .await
    .expect("materialize");
  let run = first
    .claim_next_scheduled_run("run-worker", 111, 200)
    .await
    .expect("claim run")
    .expect("run");
  let profile =
    AttestedExecutionProfileSnapshot::new(1, "{}", "sha256-v1", "profile").expect("profile");
  first
    .mark_scheduled_run_executing(&run.binding, &profile, 112)
    .await
    .expect("execute run");
  first
    .complete_scheduled_run_success(
      &run.binding,
      &ScheduledRunResult::new("payload", "").expect("result"),
      120,
    )
    .await
    .expect("complete run");
  let pool = SqlitePool::connect(&database_url(&state_dir))
    .await
    .expect("connect database");
  let delivery_id: String =
    sqlx::query_scalar("select delivery_id from scheduled_run_deliveries where run_id = ?1")
      .bind(run.binding.run_id())
      .fetch_one(&pool)
      .await
      .expect("delivery id");
  let PreparedScheduledDelivery::Pending(payload) = first
    .prepare_scheduled_delivery(
      &delivery_id,
      "text/plain; charset=utf-8",
      "payload",
      1,
      121,
      SkippedNoneBaselinePolicy::DoNotAdvance,
    )
    .await
    .expect("prepare delivery")
  else {
    panic!("Slack target must remain pending");
  };
  let barrier = Arc::new(Barrier::new(3));
  let first_task = tokio::spawn(delivery_claim_after_barrier(
    first,
    Arc::clone(&barrier),
    "delivery-worker-a",
  ));
  let second_task = tokio::spawn(delivery_claim_after_barrier(
    second,
    Arc::clone(&barrier),
    "delivery-worker-b",
  ));
  barrier.wait().await;
  let outcomes = vec![
    first_task.await.expect("first task").expect("first claim"),
    second_task
      .await
      .expect("second task")
      .expect("second claim"),
  ];
  assert_eq!(outcomes.iter().filter(|claim| claim.is_some()).count(), 1);
  let first_claim = outcomes.into_iter().flatten().next().expect("claim winner");
  assert_eq!(first_claim.binding.attempt(), 1);
  assert_eq!(first_claim.payload, payload);
  assert!(first_claim.target_json.contains(r#""channel_id":"C1""#));
  let stable_idempotency_key = first_claim.binding.idempotency_key().to_owned();
  let retry = ScheduledDeliveryFailure::ConfirmedNoWriteRetryable {
    error_kind: "slack_rate_limited".to_owned(),
    redacted_message: Some("retry later".to_owned()),
    next_attempt_at: 130,
  };
  let current_store = StateStore::initialize(&state_dir, None)
    .await
    .expect("current store");
  current_store
    .complete_scheduled_delivery_failure(&first_claim.binding, &retry, 122)
    .await
    .expect("safe retry classification");
  assert_eq!(
    current_store
      .requeue_due_scheduled_deliveries(129, 10)
      .await
      .expect("early requeue"),
    0
  );
  assert_eq!(
    current_store
      .requeue_due_scheduled_deliveries(130, 10)
      .await
      .expect("due requeue"),
    1
  );
  let next_claim = current_store
    .claim_next_scheduled_delivery("delivery-worker-c", 131, 200)
    .await
    .expect("second claim")
    .expect("requeued delivery");
  assert_eq!(next_claim.binding.attempt(), 2);
  assert_eq!(next_claim.binding.idempotency_key(), stable_idempotency_key);
  assert_eq!(next_claim.payload.digest(), payload.digest());
  assert_eq!(next_claim.payload.body(), payload.body());
  assert!(matches!(
    current_store
      .complete_scheduled_delivery_delivered(&first_claim.binding, "stale", 132)
      .await,
    Err(StateError::ScheduledDeliveryLostLease)
  ));
  current_store
    .complete_scheduled_delivery_delivered(&next_claim.binding, "slack-message-1", 132)
    .await
    .expect("commit delivery");
  let authority: (String, i64, i64, i64) = sqlx::query_as(
    "select state, attempt, fence, (select count(*) from scheduled_delivery_baselines where job_id = 'delivery-race') from scheduled_run_deliveries where delivery_id = ?1",
  )
  .bind(&delivery_id)
  .fetch_one(&pool)
  .await
  .expect("delivery authority");
  assert_eq!(authority, ("delivered".to_owned(), 2, 2, 1));
}

async fn delivery_claim_after_barrier(
  store: StateStore,
  barrier: Arc<Barrier>,
  owner: &'static str,
) -> Result<Option<ClaimedScheduledDelivery>, StateError> {
  barrier.wait().await;
  for _ in 0..20 {
    match store.claim_next_scheduled_delivery(owner, 122, 200).await {
      Err(error) if error.is_transient_storage_contention() => {
        tokio::time::sleep(Duration::from_millis(5)).await;
      }
      result => return result,
    }
  }
  store.claim_next_scheduled_delivery(owner, 122, 200).await
}

async fn delivery_reclaim_after_barrier(
  store: StateStore,
  barrier: Arc<Barrier>,
  now: i64,
) -> Result<u64, StateError> {
  barrier.wait().await;
  for _ in 0..20 {
    match store.reclaim_expired_scheduled_deliveries(now, 1).await {
      Err(error) if error.is_transient_storage_contention() => {
        tokio::time::sleep(Duration::from_millis(5)).await;
      }
      result => return result,
    }
  }
  store.reclaim_expired_scheduled_deliveries(now, 1).await
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn test_expired_delivery_reclaim_has_one_winner_and_unblocks_later_occurrence() {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state");
  let first = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize first store");
  let second = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize second store");
  let mut request = create_request(
    "delivery-reclaim",
    ScheduleSpec::fixed_interval(110, 10).expect("interval"),
    100,
  );
  request.targets = vec![second_target("delivery-reclaim")];
  first
    .create_scheduled_job(&request)
    .await
    .expect("create job");
  let pool = SqlitePool::connect(&database_url(&state_dir))
    .await
    .expect("connect database");

  let first_run = complete_due_run(&first, "delivery-reclaim", 110, 120).await;
  let first_delivery: String =
    sqlx::query_scalar("select delivery_id from scheduled_run_deliveries where run_id = ?1")
      .bind(first_run.binding.run_id())
      .fetch_one(&pool)
      .await
      .expect("first delivery");
  assert!(matches!(
    first
      .prepare_scheduled_delivery(
        &first_delivery,
        "text/plain; charset=utf-8",
        "first",
        1,
        121,
        SkippedNoneBaselinePolicy::DoNotAdvance,
      )
      .await
      .expect("prepare first"),
    PreparedScheduledDelivery::Pending(_)
  ));
  let first_claim = first
    .claim_next_scheduled_delivery("expired-worker", 122, 125)
    .await
    .expect("claim first")
    .expect("first claim");
  assert!(matches!(
    first
      .heartbeat_scheduled_delivery(&first_claim.binding, 123, 125)
      .await,
    Err(StateError::ScheduledDeliveryLostLease)
  ));
  assert!(matches!(
    first
      .heartbeat_scheduled_delivery(&first_claim.binding, 123, 124)
      .await,
    Err(StateError::ScheduledDeliveryLostLease)
  ));
  first
    .heartbeat_scheduled_delivery(&first_claim.binding, 123, 130)
    .await
    .expect("strictly extend lease");

  let second_run = complete_due_run(&first, "delivery-reclaim", 120, 128).await;
  let second_delivery: String =
    sqlx::query_scalar("select delivery_id from scheduled_run_deliveries where run_id = ?1")
      .bind(second_run.binding.run_id())
      .fetch_one(&pool)
      .await
      .expect("second delivery");
  assert!(matches!(
    first
      .prepare_scheduled_delivery(
        &second_delivery,
        "text/plain; charset=utf-8",
        "second",
        1,
        129,
        SkippedNoneBaselinePolicy::DoNotAdvance,
      )
      .await
      .expect("prepare second"),
    PreparedScheduledDelivery::Pending(_)
  ));
  assert!(
    first
      .claim_next_scheduled_delivery("blocked-worker", 130, 200)
      .await
      .expect("blocked claim")
      .is_none()
  );

  let barrier = Arc::new(Barrier::new(3));
  let first_task = tokio::spawn(delivery_reclaim_after_barrier(
    first,
    Arc::clone(&barrier),
    131,
  ));
  let second_task = tokio::spawn(delivery_reclaim_after_barrier(
    second,
    Arc::clone(&barrier),
    131,
  ));
  barrier.wait().await;
  let outcomes = [
    first_task
      .await
      .expect("first task")
      .expect("first reclaim"),
    second_task
      .await
      .expect("second task")
      .expect("second reclaim"),
  ];
  assert_eq!(outcomes.iter().sum::<u64>(), 1);
  let store = StateStore::initialize(&state_dir, None)
    .await
    .expect("reopen store");
  assert!(matches!(
    store
      .heartbeat_scheduled_delivery(&first_claim.binding, 132, 220)
      .await,
    Err(StateError::ScheduledDeliveryLostLease)
  ));
  assert_eq!(
    store
      .requeue_due_scheduled_deliveries(i64::MAX, 10)
      .await
      .expect("retry scan"),
    0
  );
  let reclaimed_authority: (String, String, String, i64) = sqlx::query_as(
    "select delivery.state, attempt.state, delivery.provider_outcome, (select count(*) from scheduled_delivery_baselines where job_id = 'delivery-reclaim') from scheduled_run_deliveries delivery join scheduled_delivery_attempts attempt on attempt.delivery_id = delivery.delivery_id and attempt.attempt = delivery.attempt where delivery.delivery_id = ?1",
  )
  .bind(&first_delivery)
  .fetch_one(&pool)
  .await
  .expect("read reclaimed authority");
  assert_eq!(
    reclaimed_authority,
    (
      "delivery_unknown".to_owned(),
      "delivery_unknown".to_owned(),
      "ambiguous_post_write".to_owned(),
      0
    )
  );
  assert!(matches!(
    store
      .prune_scheduled_delivery_history("must-not-prune-unknown", first_run.binding.run_id(), 132,)
      .await,
    Err(StateError::ScheduledDeliveryRetentionConflict)
  ));
  assert!(
    sqlx::query(
      "insert into scheduled_delivery_retention_audit (operation_id, delivery_id, run_id, job_id, delivery_state, payload_digest, authorized_at) select 'bypass-unknown', delivery_id, run_id, job_id, state, payload_digest, 132 from scheduled_run_deliveries where delivery_id = ?1",
    )
    .bind(&first_delivery)
    .execute(&pool)
    .await
    .is_err()
  );
  let later_claim = store
    .claim_next_scheduled_delivery("later-worker", 132, 200)
    .await
    .expect("claim later occurrence")
    .expect("later occurrence unblocked");
  assert_eq!(later_claim.binding.delivery_id(), second_delivery);
  assert!(matches!(
    store
      .complete_scheduled_delivery_delivered(&later_claim.binding, "too-early", 131)
      .await,
    Err(StateError::ScheduledDeliveryLostLease)
  ));
  store
    .complete_scheduled_delivery_delivered(&later_claim.binding, "receipt-2", 133)
    .await
    .expect("complete later occurrence monotonically");
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn test_ambiguous_post_write_becomes_unknown_without_retry_or_baseline() {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state");
  let store = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize store");
  let mut request = create_request("delivery-unknown", ScheduleSpec::once(110), 100);
  request.targets = vec![second_target("delivery-unknown")];
  store
    .create_scheduled_job(&request)
    .await
    .expect("create job");
  store
    .materialize_due_schedule("delivery-unknown", 0, 110)
    .await
    .expect("materialize");
  let run = store
    .claim_next_scheduled_run("run-worker", 111, 200)
    .await
    .expect("claim run")
    .expect("run");
  let profile =
    AttestedExecutionProfileSnapshot::new(1, "{}", "sha256-v1", "profile").expect("profile");
  store
    .mark_scheduled_run_executing(&run.binding, &profile, 112)
    .await
    .expect("execute run");
  store
    .complete_scheduled_run_success(
      &run.binding,
      &ScheduledRunResult::new("payload", "").expect("result"),
      120,
    )
    .await
    .expect("complete run");
  let pool = SqlitePool::connect(&database_url(&state_dir))
    .await
    .expect("connect database");
  let delivery_id: String =
    sqlx::query_scalar("select delivery_id from scheduled_run_deliveries where run_id = ?1")
      .bind(run.binding.run_id())
      .fetch_one(&pool)
      .await
      .expect("delivery id");
  let PreparedScheduledDelivery::Pending(payload) = store
    .prepare_scheduled_delivery(
      &delivery_id,
      "text/plain; charset=utf-8",
      "payload",
      1,
      121,
      SkippedNoneBaselinePolicy::DoNotAdvance,
    )
    .await
    .expect("prepare delivery")
  else {
    panic!("Slack target must remain pending");
  };
  let claim = store
    .claim_next_scheduled_delivery("delivery-worker", 122, 200)
    .await
    .expect("claim delivery")
    .expect("delivery");
  store
    .complete_scheduled_delivery_failure(
      &claim.binding,
      &ScheduledDeliveryFailure::AmbiguousPostWrite {
        error_kind: "response_lost_after_write".to_owned(),
        redacted_message: Some("provider outcome is unknown".to_owned()),
      },
      123,
    )
    .await
    .expect("record ambiguity");
  assert_eq!(
    store
      .requeue_due_scheduled_deliveries(i64::MAX, 10)
      .await
      .expect("requeue scan"),
    0
  );
  assert!(
    store
      .claim_next_scheduled_delivery("must-not-resend", 124, 200)
      .await
      .expect("claim scan")
      .is_none()
  );
  let authority: (String, String, i64, i64, i64) = sqlx::query_as(
    "select delivery.state, attempt.state, delivery.attempt, delivery.fence, (select count(*) from scheduled_delivery_baselines where job_id = 'delivery-unknown') from scheduled_run_deliveries delivery join scheduled_delivery_attempts attempt on attempt.delivery_id = delivery.delivery_id and attempt.attempt = delivery.attempt where delivery.delivery_id = ?1",
  )
  .bind(&delivery_id)
  .fetch_one(&pool)
  .await
  .expect("unknown authority");
  assert_eq!(
    authority,
    (
      "delivery_unknown".to_owned(),
      "delivery_unknown".to_owned(),
      1,
      1,
      0
    )
  );
  let baseline_foreign_keys: Vec<String> = sqlx::query_scalar(
    "select \"table\" from pragma_foreign_key_list('scheduled_delivery_baselines') order by \"table\"",
  )
  .fetch_all(&pool)
  .await
  .expect("baseline foreign keys");
  assert_eq!(baseline_foreign_keys, vec!["scheduled_jobs"]);
  assert_eq!(claim.payload.digest(), payload.digest());
}

async fn prepare_operator_unknown_delivery(
  store: &StateStore,
  job_id: &str,
  scheduled_for: i64,
) -> ClaimedScheduledDelivery {
  let mut request = create_request(job_id, ScheduleSpec::once(scheduled_for), 100);
  request.targets = vec![second_target(job_id)];
  store
    .create_scheduled_job(&request)
    .await
    .expect("create job");
  store
    .materialize_due_schedule(job_id, 0, scheduled_for)
    .await
    .expect("materialize");
  let run = store
    .claim_next_scheduled_run(
      "operator-run-worker",
      scheduled_for + 1,
      scheduled_for + 100,
    )
    .await
    .expect("claim run")
    .expect("run");
  let profile =
    AttestedExecutionProfileSnapshot::new(1, "{}", "sha256-v1", "profile").expect("profile");
  store
    .mark_scheduled_run_executing(&run.binding, &profile, scheduled_for + 2)
    .await
    .expect("execute run");
  store
    .complete_scheduled_run_success(
      &run.binding,
      &ScheduledRunResult::new(format!("payload-{job_id}"), "").expect("result"),
      scheduled_for + 3,
    )
    .await
    .expect("complete run");
  let delivery_id = store
    .list_scheduled_delivery_operator_projections(None, 100)
    .await
    .expect("list deliveries")
    .into_iter()
    .find(|delivery| delivery.job_id == job_id)
    .expect("delivery")
    .delivery_id;
  let PreparedScheduledDelivery::Pending(_) = store
    .prepare_scheduled_delivery(
      &delivery_id,
      "text/plain; charset=utf-8",
      &format!("payload-{job_id}"),
      1,
      scheduled_for + 4,
      SkippedNoneBaselinePolicy::DoNotAdvance,
    )
    .await
    .expect("prepare delivery")
  else {
    panic!("Slack delivery must remain pending");
  };
  let claim = store
    .claim_next_scheduled_delivery(
      "operator-delivery-worker",
      scheduled_for + 5,
      scheduled_for + 100,
    )
    .await
    .expect("claim delivery")
    .expect("delivery");
  store
    .complete_scheduled_delivery_failure(
      &claim.binding,
      &ScheduledDeliveryFailure::AmbiguousPostWrite {
        error_kind: "ambiguous".to_owned(),
        redacted_message: Some("provider evidence required".to_owned()),
      },
      scheduled_for + 6,
    )
    .await
    .expect("record ambiguity");
  claim
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn test_operator_delivery_evidence_is_canonical_versioned_and_target_bound() {
  let malformed_receipt = "not-json".to_owned();
  let (evidence_json, evidence_digest) = operator_delivery_evidence(
    "provider_confirmed_delivered",
    "malformed-receipt",
    "slack",
    "workspace",
    "channel",
    Some(&malformed_receipt),
  );
  let malformed_action = ScheduledDeliveryUnknownAction::ConfirmDelivered {
    provider_receipt: malformed_receipt,
    evidence_json,
    evidence_digest,
  };
  assert!(matches!(
    SchedulerOperatorRequest::for_delivery_action(
      owner(),
      "malformed-receipt",
      "delivery",
      1,
      1,
      &malformed_action,
      100,
    ),
    Err(StateValueError::InvalidJson { .. })
  ));

  let extra_key_receipt = json!({
    "conversation_id": "C1",
    "extra": "forbidden",
    "message_id": "provider-message",
    "provider": "slack",
    "receipt_version": 1,
    "target_kind": "channel",
    "tenant": "workspace",
    "thread_id": null,
  })
  .to_string();
  let (evidence_json, evidence_digest) = operator_delivery_evidence(
    "provider_confirmed_delivered",
    "extra-key-receipt",
    "slack",
    "workspace",
    "channel",
    Some(&extra_key_receipt),
  );
  let extra_key_action = ScheduledDeliveryUnknownAction::ConfirmDelivered {
    provider_receipt: extra_key_receipt,
    evidence_json,
    evidence_digest,
  };
  assert!(matches!(
    SchedulerOperatorRequest::for_delivery_action(
      owner(),
      "extra-key-receipt",
      "delivery",
      1,
      1,
      &extra_key_action,
      100,
    ),
    Err(StateValueError::InvalidJson { .. })
  ));

  let (evidence_json, _) = operator_delivery_evidence(
    "provider_confirmed_no_write",
    "digest-mismatch",
    "slack",
    "workspace",
    "channel",
    None,
  );
  let digest_mismatch_action = ScheduledDeliveryUnknownAction::ConfirmNoWriteTerminal {
    evidence_json,
    evidence_digest: "f".repeat(64),
  };
  assert!(matches!(
    SchedulerOperatorRequest::for_delivery_action(
      owner(),
      "digest-mismatch",
      "delivery",
      1,
      1,
      &digest_mismatch_action,
      100,
    ),
    Err(StateValueError::InvalidSha256 { .. })
  ));

  let (evidence_json, evidence_digest) = operator_delivery_evidence(
    "provider_confirmed_delivered",
    "masquerading-no-write",
    "slack",
    "workspace",
    "channel",
    None,
  );
  let masquerading_action = ScheduledDeliveryUnknownAction::ConfirmNoWriteTerminal {
    evidence_json,
    evidence_digest,
  };
  assert!(matches!(
    SchedulerOperatorRequest::for_delivery_action(
      owner(),
      "masquerading-no-write",
      "delivery",
      1,
      1,
      &masquerading_action,
      100,
    ),
    Err(StateValueError::InvalidVersion)
  ));

  let temp = tempdir().expect("create tempdir");
  let store = StateStore::initialize(&temp.path().join("state"), None)
    .await
    .expect("initialize store");
  let unknown = prepare_operator_unknown_delivery(&store, "operator-target-binding", 110).await;
  for (request_id, provider, tenant, target_kind, conversation_id) in [
    ("provider-mismatch", "github", "workspace", "channel", "C1"),
    (
      "tenant-mismatch",
      "slack",
      "other-workspace",
      "channel",
      "C1",
    ),
    ("kind-mismatch", "slack", "workspace", "dm", "C1"),
    (
      "conversation-mismatch",
      "slack",
      "workspace",
      "channel",
      "C2",
    ),
  ] {
    let receipt =
      operator_provider_receipt(provider, tenant, target_kind, conversation_id, "message-1");
    let (evidence_json, evidence_digest) = operator_delivery_evidence(
      "provider_confirmed_delivered",
      request_id,
      provider,
      tenant,
      target_kind,
      Some(&receipt),
    );
    let action = ScheduledDeliveryUnknownAction::ConfirmDelivered {
      provider_receipt: receipt,
      evidence_json,
      evidence_digest,
    };
    let request = SchedulerOperatorRequest::for_delivery_action(
      owner(),
      request_id,
      unknown.binding.delivery_id(),
      unknown.binding.attempt(),
      unknown.binding.fence(),
      &action,
      120,
    )
    .expect("well-formed mismatched authority");
    assert!(matches!(
      store
        .operator_act_on_unknown_delivery(
          &request,
          unknown.binding.delivery_id(),
          unknown.binding.attempt(),
          unknown.binding.fence(),
          &action,
        )
        .await,
      Err(StateError::InvalidSchedulerState { .. })
    ));
  }
}

async fn operator_delivery_action_after_barrier(
  store: StateStore,
  barrier: Arc<Barrier>,
  request: SchedulerOperatorRequest,
  delivery_id: String,
  expected_attempt: i64,
  expected_fence: i64,
  action: ScheduledDeliveryUnknownAction,
) -> Result<SchedulerOperatorMutationOutcome, StateError> {
  barrier.wait().await;
  for _ in 0..20 {
    match store
      .operator_act_on_unknown_delivery(
        &request,
        &delivery_id,
        expected_attempt,
        expected_fence,
        &action,
      )
      .await
    {
      Err(error) if error.is_transient_storage_contention() => {
        tokio::time::sleep(Duration::from_millis(5)).await;
      }
      result => return result,
    }
  }
  store
    .operator_act_on_unknown_delivery(
      &request,
      &delivery_id,
      expected_attempt,
      expected_fence,
      &action,
    )
    .await
}

#[tokio::test]
async fn test_operator_delivery_exact_request_has_one_transition_across_two_stores() {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state");
  let first = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize first store");
  let second = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize second store");
  let unknown = prepare_operator_unknown_delivery(&first, "operator-delivery-race", 110).await;
  let receipt = operator_provider_receipt("slack", "workspace", "channel", "C1", "provider-race-1");
  let (evidence_json, evidence_digest) = operator_delivery_evidence(
    "provider_confirmed_delivered",
    "provider-race-case",
    "slack",
    "workspace",
    "channel",
    Some(&receipt),
  );
  let action = ScheduledDeliveryUnknownAction::ConfirmDelivered {
    provider_receipt: receipt,
    evidence_json,
    evidence_digest,
  };
  let request = SchedulerOperatorRequest::for_delivery_action(
    owner(),
    "delivery-race-request",
    unknown.binding.delivery_id(),
    unknown.binding.attempt(),
    unknown.binding.fence(),
    &action,
    120,
  )
  .expect("operator request");
  let barrier = Arc::new(Barrier::new(3));
  let first_task = tokio::spawn(operator_delivery_action_after_barrier(
    first,
    Arc::clone(&barrier),
    request.clone(),
    unknown.binding.delivery_id().to_owned(),
    unknown.binding.attempt(),
    unknown.binding.fence(),
    action.clone(),
  ));
  let second_task = tokio::spawn(operator_delivery_action_after_barrier(
    second,
    Arc::clone(&barrier),
    request,
    unknown.binding.delivery_id().to_owned(),
    unknown.binding.attempt(),
    unknown.binding.fence(),
    action,
  ));
  barrier.wait().await;
  let outcomes = [
    first_task.await.expect("first task").expect("first action"),
    second_task
      .await
      .expect("second task")
      .expect("second action"),
  ];
  assert_eq!(
    outcomes
      .iter()
      .filter(|outcome| **outcome == SchedulerOperatorMutationOutcome::Applied)
      .count(),
    1
  );
  assert_eq!(
    outcomes
      .iter()
      .filter(|outcome| **outcome == SchedulerOperatorMutationOutcome::Replay)
      .count(),
    1
  );
  let pool = SqlitePool::connect(&database_url(&state_dir))
    .await
    .expect("connect database");
  let counts: (i64, i64, i64, String) = sqlx::query_as(
    "select (select count(*) from scheduler_operator_actions where target_id = ?1), (select count(*) from scheduler_operator_action_consumptions where target_id = ?1), (select count(*) from scheduled_delivery_baselines where job_id = 'operator-delivery-race'), (select state from scheduled_run_deliveries where delivery_id = ?1)",
  )
  .bind(unknown.binding.delivery_id())
  .fetch_one(&pool)
  .await
  .expect("operator race authority");
  assert_eq!(counts, (1, 1, 1, "delivered".to_owned()));
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn test_operator_delivery_unknown_actions_preserve_authority_and_baselines() {
  let temp = tempdir().expect("create tempdir");
  let store = StateStore::initialize(&temp.path().join("state"), None)
    .await
    .expect("initialize store");

  let delivered = prepare_operator_unknown_delivery(&store, "operator-delivered", 110).await;
  let bypass_pool = SqlitePool::connect(&database_url(&temp.path().join("state")))
    .await
    .expect("connect bypass database");
  assert!(
    sqlx::query(
      "update scheduled_run_deliveries set state = 'delivered', provider_receipt = 'bypass', provider_outcome = 'confirmed_success', error_kind = null, error_message = null, updated_at = 119 where delivery_id = ?1 and state = 'delivery_unknown'",
    )
    .bind(delivered.binding.delivery_id())
    .execute(&bypass_pool)
    .await
    .is_err(),
    "direct SQL must not bypass operator authority"
  );
  let provider_receipt =
    operator_provider_receipt("slack", "workspace", "channel", "C1", "provider-message-1");
  let (delivered_evidence, delivered_evidence_digest) = operator_delivery_evidence(
    "provider_confirmed_delivered",
    "provider-case-delivered",
    "slack",
    "workspace",
    "channel",
    Some(&provider_receipt),
  );
  let delivered_action = ScheduledDeliveryUnknownAction::ConfirmDelivered {
    provider_receipt,
    evidence_json: delivered_evidence,
    evidence_digest: delivered_evidence_digest,
  };
  let delivered_request = SchedulerOperatorRequest::for_delivery_action(
    owner(),
    "confirm-delivered",
    delivered.binding.delivery_id(),
    delivered.binding.attempt(),
    delivered.binding.fence(),
    &delivered_action,
    120,
  )
  .expect("delivered authority");
  assert_eq!(
    store
      .operator_act_on_unknown_delivery(
        &delivered_request,
        delivered.binding.delivery_id(),
        delivered.binding.attempt(),
        delivered.binding.fence(),
        &delivered_action,
      )
      .await
      .expect("confirm delivered"),
    SchedulerOperatorMutationOutcome::Applied
  );
  assert_eq!(
    store
      .operator_act_on_unknown_delivery(
        &delivered_request,
        delivered.binding.delivery_id(),
        delivered.binding.attempt(),
        delivered.binding.fence(),
        &delivered_action,
      )
      .await
      .expect("replay delivered"),
    SchedulerOperatorMutationOutcome::Replay
  );
  let (conflicting_evidence, conflicting_evidence_digest) = operator_delivery_evidence(
    "operator_acknowledged_unknown",
    "conflicting-delivery-request",
    "slack",
    "workspace",
    "channel",
    None,
  );
  let conflicting_action = ScheduledDeliveryUnknownAction::AcknowledgeUnknown {
    evidence_json: conflicting_evidence,
    evidence_digest: conflicting_evidence_digest,
  };
  let conflicting_request = SchedulerOperatorRequest::for_delivery_action(
    owner(),
    "confirm-delivered",
    delivered.binding.delivery_id(),
    delivered.binding.attempt(),
    delivered.binding.fence(),
    &conflicting_action,
    120,
  )
  .expect("conflicting delivery request");
  assert_eq!(
    store
      .operator_act_on_unknown_delivery(
        &conflicting_request,
        delivered.binding.delivery_id(),
        delivered.binding.attempt(),
        delivered.binding.fence(),
        &conflicting_action,
      )
      .await
      .expect("conflicting delivery replay"),
    SchedulerOperatorMutationOutcome::Conflict
  );

  let no_write = prepare_operator_unknown_delivery(&store, "operator-no-write", 130).await;
  let (no_write_evidence, no_write_evidence_digest) = operator_delivery_evidence(
    "provider_confirmed_no_write",
    "provider-case-no-write",
    "slack",
    "workspace",
    "channel",
    None,
  );
  let no_write_action = ScheduledDeliveryUnknownAction::ConfirmNoWriteTerminal {
    evidence_json: no_write_evidence,
    evidence_digest: no_write_evidence_digest,
  };
  let no_write_request = SchedulerOperatorRequest::for_delivery_action(
    owner(),
    "confirm-no-write",
    no_write.binding.delivery_id(),
    no_write.binding.attempt(),
    no_write.binding.fence(),
    &no_write_action,
    140,
  )
  .expect("no-write authority");
  let stale_no_write_request = SchedulerOperatorRequest::for_delivery_action(
    owner(),
    "stale-no-write",
    no_write.binding.delivery_id(),
    no_write.binding.attempt(),
    no_write.binding.fence() + 1,
    &no_write_action,
    140,
  )
  .expect("stale no-write authority");
  assert_eq!(
    store
      .operator_act_on_unknown_delivery(
        &stale_no_write_request,
        no_write.binding.delivery_id(),
        no_write.binding.attempt(),
        no_write.binding.fence() + 1,
        &no_write_action,
      )
      .await
      .expect("stale no write"),
    SchedulerOperatorMutationOutcome::Conflict
  );
  assert_eq!(
    store
      .operator_act_on_unknown_delivery(
        &no_write_request,
        no_write.binding.delivery_id(),
        no_write.binding.attempt(),
        no_write.binding.fence(),
        &no_write_action,
      )
      .await
      .expect("confirm no write"),
    SchedulerOperatorMutationOutcome::Applied
  );

  let acknowledged = prepare_operator_unknown_delivery(&store, "operator-ack", 150).await;
  let (ack_evidence, ack_evidence_digest) = operator_delivery_evidence(
    "operator_acknowledged_unknown",
    "operator-case-ack",
    "slack",
    "workspace",
    "channel",
    None,
  );
  let ack_action = ScheduledDeliveryUnknownAction::AcknowledgeUnknown {
    evidence_json: ack_evidence,
    evidence_digest: ack_evidence_digest,
  };
  let ack_request = SchedulerOperatorRequest::for_delivery_action(
    owner(),
    "acknowledge-unknown",
    acknowledged.binding.delivery_id(),
    acknowledged.binding.attempt(),
    acknowledged.binding.fence(),
    &ack_action,
    160,
  )
  .expect("ack authority");
  assert_eq!(
    store
      .operator_act_on_unknown_delivery(
        &ack_request,
        acknowledged.binding.delivery_id(),
        acknowledged.binding.attempt(),
        acknowledged.binding.fence(),
        &ack_action,
      )
      .await
      .expect("acknowledge"),
    SchedulerOperatorMutationOutcome::Applied
  );

  let resend = prepare_operator_unknown_delivery(&store, "operator-resend", 170).await;
  let (resend_evidence, resend_evidence_digest) = operator_delivery_evidence(
    "operator_force_resend",
    "operator-case-resend",
    "slack",
    "workspace",
    "channel",
    None,
  );
  let resend_action = ScheduledDeliveryUnknownAction::ForceResend {
    evidence_json: resend_evidence,
    evidence_digest: resend_evidence_digest,
    duplicate_risk_acknowledged: true,
  };
  let resend_request = SchedulerOperatorRequest::for_delivery_action(
    owner(),
    "force-resend",
    resend.binding.delivery_id(),
    resend.binding.attempt(),
    resend.binding.fence(),
    &resend_action,
    180,
  )
  .expect("resend authority");
  assert_eq!(
    store
      .operator_act_on_unknown_delivery(
        &resend_request,
        resend.binding.delivery_id(),
        resend.binding.attempt(),
        resend.binding.fence(),
        &resend_action,
      )
      .await
      .expect("force resend"),
    SchedulerOperatorMutationOutcome::Applied
  );
  let claimed_resend = store
    .claim_next_scheduled_delivery("resend-worker", 181, 220)
    .await
    .expect("claim resend")
    .expect("resent delivery");
  assert_eq!(
    claimed_resend.binding.delivery_id(),
    resend.binding.delivery_id()
  );
  assert_eq!(
    claimed_resend.binding.attempt(),
    resend.binding.attempt() + 1
  );

  let pool = SqlitePool::connect(&database_url(&temp.path().join("state")))
    .await
    .expect("connect database");
  let baselines: (i64, i64, i64, i64) = sqlx::query_as(
    "select (select count(*) from scheduled_delivery_baselines where job_id = 'operator-delivered'), (select count(*) from scheduled_delivery_baselines where job_id = 'operator-no-write'), (select count(*) from scheduled_delivery_baselines where job_id = 'operator-ack'), (select count(*) from scheduled_delivery_baselines where job_id = 'operator-resend')",
  )
  .fetch_one(&pool)
  .await
  .expect("baseline counts");
  assert_eq!(baselines, (1, 0, 0, 0));

  let projections = store
    .list_scheduled_delivery_operator_projections(None, 100)
    .await
    .expect("delivery projections");
  let state_for = |job_id: &str| {
    projections
      .iter()
      .find(|delivery| delivery.job_id == job_id)
      .expect("projected delivery")
      .state
  };
  assert_eq!(
    state_for("operator-delivered"),
    ScheduledDeliveryState::Delivered
  );
  assert_eq!(
    state_for("operator-no-write"),
    ScheduledDeliveryState::FailedTerminal
  );
  assert_eq!(
    state_for("operator-ack"),
    ScheduledDeliveryState::DeliveryUnknown
  );
  let delivered_audit = store
    .list_scheduler_operator_actions("delivery", delivered.binding.delivery_id(), 10)
    .await
    .expect("delivery audit");
  assert_eq!(delivered_audit.len(), 1);
  assert!(delivered_audit[0].consumed);
  let ack_audit = store
    .list_scheduler_operator_actions("delivery", acknowledged.binding.delivery_id(), 10)
    .await
    .expect("ack audit");
  assert_eq!(ack_audit.len(), 1);
  assert!(!ack_audit[0].consumed);
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn test_delivered_baseline_conflict_rolls_back_terminal_authority_atomically() {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state");
  let store = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize store");
  let mut request = create_request("delivery-baseline-conflict", ScheduleSpec::once(110), 100);
  request.targets = vec![second_target("delivery-baseline-conflict")];
  store
    .create_scheduled_job(&request)
    .await
    .expect("create job");
  let run = complete_due_run(&store, "delivery-baseline-conflict", 110, 120).await;
  let pool = SqlitePool::connect(&database_url(&state_dir))
    .await
    .expect("connect database");
  let delivery_id: String =
    sqlx::query_scalar("select delivery_id from scheduled_run_deliveries where run_id = ?1")
      .bind(run.binding.run_id())
      .fetch_one(&pool)
      .await
      .expect("delivery id");
  let PreparedScheduledDelivery::Pending(payload) = store
    .prepare_scheduled_delivery(
      &delivery_id,
      "text/plain; charset=utf-8",
      "payload",
      1,
      121,
      SkippedNoneBaselinePolicy::DoNotAdvance,
    )
    .await
    .expect("prepare payload")
  else {
    panic!("first payload must remain pending");
  };
  let claim = store
    .claim_next_scheduled_delivery("delivery-worker", 122, 200)
    .await
    .expect("claim delivery")
    .expect("delivery claim");
  let competing_digest = test_sha256_hex("competing payload");
  sqlx::query(
    "insert into scheduled_delivery_baselines (job_id, target_identity_digest, target_snapshot_digest_algorithm, target_snapshot_digest, delivery_policy_version, render_version, hash_algorithm, accepted_payload_digest, source_delivery_id, source_run_id, source_result_id, source_result_hash, accepted_at, baseline_version) values ('delivery-baseline-conflict', ?1, 'sha256-v1', ?2, 1, 1, 'sha256-utf8-exact-v1', ?3, 'competing-delivery', 'competing-run', null, 'competing-result', 122, 1)",
  )
  .bind(payload.target_identity_digest())
  .bind(payload.target_snapshot_digest())
  .bind(&competing_digest)
  .execute(&pool)
  .await
  .expect("seed competing baseline");
  assert!(matches!(
    store
      .complete_scheduled_delivery_delivered(&claim.binding, "receipt", 123)
      .await,
    Err(StateError::ScheduledDeliveryBaselineConflict)
  ));
  let authority: (String, String, Option<String>, Option<String>, String, i64) = sqlx::query_as(
    "select delivery.state, attempt.state, delivery.provider_receipt, delivery.provider_outcome, baseline.source_delivery_id, baseline.baseline_version from scheduled_run_deliveries delivery join scheduled_delivery_attempts attempt on attempt.delivery_id = delivery.delivery_id and attempt.attempt = delivery.attempt join scheduled_delivery_baselines baseline on baseline.job_id = delivery.job_id and baseline.target_identity_digest = delivery.target_identity_digest and baseline.target_snapshot_digest_algorithm = delivery.target_snapshot_digest_algorithm and baseline.target_snapshot_digest = delivery.target_snapshot_digest and baseline.delivery_policy_version = delivery.delivery_policy_version and baseline.render_version = delivery.render_version and baseline.hash_algorithm = delivery.hash_algorithm where delivery.delivery_id = ?1",
  )
  .bind(&delivery_id)
  .fetch_one(&pool)
  .await
  .expect("read rolled back authority");
  assert_eq!(
    authority,
    (
      "sending".to_owned(),
      "sending".to_owned(),
      None,
      None,
      "competing-delivery".to_owned(),
      1
    )
  );
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
    "insert into scheduled_run_deliveries (delivery_id, run_id, job_id, target_identity_digest, target_json, state, delivery_policy_version, created_at, updated_at) values ('lease-delivery', ?1, 'ownership-a', 'identity', '{}', 'pending', 1, 111, 111)",
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
      "insert into scheduled_run_deliveries (delivery_id, run_id, job_id, target_identity_digest, target_json, state, delivery_policy_version, created_at, updated_at) values ('cross-job-delivery', ?1, 'ownership-b', 'identity', '{}', 'pending', 1, 111, 111)",
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
