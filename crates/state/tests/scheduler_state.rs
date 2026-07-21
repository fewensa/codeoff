use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;

use codeoff_state::{
  CapabilityProfileSnapshot, CreateScheduledJob, DeliveryTargetSnapshot, IdempotencyDecision,
  MaterializationOutcome, OccurrenceError, PrincipalKey, ScheduleMutationIdempotency, ScheduleSpec,
  ScheduledJobDefinition, ScheduledJobMutation, ScheduledJobStatus, StateError, StateStore,
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
  DeliveryTargetSnapshot {
    target_id: format!("target-{job}"),
    provider: "none".to_owned(),
    connector: "none".to_owned(),
    tenant: "none".to_owned(),
    kind: "none".to_owned(),
    address_json: "{}".to_owned(),
    resolver_version: 1,
    resolver_digest: "resolver-v1".to_owned(),
    identity_digest: "none-v1".to_owned(),
  }
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
  assert_eq!(job.definition.version, 2);
  assert_eq!(job.next_run_at, Some(250));
}

#[tokio::test]
async fn test_schedule_idempotency_replays_exact_response_and_detects_conflict() {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state");
  let store = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize state store");
  let idempotency = mutation_idempotency("request-1", "digest-a");
  assert_eq!(
    store
      .claim_schedule_idempotency("create", &idempotency, 100)
      .await
      .expect("claim"),
    IdempotencyDecision::Claimed
  );
  assert_eq!(
    store
      .claim_schedule_idempotency("create", &idempotency, 100)
      .await
      .expect("in progress"),
    IdempotencyDecision::InProgress
  );
  let conflicting = mutation_idempotency("request-1", "digest-b");
  assert_eq!(
    store
      .claim_schedule_idempotency("create", &conflicting, 100)
      .await
      .expect("conflict"),
    IdempotencyDecision::Conflict
  );
  assert!(
    store
      .complete_schedule_idempotency("create", &idempotency, 101)
      .await
      .expect("complete")
  );
  assert_eq!(
    store
      .claim_schedule_idempotency("create", &idempotency, 102)
      .await
      .expect("replay"),
    IdempotencyDecision::Replay(r#"{"job_id":"stable"}"#.to_owned())
  );
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
  assert_eq!(
    store
      .claim_schedule_idempotency("pause", &idempotency, 100)
      .await
      .expect("claim in progress"),
    IdempotencyDecision::Claimed
  );
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
async fn test_current_schema_upgrades_forward_and_repeated_initialize_is_safe() {
  let temp = tempdir().expect("create tempdir");
  let old_migrations = temp.path().join("old-migrations");
  std::fs::create_dir(&old_migrations).expect("create migration fixture");
  let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
  for entry in std::fs::read_dir(source).expect("read migrations") {
    let entry = entry.expect("migration entry");
    if entry.file_name() != "20260721000000_scheduler.sql" {
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
    "select count(*) from _sqlx_migrations where version = 20260721000000 and success = true",
  )
  .fetch_one(&pool)
  .await
  .expect("query scheduler migration");
  assert_eq!(scheduler_migrations, 1);
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
async fn test_two_independent_stores_share_idempotency_digest_authority() {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state");
  let first = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize first store");
  let second = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize second store");
  let idempotency = mutation_idempotency("request-race", "same");
  let barrier = Arc::new(Barrier::new(3));
  let first_barrier = Arc::clone(&barrier);
  let first_idempotency = idempotency.clone();
  let first_task = tokio::spawn(async move {
    first_barrier.wait().await;
    first
      .claim_schedule_idempotency("update", &first_idempotency, 100)
      .await
  });
  let second_barrier = Arc::clone(&barrier);
  let second_task = tokio::spawn(async move {
    second_barrier.wait().await;
    second
      .claim_schedule_idempotency("update", &idempotency, 100)
      .await
  });
  barrier.wait().await;
  let decisions = [
    first_task
      .await
      .expect("first task")
      .expect("first decision"),
    second_task
      .await
      .expect("second task")
      .expect("second decision"),
  ];
  assert!(decisions.contains(&IdempotencyDecision::Claimed));
  assert!(decisions.contains(&IdempotencyDecision::InProgress));
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
    "explain query plan select job_id from schedules where next_run_at <= 200 order by next_run_at, job_id",
  )
  .fetch_all(&pool)
  .await
  .expect("query plan");
  assert!(plan.iter().any(|row| {
    row
      .try_get::<String, _>("detail")
      .is_ok_and(|detail| detail.contains("idx_schedules_due"))
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
}

#[tokio::test]
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
    "insert into scheduled_run_deliveries (delivery_id, run_id, target_identity_digest, target_json, state, delivery_policy_version, render_version, hash_algorithm, payload_digest, expected_baseline_version, created_at, updated_at) values ('delivery-a', ?1, 'none-v1', '{}', 'delivered', 1, 1, 'sha256-utf8-exact-v1', 'payload-a', 0, 112, 112)",
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
