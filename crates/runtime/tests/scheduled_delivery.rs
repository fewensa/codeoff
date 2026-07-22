use std::collections::VecDeque;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use codeoff_runtime::scheduled_delivery::{
  DeliveryProvider, DeliveryProviderOutcome, DeliveryProviderRequest, ProviderMessageIdentity,
  ScheduledDeliveryTickOutcome, run_scheduled_delivery_tick, run_scheduled_delivery_worker,
};
use codeoff_state::{
  AcceptedDeliveryBaselineIdentity, AttestedExecutionProfileSnapshot, CapabilityProfileSnapshot,
  CreateScheduledJob, DeliveryTargetSnapshot, PreparedScheduledDelivery, PrincipalKey,
  ScheduleSpec, ScheduledJobDefinition, ScheduledRunResult, SkippedNoneBaselinePolicy, StateStore,
};
use tempfile::{TempDir, tempdir};
use tokio::sync::{Notify, watch};

const TARGET_IDENTITY: &str = "0000000000000000000000000000000000000000000000000000000000000002";

#[derive(Debug, Clone, PartialEq, Eq)]
struct ObservedSend {
  body: String,
  target_json: String,
  idempotency_key: String,
}

struct FakeProvider {
  outcomes: Mutex<VecDeque<DeliveryProviderOutcome>>,
  observed: Mutex<Vec<ObservedSend>>,
}

impl FakeProvider {
  fn new(outcomes: impl IntoIterator<Item = DeliveryProviderOutcome>) -> Self {
    Self {
      outcomes: Mutex::new(outcomes.into_iter().collect()),
      observed: Mutex::new(Vec::new()),
    }
  }

  fn observed(&self) -> Vec<ObservedSend> {
    self.observed.lock().expect("observed sends").clone()
  }
}

#[async_trait]
impl DeliveryProvider for FakeProvider {
  async fn send(&self, request: DeliveryProviderRequest<'_>) -> DeliveryProviderOutcome {
    self
      .observed
      .lock()
      .expect("observed sends")
      .push(ObservedSend {
        body: request.payload.body().to_owned(),
        target_json: request.target_json.to_owned(),
        idempotency_key: request.idempotency_key.to_owned(),
      });
    self
      .outcomes
      .lock()
      .expect("provider outcomes")
      .pop_front()
      .expect("fake outcome")
  }
}

struct BlockingProvider {
  calls: AtomicUsize,
  started: Notify,
  release: Notify,
}

#[async_trait]
impl DeliveryProvider for BlockingProvider {
  async fn send(&self, _request: DeliveryProviderRequest<'_>) -> DeliveryProviderOutcome {
    self.calls.fetch_add(1, Ordering::SeqCst);
    self.started.notify_one();
    self.release.notified().await;
    success()
  }
}

fn success() -> DeliveryProviderOutcome {
  DeliveryProviderOutcome::ConfirmedSuccess(ProviderMessageIdentity {
    provider: "slack".to_owned(),
    tenant: "T1".to_owned(),
    conversation_id: "C1".to_owned(),
    thread_id: None,
    message_id: "200.000001".to_owned(),
  })
}

fn owner() -> PrincipalKey {
  PrincipalKey::new("user", "slack", "T1", "U1").expect("owner")
}

fn target(job_id: &str) -> DeliveryTargetSnapshot {
  DeliveryTargetSnapshot::new(
    format!("target-{job_id}"),
    "slack",
    "slack-default",
    "T1",
    "channel",
    r#"{"channel_id":"C1"}"#,
    1,
    "test-resolver-v1",
    TARGET_IDENTITY,
  )
  .expect("target")
}

async fn prepared_delivery(
  job_id: &str,
  body: &str,
) -> (
  TempDir,
  StateStore,
  String,
  codeoff_state::DeliveryPayloadSnapshot,
) {
  let temp = tempdir().expect("tempdir");
  let state_dir = temp.path().join("state");
  let store = StateStore::initialize(&state_dir, None)
    .await
    .expect("state");
  store
    .create_scheduled_job(&CreateScheduledJob {
      job_id: job_id.to_owned(),
      schedule_id: format!("schedule-{job_id}"),
      definition: ScheduledJobDefinition::new(1, r#"{"prompt":"check"}"#).expect("definition"),
      creator: owner(),
      owner: owner(),
      capability: CapabilityProfileSnapshot::new(1, "none", "{}").expect("capability"),
      targets: vec![target(job_id)],
      schedule: ScheduleSpec::fixed_interval(110, 10).expect("interval"),
      now: 100,
    })
    .await
    .expect("create");
  store
    .materialize_due_schedule(job_id, 0, 110)
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
    .expect("executing");
  store
    .complete_scheduled_run_success(
      &run.binding,
      &ScheduledRunResult::new(body, "").expect("result"),
      120,
    )
    .await
    .expect("complete run");
  let delivery_id = delivery_id(run.binding.run_id(), TARGET_IDENTITY);
  let PreparedScheduledDelivery::Pending(payload) = store
    .prepare_scheduled_delivery(
      &delivery_id,
      "text/markdown; charset=utf-8",
      body,
      1,
      121,
      SkippedNoneBaselinePolicy::DoNotAdvance,
    )
    .await
    .expect("prepare")
  else {
    panic!("Slack target must remain pending");
  };
  (temp, store, delivery_id, payload)
}

fn delivery_id(run_id: &str, identity: &str) -> String {
  let mut key = String::from("intent:v1:");
  for byte in run_id.as_bytes() {
    write!(&mut key, "{byte:02x}").expect("write id");
  }
  write!(&mut key, ":{identity}:1").expect("write identity");
  key
}

fn shutdown() -> watch::Receiver<bool> {
  watch::channel(false).1
}

fn baseline_identity(
  job_id: &str,
  payload: &codeoff_state::DeliveryPayloadSnapshot,
) -> AcceptedDeliveryBaselineIdentity {
  AcceptedDeliveryBaselineIdentity {
    job_id: job_id.to_owned(),
    target_identity_digest: payload.target_identity_digest().to_owned(),
    target_snapshot_digest_algorithm: "sha256-v1".to_owned(),
    target_snapshot_digest: payload.target_snapshot_digest().to_owned(),
    delivery_policy_version: 1,
    render_version: 1,
    hash_algorithm: "sha256-utf8-exact-v1".to_owned(),
  }
}

#[tokio::test]
async fn confirmed_success_persists_identity_and_advances_baseline() {
  let (_temp, store, _, payload) = prepared_delivery("delivery-success", "exact body  \n").await;
  let provider = FakeProvider::new([success()]);
  assert_eq!(
    run_scheduled_delivery_tick(&store, &provider, "worker", 122, shutdown())
      .await
      .expect("tick"),
    ScheduledDeliveryTickOutcome::Delivered
  );
  let observed = provider.observed();
  assert_eq!(observed.len(), 1);
  assert_eq!(observed[0].body.as_bytes(), b"exact body  \n");
  assert_eq!(
    store
      .get_accepted_delivery_baseline(&baseline_identity("delivery-success", &payload))
      .await
      .expect("baseline")
      .expect("accepted")
      .accepted_payload_digest,
    payload.digest()
  );
}

#[tokio::test]
async fn retry_reuses_exact_payload_target_and_idempotency_without_agent_work() {
  let (_temp, store, _, payload) = prepared_delivery("delivery-retry", "retry body").await;
  let agent_invocations = AtomicUsize::new(1);
  let provider = FakeProvider::new([
    DeliveryProviderOutcome::ConfirmedNoWriteRetryable {
      retry_after_seconds: Some(10),
      error_kind: "rate_limited".to_owned(),
    },
    success(),
  ]);
  assert_eq!(
    run_scheduled_delivery_tick(&store, &provider, "worker-a", 122, shutdown())
      .await
      .expect("first tick"),
    ScheduledDeliveryTickOutcome::RetryDeferred
  );
  assert_eq!(
    run_scheduled_delivery_tick(&store, &provider, "worker-b", 132, shutdown())
      .await
      .expect("retry tick"),
    ScheduledDeliveryTickOutcome::Delivered
  );
  let observed = provider.observed();
  assert_eq!(observed.len(), 2);
  assert_eq!(observed[0], observed[1]);
  assert_eq!(agent_invocations.load(Ordering::SeqCst), 1);
  assert_eq!(observed[0].body, payload.body());
}

#[tokio::test]
async fn terminal_and_ambiguous_outcomes_never_retry_or_advance_baseline() {
  for (suffix, outcome, expected) in [
    (
      "terminal",
      DeliveryProviderOutcome::ConfirmedNoWriteTerminal {
        error_kind: "invalid_auth".to_owned(),
      },
      ScheduledDeliveryTickOutcome::FailedTerminal,
    ),
    (
      "unknown",
      DeliveryProviderOutcome::AmbiguousPostWrite {
        error_kind: "write_then_disconnect".to_owned(),
      },
      ScheduledDeliveryTickOutcome::DeliveryUnknown,
    ),
  ] {
    let job_id = format!("delivery-{suffix}");
    let (_temp, store, _, payload) = prepared_delivery(&job_id, "body").await;
    let provider = FakeProvider::new([outcome]);
    assert_eq!(
      run_scheduled_delivery_tick(&store, &provider, "worker", 122, shutdown())
        .await
        .expect("terminal tick"),
      expected
    );
    assert_eq!(
      run_scheduled_delivery_tick(&store, &provider, "worker", 500, shutdown())
        .await
        .expect("no retry"),
      ScheduledDeliveryTickOutcome::Idle
    );
    assert_eq!(provider.observed().len(), 1);
    assert!(
      store
        .get_accepted_delivery_baseline(&baseline_identity(&job_id, &payload))
        .await
        .expect("baseline")
        .is_none()
    );
  }
}

#[tokio::test]
async fn cancellation_after_dispatch_is_unknown_and_not_retried() {
  let (_temp, store, _, payload) = prepared_delivery("delivery-cancel", "body").await;
  let provider = Arc::new(BlockingProvider {
    calls: AtomicUsize::new(0),
    started: Notify::new(),
    release: Notify::new(),
  });
  let (shutdown_tx, shutdown_rx) = watch::channel(false);
  let task_store = store.clone();
  let task_provider = Arc::clone(&provider);
  let task = tokio::spawn(async move {
    run_scheduled_delivery_tick(
      &task_store,
      task_provider.as_ref(),
      "worker",
      122,
      shutdown_rx,
    )
    .await
  });
  provider.started.notified().await;
  shutdown_tx.send(true).expect("shutdown");
  assert_eq!(
    task.await.expect("task").expect("tick"),
    ScheduledDeliveryTickOutcome::DeliveryUnknown
  );
  assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
  assert!(
    store
      .get_accepted_delivery_baseline(&baseline_identity("delivery-cancel", &payload))
      .await
      .expect("baseline")
      .is_none()
  );
}

#[tokio::test]
async fn stale_fence_cannot_overwrite_reclaimed_unknown_or_advance_baseline() {
  let (_temp, store, _, payload) = prepared_delivery("delivery-stale", "body").await;
  let provider = Arc::new(BlockingProvider {
    calls: AtomicUsize::new(0),
    started: Notify::new(),
    release: Notify::new(),
  });
  let (_shutdown_tx, shutdown_rx) = watch::channel(false);
  let task_store = store.clone();
  let task_provider = Arc::clone(&provider);
  let task = tokio::spawn(async move {
    run_scheduled_delivery_tick(
      &task_store,
      task_provider.as_ref(),
      "worker",
      122,
      shutdown_rx,
    )
    .await
  });
  provider.started.notified().await;
  assert_eq!(
    store
      .reclaim_expired_scheduled_deliveries(1_000, 1)
      .await
      .expect("reclaim"),
    1
  );
  provider.release.notify_one();
  assert_eq!(
    task.await.expect("task").expect("tick"),
    ScheduledDeliveryTickOutcome::LostFence
  );
  assert!(
    store
      .get_accepted_delivery_baseline(&baseline_identity("delivery-stale", &payload))
      .await
      .expect("baseline")
      .is_none()
  );
}

#[tokio::test]
async fn two_workers_make_one_provider_call_for_one_delivery() {
  let (_temp, store, _, _) = prepared_delivery("delivery-two-workers", "body").await;
  let provider = Arc::new(FakeProvider::new([success()]));
  let first_store = store.clone();
  let first_provider = Arc::clone(&provider);
  let first = tokio::spawn(async move {
    run_scheduled_delivery_tick(
      &first_store,
      first_provider.as_ref(),
      "worker-a",
      122,
      shutdown(),
    )
    .await
  });
  let second_store = store.clone();
  let second_provider = Arc::clone(&provider);
  let second = tokio::spawn(async move {
    run_scheduled_delivery_tick(
      &second_store,
      second_provider.as_ref(),
      "worker-b",
      122,
      shutdown(),
    )
    .await
  });
  let outcomes = [
    first.await.expect("first").expect("first tick"),
    second.await.expect("second").expect("second tick"),
  ];
  assert_eq!(
    outcomes
      .iter()
      .filter(|outcome| **outcome == ScheduledDeliveryTickOutcome::Delivered)
      .count(),
    1
  );
  assert_eq!(provider.observed().len(), 1);
}

#[tokio::test]
async fn shutdown_during_preclaim_storage_wait_stops_without_dispatch() {
  let (_temp, store, _, _) = prepared_delivery("delivery-cancel-before", "body").await;
  let lock = store
    .acquire_exclusive_storage_lock_for_tests()
    .await
    .expect("exclusive lock");
  let provider = Arc::new(FakeProvider::new([]));
  let (shutdown_tx, shutdown_rx) = watch::channel(false);
  let task_store = store.clone();
  let task_provider = Arc::clone(&provider);
  let task = tokio::spawn(async move {
    run_scheduled_delivery_tick(
      &task_store,
      task_provider.as_ref(),
      "worker",
      122,
      shutdown_rx,
    )
    .await
  });
  tokio::task::yield_now().await;
  shutdown_tx.send(true).expect("shutdown");
  lock.release().await.expect("release lock");
  assert_eq!(
    task.await.expect("task").expect("tick"),
    ScheduledDeliveryTickOutcome::Cancelled
  );
  assert!(provider.observed().is_empty());
}

#[tokio::test]
async fn worker_shutdown_joins_in_flight_send_without_new_claims() {
  let (_temp, store, _, _) = prepared_delivery("delivery-worker-shutdown", "body").await;
  let provider = Arc::new(BlockingProvider {
    calls: AtomicUsize::new(0),
    started: Notify::new(),
    release: Notify::new(),
  });
  let (shutdown_tx, shutdown_rx) = watch::channel(false);
  let task_store = store;
  let task_provider: Arc<dyn DeliveryProvider> = provider.clone();
  let task = tokio::spawn(run_scheduled_delivery_worker(
    task_store,
    task_provider,
    "worker".to_owned(),
    shutdown_rx,
  ));
  provider.started.notified().await;
  shutdown_tx.send(true).expect("shutdown");
  tokio::time::timeout(Duration::from_secs(1), task)
    .await
    .expect("worker join deadline")
    .expect("worker task")
    .expect("worker result");
  assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn unchanged_payload_skips_without_provider_call() {
  let (_temp, store, _, first_payload) = prepared_delivery("delivery-unchanged", "same body").await;
  let first = FakeProvider::new([success()]);
  assert_eq!(
    run_scheduled_delivery_tick(&store, &first, "worker", 122, shutdown())
      .await
      .expect("first tick"),
    ScheduledDeliveryTickOutcome::Delivered
  );
  store
    .materialize_due_schedule("delivery-unchanged", 0, 120)
    .await
    .expect("second occurrence");
  let run = store
    .claim_next_scheduled_run("run-worker", 123, 200)
    .await
    .expect("claim second run")
    .expect("second run");
  let profile =
    AttestedExecutionProfileSnapshot::new(1, "{}", "sha256-v1", "profile").expect("profile");
  store
    .mark_scheduled_run_executing(&run.binding, &profile, 124)
    .await
    .expect("executing");
  store
    .complete_scheduled_run_success(
      &run.binding,
      &ScheduledRunResult::new("same body", "").expect("result"),
      125,
    )
    .await
    .expect("complete second run");
  let delivery_id = delivery_id(run.binding.run_id(), TARGET_IDENTITY);
  assert!(matches!(
    store
      .prepare_scheduled_delivery(
        &delivery_id,
        "text/markdown; charset=utf-8",
        "same body",
        1,
        126,
        SkippedNoneBaselinePolicy::DoNotAdvance,
      )
      .await
      .expect("prepare second delivery"),
    PreparedScheduledDelivery::SkippedUnchanged(_) | PreparedScheduledDelivery::Pending(_)
  ));
  let provider = FakeProvider::new([]);
  assert_eq!(
    run_scheduled_delivery_tick(&store, &provider, "worker", 127, shutdown())
      .await
      .expect("unchanged tick"),
    ScheduledDeliveryTickOutcome::Idle
  );
  assert!(provider.observed().is_empty());
  assert!(
    store
      .get_accepted_delivery_baseline(&baseline_identity("delivery-unchanged", &first_payload))
      .await
      .expect("baseline")
      .is_some()
  );
}
