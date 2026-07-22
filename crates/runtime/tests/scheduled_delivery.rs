use std::collections::VecDeque;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use codeoff_runtime::scheduled_delivery::{
  DeliveryClock, DeliveryProvider, DeliveryProviderOutcome, DeliveryProviderReadiness,
  DeliveryProviderReadinessRequest, DeliveryProviderRequest, ProviderMessageIdentity,
  ScheduledDeliveryTickOutcome, prepare_next_scheduled_delivery,
  run_scheduled_delivery_tick_with_clock, run_scheduled_delivery_worker_with_clock,
};
use codeoff_state::{
  AcceptedDeliveryBaselineIdentity, AttestedExecutionProfileSnapshot, CapabilityProfileSnapshot,
  CreateScheduledJob, DeliveryTargetSnapshot, PreparedScheduledDelivery, PrincipalKey,
  ScheduleSpec, ScheduledJobDefinition, ScheduledRunResult, SkippedNoneBaselinePolicy, StateStore,
};
use sha2::{Digest, Sha256};
use tempfile::{TempDir, tempdir};
use tokio::sync::{Notify, watch};

const NONE_TARGET_IDENTITY: &str =
  "0000000000000000000000000000000000000000000000000000000000000001";
const TARGET_IDENTITY: &str = "0000000000000000000000000000000000000000000000000000000000000002";
const SECOND_TARGET_IDENTITY: &str =
  "0000000000000000000000000000000000000000000000000000000000000003";

#[derive(Debug, Clone, PartialEq, Eq)]
struct ObservedSend {
  body: String,
  target_json: String,
  idempotency_key: String,
}

struct FakeProvider {
  readiness: Mutex<VecDeque<DeliveryProviderReadiness>>,
  readiness_calls: AtomicUsize,
  outcomes: Mutex<VecDeque<DeliveryProviderOutcome>>,
  observed: Mutex<Vec<ObservedSend>>,
}

impl FakeProvider {
  fn new(outcomes: impl IntoIterator<Item = DeliveryProviderOutcome>) -> Self {
    Self {
      readiness: Mutex::new(VecDeque::new()),
      readiness_calls: AtomicUsize::new(0),
      outcomes: Mutex::new(outcomes.into_iter().collect()),
      observed: Mutex::new(Vec::new()),
    }
  }

  fn observed(&self) -> Vec<ObservedSend> {
    self.observed.lock().expect("observed sends").clone()
  }

  fn with_readiness(self, readiness: impl IntoIterator<Item = DeliveryProviderReadiness>) -> Self {
    *self.readiness.lock().expect("readiness") = readiness.into_iter().collect();
    self
  }
}

#[async_trait]
impl DeliveryProvider for FakeProvider {
  async fn readiness(
    &self,
    _request: DeliveryProviderReadinessRequest<'_>,
  ) -> DeliveryProviderReadiness {
    self.readiness_calls.fetch_add(1, Ordering::SeqCst);
    self
      .readiness
      .lock()
      .expect("readiness")
      .pop_front()
      .unwrap_or(DeliveryProviderReadiness::Ready)
  }

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

struct BlockingReadinessProvider {
  readiness_started: Notify,
  release_readiness: Notify,
  sends: AtomicUsize,
}

struct ExactReadinessProvider {
  readiness_started: Notify,
  release_readiness: Notify,
  readiness_delivery_ids: Mutex<Vec<String>>,
  sends: AtomicUsize,
}

struct PendingReadinessProvider {
  started: Notify,
}

#[async_trait]
impl DeliveryProvider for BlockingReadinessProvider {
  async fn readiness(
    &self,
    _request: DeliveryProviderReadinessRequest<'_>,
  ) -> DeliveryProviderReadiness {
    self.readiness_started.notify_one();
    self.release_readiness.notified().await;
    DeliveryProviderReadiness::Ready
  }

  async fn send(&self, _request: DeliveryProviderRequest<'_>) -> DeliveryProviderOutcome {
    self.sends.fetch_add(1, Ordering::SeqCst);
    success()
  }
}

#[async_trait]
impl DeliveryProvider for ExactReadinessProvider {
  async fn readiness(
    &self,
    request: DeliveryProviderReadinessRequest<'_>,
  ) -> DeliveryProviderReadiness {
    self
      .readiness_delivery_ids
      .lock()
      .expect("readiness ids")
      .push(request.delivery_id.to_owned());
    self.readiness_started.notify_one();
    self.release_readiness.notified().await;
    DeliveryProviderReadiness::Ready
  }

  async fn send(&self, _request: DeliveryProviderRequest<'_>) -> DeliveryProviderOutcome {
    self.sends.fetch_add(1, Ordering::SeqCst);
    success()
  }
}

#[async_trait]
impl DeliveryProvider for PendingReadinessProvider {
  async fn readiness(
    &self,
    _request: DeliveryProviderReadinessRequest<'_>,
  ) -> DeliveryProviderReadiness {
    self.started.notify_one();
    std::future::pending().await
  }

  async fn send(&self, _request: DeliveryProviderRequest<'_>) -> DeliveryProviderOutcome {
    panic!("timed-out readiness must not dispatch")
  }
}

struct PendingProvider {
  started: Notify,
}

struct PanicProvider;

#[async_trait]
impl DeliveryProvider for PanicProvider {
  async fn readiness(
    &self,
    _request: DeliveryProviderReadinessRequest<'_>,
  ) -> DeliveryProviderReadiness {
    DeliveryProviderReadiness::Ready
  }

  async fn send(&self, _request: DeliveryProviderRequest<'_>) -> DeliveryProviderOutcome {
    panic!("scheduled provider panic")
  }
}

#[async_trait]
impl DeliveryProvider for PendingProvider {
  async fn readiness(
    &self,
    _request: DeliveryProviderReadinessRequest<'_>,
  ) -> DeliveryProviderReadiness {
    DeliveryProviderReadiness::Ready
  }

  async fn send(&self, _request: DeliveryProviderRequest<'_>) -> DeliveryProviderOutcome {
    self.started.notify_one();
    std::future::pending().await
  }
}

#[async_trait]
impl DeliveryProvider for BlockingProvider {
  async fn readiness(
    &self,
    _request: DeliveryProviderReadinessRequest<'_>,
  ) -> DeliveryProviderReadiness {
    DeliveryProviderReadiness::Ready
  }

  async fn send(&self, _request: DeliveryProviderRequest<'_>) -> DeliveryProviderOutcome {
    self.calls.fetch_add(1, Ordering::SeqCst);
    self.started.notify_one();
    self.release.notified().await;
    success()
  }
}

struct TestClock(AtomicI64);

impl DeliveryClock for TestClock {
  fn now_unix_seconds(&self) -> i64 {
    self.0.load(Ordering::SeqCst)
  }
}

fn clock(now: i64) -> Arc<dyn DeliveryClock> {
  Arc::new(TestClock(AtomicI64::new(now)))
}

struct TokioClock {
  base: i64,
  started: tokio::time::Instant,
}

struct CountingStepClock {
  next: AtomicI64,
  calls: Arc<AtomicUsize>,
  values: Arc<Mutex<Vec<i64>>>,
}

impl DeliveryClock for CountingStepClock {
  fn now_unix_seconds(&self) -> i64 {
    self.calls.fetch_add(1, Ordering::SeqCst);
    let value = self.next.fetch_add(1, Ordering::SeqCst);
    self.values.lock().expect("clock values").push(value);
    value
  }
}

impl TokioClock {
  fn new(base: i64) -> Self {
    Self {
      base,
      started: tokio::time::Instant::now(),
    }
  }
}

impl DeliveryClock for TokioClock {
  fn now_unix_seconds(&self) -> i64 {
    self
      .base
      .saturating_add(i64::try_from(self.started.elapsed().as_secs()).unwrap_or(i64::MAX))
  }
}

struct GateClock {
  now: i64,
  calls: AtomicUsize,
  gate_call: usize,
  reached: Mutex<Option<mpsc::Sender<()>>>,
  release: Mutex<mpsc::Receiver<()>>,
}

impl DeliveryClock for GateClock {
  fn now_unix_seconds(&self) -> i64 {
    let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
    if call == self.gate_call {
      if let Some(reached) = self.reached.lock().expect("gate reached").take() {
        reached.send(()).expect("report clock gate");
      }
      self
        .release
        .lock()
        .expect("gate release")
        .recv()
        .expect("release clock gate");
    }
    self.now
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
  slack_target(job_id, TARGET_IDENTITY, "C1")
}

fn slack_target(job_id: &str, identity: &str, channel_id: &str) -> DeliveryTargetSnapshot {
  DeliveryTargetSnapshot::new(
    format!("target-{job_id}-{identity}"),
    "slack",
    "slack-default",
    "T1",
    "channel",
    format!(r#"{{"channel_id":"{channel_id}"}}"#),
    1,
    "test-resolver-v1",
    identity,
  )
  .expect("target")
}

fn none_target(job_id: &str) -> DeliveryTargetSnapshot {
  DeliveryTargetSnapshot::new(
    format!("target-{job_id}-none"),
    "none",
    "none",
    "none",
    "none",
    "{}",
    1,
    "none-v1",
    NONE_TARGET_IDENTITY,
  )
  .expect("none target")
}

fn sha256_hex(value: &str) -> String {
  let mut digest = Sha256::new();
  digest.update(value.as_bytes());
  let mut encoded = String::with_capacity(64);
  for byte in digest.finalize() {
    write!(&mut encoded, "{byte:02x}").expect("write digest");
  }
  encoded
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
  let (temp, store, delivery_id) = completed_delivery_intent(job_id, body).await;
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

async fn completed_delivery_intent(job_id: &str, body: &str) -> (TempDir, StateStore, String) {
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
  (temp, store, delivery_id)
}

async fn prepare_next_delivery(store: &StateStore, job_id: &str, body: &str) -> String {
  store
    .materialize_due_schedule(job_id, 0, 120)
    .await
    .expect("next occurrence");
  let run = store
    .claim_next_scheduled_run("run-worker-next", 123, 200)
    .await
    .expect("claim next run")
    .expect("next run");
  let profile =
    AttestedExecutionProfileSnapshot::new(1, "{}", "sha256-v1", "profile").expect("profile");
  store
    .mark_scheduled_run_executing(&run.binding, &profile, 124)
    .await
    .expect("executing next run");
  store
    .complete_scheduled_run_success(
      &run.binding,
      &ScheduledRunResult::new(body, "").expect("result"),
      125,
    )
    .await
    .expect("complete next run");
  let delivery_id = delivery_id(run.binding.run_id(), TARGET_IDENTITY);
  assert!(matches!(
    store
      .prepare_scheduled_delivery(
        &delivery_id,
        "text/markdown; charset=utf-8",
        body,
        1,
        126,
        SkippedNoneBaselinePolicy::DoNotAdvance,
      )
      .await
      .expect("prepare next delivery"),
    PreparedScheduledDelivery::Pending(_)
  ));
  delivery_id
}

async fn wait_for_delivery_lease_at_least(store: &StateStore, delivery_id: &str, minimum: i64) {
  tokio::time::timeout(Duration::from_secs(1), async {
    loop {
      match store.scheduled_delivery_lease_for_tests(delivery_id).await {
        Ok(Some(lease_expires_at)) if lease_expires_at >= minimum => return,
        Ok(_) | Err(_) => tokio::task::yield_now().await,
      }
    }
  })
  .await
  .expect("heartbeat lease extension");
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
    run_scheduled_delivery_tick_with_clock(&store, &provider, "worker", clock(122), shutdown())
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
#[allow(clippy::too_many_lines)]
async fn committed_multi_target_result_survives_restart_and_delivers_independently() {
  let temp = tempdir().expect("tempdir");
  let state_dir = temp.path().join("state");
  let store = StateStore::initialize(&state_dir, None)
    .await
    .expect("state");
  let job_id = "delivery-multi-restart";
  let body = "exact UTF-8: 測試 e\u{0301}  \n";
  store
    .create_scheduled_job(&CreateScheduledJob {
      job_id: job_id.to_owned(),
      schedule_id: format!("schedule-{job_id}"),
      definition: ScheduledJobDefinition::new(1, r#"{"prompt":"check"}"#).expect("definition"),
      creator: owner(),
      owner: owner(),
      capability: CapabilityProfileSnapshot::new(1, "none", "{}").expect("capability"),
      targets: vec![
        slack_target(job_id, TARGET_IDENTITY, "C1"),
        slack_target(job_id, SECOND_TARGET_IDENTITY, "C2"),
      ],
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
  let first_run_id = run.binding.run_id().to_owned();
  let profile =
    AttestedExecutionProfileSnapshot::new(1, "{}", "sha256-v1", "profile").expect("profile");
  store
    .mark_scheduled_run_executing(&run.binding, &profile, 112)
    .await
    .expect("executing");
  store
    .complete_scheduled_run_success(
      &run.binding,
      &ScheduledRunResult::new(body, "accepted context").expect("result"),
      120,
    )
    .await
    .expect("complete run");
  drop(store);

  let restarted = StateStore::initialize(&state_dir, None)
    .await
    .expect("restart state");
  let agent_invocations = AtomicUsize::new(1);
  let provider = FakeProvider::new([
    success(),
    DeliveryProviderOutcome::AmbiguousPostWrite {
      error_kind: "write_then_disconnect".to_owned(),
    },
    success(),
  ]);
  assert_eq!(
    run_scheduled_delivery_tick_with_clock(
      &restarted,
      &provider,
      "delivery-worker-a",
      clock(122),
      shutdown(),
    )
    .await
    .expect("first target"),
    ScheduledDeliveryTickOutcome::Delivered
  );
  assert_eq!(
    run_scheduled_delivery_tick_with_clock(
      &restarted,
      &provider,
      "delivery-worker-b",
      clock(123),
      shutdown(),
    )
    .await
    .expect("second target"),
    ScheduledDeliveryTickOutcome::DeliveryUnknown
  );
  assert_eq!(
    restarted
      .scheduled_run_state_for_tests(&first_run_id)
      .await
      .expect("run state"),
    "succeeded"
  );
  assert_eq!(agent_invocations.load(Ordering::SeqCst), 1);

  let first_delivery_id = delivery_id(&first_run_id, TARGET_IDENTITY);
  let second_delivery_id = delivery_id(&first_run_id, SECOND_TARGET_IDENTITY);
  assert_eq!(
    restarted
      .scheduled_delivery_authority_for_tests(&first_delivery_id)
      .await
      .expect("first authority"),
    ("delivered".to_owned(), 1, 1, 1)
  );
  assert_eq!(
    restarted
      .scheduled_delivery_authority_for_tests(&second_delivery_id)
      .await
      .expect("second authority"),
    ("delivery_unknown".to_owned(), 1, 1, 1)
  );
  let observed = provider.observed();
  assert_eq!(observed.len(), 2);
  assert_eq!(observed[0].body.as_bytes(), body.as_bytes());
  assert_eq!(observed[1].body.as_bytes(), body.as_bytes());
  assert!(observed[0].target_json.contains(TARGET_IDENTITY));
  assert!(observed[1].target_json.contains(SECOND_TARGET_IDENTITY));
  let delivered_identity = AcceptedDeliveryBaselineIdentity {
    job_id: job_id.to_owned(),
    target_identity_digest: TARGET_IDENTITY.to_owned(),
    target_snapshot_digest_algorithm: "sha256-v1".to_owned(),
    target_snapshot_digest: sha256_hex(&observed[0].target_json),
    delivery_policy_version: 1,
    render_version: 1,
    hash_algorithm: "sha256-utf8-exact-v1".to_owned(),
  };
  let unknown_identity = AcceptedDeliveryBaselineIdentity {
    target_identity_digest: SECOND_TARGET_IDENTITY.to_owned(),
    target_snapshot_digest: sha256_hex(&observed[1].target_json),
    ..delivered_identity.clone()
  };
  assert!(
    restarted
      .get_accepted_delivery_baseline(&delivered_identity)
      .await
      .expect("delivered baseline")
      .is_some()
  );
  assert!(
    restarted
      .get_accepted_delivery_baseline(&unknown_identity)
      .await
      .expect("unknown baseline")
      .is_none()
  );

  restarted
    .materialize_due_schedule(job_id, 0, 120)
    .await
    .expect("next occurrence");
  let next_run = restarted
    .claim_next_scheduled_run("next-run-worker", 124, 200)
    .await
    .expect("claim next run")
    .expect("next run");
  restarted
    .mark_scheduled_run_executing(&next_run.binding, &profile, 125)
    .await
    .expect("execute next run");
  restarted
    .complete_scheduled_run_success(
      &next_run.binding,
      &ScheduledRunResult::new(body, "next context").expect("next result"),
      126,
    )
    .await
    .expect("complete next run");
  assert_eq!(
    run_scheduled_delivery_tick_with_clock(
      &restarted,
      &provider,
      "delivery-worker-c",
      clock(127),
      shutdown(),
    )
    .await
    .expect("unchanged delivered target"),
    ScheduledDeliveryTickOutcome::SkippedUnchanged
  );
  assert_eq!(provider.observed().len(), 2);
  assert_eq!(
    run_scheduled_delivery_tick_with_clock(
      &restarted,
      &provider,
      "delivery-worker-d",
      clock(128),
      shutdown(),
    )
    .await
    .expect("unknown target remains sendable"),
    ScheduledDeliveryTickOutcome::Delivered
  );
  assert_eq!(provider.observed().len(), 3);
  assert_eq!(agent_invocations.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn none_target_prepares_without_provider_and_advances_accepted_baseline() {
  let temp = tempdir().expect("tempdir");
  let store = StateStore::initialize(&temp.path().join("state"), None)
    .await
    .expect("state");
  let job_id = "delivery-none-only";
  let body = "none-only exact result  \n";
  store
    .create_scheduled_job(&CreateScheduledJob {
      job_id: job_id.to_owned(),
      schedule_id: format!("schedule-{job_id}"),
      definition: ScheduledJobDefinition::new(1, "{}").expect("definition"),
      creator: owner(),
      owner: owner(),
      capability: CapabilityProfileSnapshot::new(1, "none", "{}").expect("capability"),
      targets: vec![none_target(job_id)],
      schedule: ScheduleSpec::once(110),
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
    .expect("complete");

  let Some(PreparedScheduledDelivery::SkippedNone(payload)) =
    prepare_next_scheduled_delivery(&store, 121)
      .await
      .expect("prepare none")
  else {
    panic!("none target must complete locally")
  };
  assert_eq!(payload.body().as_bytes(), body.as_bytes());
  assert_eq!(
    store
      .scheduled_delivery_authority_for_tests(payload.delivery_id())
      .await
      .expect("none authority"),
    ("skipped_none".to_owned(), 0, 0, 0)
  );
  assert!(
    store
      .get_accepted_delivery_baseline(&baseline_identity(job_id, &payload))
      .await
      .expect("none baseline")
      .is_some()
  );
}

#[tokio::test]
async fn transient_readiness_preserves_authority_then_recovery_claims_once() {
  let (_temp, store, delivery_id, _) =
    prepared_delivery("delivery-readiness-recovery", "body").await;
  let provider = FakeProvider::new([success()]).with_readiness([
    DeliveryProviderReadiness::Deferred {
      retry_after_seconds: Some(17),
      error_kind: "provider_unavailable".to_owned(),
    },
    DeliveryProviderReadiness::Ready,
  ]);
  assert_eq!(
    run_scheduled_delivery_tick_with_clock(&store, &provider, "worker", clock(122), shutdown(),)
      .await
      .expect("deferred tick"),
    ScheduledDeliveryTickOutcome::ReadinessDeferred {
      retry_after: Duration::from_secs(17),
    }
  );
  assert_eq!(
    store
      .scheduled_delivery_authority_for_tests(&delivery_id)
      .await
      .expect("authority"),
    ("pending".to_owned(), 0, 0, 0)
  );
  assert_eq!(
    run_scheduled_delivery_tick_with_clock(&store, &provider, "worker", clock(123), shutdown(),)
      .await
      .expect("ready tick"),
    ScheduledDeliveryTickOutcome::Delivered
  );
  assert_eq!(
    store
      .scheduled_delivery_authority_for_tests(&delivery_id)
      .await
      .expect("authority"),
    ("delivered".to_owned(), 1, 1, 1)
  );
}

#[tokio::test]
async fn oversized_readiness_retry_after_is_capped_without_delivery_mutation() {
  let (_temp, store, delivery_id, _) =
    prepared_delivery("delivery-readiness-oversized-retry-after", "body").await;
  let provider = FakeProvider::new([]).with_readiness([DeliveryProviderReadiness::Deferred {
    retry_after_seconds: Some(u64::MAX),
    error_kind: "provider_unavailable".to_owned(),
  }]);

  assert_eq!(
    run_scheduled_delivery_tick_with_clock(&store, &provider, "worker", clock(122), shutdown(),)
      .await
      .expect("deferred tick"),
    ScheduledDeliveryTickOutcome::ReadinessDeferred {
      retry_after: Duration::from_hours(1),
    }
  );
  assert_eq!(
    store
      .scheduled_delivery_authority_for_tests(&delivery_id)
      .await
      .expect("authority"),
    ("pending".to_owned(), 0, 0, 0)
  );
  assert!(provider.observed().is_empty());
}

#[tokio::test]
async fn fatal_provider_readiness_surfaces_without_mutating_any_delivery() {
  let (_temp, store, delivery_id, _) = prepared_delivery("delivery-readiness-fatal", "body").await;
  let next_id = prepare_next_delivery(&store, "delivery-readiness-fatal", "next").await;
  let provider = FakeProvider::new([]).with_readiness([DeliveryProviderReadiness::FatalProvider {
    error_kind: "invalid_auth".to_owned(),
  }]);
  let error =
    run_scheduled_delivery_tick_with_clock(&store, &provider, "worker", clock(122), shutdown())
      .await
      .expect_err("fatal readiness must fail lifecycle");
  assert!(error.to_string().contains("readiness failed fatally"));
  for pending_id in [&delivery_id, &next_id] {
    assert_eq!(
      store
        .scheduled_delivery_authority_for_tests(pending_id)
        .await
        .expect("authority"),
      ("pending".to_owned(), 0, 0, 0)
    );
  }
  assert!(provider.observed().is_empty());
}

#[tokio::test]
async fn exact_target_readiness_rejection_terminalizes_one_delivery_then_continues_queue() {
  let (_temp, store, rejected_id, rejected_payload) =
    prepared_delivery("delivery-readiness-reject", "rejected").await;
  let delivered_id = prepare_next_delivery(&store, "delivery-readiness-reject", "valid").await;
  let provider = FakeProvider::new([success()]).with_readiness([
    DeliveryProviderReadiness::RejectDelivery {
      error_kind: "target_unavailable".to_owned(),
    },
    DeliveryProviderReadiness::Ready,
  ]);
  assert_eq!(
    run_scheduled_delivery_tick_with_clock(&store, &provider, "worker-a", clock(132), shutdown(),)
      .await
      .expect("reject exact delivery"),
    ScheduledDeliveryTickOutcome::FailedTerminal
  );
  assert_eq!(
    store
      .scheduled_delivery_authority_for_tests(&rejected_id)
      .await
      .expect("rejected authority"),
    ("failed_terminal".to_owned(), 0, 0, 0)
  );
  assert_eq!(
    store
      .scheduled_delivery_run_state_for_tests(&rejected_id)
      .await
      .expect("rejected parent run"),
    "succeeded"
  );
  assert!(
    store
      .get_accepted_delivery_baseline(&baseline_identity(
        "delivery-readiness-reject",
        &rejected_payload,
      ))
      .await
      .expect("rejected baseline")
      .is_none()
  );
  assert!(provider.observed().is_empty());
  assert_eq!(
    run_scheduled_delivery_tick_with_clock(&store, &provider, "worker-b", clock(133), shutdown(),)
      .await
      .expect("continue queue"),
    ScheduledDeliveryTickOutcome::Delivered
  );
  assert_eq!(
    store
      .scheduled_delivery_authority_for_tests(&delivered_id)
      .await
      .expect("delivered authority"),
    ("delivered".to_owned(), 1, 1, 1)
  );
  assert_eq!(provider.observed().len(), 1);
}

#[tokio::test]
async fn readiness_timeout_is_retryable_without_claim_or_dispatch() {
  let (_temp, store, delivery_id, _) =
    prepared_delivery("delivery-readiness-timeout", "body").await;
  let provider = Arc::new(PendingReadinessProvider {
    started: Notify::new(),
  });
  let task_store = store.clone();
  let task_provider = Arc::clone(&provider);
  let task = tokio::spawn(async move {
    run_scheduled_delivery_tick_with_clock(
      &task_store,
      task_provider.as_ref(),
      "worker",
      Arc::new(TokioClock::new(122)),
      shutdown(),
    )
    .await
  });
  provider.started.notified().await;
  tokio::time::pause();
  tokio::time::advance(Duration::from_secs(11)).await;
  tokio::time::resume();
  assert_eq!(
    task.await.expect("task").expect("timeout tick"),
    ScheduledDeliveryTickOutcome::ReadinessDeferred {
      retry_after: Duration::from_secs(1),
    }
  );
  assert_eq!(
    store
      .scheduled_delivery_authority_for_tests(&delivery_id)
      .await
      .expect("authority"),
    ("pending".to_owned(), 0, 0, 0)
  );
}

#[tokio::test]
async fn provider_outage_does_not_block_expired_reclaim_or_start_a_new_attempt() {
  for (suffix, readiness, permanent) in [
    (
      "transient",
      DeliveryProviderReadiness::Deferred {
        retry_after_seconds: None,
        error_kind: "unavailable".to_owned(),
      },
      false,
    ),
    (
      "permanent",
      DeliveryProviderReadiness::FatalProvider {
        error_kind: "invalid_auth".to_owned(),
      },
      true,
    ),
  ] {
    let job_id = format!("delivery-reclaim-outage-{suffix}");
    let (_temp, store, expired_id, _) = prepared_delivery(&job_id, "first").await;
    let next_id = prepare_next_delivery(&store, &job_id, "second").await;
    store
      .claim_next_scheduled_delivery("expired-worker", 122, 125)
      .await
      .expect("claim expired")
      .expect("expired claim");
    let provider = FakeProvider::new([]).with_readiness([readiness]);
    let result =
      run_scheduled_delivery_tick_with_clock(&store, &provider, "worker", clock(130), shutdown())
        .await;
    if permanent {
      assert!(
        result
          .expect_err("permanent readiness")
          .to_string()
          .contains("readiness failed fatally")
      );
    } else {
      assert_eq!(
        result.expect("transient readiness"),
        ScheduledDeliveryTickOutcome::ReadinessDeferred {
          retry_after: Duration::from_secs(1),
        }
      );
    }
    assert_eq!(
      store
        .scheduled_delivery_authority_for_tests(&expired_id)
        .await
        .expect("expired authority"),
      ("delivery_unknown".to_owned(), 1, 1, 1)
    );
    assert_eq!(
      store
        .scheduled_delivery_authority_for_tests(&next_id)
        .await
        .expect("next authority"),
      ("pending".to_owned(), 0, 0, 0)
    );
    assert!(provider.observed().is_empty());
  }
}

#[tokio::test]
async fn shutdown_observed_before_tick_never_polls_provider_or_mutates_delivery() {
  let (_temp, store, delivery_id, _) =
    prepared_delivery("delivery-shutdown-before-readiness", "body").await;
  let provider = FakeProvider::new([success()]);
  let (shutdown_tx, shutdown_rx) = watch::channel(false);
  shutdown_tx.send(true).expect("shutdown");
  assert_eq!(
    run_scheduled_delivery_tick_with_clock(&store, &provider, "worker", clock(122), shutdown_rx,)
      .await
      .expect("cancelled tick"),
    ScheduledDeliveryTickOutcome::Cancelled
  );
  assert_eq!(provider.readiness_calls.load(Ordering::SeqCst), 0);
  assert!(provider.observed().is_empty());
  assert_eq!(
    store
      .scheduled_delivery_authority_for_tests(&delivery_id)
      .await
      .expect("authority"),
    ("pending".to_owned(), 0, 0, 0)
  );
}

#[tokio::test]
async fn shutdown_between_readiness_and_claim_leaves_authority_unmodified() {
  let (_temp, store, delivery_id, _) =
    prepared_delivery("delivery-shutdown-after-readiness", "body").await;
  let provider = Arc::new(BlockingReadinessProvider {
    readiness_started: Notify::new(),
    release_readiness: Notify::new(),
    sends: AtomicUsize::new(0),
  });
  let (shutdown_tx, shutdown_rx) = watch::channel(false);
  let task_store = store.clone();
  let task_provider = Arc::clone(&provider);
  let task = tokio::spawn(async move {
    run_scheduled_delivery_tick_with_clock(
      &task_store,
      task_provider.as_ref(),
      "worker",
      clock(122),
      shutdown_rx,
    )
    .await
  });
  provider.readiness_started.notified().await;
  shutdown_tx.send(true).expect("shutdown");
  provider.release_readiness.notify_one();
  assert_eq!(
    task.await.expect("task").expect("tick"),
    ScheduledDeliveryTickOutcome::Cancelled
  );
  assert_eq!(provider.sends.load(Ordering::SeqCst), 0);
  assert_eq!(
    store
      .scheduled_delivery_authority_for_tests(&delivery_id)
      .await
      .expect("authority"),
    ("pending".to_owned(), 0, 0, 0)
  );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_after_predispatch_check_but_before_first_send_poll_requeues_safely() {
  let (_temp, store, delivery_id, _) =
    prepared_delivery("delivery-shutdown-predispatch", "body").await;
  let provider = Arc::new(FakeProvider::new([success()]));
  let (reached_tx, reached_rx) = mpsc::channel();
  let (release_tx, release_rx) = mpsc::channel();
  let gate_clock: Arc<dyn DeliveryClock> = Arc::new(GateClock {
    now: 122,
    calls: AtomicUsize::new(0),
    gate_call: 4,
    reached: Mutex::new(Some(reached_tx)),
    release: Mutex::new(release_rx),
  });
  let (shutdown_tx, shutdown_rx) = watch::channel(false);
  let task_store = store.clone();
  let task_provider = Arc::clone(&provider);
  let task = tokio::spawn(async move {
    run_scheduled_delivery_tick_with_clock(
      &task_store,
      task_provider.as_ref(),
      "worker",
      gate_clock,
      shutdown_rx,
    )
    .await
  });
  tokio::task::spawn_blocking(move || reached_rx.recv().expect("predispatch clock gate"))
    .await
    .expect("gate waiter");
  shutdown_tx.send(true).expect("shutdown");
  release_tx.send(()).expect("release predispatch gate");
  assert_eq!(
    task.await.expect("task").expect("tick"),
    ScheduledDeliveryTickOutcome::RetryDeferred
  );
  assert!(provider.observed().is_empty());
  assert_eq!(
    store
      .scheduled_delivery_authority_for_tests(&delivery_id)
      .await
      .expect("authority"),
    ("failed_retryable".to_owned(), 1, 1, 1)
  );
  assert_eq!(
    run_scheduled_delivery_tick_with_clock(
      &store,
      provider.as_ref(),
      "worker",
      clock(123),
      shutdown(),
    )
    .await
    .expect("retry tick"),
    ScheduledDeliveryTickOutcome::Delivered
  );
  assert_eq!(provider.observed().len(), 1);
}

#[tokio::test]
async fn retry_reuses_exact_payload_target_and_idempotency_without_agent_work() {
  let (_temp, store, _, payload) = prepared_delivery("delivery-retry", "retry body").await;
  let agent_invocations = AtomicUsize::new(1);
  let provider = FakeProvider::new([
    DeliveryProviderOutcome::ConfirmedNoWriteRetryable {
      retry_after_seconds: Some(1),
      error_kind: "rate_limited".to_owned(),
    },
    success(),
  ]);
  assert_eq!(
    run_scheduled_delivery_tick_with_clock(&store, &provider, "worker-a", clock(122), shutdown())
      .await
      .expect("first tick"),
    ScheduledDeliveryTickOutcome::RetryDeferred
  );
  assert_eq!(
    run_scheduled_delivery_tick_with_clock(&store, &provider, "worker-b", clock(127), shutdown())
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
async fn retry_after_at_delivery_deadline_becomes_terminal_without_retry() {
  let (_temp, store, _, _) = prepared_delivery("delivery-retry-deadline", "body").await;
  let provider = FakeProvider::new([DeliveryProviderOutcome::ConfirmedNoWriteRetryable {
    retry_after_seconds: Some(3_600),
    error_kind: "rate_limited".to_owned(),
  }]);
  assert_eq!(
    run_scheduled_delivery_tick_with_clock(&store, &provider, "worker", clock(122), shutdown())
      .await
      .expect("deadline tick"),
    ScheduledDeliveryTickOutcome::FailedTerminal
  );
  assert_eq!(
    run_scheduled_delivery_tick_with_clock(&store, &provider, "worker", clock(3_721), shutdown())
      .await
      .expect("no retry"),
    ScheduledDeliveryTickOutcome::Idle
  );
  assert_eq!(provider.observed().len(), 1);
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
      run_scheduled_delivery_tick_with_clock(&store, &provider, "worker", clock(122), shutdown())
        .await
        .expect("terminal tick"),
      expected
    );
    assert_eq!(
      run_scheduled_delivery_tick_with_clock(&store, &provider, "worker", clock(500), shutdown())
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
    run_scheduled_delivery_tick_with_clock(
      &task_store,
      task_provider.as_ref(),
      "worker",
      clock(122),
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
    run_scheduled_delivery_tick_with_clock(
      &task_store,
      task_provider.as_ref(),
      "worker",
      clock(122),
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
async fn heartbeat_prevents_independent_store_reclaim_during_long_send() {
  let (temp, store, delivery_id, payload) = prepared_delivery("delivery-heartbeat", "body").await;
  let independent = StateStore::initialize(&temp.path().join("state"), None)
    .await
    .expect("independent state");
  let provider = Arc::new(BlockingProvider {
    calls: AtomicUsize::new(0),
    started: Notify::new(),
    release: Notify::new(),
  });
  let task_store = store.clone();
  let task_provider = Arc::clone(&provider);
  let task = tokio::spawn(async move {
    run_scheduled_delivery_tick_with_clock(
      &task_store,
      task_provider.as_ref(),
      "worker",
      Arc::new(TokioClock::new(122)),
      shutdown(),
    )
    .await
  });
  provider.started.notified().await;
  tokio::time::pause();
  tokio::time::advance(Duration::from_secs(20)).await;
  tokio::task::yield_now().await;
  tokio::time::resume();
  wait_for_delivery_lease_at_least(&independent, &delivery_id, 202).await;
  assert_eq!(
    independent
      .reclaim_expired_scheduled_deliveries(183, 1)
      .await
      .expect("reclaim check"),
    0
  );
  provider.release.notify_one();
  assert_eq!(
    task.await.expect("task").expect("tick"),
    ScheduledDeliveryTickOutcome::Delivered
  );
  assert!(
    store
      .get_accepted_delivery_baseline(&baseline_identity("delivery-heartbeat", &payload))
      .await
      .expect("baseline")
      .is_some()
  );
}

#[tokio::test]
async fn queued_heartbeat_finishes_before_final_refresh_without_false_lost_fence() {
  let (temp, store, delivery_id, payload) =
    prepared_delivery("delivery-heartbeat-finalize", "body").await;
  let independent = StateStore::initialize(&temp.path().join("state"), None)
    .await
    .expect("independent state");
  let provider = Arc::new(BlockingProvider {
    calls: AtomicUsize::new(0),
    started: Notify::new(),
    release: Notify::new(),
  });
  let clock_calls = Arc::new(AtomicUsize::new(0));
  let clock_values = Arc::new(Mutex::new(Vec::new()));
  let task_store = store.clone();
  let task_provider = Arc::clone(&provider);
  let task_clock_calls = Arc::clone(&clock_calls);
  let task_clock_values = Arc::clone(&clock_values);
  let task = tokio::spawn(async move {
    run_scheduled_delivery_tick_with_clock(
      &task_store,
      task_provider.as_ref(),
      "worker",
      Arc::new(CountingStepClock {
        next: AtomicI64::new(122),
        calls: task_clock_calls,
        values: task_clock_values,
      }),
      shutdown(),
    )
    .await
  });
  provider.started.notified().await;
  let lock = independent
    .acquire_exclusive_storage_lock_for_tests()
    .await
    .expect("exclusive lock");
  tokio::time::pause();
  tokio::time::advance(Duration::from_secs(10)).await;
  while clock_calls.load(Ordering::SeqCst) < 5 {
    tokio::task::yield_now().await;
  }
  tokio::time::resume();
  provider.release.notify_one();
  tokio::task::yield_now().await;
  lock.release().await.expect("release lock");
  let outcome = task.await.expect("task").expect("tick");
  let authority = store
    .scheduled_delivery_authority_for_tests(&delivery_id)
    .await
    .expect("authority");
  let lease = store
    .scheduled_delivery_lease_for_tests(&delivery_id)
    .await
    .expect("lease");
  assert_eq!(
    outcome,
    ScheduledDeliveryTickOutcome::Delivered,
    "{authority:?} {lease:?} {:?}",
    clock_values.lock().expect("clock values")
  );
  assert!(
    store
      .get_accepted_delivery_baseline(&baseline_identity("delivery-heartbeat-finalize", &payload,))
      .await
      .expect("baseline")
      .is_some()
  );
}

#[tokio::test]
async fn heartbeat_contention_surfaces_storage_failure_then_reclaims_unknown() {
  let (temp, store, _delivery_id, payload) =
    prepared_delivery("delivery-heartbeat-contention", "body").await;
  let independent = StateStore::initialize(&temp.path().join("state"), None)
    .await
    .expect("independent state");
  let provider = Arc::new(BlockingProvider {
    calls: AtomicUsize::new(0),
    started: Notify::new(),
    release: Notify::new(),
  });
  let task_store = store.clone();
  let task_provider = Arc::clone(&provider);
  let task = tokio::spawn(async move {
    run_scheduled_delivery_tick_with_clock(
      &task_store,
      task_provider.as_ref(),
      "worker",
      Arc::new(TokioClock::new(122)),
      shutdown(),
    )
    .await
  });
  provider.started.notified().await;
  tokio::time::pause();
  let lock = independent
    .acquire_exclusive_storage_lock_for_tests()
    .await
    .expect("exclusive lock");
  tokio::time::advance(Duration::from_secs(10)).await;
  tokio::task::yield_now().await;
  tokio::time::advance(Duration::from_secs(68)).await;
  lock.release().await.expect("release lock");
  tokio::task::yield_now().await;
  tokio::time::resume();
  provider.release.notify_one();
  let error = task
    .await
    .expect("task")
    .expect_err("contention must surface storage failure");
  assert!(
    error.to_string().contains("timed out"),
    "unexpected error: {error}"
  );
  assert_eq!(
    independent
      .reclaim_expired_scheduled_deliveries(300, 1)
      .await
      .expect("reclaim failed worker claim"),
    1
  );
  assert!(
    store
      .get_accepted_delivery_baseline(&baseline_identity(
        "delivery-heartbeat-contention",
        &payload,
      ))
      .await
      .expect("baseline")
      .is_none()
  );
}

#[tokio::test]
async fn real_send_timeout_commits_ambiguous_unknown_without_retry() {
  let (_temp, store, delivery_id, payload) = prepared_delivery("delivery-timeout", "body").await;
  let provider = Arc::new(PendingProvider {
    started: Notify::new(),
  });
  let task_store = store.clone();
  let task_provider = Arc::clone(&provider);
  let task = tokio::spawn(async move {
    run_scheduled_delivery_tick_with_clock(
      &task_store,
      task_provider.as_ref(),
      "worker",
      Arc::new(TokioClock::new(122)),
      shutdown(),
    )
    .await
  });
  provider.started.notified().await;
  tokio::time::pause();
  tokio::time::advance(Duration::from_secs(31)).await;
  tokio::time::resume();
  assert_eq!(
    task.await.expect("task").expect("tick"),
    ScheduledDeliveryTickOutcome::DeliveryUnknown
  );
  assert_eq!(
    store
      .scheduled_delivery_authority_for_tests(&delivery_id)
      .await
      .expect("authority"),
    ("delivery_unknown".to_owned(), 1, 1, 1)
  );
  assert!(
    store
      .get_accepted_delivery_baseline(&baseline_identity("delivery-timeout", &payload))
      .await
      .expect("baseline")
      .is_none()
  );
}

#[tokio::test]
async fn provider_panic_leaves_claim_for_reclaim_without_detached_heartbeat() {
  let (temp, store, delivery_id, payload) =
    prepared_delivery("delivery-provider-panic", "body").await;
  let independent = StateStore::initialize(&temp.path().join("state"), None)
    .await
    .expect("independent state");
  let task = tokio::spawn(async move {
    run_scheduled_delivery_tick_with_clock(&store, &PanicProvider, "worker", clock(122), shutdown())
      .await
  });
  let panic = task
    .await
    .expect_err("provider panic must reach task owner");
  assert!(panic.is_panic());
  assert_eq!(
    independent
      .scheduled_delivery_authority_for_tests(&delivery_id)
      .await
      .expect("claimed authority"),
    ("sending".to_owned(), 1, 1, 1)
  );
  assert_eq!(
    independent
      .reclaim_expired_scheduled_deliveries(183, 1)
      .await
      .expect("reclaim panic claim"),
    1
  );
  assert!(
    independent
      .get_accepted_delivery_baseline(&baseline_identity("delivery-provider-panic", &payload))
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
    run_scheduled_delivery_tick_with_clock(
      &first_store,
      first_provider.as_ref(),
      "worker-a",
      clock(122),
      shutdown(),
    )
    .await
  });
  let second_store = store.clone();
  let second_provider = Arc::clone(&provider);
  let second = tokio::spawn(async move {
    run_scheduled_delivery_tick_with_clock(
      &second_store,
      second_provider.as_ref(),
      "worker-b",
      clock(122),
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_restarted_workers_prepare_once_and_make_one_provider_call() {
  let (temp, first_store, delivery_id) =
    completed_delivery_intent("delivery-unprepared-race", "body").await;
  let second_store = StateStore::initialize(&temp.path().join("state"), None)
    .await
    .expect("second store");
  let provider = Arc::new(FakeProvider::new([success()]));
  let (first_shutdown, first_shutdown_rx) = watch::channel(false);
  let (second_shutdown, second_shutdown_rx) = watch::channel(false);
  let first_provider: Arc<dyn DeliveryProvider> = provider.clone();
  let first = tokio::spawn(run_scheduled_delivery_worker_with_clock(
    first_store,
    first_provider,
    "worker-a".to_owned(),
    clock(122),
    first_shutdown_rx,
  ));
  let second_provider: Arc<dyn DeliveryProvider> = provider.clone();
  let second = tokio::spawn(run_scheduled_delivery_worker_with_clock(
    second_store,
    second_provider,
    "worker-b".to_owned(),
    clock(122),
    second_shutdown_rx,
  ));
  tokio::time::timeout(Duration::from_secs(2), async {
    while provider.observed().is_empty() {
      tokio::time::sleep(Duration::from_millis(10)).await;
    }
  })
  .await
  .expect("delivery deadline");
  first_shutdown.send(true).expect("first shutdown");
  second_shutdown.send(true).expect("second shutdown");
  first
    .await
    .expect("first task")
    .expect("first worker result");
  second
    .await
    .expect("second task")
    .expect("second worker result");
  assert_eq!(provider.observed().len(), 1);
  assert_eq!(
    StateStore::initialize(&temp.path().join("state"), None)
      .await
      .expect("reopen")
      .scheduled_delivery_authority_for_tests(&delivery_id)
      .await
      .expect("authority"),
    ("delivered".to_owned(), 1, 1, 1)
  );
}

#[tokio::test]
async fn readiness_for_delivery_a_can_never_authorize_delivery_b() {
  let (_temp, store, first_id, _) = prepared_delivery("delivery-exact-authority", "first").await;
  let second_id = prepare_next_delivery(&store, "delivery-exact-authority", "second").await;
  let blocked = Arc::new(ExactReadinessProvider {
    readiness_started: Notify::new(),
    release_readiness: Notify::new(),
    readiness_delivery_ids: Mutex::new(Vec::new()),
    sends: AtomicUsize::new(0),
  });
  let blocked_store = store.clone();
  let blocked_provider = Arc::clone(&blocked);
  let first_worker = tokio::spawn(async move {
    run_scheduled_delivery_tick_with_clock(
      &blocked_store,
      blocked_provider.as_ref(),
      "worker-a",
      clock(130),
      shutdown(),
    )
    .await
  });
  blocked.readiness_started.notified().await;
  assert_eq!(
    blocked
      .readiness_delivery_ids
      .lock()
      .expect("readiness ids")
      .as_slice(),
    [first_id.as_str()]
  );

  let winner = FakeProvider::new([success()]);
  assert_eq!(
    run_scheduled_delivery_tick_with_clock(&store, &winner, "worker-b", clock(130), shutdown())
      .await
      .expect("winner tick"),
    ScheduledDeliveryTickOutcome::Delivered
  );
  blocked.release_readiness.notify_one();
  assert_eq!(
    first_worker.await.expect("worker-a").expect("stale tick"),
    ScheduledDeliveryTickOutcome::Idle
  );
  assert_eq!(blocked.sends.load(Ordering::SeqCst), 0);
  assert_eq!(
    store
      .scheduled_delivery_authority_for_tests(&second_id)
      .await
      .expect("second authority"),
    ("pending".to_owned(), 0, 0, 0)
  );
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
    run_scheduled_delivery_tick_with_clock(
      &task_store,
      task_provider.as_ref(),
      "worker",
      clock(122),
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
  let second_delivery_id =
    prepare_next_delivery(&store, "delivery-worker-shutdown", "second body").await;
  let provider = Arc::new(BlockingProvider {
    calls: AtomicUsize::new(0),
    started: Notify::new(),
    release: Notify::new(),
  });
  let (shutdown_tx, shutdown_rx) = watch::channel(false);
  let task_store = store.clone();
  let task_provider: Arc<dyn DeliveryProvider> = provider.clone();
  let task = tokio::spawn(run_scheduled_delivery_worker_with_clock(
    task_store,
    task_provider,
    "worker".to_owned(),
    clock(122),
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
  assert_eq!(
    store
      .scheduled_delivery_authority_for_tests(&second_delivery_id)
      .await
      .expect("second authority"),
    ("pending".to_owned(), 0, 0, 0)
  );
}

#[tokio::test]
async fn unchanged_payload_skips_without_provider_call() {
  let (_temp, store, _, first_payload) = prepared_delivery("delivery-unchanged", "same body").await;
  let first = FakeProvider::new([success()]);
  assert_eq!(
    run_scheduled_delivery_tick_with_clock(&store, &first, "worker", clock(122), shutdown())
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
    run_scheduled_delivery_tick_with_clock(&store, &provider, "worker", clock(127), shutdown())
      .await
      .expect("unchanged tick"),
    ScheduledDeliveryTickOutcome::SkippedUnchanged
  );
  assert!(provider.observed().is_empty());
  assert_eq!(provider.readiness_calls.load(Ordering::SeqCst), 0);
  assert!(
    store
      .get_accepted_delivery_baseline(&baseline_identity("delivery-unchanged", &first_payload))
      .await
      .expect("baseline")
      .is_some()
  );
}
