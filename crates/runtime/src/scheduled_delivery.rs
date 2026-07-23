use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::{future::Future, panic::AssertUnwindSafe, pin::Pin, task::Context, task::Poll};

use async_trait::async_trait;
use codeoff_core::SchedulerOperationalPolicy;
use codeoff_state::{
  ClaimedScheduledDelivery, DeliveryPayloadSnapshot, PreparedScheduledDelivery,
  ScheduledDeliveryFailure, ScheduledDeliveryWork, SkippedNoneBaselinePolicy, StateError,
  StateStore,
};
use serde_json::json;
use tokio::sync::{oneshot, watch};
use tokio::task::JoinHandle;

use crate::scheduler_observability::{
  SchedulerLoopGuard, SchedulerOperation, SchedulerOperationStatus, SchedulerTelemetry,
  SchedulerTelemetryErrorKind, SchedulerTelemetryEvent, SchedulerWorker, record_scheduler_event,
};

const DELIVERY_POLICY_VERSION: u32 = 1;
const DELIVERY_RENDER_VERSION: u32 = 1;
const DELIVERY_CONTENT_TYPE: &str = "text/markdown; charset=utf-8";

pub struct DeliveryProviderReadinessRequest<'a> {
  pub delivery_id: &'a str,
  pub target_json: &'a str,
  pub target_digest: &'a str,
  pub payload_digest: &'a str,
  pub binding_digest: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryProviderReadiness {
  Ready,
  Deferred {
    retry_after_seconds: Option<u64>,
    error_kind: String,
  },
  RejectDelivery {
    error_kind: String,
  },
  FatalProvider {
    error_kind: String,
  },
}

pub struct DeliveryProviderRequest<'a> {
  pub payload: &'a DeliveryPayloadSnapshot,
  pub target_json: &'a str,
  pub idempotency_key: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderMessageIdentity {
  pub provider: String,
  pub tenant: String,
  pub conversation_id: String,
  pub thread_id: Option<String>,
  pub message_id: String,
}

impl ProviderMessageIdentity {
  fn canonical_receipt(&self) -> Result<String, StateError> {
    serde_json::to_string(&json!({
      "provider": self.provider,
      "tenant": self.tenant,
      "conversation_id": self.conversation_id,
      "thread_id": self.thread_id,
      "message_id": self.message_id,
    }))
    .map_err(|error| StateError::InvalidSchedulerState {
      reason: format!("scheduled delivery receipt is invalid: {error}"),
    })
  }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryProviderOutcome {
  ConfirmedSuccess(ProviderMessageIdentity),
  ConfirmedNoWriteRetryable {
    retry_after_seconds: Option<u64>,
    error_kind: String,
  },
  ConfirmedNoWriteTerminal {
    error_kind: String,
  },
  AmbiguousPostWrite {
    error_kind: String,
  },
}

#[async_trait]
pub trait DeliveryProvider: Send + Sync {
  async fn readiness(
    &self,
    request: DeliveryProviderReadinessRequest<'_>,
  ) -> DeliveryProviderReadiness;

  async fn send(&self, request: DeliveryProviderRequest<'_>) -> DeliveryProviderOutcome;
}

pub trait DeliveryClock: Send + Sync {
  fn now_unix_seconds(&self) -> i64;
}

struct SystemDeliveryClock;

impl DeliveryClock for SystemDeliveryClock {
  fn now_unix_seconds(&self) -> i64 {
    SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .map_or(0, |duration| {
        i64::try_from(duration.as_secs()).unwrap_or(i64::MAX)
      })
  }
}

#[derive(Clone)]
struct DeliveryTimeline {
  clock: Arc<dyn DeliveryClock>,
  last: Arc<AtomicI64>,
}

#[derive(Default)]
struct DeliveryWorkerState {
  readiness_failure_streak: u32,
}

impl DeliveryWorkerState {
  fn readiness_ready(&mut self) {
    self.readiness_failure_streak = 0;
  }

  fn readiness_retry(
    &mut self,
    retry_after_seconds: Option<u64>,
    policy: &SchedulerOperationalPolicy,
  ) -> Duration {
    let exponent = self.readiness_failure_streak.min(31);
    self.readiness_failure_streak = self.readiness_failure_streak.saturating_add(1);
    let local_seconds = u64::from(policy.delivery_readiness_retry_base_seconds)
      .checked_shl(exponent)
      .unwrap_or(u64::from(policy.delivery_readiness_retry_max_seconds))
      .min(u64::from(policy.delivery_readiness_retry_max_seconds));
    let provider_seconds = retry_after_seconds
      .filter(|seconds| *seconds > 0)
      .map(|seconds| seconds.min(u64::from(policy.delivery_retry_after_max_seconds)))
      .unwrap_or(0);
    Duration::from_secs(local_seconds.max(provider_seconds))
  }
}

impl DeliveryTimeline {
  fn new(clock: Arc<dyn DeliveryClock>) -> Self {
    Self {
      clock,
      last: Arc::new(AtomicI64::new(0)),
    }
  }

  fn fresh_now(&self) -> i64 {
    let observed = self.clock.now_unix_seconds().max(0);
    self
      .last
      .fetch_max(observed, Ordering::AcqRel)
      .max(observed)
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScheduledDeliveryTickOutcome {
  Idle,
  Cancelled,
  SkippedNone,
  SkippedUnchanged,
  ReadinessDeferred { retry_after: Duration },
  Delivered,
  RetryDeferred,
  FailedTerminal,
  DeliveryUnknown,
  LostFence,
}

/// Freezes accepted scheduled results into exact delivery payloads without provider access.
///
/// This worker is used when provider delivery is disabled so `none` targets still complete and
/// non-provider payload authority remains restart-safe.
///
/// # Errors
/// Returns an error when durable result or delivery authority is invalid or storage fails.
pub async fn run_scheduled_delivery_preparation_worker(
  state: StateStore,
  shutdown: watch::Receiver<bool>,
  telemetry: Arc<dyn SchedulerTelemetry>,
) -> Result<(), StateError> {
  let loop_guard =
    SchedulerLoopGuard::start(telemetry.clone(), SchedulerWorker::DeliveryPreparation);
  let result = run_scheduled_delivery_preparation_worker_inner(state, shutdown, &telemetry).await;
  loop_guard.finish(
    if result.is_ok() {
      SchedulerOperationStatus::Stopped
    } else {
      SchedulerOperationStatus::Failed
    },
    result
      .as_ref()
      .err()
      .map(|_| SchedulerTelemetryErrorKind::State),
  );
  result
}

async fn run_scheduled_delivery_preparation_worker_inner(
  state: StateStore,
  shutdown: watch::Receiver<bool>,
  telemetry: &Arc<dyn SchedulerTelemetry>,
) -> Result<(), StateError> {
  let timeline = DeliveryTimeline::new(Arc::new(SystemDeliveryClock));
  let policy = state.scheduler_operational_policy();
  loop {
    if *shutdown.borrow() {
      return Ok(());
    }
    let started_at = Instant::now();
    let preparation = tokio::select! {
      biased;
      () = cancellation_requested(shutdown.clone()) => return Ok(()),
      preparation = prepare_next_scheduled_delivery(&state, timeline.fresh_now()) => preparation,
    };
    record_delivery_event(
      telemetry.as_ref(),
      SchedulerWorker::DeliveryPreparation,
      SchedulerOperation::Tick,
      match &preparation {
        Ok(Some(_)) => SchedulerOperationStatus::Completed,
        Ok(None) => SchedulerOperationStatus::Idle,
        Err(_) => SchedulerOperationStatus::Failed,
      },
      preparation
        .as_ref()
        .err()
        .map(|_| SchedulerTelemetryErrorKind::State),
      started_at.elapsed(),
      None,
    );
    let preparation = match preparation {
      Ok(preparation) => preparation,
      Err(error) if error.is_transient_storage_contention() => {
        tokio::select! {
          biased;
          () = cancellation_requested(shutdown.clone()) => return Ok(()),
          () = tokio::time::sleep(Duration::from_millis(policy.delivery_tick_interval_ms)) => {}
        }
        continue;
      }
      Err(error) => return Err(error),
    };
    let delay = if preparation.is_some() {
      Duration::ZERO
    } else {
      Duration::from_millis(policy.delivery_tick_interval_ms)
    };
    tokio::select! {
      biased;
      () = cancellation_requested(shutdown.clone()) => return Ok(()),
      () = tokio::time::sleep(delay) => {}
    }
  }
}

/// Freezes one accepted result into the immutable payload for its next pending delivery intent.
///
/// # Errors
/// Returns an error when durable result or delivery authority is invalid or storage fails.
pub async fn prepare_next_scheduled_delivery(
  state: &StateStore,
  now: i64,
) -> Result<Option<PreparedScheduledDelivery>, StateError> {
  let Some(input) = state.next_scheduled_delivery_render_input().await? else {
    return Ok(None);
  };
  let prepared = state
    .prepare_scheduled_delivery(
      input.delivery_id(),
      DELIVERY_CONTENT_TYPE,
      input.body(),
      DELIVERY_RENDER_VERSION,
      now,
      SkippedNoneBaselinePolicy::Accept,
    )
    .await;
  match prepared {
    Ok(prepared) => Ok(Some(prepared)),
    Err(StateError::ScheduledDeliveryPayloadConflict) => state
      .prepare_scheduled_delivery(
        input.delivery_id(),
        DELIVERY_CONTENT_TYPE,
        input.body(),
        DELIVERY_RENDER_VERSION,
        now,
        SkippedNoneBaselinePolicy::Accept,
      )
      .await
      .map(Some),
    Err(error) => Err(error),
  }
}

pub async fn run_scheduled_delivery_worker(
  state: StateStore,
  provider: Arc<dyn DeliveryProvider>,
  lease_owner: String,
  shutdown: watch::Receiver<bool>,
  telemetry: Arc<dyn SchedulerTelemetry>,
) -> Result<(), StateError> {
  run_scheduled_delivery_worker_with_clock(
    state,
    provider,
    lease_owner,
    Arc::new(SystemDeliveryClock),
    shutdown,
    telemetry,
  )
  .await
}

pub async fn run_scheduled_delivery_worker_with_clock(
  state: StateStore,
  provider: Arc<dyn DeliveryProvider>,
  lease_owner: String,
  clock: Arc<dyn DeliveryClock>,
  shutdown: watch::Receiver<bool>,
  telemetry: Arc<dyn SchedulerTelemetry>,
) -> Result<(), StateError> {
  let loop_guard = SchedulerLoopGuard::start(telemetry.clone(), SchedulerWorker::Delivery);
  let result =
    run_scheduled_delivery_worker_inner(state, provider, lease_owner, clock, shutdown, &telemetry)
      .await;
  loop_guard.finish(
    if result.is_ok() {
      SchedulerOperationStatus::Stopped
    } else {
      SchedulerOperationStatus::Failed
    },
    result
      .as_ref()
      .err()
      .map(|_| SchedulerTelemetryErrorKind::State),
  );
  result
}

async fn run_scheduled_delivery_worker_inner(
  state: StateStore,
  provider: Arc<dyn DeliveryProvider>,
  lease_owner: String,
  clock: Arc<dyn DeliveryClock>,
  shutdown: watch::Receiver<bool>,
  telemetry: &Arc<dyn SchedulerTelemetry>,
) -> Result<(), StateError> {
  let timeline = DeliveryTimeline::new(clock);
  let policy = state.scheduler_operational_policy();
  let mut worker_state = DeliveryWorkerState::default();
  loop {
    if *shutdown.borrow() {
      return Ok(());
    }
    let started_at = Instant::now();
    let tick = run_scheduled_delivery_tick_with_timeline(
      &state,
      provider.as_ref(),
      &lease_owner,
      timeline.clone(),
      shutdown.clone(),
      &mut worker_state,
      telemetry.as_ref(),
    )
    .await;
    record_delivery_event(
      telemetry.as_ref(),
      SchedulerWorker::Delivery,
      SchedulerOperation::Tick,
      match &tick {
        Ok(outcome) => delivery_tick_status(*outcome),
        Err(_) => SchedulerOperationStatus::Failed,
      },
      tick
        .as_ref()
        .err()
        .map(|_| SchedulerTelemetryErrorKind::State),
      started_at.elapsed(),
      None,
    );
    let tick = match tick {
      Ok(tick) => tick,
      Err(error) if error.is_transient_storage_contention() => {
        tokio::select! {
          biased;
          () = cancellation_requested(shutdown.clone()) => return Ok(()),
          () = tokio::time::sleep(Duration::from_millis(policy.delivery_tick_interval_ms)) => {}
        }
        continue;
      }
      Err(error) => return Err(error),
    };
    let delay = match tick {
      ScheduledDeliveryTickOutcome::Cancelled => return Ok(()),
      ScheduledDeliveryTickOutcome::Idle => Duration::from_millis(policy.delivery_tick_interval_ms),
      ScheduledDeliveryTickOutcome::ReadinessDeferred { retry_after } => retry_after,
      _ => Duration::ZERO,
    };
    tokio::select! {
      biased;
      () = cancellation_requested(shutdown.clone()) => return Ok(()),
      () = tokio::time::sleep(delay) => {}
    }
  }
}

fn record_delivery_event(
  telemetry: &dyn SchedulerTelemetry,
  worker: SchedulerWorker,
  operation: SchedulerOperation,
  status: SchedulerOperationStatus,
  error_kind: Option<SchedulerTelemetryErrorKind>,
  duration: Duration,
  attempt: Option<u32>,
) {
  record_scheduler_event(
    telemetry,
    SchedulerTelemetryEvent {
      worker,
      operation,
      status,
      error_kind,
      duration,
      attempt,
    },
  );
}

const fn delivery_tick_status(outcome: ScheduledDeliveryTickOutcome) -> SchedulerOperationStatus {
  match outcome {
    ScheduledDeliveryTickOutcome::Idle => SchedulerOperationStatus::Idle,
    ScheduledDeliveryTickOutcome::Cancelled => SchedulerOperationStatus::Cancelled,
    ScheduledDeliveryTickOutcome::SkippedNone | ScheduledDeliveryTickOutcome::SkippedUnchanged => {
      SchedulerOperationStatus::Skipped
    }
    ScheduledDeliveryTickOutcome::ReadinessDeferred { .. }
    | ScheduledDeliveryTickOutcome::RetryDeferred => SchedulerOperationStatus::Deferred,
    ScheduledDeliveryTickOutcome::Delivered => SchedulerOperationStatus::Completed,
    ScheduledDeliveryTickOutcome::FailedTerminal => SchedulerOperationStatus::Failed,
    ScheduledDeliveryTickOutcome::DeliveryUnknown => SchedulerOperationStatus::Unknown,
    ScheduledDeliveryTickOutcome::LostFence => SchedulerOperationStatus::LostAuthority,
  }
}

pub async fn run_scheduled_delivery_tick(
  state: &StateStore,
  provider: &dyn DeliveryProvider,
  lease_owner: &str,
  shutdown: watch::Receiver<bool>,
  telemetry: Arc<dyn SchedulerTelemetry>,
) -> Result<ScheduledDeliveryTickOutcome, StateError> {
  run_scheduled_delivery_tick_with_clock(
    state,
    provider,
    lease_owner,
    Arc::new(SystemDeliveryClock),
    shutdown,
    telemetry,
  )
  .await
}

pub async fn run_scheduled_delivery_tick_with_clock(
  state: &StateStore,
  provider: &dyn DeliveryProvider,
  lease_owner: &str,
  clock: Arc<dyn DeliveryClock>,
  shutdown: watch::Receiver<bool>,
  telemetry: Arc<dyn SchedulerTelemetry>,
) -> Result<ScheduledDeliveryTickOutcome, StateError> {
  let mut worker_state = DeliveryWorkerState::default();
  run_scheduled_delivery_tick_with_timeline(
    state,
    provider,
    lease_owner,
    DeliveryTimeline::new(clock),
    shutdown,
    &mut worker_state,
    telemetry.as_ref(),
  )
  .await
}

async fn run_scheduled_delivery_tick_with_timeline(
  state: &StateStore,
  provider: &dyn DeliveryProvider,
  lease_owner: &str,
  timeline: DeliveryTimeline,
  shutdown: watch::Receiver<bool>,
  worker_state: &mut DeliveryWorkerState,
  telemetry: &dyn SchedulerTelemetry,
) -> Result<ScheduledDeliveryTickOutcome, StateError> {
  if *shutdown.borrow() {
    return Ok(ScheduledDeliveryTickOutcome::Cancelled);
  }
  let policy = state.scheduler_operational_policy();
  state
    .reclaim_expired_scheduled_deliveries(
      timeline.fresh_now(),
      u32::from(policy.delivery_batch_limit),
    )
    .await?;
  if *shutdown.borrow() {
    return Ok(ScheduledDeliveryTickOutcome::Cancelled);
  }
  let preparation = tokio::select! {
    biased;
    () = cancellation_requested(shutdown.clone()) => {
      return Ok(ScheduledDeliveryTickOutcome::Cancelled);
    }
    preparation = prepare_next_scheduled_delivery(state, timeline.fresh_now()) => preparation?,
  };
  if matches!(preparation, Some(PreparedScheduledDelivery::SkippedNone(_))) {
    return Ok(ScheduledDeliveryTickOutcome::SkippedNone);
  }
  if matches!(
    preparation,
    Some(PreparedScheduledDelivery::SkippedUnchanged(_))
  ) {
    return Ok(ScheduledDeliveryTickOutcome::SkippedUnchanged);
  }
  let work = state
    .peek_scheduled_delivery_work(timeline.fresh_now())
    .await?;
  match work {
    ScheduledDeliveryWork::Idle => Ok(ScheduledDeliveryTickOutcome::Idle),
    ScheduledDeliveryWork::SkipUnchanged(authority) => {
      if *shutdown.borrow() {
        return Ok(ScheduledDeliveryTickOutcome::Cancelled);
      }
      if state
        .skip_scheduled_delivery_unchanged(&authority, timeline.fresh_now())
        .await?
      {
        Ok(ScheduledDeliveryTickOutcome::SkippedUnchanged)
      } else {
        Ok(ScheduledDeliveryTickOutcome::Idle)
      }
    }
    ScheduledDeliveryWork::ProviderRequired(authority) => {
      if *shutdown.borrow() {
        return Ok(ScheduledDeliveryTickOutcome::Cancelled);
      }
      let policy = authority.scheduler_policy().clone();
      let readiness = provider.readiness(DeliveryProviderReadinessRequest {
        delivery_id: authority.delivery_id(),
        target_json: authority.target_json(),
        target_digest: authority.target_digest(),
        payload_digest: authority.payload_digest(),
        binding_digest: authority.binding_digest(),
      });
      tokio::pin!(readiness);
      let readiness = tokio::select! {
        biased;
        () = cancellation_requested(shutdown.clone()) => {
          return Ok(ScheduledDeliveryTickOutcome::Cancelled);
        }
        readiness = &mut readiness => readiness,
        () = tokio::time::sleep(Duration::from_secs(u64::from(
          policy.delivery_readiness_timeout_seconds,
        ))) => {
          DeliveryProviderReadiness::Deferred {
            retry_after_seconds: None,
            error_kind: "provider_readiness_timeout".to_owned(),
          }
        }
      };
      match readiness {
        DeliveryProviderReadiness::Ready => worker_state.readiness_ready(),
        DeliveryProviderReadiness::Deferred {
          retry_after_seconds,
          error_kind: _,
        } => {
          return Ok(ScheduledDeliveryTickOutcome::ReadinessDeferred {
            retry_after: worker_state.readiness_retry(retry_after_seconds, &policy),
          });
        }
        DeliveryProviderReadiness::RejectDelivery { error_kind } => {
          if state
            .reject_scheduled_delivery_readiness(&authority, &error_kind, timeline.fresh_now())
            .await?
          {
            return Ok(ScheduledDeliveryTickOutcome::FailedTerminal);
          }
          return Ok(ScheduledDeliveryTickOutcome::Idle);
        }
        DeliveryProviderReadiness::FatalProvider { error_kind: _ } => {
          return Err(StateError::InvalidSchedulerState {
            reason: "scheduled delivery provider readiness failed fatally".to_owned(),
          });
        }
      }
      if *shutdown.borrow() {
        return Ok(ScheduledDeliveryTickOutcome::Cancelled);
      }
      let claim_time = timeline.fresh_now();
      let claim_clock = || timeline.fresh_now();
      let Some(claim) = state
        .claim_scheduled_delivery_from_snapshot_with_clock(
          &authority,
          lease_owner,
          claim_time,
          &claim_clock,
        )
        .await?
      else {
        return Ok(ScheduledDeliveryTickOutcome::Idle);
      };
      dispatch_claimed_delivery(state, provider, claim, timeline, shutdown, telemetry).await
    }
  }
}

async fn dispatch_claimed_delivery(
  state: &StateStore,
  provider: &dyn DeliveryProvider,
  claim: ClaimedScheduledDelivery,
  timeline: DeliveryTimeline,
  shutdown: watch::Receiver<bool>,
  telemetry: &dyn SchedulerTelemetry,
) -> Result<ScheduledDeliveryTickOutcome, StateError> {
  let started_at = Instant::now();
  let attempt = u32::try_from(claim.binding.attempt()).unwrap_or(u32::MAX);
  record_delivery_event(
    telemetry,
    SchedulerWorker::Delivery,
    SchedulerOperation::Attempt,
    SchedulerOperationStatus::Started,
    None,
    Duration::ZERO,
    Some(attempt),
  );
  let result = dispatch_claimed_delivery_inner(state, provider, claim, timeline, shutdown).await;
  record_delivery_event(
    telemetry,
    SchedulerWorker::Delivery,
    SchedulerOperation::Attempt,
    match &result {
      Ok(outcome) => delivery_tick_status(*outcome),
      Err(_) => SchedulerOperationStatus::Failed,
    },
    result
      .as_ref()
      .err()
      .map(|_| SchedulerTelemetryErrorKind::State),
    started_at.elapsed(),
    Some(attempt),
  );
  result
}

async fn dispatch_claimed_delivery_inner(
  state: &StateStore,
  provider: &dyn DeliveryProvider,
  claim: ClaimedScheduledDelivery,
  timeline: DeliveryTimeline,
  shutdown: watch::Receiver<bool>,
) -> Result<ScheduledDeliveryTickOutcome, StateError> {
  let mut heartbeat = DeliveryHeartbeat::start(
    state.clone(),
    claim.binding.clone(),
    timeline.clone(),
    claim.scheduler_policy.clone(),
  );
  if *shutdown.borrow() {
    return release_before_dispatch(state, &claim, &timeline, &mut heartbeat).await;
  }
  let dispatch_now = timeline.fresh_now();
  if claim
    .scheduler_policy
    .delivery_deadline_at(claim.payload.created_at())
    .is_none_or(|deadline| dispatch_now >= deadline)
  {
    if let Err(error) = heartbeat.stop_and_join().await {
      return authority_error(error);
    }
    return commit_failure(
      state,
      &claim,
      ScheduledDeliveryFailure::ConfirmedNoWriteTerminal {
        error_kind: "delivery_deadline_exceeded".to_owned(),
        redacted_message: None,
      },
      dispatch_now,
      ScheduledDeliveryTickOutcome::FailedTerminal,
    )
    .await;
  }

  let request = DeliveryProviderRequest {
    payload: &claim.payload,
    target_json: &claim.target_json,
    idempotency_key: claim.binding.idempotency_key(),
  };
  let send_polled = Arc::new(AtomicBool::new(false));
  let send = CatchUnwindFuture::new(provider.send(request), Arc::clone(&send_polled));
  tokio::pin!(send);
  let outcome = tokio::select! {
    biased;
    () = cancellation_requested(shutdown) => {
      if send_polled.load(Ordering::Acquire) {
        DeliveryProviderOutcome::AmbiguousPostWrite {
          error_kind: "cancelled_after_dispatch".to_owned(),
        }
      } else {
        return release_before_dispatch(state, &claim, &timeline, &mut heartbeat).await;
      }
    },
    heartbeat_result = &mut heartbeat.join => {
      return heartbeat_ended(heartbeat_result);
    }
    outcome = &mut send => match outcome {
      Ok(outcome) => outcome,
      Err(panic) => {
        if let Err(error) = heartbeat.stop_and_join().await {
          panic!("scheduled delivery provider and heartbeat cleanup failed: {error}");
        }
        std::panic::resume_unwind(panic);
      }
    },
    () = tokio::time::sleep(Duration::from_secs(u64::from(
      claim.scheduler_policy.delivery_send_timeout_seconds,
    ))) => DeliveryProviderOutcome::AmbiguousPostWrite {
      error_kind: "provider_timeout".to_owned(),
    },
  };
  if let Err(error) = heartbeat.stop_and_join().await {
    return authority_error(error);
  }
  finalize_outcome(state, &claim, outcome, &timeline).await
}

struct CatchUnwindFuture<F> {
  inner: Pin<Box<F>>,
  polled: Arc<AtomicBool>,
}

impl<F> CatchUnwindFuture<F> {
  fn new(inner: F, polled: Arc<AtomicBool>) -> Self {
    Self {
      inner: Box::pin(inner),
      polled,
    }
  }
}

impl<F: Future> Future for CatchUnwindFuture<F> {
  type Output = Result<F::Output, Box<dyn std::any::Any + Send>>;

  fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
    self.polled.store(true, Ordering::Release);
    std::panic::catch_unwind(AssertUnwindSafe(|| self.inner.as_mut().poll(context)))
      .map_or_else(|panic| Poll::Ready(Err(panic)), |poll| poll.map(Ok))
  }
}

async fn finalize_outcome(
  state: &StateStore,
  claim: &ClaimedScheduledDelivery,
  outcome: DeliveryProviderOutcome,
  timeline: &DeliveryTimeline,
) -> Result<ScheduledDeliveryTickOutcome, StateError> {
  let finalization = async {
    let heartbeat_time = timeline.fresh_now();
    let lease_expires_at = checked_add(
      heartbeat_time,
      i64::from(claim.scheduler_policy.delivery_lease_seconds) + 1,
      "delivery finalization lease",
    )?;
    state
      .heartbeat_scheduled_delivery(&claim.binding, heartbeat_time, lease_expires_at)
      .await?;
    let completion_time = timeline.fresh_now();
    commit_outcome(state, claim, outcome, completion_time).await
  };
  match tokio::time::timeout(
    Duration::from_secs(u64::from(
      claim.scheduler_policy.delivery_finalization_timeout_seconds,
    )),
    finalization,
  )
  .await
  {
    Ok(Ok(outcome)) => Ok(outcome),
    Ok(Err(error)) => authority_error(error),
    Err(_) => Err(StateError::InvalidSchedulerState {
      reason: "scheduled delivery finalization timed out".to_owned(),
    }),
  }
}

struct DeliveryHeartbeat {
  stop: Option<oneshot::Sender<()>>,
  join: JoinHandle<Result<(), StateError>>,
  finalization_timeout: Duration,
}

impl DeliveryHeartbeat {
  fn start(
    state: StateStore,
    binding: codeoff_state::ScheduledDeliveryBinding,
    timeline: DeliveryTimeline,
    policy: SchedulerOperationalPolicy,
  ) -> Self {
    let (stop, mut stopped) = oneshot::channel();
    let join = tokio::spawn(async move {
      loop {
        tokio::select! {
          biased;
          _ = &mut stopped => return Ok(()),
          () = tokio::time::sleep(Duration::from_millis(
            policy.delivery_heartbeat_interval_ms,
          )) => {}
        }
        let heartbeat_time = timeline.fresh_now();
        let lease_expires_at = checked_add(
          heartbeat_time,
          i64::from(policy.delivery_lease_seconds),
          "delivery heartbeat lease",
        )?;
        state
          .heartbeat_scheduled_delivery(&binding, heartbeat_time, lease_expires_at)
          .await?;
      }
    });
    Self {
      stop: Some(stop),
      join,
      finalization_timeout: Duration::from_secs(u64::from(
        policy.delivery_finalization_timeout_seconds,
      )),
    }
  }

  async fn stop_and_join(&mut self) -> Result<(), StateError> {
    if let Some(stop) = self.stop.take() {
      let _ = stop.send(());
    }
    if let Ok(result) = tokio::time::timeout(self.finalization_timeout, &mut self.join).await {
      heartbeat_stopped(result)
    } else {
      self.join.abort();
      match (&mut self.join).await {
        Ok(Err(error)) => Err(error),
        Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
        Ok(Ok(())) | Err(_) => Err(StateError::InvalidSchedulerState {
          reason: "scheduled delivery heartbeat cleanup timed out".to_owned(),
        }),
      }
    }
  }
}

impl Drop for DeliveryHeartbeat {
  fn drop(&mut self) {
    self.join.abort();
  }
}

fn heartbeat_ended(
  result: Result<Result<(), StateError>, tokio::task::JoinError>,
) -> Result<ScheduledDeliveryTickOutcome, StateError> {
  match result {
    Ok(Err(error)) if is_lost_delivery_authority(&error) => {
      Ok(ScheduledDeliveryTickOutcome::LostFence)
    }
    Ok(Err(error)) => Err(error),
    Ok(Ok(())) => Err(StateError::InvalidSchedulerState {
      reason: "scheduled delivery heartbeat stopped unexpectedly".to_owned(),
    }),
    Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
    Err(_) => Err(StateError::InvalidSchedulerState {
      reason: "scheduled delivery heartbeat was cancelled unexpectedly".to_owned(),
    }),
  }
}

fn heartbeat_stopped(
  result: Result<Result<(), StateError>, tokio::task::JoinError>,
) -> Result<(), StateError> {
  match result {
    Ok(result) => result,
    Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
    Err(_) => Err(StateError::InvalidSchedulerState {
      reason: "scheduled delivery heartbeat was cancelled during cleanup".to_owned(),
    }),
  }
}

fn authority_error(error: StateError) -> Result<ScheduledDeliveryTickOutcome, StateError> {
  if is_lost_delivery_authority(&error) {
    Ok(ScheduledDeliveryTickOutcome::LostFence)
  } else {
    Err(error)
  }
}

async fn release_before_dispatch(
  state: &StateStore,
  claim: &ClaimedScheduledDelivery,
  timeline: &DeliveryTimeline,
  heartbeat: &mut DeliveryHeartbeat,
) -> Result<ScheduledDeliveryTickOutcome, StateError> {
  if let Err(error) = heartbeat.stop_and_join().await {
    return authority_error(error);
  }
  let now = timeline.fresh_now();
  let failure = claim
    .scheduler_policy
    .delivery_retry_at(
      claim.binding.delivery_id(),
      claim.binding.attempt(),
      claim.payload.created_at(),
      now,
      None,
    )
    .map_or_else(
      || ScheduledDeliveryFailure::ConfirmedNoWriteTerminal {
        error_kind: "delivery_retry_exhausted".to_owned(),
        redacted_message: None,
      },
      |next_attempt_at| ScheduledDeliveryFailure::ConfirmedNoWriteRetryable {
        error_kind: "cancelled_before_dispatch".to_owned(),
        redacted_message: None,
        next_attempt_at,
      },
    );
  let outcome = if matches!(
    failure,
    ScheduledDeliveryFailure::ConfirmedNoWriteRetryable { .. }
  ) {
    ScheduledDeliveryTickOutcome::RetryDeferred
  } else {
    ScheduledDeliveryTickOutcome::FailedTerminal
  };
  let commit = commit_failure(state, claim, failure, now, outcome);
  match tokio::time::timeout(
    Duration::from_secs(u64::from(
      claim.scheduler_policy.delivery_finalization_timeout_seconds,
    )),
    commit,
  )
  .await
  {
    Ok(result) => result,
    Err(_) => Err(StateError::InvalidSchedulerState {
      reason: "scheduled delivery pre-dispatch release timed out".to_owned(),
    }),
  }
}

async fn commit_outcome(
  state: &StateStore,
  claim: &ClaimedScheduledDelivery,
  outcome: DeliveryProviderOutcome,
  now: i64,
) -> Result<ScheduledDeliveryTickOutcome, StateError> {
  match outcome {
    DeliveryProviderOutcome::ConfirmedSuccess(identity) => {
      match state
        .complete_scheduled_delivery_delivered(&claim.binding, &identity.canonical_receipt()?, now)
        .await
      {
        Ok(()) => Ok(ScheduledDeliveryTickOutcome::Delivered),
        Err(error) if is_lost_delivery_authority(&error) => {
          Ok(ScheduledDeliveryTickOutcome::LostFence)
        }
        Err(error) => Err(error),
      }
    }
    DeliveryProviderOutcome::ConfirmedNoWriteRetryable {
      retry_after_seconds,
      error_kind,
    } => {
      let Some(next_attempt_at) = retry_at(claim, now, retry_after_seconds) else {
        return commit_failure(
          state,
          claim,
          ScheduledDeliveryFailure::ConfirmedNoWriteTerminal {
            error_kind: "delivery_retry_exhausted".to_owned(),
            redacted_message: None,
          },
          now,
          ScheduledDeliveryTickOutcome::FailedTerminal,
        )
        .await;
      };
      commit_failure(
        state,
        claim,
        ScheduledDeliveryFailure::ConfirmedNoWriteRetryable {
          error_kind,
          redacted_message: None,
          next_attempt_at,
        },
        now,
        ScheduledDeliveryTickOutcome::RetryDeferred,
      )
      .await
    }
    DeliveryProviderOutcome::ConfirmedNoWriteTerminal { error_kind } => {
      commit_failure(
        state,
        claim,
        ScheduledDeliveryFailure::ConfirmedNoWriteTerminal {
          error_kind,
          redacted_message: None,
        },
        now,
        ScheduledDeliveryTickOutcome::FailedTerminal,
      )
      .await
    }
    DeliveryProviderOutcome::AmbiguousPostWrite { error_kind } => {
      commit_failure(
        state,
        claim,
        ScheduledDeliveryFailure::AmbiguousPostWrite {
          error_kind,
          redacted_message: None,
        },
        now,
        ScheduledDeliveryTickOutcome::DeliveryUnknown,
      )
      .await
    }
  }
}

async fn commit_failure(
  state: &StateStore,
  claim: &ClaimedScheduledDelivery,
  failure: ScheduledDeliveryFailure,
  now: i64,
  success: ScheduledDeliveryTickOutcome,
) -> Result<ScheduledDeliveryTickOutcome, StateError> {
  match state
    .complete_scheduled_delivery_failure(&claim.binding, &failure, now)
    .await
  {
    Ok(()) => Ok(success),
    Err(error) if is_lost_delivery_authority(&error) => Ok(ScheduledDeliveryTickOutcome::LostFence),
    Err(error) => Err(error),
  }
}

fn retry_at(
  claim: &ClaimedScheduledDelivery,
  now: i64,
  retry_after_seconds: Option<u64>,
) -> Option<i64> {
  if claim.payload.delivery_policy_version() != DELIVERY_POLICY_VERSION {
    return None;
  }
  claim.scheduler_policy.delivery_retry_at(
    claim.binding.delivery_id(),
    claim.binding.attempt(),
    claim.payload.created_at(),
    now,
    retry_after_seconds,
  )
}

fn is_lost_delivery_authority(error: &StateError) -> bool {
  matches!(
    error,
    StateError::ScheduledDeliveryLostLease | StateError::ScheduledDeliveryBaselineConflict
  )
}

fn checked_add(value: i64, increment: i64, field: &str) -> Result<i64, StateError> {
  value
    .checked_add(increment)
    .ok_or_else(|| StateError::InvalidSchedulerState {
      reason: format!("{field} overflows"),
    })
}

async fn cancellation_requested(mut shutdown: watch::Receiver<bool>) {
  while !*shutdown.borrow() {
    if shutdown.changed().await.is_err() {
      std::future::pending::<()>().await;
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::sync::Mutex;
  use tempfile::tempdir;

  #[derive(Default)]
  struct RecordingTelemetry {
    events: Mutex<Vec<SchedulerTelemetryEvent>>,
  }

  impl SchedulerTelemetry for RecordingTelemetry {
    fn record(&self, event: SchedulerTelemetryEvent) {
      self.events.lock().expect("telemetry events").push(event);
    }
  }

  #[tokio::test]
  async fn preparation_worker_emits_one_normal_loop_terminal_event() {
    let temp = tempdir().expect("tempdir");
    let state = StateStore::initialize(&temp.path().join("state"), None)
      .await
      .expect("state");
    let (shutdown, shutdown_rx) = watch::channel(true);
    let telemetry = Arc::new(RecordingTelemetry::default());

    run_scheduled_delivery_preparation_worker(state, shutdown_rx, telemetry.clone())
      .await
      .expect("worker exit");
    drop(shutdown);
    let events = telemetry.events.lock().expect("telemetry events");
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].status, SchedulerOperationStatus::Started);
    assert_eq!(events[1].status, SchedulerOperationStatus::Stopped);
    assert_eq!(events[1].worker, SchedulerWorker::DeliveryPreparation);
  }

  #[test]
  fn delivery_tick_telemetry_uses_fixed_outcomes() {
    for (outcome, expected) in [
      (
        ScheduledDeliveryTickOutcome::Cancelled,
        SchedulerOperationStatus::Cancelled,
      ),
      (
        ScheduledDeliveryTickOutcome::SkippedNone,
        SchedulerOperationStatus::Skipped,
      ),
      (
        ScheduledDeliveryTickOutcome::ReadinessDeferred {
          retry_after: Duration::from_secs(1),
        },
        SchedulerOperationStatus::Deferred,
      ),
      (
        ScheduledDeliveryTickOutcome::Delivered,
        SchedulerOperationStatus::Completed,
      ),
      (
        ScheduledDeliveryTickOutcome::DeliveryUnknown,
        SchedulerOperationStatus::Unknown,
      ),
      (
        ScheduledDeliveryTickOutcome::LostFence,
        SchedulerOperationStatus::LostAuthority,
      ),
    ] {
      assert_eq!(delivery_tick_status(outcome), expected);
    }
  }

  #[test]
  fn readiness_backoff_caps_local_and_provider_delays_and_resets() {
    let mut state = DeliveryWorkerState::default();
    let policy = SchedulerOperationalPolicy::default();
    assert_eq!(state.readiness_retry(None, &policy), Duration::from_secs(1));
    assert_eq!(
      state.readiness_retry(Some(0), &policy),
      Duration::from_secs(2)
    );
    assert_eq!(state.readiness_retry(None, &policy), Duration::from_secs(4));
    assert_eq!(state.readiness_retry(None, &policy), Duration::from_secs(8));
    assert_eq!(
      state.readiness_retry(None, &policy),
      Duration::from_secs(16)
    );
    assert_eq!(
      state.readiness_retry(None, &policy),
      Duration::from_secs(32)
    );
    assert_eq!(state.readiness_retry(None, &policy), Duration::from_mins(1));
    assert_eq!(
      state.readiness_retry(Some(120), &policy),
      Duration::from_mins(2)
    );
    assert_eq!(
      state.readiness_retry(Some(u64::MAX), &policy),
      Duration::from_hours(1)
    );
    state.readiness_ready();
    assert_eq!(state.readiness_retry(None, &policy), Duration::from_secs(1));
  }

  #[tokio::test]
  async fn send_poll_tracking_marks_ready_and_panicking_futures() {
    let ready_polled = Arc::new(AtomicBool::new(false));
    let Ok(value) = CatchUnwindFuture::new(async { 42 }, Arc::clone(&ready_polled)).await else {
      panic!("ready future panicked")
    };
    assert_eq!(value, 42);
    assert!(ready_polled.load(Ordering::Acquire));

    let panic_polled = Arc::new(AtomicBool::new(false));
    assert!(
      CatchUnwindFuture::new(
        async { panic!("test send panic") },
        Arc::clone(&panic_polled),
      )
      .await
      .is_err()
    );
    assert!(panic_polled.load(Ordering::Acquire));
  }
}
