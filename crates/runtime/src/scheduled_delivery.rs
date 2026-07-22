use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{future::Future, panic::AssertUnwindSafe, pin::Pin, task::Context, task::Poll};

use async_trait::async_trait;
use codeoff_state::{
  ClaimedScheduledDelivery, DeliveryPayloadSnapshot, ScheduledDeliveryFailure,
  ScheduledDeliveryWork, StateError, StateStore,
};
use serde_json::json;
use tokio::sync::{Mutex as AsyncMutex, oneshot, watch};
use tokio::task::JoinHandle;

const DELIVERY_TICK_INTERVAL: Duration = Duration::from_millis(250);
const DELIVERY_LEASE_SECONDS: i64 = 60;
const DELIVERY_SEND_TIMEOUT: Duration = Duration::from_secs(30);
const DELIVERY_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);
const DELIVERY_BATCH_LIMIT: u32 = 32;
const DELIVERY_POLICY_VERSION: u32 = 1;
const MAX_DELIVERY_ATTEMPTS: i64 = 5;
const DELIVERY_DEADLINE_SECONDS: i64 = 3_600;
const MAX_RETRY_DELAY_SECONDS: i64 = 300;
const MAX_RETRY_AFTER_SECONDS: i64 = 3_600;
const DEFAULT_READINESS_RETRY: Duration = Duration::from_secs(5);
const MAX_READINESS_RETRY: Duration = Duration::from_mins(1);

pub struct DeliveryProviderReadinessRequest<'a> {
  pub target_json: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryProviderReadiness {
  Ready,
  Retryable {
    retry_after_seconds: Option<u64>,
    error_kind: String,
  },
  Permanent {
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
  SkippedUnchanged,
  ReadinessDeferred { retry_after: Duration },
  Delivered,
  RetryDeferred,
  FailedTerminal,
  DeliveryUnknown,
  LostFence,
}

pub async fn run_scheduled_delivery_worker(
  state: StateStore,
  provider: Arc<dyn DeliveryProvider>,
  lease_owner: String,
  shutdown: watch::Receiver<bool>,
) -> Result<(), StateError> {
  run_scheduled_delivery_worker_with_clock(
    state,
    provider,
    lease_owner,
    Arc::new(SystemDeliveryClock),
    shutdown,
  )
  .await
}

pub async fn run_scheduled_delivery_worker_with_clock(
  state: StateStore,
  provider: Arc<dyn DeliveryProvider>,
  lease_owner: String,
  clock: Arc<dyn DeliveryClock>,
  shutdown: watch::Receiver<bool>,
) -> Result<(), StateError> {
  let timeline = DeliveryTimeline::new(clock);
  loop {
    if *shutdown.borrow() {
      return Ok(());
    }
    let tick = run_scheduled_delivery_tick_with_timeline(
      &state,
      provider.as_ref(),
      &lease_owner,
      timeline.clone(),
      shutdown.clone(),
    )
    .await?;
    let delay = match tick {
      ScheduledDeliveryTickOutcome::Cancelled => return Ok(()),
      ScheduledDeliveryTickOutcome::Idle => DELIVERY_TICK_INTERVAL,
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

pub async fn run_scheduled_delivery_tick(
  state: &StateStore,
  provider: &dyn DeliveryProvider,
  lease_owner: &str,
  shutdown: watch::Receiver<bool>,
) -> Result<ScheduledDeliveryTickOutcome, StateError> {
  run_scheduled_delivery_tick_with_clock(
    state,
    provider,
    lease_owner,
    Arc::new(SystemDeliveryClock),
    shutdown,
  )
  .await
}

pub async fn run_scheduled_delivery_tick_with_clock(
  state: &StateStore,
  provider: &dyn DeliveryProvider,
  lease_owner: &str,
  clock: Arc<dyn DeliveryClock>,
  shutdown: watch::Receiver<bool>,
) -> Result<ScheduledDeliveryTickOutcome, StateError> {
  run_scheduled_delivery_tick_with_timeline(
    state,
    provider,
    lease_owner,
    DeliveryTimeline::new(clock),
    shutdown,
  )
  .await
}

async fn run_scheduled_delivery_tick_with_timeline(
  state: &StateStore,
  provider: &dyn DeliveryProvider,
  lease_owner: &str,
  timeline: DeliveryTimeline,
  shutdown: watch::Receiver<bool>,
) -> Result<ScheduledDeliveryTickOutcome, StateError> {
  if *shutdown.borrow() {
    return Ok(ScheduledDeliveryTickOutcome::Cancelled);
  }
  let work = state
    .peek_scheduled_delivery_work(timeline.fresh_now())
    .await?;
  match work {
    ScheduledDeliveryWork::Idle => return Ok(ScheduledDeliveryTickOutcome::Idle),
    ScheduledDeliveryWork::SkipUnchanged => {
      if *shutdown.borrow() {
        return Ok(ScheduledDeliveryTickOutcome::Cancelled);
      }
      return if state
        .skip_next_unchanged_scheduled_delivery(timeline.fresh_now())
        .await?
      {
        Ok(ScheduledDeliveryTickOutcome::SkippedUnchanged)
      } else {
        Ok(ScheduledDeliveryTickOutcome::Idle)
      };
    }
    ScheduledDeliveryWork::ProviderRequired { target_json } => {
      if *shutdown.borrow() {
        return Ok(ScheduledDeliveryTickOutcome::Cancelled);
      }
      let readiness = provider.readiness(DeliveryProviderReadinessRequest {
        target_json: &target_json,
      });
      tokio::pin!(readiness);
      let readiness = tokio::select! {
        biased;
        () = cancellation_requested(shutdown.clone()) => {
          return Ok(ScheduledDeliveryTickOutcome::Cancelled);
        }
        readiness = &mut readiness => readiness,
      };
      match readiness {
        DeliveryProviderReadiness::Ready => {}
        DeliveryProviderReadiness::Retryable {
          retry_after_seconds,
          error_kind: _,
        } => {
          return Ok(ScheduledDeliveryTickOutcome::ReadinessDeferred {
            retry_after: readiness_retry_delay(retry_after_seconds),
          });
        }
        DeliveryProviderReadiness::Permanent { error_kind: _ } => {
          return Err(StateError::InvalidSchedulerState {
            reason: "scheduled delivery provider readiness failed permanently".to_owned(),
          });
        }
      }
    }
  }
  if *shutdown.borrow() {
    return Ok(ScheduledDeliveryTickOutcome::Cancelled);
  }
  state
    .requeue_due_scheduled_deliveries(timeline.fresh_now(), DELIVERY_BATCH_LIMIT)
    .await?;
  state
    .reclaim_expired_scheduled_deliveries(timeline.fresh_now(), DELIVERY_BATCH_LIMIT)
    .await?;
  if *shutdown.borrow() {
    return Ok(ScheduledDeliveryTickOutcome::Cancelled);
  }
  let claim_time = timeline.fresh_now();
  let lease_expires_at = checked_add(claim_time, DELIVERY_LEASE_SECONDS, "delivery lease")?;
  let Some(claim) = state
    .claim_next_scheduled_delivery(lease_owner, claim_time, lease_expires_at)
    .await?
  else {
    return Ok(ScheduledDeliveryTickOutcome::Idle);
  };
  let mut heartbeat =
    DeliveryHeartbeat::start(state.clone(), claim.binding.clone(), timeline.clone());
  timeline.fresh_now();
  if *shutdown.borrow() {
    return release_before_dispatch(state, &claim, &timeline, &mut heartbeat).await;
  }

  let request = DeliveryProviderRequest {
    payload: &claim.payload,
    target_json: &claim.target_json,
    idempotency_key: claim.binding.idempotency_key(),
  };
  let send = CatchUnwindFuture::new(provider.send(request));
  tokio::pin!(send);
  let outcome = tokio::select! {
    biased;
    () = cancellation_requested(shutdown) => DeliveryProviderOutcome::AmbiguousPostWrite {
      error_kind: "cancelled_after_dispatch".to_owned(),
    },
    heartbeat_result = &mut heartbeat.join => {
      return heartbeat_ended(heartbeat_result);
    }
    outcome = &mut send => match outcome {
      Ok(outcome) => outcome,
      Err(panic) => {
        heartbeat.stop_and_join().await;
        std::panic::resume_unwind(panic);
      }
    },
    () = tokio::time::sleep(DELIVERY_SEND_TIMEOUT) => DeliveryProviderOutcome::AmbiguousPostWrite {
      error_kind: "provider_timeout".to_owned(),
    },
  };
  if let Err(error) = refresh_lease_before_commit(state, &claim, &timeline, &mut heartbeat).await {
    heartbeat.stop_and_join().await;
    return if is_lost_delivery_authority(&error) {
      Ok(ScheduledDeliveryTickOutcome::LostFence)
    } else {
      Err(error)
    };
  }
  let completion_time = timeline.fresh_now();
  let commit = commit_outcome(state, &claim, outcome, completion_time);
  tokio::pin!(commit);
  let result = tokio::select! {
    biased;
    heartbeat_result = &mut heartbeat.join => return heartbeat_ended(heartbeat_result),
    result = &mut commit => result,
  };
  heartbeat.stop_and_join().await;
  result
}

struct CatchUnwindFuture<F> {
  inner: Pin<Box<F>>,
}

impl<F> CatchUnwindFuture<F> {
  fn new(inner: F) -> Self {
    Self {
      inner: Box::pin(inner),
    }
  }
}

impl<F: Future> Future for CatchUnwindFuture<F> {
  type Output = Result<F::Output, Box<dyn std::any::Any + Send>>;

  fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
    std::panic::catch_unwind(AssertUnwindSafe(|| self.inner.as_mut().poll(context)))
      .map_or_else(|panic| Poll::Ready(Err(panic)), |poll| poll.map(Ok))
  }
}

async fn refresh_lease_before_commit(
  state: &StateStore,
  claim: &ClaimedScheduledDelivery,
  timeline: &DeliveryTimeline,
  heartbeat: &mut DeliveryHeartbeat,
) -> Result<(), StateError> {
  let heartbeat_time = timeline.fresh_now();
  let lease_expires_at = checked_add(
    heartbeat_time,
    DELIVERY_LEASE_SECONDS + 1,
    "delivery precommit lease",
  )?;
  let _heartbeat_gate = heartbeat.gate.lock().await;
  let refresh =
    state.heartbeat_scheduled_delivery(&claim.binding, heartbeat_time, lease_expires_at);
  tokio::pin!(refresh);
  tokio::select! {
    biased;
    heartbeat_result = &mut heartbeat.join => heartbeat_ended(heartbeat_result).map(|_| ()),
    result = &mut refresh => result,
  }
}

struct DeliveryHeartbeat {
  stop: Option<oneshot::Sender<()>>,
  join: JoinHandle<Result<(), StateError>>,
  gate: Arc<AsyncMutex<()>>,
}

impl DeliveryHeartbeat {
  fn start(
    state: StateStore,
    binding: codeoff_state::ScheduledDeliveryBinding,
    timeline: DeliveryTimeline,
  ) -> Self {
    let (stop, mut stopped) = oneshot::channel();
    let gate = Arc::new(AsyncMutex::new(()));
    let task_gate = Arc::clone(&gate);
    let join = tokio::spawn(async move {
      loop {
        tokio::select! {
          biased;
          _ = &mut stopped => return Ok(()),
          () = tokio::time::sleep(DELIVERY_HEARTBEAT_INTERVAL) => {}
        }
        let heartbeat_time = timeline.fresh_now();
        let lease_expires_at = checked_add(
          heartbeat_time,
          DELIVERY_LEASE_SECONDS,
          "delivery heartbeat lease",
        )?;
        let _heartbeat_gate = task_gate.lock().await;
        state
          .heartbeat_scheduled_delivery(&binding, heartbeat_time, lease_expires_at)
          .await?;
      }
    });
    Self {
      stop: Some(stop),
      join,
      gate,
    }
  }

  async fn stop_and_join(&mut self) {
    if let Some(stop) = self.stop.take() {
      let _ = stop.send(());
    }
    if !self.join.is_finished() {
      let _ = (&mut self.join).await;
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

async fn release_before_dispatch(
  state: &StateStore,
  claim: &ClaimedScheduledDelivery,
  timeline: &DeliveryTimeline,
  heartbeat: &mut DeliveryHeartbeat,
) -> Result<ScheduledDeliveryTickOutcome, StateError> {
  let now = timeline.fresh_now();
  let next_attempt_at = checked_add(now, 1, "shutdown delivery retry")?;
  let commit = commit_failure(
    state,
    claim,
    ScheduledDeliveryFailure::ConfirmedNoWriteRetryable {
      error_kind: "cancelled_before_dispatch".to_owned(),
      redacted_message: None,
      next_attempt_at,
    },
    now,
    ScheduledDeliveryTickOutcome::RetryDeferred,
  );
  tokio::pin!(commit);
  let result = tokio::select! {
    biased;
    heartbeat_result = &mut heartbeat.join => return heartbeat_ended(heartbeat_result),
    result = &mut commit => result,
  };
  heartbeat.stop_and_join().await;
  result
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
      let Some(next_attempt_at) = retry_at(claim, now, retry_after_seconds)? else {
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
) -> Result<Option<i64>, StateError> {
  if claim.payload.delivery_policy_version() != DELIVERY_POLICY_VERSION
    || claim.binding.attempt() >= MAX_DELIVERY_ATTEMPTS
  {
    return Ok(None);
  }
  let deadline = checked_add(
    claim.payload.created_at(),
    DELIVERY_DEADLINE_SECONDS,
    "delivery deadline",
  )?;
  if now >= deadline {
    return Ok(None);
  }
  let exponent = u32::try_from(claim.binding.attempt().saturating_sub(1).min(8)).unwrap_or(8);
  let exponential = 5_i64
    .checked_shl(exponent)
    .unwrap_or(MAX_RETRY_DELAY_SECONDS)
    .min(MAX_RETRY_DELAY_SECONDS);
  let jitter_bound = (exponential / 4).max(1);
  let jitter = claim
    .binding
    .delivery_id()
    .bytes()
    .fold(0_i64, |value, byte| value.wrapping_add(i64::from(byte)))
    .rem_euclid(jitter_bound);
  let retry_after = retry_after_seconds.map_or(0, |seconds| {
    i64::try_from(seconds)
      .unwrap_or(MAX_RETRY_AFTER_SECONDS)
      .clamp(1, MAX_RETRY_AFTER_SECONDS)
  });
  let delay = exponential.saturating_add(jitter).max(retry_after);
  let next_attempt_at = checked_add(now, delay, "delivery retry")?;
  Ok((next_attempt_at <= deadline).then_some(next_attempt_at))
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

fn readiness_retry_delay(retry_after_seconds: Option<u64>) -> Duration {
  retry_after_seconds.map_or(DEFAULT_READINESS_RETRY, |seconds| {
    Duration::from_secs(seconds.clamp(1, MAX_READINESS_RETRY.as_secs()))
  })
}

async fn cancellation_requested(mut shutdown: watch::Receiver<bool>) {
  while !*shutdown.borrow() {
    if shutdown.changed().await.is_err() {
      std::future::pending::<()>().await;
    }
  }
}
