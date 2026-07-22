use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use codeoff_state::{
  ClaimedScheduledDelivery, DeliveryPayloadSnapshot, ScheduledDeliveryFailure, StateError,
  StateStore,
};
use serde_json::json;
use tokio::sync::watch;

const DELIVERY_TICK_INTERVAL: Duration = Duration::from_millis(250);
const DELIVERY_LEASE_SECONDS: i64 = 60;
const DELIVERY_SEND_TIMEOUT: Duration = Duration::from_secs(30);
const DELIVERY_BATCH_LIMIT: u32 = 32;
const DELIVERY_POLICY_VERSION: u32 = 1;
const MAX_DELIVERY_ATTEMPTS: i64 = 5;
const DELIVERY_DEADLINE_SECONDS: i64 = 3_600;
const MAX_RETRY_DELAY_SECONDS: i64 = 300;
const MAX_RETRY_AFTER_SECONDS: i64 = 3_600;

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
  async fn send(&self, request: DeliveryProviderRequest<'_>) -> DeliveryProviderOutcome;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScheduledDeliveryTickOutcome {
  Idle,
  Cancelled,
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
  loop {
    if *shutdown.borrow() {
      return Ok(());
    }
    let tick = run_scheduled_delivery_tick(
      &state,
      provider.as_ref(),
      &lease_owner,
      now_unix_seconds(),
      shutdown.clone(),
    )
    .await?;
    let delay = match tick {
      ScheduledDeliveryTickOutcome::Cancelled => return Ok(()),
      ScheduledDeliveryTickOutcome::Idle => DELIVERY_TICK_INTERVAL,
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
  now: i64,
  shutdown: watch::Receiver<bool>,
) -> Result<ScheduledDeliveryTickOutcome, StateError> {
  if *shutdown.borrow() {
    return Ok(ScheduledDeliveryTickOutcome::Cancelled);
  }
  state
    .requeue_due_scheduled_deliveries(now, DELIVERY_BATCH_LIMIT)
    .await?;
  state
    .reclaim_expired_scheduled_deliveries(now, DELIVERY_BATCH_LIMIT)
    .await?;
  if *shutdown.borrow() {
    return Ok(ScheduledDeliveryTickOutcome::Cancelled);
  }
  let lease_expires_at = checked_add(now, DELIVERY_LEASE_SECONDS, "delivery lease")?;
  let Some(claim) = state
    .claim_next_scheduled_delivery(lease_owner, now, lease_expires_at)
    .await?
  else {
    return Ok(ScheduledDeliveryTickOutcome::Idle);
  };
  if *shutdown.borrow() {
    return release_before_dispatch(state, &claim, now).await;
  }

  let request = DeliveryProviderRequest {
    payload: &claim.payload,
    target_json: &claim.target_json,
    idempotency_key: claim.binding.idempotency_key(),
  };
  let send = provider.send(request);
  tokio::pin!(send);
  let outcome = tokio::select! {
    biased;
    outcome = &mut send => outcome,
    () = cancellation_requested(shutdown) => DeliveryProviderOutcome::AmbiguousPostWrite {
      error_kind: "cancelled_after_dispatch".to_owned(),
    },
    () = tokio::time::sleep(DELIVERY_SEND_TIMEOUT) => DeliveryProviderOutcome::AmbiguousPostWrite {
      error_kind: "provider_timeout".to_owned(),
    },
  };
  commit_outcome(state, &claim, outcome, now).await
}

async fn release_before_dispatch(
  state: &StateStore,
  claim: &ClaimedScheduledDelivery,
  now: i64,
) -> Result<ScheduledDeliveryTickOutcome, StateError> {
  let next_attempt_at = checked_add(now, 1, "shutdown delivery retry")?;
  commit_failure(
    state,
    claim,
    ScheduledDeliveryFailure::ConfirmedNoWriteRetryable {
      error_kind: "cancelled_before_dispatch".to_owned(),
      redacted_message: None,
      next_attempt_at,
    },
    now,
    ScheduledDeliveryTickOutcome::RetryDeferred,
  )
  .await
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

fn now_unix_seconds() -> i64 {
  SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .map_or(0, |duration| {
      i64::try_from(duration.as_secs()).unwrap_or(i64::MAX)
    })
}

async fn cancellation_requested(mut shutdown: watch::Receiver<bool>) {
  while !*shutdown.borrow() {
    if shutdown.changed().await.is_err() {
      return;
    }
  }
}
