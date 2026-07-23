use std::process;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use codeoff_state::{PrincipalKey, ScheduleMutationAudit, StateError};

use crate::schedule_authorization::ScheduleInvocation;
use crate::schedule_service::ScheduleServiceError;

static AUDIT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub(crate) struct ScheduleAuditAttempt {
  pub(crate) event_id: String,
  pub(crate) principal: Option<PrincipalKey>,
  pub(crate) operation: &'static str,
  pub(crate) job_id: Option<String>,
  pub(crate) request_id: String,
  pub(crate) correlation_id: String,
  pub(crate) occurred_at: i64,
  started_at: Instant,
}

impl ScheduleAuditAttempt {
  pub(crate) fn new(
    invocation: &ScheduleInvocation,
    operation: &'static str,
    request_id: Option<&str>,
    job_id: Option<&str>,
    occurred_at: i64,
  ) -> Self {
    let event_id = unique_audit_event_id();
    let correlation_id = request_id
      .filter(|value| !value.is_empty() && value.len() <= 255)
      .map(ToOwned::to_owned)
      .unwrap_or_else(|| event_id.clone());
    Self {
      event_id,
      principal: invocation.canonical_actor().ok(),
      operation,
      job_id: job_id.map(ToOwned::to_owned),
      request_id: correlation_id.clone(),
      correlation_id,
      occurred_at,
      started_at: Instant::now(),
    }
  }

  pub(crate) fn record(
    &self,
    outcome: &str,
    decision: &str,
    error_code: Option<&str>,
  ) -> ScheduleMutationAudit {
    ScheduleMutationAudit {
      audit_id: self.event_id.clone(),
      principal: self.principal.clone(),
      operation: self.operation.to_owned(),
      job_id: self.job_id.clone(),
      request_id: self.request_id.clone(),
      outcome: outcome.to_owned(),
      decision: decision.to_owned(),
      reason: error_code.map(ToOwned::to_owned),
      error_code: error_code.map(ToOwned::to_owned),
      old_generation: None,
      new_generation: None,
      resolver_provider: None,
      target_kind: None,
      resolver_version: None,
      resolver_digest: None,
      capability_version: None,
      capability_digest: None,
      idempotency_outcome: None,
      latency_ms: i64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(i64::MAX),
      correlation_id: self.correlation_id.clone(),
      occurred_at: self.occurred_at,
    }
  }

  pub(crate) fn error_record(&self, error: &ScheduleServiceError) -> ScheduleMutationAudit {
    let classification = classify_error(error);
    self.record(
      classification.outcome,
      classification.decision,
      Some(error.code()),
    )
  }
}

struct AuditClassification {
  outcome: &'static str,
  decision: &'static str,
}

fn classify_error(error: &ScheduleServiceError) -> AuditClassification {
  let (outcome, decision) = match error {
    ScheduleServiceError::Unauthorized => ("denied", "deny"),
    ScheduleServiceError::NotVisible => ("not_visible", "deny"),
    ScheduleServiceError::InvalidRequest(_)
    | ScheduleServiceError::PolicyLimit(_)
    | ScheduleServiceError::State(StateError::ScheduledActiveJobLimitExceeded { .. }) => {
      ("validation", "deny")
    }
    ScheduleServiceError::ResolverUnavailable => ("resolver_unavailable", "error"),
    ScheduleServiceError::TargetUnavailable => ("target_unavailable", "deny"),
    ScheduleServiceError::ResolverNotAllowed => ("resolver_not_allowed", "deny"),
    ScheduleServiceError::ResolverTimeout => ("resolver_timeout", "error"),
    ScheduleServiceError::CapabilityUnavailable => ("capability_unavailable", "deny"),
    ScheduleServiceError::CapabilityInvalid => ("capability_invalid", "error"),
    ScheduleServiceError::IdempotencyInProgress => ("in_progress", "error"),
    ScheduleServiceError::IdempotencyConflict => ("conflict", "deny"),
    ScheduleServiceError::State(StateError::SchedulerGenerationConflict) => {
      ("stale_generation", "error")
    }
    ScheduleServiceError::State(StateError::ScheduledOnceExpired) => {
      ("expired_not_resumable", "error")
    }
    ScheduleServiceError::State(error) if error.is_transient_storage_contention() => {
      ("storage_busy", "error")
    }
    ScheduleServiceError::State(_) => ("storage_internal", "error"),
  };
  AuditClassification { outcome, decision }
}

fn unique_audit_event_id() -> String {
  let sequence = AUDIT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
  let nanos = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap_or_default()
    .as_nanos();
  format!("audit_{:x}_{nanos:x}_{sequence:x}", process::id())
}
