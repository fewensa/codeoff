use std::str::FromStr;

use super::{StateValueError, validate_lowercase_sha256, validate_text};
use crate::StateError;

pub const DELIVERY_PAYLOAD_SCHEMA_VERSION: u32 = 1;
pub const DELIVERY_PAYLOAD_HASH_ALGORITHM: &str = "sha256-utf8-exact-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScheduledDeliveryState {
  Pending,
  Sending,
  Delivered,
  FailedRetryable,
  FailedTerminal,
  DeliveryUnknown,
  SkippedNone,
  SkippedUnchanged,
}

impl ScheduledDeliveryState {
  #[must_use]
  pub const fn as_str(self) -> &'static str {
    match self {
      Self::Pending => "pending",
      Self::Sending => "sending",
      Self::Delivered => "delivered",
      Self::FailedRetryable => "failed_retryable",
      Self::FailedTerminal => "failed_terminal",
      Self::DeliveryUnknown => "delivery_unknown",
      Self::SkippedNone => "skipped_none",
      Self::SkippedUnchanged => "skipped_unchanged",
    }
  }
}

impl FromStr for ScheduledDeliveryState {
  type Err = StateError;

  fn from_str(value: &str) -> Result<Self, Self::Err> {
    match value {
      "pending" => Ok(Self::Pending),
      "sending" => Ok(Self::Sending),
      "delivered" => Ok(Self::Delivered),
      "failed_retryable" => Ok(Self::FailedRetryable),
      "failed_terminal" => Ok(Self::FailedTerminal),
      "delivery_unknown" => Ok(Self::DeliveryUnknown),
      "skipped_none" => Ok(Self::SkippedNone),
      "skipped_unchanged" => Ok(Self::SkippedUnchanged),
      _ => Err(StateError::InvalidSchedulerState {
        reason: format!("invalid delivery state {value}"),
      }),
    }
  }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryPayloadSnapshot {
  schema_version: u32,
  delivery_id: String,
  run_id: String,
  result_id: String,
  content_type: String,
  body: String,
  digest: String,
  target_identity_digest: String,
  target_snapshot_digest: String,
  target_snapshot_version: u32,
  delivery_policy_version: u32,
  render_version: u32,
  created_at: i64,
}

impl DeliveryPayloadSnapshot {
  #[allow(clippy::too_many_arguments)]
  pub(crate) fn from_durable_parts(
    delivery_id: String,
    run_id: String,
    result_id: String,
    content_type: String,
    body: String,
    digest: String,
    target_identity_digest: String,
    target_snapshot_digest: String,
    target_snapshot_version: u32,
    delivery_policy_version: u32,
    render_version: u32,
    created_at: i64,
  ) -> Result<Self, StateValueError> {
    let value = Self {
      schema_version: DELIVERY_PAYLOAD_SCHEMA_VERSION,
      delivery_id,
      run_id,
      result_id,
      content_type,
      body,
      digest,
      target_identity_digest,
      target_snapshot_digest,
      target_snapshot_version,
      delivery_policy_version,
      render_version,
      created_at,
    };
    value.validate()?;
    Ok(value)
  }

  pub(crate) fn validate(&self) -> Result<(), StateValueError> {
    for (field, value) in [
      ("delivery id", self.delivery_id.as_str()),
      ("delivery run id", self.run_id.as_str()),
      ("delivery result id", self.result_id.as_str()),
      ("delivery content type", self.content_type.as_str()),
    ] {
      validate_text(field, value)?;
    }
    validate_lowercase_sha256("delivery payload digest", &self.digest)?;
    validate_lowercase_sha256(
      "delivery target identity digest",
      &self.target_identity_digest,
    )?;
    validate_lowercase_sha256(
      "delivery target snapshot digest",
      &self.target_snapshot_digest,
    )?;
    if self.schema_version == 0
      || self.target_snapshot_version == 0
      || self.delivery_policy_version == 0
      || self.render_version == 0
      || self.created_at < 0
    {
      return Err(StateValueError::InvalidVersion);
    }
    Ok(())
  }

  #[must_use]
  pub const fn schema_version(&self) -> u32 {
    self.schema_version
  }
  #[must_use]
  pub fn delivery_id(&self) -> &str {
    &self.delivery_id
  }
  #[must_use]
  pub fn run_id(&self) -> &str {
    &self.run_id
  }
  #[must_use]
  pub fn result_id(&self) -> &str {
    &self.result_id
  }
  #[must_use]
  pub fn content_type(&self) -> &str {
    &self.content_type
  }
  #[must_use]
  pub fn body(&self) -> &str {
    &self.body
  }
  #[must_use]
  pub fn digest(&self) -> &str {
    &self.digest
  }
  #[must_use]
  pub fn target_identity_digest(&self) -> &str {
    &self.target_identity_digest
  }
  #[must_use]
  pub fn target_snapshot_digest(&self) -> &str {
    &self.target_snapshot_digest
  }
  #[must_use]
  pub const fn target_snapshot_version(&self) -> u32 {
    self.target_snapshot_version
  }
  #[must_use]
  pub const fn delivery_policy_version(&self) -> u32 {
    self.delivery_policy_version
  }
  #[must_use]
  pub const fn render_version(&self) -> u32 {
    self.render_version
  }
  #[must_use]
  pub const fn created_at(&self) -> i64 {
    self.created_at
  }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduledDeliveryBinding {
  delivery_id: String,
  attempt: i64,
  fence: i64,
  lease_owner: String,
  idempotency_key: String,
}

impl ScheduledDeliveryBinding {
  pub(crate) fn new(
    delivery_id: String,
    attempt: i64,
    fence: i64,
    lease_owner: String,
    idempotency_key: String,
  ) -> Self {
    Self {
      delivery_id,
      attempt,
      fence,
      lease_owner,
      idempotency_key,
    }
  }

  #[must_use]
  pub fn delivery_id(&self) -> &str {
    &self.delivery_id
  }
  #[must_use]
  pub const fn attempt(&self) -> i64 {
    self.attempt
  }
  #[must_use]
  pub const fn fence(&self) -> i64 {
    self.fence
  }
  #[must_use]
  pub fn lease_owner(&self) -> &str {
    &self.lease_owner
  }
  #[must_use]
  pub fn idempotency_key(&self) -> &str {
    &self.idempotency_key
  }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimedScheduledDelivery {
  pub binding: ScheduledDeliveryBinding,
  pub payload: DeliveryPayloadSnapshot,
  pub target_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduledDeliveryAuthority {
  delivery_id: String,
  source_state: ScheduledDeliveryState,
  target_json: String,
  target_digest: String,
  payload_digest: String,
  binding_digest: String,
  intent_key: String,
}

impl ScheduledDeliveryAuthority {
  pub(crate) fn new(
    delivery_id: String,
    source_state: ScheduledDeliveryState,
    target_json: String,
    target_digest: String,
    payload_digest: String,
    binding_digest: String,
    intent_key: String,
  ) -> Self {
    Self {
      delivery_id,
      source_state,
      target_json,
      target_digest,
      payload_digest,
      binding_digest,
      intent_key,
    }
  }

  #[must_use]
  pub fn delivery_id(&self) -> &str {
    &self.delivery_id
  }
  #[must_use]
  pub const fn source_state(&self) -> ScheduledDeliveryState {
    self.source_state
  }
  #[must_use]
  pub fn target_json(&self) -> &str {
    &self.target_json
  }
  #[must_use]
  pub fn target_digest(&self) -> &str {
    &self.target_digest
  }
  #[must_use]
  pub fn payload_digest(&self) -> &str {
    &self.payload_digest
  }
  #[must_use]
  pub fn binding_digest(&self) -> &str {
    &self.binding_digest
  }
  pub(crate) fn intent_key(&self) -> &str {
    &self.intent_key
  }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScheduledDeliveryWork {
  Idle,
  SkipUnchanged(ScheduledDeliveryAuthority),
  ProviderRequired(ScheduledDeliveryAuthority),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkippedNoneBaselinePolicy {
  DoNotAdvance,
  Accept,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreparedScheduledDelivery {
  Pending(DeliveryPayloadSnapshot),
  SkippedNone(DeliveryPayloadSnapshot),
  SkippedUnchanged(DeliveryPayloadSnapshot),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduledDeliveryRenderInput {
  delivery_id: String,
  body: String,
}

impl ScheduledDeliveryRenderInput {
  pub(crate) fn new(delivery_id: String, body: String) -> Self {
    Self { delivery_id, body }
  }

  #[must_use]
  pub fn delivery_id(&self) -> &str {
    &self.delivery_id
  }

  #[must_use]
  pub fn body(&self) -> &str {
    &self.body
  }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScheduledDeliveryFailure {
  ConfirmedNoWriteRetryable {
    error_kind: String,
    redacted_message: Option<String>,
    next_attempt_at: i64,
  },
  ConfirmedNoWriteTerminal {
    error_kind: String,
    redacted_message: Option<String>,
  },
  AmbiguousPostWrite {
    error_kind: String,
    redacted_message: Option<String>,
  },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedDeliveryBaselineIdentity {
  pub job_id: String,
  pub target_identity_digest: String,
  pub target_snapshot_digest_algorithm: String,
  pub target_snapshot_digest: String,
  pub delivery_policy_version: i64,
  pub render_version: i64,
  pub hash_algorithm: String,
}

impl AcceptedDeliveryBaselineIdentity {
  pub(crate) fn validate(&self) -> Result<(), StateValueError> {
    validate_text("job id", &self.job_id)?;
    validate_lowercase_sha256(
      "delivery target identity digest",
      &self.target_identity_digest,
    )?;
    validate_lowercase_sha256(
      "delivery target snapshot digest",
      &self.target_snapshot_digest,
    )?;
    if self.target_snapshot_digest_algorithm != "sha256-v1" {
      return Err(StateValueError::InvalidSha256 {
        field: "delivery target snapshot digest algorithm",
      });
    }
    if self.delivery_policy_version <= 0 || self.render_version <= 0 {
      return Err(StateValueError::InvalidVersion);
    }
    if self.hash_algorithm != DELIVERY_PAYLOAD_HASH_ALGORITHM {
      return Err(StateValueError::InvalidSha256 {
        field: "delivery hash algorithm",
      });
    }
    Ok(())
  }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedDeliveryBaseline {
  pub accepted_payload_digest: String,
  pub source_delivery_id: String,
  pub source_run_id: String,
  pub source_result_id: Option<String>,
  pub source_result_hash: String,
  pub accepted_at: i64,
  pub baseline_version: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScheduledDeliveryRetentionReport {
  pub delivery_attempts: u64,
  pub deliveries: u64,
  pub late_evidence: u64,
  pub run_attempts: u64,
  pub result_artifacts: u64,
  pub runs: u64,
}
