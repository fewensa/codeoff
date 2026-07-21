use std::str::FromStr;

use chrono::{DateTime, Utc};
use croner::parser::CronParser;
use serde_json::Value;
use thiserror::Error;

use crate::StateError;

mod store;
mod timezone;

use timezone::BundledTimeZone;

type ScheduleStorageParts = (
  &'static str,
  String,
  Option<String>,
  Option<i64>,
  Option<i64>,
  Option<i64>,
);

const MAX_SNAPSHOT_BYTES: usize = 256 * 1024;
const MAX_CONTEXT_BYTES: usize = 64 * 1024;
const MAX_DELIVERY_TARGETS: usize = 32;
const DEFAULT_OCCURRENCE_STEPS: u32 = 100_000;
const MAX_CRON_HORIZON_SECONDS: i64 = 366 * 24 * 60 * 60 * 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum StateValueError {
  #[error("{field} must not be empty")]
  Empty { field: &'static str },
  #[error("{field} exceeds its storage bound")]
  TooLarge { field: &'static str },
  #[error("{field} must be valid JSON")]
  InvalidJson { field: &'static str },
  #[error("{field} must use canonical JSON encoding")]
  NonCanonicalJson { field: &'static str },
  #[error("{field} contains forbidden durable data")]
  ForbiddenDurableData { field: &'static str },
  #[error("version must be positive")]
  InvalidVersion,
  #[error("once timestamp must be strictly later than now")]
  OnceNotFuture,
  #[error("fixed interval must be positive")]
  InvalidInterval,
  #[error("cron must contain exactly five fields")]
  InvalidCronFieldCount,
  #[error("invalid cron expression")]
  InvalidCron,
  #[error("invalid IANA timezone")]
  InvalidTimezone,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum OccurrenceError {
  #[error("schedule has no future occurrence")]
  NoFutureOccurrence,
  #[error("occurrence arithmetic overflowed")]
  ArithmeticOverflow,
  #[error("bounded occurrence search was exhausted")]
  SearchExhausted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OccurrenceWindow {
  pub scheduled_for: i64,
  pub coalesced_through: i64,
  pub skipped_count: u32,
  pub skipped_count_saturated: bool,
  pub next_run_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrincipalKey {
  kind: String,
  provider: String,
  tenant: String,
  subject: String,
}

impl PrincipalKey {
  /// Builds a canonical structured principal key.
  ///
  /// # Errors
  /// Returns an error when any dimension is empty or exceeds its storage bound.
  pub fn new(
    kind: impl Into<String>,
    provider: impl Into<String>,
    tenant: impl Into<String>,
    subject: impl Into<String>,
  ) -> Result<Self, StateValueError> {
    let value = Self {
      kind: kind.into(),
      provider: provider.into(),
      tenant: tenant.into(),
      subject: subject.into(),
    };
    validate_text("principal.kind", &value.kind)?;
    validate_text("principal.provider", &value.provider)?;
    validate_text("principal.tenant", &value.tenant)?;
    validate_text("principal.subject", &value.subject)?;
    Ok(value)
  }

  #[must_use]
  pub fn kind(&self) -> &str {
    &self.kind
  }
  #[must_use]
  pub fn provider(&self) -> &str {
    &self.provider
  }
  #[must_use]
  pub fn tenant(&self) -> &str {
    &self.tenant
  }
  #[must_use]
  pub fn subject(&self) -> &str {
    &self.subject
  }

  fn validate(&self) -> Result<(), StateValueError> {
    validate_text("principal.kind", &self.kind)?;
    validate_text("principal.provider", &self.provider)?;
    validate_text("principal.tenant", &self.tenant)?;
    validate_text("principal.subject", &self.subject)
  }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduledJobDefinition {
  version: u32,
  canonical_json: String,
}

impl ScheduledJobDefinition {
  /// Builds a versioned durable job definition snapshot.
  ///
  /// # Errors
  /// Returns an error for version zero, invalid JSON, or an oversized snapshot.
  pub fn new(version: u32, canonical_json: impl Into<String>) -> Result<Self, StateValueError> {
    let canonical_json = canonicalize_snapshot(version, "definition", &canonical_json.into())?;
    Ok(Self {
      version,
      canonical_json,
    })
  }
  #[must_use]
  pub const fn version(&self) -> u32 {
    self.version
  }
  #[must_use]
  pub fn canonical_json(&self) -> &str {
    &self.canonical_json
  }

  fn validate(&self) -> Result<(), StateValueError> {
    validate_canonical_snapshot(self.version, "definition", &self.canonical_json)
  }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityProfileSnapshot {
  schema_version: u32,
  digest: String,
  canonical_json: String,
}

impl CapabilityProfileSnapshot {
  /// Builds the effective capability profile captured for a job or run.
  ///
  /// # Errors
  /// Returns an error for invalid version, digest, JSON, or size.
  pub fn new(
    schema_version: u32,
    digest: impl Into<String>,
    canonical_json: impl Into<String>,
  ) -> Result<Self, StateValueError> {
    let digest = digest.into();
    let canonical_json =
      canonicalize_snapshot(schema_version, "capability profile", &canonical_json.into())?;
    validate_text("capability profile digest", &digest)?;
    Ok(Self {
      schema_version,
      digest,
      canonical_json,
    })
  }
  #[must_use]
  pub const fn schema_version(&self) -> u32 {
    self.schema_version
  }
  #[must_use]
  pub fn digest(&self) -> &str {
    &self.digest
  }
  #[must_use]
  pub fn canonical_json(&self) -> &str {
    &self.canonical_json
  }

  fn validate(&self) -> Result<(), StateValueError> {
    validate_text("capability profile digest", &self.digest)?;
    validate_canonical_snapshot(
      self.schema_version,
      "capability profile",
      &self.canonical_json,
    )
  }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryTargetSnapshot {
  target_id: String,
  provider: String,
  connector: String,
  tenant: String,
  kind: String,
  address_json: String,
  resolver_version: u32,
  resolver_digest: String,
  identity_digest: String,
}

impl DeliveryTargetSnapshot {
  /// Builds a resolved, versioned delivery target snapshot.
  ///
  /// # Errors
  /// Returns an error when identity fields or the durable address envelope are invalid.
  #[allow(clippy::too_many_arguments)]
  pub fn new(
    target_id: impl Into<String>,
    provider: impl Into<String>,
    connector: impl Into<String>,
    tenant: impl Into<String>,
    kind: impl Into<String>,
    address_json: impl Into<String>,
    resolver_version: u32,
    resolver_digest: impl Into<String>,
    identity_digest: impl Into<String>,
  ) -> Result<Self, StateValueError> {
    let mut value = Self {
      target_id: target_id.into(),
      provider: provider.into(),
      connector: connector.into(),
      tenant: tenant.into(),
      kind: kind.into(),
      address_json: address_json.into(),
      resolver_version,
      resolver_digest: resolver_digest.into(),
      identity_digest: identity_digest.into(),
    };
    value.address_json =
      canonicalize_snapshot(resolver_version, "target address", &value.address_json)?;
    value.validate()?;
    Ok(value)
  }
  /// Validates a fully resolved delivery target snapshot.
  ///
  /// # Errors
  /// Returns an error when a required identity field or bounded JSON snapshot is invalid.
  pub fn validate(&self) -> Result<(), StateValueError> {
    for (field, value) in [
      ("target id", self.target_id.as_str()),
      ("target provider", self.provider.as_str()),
      ("target connector", self.connector.as_str()),
      ("target tenant", self.tenant.as_str()),
      ("target kind", self.kind.as_str()),
      ("resolver digest", self.resolver_digest.as_str()),
      ("target identity digest", self.identity_digest.as_str()),
    ] {
      validate_text(field, value)?;
    }
    validate_canonical_snapshot(self.resolver_version, "target address", &self.address_json)
  }
  #[must_use]
  pub fn identity_digest(&self) -> &str {
    &self.identity_digest
  }
  #[must_use]
  pub fn provider(&self) -> &str {
    &self.provider
  }
  #[must_use]
  pub fn connector(&self) -> &str {
    &self.connector
  }
  #[must_use]
  pub fn tenant(&self) -> &str {
    &self.tenant
  }
  #[must_use]
  pub fn kind(&self) -> &str {
    &self.kind
  }
  #[must_use]
  pub fn address_json(&self) -> &str {
    &self.address_json
  }
  #[must_use]
  pub const fn resolver_version(&self) -> u32 {
    self.resolver_version
  }
  #[must_use]
  pub fn resolver_digest(&self) -> &str {
    &self.resolver_digest
  }

  /// Replaces the storage identity while preserving the resolved target snapshot.
  ///
  /// # Errors
  /// Returns an error when the job-scoped target id is invalid.
  pub fn with_target_id(mut self, target_id: impl Into<String>) -> Result<Self, StateValueError> {
    self.target_id = target_id.into();
    self.validate()?;
    Ok(self)
  }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScheduleSpec {
  Once {
    at: i64,
  },
  FixedInterval {
    anchor: i64,
    every_seconds: i64,
  },
  Cron {
    expression: String,
    timezone: String,
  },
}

impl ScheduleSpec {
  #[must_use]
  pub const fn once(at: i64) -> Self {
    Self::Once { at }
  }

  /// Builds an immutable anchor-based interval schedule.
  ///
  /// # Errors
  /// Returns an error when the interval is not positive.
  pub fn fixed_interval(anchor: i64, every_seconds: i64) -> Result<Self, StateValueError> {
    if every_seconds <= 0 {
      return Err(StateValueError::InvalidInterval);
    }
    Ok(Self::FixedInterval {
      anchor,
      every_seconds,
    })
  }

  /// Parses a standard five-field cron expression and IANA timezone.
  ///
  /// # Errors
  /// Returns an error for non-five-field cron, invalid cron syntax, or an invalid timezone.
  pub fn cron(expression: &str, timezone: &str) -> Result<Self, StateValueError> {
    let canonical = expression.split_whitespace().collect::<Vec<_>>().join(" ");
    if canonical.split_whitespace().count() != 5 {
      return Err(StateValueError::InvalidCronFieldCount);
    }
    CronParser::new()
      .parse(&canonical)
      .map_err(|_| StateValueError::InvalidCron)?;
    let timezone_name = timezone;
    let timezone =
      BundledTimeZone::parse(timezone_name).map_err(|()| StateValueError::InvalidTimezone)?;
    Ok(Self::Cron {
      expression: canonical,
      timezone: timezone
        .canonical_name()
        .unwrap_or(timezone_name)
        .to_owned(),
    })
  }

  /// Applies create-time rules that depend on the caller-provided server clock.
  ///
  /// # Errors
  /// Returns an error when a once occurrence is not strictly in the future.
  pub fn validate_for_create(&self, now: i64) -> Result<(), StateValueError> {
    if let Self::Once { at } = self
      && *at <= now
    {
      return Err(StateValueError::OnceNotFuture);
    }
    Ok(())
  }

  /// Returns the first occurrence for a newly created schedule.
  ///
  /// # Errors
  /// Returns an error for arithmetic overflow or an exhausted cron search.
  pub fn first_after_create(&self, now: i64) -> Result<i64, OccurrenceError> {
    match self {
      Self::Once { at } => Ok(*at),
      Self::FixedInterval { anchor, .. } if *anchor > now => Ok(*anchor),
      _ => self.next_after(now),
    }
  }

  /// Finds the first canonical occurrence strictly after `reference`.
  ///
  /// # Errors
  /// Returns an error when there is no future occurrence, arithmetic overflows, or search bounds
  /// are exhausted.
  pub fn next_after(&self, reference: i64) -> Result<i64, OccurrenceError> {
    match self {
      Self::Once { at } => (*at > reference)
        .then_some(*at)
        .ok_or(OccurrenceError::NoFutureOccurrence),
      Self::FixedInterval {
        anchor,
        every_seconds,
      } => next_fixed_interval(*anchor, *every_seconds, reference),
      Self::Cron {
        expression,
        timezone,
      } => next_cron(expression, timezone, reference),
    }
  }

  /// Coalesces due canonical occurrences into one materialization window.
  ///
  /// # Errors
  /// Returns an error when arithmetic fails or the explicit step bound is exhausted.
  pub fn coalesce(
    &self,
    due: i64,
    now: i64,
    max_steps: u32,
  ) -> Result<OccurrenceWindow, OccurrenceError> {
    if due > now {
      return Ok(OccurrenceWindow {
        scheduled_for: due,
        coalesced_through: due,
        skipped_count: 0,
        skipped_count_saturated: false,
        next_run_at: Some(due),
      });
    }
    if let Self::Once { .. } = self {
      return Ok(OccurrenceWindow {
        scheduled_for: due,
        coalesced_through: due,
        skipped_count: 0,
        skipped_count_saturated: false,
        next_run_at: None,
      });
    }
    if let Self::FixedInterval { every_seconds, .. } = self {
      return coalesce_fixed_interval(due, now, *every_seconds);
    }
    let mut current = due;
    let mut skipped_count = 0_u32;
    for _ in 0..max_steps {
      let next = match self.next_after(current) {
        Ok(next) => next,
        Err(OccurrenceError::NoFutureOccurrence) => {
          return Ok(OccurrenceWindow {
            scheduled_for: due,
            coalesced_through: current,
            skipped_count,
            skipped_count_saturated: false,
            next_run_at: None,
          });
        }
        Err(error) => return Err(error),
      };
      if next > now {
        return Ok(OccurrenceWindow {
          scheduled_for: due,
          coalesced_through: current,
          skipped_count,
          skipped_count_saturated: false,
          next_run_at: Some(next),
        });
      }
      current = next;
      skipped_count = skipped_count.saturating_add(1);
    }
    Err(OccurrenceError::SearchExhausted)
  }

  fn storage_parts(&self) -> ScheduleStorageParts {
    match self {
      Self::Once { at } => ("once", at.to_string(), None, Some(*at), None, None),
      Self::FixedInterval {
        anchor,
        every_seconds,
      } => (
        "fixed_interval",
        every_seconds.to_string(),
        None,
        None,
        Some(*anchor),
        Some(*every_seconds),
      ),
      Self::Cron {
        expression,
        timezone,
      } => (
        "cron",
        expression.clone(),
        Some(timezone.clone()),
        None,
        None,
        None,
      ),
    }
  }

  fn from_storage(
    kind: &str,
    canonical_spec: &str,
    timezone: Option<&str>,
    once_at: Option<i64>,
    anchor_at: Option<i64>,
    interval_seconds: Option<i64>,
  ) -> Result<Self, StateError> {
    match kind {
      "once" => once_at.map(Self::once),
      "fixed_interval" => match (anchor_at, interval_seconds) {
        (Some(anchor), Some(every_seconds)) => Self::fixed_interval(anchor, every_seconds).ok(),
        _ => None,
      },
      "cron" => timezone.and_then(|timezone| Self::cron(canonical_spec, timezone).ok()),
      _ => None,
    }
    .ok_or_else(|| StateError::InvalidSchedulerState {
      reason: "invalid persisted schedule".to_owned(),
    })
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScheduledJobStatus {
  Active,
  Paused,
  Completed,
  Deleted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScheduledRunState {
  Pending,
  Leased,
  Executing,
  Succeeded,
  Failed,
  TimedOut,
  Cancelled,
  OutcomeUnknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunLeaseBinding {
  run_id: String,
  job_id: String,
  attempt: i64,
  fence: i64,
  lease_owner: String,
}

impl RunLeaseBinding {
  #[must_use]
  pub fn run_id(&self) -> &str {
    &self.run_id
  }

  #[must_use]
  pub fn job_id(&self) -> &str {
    &self.job_id
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimedScheduledRun {
  pub binding: RunLeaseBinding,
  pub schedule_id: String,
  pub job_generation: i64,
  pub schedule_generation: i64,
  pub scheduled_for: i64,
  pub coalesced_through: i64,
  pub definition_version: u32,
  pub definition_json: String,
  pub capability_schema_version: u32,
  pub capability_digest: String,
  pub capability_json: String,
  pub targets_json: String,
  pub execution_baseline_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestedExecutionProfileSnapshot {
  schema_version: u32,
  canonical_json: String,
  hash_algorithm: String,
  digest: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreflightFailureDisposition {
  RetryAt(i64),
  Fail,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpiredRunReclaimOutcome {
  Idle,
  Retried {
    run_id: String,
    attempt: i64,
    fence: i64,
  },
  Failed {
    run_id: String,
    attempt: i64,
    fence: i64,
  },
  OutcomeUnknown {
    run_id: String,
    attempt: i64,
    fence: i64,
  },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScheduledRunLateEvidenceKind {
  CompletionAfterLeaseLoss,
  PreflightAfterLeaseLoss,
  HeartbeatAfterLeaseLoss,
}

impl ScheduledRunLateEvidenceKind {
  #[must_use]
  pub const fn as_str(self) -> &'static str {
    match self {
      Self::CompletionAfterLeaseLoss => "completion_after_lease_loss",
      Self::PreflightAfterLeaseLoss => "preflight_after_lease_loss",
      Self::HeartbeatAfterLeaseLoss => "heartbeat_after_lease_loss",
    }
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LateEvidenceAppendOutcome {
  Recorded,
  Duplicate,
  QuotaExceeded,
}

impl AttestedExecutionProfileSnapshot {
  /// Builds the bounded profile attested before a scheduled turn starts.
  ///
  /// # Errors
  /// Returns an error when the profile is invalid, non-canonical, or oversized.
  pub fn new(
    schema_version: u32,
    canonical_json: impl Into<String>,
    hash_algorithm: impl Into<String>,
    digest: impl Into<String>,
  ) -> Result<Self, StateValueError> {
    let canonical_json = canonical_json.into();
    let value = Self {
      schema_version,
      canonical_json: canonicalize_snapshot(
        schema_version,
        "attested execution profile",
        &canonical_json,
      )?,
      hash_algorithm: hash_algorithm.into(),
      digest: digest.into(),
    };
    validate_text("attested profile hash algorithm", &value.hash_algorithm)?;
    validate_text("attested profile digest", &value.digest)?;
    Ok(value)
  }

  fn validate(&self) -> Result<(), StateValueError> {
    validate_canonical_snapshot(
      self.schema_version,
      "attested execution profile",
      &self.canonical_json,
    )?;
    validate_text("attested profile hash algorithm", &self.hash_algorithm)?;
    validate_text("attested profile digest", &self.digest)
  }
}

impl ScheduledRunState {
  #[must_use]
  pub const fn as_str(self) -> &'static str {
    match self {
      Self::Pending => "pending",
      Self::Leased => "leased",
      Self::Executing => "executing",
      Self::Succeeded => "succeeded",
      Self::Failed => "failed",
      Self::TimedOut => "timed_out",
      Self::Cancelled => "cancelled",
      Self::OutcomeUnknown => "outcome_unknown",
    }
  }
}

impl FromStr for ScheduledRunState {
  type Err = StateError;

  fn from_str(value: &str) -> Result<Self, Self::Err> {
    match value {
      "pending" => Ok(Self::Pending),
      "leased" => Ok(Self::Leased),
      "executing" => Ok(Self::Executing),
      "succeeded" => Ok(Self::Succeeded),
      "failed" => Ok(Self::Failed),
      "timed_out" => Ok(Self::TimedOut),
      "cancelled" => Ok(Self::Cancelled),
      "outcome_unknown" => Ok(Self::OutcomeUnknown),
      _ => Err(StateError::InvalidSchedulerState {
        reason: format!("invalid run state {value}"),
      }),
    }
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScheduledDeliveryState {
  Pending,
  Leased,
  Sending,
  Delivered,
  Failed,
  DeliveryUnknown,
  Skipped,
}

impl ScheduledDeliveryState {
  #[must_use]
  pub const fn as_str(self) -> &'static str {
    match self {
      Self::Pending => "pending",
      Self::Leased => "leased",
      Self::Sending => "sending",
      Self::Delivered => "delivered",
      Self::Failed => "failed",
      Self::DeliveryUnknown => "delivery_unknown",
      Self::Skipped => "skipped",
    }
  }
}

impl FromStr for ScheduledDeliveryState {
  type Err = StateError;

  fn from_str(value: &str) -> Result<Self, Self::Err> {
    match value {
      "pending" => Ok(Self::Pending),
      "leased" => Ok(Self::Leased),
      "sending" => Ok(Self::Sending),
      "delivered" => Ok(Self::Delivered),
      "failed" => Ok(Self::Failed),
      "delivery_unknown" => Ok(Self::DeliveryUnknown),
      "skipped" => Ok(Self::Skipped),
      _ => Err(StateError::InvalidSchedulerState {
        reason: format!("invalid delivery state {value}"),
      }),
    }
  }
}

impl ScheduledJobStatus {
  #[must_use]
  pub const fn as_str(self) -> &'static str {
    match self {
      Self::Active => "active",
      Self::Paused => "paused",
      Self::Completed => "completed",
      Self::Deleted => "deleted",
    }
  }

  fn parse(value: &str) -> Result<Self, StateError> {
    match value {
      "active" => Ok(Self::Active),
      "paused" => Ok(Self::Paused),
      "completed" => Ok(Self::Completed),
      "deleted" => Ok(Self::Deleted),
      _ => Err(StateError::InvalidSchedulerState {
        reason: format!("invalid job status {value}"),
      }),
    }
  }
}

#[derive(Debug, Clone)]
pub struct CreateScheduledJob {
  pub job_id: String,
  pub schedule_id: String,
  pub definition: ScheduledJobDefinition,
  pub creator: PrincipalKey,
  pub owner: PrincipalKey,
  pub capability: CapabilityProfileSnapshot,
  pub targets: Vec<DeliveryTargetSnapshot>,
  pub schedule: ScheduleSpec,
  pub now: i64,
}

#[derive(Debug, Clone)]
pub struct UpdateScheduledJob {
  pub job_id: String,
  pub expected_generation: i64,
  pub definition: ScheduledJobDefinition,
  pub capability: CapabilityProfileSnapshot,
  pub targets: Vec<DeliveryTargetSnapshot>,
  pub schedule: ScheduleSpec,
  pub now: i64,
}

#[derive(Debug, Clone)]
pub struct UpdateExecutionBaseline {
  pub job_id: String,
  pub expected_version: i64,
  pub hash_algorithm: String,
  pub result_hash: String,
  pub previous_success_context: String,
  pub source_run_id: String,
  pub completed_at: i64,
}

#[derive(Debug, Clone)]
pub struct UpdateAcceptedDeliveryBaseline {
  pub job_id: String,
  pub target_identity_digest: String,
  pub delivery_policy_version: i64,
  pub render_version: i64,
  pub hash_algorithm: String,
  pub accepted_payload_digest: String,
  pub source_delivery_id: String,
  pub source_run_id: String,
  pub source_result_hash: String,
  pub accepted_at: i64,
  pub expected_version: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedDeliveryBaseline {
  pub accepted_payload_digest: String,
  pub source_delivery_id: String,
  pub source_run_id: String,
  pub source_result_hash: String,
  pub accepted_at: i64,
  pub baseline_version: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduledJobListPage {
  pub job_ids: Vec<String>,
  pub next_cursor: Option<String>,
}

#[derive(Debug, Clone)]
pub enum ScheduledJobMutation {
  Create(Box<CreateScheduledJob>),
  Update(Box<UpdateScheduledJob>),
  Pause {
    job_id: String,
    expected_generation: i64,
    now: i64,
  },
  Resume {
    job_id: String,
    expected_generation: i64,
    now: i64,
  },
  Delete {
    job_id: String,
    expected_generation: i64,
    now: i64,
  },
}

impl ScheduledJobMutation {
  const fn operation(&self) -> &'static str {
    match self {
      Self::Create(_) => "create",
      Self::Update(_) => "update",
      Self::Pause { .. } => "pause",
      Self::Resume { .. } => "resume",
      Self::Delete { .. } => "delete",
    }
  }

  const fn now(&self) -> i64 {
    match self {
      Self::Create(request) => request.now,
      Self::Update(request) => request.now,
      Self::Pause { now, .. } | Self::Resume { now, .. } | Self::Delete { now, .. } => *now,
    }
  }
}

#[derive(Debug, Clone)]
pub struct ScheduleMutationIdempotency {
  pub principal: PrincipalKey,
  pub request_id: String,
  pub digest_algorithm: String,
  pub request_digest: String,
  pub response_json: String,
}

#[derive(Debug, Clone)]
pub struct ScheduleMutationAudit {
  pub audit_id: String,
  pub principal: Option<PrincipalKey>,
  pub operation: String,
  pub job_id: Option<String>,
  pub request_id: String,
  pub outcome: String,
  pub decision: String,
  pub reason: Option<String>,
  pub error_code: Option<String>,
  pub old_generation: Option<i64>,
  pub new_generation: Option<i64>,
  pub resolver_provider: Option<String>,
  pub target_kind: Option<String>,
  pub resolver_version: Option<i64>,
  pub resolver_digest: Option<String>,
  pub capability_version: Option<i64>,
  pub capability_digest: Option<String>,
  pub idempotency_outcome: Option<String>,
  pub latency_ms: i64,
  pub correlation_id: String,
  pub occurred_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduleAuditSummary {
  pub audit_id: String,
  pub operation: String,
  pub outcome: String,
  pub decision: String,
  pub reason: Option<String>,
  pub error_code: Option<String>,
  pub idempotency_outcome: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransactionalMutationOutcome {
  Applied(String),
  Replay(String),
  InProgress,
  Conflict,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduledJob {
  pub job_id: String,
  pub definition: ScheduledJobDefinition,
  pub creator: PrincipalKey,
  pub owner: PrincipalKey,
  pub capability: CapabilityProfileSnapshot,
  pub status: ScheduledJobStatus,
  pub generation: i64,
  pub schedule_id: String,
  pub schedule_generation: i64,
  pub schedule: ScheduleSpec,
  pub next_run_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduledRun {
  pub run_id: String,
  pub job_id: String,
  pub scheduled_for: i64,
  pub coalesced_through: i64,
  pub skipped_count: u32,
  pub skipped_count_saturated: bool,
  pub state: ScheduledRunState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaterializationOutcome {
  Created(ScheduledRun),
  NotDue,
  Blocked,
  AlreadyMaterialized,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdempotencyDecision {
  Claimed,
  Replay(String),
  InProgress,
  Conflict,
}

fn next_fixed_interval(
  anchor: i64,
  every_seconds: i64,
  reference: i64,
) -> Result<i64, OccurrenceError> {
  if reference < anchor {
    return Ok(anchor);
  }
  let elapsed = reference
    .checked_sub(anchor)
    .ok_or(OccurrenceError::ArithmeticOverflow)?;
  let steps = elapsed
    .checked_div(every_seconds)
    .and_then(|steps| steps.checked_add(1))
    .ok_or(OccurrenceError::ArithmeticOverflow)?;
  anchor
    .checked_add(
      steps
        .checked_mul(every_seconds)
        .ok_or(OccurrenceError::ArithmeticOverflow)?,
    )
    .ok_or(OccurrenceError::ArithmeticOverflow)
}

fn coalesce_fixed_interval(
  due: i64,
  now: i64,
  every_seconds: i64,
) -> Result<OccurrenceWindow, OccurrenceError> {
  let elapsed = now
    .checked_sub(due)
    .ok_or(OccurrenceError::ArithmeticOverflow)?;
  let skipped = elapsed
    .checked_div(every_seconds)
    .ok_or(OccurrenceError::ArithmeticOverflow)?;
  let coalesced_through = due
    .checked_add(
      skipped
        .checked_mul(every_seconds)
        .ok_or(OccurrenceError::ArithmeticOverflow)?,
    )
    .ok_or(OccurrenceError::ArithmeticOverflow)?;
  let next_run_at = coalesced_through
    .checked_add(every_seconds)
    .ok_or(OccurrenceError::ArithmeticOverflow)?;
  let skipped_count = u32::try_from(skipped).unwrap_or(u32::MAX);
  Ok(OccurrenceWindow {
    scheduled_for: due,
    coalesced_through,
    skipped_count,
    skipped_count_saturated: skipped > i64::from(u32::MAX),
    next_run_at: Some(next_run_at),
  })
}

fn next_cron(expression: &str, timezone: &str, reference: i64) -> Result<i64, OccurrenceError> {
  let horizon_end = reference
    .checked_add(MAX_CRON_HORIZON_SECONDS)
    .ok_or(OccurrenceError::ArithmeticOverflow)?;
  if !BundledTimeZone::supports_timestamp(reference)
    || !BundledTimeZone::supports_timestamp(horizon_end)
  {
    return Err(OccurrenceError::ArithmeticOverflow);
  }
  let cron = CronParser::new()
    .parse(expression)
    .map_err(|_| OccurrenceError::NoFutureOccurrence)?;
  let timezone =
    BundledTimeZone::parse(timezone).map_err(|()| OccurrenceError::NoFutureOccurrence)?;
  let reference_utc =
    DateTime::<Utc>::from_timestamp(reference, 0).ok_or(OccurrenceError::ArithmeticOverflow)?;
  let local = reference_utc.with_timezone(&timezone);
  let next = cron
    .find_next_occurrence(&local, false)
    .map_err(|_| OccurrenceError::NoFutureOccurrence)?;
  let timestamp = next.timestamp();
  if timestamp <= reference
    || timestamp
      .checked_sub(reference)
      .is_none_or(|distance| distance > MAX_CRON_HORIZON_SECONDS)
  {
    return Err(OccurrenceError::SearchExhausted);
  }
  Ok(timestamp)
}

fn canonicalize_snapshot(
  version: u32,
  field: &'static str,
  json: &str,
) -> Result<String, StateValueError> {
  if version == 0 {
    return Err(StateValueError::InvalidVersion);
  }
  if json.len() > MAX_SNAPSHOT_BYTES {
    return Err(StateValueError::TooLarge { field });
  }
  let value =
    serde_json::from_str::<Value>(json).map_err(|_| StateValueError::InvalidJson { field })?;
  if contains_forbidden_durable_key(&value) {
    return Err(StateValueError::ForbiddenDurableData { field });
  }
  let canonical =
    serde_json::to_string(&value).map_err(|_| StateValueError::InvalidJson { field })?;
  if canonical.len() > MAX_SNAPSHOT_BYTES {
    return Err(StateValueError::TooLarge { field });
  }
  Ok(canonical)
}

fn validate_canonical_snapshot(
  version: u32,
  field: &'static str,
  json: &str,
) -> Result<(), StateValueError> {
  let canonical = canonicalize_snapshot(version, field, json)?;
  if canonical != json {
    return Err(StateValueError::NonCanonicalJson { field });
  }
  Ok(())
}

fn contains_forbidden_durable_key(value: &Value) -> bool {
  match value {
    Value::Object(object) => object
      .iter()
      .any(|(key, value)| is_forbidden_durable_key(key) || contains_forbidden_durable_key(value)),
    Value::Array(values) => values.iter().any(contains_forbidden_durable_key),
    _ => false,
  }
}

fn is_forbidden_durable_key(key: &str) -> bool {
  let normalized = key.trim().to_ascii_lowercase().replace('-', "_");
  matches!(
    normalized.as_str(),
    "secret"
      | "token"
      | "password"
      | "private_key"
      | "auth"
      | "authorization"
      | "credentials"
      | "api_key"
      | "client_secret"
      | "access_token"
      | "refresh_token"
      | "event_id"
      | "dedupe_key"
      | "origin"
      | "slack_event"
      | "live_event"
  ) || normalized.ends_with("_secret")
    || normalized.ends_with("_token")
    || normalized.ends_with("_password")
    || normalized.ends_with("_private_key")
    || normalized.ends_with("_api_key")
}

fn validate_text(field: &'static str, value: &str) -> Result<(), StateValueError> {
  if value.is_empty() {
    return Err(StateValueError::Empty { field });
  }
  if value.len() > MAX_CONTEXT_BYTES {
    return Err(StateValueError::TooLarge { field });
  }
  Ok(())
}

fn invalid_value(error: StateValueError) -> StateError {
  StateError::InvalidSchedulerState {
    reason: error.to_string(),
  }
}

fn invalid_occurrence(error: OccurrenceError) -> StateError {
  StateError::InvalidSchedulerState {
    reason: error.to_string(),
  }
}

fn scheduler_error(source: sqlx::Error) -> StateError {
  StateError::Scheduler { source }
}

fn invalid_json(error: serde_json::Error) -> StateError {
  let reason = error.to_string();
  drop(error);
  StateError::InvalidSchedulerState { reason }
}

fn materialized_run(
  run_id: String,
  job_id: &str,
  window: OccurrenceWindow,
) -> MaterializationOutcome {
  MaterializationOutcome::Created(ScheduledRun {
    run_id,
    job_id: job_id.to_owned(),
    scheduled_for: window.scheduled_for,
    coalesced_through: window.coalesced_through,
    skipped_count: window.skipped_count,
    skipped_count_saturated: window.skipped_count_saturated,
    state: ScheduledRunState::Pending,
  })
}

fn positive_u32(value: i64) -> Result<u32, StateError> {
  u32::try_from(value)
    .ok()
    .filter(|value| *value > 0)
    .ok_or_else(|| StateError::InvalidSchedulerState {
      reason: "persisted version is not positive".to_owned(),
    })
}
