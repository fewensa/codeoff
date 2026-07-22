use std::fmt::{self, Write as _};
use std::str::FromStr;

use chrono::{DateTime, Utc};
use codeoff_core::SchedulerOperationalPolicy;
use croner::parser::CronParser;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::StateError;

mod delivery;
mod store;
mod timezone;

pub use delivery::{
  AcceptedDeliveryBaseline, AcceptedDeliveryBaselineIdentity, ClaimedScheduledDelivery,
  DELIVERY_PAYLOAD_HASH_ALGORITHM, DELIVERY_PAYLOAD_SCHEMA_VERSION, DeliveryPayloadSnapshot,
  PreparedScheduledDelivery, ScheduledDeliveryAuthority, ScheduledDeliveryBinding,
  ScheduledDeliveryFailure, ScheduledDeliveryReconcileOutcome, ScheduledDeliveryRenderInput,
  ScheduledDeliveryRetentionReport, ScheduledDeliveryState, ScheduledDeliveryWork,
  SkippedNoneBaselinePolicy,
};
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
const MAX_PREVIOUS_SUCCESS_BYTES: usize = 16 * 1024;
const MAX_DELIVERY_TARGETS: usize = 32;
const MAX_CRON_HORIZON_SECONDS: i64 = 366 * 24 * 60 * 60 * 10;
const GREGORIAN_CYCLE_START: i64 = 946_684_800;
const GREGORIAN_CYCLE_END: i64 = 13_569_465_600;

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
  #[error("{field} must be lowercase sha256")]
  InvalidSha256 { field: &'static str },
  #[error("{field} is invalid")]
  InvalidValue { field: &'static str },
  #[error("version must be positive")]
  InvalidVersion,
  #[error("once timestamp must be strictly later than now")]
  OnceNotFuture,
  #[error("fixed interval must be positive")]
  InvalidInterval,
  #[error("schedule cadence is shorter than the configured minimum")]
  CadenceTooShort,
  #[error("cron cadence proof exhausted its configured occurrence bound")]
  CadenceProofExhausted,
  #[error("cron cadence cannot be proven for this timezone and minimum")]
  CadenceProofUnavailable,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryTargetRoute {
  provider: String,
  tenant: String,
  kind: String,
  conversation_id: String,
  thread_id: Option<String>,
  requested_identity_digest: String,
}

impl DeliveryTargetRoute {
  /// Parses one canonical resolver-produced target envelope into provider-neutral routing
  /// coordinates.
  ///
  /// # Errors
  /// Returns an error for legacy, unknown, non-canonical, or kind-inconsistent route shapes.
  pub fn from_canonical_target_json(target_json: &str) -> Result<Self, StateValueError> {
    let target: Value =
      serde_json::from_str(target_json).map_err(|_| StateValueError::InvalidJson {
        field: "delivery target route",
      })?;
    if serde_json::to_string(&target).map_err(|_| StateValueError::InvalidJson {
      field: "delivery target route",
    })?
      != target_json
    {
      return Err(StateValueError::NonCanonicalJson {
        field: "delivery target route",
      });
    }
    let target = target.as_object().ok_or(StateValueError::InvalidJson {
      field: "delivery target route",
    })?;
    let target_keys = [
      "address",
      "connector",
      "identity_digest",
      "kind",
      "provider",
      "resolver_digest",
      "resolver_version",
      "tenant",
    ];
    if target.len() != target_keys.len()
      || target_keys.iter().any(|key| !target.contains_key(*key))
      || target
        .get("resolver_version")
        .and_then(Value::as_u64)
        .is_none_or(|version| version == 0 || version > u64::from(u32::MAX))
    {
      return Err(StateValueError::InvalidJson {
        field: "delivery target route",
      });
    }
    let provider = required_delivery_route_text(target, "provider")?;
    let connector = required_delivery_route_text(target, "connector")?;
    let tenant = required_delivery_route_text(target, "tenant")?;
    let kind = target
      .get("kind")
      .and_then(Value::as_str)
      .ok_or(StateValueError::InvalidJson {
        field: "delivery target route",
      })?;
    let resolver_digest = required_delivery_route_text(target, "resolver_digest")?;
    for value in [provider, connector, tenant, kind, resolver_digest] {
      validate_text("delivery target route identity", value)?;
    }
    let identity_digest = target
      .get("identity_digest")
      .and_then(Value::as_str)
      .ok_or(StateValueError::InvalidJson {
        field: "delivery target route",
      })?;
    validate_lowercase_sha256("delivery target identity digest", identity_digest)?;
    if !matches!(kind, "channel" | "direct_message" | "thread") {
      return Err(StateValueError::InvalidJson {
        field: "delivery target route",
      });
    }
    let address = target.get("address").ok_or(StateValueError::InvalidJson {
      field: "delivery target route",
    })?;
    let (conversation_id, thread_id, requested_identity_digest, identity_address) =
      parse_delivery_target_route_address(address, tenant, kind)?;
    let expected_identity_digest = sha256_hex(
      json!({
        "address": identity_address,
        "connector": connector,
        "kind": kind,
        "provider": provider,
        "tenant": tenant,
      })
      .to_string()
      .as_bytes(),
    );
    if expected_identity_digest != identity_digest {
      return Err(StateValueError::InvalidSha256 {
        field: "delivery target identity digest",
      });
    }
    Ok(Self {
      provider: provider.to_owned(),
      tenant: tenant.to_owned(),
      kind: kind.to_owned(),
      conversation_id,
      thread_id,
      requested_identity_digest,
    })
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
  pub fn kind(&self) -> &str {
    &self.kind
  }

  #[must_use]
  pub fn conversation_id(&self) -> &str {
    &self.conversation_id
  }

  #[must_use]
  pub fn thread_id(&self) -> Option<&str> {
    self.thread_id.as_deref()
  }

  #[must_use]
  pub fn requested_identity_digest(&self) -> &str {
    &self.requested_identity_digest
  }
}

fn required_delivery_route_text<'a>(
  object: &'a serde_json::Map<String, Value>,
  key: &'static str,
) -> Result<&'a str, StateValueError> {
  object
    .get(key)
    .and_then(Value::as_str)
    .ok_or(StateValueError::InvalidJson {
      field: "delivery target route",
    })
}

fn parse_delivery_target_route_address(
  address: &Value,
  tenant: &str,
  kind: &str,
) -> Result<(String, Option<String>, String, Value), StateValueError> {
  let address = address.as_object().ok_or(StateValueError::InvalidJson {
    field: "delivery target route",
  })?;
  let address_keys = [
    "authorization_evidence",
    "coordinates",
    "created_at",
    "requested_identity_digest",
    "routing_authority",
    "schema_version",
    "workspace_id",
  ];
  if address.len() != address_keys.len()
    || address_keys.iter().any(|key| !address.contains_key(*key))
    || address.get("schema_version").and_then(Value::as_u64) != Some(1)
    || address.get("workspace_id").and_then(Value::as_str) != Some(tenant)
    || address
      .get("created_at")
      .and_then(Value::as_i64)
      .is_none_or(|created_at| created_at < 0)
  {
    return Err(StateValueError::InvalidJson {
      field: "delivery target route",
    });
  }
  let requested_identity_digest = address
    .get("requested_identity_digest")
    .and_then(Value::as_str)
    .ok_or(StateValueError::InvalidJson {
      field: "delivery target route",
    })?;
  validate_lowercase_sha256(
    "delivery target requested identity digest",
    requested_identity_digest,
  )?;
  let routing_authority = validate_delivery_route_authority(
    address
      .get("routing_authority")
      .ok_or(StateValueError::InvalidJson {
        field: "delivery target route",
      })?,
    tenant,
  )?;
  validate_delivery_route_evidence(address.get("authorization_evidence").ok_or(
    StateValueError::InvalidJson {
      field: "delivery target route",
    },
  )?)?;
  let coordinates = address
    .get("coordinates")
    .and_then(Value::as_object)
    .ok_or(StateValueError::InvalidJson {
      field: "delivery target route",
    })?;
  let expected_coordinate_count = usize::from(kind == "thread") + 1;
  if coordinates.len() != expected_coordinate_count
    || !coordinates.contains_key("channel_id")
    || (kind == "thread") != coordinates.contains_key("thread_ts")
  {
    return Err(StateValueError::InvalidJson {
      field: "delivery target route",
    });
  }
  let conversation_id = coordinates
    .get("channel_id")
    .and_then(Value::as_str)
    .ok_or(StateValueError::InvalidJson {
      field: "delivery target route",
    })?;
  validate_text("delivery target route conversation", conversation_id)?;
  let thread_id = coordinates
    .get("thread_ts")
    .map(|value| {
      value.as_str().ok_or(StateValueError::InvalidJson {
        field: "delivery target route",
      })
    })
    .transpose()?;
  if let Some(thread_id) = thread_id {
    validate_text("delivery target route thread", thread_id)?;
  }
  let identity_address = json!({
    "coordinates": Value::Object(coordinates.clone()),
    "routing_authority": routing_authority,
    "workspace_id": tenant,
  });
  Ok((
    conversation_id.to_owned(),
    thread_id.map(str::to_owned),
    requested_identity_digest.to_owned(),
    identity_address,
  ))
}

fn validate_delivery_route_authority(
  authority: &Value,
  tenant: &str,
) -> Result<Value, StateValueError> {
  let authority = authority.as_object().ok_or(StateValueError::InvalidJson {
    field: "delivery target route authority",
  })?;
  let keys = [
    "context_team_id",
    "conversation_host_id",
    "enterprise_id",
    "team_id",
  ];
  if authority.len() != keys.len()
    || keys.iter().any(|key| !authority.contains_key(*key))
    || authority.get("team_id").and_then(Value::as_str) != Some(tenant)
    || authority.get("context_team_id").and_then(Value::as_str) != Some(tenant)
  {
    return Err(StateValueError::InvalidJson {
      field: "delivery target route authority",
    });
  }
  validate_text(
    "delivery target conversation host",
    required_delivery_route_text(authority, "conversation_host_id")?,
  )?;
  if let Some(enterprise_id) = authority.get("enterprise_id").and_then(Value::as_str) {
    validate_text("delivery target enterprise", enterprise_id)?;
  } else if !authority.get("enterprise_id").is_some_and(Value::is_null) {
    return Err(StateValueError::InvalidJson {
      field: "delivery target route authority",
    });
  }
  Ok(Value::Object(authority.clone()))
}

fn validate_delivery_route_evidence(evidence: &Value) -> Result<(), StateValueError> {
  let evidence = evidence.as_object().ok_or(StateValueError::InvalidJson {
    field: "delivery target route evidence",
  })?;
  let keys = ["digest", "version"];
  if evidence.len() != keys.len()
    || keys.iter().any(|key| !evidence.contains_key(*key))
    || evidence
      .get("version")
      .and_then(Value::as_u64)
      .is_none_or(|version| version == 0)
  {
    return Err(StateValueError::InvalidJson {
      field: "delivery target route evidence",
    });
  }
  validate_lowercase_sha256(
    "delivery target authorization evidence digest",
    evidence
      .get("digest")
      .and_then(Value::as_str)
      .ok_or(StateValueError::InvalidJson {
        field: "delivery target route evidence",
      })?,
  )
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
    ] {
      validate_text(field, value)?;
    }
    validate_lowercase_sha256("target identity digest", &self.identity_digest)?;
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

  /// Returns provider-neutral routing coordinates from this resolver-produced target.
  ///
  /// # Errors
  /// Returns an error when the address does not use the recognized versioned route schema.
  pub fn delivery_route(&self) -> Result<DeliveryTargetRoute, StateValueError> {
    let address: Value =
      serde_json::from_str(&self.address_json).map_err(|_| StateValueError::InvalidJson {
        field: "delivery target route",
      })?;
    DeliveryTargetRoute::from_canonical_target_json(
      &json!({
        "address": address,
        "connector": self.connector,
        "identity_digest": self.identity_digest,
        "kind": self.kind,
        "provider": self.provider,
        "resolver_digest": self.resolver_digest,
        "resolver_version": self.resolver_version,
        "tenant": self.tenant,
      })
      .to_string(),
    )
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

  /// Validates that this schedule cannot produce occurrences faster than the policy minimum.
  ///
  /// # Errors
  /// Returns `CadenceTooShort` when the first once delay, fixed interval, or consecutive cron
  /// occurrences are shorter than the configured minimum.
  pub fn validate_minimum_cadence(
    &self,
    now: i64,
    minimum_seconds: u32,
    proof_limit: u32,
  ) -> Result<(), StateValueError> {
    let minimum = i64::from(minimum_seconds);
    let valid = match self {
      Self::Once { at } => at.checked_sub(now).is_some_and(|delay| delay >= minimum),
      Self::FixedInterval { every_seconds, .. } => *every_seconds >= minimum,
      Self::Cron {
        expression,
        timezone,
      } => prove_cron_minimum_cadence(expression, timezone, minimum, proof_limit)?,
    };
    if !valid {
      return Err(StateValueError::CadenceTooShort);
    }
    Ok(())
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

fn prove_cron_minimum_cadence(
  expression: &str,
  timezone: &str,
  minimum: i64,
  proof_limit: u32,
) -> Result<bool, StateValueError> {
  if minimum <= 60 {
    return Ok(true);
  }
  let fields = expression.split_whitespace().collect::<Vec<_>>();
  if fields.len() != 5 {
    return Err(StateValueError::InvalidCron);
  }
  let fixed_minute = fields[0].parse::<u8>().is_ok_and(|minute| minute < 60);
  let fixed_hour = fields[1].parse::<u8>().is_ok_and(|hour| hour < 24);
  if timezone == "UTC" && fixed_minute && fields[1] == "*" && fields[2..] == ["*", "*", "*"] {
    return Ok(minimum <= 3_600);
  }
  if timezone == "UTC" && fixed_minute && fixed_hour && fields[2..] == ["*", "*", "*"] {
    return Ok(minimum <= 86_400);
  }
  let fixed_daily = fixed_minute && fixed_hour && fields[2..] == ["*", "*", "*"];
  if timezone != "UTC" && !fixed_daily {
    return Err(StateValueError::CadenceProofUnavailable);
  }
  let proof_limit = if fixed_daily {
    proof_limit.max(146_100)
  } else {
    proof_limit
  };
  let cron = CronParser::new()
    .parse(expression)
    .map_err(|_| StateValueError::InvalidCron)?;
  let timezone =
    BundledTimeZone::parse(timezone).map_err(|()| StateValueError::CadenceProofUnavailable)?;
  let mut previous = None;
  let mut first = None;
  let mut reference = GREGORIAN_CYCLE_START - 1;
  let mut occurrences = 0_u32;
  loop {
    let reference_utc = DateTime::<Utc>::from_timestamp(reference, 0)
      .ok_or(StateValueError::CadenceProofUnavailable)?;
    let occurrence = cron
      .find_next_occurrence(&reference_utc.with_timezone(&timezone), false)
      .map_err(|_| StateValueError::CadenceProofUnavailable)?
      .timestamp();
    if occurrence <= reference {
      return Err(StateValueError::CadenceProofUnavailable);
    }
    if occurrence >= GREGORIAN_CYCLE_END {
      break;
    }
    occurrences = occurrences
      .checked_add(1)
      .ok_or(StateValueError::CadenceProofExhausted)?;
    if occurrences > proof_limit {
      return Err(StateValueError::CadenceProofExhausted);
    }
    first.get_or_insert(occurrence);
    if previous.is_some_and(|prior| occurrence - prior < minimum) {
      return Ok(false);
    }
    previous = Some(occurrence);
    reference = occurrence;
  }
  let (Some(first), Some(last)) = (first, previous) else {
    return Err(StateValueError::CadenceProofUnavailable);
  };
  let cycle = GREGORIAN_CYCLE_END - GREGORIAN_CYCLE_START;
  Ok(first + cycle - last >= minimum)
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
pub struct BoundedSchedulerGauge {
  pub value: u64,
  pub saturated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedSchedulerAge {
  pub value: u64,
  pub saturated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchedulerObservabilitySnapshot {
  pub due_jobs: BoundedSchedulerGauge,
  pub pending_runs: BoundedSchedulerGauge,
  pub leased_runs: BoundedSchedulerGauge,
  pub executing_runs: BoundedSchedulerGauge,
  pub unknown_runs: BoundedSchedulerGauge,
  pub unprepared_delivery_intents: BoundedSchedulerGauge,
  pub pending_deliveries: BoundedSchedulerGauge,
  pub sending_deliveries: BoundedSchedulerGauge,
  pub retryable_deliveries: BoundedSchedulerGauge,
  pub unknown_deliveries: BoundedSchedulerGauge,
  pub oldest_pending_run_age: Option<BoundedSchedulerAge>,
  pub oldest_unprepared_delivery_intent_age: Option<BoundedSchedulerAge>,
  pub oldest_pending_delivery_age: Option<BoundedSchedulerAge>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunLeaseBinding {
  run_id: String,
  job_id: String,
  attempt: i64,
  fence: i64,
  lease_owner: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduledExecutorEpochAuthority {
  pub schema_version: u32,
  pub deployment_epoch: i64,
  pub attestation_id: String,
  pub attestation_digest: String,
  pub profile_digest: String,
  pub issued_at: i64,
  pub expires_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduledExecutorAdmission {
  pub schema_version: u32,
  pub deployment_epoch: i64,
  pub attestation_id: String,
  pub profile_digest: String,
  pub signed_not_after: i64,
  pub operation_deadline: i64,
}

impl ScheduledExecutorAdmission {
  /// Validates the exact deployment identity and bounded operation window.
  ///
  /// # Errors
  /// Returns an error when the admission cannot safely authorize a state mutation.
  pub fn validate(&self) -> Result<(), StateValueError> {
    if self.schema_version != 1
      || self.deployment_epoch <= 0
      || self.operation_deadline <= 0
      || self.operation_deadline >= self.signed_not_after
    {
      return Err(StateValueError::InvalidValue {
        field: "scheduled executor admission",
      });
    }
    validate_lowercase_sha256("scheduled executor admission id", &self.attestation_id)?;
    validate_lowercase_sha256("scheduled executor admission profile", &self.profile_digest)
  }
}

impl ScheduledExecutorEpochAuthority {
  /// Validates the durable deployment epoch authority before registration.
  ///
  /// # Errors
  /// Returns an error for unsupported versions, invalid digests, epochs, or time bounds.
  pub fn validate(&self, now: i64) -> Result<(), StateValueError> {
    if self.schema_version != 1 || self.deployment_epoch <= 0 {
      return Err(StateValueError::InvalidValue {
        field: "scheduled executor deployment epoch",
      });
    }
    for (field, value) in [
      ("scheduled executor attestation id", &self.attestation_id),
      (
        "scheduled executor attestation digest",
        &self.attestation_digest,
      ),
      ("scheduled executor profile digest", &self.profile_digest),
    ] {
      validate_lowercase_sha256(field, value)?;
    }
    if self.issued_at <= 0 || self.expires_at <= self.issued_at || self.expires_at <= now {
      return Err(StateValueError::InvalidValue {
        field: "scheduled executor epoch validity",
      });
    }
    Ok(())
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScheduledExecutorEpochRegistration {
  Activated,
  Resumed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumeScheduledExecutionPermit {
  pub deployment_epoch: i64,
  pub attestation_id: String,
  pub profile_digest: String,
  pub run_id: String,
  pub job_id: String,
  pub attempt: i64,
  pub fence: i64,
  pub authority_digest: String,
  pub nonce: String,
  pub permit_id: String,
  pub consumed_at: i64,
}

impl ConsumeScheduledExecutionPermit {
  fn validate(&self) -> Result<(), StateValueError> {
    if self.deployment_epoch <= 0
      || self.attempt <= 0
      || self.fence <= 0
      || self.consumed_at <= 0
      || self.run_id.is_empty()
      || self.job_id.is_empty()
    {
      return Err(StateValueError::InvalidValue {
        field: "scheduled execution permit binding",
      });
    }
    for (field, value) in [
      ("scheduled execution attestation id", &self.attestation_id),
      ("scheduled execution profile digest", &self.profile_digest),
      (
        "scheduled execution authority digest",
        &self.authority_digest,
      ),
      ("scheduled execution permit nonce", &self.nonce),
      ("scheduled execution permit id", &self.permit_id),
    ] {
      validate_lowercase_sha256(field, value)?;
    }
    Ok(())
  }
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
  pub scheduler_policy: SchedulerOperationalPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduledPrepareAuthority {
  nonce: String,
  canonical_json: String,
  digest: String,
  instruction: String,
  previous_success: Option<String>,
  previous_success_was_truncated: bool,
}

impl ScheduledPrepareAuthority {
  /// Builds the version-one execution authority over a complete immutable run snapshot.
  ///
  /// # Errors
  /// Returns an error when the nonce or any persisted snapshot is invalid.
  #[allow(
    clippy::too_many_lines,
    reason = "keeps the canonical authority field order and digest inputs auditable in one owner"
  )]
  pub fn for_claim(
    claim: &ClaimedScheduledRun,
    nonce: impl Into<String>,
  ) -> Result<Self, StateValueError> {
    let nonce = nonce.into();
    validate_lowercase_sha256("scheduled prepare nonce", &nonce)?;
    validate_canonical_snapshot(
      claim.definition_version,
      "scheduled definition",
      &claim.definition_json,
    )?;
    validate_canonical_snapshot(
      claim.capability_schema_version,
      "scheduled capability",
      &claim.capability_json,
    )?;
    validate_canonical_json("scheduled targets", &claim.targets_json)?;
    validate_canonical_json(
      "scheduled execution baseline",
      &claim.execution_baseline_json,
    )?;
    claim
      .scheduler_policy
      .validate()
      .map_err(|_| StateValueError::InvalidValue {
        field: "scheduled operational policy",
      })?;
    let definition: Value =
      serde_json::from_str(&claim.definition_json).map_err(|_| StateValueError::InvalidJson {
        field: "scheduled definition",
      })?;
    let instruction = definition
      .get("instruction")
      .and_then(Value::as_str)
      .filter(|value| !value.trim().is_empty())
      .ok_or(StateValueError::InvalidJson {
        field: "scheduled definition",
      })?
      .to_owned();
    let baseline: Value = serde_json::from_str(&claim.execution_baseline_json).map_err(|_| {
      StateValueError::InvalidJson {
        field: "scheduled execution baseline",
      }
    })?;
    let include_previous = definition
      .pointer("/previous_success/kind")
      .and_then(Value::as_str)
      == Some("latest_success");
    let previous = include_previous
      .then(|| {
        baseline
          .get("previous_success_context")
          .and_then(Value::as_str)
      })
      .flatten();
    let (previous_success, previous_success_was_truncated) =
      previous.map_or((None, false), |value| {
        let boundary = bounded_utf8_boundary(value, MAX_PREVIOUS_SUCCESS_BYTES);
        (Some(value[..boundary].to_owned()), boundary < value.len())
      });
    let instruction_digest = framed_sha256("scheduled-instruction-v1", &[instruction.as_bytes()]);
    let definition_digest = framed_sha256(
      "scheduled-definition-v1",
      &[claim.definition_json.as_bytes()],
    );
    let capability_digest = framed_sha256(
      "scheduled-capability-v1",
      &[claim.capability_json.as_bytes()],
    );
    let targets_digest = framed_sha256("scheduled-targets-v1", &[claim.targets_json.as_bytes()]);
    let baseline_digest = framed_sha256(
      "scheduled-baseline-v1",
      &[claim.execution_baseline_json.as_bytes()],
    );
    let task_json = json!({
      "channel": null,
      "feedback_target": null,
      "instruction": instruction,
      "previous_success": previous_success.as_ref().map(|content| json!({
        "content": content,
        "was_truncated": previous_success_was_truncated,
      })),
      "principal": {"kind": "service", "service": "codeoff-scheduler"},
      "session": "fresh",
      "source": {
        "job_id": claim.binding.job_id(),
        "kind": "scheduled_run",
        "run_id": claim.binding.run_id(),
        "scheduled_for": claim.scheduled_for.to_string(),
      },
      "task_id": format!("scheduled:{}:{}:{}", claim.binding.run_id(), claim.binding.attempt(), claim.binding.fence()),
      "tool_policy": "none",
    })
    .to_string();
    let task_digest = framed_sha256("scheduled-agent-task-v1", &[task_json.as_bytes()]);
    let authority_json = json!({
      "binding": {
        "attempt": claim.binding.attempt(),
        "fence": claim.binding.fence(),
        "job_id": claim.binding.job_id(),
        "lease_owner": claim.binding.lease_owner(),
        "run_id": claim.binding.run_id(),
      },
      "capability_identity_digest": claim.capability_digest,
      "claim": {
        "capability_schema_version": claim.capability_schema_version,
        "coalesced_through": claim.coalesced_through,
        "definition_version": claim.definition_version,
        "job_generation": claim.job_generation,
        "schedule_generation": claim.schedule_generation,
        "schedule_id": claim.schedule_id,
        "scheduled_for": claim.scheduled_for,
      },
      "digests": {
        "baseline": baseline_digest,
        "capability": capability_digest,
        "definition": definition_digest,
        "instruction": instruction_digest,
        "targets": targets_digest,
        "task": task_digest,
      },
      "nonce": nonce,
      "operational_policy": claim.scheduler_policy,
      "schema_version": 1,
    })
    .to_string();
    let digest = framed_sha256(
      "scheduled-prepare-authority-v1",
      &[authority_json.as_bytes()],
    );
    Ok(Self {
      nonce,
      canonical_json: authority_json,
      digest,
      instruction,
      previous_success,
      previous_success_was_truncated,
    })
  }

  #[must_use]
  pub fn nonce(&self) -> &str {
    &self.nonce
  }

  #[must_use]
  pub fn canonical_json(&self) -> &str {
    &self.canonical_json
  }

  #[must_use]
  pub fn digest(&self) -> &str {
    &self.digest
  }

  #[must_use]
  pub fn instruction(&self) -> &str {
    &self.instruction
  }

  #[must_use]
  pub fn previous_success(&self) -> Option<&str> {
    self.previous_success.as_deref()
  }

  #[must_use]
  pub const fn previous_success_was_truncated(&self) -> bool {
    self.previous_success_was_truncated
  }

  #[must_use]
  /// Builds the canonical attestation envelope for this authority.
  ///
  /// # Panics
  /// Panics only if this privately constructed authority no longer contains valid canonical JSON.
  pub fn attestation_json(&self, side_effect_free: bool) -> String {
    let authority: Value = serde_json::from_str(&self.canonical_json)
      .expect("validated authority remains valid canonical JSON");
    json!({
      "authority": authority,
      "authority_digest": self.digest,
      "schema_version": 1,
      "side_effect_free": side_effect_free,
    })
    .to_string()
  }

  /// Builds the version-two attestation envelope used for safe execution recovery.
  ///
  /// The capability profile must be the canonical server-issued profile for the executor that
  /// prepared this exact authority. The envelope records the complete enforced execution surface
  /// rather than trusting a caller-supplied `side_effect_free` assertion.
  ///
  /// # Errors
  /// Returns an error when the capability profile is not canonical or is incomplete.
  ///
  /// # Panics
  /// Panics only if this privately constructed authority no longer contains valid canonical JSON.
  pub fn recovery_attestation_json(
    &self,
    capability_profile_json: &str,
  ) -> Result<String, StateValueError> {
    let capability_profile = validate_recovery_capability_profile(capability_profile_json)?;
    let authority: Value = serde_json::from_str(&self.canonical_json)
      .expect("validated authority remains valid canonical JSON");
    Ok(
      json!({
        "authority": authority,
        "authority_digest": self.digest,
        "capability_profile": capability_profile,
        "execution_surface": {
          "approval_policy": "never",
          "dynamic_tools": false,
          "network_access": false,
          "sandbox": "read-only",
          "web_search": "disabled",
        },
        "schema_version": 2,
      })
      .to_string(),
    )
  }

  #[must_use]
  pub fn attestation_matches(
    &self,
    canonical_json: &str,
    digest: &str,
    require_side_effect_free: bool,
  ) -> bool {
    let Ok(profile) = serde_json::from_str::<Value>(canonical_json) else {
      return false;
    };
    if serde_json::to_string(&profile).ok().as_deref() != Some(canonical_json)
      || sha256_hex(canonical_json.as_bytes()) != digest
      || profile.get("schema_version").and_then(Value::as_u64) != Some(1)
      || profile.get("authority_digest").and_then(Value::as_str) != Some(self.digest())
      || profile.get("authority")
        != serde_json::from_str::<Value>(&self.canonical_json)
          .ok()
          .as_ref()
    {
      return false;
    }
    !require_side_effect_free
      || profile.get("side_effect_free").and_then(Value::as_bool) == Some(true)
  }

  #[must_use]
  pub fn recovery_attestation_matches(&self, canonical_json: &str, digest: &str) -> bool {
    let Ok(profile) = serde_json::from_str::<Value>(canonical_json) else {
      return false;
    };
    let expected_surface = json!({
      "approval_policy": "never",
      "dynamic_tools": false,
      "network_access": false,
      "sandbox": "read-only",
      "web_search": "disabled",
    });
    if serde_json::to_string(&profile).ok().as_deref() != Some(canonical_json)
      || sha256_hex(canonical_json.as_bytes()) != digest
      || profile.get("schema_version").and_then(Value::as_u64) != Some(2)
      || profile.get("authority_digest").and_then(Value::as_str) != Some(self.digest())
      || profile.get("authority")
        != serde_json::from_str::<Value>(&self.canonical_json)
          .ok()
          .as_ref()
      || profile.get("execution_surface") != Some(&expected_surface)
    {
      return false;
    }
    profile
      .get("capability_profile")
      .is_some_and(|value| validate_recovery_capability_profile_value(value).is_ok())
  }
}

fn validate_recovery_capability_profile(canonical_json: &str) -> Result<Value, StateValueError> {
  validate_canonical_json("scheduled recovery capability profile", canonical_json)?;
  let value = serde_json::from_str(canonical_json).map_err(|_| StateValueError::InvalidJson {
    field: "scheduled recovery capability profile",
  })?;
  validate_recovery_capability_profile_value(&value)?;
  Ok(value)
}

fn validate_recovery_capability_profile_value(value: &Value) -> Result<(), StateValueError> {
  const EXPECTED_GITHUB_TOOLS: [&str; 4] =
    ["issue_read", "list_issues", "search_issues", "search_orgs"];
  const REQUIRED_TEXT: [&str; 15] = [
    "app_server_schema_sha256",
    "codex_program_sha256",
    "codex_version",
    "config_revision",
    "config_sha256",
    "credential_deny_policy_revision",
    "credential_isolation_revision",
    "credential_reference",
    "github_mcp_artifact_sha256",
    "github_mcp_endpoint_identity",
    "github_mcp_version",
    "negative_test_revision",
    "output_schema_revision",
    "permission_policy_revision",
    "profile_sha256",
  ];
  let object = value.as_object().ok_or(StateValueError::InvalidJson {
    field: "scheduled recovery capability profile",
  })?;
  if object.len() != REQUIRED_TEXT.len() + 2
    || REQUIRED_TEXT.iter().any(|field| {
      object
        .get(*field)
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    })
    || object
      .get("attested_at_unix_seconds")
      .and_then(Value::as_u64)
      .is_none()
  {
    return Err(StateValueError::InvalidJson {
      field: "scheduled recovery capability profile",
    });
  }
  let Some(tools) = object.get("github_tools").and_then(Value::as_array) else {
    return Err(StateValueError::InvalidJson {
      field: "scheduled recovery capability profile",
    });
  };
  if tools.len() != EXPECTED_GITHUB_TOOLS.len()
    || tools
      .iter()
      .zip(EXPECTED_GITHUB_TOOLS)
      .any(|(actual, expected)| actual.as_str() != Some(expected))
  {
    return Err(StateValueError::InvalidJson {
      field: "scheduled recovery capability profile",
    });
  }
  for field in [
    "app_server_schema_sha256",
    "codex_program_sha256",
    "config_sha256",
    "github_mcp_artifact_sha256",
    "profile_sha256",
  ] {
    validate_lowercase_sha256(
      "scheduled recovery capability profile digest",
      object[field]
        .as_str()
        .expect("required string checked above"),
    )?;
  }
  let canonical_profile = json!({
    "app_server_schema_sha256": object["app_server_schema_sha256"],
    "codex_program_sha256": object["codex_program_sha256"],
    "codex_version": object["codex_version"],
    "config_revision": object["config_revision"],
    "config_sha256": object["config_sha256"],
    "credential_deny_policy_revision": object["credential_deny_policy_revision"],
    "credential_isolation_revision": object["credential_isolation_revision"],
    "credential_reference": object["credential_reference"],
    "github_mcp_artifact_sha256": object["github_mcp_artifact_sha256"],
    "github_mcp_endpoint_identity": object["github_mcp_endpoint_identity"],
    "github_mcp_version": object["github_mcp_version"],
    "github_tools": object["github_tools"],
    "negative_test_revision": object["negative_test_revision"],
    "output_schema_revision": object["output_schema_revision"],
    "permission_policy_revision": object["permission_policy_revision"],
  });
  if object["profile_sha256"].as_str()
    != Some(&sha256_hex(canonical_profile.to_string().as_bytes()))
  {
    return Err(StateValueError::InvalidSha256 {
      field: "scheduled recovery capability profile digest",
    });
  }
  Ok(())
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScheduledExecutionTerminal {
  Failed,
  TimedOut,
  Cancelled,
  OutcomeUnknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportConvergence {
  Converged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScheduledExecutionDisposition {
  RetryAt {
    retry_at: i64,
    deadline_at: i64,
    max_attempts: i64,
    transport: TransportConvergence,
    exhausted: ScheduledExecutionTerminal,
  },
  Terminal(ScheduledExecutionTerminal),
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScheduledRunReconcileOutcome {
  Applied(ExpiredRunReclaimOutcome),
  Stale,
  NotEligible,
}

#[derive(Clone, PartialEq, Eq)]
pub struct ScheduledRunReconcileCandidate {
  run_id: String,
  state: ScheduledRunState,
  attempt: i64,
  fence: i64,
  lease_owner: String,
  lease_expires_at: i64,
}

impl ScheduledRunReconcileCandidate {
  #[must_use]
  pub fn run_id(&self) -> &str {
    &self.run_id
  }

  #[must_use]
  pub const fn state(&self) -> ScheduledRunState {
    self.state
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
  pub const fn lease_expires_at(&self) -> i64 {
    self.lease_expires_at
  }

  /// Returns the canonical, sanitized authority snapshot bound into reconcile plans.
  #[must_use]
  pub fn canonical_plan_snapshot(&self) -> String {
    json!({
      "attempt": self.attempt,
      "fence": self.fence,
      "lease_expires_at": self.lease_expires_at,
      "lease_owner_digest": sha256_hex(self.lease_owner.as_bytes()),
      "run_id": self.run_id,
      "state": self.state.as_str(),
    })
    .to_string()
  }
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduledRunResult {
  summary: String,
  previous_success_context: String,
}

impl ScheduledRunResult {
  /// Builds a bounded version-one scheduled execution result.
  ///
  /// # Errors
  /// Returns an error when the summary is empty or either field exceeds its storage bound.
  pub fn new(
    summary: impl Into<String>,
    previous_success_context: impl Into<String>,
  ) -> Result<Self, StateValueError> {
    let value = Self {
      summary: summary.into(),
      previous_success_context: previous_success_context.into(),
    };
    validate_text("scheduled result summary", &value.summary)?;
    if value.previous_success_context.len() > MAX_CONTEXT_BYTES {
      return Err(StateValueError::TooLarge {
        field: "scheduled result previous success context",
      });
    }
    Ok(value)
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScheduledRunSuccessOutcome {
  Committed,
  LateEvidence(LateEvidenceAppendOutcome),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScheduledRunExecutionOutcome {
  Retried,
  Terminal(ScheduledExecutionTerminal),
  LateEvidence(LateEvidenceAppendOutcome),
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

#[derive(Debug, Clone)]
pub struct SchedulerOperatorRequest {
  pub principal: PrincipalKey,
  pub request_id: String,
  pub request_digest: String,
  pub occurred_at: i64,
}

impl SchedulerOperatorRequest {
  /// Builds authority for one exact manual run retry.
  ///
  /// # Errors
  /// Returns an error for invalid principal, request, target, or counters.
  #[allow(clippy::too_many_arguments)]
  pub fn for_run_retry(
    principal: PrincipalKey,
    request_id: impl Into<String>,
    run_id: &str,
    expected_attempt: i64,
    expected_fence: i64,
    expected_state: ScheduledRunState,
    reason_json: &str,
    reason_digest: &str,
    next_attempt_at: i64,
    occurred_at: i64,
  ) -> Result<Self, StateValueError> {
    principal.validate()?;
    let request_id = request_id.into();
    validate_text("operator request id", &request_id)?;
    validate_text("operator run id", run_id)?;
    validate_operator_reason(reason_json, reason_digest)?;
    if expected_attempt <= 0
      || expected_fence <= 0
      || next_attempt_at < occurred_at
      || !matches!(
        expected_state,
        ScheduledRunState::Failed | ScheduledRunState::TimedOut | ScheduledRunState::Cancelled
      )
    {
      return Err(StateValueError::InvalidVersion);
    }
    Ok(Self {
      principal,
      request_id,
      request_digest: operator_action_request_digest(
        "retry_run",
        "run",
        run_id,
        expected_attempt,
        expected_fence,
        expected_state.as_str(),
        "pending",
        None,
        None,
        Some(reason_json),
        Some(reason_digest),
        None,
        false,
        next_attempt_at,
      ),
      occurred_at,
    })
  }

  /// Builds authority for one exact manual retry of a conclusively unwritten delivery.
  ///
  /// # Errors
  /// Returns an error for invalid principal, request, target, evidence, or counters.
  #[allow(clippy::too_many_arguments)]
  pub fn for_delivery_retry(
    principal: PrincipalKey,
    request_id: impl Into<String>,
    delivery_id: &str,
    expected_attempt: i64,
    expected_fence: i64,
    reason_json: &str,
    reason_digest: &str,
    occurred_at: i64,
  ) -> Result<Self, StateValueError> {
    principal.validate()?;
    let request_id = request_id.into();
    validate_text("operator request id", &request_id)?;
    validate_text("operator delivery id", delivery_id)?;
    validate_operator_reason(reason_json, reason_digest)?;
    if expected_attempt <= 0 || expected_fence <= 0 || occurred_at < 0 {
      return Err(StateValueError::InvalidVersion);
    }
    Ok(Self {
      principal,
      request_id,
      request_digest: operator_action_request_digest(
        "retry_delivery",
        "delivery",
        delivery_id,
        expected_attempt,
        expected_fence,
        "failed_retryable",
        "pending",
        Some(reason_json),
        Some(reason_digest),
        None,
        None,
        None,
        false,
        occurred_at,
      ),
      occurred_at,
    })
  }

  /// Builds authority for one exact ambiguous-delivery operator action.
  ///
  /// # Errors
  /// Returns an error for invalid principal, request, target, evidence, or counters.
  pub fn for_delivery_action(
    principal: PrincipalKey,
    request_id: impl Into<String>,
    delivery_id: &str,
    expected_attempt: i64,
    expected_fence: i64,
    action: &ScheduledDeliveryUnknownAction,
    occurred_at: i64,
  ) -> Result<Self, StateValueError> {
    principal.validate()?;
    let request_id = request_id.into();
    validate_text("operator request id", &request_id)?;
    validate_text("operator delivery id", delivery_id)?;
    if expected_attempt <= 0 || expected_fence <= 0 {
      return Err(StateValueError::InvalidVersion);
    }
    let (
      action_name,
      after_state,
      evidence_json,
      evidence_digest,
      receipt,
      reason_json,
      reason_digest,
      duplicate_ack,
    ) = action.authority_parts()?;
    Ok(Self {
      principal,
      request_id,
      request_digest: operator_action_request_digest(
        action_name,
        "delivery",
        delivery_id,
        expected_attempt,
        expected_fence,
        "delivery_unknown",
        after_state,
        Some(evidence_json),
        Some(evidence_digest),
        reason_json,
        reason_digest,
        receipt,
        duplicate_ack,
        occurred_at,
      ),
      occurred_at,
    })
  }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchedulerOperatorMutationOutcome {
  Applied,
  Replay,
  Conflict,
}

#[derive(Clone, PartialEq, Eq)]
pub enum ScheduledDeliveryUnknownAction {
  ConfirmDelivered {
    provider_receipt: String,
    evidence_json: String,
    evidence_digest: String,
  },
  ConfirmNoWriteTerminal {
    evidence_json: String,
    evidence_digest: String,
  },
  ForceResend {
    evidence_json: String,
    evidence_digest: String,
    reason_json: String,
    reason_digest: String,
    duplicate_risk_acknowledged: bool,
  },
  AcknowledgeUnknown {
    evidence_json: String,
    evidence_digest: String,
  },
}

impl fmt::Debug for ScheduledDeliveryUnknownAction {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::ConfirmDelivered {
        evidence_digest, ..
      } => formatter
        .debug_struct("ConfirmDelivered")
        .field("evidence_digest", evidence_digest)
        .finish_non_exhaustive(),
      Self::ConfirmNoWriteTerminal {
        evidence_digest, ..
      } => formatter
        .debug_struct("ConfirmNoWriteTerminal")
        .field("evidence_digest", evidence_digest)
        .finish_non_exhaustive(),
      Self::ForceResend {
        evidence_digest,
        reason_digest,
        duplicate_risk_acknowledged,
        ..
      } => formatter
        .debug_struct("ForceResend")
        .field("evidence_digest", evidence_digest)
        .field("reason_digest", reason_digest)
        .field("duplicate_risk_acknowledged", duplicate_risk_acknowledged)
        .finish_non_exhaustive(),
      Self::AcknowledgeUnknown {
        evidence_digest, ..
      } => formatter
        .debug_struct("AcknowledgeUnknown")
        .field("evidence_digest", evidence_digest)
        .finish_non_exhaustive(),
    }
  }
}

type DeliveryUnknownAuthorityParts<'a> = (
  &'static str,
  &'static str,
  &'a str,
  &'a str,
  Option<&'a str>,
  Option<&'a str>,
  Option<&'a str>,
  bool,
);

impl ScheduledDeliveryUnknownAction {
  fn authority_parts(&self) -> Result<DeliveryUnknownAuthorityParts<'_>, StateValueError> {
    let parts = match self {
      Self::ConfirmDelivered {
        provider_receipt,
        evidence_json,
        evidence_digest,
      } => {
        validate_operator_provider_receipt(provider_receipt)?;
        validate_operator_delivery_evidence(
          evidence_json,
          evidence_digest,
          "provider_confirmed_delivered",
          Some(provider_receipt),
        )?;
        (
          "confirm_delivery_delivered",
          "delivered",
          evidence_json.as_str(),
          evidence_digest.as_str(),
          Some(provider_receipt.as_str()),
          None,
          None,
          false,
        )
      }
      Self::ConfirmNoWriteTerminal {
        evidence_json,
        evidence_digest,
      } => {
        validate_operator_delivery_evidence(
          evidence_json,
          evidence_digest,
          "provider_confirmed_no_write",
          None,
        )?;
        (
          "confirm_delivery_no_write",
          "failed_terminal",
          evidence_json.as_str(),
          evidence_digest.as_str(),
          None,
          None,
          None,
          false,
        )
      }
      Self::ForceResend {
        evidence_json,
        evidence_digest,
        reason_json,
        reason_digest,
        duplicate_risk_acknowledged,
      } => {
        if !duplicate_risk_acknowledged {
          return Err(StateValueError::InvalidVersion);
        }
        validate_operator_reason(reason_json, reason_digest)?;
        validate_operator_delivery_evidence(
          evidence_json,
          evidence_digest,
          "operator_force_resend",
          None,
        )?;
        (
          "force_delivery_resend",
          "pending",
          evidence_json.as_str(),
          evidence_digest.as_str(),
          None,
          Some(reason_json.as_str()),
          Some(reason_digest.as_str()),
          true,
        )
      }
      Self::AcknowledgeUnknown {
        evidence_json,
        evidence_digest,
      } => {
        validate_operator_delivery_evidence(
          evidence_json,
          evidence_digest,
          "operator_acknowledged_unknown",
          None,
        )?;
        (
          "acknowledge_delivery_unknown",
          "delivery_unknown",
          evidence_json.as_str(),
          evidence_digest.as_str(),
          None,
          None,
          None,
          false,
        )
      }
    };
    Ok(parts)
  }
}

fn validate_operator_provider_receipt(provider_receipt: &str) -> Result<(), StateValueError> {
  let receipt: Value =
    serde_json::from_str(provider_receipt).map_err(|_| StateValueError::InvalidJson {
      field: "operator provider receipt",
    })?;
  let Some(object) = receipt.as_object() else {
    return Err(StateValueError::InvalidJson {
      field: "operator provider receipt",
    });
  };
  let exact_keys = [
    "conversation_id",
    "message_id",
    "provider",
    "receipt_version",
    "target_kind",
    "tenant",
    "thread_id",
  ];
  if object.len() != exact_keys.len() || exact_keys.iter().any(|key| !object.contains_key(*key)) {
    return Err(StateValueError::InvalidJson {
      field: "operator provider receipt",
    });
  }
  if object.get("receipt_version").and_then(Value::as_u64) != Some(1) {
    return Err(StateValueError::InvalidVersion);
  }
  for key in [
    "provider",
    "tenant",
    "target_kind",
    "conversation_id",
    "message_id",
  ] {
    let value = object
      .get(key)
      .and_then(Value::as_str)
      .ok_or(StateValueError::InvalidJson {
        field: "operator provider receipt",
      })?;
    validate_text("operator provider receipt identity", value)?;
  }
  if let Some(thread_id) = object.get("thread_id").and_then(Value::as_str) {
    validate_text("operator provider receipt thread id", thread_id)?;
  } else if !object.get("thread_id").is_some_and(Value::is_null) {
    return Err(StateValueError::InvalidJson {
      field: "operator provider receipt",
    });
  }
  if serde_json::to_string(&receipt).map_err(|_| StateValueError::InvalidJson {
    field: "operator provider receipt",
  })?
    != provider_receipt
  {
    return Err(StateValueError::NonCanonicalJson {
      field: "operator provider receipt",
    });
  }
  Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_operator_delivery_evidence(
  evidence_json: &str,
  evidence_digest: &str,
  expected_kind: &str,
  provider_receipt: Option<&str>,
) -> Result<(), StateValueError> {
  validate_lowercase_sha256("operator evidence digest", evidence_digest)?;
  let evidence: Value =
    serde_json::from_str(evidence_json).map_err(|_| StateValueError::InvalidJson {
      field: "operator delivery evidence",
    })?;
  let Some(object) = evidence.as_object() else {
    return Err(StateValueError::InvalidJson {
      field: "operator delivery evidence",
    });
  };
  let mut exact_keys = vec![
    "evidence_id",
    "evidence_version",
    "kind",
    "provider",
    "target_kind",
    "tenant",
  ];
  let expected_query_result = match expected_kind {
    "provider_confirmed_delivered" => Some("write_confirmed"),
    "provider_confirmed_no_write" => Some("no_write_confirmed"),
    "operator_force_resend" => Some("no_matching_write_found"),
    "operator_acknowledged_unknown" => None,
    _ => return Err(StateValueError::InvalidVersion),
  };
  if expected_query_result.is_some() {
    exact_keys.extend([
      "provider_query_completed_at",
      "provider_query_result",
      "provider_query_scope",
      "provider_query_started_at",
      "provider_query_summary_digest",
      "provider_query_window_end",
      "provider_query_window_start",
    ]);
  }
  if provider_receipt.is_some() {
    exact_keys.push("receipt_digest");
  }
  if object.len() != exact_keys.len() || exact_keys.iter().any(|key| !object.contains_key(*key)) {
    return Err(StateValueError::InvalidJson {
      field: "operator delivery evidence",
    });
  }
  if object.get("evidence_version").and_then(Value::as_u64) != Some(1)
    || object.get("kind").and_then(Value::as_str) != Some(expected_kind)
  {
    return Err(StateValueError::InvalidVersion);
  }
  for key in ["evidence_id", "provider", "tenant", "target_kind"] {
    let value = object
      .get(key)
      .and_then(Value::as_str)
      .ok_or(StateValueError::InvalidJson {
        field: "operator delivery evidence",
      })?;
    validate_text("operator delivery evidence identity", value)?;
  }
  if let Some(expected_query_result) = expected_query_result {
    let started_at = object
      .get("provider_query_started_at")
      .and_then(Value::as_i64)
      .ok_or(StateValueError::InvalidJson {
        field: "operator delivery evidence",
      })?;
    let completed_at = object
      .get("provider_query_completed_at")
      .and_then(Value::as_i64)
      .ok_or(StateValueError::InvalidJson {
        field: "operator delivery evidence",
      })?;
    let window_start = object
      .get("provider_query_window_start")
      .and_then(Value::as_i64)
      .ok_or(StateValueError::InvalidJson {
        field: "operator delivery evidence",
      })?;
    let window_end = object
      .get("provider_query_window_end")
      .and_then(Value::as_i64)
      .ok_or(StateValueError::InvalidJson {
        field: "operator delivery evidence",
      })?;
    if started_at < 0
      || completed_at < started_at
      || window_start < 0
      || window_end < window_start
      || window_end > completed_at
      || window_end - window_start > 31 * 24 * 60 * 60
      || object.get("provider_query_scope").and_then(Value::as_str)
        != Some("canonical_delivery_target")
      || object.get("provider_query_result").and_then(Value::as_str) != Some(expected_query_result)
    {
      return Err(StateValueError::InvalidJson {
        field: "operator delivery evidence",
      });
    }
    let summary_digest = object
      .get("provider_query_summary_digest")
      .and_then(Value::as_str)
      .ok_or(StateValueError::InvalidJson {
        field: "operator delivery evidence",
      })?;
    validate_lowercase_sha256("operator query summary digest", summary_digest)?;
  }
  if let Some(provider_receipt) = provider_receipt {
    let receipt_digest =
      object
        .get("receipt_digest")
        .and_then(Value::as_str)
        .ok_or(StateValueError::InvalidJson {
          field: "operator delivery evidence",
        })?;
    validate_lowercase_sha256("operator receipt digest", receipt_digest)?;
    if sha256_hex(provider_receipt.as_bytes()) != receipt_digest {
      return Err(StateValueError::InvalidSha256 {
        field: "operator receipt digest",
      });
    }
  }
  if serde_json::to_string(&evidence).map_err(|_| StateValueError::InvalidJson {
    field: "operator delivery evidence",
  })?
    != evidence_json
  {
    return Err(StateValueError::NonCanonicalJson {
      field: "operator delivery evidence",
    });
  }
  if sha256_hex(evidence_json.as_bytes()) != evidence_digest {
    return Err(StateValueError::InvalidSha256 {
      field: "operator evidence digest",
    });
  }
  Ok(())
}

pub(crate) fn operator_delivery_evidence_binding(
  action: &ScheduledDeliveryUnknownAction,
) -> Result<(String, String, String), StateValueError> {
  let (_, _, evidence_json, _, _, _, _, _) = action.authority_parts()?;
  let evidence: Value =
    serde_json::from_str(evidence_json).map_err(|_| StateValueError::InvalidJson {
      field: "operator delivery evidence",
    })?;
  let object = evidence.as_object().ok_or(StateValueError::InvalidJson {
    field: "operator delivery evidence",
  })?;
  Ok((
    object
      .get("provider")
      .and_then(Value::as_str)
      .ok_or(StateValueError::InvalidJson {
        field: "operator delivery evidence",
      })?
      .to_owned(),
    object
      .get("tenant")
      .and_then(Value::as_str)
      .ok_or(StateValueError::InvalidJson {
        field: "operator delivery evidence",
      })?
      .to_owned(),
    object
      .get("target_kind")
      .and_then(Value::as_str)
      .ok_or(StateValueError::InvalidJson {
        field: "operator delivery evidence",
      })?
      .to_owned(),
  ))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn operator_action_request_digest(
  action: &str,
  target_kind: &str,
  target_id: &str,
  expected_attempt: i64,
  expected_fence: i64,
  before_state: &str,
  after_state: &str,
  evidence_json: Option<&str>,
  evidence_digest: Option<&str>,
  reason_json: Option<&str>,
  reason_digest: Option<&str>,
  provider_receipt: Option<&str>,
  duplicate_risk_acknowledged: bool,
  effective_at: i64,
) -> String {
  sha256_hex(
    json!({
      "action": action,
      "after_state": after_state,
      "before_state": before_state,
      "duplicate_risk_acknowledged": duplicate_risk_acknowledged,
      "effective_at": effective_at,
      "evidence_json": evidence_json,
      "evidence_digest": evidence_digest,
      "expected_attempt": expected_attempt,
      "expected_fence": expected_fence,
      "provider_receipt": provider_receipt,
      "reason_digest": reason_digest,
      "reason_json": reason_json,
      "target_id": target_id,
      "target_kind": target_kind,
    })
    .to_string()
    .as_bytes(),
  )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduledRunOperatorProjection {
  pub run_id: String,
  pub job_id: String,
  pub state: ScheduledRunState,
  pub attempt: i64,
  pub fence: i64,
  pub next_attempt_at: Option<i64>,
  pub lease_expires_at: Option<i64>,
  pub error_kind: Option<String>,
  pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduledDeliveryOperatorProjection {
  pub delivery_id: String,
  pub run_id: String,
  pub job_id: String,
  pub state: ScheduledDeliveryState,
  pub attempt: i64,
  pub fence: i64,
  pub next_attempt_at: Option<i64>,
  pub lease_expires_at: Option<i64>,
  pub provider_outcome: Option<String>,
  pub error_kind: Option<String>,
  pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchedulerOperatorActionSummary {
  pub action_id: String,
  pub action: String,
  pub target_kind: String,
  pub target_id: String,
  pub before_state: String,
  pub after_state: String,
  pub occurred_at: i64,
  pub consumed: bool,
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

fn validate_canonical_json(field: &'static str, json: &str) -> Result<(), StateValueError> {
  if json.len() > MAX_SNAPSHOT_BYTES {
    return Err(StateValueError::TooLarge { field });
  }
  let value =
    serde_json::from_str::<Value>(json).map_err(|_| StateValueError::InvalidJson { field })?;
  if serde_json::to_string(&value).ok().as_deref() != Some(json) {
    return Err(StateValueError::NonCanonicalJson { field });
  }
  Ok(())
}

fn validate_operator_reason(reason_json: &str, reason_digest: &str) -> Result<(), StateValueError> {
  const FIELD: &str = "operator retry reason";
  if reason_json.len() > MAX_CONTEXT_BYTES {
    return Err(StateValueError::TooLarge { field: FIELD });
  }
  validate_canonical_json(FIELD, reason_json)?;
  validate_lowercase_sha256("operator retry reason digest", reason_digest)?;
  if sha256_hex(reason_json.as_bytes()) != reason_digest {
    return Err(StateValueError::InvalidSha256 {
      field: "operator retry reason digest",
    });
  }
  let value: Value =
    serde_json::from_str(reason_json).map_err(|_| StateValueError::InvalidJson { field: FIELD })?;
  let object = value
    .as_object()
    .ok_or(StateValueError::InvalidJson { field: FIELD })?;
  let exact_keys = ["reason", "reason_code", "schema_version"];
  let reason = object.get("reason").and_then(Value::as_str);
  let reason_code = object.get("reason_code").and_then(Value::as_str);
  if object.len() != exact_keys.len()
    || exact_keys.iter().any(|key| !object.contains_key(*key))
    || object.get("schema_version").and_then(Value::as_u64) != Some(1)
    || reason
      .is_none_or(|reason| reason.is_empty() || reason.len() > 4 * 1024 || reason.trim() != reason)
    || reason_code.is_none_or(|code| {
      code.is_empty()
        || code.len() > 64
        || !code
          .bytes()
          .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    })
  {
    return Err(StateValueError::InvalidJson { field: FIELD });
  }
  Ok(())
}

fn bounded_utf8_boundary(value: &str, maximum: usize) -> usize {
  if value.len() <= maximum {
    return value.len();
  }
  value
    .char_indices()
    .map(|(index, _)| index)
    .take_while(|index| *index <= maximum)
    .last()
    .unwrap_or(0)
}

fn framed_sha256(domain: &str, values: &[&[u8]]) -> String {
  let mut digest = Sha256::new();
  for value in std::iter::once(domain.as_bytes()).chain(values.iter().copied()) {
    digest.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(value);
  }
  let bytes = digest.finalize();
  encode_sha256(&bytes)
}

fn sha256_hex(value: &[u8]) -> String {
  let mut digest = Sha256::new();
  digest.update(value);
  let bytes = digest.finalize();
  encode_sha256(&bytes)
}

fn encode_sha256(value: &[u8]) -> String {
  value
    .iter()
    .fold(String::with_capacity(64), |mut encoded, byte| {
      write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
      encoded
    })
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

fn validate_lowercase_sha256(field: &'static str, value: &str) -> Result<(), StateValueError> {
  if value.len() != 64
    || !value
      .bytes()
      .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
  {
    return Err(StateValueError::InvalidSha256 { field });
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

#[cfg(test)]
mod tests {
  use super::{ScheduleSpec, StateValueError};

  #[test]
  fn cron_cadence_proof_rejects_a_later_short_pair() {
    let schedule = ScheduleSpec::cron("0 0 1,15,16 * *", "UTC").expect("valid cron");
    assert_eq!(
      schedule
        .validate_minimum_cadence(1_800_000_000, 2 * 86_400, 100_000)
        .expect_err("the monthly 15th to 16th gap is too short"),
      StateValueError::CadenceTooShort
    );
  }

  #[test]
  fn cron_cadence_proof_accepts_common_safe_utc_and_timezone_daily_schedules() {
    ScheduleSpec::cron("0 3 * * *", "UTC")
      .expect("valid UTC daily cron")
      .validate_minimum_cadence(1_800_000_000, 86_400, 1)
      .expect("fixed UTC daily cadence is statically proven");
    ScheduleSpec::cron("0 3 * * *", "America/New_York")
      .expect("valid timezone daily cron")
      .validate_minimum_cadence(1_800_000_000, 23 * 3_600, 1)
      .expect("full-cycle timezone proof includes DST transitions");
  }

  #[test]
  fn cron_cadence_proof_fails_closed_for_exhaustion_and_variable_timezone_rules() {
    let exhausted = ScheduleSpec::cron("0 0 1 * *", "UTC").expect("valid monthly cron");
    assert_eq!(
      exhausted
        .validate_minimum_cadence(1_800_000_000, 61, 1)
        .expect_err("proof bound must be enforced"),
      StateValueError::CadenceProofExhausted
    );
    let variable = ScheduleSpec::cron("0 0 1,15,16 * *", "America/New_York").expect("valid cron");
    assert_eq!(
      variable
        .validate_minimum_cadence(1_800_000_000, 61, 100_000)
        .expect_err("variable timezone expression is not canonically provable"),
      StateValueError::CadenceProofUnavailable
    );
  }
}
