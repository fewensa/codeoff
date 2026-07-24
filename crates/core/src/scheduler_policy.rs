//! Canonical operational policy for durable scheduler work.

use std::fmt;

use serde::{Deserialize, Serialize};

pub const SCHEDULER_OPERATIONAL_POLICY_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchedulerOperationalPolicy {
  pub schema_version: u32,
  pub recovery_batch_limit: u16,
  pub materialization_batch_limit: u16,
  pub occurrence_search_limit: u32,
  pub tick_interval_ms: u64,
  pub error_backoff_ms: u64,
  pub minimum_schedule_cadence_seconds: u32,
  pub max_active_jobs: u32,
  pub max_active_jobs_per_owner: u32,
  pub max_prompt_bytes: u32,
  pub max_result_bytes: u32,
  pub max_summary_bytes: u32,
  pub run_lease_seconds: u16,
  pub run_heartbeat_interval_ms: u64,
  pub run_timeout_seconds: u32,
  pub run_prepare_grace_ms: u64,
  pub run_cancellation_grace_ms: u64,
  pub run_finalization_grace_ms: u64,
  pub run_retry_base_seconds: u32,
  pub run_retry_max_seconds: u32,
  pub run_deadline_seconds: u32,
  pub run_max_attempts: u16,
  pub delivery_tick_interval_ms: u64,
  pub delivery_batch_limit: u16,
  pub delivery_lease_seconds: u16,
  pub delivery_heartbeat_interval_ms: u64,
  pub delivery_readiness_timeout_seconds: u16,
  pub delivery_send_timeout_seconds: u16,
  pub delivery_finalization_timeout_seconds: u16,
  pub delivery_max_attempts: u16,
  pub delivery_retry_base_seconds: u32,
  pub delivery_retry_max_seconds: u32,
  pub delivery_retry_after_max_seconds: u32,
  pub delivery_deadline_seconds: u32,
  pub delivery_readiness_retry_base_seconds: u16,
  pub delivery_readiness_retry_max_seconds: u16,
}

impl Default for SchedulerOperationalPolicy {
  fn default() -> Self {
    Self {
      schema_version: SCHEDULER_OPERATIONAL_POLICY_VERSION,
      recovery_batch_limit: 32,
      materialization_batch_limit: 32,
      occurrence_search_limit: 100_000,
      tick_interval_ms: 250,
      error_backoff_ms: 1_000,
      minimum_schedule_cadence_seconds: 60,
      max_active_jobs: 1_000,
      max_active_jobs_per_owner: 100,
      max_prompt_bytes: 64 * 1024,
      max_result_bytes: 64 * 1024,
      max_summary_bytes: 32 * 1024,
      run_lease_seconds: 60,
      run_heartbeat_interval_ms: 15_000,
      run_timeout_seconds: 1_800,
      run_prepare_grace_ms: 5_000,
      run_cancellation_grace_ms: 5_000,
      run_finalization_grace_ms: 5_000,
      run_retry_base_seconds: 30,
      run_retry_max_seconds: 300,
      run_deadline_seconds: 3_600,
      run_max_attempts: 3,
      delivery_tick_interval_ms: 250,
      delivery_batch_limit: 32,
      delivery_lease_seconds: 60,
      delivery_heartbeat_interval_ms: 10_000,
      delivery_readiness_timeout_seconds: 10,
      delivery_send_timeout_seconds: 30,
      delivery_finalization_timeout_seconds: 5,
      delivery_max_attempts: 5,
      delivery_retry_base_seconds: 5,
      delivery_retry_max_seconds: 300,
      delivery_retry_after_max_seconds: 3_600,
      delivery_deadline_seconds: 3_600,
      delivery_readiness_retry_base_seconds: 1,
      delivery_readiness_retry_max_seconds: 60,
    }
  }
}

impl SchedulerOperationalPolicy {
  #[must_use]
  pub fn legacy_compatible() -> Self {
    Self {
      minimum_schedule_cadence_seconds: 1,
      max_active_jobs: 1_000_000,
      max_active_jobs_per_owner: 1_000_000,
      max_summary_bytes: 64 * 1024,
      run_retry_max_seconds: 30,
      ..Self::default()
    }
  }

  /// Validates the complete scheduler policy as one coherent contract.
  ///
  /// # Errors
  /// Returns the first stable field and reason that violates the policy contract.
  pub fn validate(&self) -> Result<(), SchedulerPolicyValidationError> {
    validate_eq(
      "schema_version",
      self.schema_version,
      SCHEDULER_OPERATIONAL_POLICY_VERSION,
      "must be the supported scheduler policy schema version",
    )?;
    validate_range("recovery_batch_limit", self.recovery_batch_limit, 1, 1_024)?;
    validate_range(
      "materialization_batch_limit",
      self.materialization_batch_limit,
      1,
      1_024,
    )?;
    validate_range(
      "occurrence_search_limit",
      self.occurrence_search_limit,
      1,
      1_000_000,
    )?;
    validate_range("tick_interval_ms", self.tick_interval_ms, 10, 60_000)?;
    validate_range("error_backoff_ms", self.error_backoff_ms, 10, 300_000)?;
    validate_range(
      "minimum_schedule_cadence_seconds",
      self.minimum_schedule_cadence_seconds,
      1,
      86_400,
    )?;
    validate_range("max_active_jobs", self.max_active_jobs, 1, 1_000_000)?;
    validate_range(
      "max_active_jobs_per_owner",
      self.max_active_jobs_per_owner,
      1,
      self.max_active_jobs,
    )?;
    validate_range("max_prompt_bytes", self.max_prompt_bytes, 1, 256 * 1024)?;
    validate_range("max_result_bytes", self.max_result_bytes, 1, 256 * 1024)?;
    validate_range(
      "max_summary_bytes",
      self.max_summary_bytes,
      1,
      self.max_result_bytes,
    )?;
    validate_run_policy(self)?;
    validate_delivery_policy(self)
  }

  #[must_use]
  pub fn run_retry_delay_seconds(&self, run_id: &str, attempt: i64) -> u32 {
    bounded_exponential_delay(
      self.run_retry_base_seconds,
      self.run_retry_max_seconds,
      run_id,
      attempt,
    )
  }

  #[must_use]
  pub fn delivery_retry_delay_seconds(&self, delivery_id: &str, attempt: i64) -> u32 {
    bounded_exponential_delay(
      self.delivery_retry_base_seconds,
      self.delivery_retry_max_seconds,
      delivery_id,
      attempt,
    )
  }

  #[must_use]
  pub fn run_deadline_at(&self, scheduled_for: i64) -> Option<i64> {
    scheduled_for.checked_add(i64::from(self.run_deadline_seconds))
  }

  #[must_use]
  pub fn delivery_deadline_at(&self, payload_created_at: i64) -> Option<i64> {
    payload_created_at.checked_add(i64::from(self.delivery_deadline_seconds))
  }

  #[must_use]
  pub fn run_retry_at(
    &self,
    run_id: &str,
    attempt: i64,
    scheduled_for: i64,
    now: i64,
  ) -> Option<i64> {
    let next = now.checked_add(i64::from(self.run_retry_delay_seconds(run_id, attempt)))?;
    can_retry(
      attempt,
      self.run_max_attempts,
      next,
      self.run_deadline_at(scheduled_for)?,
    )
    .then_some(next)
  }

  #[must_use]
  pub fn delivery_retry_at(
    &self,
    delivery_id: &str,
    attempt: i64,
    payload_created_at: i64,
    now: i64,
    retry_after_seconds: Option<u64>,
  ) -> Option<i64> {
    let policy_delay = i64::from(self.delivery_retry_delay_seconds(delivery_id, attempt));
    let retry_after = retry_after_seconds.map_or(0, |seconds| {
      i64::try_from(seconds)
        .unwrap_or(i64::from(self.delivery_retry_after_max_seconds))
        .clamp(1, i64::from(self.delivery_retry_after_max_seconds))
    });
    let next = now.checked_add(policy_delay.max(retry_after))?;
    can_retry(
      attempt,
      self.delivery_max_attempts,
      next,
      self.delivery_deadline_at(payload_created_at)?,
    )
    .then_some(next)
  }

  #[must_use]
  pub fn delivery_can_retry_at(&self, attempt: i64, payload_created_at: i64, next_at: i64) -> bool {
    self
      .delivery_deadline_at(payload_created_at)
      .is_some_and(|deadline| can_retry(attempt, self.delivery_max_attempts, next_at, deadline))
  }
}

fn can_retry(attempt: i64, max_attempts: u16, next_at: i64, absolute_deadline: i64) -> bool {
  attempt < i64::from(max_attempts) && next_at < absolute_deadline
}

fn validate_run_policy(
  policy: &SchedulerOperationalPolicy,
) -> Result<(), SchedulerPolicyValidationError> {
  validate_range("run_lease_seconds", policy.run_lease_seconds, 5, 3_600)?;
  validate_heartbeat(
    "run_heartbeat_interval_ms",
    policy.run_heartbeat_interval_ms,
    policy.run_lease_seconds,
  )?;
  let run_lease_ms = u128::from(policy.run_lease_seconds) * 1_000;
  if u128::from(policy.tick_interval_ms) >= run_lease_ms {
    return Err(invalid(
      "tick_interval_ms",
      "must be shorter than run_lease_seconds",
    ));
  }
  validate_range("run_timeout_seconds", policy.run_timeout_seconds, 1, 21_600)?;
  validate_range(
    "run_prepare_grace_ms",
    policy.run_prepare_grace_ms,
    1,
    60_000,
  )?;
  validate_range(
    "run_cancellation_grace_ms",
    policy.run_cancellation_grace_ms,
    3,
    60_000,
  )?;
  validate_range(
    "run_finalization_grace_ms",
    policy.run_finalization_grace_ms,
    1,
    60_000,
  )?;
  validate_range(
    "run_retry_base_seconds",
    policy.run_retry_base_seconds,
    1,
    86_400,
  )?;
  validate_range(
    "run_retry_max_seconds",
    policy.run_retry_max_seconds,
    policy.run_retry_base_seconds,
    86_400,
  )?;
  validate_range(
    "run_deadline_seconds",
    policy.run_deadline_seconds,
    1,
    604_800,
  )?;
  validate_range("run_max_attempts", policy.run_max_attempts, 1, 20)?;
  let required_ms = u128::from(policy.run_timeout_seconds) * 1_000
    + u128::from(policy.run_prepare_grace_ms)
    + u128::from(policy.run_cancellation_grace_ms)
    + u128::from(policy.run_finalization_grace_ms);
  if required_ms > u128::from(policy.run_deadline_seconds) * 1_000 {
    return Err(invalid(
      "run_deadline_seconds",
      "must cover run timeout and all completion grace intervals",
    ));
  }
  Ok(())
}

fn validate_delivery_policy(
  policy: &SchedulerOperationalPolicy,
) -> Result<(), SchedulerPolicyValidationError> {
  validate_range(
    "delivery_tick_interval_ms",
    policy.delivery_tick_interval_ms,
    10,
    60_000,
  )?;
  validate_range(
    "delivery_batch_limit",
    policy.delivery_batch_limit,
    1,
    1_024,
  )?;
  validate_range(
    "delivery_lease_seconds",
    policy.delivery_lease_seconds,
    5,
    3_600,
  )?;
  validate_heartbeat(
    "delivery_heartbeat_interval_ms",
    policy.delivery_heartbeat_interval_ms,
    policy.delivery_lease_seconds,
  )?;
  if u128::from(policy.delivery_tick_interval_ms)
    >= u128::from(policy.delivery_lease_seconds) * 1_000
  {
    return Err(invalid(
      "delivery_tick_interval_ms",
      "must be shorter than delivery_lease_seconds",
    ));
  }
  validate_range(
    "delivery_readiness_timeout_seconds",
    policy.delivery_readiness_timeout_seconds,
    1,
    300,
  )?;
  validate_range(
    "delivery_send_timeout_seconds",
    policy.delivery_send_timeout_seconds,
    1,
    3_600,
  )?;
  validate_range(
    "delivery_finalization_timeout_seconds",
    policy.delivery_finalization_timeout_seconds,
    1,
    60,
  )?;
  validate_range("delivery_max_attempts", policy.delivery_max_attempts, 1, 20)?;
  validate_range(
    "delivery_retry_base_seconds",
    policy.delivery_retry_base_seconds,
    1,
    3_600,
  )?;
  validate_range(
    "delivery_retry_max_seconds",
    policy.delivery_retry_max_seconds,
    policy.delivery_retry_base_seconds,
    86_400,
  )?;
  validate_range(
    "delivery_retry_after_max_seconds",
    policy.delivery_retry_after_max_seconds,
    1,
    policy.delivery_deadline_seconds,
  )?;
  validate_range(
    "delivery_deadline_seconds",
    policy.delivery_deadline_seconds,
    1,
    604_800,
  )?;
  validate_range(
    "delivery_readiness_retry_base_seconds",
    policy.delivery_readiness_retry_base_seconds,
    1,
    3_600,
  )?;
  validate_range(
    "delivery_readiness_retry_max_seconds",
    policy.delivery_readiness_retry_max_seconds,
    policy.delivery_readiness_retry_base_seconds,
    3_600,
  )?;
  let required = u32::from(policy.delivery_send_timeout_seconds)
    .saturating_add(u32::from(policy.delivery_finalization_timeout_seconds));
  if required > policy.delivery_deadline_seconds {
    return Err(invalid(
      "delivery_deadline_seconds",
      "must cover delivery send and finalization timeouts",
    ));
  }
  Ok(())
}

fn validate_heartbeat(
  field: &'static str,
  heartbeat_ms: u64,
  lease_seconds: u16,
) -> Result<(), SchedulerPolicyValidationError> {
  if heartbeat_ms == 0 || u128::from(heartbeat_ms) * 3 >= u128::from(lease_seconds) * 1_000 {
    return Err(invalid(
      field,
      "must be positive and strictly shorter than one third of its lease",
    ));
  }
  Ok(())
}

fn bounded_exponential_delay(base: u32, cap: u32, identity: &str, attempt: i64) -> u32 {
  let exponent = u32::try_from(attempt.saturating_sub(1).clamp(0, 31)).unwrap_or(31);
  let exponential = base.checked_shl(exponent).unwrap_or(cap).min(cap);
  let jitter_bound = (exponential / 4).max(1);
  let jitter = stable_hash(identity) % u64::from(jitter_bound);
  exponential
    .saturating_add(u32::try_from(jitter).unwrap_or(u32::MAX))
    .min(cap)
}

fn stable_hash(value: &str) -> u64 {
  value.bytes().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
    (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3)
  })
}

fn validate_eq<T>(
  field: &'static str,
  value: T,
  expected: T,
  reason: &'static str,
) -> Result<(), SchedulerPolicyValidationError>
where
  T: Copy + PartialEq,
{
  if value != expected {
    return Err(invalid(field, reason));
  }
  Ok(())
}

fn validate_range<T>(
  field: &'static str,
  value: T,
  minimum: T,
  maximum: T,
) -> Result<(), SchedulerPolicyValidationError>
where
  T: Copy + PartialOrd,
{
  if value < minimum || value > maximum {
    return Err(invalid(field, "is outside the supported range"));
  }
  Ok(())
}

const fn invalid(field: &'static str, reason: &'static str) -> SchedulerPolicyValidationError {
  SchedulerPolicyValidationError { field, reason }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchedulerPolicyValidationError {
  pub field: &'static str,
  pub reason: &'static str,
}

impl fmt::Display for SchedulerPolicyValidationError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(formatter, "{} {}", self.field, self.reason)
  }
}

impl std::error::Error for SchedulerPolicyValidationError {}

#[cfg(test)]
mod tests {
  use super::SchedulerOperationalPolicy;

  #[test]
  fn scheduler_policy_requires_strict_heartbeat_and_coherent_deadlines() {
    let policy = SchedulerOperationalPolicy {
      run_heartbeat_interval_ms: 20_000,
      ..SchedulerOperationalPolicy::default()
    };
    assert_eq!(
      policy
        .validate()
        .expect_err("one third is not strict")
        .field,
      "run_heartbeat_interval_ms"
    );

    let defaults = SchedulerOperationalPolicy::default();
    let policy = SchedulerOperationalPolicy {
      run_deadline_seconds: defaults.run_timeout_seconds,
      ..defaults
    };
    assert_eq!(
      policy.validate().expect_err("graces exceed deadline").field,
      "run_deadline_seconds"
    );
  }

  #[test]
  fn scheduler_retry_backoff_is_capped_deterministic_and_attempt_based() {
    let policy = SchedulerOperationalPolicy {
      run_retry_base_seconds: 10,
      run_retry_max_seconds: 40,
      ..SchedulerOperationalPolicy::default()
    };
    let first = policy.run_retry_delay_seconds("run-a", 1);
    let second = policy.run_retry_delay_seconds("run-a", 2);
    assert!((10..=12).contains(&first));
    assert!((20..=24).contains(&second));
    assert_eq!(second, policy.run_retry_delay_seconds("run-a", 2));
    assert_eq!(policy.run_retry_delay_seconds("run-a", 20), 40);
  }

  #[test]
  fn scheduler_retry_authority_is_strict_at_attempt_and_deadline_boundaries() {
    let policy = SchedulerOperationalPolicy {
      run_retry_base_seconds: 10,
      run_retry_max_seconds: 10,
      run_deadline_seconds: 100,
      run_max_attempts: 2,
      delivery_retry_base_seconds: 10,
      delivery_retry_max_seconds: 10,
      delivery_deadline_seconds: 100,
      delivery_max_attempts: 2,
      ..SchedulerOperationalPolicy::default()
    };
    assert!(policy.run_retry_at("run", 1, 100, 190).is_none());
    assert!(policy.run_retry_at("run", 2, 100, 110).is_none());
    assert!(!policy.delivery_can_retry_at(1, 100, 200));
    assert!(!policy.delivery_can_retry_at(2, 100, 150));
  }
}
