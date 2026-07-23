//! Canonical identities shared by scheduled deployment configuration and remote execution.

use std::fmt;

pub const MAX_CRITICAL_ID_BYTES: usize = 128;
pub const MAX_CREDENTIAL_REVISION_BYTES: usize = 128;
pub const MAX_EVIDENCE_KEY_ID_BYTES: usize = 128;
pub const MAX_RUNNER_WORKLOAD_IDENTITY_BYTES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScheduledIdentityError {
  reason: &'static str,
}

impl ScheduledIdentityError {
  #[must_use]
  pub const fn reason(self) -> &'static str {
    self.reason
  }
}

impl fmt::Display for ScheduledIdentityError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str(self.reason)
  }
}

impl std::error::Error for ScheduledIdentityError {}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CriticalId(String);

impl CriticalId {
  /// Parses a bounded canonical identifier used in a signed scheduling binding.
  ///
  /// # Errors
  /// Returns an error when the value is empty, oversized, or noncanonical.
  pub fn parse(value: &str) -> Result<Self, ScheduledIdentityError> {
    if !is_bounded_ascii_token(value, MAX_CRITICAL_ID_BYTES, false, true) {
      return Err(ScheduledIdentityError {
        reason: "critical_id_invalid",
      });
    }
    Ok(Self(value.to_owned()))
  }

  #[must_use]
  pub fn as_str(&self) -> &str {
    &self.0
  }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CredentialRevision(String);

impl CredentialRevision {
  /// Parses a bounded lowercase credential revision.
  ///
  /// # Errors
  /// Returns an error when the value is empty, oversized, or noncanonical.
  pub fn parse(value: &str) -> Result<Self, ScheduledIdentityError> {
    if !is_bounded_ascii_token(value, MAX_CREDENTIAL_REVISION_BYTES, true, false) {
      return Err(ScheduledIdentityError {
        reason: "credential_revision_invalid",
      });
    }
    Ok(Self(value.to_owned()))
  }

  #[must_use]
  pub fn as_str(&self) -> &str {
    &self.0
  }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EvidenceKeyId(String);

impl EvidenceKeyId {
  /// Parses the exact canonical key identifier shared by config and evidence verification.
  ///
  /// # Errors
  /// Returns an error unless the identifier is 1..=128 lowercase ASCII alphanumeric/hyphen bytes.
  pub fn parse(value: &str) -> Result<Self, ScheduledIdentityError> {
    if value.is_empty()
      || value.len() > MAX_EVIDENCE_KEY_ID_BYTES
      || !value
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
      return Err(ScheduledIdentityError {
        reason: "evidence_key_id_invalid",
      });
    }
    Ok(Self(value.to_owned()))
  }

  #[must_use]
  pub fn as_str(&self) -> &str {
    &self.0
  }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RunnerWorkloadIdentity(String);

impl RunnerWorkloadIdentity {
  /// Parses the narrow canonical SPIFFE identity accepted by scheduled execution.
  ///
  /// # Errors
  /// Returns an error when the URI is oversized or violates the canonical SPIFFE contract.
  pub fn parse(value: &str) -> Result<Self, ScheduledIdentityError> {
    if value.is_empty()
      || value.len() > MAX_RUNNER_WORKLOAD_IDENTITY_BYTES
      || !value.is_ascii()
      || value != value.trim()
    {
      return Err(ScheduledIdentityError {
        reason: "runner_workload_identity_invalid",
      });
    }
    let remainder = value
      .strip_prefix("spiffe://")
      .ok_or(ScheduledIdentityError {
        reason: "runner_workload_identity_scheme_invalid",
      })?;
    let (trust_domain, path) = remainder.split_once('/').ok_or(ScheduledIdentityError {
      reason: "runner_workload_identity_path_missing",
    })?;
    if !valid_trust_domain(trust_domain) || !valid_spiffe_path(path) {
      return Err(ScheduledIdentityError {
        reason: "runner_workload_identity_noncanonical",
      });
    }
    Ok(Self(value.to_owned()))
  }

  #[must_use]
  pub fn as_str(&self) -> &str {
    &self.0
  }
}

fn is_bounded_ascii_token(
  value: &str,
  max_bytes: usize,
  lowercase_only: bool,
  allow_colon: bool,
) -> bool {
  if value.is_empty() || value.len() > max_bytes || !value.is_ascii() || value != value.trim() {
    return false;
  }
  let mut bytes = value.bytes();
  let Some(first) = bytes.next() else {
    return false;
  };
  if !first.is_ascii_alphanumeric() || (lowercase_only && first.is_ascii_uppercase()) {
    return false;
  }
  let Some(last) = value.bytes().next_back() else {
    return false;
  };
  if !last.is_ascii_alphanumeric() || (lowercase_only && last.is_ascii_uppercase()) {
    return false;
  }
  value.bytes().all(|byte| {
    byte.is_ascii_digit()
      || byte.is_ascii_lowercase()
      || (!lowercase_only && byte.is_ascii_uppercase())
      || matches!(byte, b'-' | b'_' | b'.')
      || (allow_colon && byte == b':')
  })
}

fn valid_trust_domain(value: &str) -> bool {
  if value.is_empty() || value.len() > 128 || !value.is_ascii() {
    return false;
  }
  value.split('.').all(|label| {
    !label.is_empty()
      && label.len() <= 63
      && label
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
      && label
        .bytes()
        .next()
        .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
      && label
        .bytes()
        .next_back()
        .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
  })
}

fn valid_spiffe_path(value: &str) -> bool {
  !value.is_empty()
    && !value.ends_with('/')
    && value.split('/').all(|segment| {
      !segment.is_empty()
        && segment.len() <= 64
        && !matches!(segment, "." | "..")
        && segment
          .bytes()
          .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    })
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn runner_workload_identity_accepts_only_the_narrow_canonical_spiffe_contract() {
    for valid in [
      "spiffe://codeoff/runner/production",
      "spiffe://example.org/ns/default/sa/runner-1",
      "spiffe://trust-domain/workload/Runner_1",
    ] {
      assert_eq!(
        RunnerWorkloadIdentity::parse(valid)
          .expect("valid SPIFFE identity")
          .as_str(),
        valid
      );
    }
    for invalid in [
      "",
      " spiffe://codeoff/runner/production",
      "https://codeoff/runner/production",
      "SPIFFE://codeoff/runner/production",
      "spiffe://Codeoff/runner/production",
      "spiffe://codeoff",
      "spiffe://codeoff/",
      "spiffe://codeoff//runner",
      "spiffe://codeoff/runner/../production",
      "spiffe://codeoff/runner%2fproduction",
      "spiffe://codeoff/runner?query=yes",
      "spiffe://codeoff/runner#fragment",
      "spiffe://user@codeoff/runner",
      "spiffe://codeoff:443/runner",
      "spiffe://-codeoff/runner",
      "spiffe://codeoff-/runner",
    ] {
      assert!(
        RunnerWorkloadIdentity::parse(invalid).is_err(),
        "invalid={invalid}"
      );
    }
  }

  #[test]
  fn credential_revision_and_critical_id_use_one_bounded_token_contract() {
    assert!(CredentialRevision::parse("github-readonly-2026-07").is_ok());
    assert!(CredentialRevision::parse("GitHub-2026").is_err());
    assert!(CredentialRevision::parse("revision/2").is_err());
    assert!(CredentialRevision::parse("revision-").is_err());
    assert!(CredentialRevision::parse(&"a".repeat(MAX_CREDENTIAL_REVISION_BYTES + 1)).is_err());

    assert!(CriticalId::parse("run:2026-07-23_01").is_ok());
    assert!(CriticalId::parse("run/1").is_err());
    assert!(CriticalId::parse(" run-1").is_err());
    assert!(CriticalId::parse("run-").is_err());
    assert!(CriticalId::parse(&"a".repeat(MAX_CRITICAL_ID_BYTES + 1)).is_err());
  }

  #[test]
  fn evidence_key_id_has_one_exact_bounded_canonical_contract() {
    let max = "a".repeat(MAX_EVIDENCE_KEY_ID_BYTES);
    for valid in ["a", "executor-key-1", max.as_str()] {
      assert!(EvidenceKeyId::parse(valid).is_ok(), "valid={valid}");
    }
    let oversized = "a".repeat(MAX_EVIDENCE_KEY_ID_BYTES + 1);
    for invalid in [
      "",
      "KEY-1",
      "key_1",
      "key/1",
      " key-1",
      "key-1 ",
      oversized.as_str(),
    ] {
      assert!(EvidenceKeyId::parse(invalid).is_err(), "invalid={invalid}");
    }
  }
}
