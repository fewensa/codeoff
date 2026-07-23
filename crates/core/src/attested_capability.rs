use std::collections::BTreeSet;
use std::fmt;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::scheduled_identity::CredentialRevision;

const EXPECTED_GITHUB_TOOLS: [&str; 5] = [
  "get_me",
  "issue_read",
  "list_issues",
  "search_issues",
  "search_orgs",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestedCapabilityProfile {
  pub codex_version: String,
  pub app_server_schema_sha256: String,
  pub codex_program_sha256: String,
  pub github_mcp_version: String,
  pub github_mcp_configured_artifact_sha256: String,
  pub github_mcp_configured_endpoint_identity: String,
  pub github_mcp_access_auth_mode: String,
  pub github_mcp_access_token_revision: String,
  pub github_mcp_health_checked_at_unix_seconds: u64,
  pub github_mcp_health_credential_revision: String,
  pub github_mcp_health_result_sha256: String,
  pub github_mcp_health_tool: String,
  pub github_tools: BTreeSet<String>,
  pub credential_reference: String,
  pub permission_policy_revision: String,
  pub config_revision: String,
  pub config_sha256: String,
  pub gateway_image_digest: String,
  pub runner_image_digest: String,
  pub runner_workload_identity: String,
  pub runner_client_cert_public_key_fingerprint: String,
  pub credential_revision: String,
  pub credential_isolation_revision: String,
  pub credential_deny_policy_revision: String,
  pub negative_test_revision: String,
  pub output_schema_revision: String,
  pub attested_at_unix_seconds: u64,
  pub profile_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestedCapabilityProfileError {
  InvalidJson,
  NonCanonicalJson,
  InvalidShape,
  InvalidField,
  DigestMismatch,
}

impl fmt::Display for AttestedCapabilityProfileError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(formatter, "{self:?}")
  }
}

impl std::error::Error for AttestedCapabilityProfileError {}

impl AttestedCapabilityProfile {
  #[must_use]
  pub fn canonical_json(&self) -> String {
    let tools: Vec<_> = self.github_tools.iter().collect();
    json!({
      "app_server_schema_sha256": self.app_server_schema_sha256,
      "attested_at_unix_seconds": self.attested_at_unix_seconds,
      "codex_program_sha256": self.codex_program_sha256,
      "codex_version": self.codex_version,
      "config_revision": self.config_revision,
      "config_sha256": self.config_sha256,
      "credential_deny_policy_revision": self.credential_deny_policy_revision,
      "credential_isolation_revision": self.credential_isolation_revision,
      "credential_reference": self.credential_reference,
      "credential_revision": self.credential_revision,
      "gateway_image_digest": self.gateway_image_digest,
      "github_mcp_configured_artifact_sha256": self.github_mcp_configured_artifact_sha256,
      "github_mcp_access_auth_mode": self.github_mcp_access_auth_mode,
      "github_mcp_access_token_revision": self.github_mcp_access_token_revision,
      "github_mcp_configured_endpoint_identity": self.github_mcp_configured_endpoint_identity,
      "github_mcp_health_checked_at_unix_seconds": self.github_mcp_health_checked_at_unix_seconds,
      "github_mcp_health_credential_revision": self.github_mcp_health_credential_revision,
      "github_mcp_health_result_sha256": self.github_mcp_health_result_sha256,
      "github_mcp_health_tool": self.github_mcp_health_tool,
      "github_mcp_version": self.github_mcp_version,
      "github_tools": tools,
      "negative_test_revision": self.negative_test_revision,
      "output_schema_revision": self.output_schema_revision,
      "permission_policy_revision": self.permission_policy_revision,
      "profile_sha256": self.profile_sha256,
      "runner_client_cert_public_key_fingerprint": self.runner_client_cert_public_key_fingerprint,
      "runner_image_digest": self.runner_image_digest,
      "runner_workload_identity": self.runner_workload_identity,
    })
    .to_string()
  }

  #[must_use]
  pub fn computed_profile_sha256(&self) -> String {
    let tools: Vec<_> = self.github_tools.iter().collect();
    let canonical = json!({
      "app_server_schema_sha256": self.app_server_schema_sha256,
      "codex_program_sha256": self.codex_program_sha256,
      "codex_version": self.codex_version,
      "config_revision": self.config_revision,
      "config_sha256": self.config_sha256,
      "credential_deny_policy_revision": self.credential_deny_policy_revision,
      "credential_isolation_revision": self.credential_isolation_revision,
      "credential_reference": self.credential_reference,
      "credential_revision": self.credential_revision,
      "gateway_image_digest": self.gateway_image_digest,
      "github_mcp_configured_artifact_sha256": self.github_mcp_configured_artifact_sha256,
      "github_mcp_access_auth_mode": self.github_mcp_access_auth_mode,
      "github_mcp_access_token_revision": self.github_mcp_access_token_revision,
      "github_mcp_configured_endpoint_identity": self.github_mcp_configured_endpoint_identity,
      "github_mcp_health_checked_at_unix_seconds": self.github_mcp_health_checked_at_unix_seconds,
      "github_mcp_health_credential_revision": self.github_mcp_health_credential_revision,
      "github_mcp_health_result_sha256": self.github_mcp_health_result_sha256,
      "github_mcp_health_tool": self.github_mcp_health_tool,
      "github_mcp_version": self.github_mcp_version,
      "github_tools": tools,
      "negative_test_revision": self.negative_test_revision,
      "output_schema_revision": self.output_schema_revision,
      "permission_policy_revision": self.permission_policy_revision,
      "runner_client_cert_public_key_fingerprint": self.runner_client_cert_public_key_fingerprint,
      "runner_image_digest": self.runner_image_digest,
      "runner_workload_identity": self.runner_workload_identity,
    });
    sha256_hex(canonical.to_string().as_bytes())
  }

  /// Validates runtime evidence, configured deployment claims, and their self-digest.
  ///
  /// # Errors
  /// Returns an error when a required field, digest, image identity, or tool inventory is invalid.
  pub fn validate(&self) -> Result<(), AttestedCapabilityProfileError> {
    if self.attested_at_unix_seconds == 0
      || self.github_mcp_health_checked_at_unix_seconds != self.attested_at_unix_seconds
      || self.github_mcp_access_auth_mode != "bearer-token-env-v1"
      || self.github_mcp_health_tool != "get_me"
      || self.github_mcp_health_credential_revision != self.credential_revision
      || CredentialRevision::parse(&self.github_mcp_access_token_revision).is_err()
      || self.profile_sha256 != self.computed_profile_sha256()
      || self.text_fields().iter().any(|value| value.is_empty())
      || self.github_tools
        != EXPECTED_GITHUB_TOOLS
          .into_iter()
          .map(str::to_owned)
          .collect()
    {
      return Err(AttestedCapabilityProfileError::InvalidField);
    }
    for digest in [
      &self.app_server_schema_sha256,
      &self.codex_program_sha256,
      &self.config_sha256,
      &self.github_mcp_configured_artifact_sha256,
      &self.github_mcp_health_result_sha256,
      &self.profile_sha256,
      &self.runner_client_cert_public_key_fingerprint,
    ] {
      if !is_lowercase_hex(digest, 64) {
        return Err(AttestedCapabilityProfileError::InvalidField);
      }
    }
    for digest in [&self.gateway_image_digest, &self.runner_image_digest] {
      if !digest
        .strip_prefix("sha256:")
        .is_some_and(|value| is_lowercase_hex(value, 64))
      {
        return Err(AttestedCapabilityProfileError::InvalidField);
      }
    }
    Ok(())
  }

  /// Parses one exact canonical capability profile.
  ///
  /// # Errors
  /// Returns an error for malformed, noncanonical, incomplete, or digest-mismatched profiles.
  pub fn parse_canonical_json(value: &str) -> Result<Self, AttestedCapabilityProfileError> {
    let parsed: Value =
      serde_json::from_str(value).map_err(|_| AttestedCapabilityProfileError::InvalidJson)?;
    if serde_json::to_string(&parsed).ok().as_deref() != Some(value) {
      return Err(AttestedCapabilityProfileError::NonCanonicalJson);
    }
    let object = parsed
      .as_object()
      .filter(|object| object.len() == 28)
      .ok_or(AttestedCapabilityProfileError::InvalidShape)?;
    let string = |field: &str| {
      object
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(AttestedCapabilityProfileError::InvalidField)
    };
    let tools = object
      .get("github_tools")
      .and_then(Value::as_array)
      .ok_or(AttestedCapabilityProfileError::InvalidField)?
      .iter()
      .map(|value| {
        value
          .as_str()
          .map(str::to_owned)
          .ok_or(AttestedCapabilityProfileError::InvalidField)
      })
      .collect::<Result<BTreeSet<_>, _>>()?;
    let profile = Self {
      app_server_schema_sha256: string("app_server_schema_sha256")?,
      attested_at_unix_seconds: object
        .get("attested_at_unix_seconds")
        .and_then(Value::as_u64)
        .ok_or(AttestedCapabilityProfileError::InvalidField)?,
      codex_program_sha256: string("codex_program_sha256")?,
      codex_version: string("codex_version")?,
      config_revision: string("config_revision")?,
      config_sha256: string("config_sha256")?,
      credential_deny_policy_revision: string("credential_deny_policy_revision")?,
      credential_isolation_revision: string("credential_isolation_revision")?,
      credential_reference: string("credential_reference")?,
      credential_revision: string("credential_revision")?,
      gateway_image_digest: string("gateway_image_digest")?,
      github_mcp_configured_artifact_sha256: string("github_mcp_configured_artifact_sha256")?,
      github_mcp_access_auth_mode: string("github_mcp_access_auth_mode")?,
      github_mcp_access_token_revision: string("github_mcp_access_token_revision")?,
      github_mcp_configured_endpoint_identity: string("github_mcp_configured_endpoint_identity")?,
      github_mcp_health_checked_at_unix_seconds: object
        .get("github_mcp_health_checked_at_unix_seconds")
        .and_then(Value::as_u64)
        .ok_or(AttestedCapabilityProfileError::InvalidField)?,
      github_mcp_health_credential_revision: string("github_mcp_health_credential_revision")?,
      github_mcp_health_result_sha256: string("github_mcp_health_result_sha256")?,
      github_mcp_health_tool: string("github_mcp_health_tool")?,
      github_mcp_version: string("github_mcp_version")?,
      github_tools: tools,
      negative_test_revision: string("negative_test_revision")?,
      output_schema_revision: string("output_schema_revision")?,
      permission_policy_revision: string("permission_policy_revision")?,
      profile_sha256: string("profile_sha256")?,
      runner_client_cert_public_key_fingerprint: string(
        "runner_client_cert_public_key_fingerprint",
      )?,
      runner_image_digest: string("runner_image_digest")?,
      runner_workload_identity: string("runner_workload_identity")?,
    };
    profile.validate()?;
    Ok(profile)
  }

  fn text_fields(&self) -> [&str; 19] {
    [
      &self.codex_version,
      &self.github_mcp_version,
      &self.github_mcp_configured_endpoint_identity,
      &self.github_mcp_access_auth_mode,
      &self.github_mcp_access_token_revision,
      &self.github_mcp_health_credential_revision,
      &self.github_mcp_health_tool,
      &self.credential_reference,
      &self.permission_policy_revision,
      &self.config_revision,
      &self.credential_revision,
      &self.credential_isolation_revision,
      &self.credential_deny_policy_revision,
      &self.negative_test_revision,
      &self.output_schema_revision,
      &self.runner_workload_identity,
      &self.gateway_image_digest,
      &self.runner_image_digest,
      &self.profile_sha256,
    ]
  }
}

fn is_lowercase_hex(value: &str, length: usize) -> bool {
  value.len() == length
    && value
      .bytes()
      .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sha256_hex(bytes: &[u8]) -> String {
  format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
  use super::*;

  fn profile() -> AttestedCapabilityProfile {
    let mut profile = AttestedCapabilityProfile {
      codex_version: "0.144.6".to_owned(),
      app_server_schema_sha256: "1".repeat(64),
      codex_program_sha256: "2".repeat(64),
      github_mcp_version: "1.6.0".to_owned(),
      github_mcp_configured_artifact_sha256: "3".repeat(64),
      github_mcp_configured_endpoint_identity: "configured-sidecar".to_owned(),
      github_mcp_access_auth_mode: "bearer-token-env-v1".to_owned(),
      github_mcp_access_token_revision: "mcp-channel-v1".to_owned(),
      github_mcp_health_checked_at_unix_seconds: 1,
      github_mcp_health_credential_revision: "credential-v1".to_owned(),
      github_mcp_health_result_sha256: "4".repeat(64),
      github_mcp_health_tool: "get_me".to_owned(),
      github_tools: EXPECTED_GITHUB_TOOLS.map(str::to_owned).into(),
      credential_reference: "configured-credential".to_owned(),
      permission_policy_revision: "policy-v1".to_owned(),
      config_revision: "config-v1".to_owned(),
      config_sha256: "5".repeat(64),
      gateway_image_digest: format!("sha256:{}", "6".repeat(64)),
      runner_image_digest: format!("sha256:{}", "7".repeat(64)),
      runner_workload_identity: "spiffe://codeoff/runner/production".to_owned(),
      runner_client_cert_public_key_fingerprint: "8".repeat(64),
      credential_revision: "credential-v1".to_owned(),
      credential_isolation_revision: "isolation-v1".to_owned(),
      credential_deny_policy_revision: "deny-v1".to_owned(),
      negative_test_revision: "negative-v1".to_owned(),
      output_schema_revision: "output-v1".to_owned(),
      attested_at_unix_seconds: 1,
      profile_sha256: String::new(),
    };
    profile.profile_sha256 = profile.computed_profile_sha256();
    profile
  }

  #[test]
  fn canonical_profile_rejects_legacy_mixed_unknown_and_duplicate_provenance_keys() {
    let canonical = profile().canonical_json();
    assert!(AttestedCapabilityProfile::parse_canonical_json(&canonical).is_ok());

    let mut legacy: Value = serde_json::from_str(&canonical).expect("profile JSON");
    let object = legacy.as_object_mut().expect("profile object");
    let artifact = object
      .remove("github_mcp_configured_artifact_sha256")
      .expect("configured artifact");
    let endpoint = object
      .remove("github_mcp_configured_endpoint_identity")
      .expect("configured endpoint");
    object.insert("github_mcp_artifact_sha256".to_owned(), artifact);
    object.insert("github_mcp_endpoint_identity".to_owned(), endpoint);
    assert!(AttestedCapabilityProfile::parse_canonical_json(&legacy.to_string()).is_err());

    let mut mixed: Value = serde_json::from_str(&canonical).expect("profile JSON");
    mixed
      .as_object_mut()
      .expect("profile object")
      .insert("github_mcp_endpoint_identity".to_owned(), json!("legacy"));
    assert!(matches!(
      AttestedCapabilityProfile::parse_canonical_json(&mixed.to_string()),
      Err(AttestedCapabilityProfileError::InvalidShape)
    ));

    let unknown = format!(
      "{},\"unknown_provenance\":true}}",
      canonical.trim_end_matches('}')
    );
    assert!(matches!(
      AttestedCapabilityProfile::parse_canonical_json(&unknown),
      Err(AttestedCapabilityProfileError::InvalidShape)
    ));
    let duplicate = format!(
      "{},\"github_mcp_configured_endpoint_identity\":\"duplicate\"}}",
      canonical.trim_end_matches('}')
    );
    assert!(matches!(
      AttestedCapabilityProfile::parse_canonical_json(&duplicate),
      Err(AttestedCapabilityProfileError::NonCanonicalJson)
    ));
  }

  #[test]
  fn configured_deployment_claims_are_signed_but_not_live_workload_proof() {
    let original = profile();
    let mut changed = original.clone();
    changed.github_mcp_configured_endpoint_identity = "different-configured-sidecar".to_owned();
    assert_ne!(
      changed.computed_profile_sha256(),
      original.computed_profile_sha256()
    );
    assert!(!original.canonical_json().contains("observed_endpoint"));
    assert!(!original.canonical_json().contains("live_provenance"));
  }
}
