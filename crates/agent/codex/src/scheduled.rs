//! Fail-closed Codex execution boundary for scheduled tasks.

use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::Arc;
#[cfg(test)]
use std::sync::atomic::AtomicU64;
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(unix)]
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
#[cfg(unix)]
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use codeoff_agent_contract::{
  AgentTask, InvocationPrincipal, InvocationSource, SessionMode, ToolPolicy,
};
use codeoff_config::{CredentialRevision, RunnerWorkloadIdentity, ScheduledCodexConfig};
use codeoff_core::AttestedCapabilityProfile;
use ring::signature::{ED25519, UnparsedPublicKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[cfg(unix)]
use nix::errno::Errno;
#[cfg(unix)]
use nix::fcntl::{FcntlArg, FdFlag, fcntl};
#[cfg(unix)]
use nix::sys::signal::{Signal, killpg};
#[cfg(unix)]
use nix::unistd::Pid;

#[cfg(unix)]
use crate::scheduled_artifacts::{
  VerifiedScheduledArtifacts, read_trusted_owner_scheduled_authority_material,
  read_verified_scheduled_authority_material, verify_scheduled_artifacts,
  verify_scheduled_artifacts_as_trusted_owner,
};
#[cfg(all(unix, test))]
use crate::scheduled_artifacts::{test_artifacts, verify_scheduled_artifacts_for_test};
use crate::{JsonlTransport, send_notification, send_request};

pub const CODEX_CLI_VERSION: &str = "0.144.6";
pub const CODEX_APP_SERVER_SCHEMA_SHA256: &str =
  "2bc9867446f03c818018ee33c249f4d1da22c3e19a68d606b0e435faba04f1d1";
pub const GITHUB_MCP_SERVER_VERSION: &str = "1.6.0";
pub const GITHUB_MCP_ARTIFACT_SHA256_X86_64: &str =
  "955fff9cf50ae99ee021871a4782c36360252d82fd03c8307fd7394c44ba3886";
pub const GITHUB_MCP_ARTIFACT_SHA256_ARM64: &str =
  "5d47f9e36850769db8a46c97a7ad1e7a1bd51502c57765a81e697f5740455227";

const GITHUB_MCP_NAME: &str = "github";
const GITHUB_MCP_SERVER_INFO_NAME: &str = "github-mcp-server";
const GITHUB_MCP_HEALTH_TOOL: &str = "get_me";
pub const GITHUB_MCP_ACCESS_TOKEN_ENV: &str = "CODEOFF_SCHEDULED_GITHUB_MCP_BEARER_TOKEN";
const GITHUB_MCP_ACCESS_AUTH_MODE: &str = "bearer-token-env-v1";
const OUTPUT_SCHEMA_REVISION: &str = "scheduled-result-v1";
const OUTPUT_SCHEMA_VERSION: u64 = 1;
const CREDENTIAL_DENY_POLICY_REVISION: &str = "scheduled-credential-isolation-v1";
const NEGATIVE_TEST_REVISION: &str = "scheduled-secret-falsifier-v1";
const MAX_FAILURE_BYTES: usize = 2 * 1024;
const MAX_FINAL_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_FINAL_SUMMARY_BYTES: usize = 32 * 1024;
const MAX_FINAL_ITEM_COUNT: usize = 16;
const MAX_MCP_HEALTH_RESULT_BYTES: usize = 64 * 1024;
const MAX_MCP_HEALTH_RESULT_DEPTH: usize = 16;
const MIN_MCP_ACCESS_TOKEN_BYTES: usize = 32;
const MAX_MCP_ACCESS_TOKEN_BYTES: usize = 4 * 1024;
const MAX_ITEM_ID_BYTES: usize = 256;
const MAX_INSTRUCTION_BYTES: usize = 64 * 1024;
#[cfg_attr(
  not(test),
  allow(dead_code, reason = "reserved for the issue 09 deployment verifier")
)]
const MAX_JSONL_MESSAGE_BYTES: usize = 1024 * 1024;
const MAX_OUTPUT_SCHEMA_BYTES: usize = 4 * 1024;
const MAX_OUTPUT_SCHEMA_DEPTH: usize = 6;
const MAX_RUN_TIMEOUT: Duration = Duration::from_hours(6);
const MAX_INTERRUPT_GRACE: Duration = Duration::from_secs(30);
const MAX_TERMINATE_GRACE: Duration = Duration::from_secs(30);
const MAX_KILL_GRACE: Duration = Duration::from_secs(30);
const CANCELLATION_POLL_INTERVAL: Duration = Duration::from_millis(100);
const ISOLATION_ATTESTATION_SCHEMA_VERSION: u64 = 2;
const ISOLATION_ATTESTATION_MAX_ISSUED_AGE_SECONDS: u64 = 300;
const ISOLATION_ATTESTATION_MAX_VALIDITY_SECONDS: u64 = 600;
const ISOLATION_ATTESTATION_FUTURE_SKEW_SECONDS: u64 = 30;
const MAX_ISOLATION_TRUST_KEYS: usize = 16;
#[cfg(test)]
const TEST_PERMIT_TTL: Duration = Duration::from_secs(30);
#[cfg_attr(
  not(test),
  allow(dead_code, reason = "reserved for the issue 09 deployment verifier")
)]
const CHILD_PATH: &str = "/usr/local/bin:/usr/bin:/bin";
#[cfg_attr(
  not(test),
  allow(dead_code, reason = "reserved for the issue 09 deployment verifier")
)]
const CHILD_LOCALE: &str = "C.UTF-8";
const EXPECTED_GITHUB_TOOLS: [&str; 5] = [
  "get_me",
  "issue_read",
  "list_issues",
  "search_issues",
  "search_orgs",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestedCapabilityProfile {
  pub codex_program: PathBuf,
  pub codex_program_sha256: String,
  pub codex_home: PathBuf,
  pub cwd: PathBuf,
  pub github_mcp_url: String,
  pub github_mcp_artifact_sha256: String,
  pub github_mcp_endpoint_identity: String,
  pub github_mcp_access_auth_mode: String,
  pub github_mcp_access_token_revision: String,
  pub credential_reference: String,
  pub permission_policy_revision: String,
  pub config_revision: String,
  pub config_sha256: String,
  pub gateway_image_digest: String,
  pub runner_image_digest: String,
  pub runner_workload_identity: String,
  pub runner_client_cert_public_key_fingerprint: String,
  pub credential_revision: String,
}

impl RequestedCapabilityProfile {
  #[must_use]
  pub fn github_tool_inventory() -> BTreeSet<String> {
    EXPECTED_GITHUB_TOOLS.map(str::to_owned).into()
  }

  #[must_use]
  pub fn dedicated_config(&self) -> String {
    let tools = EXPECTED_GITHUB_TOOLS
      .iter()
      .map(|tool| format!("\"{tool}\""))
      .collect::<Vec<_>>()
      .join(", ");
    format!(
      "web_search = \"disabled\"\n\n[shell_environment_policy]\ninherit = \"none\"\nignore_default_excludes = false\nexclude = [{token_env:?}]\ninclude_only = [\"PATH\", \"LANG\", \"LC_ALL\"]\nset = {{ PATH = {child_path:?}, LANG = {child_locale:?}, LC_ALL = {child_locale:?} }}\n\n[mcp_servers.{GITHUB_MCP_NAME}]\nurl = {url:?}\nenabled = true\nrequired = true\nbearer_token_env_var = {token_env:?}\nenabled_tools = [{tools}]\n",
      url = self.github_mcp_url,
      token_env = GITHUB_MCP_ACCESS_TOKEN_ENV,
      child_path = CHILD_PATH,
      child_locale = CHILD_LOCALE,
    )
  }

  fn validate(&self) -> Result<(), ScheduledFailure> {
    if !self.codex_program.is_absolute() {
      return Err(preflight("codex_program_not_absolute"));
    }
    if !self.codex_home.is_absolute() || !self.cwd.is_absolute() {
      return Err(preflight("scheduled_paths_not_absolute"));
    }
    if self.codex_home == self.cwd || self.cwd.starts_with(&self.codex_home) {
      return Err(preflight("scheduled_cwd_overlaps_codex_home"));
    }
    if self.github_mcp_url.contains('@') || !is_loopback_http_url(&self.github_mcp_url) {
      return Err(preflight(
        "github_mcp_endpoint_must_be_credential_free_loopback",
      ));
    }
    require_non_empty("codex_program_sha256", &self.codex_program_sha256)?;
    require_sha256("codex_program_sha256", &self.codex_program_sha256)?;
    require_non_empty(
      "github_mcp_endpoint_identity",
      &self.github_mcp_endpoint_identity,
    )?;
    if self.github_mcp_access_auth_mode != GITHUB_MCP_ACCESS_AUTH_MODE {
      return Err(preflight("github_mcp_access_auth_mode_invalid"));
    }
    CredentialRevision::parse(&self.github_mcp_access_token_revision)
      .map_err(|_| preflight("github_mcp_access_token_revision_invalid"))?;
    require_non_empty("credential_reference", &self.credential_reference)?;
    require_non_empty(
      "permission_policy_revision",
      &self.permission_policy_revision,
    )?;
    require_non_empty("config_revision", &self.config_revision)?;
    require_sha256(
      "github_mcp_artifact_sha256",
      &self.github_mcp_artifact_sha256,
    )?;
    if !cfg!(test) && !is_pinned_github_mcp_artifact(&self.github_mcp_artifact_sha256) {
      return Err(preflight("github_mcp_artifact_digest_not_pinned_v1_6_0"));
    }
    let actual_config_hash = sha256_hex(self.dedicated_config().as_bytes());
    if self.config_sha256 != actual_config_hash {
      return Err(preflight("scheduled_config_digest_mismatch"));
    }
    for digest in [&self.gateway_image_digest, &self.runner_image_digest] {
      if !is_oci_sha256_digest(digest) {
        return Err(preflight("scheduled_deployment_image_digest_invalid"));
      }
    }
    RunnerWorkloadIdentity::parse(&self.runner_workload_identity)
      .map_err(|_| preflight("runner_workload_identity_invalid"))?;
    require_sha256(
      "runner_client_cert_public_key_fingerprint",
      &self.runner_client_cert_public_key_fingerprint,
    )?;
    CredentialRevision::parse(&self.credential_revision)
      .map_err(|_| preflight("credential_revision_invalid"))?;
    Ok(())
  }
}

fn is_pinned_github_mcp_artifact(digest: &str) -> bool {
  matches!(
    digest,
    GITHUB_MCP_ARTIFACT_SHA256_X86_64 | GITHUB_MCP_ARTIFACT_SHA256_ARM64
  )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduledRuntimeEvidence {
  pub codex_version: String,
  pub app_server_schema_sha256: String,
  pub codex_program_sha256: String,
  pub config_sha256: String,
  pub runner_image_digest: String,
}

#[derive(Debug, Clone)]
pub struct ScheduledCodexRequest {
  pub task: AgentTask,
  pub identity: ScheduledExecutionIdentity,
  pub profile: RequestedCapabilityProfile,
  pub cancellation: Arc<AtomicBool>,
  pub timeout: Duration,
  pub interrupt_grace: Duration,
  pub terminate_grace: Duration,
  pub kill_grace: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduledExecutionIdentity {
  pub run_id: String,
  pub job_id: String,
  pub attempt: i64,
  pub fence: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduledDeploymentAuthority {
  pub schema_version: u32,
  pub deployment_epoch: i64,
  pub attestation_id: String,
  pub attestation_digest: String,
  pub trust_key_id: String,
  pub profile_digest: String,
  pub github_mcp_access_auth_mode: String,
  pub github_mcp_access_token_revision: String,
  pub isolation_revision: String,
  pub issued_at_unix_seconds: u64,
  pub expires_at_unix_seconds: u64,
}

#[derive(Debug)]
pub struct ScheduledIsolationPermit {
  identity: ScheduledExecutionIdentity,
  deployment_epoch: i64,
  attestation_id: String,
  profile_digest: String,
  nonce: String,
  permit_id: String,
  isolation_revision: String,
  expires_at_unix_seconds: u64,
}

pub struct RemoteIsolationPermitEnvelope {
  canonical_json: String,
}

impl std::fmt::Debug for RemoteIsolationPermitEnvelope {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter
      .debug_struct("RemoteIsolationPermitEnvelope")
      .field("canonical_json", &"[REDACTED]")
      .finish()
  }
}

impl RemoteIsolationPermitEnvelope {
  #[must_use]
  pub fn as_json(&self) -> &str {
    &self.canonical_json
  }

  /// Parses and imports one exact session-bound permit envelope.
  ///
  /// # Errors
  /// Returns a fail-closed error for malformed, expired, replay-bound, or identity-mismatched
  /// envelopes.
  pub fn import(
    encoded: &str,
    authority: &ScheduledDeploymentAuthority,
    expected_identity: &ScheduledExecutionIdentity,
    expected_authority_digest: &str,
    expected_credential_revision: &str,
    expected_session_nonce: &str,
  ) -> Result<ScheduledIsolationPermit, ScheduledFailure> {
    let value: Value = serde_json::from_str(encoded)
      .map_err(|_| preflight("scheduled_remote_permit_envelope_invalid"))?;
    let object = value
      .as_object()
      .filter(|object| {
        has_exact_fields(
          object,
          &[
            "attempt",
            "attestation_id",
            "authority_digest",
            "credential_revision",
            "deployment_epoch",
            "expires_at_unix_seconds",
            "fence",
            "job_id",
            "nonce",
            "permit_id",
            "profile_digest",
            "run_id",
            "schema_version",
            "session_nonce",
          ],
        )
      })
      .ok_or_else(|| preflight("scheduled_remote_permit_envelope_invalid"))?;
    let string = |field: &str| {
      object
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| preflight("scheduled_remote_permit_envelope_invalid"))
    };
    let positive_i64 = |field: &str| {
      object
        .get(field)
        .and_then(Value::as_i64)
        .filter(|value| *value > 0)
        .ok_or_else(|| preflight("scheduled_remote_permit_envelope_invalid"))
    };
    let expires_at = object
      .get("expires_at_unix_seconds")
      .and_then(Value::as_u64)
      .filter(|value| *value > now_unix_seconds())
      .ok_or_else(|| preflight("scheduled_remote_permit_envelope_expired"))?;
    let schema_version = object
      .get("schema_version")
      .and_then(Value::as_u64)
      .filter(|value| *value == 1)
      .ok_or_else(|| preflight("scheduled_remote_permit_envelope_invalid"))?;
    debug_assert_eq!(schema_version, 1);
    let nonce = string("nonce")?;
    let permit_id = string("permit_id")?;
    let profile_digest = string("profile_digest")?;
    let session_nonce = string("session_nonce")?;
    let authority_digest = string("authority_digest")?;
    let credential_revision = string("credential_revision")?;
    if !is_lowercase_hex(nonce, 64)
      || !is_lowercase_hex(permit_id, 64)
      || !is_lowercase_hex(profile_digest, 64)
      || !is_lowercase_hex(session_nonce, 64)
      || !is_lowercase_hex(authority_digest, 64)
      || CredentialRevision::parse(credential_revision).is_err()
      || string("attestation_id")? != authority.attestation_id
      || profile_digest != authority.profile_digest
      || authority_digest != expected_authority_digest
      || credential_revision != expected_credential_revision
      || session_nonce != expected_session_nonce
      || positive_i64("deployment_epoch")? != authority.deployment_epoch
      || string("run_id")? != expected_identity.run_id
      || string("job_id")? != expected_identity.job_id
      || positive_i64("attempt")? != expected_identity.attempt
      || positive_i64("fence")? != expected_identity.fence
      || expires_at != authority.expires_at_unix_seconds
      || serde_json::to_string(&value).ok().as_deref() != Some(encoded)
    {
      return Err(preflight(
        "scheduled_remote_permit_envelope_binding_mismatch",
      ));
    }
    ScheduledIsolationPermit::from_consumed(
      authority,
      expected_identity.clone(),
      profile_digest,
      nonce.to_owned(),
      permit_id.to_owned(),
    )
  }
}

impl ScheduledIsolationPermit {
  /// Reconstructs an opaque permit only after its exact binding was durably consumed.
  ///
  /// # Errors
  /// Returns an error when the persisted binding is malformed or does not match the current
  /// signed deployment authority.
  pub fn from_consumed(
    authority: &ScheduledDeploymentAuthority,
    identity: ScheduledExecutionIdentity,
    profile_digest: &str,
    nonce: String,
    permit_id: String,
  ) -> Result<Self, ScheduledFailure> {
    if authority.schema_version != 1
      || authority.deployment_epoch <= 0
      || authority.expires_at_unix_seconds <= now_unix_seconds()
      || authority.profile_digest != profile_digest
      || identity.run_id.is_empty()
      || identity.job_id.is_empty()
      || identity.attempt <= 0
      || identity.fence <= 0
      || !is_lowercase_hex(&nonce, 64)
      || !is_lowercase_hex(&permit_id, 64)
    {
      return Err(preflight("scheduled_consumed_permit_binding_invalid"));
    }
    Ok(Self {
      identity,
      deployment_epoch: authority.deployment_epoch,
      attestation_id: authority.attestation_id.clone(),
      profile_digest: profile_digest.to_owned(),
      nonce,
      permit_id,
      isolation_revision: authority.isolation_revision.clone(),
      expires_at_unix_seconds: authority.expires_at_unix_seconds,
    })
  }

  /// Consumes a durably bound permit into a canonical envelope for one authenticated runner
  /// session.
  ///
  /// # Errors
  /// Returns a fail-closed error when the supplied authority, credential revision, or session
  /// binding is malformed or does not match the permit.
  pub fn into_remote_envelope(
    self,
    authority_digest: &str,
    credential_revision: &str,
    session_nonce: &str,
  ) -> Result<RemoteIsolationPermitEnvelope, ScheduledFailure> {
    if !is_lowercase_hex(authority_digest, 64)
      || !is_lowercase_hex(session_nonce, 64)
      || CredentialRevision::parse(credential_revision).is_err()
      || self.expires_at_unix_seconds <= now_unix_seconds()
    {
      return Err(preflight("scheduled_remote_permit_export_invalid"));
    }
    let canonical_json = json!({
      "attempt": self.identity.attempt,
      "attestation_id": self.attestation_id,
      "authority_digest": authority_digest,
      "credential_revision": credential_revision,
      "deployment_epoch": self.deployment_epoch,
      "expires_at_unix_seconds": self.expires_at_unix_seconds,
      "fence": self.identity.fence,
      "job_id": self.identity.job_id,
      "nonce": self.nonce,
      "permit_id": self.permit_id,
      "profile_digest": self.profile_digest,
      "run_id": self.identity.run_id,
      "schema_version": 1,
      "session_nonce": session_nonce,
    })
    .to_string();
    Ok(RemoteIsolationPermitEnvelope { canonical_json })
  }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduledFinalOutput {
  pub schema_version: u64,
  pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ScheduledUsage {
  pub input: Option<u64>,
  pub cached_input: Option<u64>,
  pub output: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScheduledExecutionResult {
  Completed {
    output: ScheduledFinalOutput,
    thread_id: String,
    turn_id: String,
    usage: ScheduledUsage,
    attested_profile: Box<AttestedCapabilityProfile>,
  },
  Interrupted {
    thread_id: Option<String>,
    turn_id: Option<String>,
  },
  Failed(ScheduledFailure),
  TransportLost(ScheduledFailure),
  PreflightRejected(ScheduledFailure),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScheduledFailureKind {
  InvalidRequest,
  ProtocolIncompatible,
  CapabilityMismatch,
  CredentialIsolationUnproven,
  OutputSchemaViolation,
  TurnFailed,
  TimedOut,
  Interrupted,
  Transport,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduledFailure {
  pub kind: ScheduledFailureKind,
  pub message: String,
}

impl ScheduledFailure {
  fn new(kind: ScheduledFailureKind, message: impl AsRef<str>) -> Self {
    Self {
      kind,
      message: bounded(message.as_ref(), MAX_FAILURE_BYTES),
    }
  }
}

#[derive(Debug, Clone, PartialEq)]
pub enum TimedRead {
  Message(Value),
  TimedOut,
  Eof,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessExit {
  Exited,
  TimedOut,
}

pub trait ScheduledJsonlTransport: JsonlTransport {
  fn runtime_evidence(&self) -> &ScheduledRuntimeEvidence;

  /// Reads one message without waiting past `deadline`.
  ///
  /// # Errors
  ///
  /// Returns an error when the reader cannot decode or receive a transport message.
  fn read_json_until(&mut self, deadline: Instant) -> Result<TimedRead, String>;

  /// Closes the owned App Server stdin.
  ///
  /// # Errors
  ///
  /// Returns an error when the transport cannot close its input stream.
  fn close_stdin(&mut self) -> Result<(), String>;

  /// Sends a graceful termination signal to the owned process group.
  ///
  /// # Errors
  ///
  /// Returns an error when the process group cannot be signaled.
  fn terminate_process_group(&mut self) -> Result<(), String>;

  /// Sends an unconditional kill signal to the owned process group.
  ///
  /// # Errors
  ///
  /// Returns an error when the process group cannot be signaled.
  fn kill_process_group(&mut self) -> Result<(), String>;

  /// Reaps the process leader and waits for the entire owned process group to disappear without
  /// waiting past `deadline`.
  ///
  /// # Errors
  ///
  /// Returns an error when child status cannot be inspected or reaped.
  fn reap_until(&mut self, deadline: Instant) -> Result<ProcessExit, String>;
}

#[cfg(unix)]
#[cfg_attr(
  not(test),
  allow(dead_code, reason = "reserved for the issue 09 deployment verifier")
)]
enum ReaderEvent {
  Message(Value),
  Error(String),
  Eof,
}

/// Direct, process-group-owned stdio transport for scheduled Codex App Server runs.
///
/// This crate-private transport independently re-hashes the executable and dedicated config before
/// spawning. It cannot be used as a public bypass around the disabled production executor.
#[cfg(unix)]
#[cfg_attr(
  not(test),
  allow(dead_code, reason = "reserved for the issue 09 deployment verifier")
)]
pub(crate) struct StdioScheduledJsonlTransport {
  child: Child,
  stdin: Option<ChildStdin>,
  reader: Option<JoinHandle<()>>,
  receiver: Receiver<ReaderEvent>,
  process_group: Pid,
  runtime_evidence: ScheduledRuntimeEvidence,
}

#[cfg(unix)]
#[cfg_attr(
  not(test),
  allow(dead_code, reason = "reserved for the issue 09 deployment verifier")
)]
impl StdioScheduledJsonlTransport {
  /// Starts the pinned Codex App Server directly, with a clean allowlisted environment and its own
  /// process group.
  ///
  /// # Errors
  ///
  /// Returns an error before spawn when executable/config digests drift, an environment key looks
  /// secret-bearing, or the process and stdio cannot be established.
  pub(crate) fn spawn(
    profile: &RequestedCapabilityProfile,
    runtime_evidence: ScheduledRuntimeEvidence,
    artifacts: &Arc<VerifiedScheduledArtifacts>,
    child_identity: Option<(u32, u32)>,
    github_mcp_access_token: &str,
  ) -> Result<Self, String> {
    profile.validate().map_err(|failure| failure.message)?;
    if profile.codex_program_sha256 != runtime_evidence.codex_program_sha256 {
      return Err("codex_program_digest_mismatch_before_spawn".to_owned());
    }
    if profile.config_sha256 != runtime_evidence.config_sha256 {
      return Err("scheduled_config_digest_mismatch_before_spawn".to_owned());
    }
    let mut verified = verified_command(
      artifacts,
      &["codex", "app-server", "--listen", "stdio://"],
      true,
      child_identity,
    )?;
    verified
      .command
      .env(GITHUB_MCP_ACCESS_TOKEN_ENV, github_mcp_access_token)
      .stdin(Stdio::piped())
      .stdout(Stdio::piped())
      .stderr(Stdio::null())
      .process_group(0);
    let mut child = verified
      .command
      .spawn()
      .map_err(|error| format!("start scheduled codex app server: {error}"))?;
    let stdin = child
      .stdin
      .take()
      .ok_or_else(|| "scheduled codex app server stdin unavailable".to_owned())?;
    let stdout = child
      .stdout
      .take()
      .ok_or_else(|| "scheduled codex app server stdout unavailable".to_owned())?;
    let child_pid = i32::try_from(child.id())
      .map_err(|_| "scheduled codex app server pid overflow".to_owned())?;
    let process_group = Pid::from_raw(child_pid);
    let (sender, receiver) = mpsc::channel();
    let reader = thread::Builder::new()
      .name("scheduled-codex-jsonl".to_owned())
      .spawn(move || {
        use std::io::{BufRead, BufReader, Read as _};
        let mut stdout = BufReader::new(stdout);
        loop {
          let mut line = Vec::new();
          match (&mut stdout)
            .take(u64::try_from(MAX_JSONL_MESSAGE_BYTES + 1).unwrap_or(u64::MAX))
            .read_until(b'\n', &mut line)
          {
            Ok(0) => {
              let _ = sender.send(ReaderEvent::Eof);
              return;
            }
            Ok(_) if line.len() > MAX_JSONL_MESSAGE_BYTES => {
              let _ = sender.send(ReaderEvent::Error(
                "scheduled_codex_jsonl_message_too_large".to_owned(),
              ));
              return;
            }
            Ok(_) => match serde_json::from_slice(&line) {
              Ok(message) => {
                if sender.send(ReaderEvent::Message(message)).is_err() {
                  return;
                }
              }
              Err(error) => {
                let _ = sender.send(ReaderEvent::Error(format!(
                  "decode scheduled codex app server response: {error}"
                )));
                return;
              }
            },
            Err(error) => {
              let _ = sender.send(ReaderEvent::Error(format!(
                "read scheduled codex app server response: {error}"
              )));
              return;
            }
          }
        }
      })
      .map_err(|error| format!("start scheduled codex reader: {error}"))?;
    Ok(Self {
      child,
      stdin: Some(stdin),
      reader: Some(reader),
      receiver,
      process_group,
      runtime_evidence,
    })
  }

  fn signal_process_group(&self, signal: Signal) -> Result<(), String> {
    match killpg(self.process_group, signal) {
      Ok(()) | Err(Errno::ESRCH) => Ok(()),
      Err(error) => Err(format!(
        "signal scheduled codex process group with {signal:?}: {error}"
      )),
    }
  }

  fn join_finished_reader(&mut self) {
    if self.reader.as_ref().is_some_and(JoinHandle::is_finished)
      && let Some(reader) = self.reader.take()
    {
      let _ = reader.join();
    }
  }

  fn process_group_is_gone(&self) -> Result<bool, String> {
    match killpg(self.process_group, None) {
      Err(Errno::ESRCH) => Ok(true),
      Ok(()) => Ok(false),
      Err(error) => Err(format!(
        "inspect scheduled codex process group liveness: {error}"
      )),
    }
  }

  fn wait_process_group_until(&mut self, deadline: Instant) -> Result<ProcessExit, String> {
    loop {
      self
        .child
        .try_wait()
        .map_err(|error| format!("reap scheduled codex app server: {error}"))?;
      self.join_finished_reader();
      if self.process_group_is_gone()? {
        return Ok(ProcessExit::Exited);
      }
      if Instant::now() >= deadline {
        return Ok(ProcessExit::TimedOut);
      }
      thread::sleep(Duration::from_millis(5));
    }
  }
}

#[cfg(unix)]
impl JsonlTransport for StdioScheduledJsonlTransport {
  fn write_json(&mut self, value: Value) -> Result<(), String> {
    let stdin = self
      .stdin
      .as_mut()
      .ok_or_else(|| "scheduled codex app server stdin closed".to_owned())?;
    let mut line = serde_json::to_vec(&value)
      .map_err(|error| format!("encode scheduled codex app server request: {error}"))?;
    if line.len() > MAX_JSONL_MESSAGE_BYTES {
      return Err("scheduled_codex_jsonl_request_too_large".to_owned());
    }
    line.push(b'\n');
    stdin
      .write_all(&line)
      .map_err(|error| format!("write scheduled codex app server request: {error}"))?;
    stdin
      .flush()
      .map_err(|error| format!("flush scheduled codex app server request: {error}"))
  }

  fn read_json(&mut self) -> Result<Value, String> {
    match self.receiver.recv() {
      Ok(ReaderEvent::Message(message)) => Ok(message),
      Ok(ReaderEvent::Error(error)) => Err(error),
      Ok(ReaderEvent::Eof) | Err(_) => Err("scheduled codex app server closed stdout".to_owned()),
    }
  }
}

#[cfg(unix)]
impl ScheduledJsonlTransport for StdioScheduledJsonlTransport {
  fn runtime_evidence(&self) -> &ScheduledRuntimeEvidence {
    &self.runtime_evidence
  }

  fn read_json_until(&mut self, deadline: Instant) -> Result<TimedRead, String> {
    let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
      return Ok(TimedRead::TimedOut);
    };
    match self.receiver.recv_timeout(remaining) {
      Ok(ReaderEvent::Message(message)) => Ok(TimedRead::Message(message)),
      Ok(ReaderEvent::Error(error)) => Err(error),
      Ok(ReaderEvent::Eof) | Err(RecvTimeoutError::Disconnected) => Ok(TimedRead::Eof),
      Err(RecvTimeoutError::Timeout) => Ok(TimedRead::TimedOut),
    }
  }

  fn close_stdin(&mut self) -> Result<(), String> {
    self.stdin.take();
    Ok(())
  }

  fn terminate_process_group(&mut self) -> Result<(), String> {
    self.signal_process_group(Signal::SIGTERM)
  }

  fn kill_process_group(&mut self) -> Result<(), String> {
    self.signal_process_group(Signal::SIGKILL)
  }

  fn reap_until(&mut self, deadline: Instant) -> Result<ProcessExit, String> {
    self.wait_process_group_until(deadline)
  }
}

#[cfg(unix)]
impl Drop for StdioScheduledJsonlTransport {
  fn drop(&mut self) {
    self.stdin.take();
    let _ = self.signal_process_group(Signal::SIGTERM);
    if let Some(deadline) = Instant::now().checked_add(Duration::from_millis(100))
      && self.wait_process_group_until(deadline).ok() == Some(ProcessExit::Exited)
    {
      return;
    }
    let _ = self.signal_process_group(Signal::SIGKILL);
    if let Some(deadline) = Instant::now().checked_add(Duration::from_millis(100)) {
      let _ = self.wait_process_group_until(deadline);
    }
  }
}

pub trait PreparedScheduledCodexExecution: Send {
  fn attested_profile(&self) -> &AttestedCapabilityProfile;
  fn execute(self: Box<Self>) -> ScheduledExecutionResult;
  /// Shuts down and reaps the prepared no-turn transport.
  ///
  /// # Errors
  /// Returns a typed failure when bounded shutdown cannot prove process-tree cleanup.
  #[allow(clippy::result_large_err)]
  fn shutdown_without_execute(
    self: Box<Self>,
  ) -> Result<AttestedCapabilityProfile, ScheduledExecutionResult>;
}

pub trait ScheduledCodexExecution: Send + Sync {
  /// Performs runtime attestation and prepares an execution without starting the Agent turn.
  ///
  /// # Errors
  /// Returns a typed fail-closed result when request validation, credential isolation, transport
  /// startup, protocol negotiation, or capability attestation fails.
  #[allow(
    clippy::result_large_err,
    reason = "the typed result is shared with execution and preserves failure context"
  )]
  fn prepare(
    &self,
    request: ScheduledCodexRequest,
    permit: ScheduledIsolationPermit,
  ) -> Result<Box<dyn PreparedScheduledCodexExecution>, ScheduledExecutionResult>;

  fn execute(
    &self,
    request: ScheduledCodexRequest,
    permit: ScheduledIsolationPermit,
  ) -> ScheduledExecutionResult {
    match self.prepare(request, permit) {
      Ok(prepared) => prepared.execute(),
      Err(result) => result,
    }
  }
}

pub struct ScheduledCodexExecutor<F> {
  transport_factory: F,
}

impl<F> ScheduledCodexExecutor<F> {
  /// Creates an executor that still requires a durably consumed isolation permit on every prepare.
  pub fn new(transport_factory: F) -> Self {
    Self { transport_factory }
  }
}

impl<F, T> ScheduledCodexExecution for ScheduledCodexExecutor<F>
where
  F: Fn(RequestedCapabilityProfile) -> Result<T, String> + Send + Sync,
  T: ScheduledJsonlTransport + Send + 'static,
{
  #[allow(
    clippy::result_large_err,
    reason = "the trait returns the shared typed execution result on preparation failure"
  )]
  fn prepare(
    &self,
    request: ScheduledCodexRequest,
    permit: ScheduledIsolationPermit,
  ) -> Result<Box<dyn PreparedScheduledCodexExecution>, ScheduledExecutionResult> {
    if let Err(failure) = validate_request(&request) {
      return Err(ScheduledExecutionResult::PreflightRejected(failure));
    }
    let permit = match validate_isolation_permit(permit, &request) {
      Ok(permit) => permit,
      Err(failure) => return Err(ScheduledExecutionResult::PreflightRejected(failure)),
    };
    let mut transport = match (self.transport_factory)(request.profile.clone()) {
      Ok(transport) => transport,
      Err(error) => {
        return Err(ScheduledExecutionResult::PreflightRejected(
          ScheduledFailure::new(ScheduledFailureKind::Transport, error),
        ));
      }
    };
    let attested_profile =
      match attest_runtime(&request.profile, transport.runtime_evidence(), permit) {
        Ok(profile) => profile,
        Err(failure) => {
          let _ = bounded_shutdown(&mut transport, &request);
          return Err(ScheduledExecutionResult::PreflightRejected(failure));
        }
      };
    let Some(deadline) = Instant::now().checked_add(request.timeout) else {
      let _ = bounded_shutdown(&mut transport, &request);
      return Err(ScheduledExecutionResult::PreflightRejected(preflight(
        "scheduled_run_deadline_overflow",
      )));
    };
    prepare_protocol(transport, request, attested_profile, deadline)
  }
}

pub struct BuiltScheduledCodexExecutor {
  pub profile: RequestedCapabilityProfile,
  pub authority: ScheduledDeploymentAuthority,
  pub executor: Arc<dyn ScheduledCodexExecution>,
}

impl BuiltScheduledCodexExecutor {
  /// Runs the complete no-turn App Server and MCP readiness protocol and reaps its process tree.
  ///
  /// # Errors
  /// Returns a typed failure when static authority, runtime evidence, App Server negotiation, MCP
  /// inventory, GitHub authentication status, or bounded cleanup fails.
  #[allow(clippy::result_large_err)]
  pub fn probe_readiness(
    &self,
    timeout: Duration,
  ) -> Result<AttestedCapabilityProfile, ScheduledExecutionResult> {
    if timeout.is_zero() || timeout > MAX_RUN_TIMEOUT {
      return Err(ScheduledExecutionResult::PreflightRejected(preflight(
        "scheduled_readiness_timeout_invalid",
      )));
    }
    let identity = ScheduledExecutionIdentity {
      run_id: "readiness-probe".to_owned(),
      job_id: "readiness-probe".to_owned(),
      attempt: 1,
      fence: 1,
    };
    let request = ScheduledCodexRequest {
      task: AgentTask {
        task_id: "scheduled:readiness-probe:1:1".to_owned(),
        instruction: "Verify scheduled runner readiness without starting a turn".to_owned(),
        source: InvocationSource::ScheduledRun {
          job_id: identity.job_id.clone(),
          run_id: identity.run_id.clone(),
          scheduled_for: "1970-01-01T00:00:00Z".to_owned(),
        },
        principal: InvocationPrincipal::service("codeoff-scheduler-readiness"),
        session: SessionMode::Fresh,
        channel: None,
        previous_success: None,
        tool_policy: ToolPolicy::None,
        feedback_target: None,
      },
      identity: identity.clone(),
      profile: self.profile.clone(),
      cancellation: Arc::new(AtomicBool::new(false)),
      timeout,
      interrupt_grace: Duration::from_secs(1),
      terminate_grace: Duration::from_secs(1),
      kill_grace: Duration::from_secs(1),
    };
    let profile_digest = isolation_profile_binding_digest(&self.profile)
      .map_err(ScheduledExecutionResult::PreflightRejected)?;
    if profile_digest != self.authority.profile_digest {
      return Err(ScheduledExecutionResult::PreflightRejected(preflight(
        "scheduled_readiness_authority_profile_mismatch",
      )));
    }
    let now = now_unix_seconds();
    let expires_at = now
      .saturating_add(timeout.as_secs().max(1))
      .min(self.authority.expires_at_unix_seconds);
    if expires_at <= now {
      return Err(ScheduledExecutionResult::PreflightRejected(preflight(
        "scheduled_readiness_authority_expired",
      )));
    }
    let nonce = sha256_hex(
      format!(
        "scheduled-readiness-nonce-v1:{}:{now}",
        self.authority.attestation_id
      )
      .as_bytes(),
    );
    let permit = ScheduledIsolationPermit {
      identity,
      deployment_epoch: self.authority.deployment_epoch,
      attestation_id: self.authority.attestation_id.clone(),
      profile_digest,
      permit_id: sha256_hex(format!("scheduled-readiness-permit-v1:{nonce}").as_bytes()),
      nonce,
      isolation_revision: self.authority.isolation_revision.clone(),
      expires_at_unix_seconds: expires_at,
    };
    self
      .executor
      .prepare(request, permit)?
      .shutdown_without_execute()
  }
}

/// Verifies deployment-supplied scheduled execution authority and constructs the production
/// process-owned Codex executor.
///
/// # Errors
/// Returns a fail-closed preflight error when the binary, dedicated config, filesystem boundary,
/// signed isolation attestation, or pinned runtime evidence is absent or mismatched.
pub fn build_production_scheduled_codex_executor(
  config: &ScheduledCodexConfig,
) -> Result<BuiltScheduledCodexExecutor, ScheduledFailure> {
  build_production_scheduled_codex_executor_with_identity(config, None)
}

/// Builds a trusted supervisor-owned executor that launches Codex under the exact distinct
/// nonroot runtime identity.
///
/// # Errors
/// Returns a fail-closed error for identity, artifact, signed authority, or executable drift.
pub fn build_supervised_scheduled_codex_executor(
  config: &ScheduledCodexConfig,
  runtime_user_id: u32,
  runtime_group_id: u32,
) -> Result<BuiltScheduledCodexExecutor, ScheduledFailure> {
  if runtime_user_id == config.trusted_owner_uid
    || runtime_group_id == config.trusted_owner_gid
    || runtime_user_id != config.runtime_uid
    || runtime_group_id != config.runtime_gid
  {
    return Err(preflight("scheduled_codex_child_identity_invalid"));
  }
  build_production_scheduled_codex_executor_with_identity(
    config,
    Some((runtime_user_id, runtime_group_id)),
  )
}

fn build_production_scheduled_codex_executor_with_identity(
  config: &ScheduledCodexConfig,
  child_identity: Option<(u32, u32)>,
) -> Result<BuiltScheduledCodexExecutor, ScheduledFailure> {
  let profile = requested_profile(config);
  profile.validate()?;
  #[cfg(unix)]
  {
    let verified = child_identity.map_or_else(
      || verify_scheduled_artifacts(config, &profile),
      |_| verify_scheduled_artifacts_as_trusted_owner(config, &profile),
    );
    let artifacts = Arc::new(
      verified
        .map_err(|error| preflight(format!("scheduled_artifact_verification_failed:{error}")))?,
    );
    verify_codex_version(&artifacts, child_identity)?;
    let authority = load_signed_isolation_authority_contents(
      &profile,
      &artifacts.attestation_contents,
      &artifacts.trust_bundle_contents,
    )?;
    let runtime_evidence = ScheduledRuntimeEvidence {
      codex_version: CODEX_CLI_VERSION.to_owned(),
      app_server_schema_sha256: CODEX_APP_SERVER_SCHEMA_SHA256.to_owned(),
      codex_program_sha256: profile.codex_program_sha256.clone(),
      config_sha256: profile.config_sha256.clone(),
      runner_image_digest: profile.runner_image_digest.clone(),
    };
    let executor_artifacts = Arc::clone(&artifacts);
    let executor_evidence = runtime_evidence.clone();
    let github_mcp_access_token = load_github_mcp_access_token()?;
    let executor = ScheduledCodexExecutor::new(move |requested: RequestedCapabilityProfile| {
      StdioScheduledJsonlTransport::spawn(
        &requested,
        executor_evidence.clone(),
        &executor_artifacts,
        child_identity,
        &github_mcp_access_token,
      )
    });
    Ok(BuiltScheduledCodexExecutor {
      profile,
      authority,
      executor: Arc::new(executor),
    })
  }
  #[cfg(not(unix))]
  {
    let _ = config;
    Err(preflight("scheduled_executor_requires_unix"))
  }
}

fn load_github_mcp_access_token() -> Result<String, ScheduledFailure> {
  let token = std::env::var(GITHUB_MCP_ACCESS_TOKEN_ENV)
    .map_err(|_| preflight("github_mcp_access_token_missing"))?;
  validate_github_mcp_access_token(&token)?;
  Ok(token)
}

fn validate_github_mcp_access_token(token: &str) -> Result<(), ScheduledFailure> {
  if !(MIN_MCP_ACCESS_TOKEN_BYTES..=MAX_MCP_ACCESS_TOKEN_BYTES).contains(&token.len())
    || !token.bytes().all(|byte| byte.is_ascii_graphic())
  {
    return Err(preflight("github_mcp_access_token_invalid"));
  }
  Ok(())
}

/// Reloads and verifies the currently deployed signed execution authority from its trusted path.
///
/// # Errors
/// Returns a fail-closed preflight error when the rotated artifact, signature, freshness window,
/// or exact profile binding is invalid.
pub fn load_current_scheduled_deployment_authority(
  config: &ScheduledCodexConfig,
  profile: &RequestedCapabilityProfile,
) -> Result<ScheduledDeploymentAuthority, ScheduledFailure> {
  let (contents, trust_bundle) = read_verified_scheduled_authority_material(config)
    .map_err(|error| preflight(format!("scheduled_attestation_reload_failed:{error}")))?;
  load_signed_isolation_authority_contents(profile, &contents, &trust_bundle)
}

/// Loads the signed deployment authority from the credential-owning trusted process identity.
///
/// # Errors
/// Returns a fail-closed error when process identity, artifact ownership, signature, freshness, or
/// exact profile binding is invalid.
pub fn load_trusted_owner_scheduled_deployment_authority(
  config: &ScheduledCodexConfig,
) -> Result<(RequestedCapabilityProfile, ScheduledDeploymentAuthority), ScheduledFailure> {
  let profile = requested_profile(config);
  profile.validate()?;
  let (contents, trust_bundle) = read_trusted_owner_scheduled_authority_material(config)
    .map_err(|error| preflight(format!("scheduled_trusted_authority_load_failed:{error}")))?;
  let authority = load_signed_isolation_authority_contents(&profile, &contents, &trust_bundle)?;
  Ok((profile, authority))
}

fn requested_profile(config: &ScheduledCodexConfig) -> RequestedCapabilityProfile {
  RequestedCapabilityProfile {
    codex_program: config.codex_program.clone(),
    codex_program_sha256: config.codex_program_sha256.clone(),
    codex_home: config.codex_home.clone(),
    cwd: config.cwd.clone(),
    github_mcp_url: config.github_mcp_url.clone(),
    github_mcp_artifact_sha256: config.github_mcp_artifact_sha256.clone(),
    github_mcp_endpoint_identity: config.github_mcp_endpoint_identity.clone(),
    github_mcp_access_auth_mode: config.github_mcp_access_auth_mode.clone(),
    github_mcp_access_token_revision: config.github_mcp_access_token_revision.clone(),
    credential_reference: config.credential_reference.clone(),
    permission_policy_revision: config.permission_policy_revision.clone(),
    config_revision: config.config_revision.clone(),
    config_sha256: config.config_sha256.clone(),
    gateway_image_digest: config.gateway_image_digest.clone(),
    runner_image_digest: config.runner_image_digest.clone(),
    runner_workload_identity: config.runner_workload_identity.clone(),
    runner_client_cert_public_key_fingerprint: config
      .runner_client_cert_public_key_fingerprint
      .clone(),
    credential_revision: config.credential_revision.clone(),
  }
}

#[cfg(unix)]
fn verify_codex_version(
  artifacts: &Arc<VerifiedScheduledArtifacts>,
  child_identity: Option<(u32, u32)>,
) -> Result<(), ScheduledFailure> {
  let output = verified_command(artifacts, &["codex", "--version"], false, child_identity)
    .map_err(|error| preflight(format!("scheduled_codex_version_probe_failed:{error}")))?
    .command
    .output()
    .map_err(|error| preflight(format!("scheduled_codex_version_probe_failed:{error}")))?;
  let version = String::from_utf8(output.stdout)
    .map_err(|_| preflight("scheduled_codex_version_probe_not_utf8"))?;
  if !output.status.success() || version.trim() != format!("codex-cli {CODEX_CLI_VERSION}") {
    return Err(preflight("scheduled_codex_version_mismatch_at_startup"));
  }
  Ok(())
}

#[cfg(unix)]
struct VerifiedCommand {
  command: Command,
  _program: fs::File,
  _codex_home: fs::File,
  _cwd: fs::File,
}

#[cfg(unix)]
fn verified_command(
  artifacts: &Arc<VerifiedScheduledArtifacts>,
  arguments: &[&str],
  use_codex_home: bool,
  child_identity: Option<(u32, u32)>,
) -> Result<VerifiedCommand, String> {
  let program = artifacts
    .program
    .try_clone()
    .map_err(|error| format!("clone verified codex program: {error}"))?;
  let cwd = artifacts
    .cwd
    .try_clone()
    .map_err(|error| format!("clone verified scheduled cwd: {error}"))?;
  let codex_home = artifacts
    .codex_home
    .try_clone()
    .map_err(|error| format!("clone verified CODEX_HOME: {error}"))?;
  fcntl(&program, FcntlArg::F_SETFD(FdFlag::empty()))
    .map_err(|error| format!("make verified codex descriptor executable: {error}"))?;
  fcntl(&cwd, FcntlArg::F_SETFD(FdFlag::empty()))
    .map_err(|error| format!("inherit verified scheduled cwd descriptor: {error}"))?;
  if use_codex_home {
    fcntl(&codex_home, FcntlArg::F_SETFD(FdFlag::empty()))
      .map_err(|error| format!("inherit verified CODEX_HOME descriptor: {error}"))?;
  }
  let mut command = Command::new(format!("/proc/self/fd/{}", program.as_raw_fd()));
  if let Some((uid, gid)) = child_identity {
    command.uid(uid).gid(gid);
  }
  command
    .args(&arguments[1..])
    .env_clear()
    .envs(fixed_child_environment())
    .current_dir(format!("/proc/self/fd/{}", cwd.as_raw_fd()));
  if use_codex_home {
    command.env(
      "CODEX_HOME",
      format!("/proc/self/fd/{}", codex_home.as_raw_fd()),
    );
  }
  Ok(VerifiedCommand {
    command,
    _program: program,
    _codex_home: codex_home,
    _cwd: cwd,
  })
}

/// Creates a new dedicated `CODEX_HOME` containing only the pinned scheduled config.
///
/// # Errors
///
/// Returns an error when the profile is invalid, the directory already exists, or its config
/// cannot be created and protected.
pub fn prepare_scheduled_codex_home(
  profile: &RequestedCapabilityProfile,
) -> Result<(), ScheduledFailure> {
  profile.validate()?;
  if profile.codex_home.exists() {
    return Err(preflight("scheduled_codex_home_must_not_already_exist"));
  }
  fs::create_dir(&profile.codex_home).map_err(|error| {
    ScheduledFailure::new(
      ScheduledFailureKind::InvalidRequest,
      format!("create scheduled CODEX_HOME: {error}"),
    )
  })?;
  let config_path = profile.codex_home.join("config.toml");
  let mut config = OpenOptions::new()
    .write(true)
    .create_new(true)
    .open(&config_path)
    .map_err(|error| {
      ScheduledFailure::new(
        ScheduledFailureKind::InvalidRequest,
        format!("create scheduled config: {error}"),
      )
    })?;
  config
    .write_all(profile.dedicated_config().as_bytes())
    .map_err(|error| {
      ScheduledFailure::new(
        ScheduledFailureKind::InvalidRequest,
        format!("write scheduled config: {error}"),
      )
    })?;
  config.sync_all().map_err(|error| {
    ScheduledFailure::new(
      ScheduledFailureKind::InvalidRequest,
      format!("sync scheduled config: {error}"),
    )
  })?;
  #[cfg(unix)]
  {
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o444)).map_err(|error| {
      ScheduledFailure::new(
        ScheduledFailureKind::InvalidRequest,
        format!("protect scheduled config: {error}"),
      )
    })?;
    fs::set_permissions(&profile.codex_home, fs::Permissions::from_mode(0o555)).map_err(
      |error| {
        ScheduledFailure::new(
          ScheduledFailureKind::InvalidRequest,
          format!("protect scheduled CODEX_HOME: {error}"),
        )
      },
    )?;
  }
  Ok(())
}

fn validate_request(request: &ScheduledCodexRequest) -> Result<(), ScheduledFailure> {
  request
    .task
    .validate()
    .map_err(|error| ScheduledFailure::new(ScheduledFailureKind::InvalidRequest, error))?;
  if !matches!(request.task.source, InvocationSource::ScheduledRun { .. }) {
    return Err(preflight("scheduled_adapter_requires_scheduled_run_source"));
  }
  if !matches!(request.task.session, SessionMode::Fresh) {
    return Err(preflight("scheduled_adapter_requires_fresh_session"));
  }
  if !matches!(request.task.tool_policy, ToolPolicy::None) {
    return Err(preflight("scheduled_adapter_disallows_dynamic_tools"));
  }
  if request.task.instruction.len() > MAX_INSTRUCTION_BYTES {
    return Err(preflight("scheduled_instruction_too_large"));
  }
  if request.timeout.is_zero()
    || request.interrupt_grace.is_zero()
    || request.terminate_grace.is_zero()
    || request.kill_grace.is_zero()
  {
    return Err(preflight("scheduled_timeouts_must_be_positive"));
  }
  if request.timeout > MAX_RUN_TIMEOUT
    || request.interrupt_grace > MAX_INTERRUPT_GRACE
    || request.terminate_grace > MAX_TERMINATE_GRACE
    || request.kill_grace > MAX_KILL_GRACE
  {
    return Err(preflight("scheduled_timeouts_exceed_hard_limit"));
  }
  request
    .timeout
    .checked_add(request.interrupt_grace)
    .and_then(|duration| duration.checked_add(request.terminate_grace))
    .and_then(|duration| duration.checked_add(request.kill_grace))
    .ok_or_else(|| preflight("scheduled_timeout_budget_overflow"))?;
  validate_fixed_output_schema()?;
  request.profile.validate()
}

fn attest_runtime(
  requested: &RequestedCapabilityProfile,
  evidence: &ScheduledRuntimeEvidence,
  isolation_permit: ScheduledIsolationPermit,
) -> Result<AttestedCapabilityProfile, ScheduledFailure> {
  if isolation_permit.expires_at_unix_seconds <= now_unix_seconds() {
    return Err(ScheduledFailure::new(
      ScheduledFailureKind::CredentialIsolationUnproven,
      "credential_isolation_permit_expired_during_startup",
    ));
  }
  if evidence.codex_version != CODEX_CLI_VERSION {
    return Err(capability("codex_version_mismatch"));
  }
  if evidence.app_server_schema_sha256 != CODEX_APP_SERVER_SCHEMA_SHA256 {
    return Err(capability("codex_app_server_schema_mismatch"));
  }
  if evidence.codex_program_sha256 != requested.codex_program_sha256 {
    return Err(capability("codex_program_digest_mismatch"));
  }
  if evidence.config_sha256 != requested.config_sha256 {
    return Err(capability("scheduled_config_runtime_digest_mismatch"));
  }
  if evidence.runner_image_digest != requested.runner_image_digest {
    return Err(capability("scheduled_runner_image_digest_mismatch"));
  }
  Ok(AttestedCapabilityProfile {
    codex_version: evidence.codex_version.clone(),
    app_server_schema_sha256: evidence.app_server_schema_sha256.clone(),
    codex_program_sha256: evidence.codex_program_sha256.clone(),
    github_mcp_version: GITHUB_MCP_SERVER_VERSION.to_owned(),
    github_mcp_artifact_sha256: requested.github_mcp_artifact_sha256.clone(),
    github_mcp_endpoint_identity: requested.github_mcp_endpoint_identity.clone(),
    github_mcp_access_auth_mode: requested.github_mcp_access_auth_mode.clone(),
    github_mcp_access_token_revision: requested.github_mcp_access_token_revision.clone(),
    github_mcp_health_checked_at_unix_seconds: 0,
    github_mcp_health_credential_revision: String::new(),
    github_mcp_health_result_sha256: String::new(),
    github_mcp_health_tool: GITHUB_MCP_HEALTH_TOOL.to_owned(),
    github_tools: RequestedCapabilityProfile::github_tool_inventory(),
    credential_reference: requested.credential_reference.clone(),
    permission_policy_revision: requested.permission_policy_revision.clone(),
    config_revision: requested.config_revision.clone(),
    config_sha256: requested.config_sha256.clone(),
    gateway_image_digest: requested.gateway_image_digest.clone(),
    runner_image_digest: requested.runner_image_digest.clone(),
    runner_workload_identity: requested.runner_workload_identity.clone(),
    runner_client_cert_public_key_fingerprint: requested
      .runner_client_cert_public_key_fingerprint
      .clone(),
    credential_revision: requested.credential_revision.clone(),
    credential_isolation_revision: isolation_permit.isolation_revision,
    credential_deny_policy_revision: CREDENTIAL_DENY_POLICY_REVISION.to_owned(),
    negative_test_revision: NEGATIVE_TEST_REVISION.to_owned(),
    output_schema_revision: OUTPUT_SCHEMA_REVISION.to_owned(),
    attested_at_unix_seconds: now_unix_seconds(),
    profile_sha256: String::new(),
  })
}

struct PreparedCodexExecution<T> {
  transport: T,
  request: ScheduledCodexRequest,
  attested_profile: AttestedCapabilityProfile,
  thread_id: String,
  deadline: Instant,
}

impl<T: ScheduledJsonlTransport + Send> PreparedScheduledCodexExecution
  for PreparedCodexExecution<T>
{
  fn attested_profile(&self) -> &AttestedCapabilityProfile {
    &self.attested_profile
  }

  fn execute(mut self: Box<Self>) -> ScheduledExecutionResult {
    let result = execute_prepared_protocol(
      &mut self.transport,
      &self.request,
      &self.thread_id,
      self.attested_profile.clone(),
      self.deadline,
    );
    match bounded_shutdown(&mut self.transport, &self.request) {
      Ok(()) => result,
      Err(failure) => ScheduledExecutionResult::TransportLost(failure),
    }
  }

  #[allow(clippy::result_large_err)]
  fn shutdown_without_execute(
    mut self: Box<Self>,
  ) -> Result<AttestedCapabilityProfile, ScheduledExecutionResult> {
    let profile = self.attested_profile.clone();
    bounded_shutdown(&mut self.transport, &self.request)
      .map(|()| profile)
      .map_err(ScheduledExecutionResult::TransportLost)
  }
}

#[allow(
  clippy::result_large_err,
  reason = "preparation preserves the shared typed execution failure without lossy conversion"
)]
fn prepare_protocol<T: ScheduledJsonlTransport + Send + 'static>(
  mut transport: T,
  request: ScheduledCodexRequest,
  mut attested_profile: AttestedCapabilityProfile,
  deadline: Instant,
) -> Result<Box<dyn PreparedScheduledCodexExecution>, ScheduledExecutionResult> {
  let initialize = json!({
    "clientInfo": {"name": "codeoff-scheduler", "version": env!("CARGO_PKG_VERSION")},
  });
  if let Err(failure) = scheduled_request(
    &mut transport,
    1,
    "initialize",
    &initialize,
    deadline,
    &request.cancellation,
  ) {
    return reject_preparation(transport, &request, protocol_failure(failure));
  }
  if let Err(error) = send_notification(&mut transport, "initialized") {
    return reject_preparation(transport, &request, transport_failure(error));
  }
  let thread_params = json!({
    "approvalPolicy": "never",
    "cwd": request.profile.cwd,
    "ephemeral": true,
    "sandbox": "read-only",
    "config": {
      "web_search": "disabled",
      "shell_environment_policy": {
        "inherit": "none",
        "ignore_default_excludes": false,
        "exclude": [GITHUB_MCP_ACCESS_TOKEN_ENV],
        "include_only": ["PATH", "LANG", "LC_ALL"],
        "set": {
          "PATH": CHILD_PATH,
          "LANG": CHILD_LOCALE,
          "LC_ALL": CHILD_LOCALE,
        },
      },
      "mcp_servers": {
        GITHUB_MCP_NAME: {
          "url": request.profile.github_mcp_url,
          "enabled": true,
          "required": true,
          "bearer_token_env_var": GITHUB_MCP_ACCESS_TOKEN_ENV,
          "enabled_tools": EXPECTED_GITHUB_TOOLS,
        }
      }
    }
  });
  let thread = match scheduled_request(
    &mut transport,
    2,
    "thread/start",
    &thread_params,
    deadline,
    &request.cancellation,
  ) {
    Ok(thread) => thread,
    Err(failure) => return reject_preparation(transport, &request, protocol_failure(failure)),
  };
  let Some(thread_id) = thread["thread"]["id"].as_str().map(str::to_owned) else {
    return reject_preparation(
      transport,
      &request,
      protocol_failure(capability("thread_start_missing_thread_id")),
    );
  };
  let inventory = match scheduled_request(
    &mut transport,
    3,
    "mcpServerStatus/list",
    &json!({"threadId": thread_id, "detail": "full", "limit": 100}),
    deadline,
    &request.cancellation,
  ) {
    Ok(inventory) => inventory,
    Err(failure) => return reject_preparation(transport, &request, protocol_failure(failure)),
  };
  if let Err(failure) = attest_mcp_inventory(&inventory) {
    return reject_preparation(
      transport,
      &request,
      ScheduledExecutionResult::PreflightRejected(failure),
    );
  }
  let (health_digest, checked_at) =
    match attest_github_mcp_health(&mut transport, &request, &thread_id, deadline) {
      Ok(attestation) => attestation,
      Err(failure) => return reject_preparation(transport, &request, *failure),
    };
  attested_profile.github_mcp_health_checked_at_unix_seconds = checked_at;
  attested_profile
    .github_mcp_health_credential_revision
    .clone_from(&request.profile.credential_revision);
  attested_profile.github_mcp_health_result_sha256 = health_digest;
  attested_profile.attested_at_unix_seconds = checked_at;
  attested_profile.profile_sha256 = attested_profile.computed_profile_sha256();
  Ok(Box::new(PreparedCodexExecution {
    transport,
    request,
    attested_profile,
    thread_id,
    deadline,
  }))
}

fn attest_github_mcp_health<T: ScheduledJsonlTransport>(
  transport: &mut T,
  request: &ScheduledCodexRequest,
  thread_id: &str,
  deadline: Instant,
) -> Result<(String, u64), Box<ScheduledExecutionResult>> {
  let health = scheduled_request(
    transport,
    4,
    "mcpServer/tool/call",
    &json!({
      "arguments": {},
      "server": GITHUB_MCP_NAME,
      "threadId": thread_id,
      "tool": GITHUB_MCP_HEALTH_TOOL,
    }),
    deadline,
    &request.cancellation,
  )
  .map_err(|failure| Box::new(protocol_failure(failure)))?;
  let digest = attest_mcp_health(&health)
    .map_err(|failure| Box::new(ScheduledExecutionResult::PreflightRejected(failure)))?;
  Ok((digest, now_unix_seconds()))
}

fn execute_prepared_protocol<T: ScheduledJsonlTransport>(
  transport: &mut T,
  request: &ScheduledCodexRequest,
  thread_id: &str,
  attested_profile: AttestedCapabilityProfile,
  deadline: Instant,
) -> ScheduledExecutionResult {
  if request.cancellation.load(Ordering::Acquire) {
    return ScheduledExecutionResult::Interrupted {
      thread_id: Some(thread_id.to_owned()),
      turn_id: None,
    };
  }
  let turn_params = json!({
    "threadId": thread_id,
    "clientUserMessageId": request.task.task_id,
    "cwd": request.profile.cwd,
    "approvalPolicy": "never",
    "sandboxPolicy": {"type": "readOnly", "networkAccess": false},
    "outputSchema": fixed_output_schema(),
    "input": [{"type": "text", "text": request.task.instruction}],
  });
  let turn = match scheduled_request(
    transport,
    5,
    "turn/start",
    &turn_params,
    deadline,
    &request.cancellation,
  ) {
    Ok(turn) => turn,
    Err(failure) => return protocol_failure(failure),
  };
  let Some(turn_id) = turn["turn"]["id"]
    .as_str()
    .or_else(|| turn["turn_id"].as_str())
    .map(str::to_owned)
  else {
    return protocol_failure(capability("turn_start_missing_turn_id"));
  };
  wait_for_scheduled_turn(
    transport,
    request,
    thread_id,
    &turn_id,
    attested_profile,
    deadline,
  )
}

fn scheduled_request<T: ScheduledJsonlTransport>(
  transport: &mut T,
  id: u64,
  method: &str,
  params: &Value,
  deadline: Instant,
  cancellation: &AtomicBool,
) -> Result<Value, ScheduledFailure> {
  send_request(transport, id, method, params)
    .map_err(|error| ScheduledFailure::new(ScheduledFailureKind::Transport, error))?;
  loop {
    if cancellation.load(Ordering::Acquire) {
      return Err(ScheduledFailure::new(
        ScheduledFailureKind::Interrupted,
        format!("{method}_cancelled"),
      ));
    }
    let poll_deadline = Instant::now()
      .checked_add(CANCELLATION_POLL_INTERVAL)
      .map_or(deadline, |candidate| candidate.min(deadline));
    match transport.read_json_until(poll_deadline) {
      Ok(TimedRead::Message(response)) => {
        if response.get("id").is_none() && response["method"].is_string() {
          continue;
        }
        if response["id"].as_u64() != Some(id) {
          return Err(capability(format!("{method}_response_id_mismatch")));
        }
        if let Some(error) = response.get("error") {
          return Err(ScheduledFailure::new(
            ScheduledFailureKind::ProtocolIncompatible,
            format!(
              "{method}_failed:{}",
              error["message"].as_str().unwrap_or("unknown")
            ),
          ));
        }
        return Ok(response.get("result").cloned().unwrap_or_else(|| json!({})));
      }
      Ok(TimedRead::TimedOut) if Instant::now() < deadline => {}
      Ok(TimedRead::TimedOut) => {
        return Err(ScheduledFailure::new(
          ScheduledFailureKind::TimedOut,
          format!("{method}_timed_out"),
        ));
      }
      Ok(TimedRead::Eof) => {
        return Err(ScheduledFailure::new(
          ScheduledFailureKind::Transport,
          format!("{method}_transport_eof"),
        ));
      }
      Err(error) => {
        return Err(ScheduledFailure::new(
          ScheduledFailureKind::Transport,
          error,
        ));
      }
    }
  }
}

#[allow(
  clippy::result_large_err,
  reason = "preparation preserves the shared typed execution failure without lossy conversion"
)]
fn reject_preparation<T: ScheduledJsonlTransport>(
  mut transport: T,
  request: &ScheduledCodexRequest,
  result: ScheduledExecutionResult,
) -> Result<Box<dyn PreparedScheduledCodexExecution>, ScheduledExecutionResult> {
  match bounded_shutdown(&mut transport, request) {
    Ok(()) => Err(result),
    Err(failure) => Err(ScheduledExecutionResult::TransportLost(failure)),
  }
}

fn attest_mcp_inventory(inventory: &Value) -> Result<(), ScheduledFailure> {
  if !inventory["nextCursor"].is_null() {
    return Err(capability("mcp_inventory_exceeded_single_exact_page"));
  }
  let Some(servers) = inventory["data"].as_array() else {
    return Err(capability("mcp_inventory_missing_data"));
  };
  if servers.len() != 1 {
    return Err(capability("mcp_inventory_must_contain_exactly_github"));
  }
  let server = &servers[0];
  if server["name"].as_str() != Some(GITHUB_MCP_NAME) {
    return Err(capability("unexpected_mcp_server"));
  }
  if server["authStatus"].as_str() != Some("bearerToken") {
    return Err(capability("github_mcp_bearer_channel_auth_missing"));
  }
  if server["serverInfo"]["name"].as_str() != Some(GITHUB_MCP_SERVER_INFO_NAME)
    || server["serverInfo"]["version"].as_str() != Some(GITHUB_MCP_SERVER_VERSION)
  {
    return Err(capability("github_mcp_server_identity_or_version_mismatch"));
  }
  if !server["resources"].as_array().is_some_and(Vec::is_empty)
    || !server["resourceTemplates"]
      .as_array()
      .is_some_and(Vec::is_empty)
  {
    return Err(capability("github_mcp_resources_are_not_allowed"));
  }
  let Some(tools) = server["tools"].as_object() else {
    return Err(capability("github_mcp_tool_inventory_missing"));
  };
  let actual: BTreeSet<_> = tools.keys().cloned().collect();
  if actual != RequestedCapabilityProfile::github_tool_inventory() {
    return Err(capability("github_mcp_tool_inventory_mismatch"));
  }
  for (name, tool) in tools {
    if tool["name"].as_str() != Some(name)
      || tool["annotations"]["readOnlyHint"].as_bool() != Some(true)
    {
      return Err(capability("github_mcp_tool_not_attested_read_only"));
    }
  }
  Ok(())
}

fn attest_mcp_health(health: &Value) -> Result<String, ScheduledFailure> {
  let bytes =
    serde_json::to_vec(health).map_err(|_| capability("github_mcp_health_not_serializable"))?;
  if bytes.len() > MAX_MCP_HEALTH_RESULT_BYTES || json_depth(health) > MAX_MCP_HEALTH_RESULT_DEPTH {
    return Err(capability("github_mcp_health_result_exceeds_hard_limit"));
  }
  let object = health
    .as_object()
    .filter(|object| {
      object.contains_key("content")
        && object.keys().all(|field| {
          matches!(
            field.as_str(),
            "_meta" | "content" | "isError" | "structuredContent"
          )
        })
    })
    .ok_or_else(|| capability("github_mcp_health_response_malformed"))?;
  if let Some(is_error) = object.get("isError") {
    match is_error.as_bool() {
      Some(false) => {}
      Some(true) => return Err(capability("github_mcp_health_reported_error")),
      None => return Err(capability("github_mcp_health_response_malformed")),
    }
  }
  let content = object
    .get("content")
    .and_then(Value::as_array)
    .filter(|content| !content.is_empty() && content.len() <= 16)
    .ok_or_else(|| capability("github_mcp_health_content_missing"))?;
  let has_nonempty_text = content.iter().any(|item| {
    item.get("type").and_then(Value::as_str) == Some("text")
      && item
        .get("text")
        .and_then(Value::as_str)
        .is_some_and(|text| !text.trim().is_empty())
  });
  let has_structured_identity = object
    .get("structuredContent")
    .and_then(Value::as_object)
    .is_some_and(|identity| !identity.is_empty());
  if !has_nonempty_text && !has_structured_identity {
    return Err(capability("github_mcp_health_identity_missing"));
  }
  Ok(sha256_hex(health.to_string().as_bytes()))
}

#[allow(
  clippy::too_many_lines,
  reason = "the bounded protocol loop keeps terminal handling and output accumulation atomic"
)]
fn wait_for_scheduled_turn<T: ScheduledJsonlTransport>(
  transport: &mut T,
  request: &ScheduledCodexRequest,
  thread_id: &str,
  turn_id: &str,
  attested_profile: AttestedCapabilityProfile,
  deadline: Instant,
) -> ScheduledExecutionResult {
  let mut phased_final = None;
  let mut final_item_ids = BTreeSet::new();
  let mut final_delta_bytes = 0_usize;
  loop {
    if request.cancellation.load(Ordering::Acquire) {
      return interrupt_scheduled_turn(transport, request, thread_id, turn_id);
    }
    let poll_deadline = Instant::now()
      .checked_add(CANCELLATION_POLL_INTERVAL)
      .map_or(deadline, |candidate| candidate.min(deadline));
    match transport.read_json_until(poll_deadline) {
      Ok(TimedRead::Message(message)) => {
        let params = &message["params"];
        if let Err(failure) = observe_final_stream_event(
          message["method"].as_str(),
          params,
          thread_id,
          turn_id,
          &mut final_item_ids,
          &mut final_delta_bytes,
        ) {
          return ScheduledExecutionResult::Failed(failure);
        }
        match message["method"].as_str() {
          Some("item/tool/call") => {
            let _ = transport.write_json(json!({
              "jsonrpc": "2.0",
              "id": message["id"].clone(),
              "result": {
                "success": false,
                "contentItems": [{"type": "inputText", "text": "scheduled_dynamic_tools_disabled"}],
              }
            }));
            return ScheduledExecutionResult::PreflightRejected(capability(
              "scheduled_dynamic_tool_call_observed",
            ));
          }
          Some("item/completed")
            if params["threadId"].as_str() == Some(thread_id)
              && params["turnId"].as_str() == Some(turn_id) =>
          {
            if let Err(failure) = record_agent_message(&params["item"], &mut phased_final) {
              return ScheduledExecutionResult::Failed(failure);
            }
          }
          Some("turn/completed") if params["threadId"].as_str() == Some(thread_id) => {
            let turn = &params["turn"];
            if turn["id"].as_str() != Some(turn_id) {
              continue;
            }
            if let Some(items) = turn["items"].as_array() {
              for item in items {
                if let Err(failure) = record_agent_message(item, &mut phased_final) {
                  return ScheduledExecutionResult::Failed(failure);
                }
              }
            }
            return match turn["status"].as_str() {
              Some("completed") => {
                match phased_final
                  .as_deref()
                  .ok_or_else(|| output_violation("scheduled_final_answer_missing"))
                  .and_then(parse_final_output)
                {
                  Ok(output) => ScheduledExecutionResult::Completed {
                    output,
                    thread_id: thread_id.to_owned(),
                    turn_id: turn_id.to_owned(),
                    usage: parse_usage(turn),
                    attested_profile: Box::new(attested_profile),
                  },
                  Err(failure) => ScheduledExecutionResult::Failed(failure),
                }
              }
              Some("interrupted") => ScheduledExecutionResult::Interrupted {
                thread_id: Some(thread_id.to_owned()),
                turn_id: Some(turn_id.to_owned()),
              },
              Some("failed") => ScheduledExecutionResult::Failed(ScheduledFailure::new(
                ScheduledFailureKind::TurnFailed,
                turn["error"]["message"].as_str().unwrap_or("turn_failed"),
              )),
              _ => ScheduledExecutionResult::Failed(capability("unexpected_terminal_turn_status")),
            };
          }
          _ => {}
        }
      }
      Ok(TimedRead::TimedOut) if Instant::now() < deadline => {}
      Ok(TimedRead::TimedOut) => {
        return interrupt_scheduled_turn(transport, request, thread_id, turn_id);
      }
      Ok(TimedRead::Eof) => {
        return ScheduledExecutionResult::TransportLost(ScheduledFailure::new(
          ScheduledFailureKind::Transport,
          "transport_eof_before_terminal_turn",
        ));
      }
      Err(error) => return transport_failure(error),
    }
  }
}

fn observe_final_stream_event(
  method: Option<&str>,
  params: &Value,
  thread_id: &str,
  turn_id: &str,
  final_item_ids: &mut BTreeSet<String>,
  final_delta_bytes: &mut usize,
) -> Result<(), ScheduledFailure> {
  if params["threadId"].as_str() != Some(thread_id) || params["turnId"].as_str() != Some(turn_id) {
    return Ok(());
  }
  if method == Some("item/started")
    && params["item"]["type"].as_str() == Some("agentMessage")
    && params["item"]["phase"].as_str() == Some("final_answer")
  {
    let item_id = params["item"]["id"]
      .as_str()
      .ok_or_else(|| output_violation("scheduled_final_item_id_missing"))?;
    if item_id.len() > MAX_ITEM_ID_BYTES
      || (!final_item_ids.contains(item_id) && final_item_ids.len() >= MAX_FINAL_ITEM_COUNT)
    {
      return Err(output_violation(
        "scheduled_final_item_inventory_exceeds_limit",
      ));
    }
    final_item_ids.insert(item_id.to_owned());
  } else if method == Some("item/agentMessage/delta")
    && params["itemId"]
      .as_str()
      .is_some_and(|item_id| final_item_ids.contains(item_id))
  {
    let delta = params["delta"]
      .as_str()
      .ok_or_else(|| output_violation("scheduled_final_delta_invalid"))?;
    let total = final_delta_bytes
      .checked_add(delta.len())
      .ok_or_else(|| output_violation("scheduled_final_delta_size_overflow"))?;
    if total > MAX_FINAL_RESPONSE_BYTES {
      return Err(output_violation("scheduled_final_deltas_too_large"));
    }
    *final_delta_bytes = total;
  }
  Ok(())
}

fn interrupt_scheduled_turn<T: ScheduledJsonlTransport>(
  transport: &mut T,
  request: &ScheduledCodexRequest,
  thread_id: &str,
  turn_id: &str,
) -> ScheduledExecutionResult {
  if let Err(error) = send_request(
    transport,
    5,
    "turn/interrupt",
    &json!({"threadId": thread_id, "turnId": turn_id}),
  ) {
    return transport_failure(error);
  }
  let Some(deadline) = Instant::now().checked_add(request.interrupt_grace) else {
    return ScheduledExecutionResult::TransportLost(preflight(
      "scheduled_interrupt_deadline_overflow",
    ));
  };
  loop {
    match transport.read_json_until(deadline) {
      Ok(TimedRead::Message(message)) => {
        if message["id"].as_u64() == Some(5) && message.get("error").is_some() {
          return ScheduledExecutionResult::TransportLost(ScheduledFailure::new(
            ScheduledFailureKind::Transport,
            "turn_interrupt_rejected",
          ));
        }
        let params = &message["params"];
        if message["method"].as_str() == Some("turn/completed")
          && params["threadId"].as_str() == Some(thread_id)
          && params["turn"]["id"].as_str() == Some(turn_id)
          && params["turn"]["status"].as_str() == Some("interrupted")
        {
          return ScheduledExecutionResult::Interrupted {
            thread_id: Some(thread_id.to_owned()),
            turn_id: Some(turn_id.to_owned()),
          };
        }
      }
      Ok(TimedRead::TimedOut | TimedRead::Eof) => {
        return ScheduledExecutionResult::TransportLost(ScheduledFailure::new(
          ScheduledFailureKind::TimedOut,
          "turn_interrupt_not_confirmed",
        ));
      }
      Err(error) => return transport_failure(error),
    }
  }
}

fn bounded_shutdown<T: ScheduledJsonlTransport>(
  transport: &mut T,
  request: &ScheduledCodexRequest,
) -> Result<(), ScheduledFailure> {
  transport
    .close_stdin()
    .map_err(|error| ScheduledFailure::new(ScheduledFailureKind::Transport, error))?;
  transport
    .terminate_process_group()
    .map_err(|error| ScheduledFailure::new(ScheduledFailureKind::Transport, error))?;
  let terminate_deadline = Instant::now()
    .checked_add(request.terminate_grace)
    .ok_or_else(|| preflight("scheduled_terminate_deadline_overflow"))?;
  if transport
    .reap_until(terminate_deadline)
    .map_err(|error| ScheduledFailure::new(ScheduledFailureKind::Transport, error))?
    == ProcessExit::Exited
  {
    return Ok(());
  }
  transport
    .kill_process_group()
    .map_err(|error| ScheduledFailure::new(ScheduledFailureKind::Transport, error))?;
  let kill_deadline = Instant::now()
    .checked_add(request.kill_grace)
    .ok_or_else(|| preflight("scheduled_kill_deadline_overflow"))?;
  if transport
    .reap_until(kill_deadline)
    .map_err(|error| ScheduledFailure::new(ScheduledFailureKind::Transport, error))?
    == ProcessExit::Exited
  {
    return Ok(());
  }
  Err(ScheduledFailure::new(
    ScheduledFailureKind::Transport,
    "process_group_not_reaped_after_kill",
  ))
}

fn record_agent_message(
  item: &Value,
  phased_final: &mut Option<String>,
) -> Result<(), ScheduledFailure> {
  if item["type"].as_str() != Some("agentMessage") {
    return Ok(());
  }
  if item["phase"].as_str() != Some("final_answer") {
    return Ok(());
  }
  let Some(text) = item["text"]
    .as_str()
    .map(str::trim)
    .filter(|text| !text.is_empty())
  else {
    return Ok(());
  };
  if text.len() > MAX_FINAL_RESPONSE_BYTES {
    return Err(output_violation("scheduled_final_response_too_large"));
  }
  *phased_final = Some(text.to_owned());
  Ok(())
}

fn fixed_output_schema() -> Value {
  json!({
    "type": "object",
    "required": ["schema_version", "summary"],
    "properties": {
      "schema_version": {"type": "integer", "const": OUTPUT_SCHEMA_VERSION},
      "summary": {"type": "string", "minLength": 1, "maxLength": MAX_FINAL_SUMMARY_BYTES},
    },
    "additionalProperties": false,
  })
}

fn validate_fixed_output_schema() -> Result<(), ScheduledFailure> {
  let schema = fixed_output_schema();
  let bytes = serde_json::to_vec(&schema)
    .map_err(|_| preflight("scheduled_fixed_output_schema_not_serializable"))?;
  if bytes.len() > MAX_OUTPUT_SCHEMA_BYTES || json_depth(&schema) > MAX_OUTPUT_SCHEMA_DEPTH {
    return Err(preflight(
      "scheduled_fixed_output_schema_exceeds_hard_limit",
    ));
  }
  Ok(())
}

fn parse_final_output(text: &str) -> Result<ScheduledFinalOutput, ScheduledFailure> {
  if text.len() > MAX_FINAL_RESPONSE_BYTES {
    return Err(output_violation("scheduled_final_response_too_large"));
  }
  let value: Value = serde_json::from_str(text)
    .map_err(|_| output_violation("scheduled_final_response_invalid_json"))?;
  if json_depth(&value) > MAX_OUTPUT_SCHEMA_DEPTH {
    return Err(output_violation("scheduled_final_response_too_deep"));
  }
  let object = value
    .as_object()
    .ok_or_else(|| output_violation("scheduled_final_response_must_be_object"))?;
  if object.len() != 2 || !object.contains_key("schema_version") || !object.contains_key("summary")
  {
    return Err(output_violation("scheduled_final_response_fields_mismatch"));
  }
  let schema_version = object["schema_version"]
    .as_u64()
    .filter(|version| *version == OUTPUT_SCHEMA_VERSION)
    .ok_or_else(|| output_violation("scheduled_final_response_version_mismatch"))?;
  let summary = object["summary"]
    .as_str()
    .filter(|summary| !summary.trim().is_empty())
    .ok_or_else(|| output_violation("scheduled_final_response_summary_invalid"))?;
  if summary.len() > MAX_FINAL_SUMMARY_BYTES {
    return Err(output_violation(
      "scheduled_final_response_summary_too_large",
    ));
  }
  Ok(ScheduledFinalOutput {
    schema_version,
    summary: summary.to_owned(),
  })
}

fn json_depth(value: &Value) -> usize {
  match value {
    Value::Array(values) => 1 + values.iter().map(json_depth).max().unwrap_or(0),
    Value::Object(values) => 1 + values.values().map(json_depth).max().unwrap_or(0),
    _ => 1,
  }
}

fn parse_usage(turn: &Value) -> ScheduledUsage {
  let usage = &turn["usage"];
  ScheduledUsage {
    input: usage["inputTokens"]
      .as_u64()
      .or_else(|| usage["input_tokens"].as_u64()),
    cached_input: usage["cachedInputTokens"]
      .as_u64()
      .or_else(|| usage["cached_input_tokens"].as_u64()),
    output: usage["outputTokens"]
      .as_u64()
      .or_else(|| usage["output_tokens"].as_u64()),
  }
}

#[cfg(test)]
fn load_signed_isolation_authority(
  profile: &RequestedCapabilityProfile,
  path: &Path,
  trust_bundle: &str,
) -> Result<ScheduledDeploymentAuthority, ScheduledFailure> {
  let contents = fs::read_to_string(path)
    .map_err(|error| preflight(format!("read_scheduled_isolation_attestation:{error}")))?;
  load_signed_isolation_authority_contents(profile, &contents, trust_bundle)
}

#[allow(
  clippy::too_many_lines,
  reason = "keeps the exact signed attestation shape and validation order auditable in one owner"
)]
fn load_signed_isolation_authority_contents(
  profile: &RequestedCapabilityProfile,
  contents: &str,
  trust_bundle: &str,
) -> Result<ScheduledDeploymentAuthority, ScheduledFailure> {
  let document: Value = serde_json::from_str(contents)
    .map_err(|_| preflight("scheduled_isolation_attestation_invalid_json"))?;
  let canonical_document = document.to_string();
  if canonical_document.as_bytes() != contents.as_bytes() {
    return Err(preflight(
      "scheduled_isolation_attestation_must_be_canonical_json",
    ));
  }
  let document = document
    .as_object()
    .filter(|object| has_exact_fields(object, &["payload", "signature", "signature_algorithm"]))
    .ok_or_else(|| preflight("scheduled_isolation_attestation_fields_mismatch"))?;
  if document.get("signature_algorithm").and_then(Value::as_str) != Some("ed25519") {
    return Err(preflight(
      "scheduled_isolation_attestation_signature_algorithm_mismatch",
    ));
  }
  let payload = document
    .get("payload")
    .and_then(Value::as_object)
    .filter(|object| {
      has_exact_fields(
        object,
        &[
          "attestation_id",
          "credential_isolation_revision",
          "deployment_epoch",
          "expires_at_unix_seconds",
          "issued_at_unix_seconds",
          "negative_test_revision",
          "profile_binding_digest",
          "schema_version",
        ],
      )
    })
    .ok_or_else(|| preflight("scheduled_isolation_attestation_payload_fields_mismatch"))?;
  let canonical_payload = Value::Object(payload.clone()).to_string();
  let signature = decode_lowercase_hex(
    document
      .get("signature")
      .and_then(Value::as_str)
      .ok_or_else(|| preflight("scheduled_isolation_attestation_signature_missing"))?,
    64,
    "scheduled_isolation_attestation_signature_invalid",
  )?;
  let schema_version = payload
    .get("schema_version")
    .and_then(Value::as_u64)
    .filter(|version| *version == ISOLATION_ATTESTATION_SCHEMA_VERSION)
    .ok_or_else(|| preflight("scheduled_isolation_attestation_version_mismatch"))?;
  let _ = schema_version;
  let deployment_epoch = payload
    .get("deployment_epoch")
    .and_then(Value::as_u64)
    .and_then(|value| i64::try_from(value).ok())
    .filter(|value| *value > 0)
    .ok_or_else(|| preflight("scheduled_isolation_deployment_epoch_invalid"))?;
  let trust_keys = isolation_trust_keys_for_epoch(trust_bundle, deployment_epoch)?;
  let verified_key_ids = trust_keys
    .iter()
    .filter(|(_, public_key)| {
      UnparsedPublicKey::new(&ED25519, public_key)
        .verify(canonical_payload.as_bytes(), &signature)
        .is_ok()
    })
    .map(|(key_id, _)| key_id.clone())
    .collect::<Vec<_>>();
  let [trust_key_id] = verified_key_ids.as_slice() else {
    return Err(preflight(if verified_key_ids.is_empty() {
      "scheduled_isolation_attestation_signature_invalid"
    } else {
      "scheduled_isolation_attestation_signature_ambiguous"
    }));
  };
  let attestation_id = payload
    .get("attestation_id")
    .and_then(Value::as_str)
    .ok_or_else(|| preflight("scheduled_isolation_attestation_id_missing"))?;
  decode_lowercase_hex(
    attestation_id,
    32,
    "scheduled_isolation_attestation_id_invalid",
  )?;
  let issued_at = payload
    .get("issued_at_unix_seconds")
    .and_then(Value::as_u64)
    .ok_or_else(|| preflight("scheduled_isolation_attestation_issued_at_invalid"))?;
  let expires_at = payload
    .get("expires_at_unix_seconds")
    .and_then(Value::as_u64)
    .ok_or_else(|| preflight("scheduled_isolation_attestation_expires_at_invalid"))?;
  let now = now_unix_seconds();
  if issued_at > now.saturating_add(ISOLATION_ATTESTATION_FUTURE_SKEW_SECONDS)
    || now.saturating_sub(issued_at) > ISOLATION_ATTESTATION_MAX_ISSUED_AGE_SECONDS
    || expires_at <= now
    || expires_at <= issued_at
    || expires_at.saturating_sub(issued_at) > ISOLATION_ATTESTATION_MAX_VALIDITY_SECONDS
  {
    return Err(preflight("scheduled_isolation_attestation_not_current"));
  }
  let profile_binding_digest = payload
    .get("profile_binding_digest")
    .and_then(Value::as_str)
    .ok_or_else(|| preflight("scheduled_isolation_profile_binding_missing"))?;
  if profile_binding_digest != isolation_profile_binding_digest(profile)? {
    return Err(preflight("scheduled_isolation_profile_binding_mismatch"));
  }
  let isolation_revision = payload
    .get("credential_isolation_revision")
    .and_then(Value::as_str)
    .filter(|value| !value.is_empty() && *value == value.trim())
    .ok_or_else(|| preflight("scheduled_isolation_revision_invalid"))?;
  if payload
    .get("negative_test_revision")
    .and_then(Value::as_str)
    != Some(NEGATIVE_TEST_REVISION)
  {
    return Err(preflight(
      "scheduled_isolation_negative_test_revision_mismatch",
    ));
  }
  Ok(ScheduledDeploymentAuthority {
    schema_version: 1,
    deployment_epoch,
    attestation_id: attestation_id.to_owned(),
    attestation_digest: sha256_hex(contents.as_bytes()),
    trust_key_id: trust_key_id.clone(),
    profile_digest: profile_binding_digest.to_owned(),
    github_mcp_access_auth_mode: profile.github_mcp_access_auth_mode.clone(),
    github_mcp_access_token_revision: profile.github_mcp_access_token_revision.clone(),
    isolation_revision: isolation_revision.to_owned(),
    issued_at_unix_seconds: issued_at,
    expires_at_unix_seconds: expires_at,
  })
}

fn has_exact_fields(object: &serde_json::Map<String, Value>, expected: &[&str]) -> bool {
  object.len() == expected.len() && expected.iter().all(|field| object.contains_key(*field))
}

fn isolation_trust_keys_for_epoch(
  contents: &str,
  deployment_epoch: i64,
) -> Result<Vec<(String, Vec<u8>)>, ScheduledFailure> {
  let bundle: Value = serde_json::from_str(contents)
    .map_err(|_| preflight("scheduled_isolation_trust_bundle_invalid_json"))?;
  if bundle.to_string().as_bytes() != contents.as_bytes() {
    return Err(preflight(
      "scheduled_isolation_trust_bundle_must_be_canonical_json",
    ));
  }
  let bundle = bundle
    .as_object()
    .filter(|object| has_exact_fields(object, &["keys", "schema_version"]))
    .ok_or_else(|| preflight("scheduled_isolation_trust_bundle_fields_mismatch"))?;
  if bundle.get("schema_version").and_then(Value::as_u64) != Some(1) {
    return Err(preflight(
      "scheduled_isolation_trust_bundle_version_mismatch",
    ));
  }
  let keys = bundle
    .get("keys")
    .and_then(Value::as_array)
    .filter(|keys| !keys.is_empty() && keys.len() <= MAX_ISOLATION_TRUST_KEYS)
    .ok_or_else(|| preflight("scheduled_isolation_trust_bundle_keys_invalid"))?;
  let mut key_ids = BTreeSet::new();
  let mut public_keys = BTreeSet::new();
  let mut valid = Vec::new();
  for key in keys {
    let key = key
      .as_object()
      .filter(|object| {
        has_exact_fields(
          object,
          &[
            "key_id",
            "not_after_deployment_epoch",
            "not_before_deployment_epoch",
            "public_key",
          ],
        )
      })
      .ok_or_else(|| preflight("scheduled_isolation_trust_bundle_key_fields_mismatch"))?;
    let key_id = key
      .get("key_id")
      .and_then(Value::as_str)
      .filter(|value| is_lowercase_hex(value, 64))
      .ok_or_else(|| preflight("scheduled_isolation_trust_bundle_key_id_invalid"))?;
    let public_key_hex = key
      .get("public_key")
      .and_then(Value::as_str)
      .ok_or_else(|| preflight("scheduled_isolation_trust_bundle_public_key_invalid"))?;
    let public_key = decode_lowercase_hex(
      public_key_hex,
      32,
      "scheduled_isolation_trust_bundle_public_key_invalid",
    )?;
    if key_id != sha256_hex(&public_key) {
      return Err(preflight(
        "scheduled_isolation_trust_bundle_key_id_mismatch",
      ));
    }
    if !key_ids.insert(key_id.to_owned()) || !public_keys.insert(public_key_hex.to_owned()) {
      return Err(preflight("scheduled_isolation_trust_bundle_duplicate_key"));
    }
    let not_before = key
      .get("not_before_deployment_epoch")
      .and_then(Value::as_u64)
      .and_then(|value| i64::try_from(value).ok())
      .filter(|value| *value > 0)
      .ok_or_else(|| preflight("scheduled_isolation_trust_bundle_not_before_invalid"))?;
    let not_after = match key.get("not_after_deployment_epoch") {
      Some(Value::Null) => None,
      Some(value) => Some(
        value
          .as_u64()
          .and_then(|value| i64::try_from(value).ok())
          .filter(|value| *value >= not_before)
          .ok_or_else(|| preflight("scheduled_isolation_trust_bundle_not_after_invalid"))?,
      ),
      None => {
        return Err(preflight(
          "scheduled_isolation_trust_bundle_not_after_invalid",
        ));
      }
    };
    if deployment_epoch >= not_before && not_after.is_none_or(|epoch| deployment_epoch <= epoch) {
      valid.push((key_id.to_owned(), public_key));
    }
  }
  if valid.is_empty() {
    return Err(preflight(
      "scheduled_isolation_trust_bundle_no_key_for_epoch",
    ));
  }
  Ok(valid)
}

fn isolation_profile_binding_digest(
  profile: &RequestedCapabilityProfile,
) -> Result<String, ScheduledFailure> {
  let path = |field: &'static str, value: &Path| {
    value
      .to_str()
      .map(str::to_owned)
      .ok_or_else(|| preflight(format!("{field}_must_be_utf8")))
  };
  let binding = json!({
    "app_server_schema_sha256": CODEX_APP_SERVER_SCHEMA_SHA256,
    "child_environment": {
      "LANG": CHILD_LOCALE,
      "LC_ALL": CHILD_LOCALE,
      "PATH": CHILD_PATH,
    },
    "codex_home": path("scheduled_codex_home", &profile.codex_home)?,
    "codex_program": path("scheduled_codex_program", &profile.codex_program)?,
    "codex_program_sha256": profile.codex_program_sha256,
    "codex_version": CODEX_CLI_VERSION,
    "config_revision": profile.config_revision,
    "config_sha256": profile.config_sha256,
    "credential_reference": profile.credential_reference,
    "credential_revision": profile.credential_revision,
    "cwd": path("scheduled_cwd", &profile.cwd)?,
    "execution_surface": {
      "approval_policy": "never",
      "dynamic_tools": false,
      "network_access": false,
      "sandbox": "read-only",
      "web_search": "disabled",
    },
    "github_mcp_artifact_sha256": profile.github_mcp_artifact_sha256,
    "github_mcp_access_auth_mode": profile.github_mcp_access_auth_mode,
    "github_mcp_access_token_revision": profile.github_mcp_access_token_revision,
    "github_mcp_endpoint_identity": profile.github_mcp_endpoint_identity,
    "github_mcp_url": profile.github_mcp_url,
    "github_mcp_version": GITHUB_MCP_SERVER_VERSION,
    "github_tools": EXPECTED_GITHUB_TOOLS,
    "gateway_image_digest": profile.gateway_image_digest,
    "negative_test_revision": NEGATIVE_TEST_REVISION,
    "permission_policy_revision": profile.permission_policy_revision,
    "runner_client_cert_public_key_fingerprint": profile.runner_client_cert_public_key_fingerprint,
    "runner_image_digest": profile.runner_image_digest,
    "runner_workload_identity": profile.runner_workload_identity,
  });
  Ok(sha256_hex(binding.to_string().as_bytes()))
}

fn decode_lowercase_hex(
  value: &str,
  expected_bytes: usize,
  error: &'static str,
) -> Result<Vec<u8>, ScheduledFailure> {
  if value.len() != expected_bytes.saturating_mul(2)
    || !value
      .bytes()
      .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
  {
    return Err(preflight(error));
  }
  value
    .as_bytes()
    .chunks_exact(2)
    .map(|pair| {
      let nibble = |byte| match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => unreachable!("validated lowercase hex"),
      };
      Ok((nibble(pair[0]) << 4) | nibble(pair[1]))
    })
    .collect()
}

fn is_lowercase_hex(value: &str, expected_len: usize) -> bool {
  value.len() == expected_len
    && value
      .bytes()
      .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_oci_sha256_digest(value: &str) -> bool {
  value
    .strip_prefix("sha256:")
    .is_some_and(|digest| is_lowercase_hex(digest, 64))
}

fn is_loopback_http_url(url: &str) -> bool {
  ["http://127.0.0.1:", "http://[::1]:", "http://localhost:"]
    .iter()
    .any(|prefix| url.starts_with(prefix))
    && url.ends_with("/mcp")
}

#[cfg_attr(
  not(test),
  allow(dead_code, reason = "reserved for the issue 09 deployment verifier")
)]
fn fixed_child_environment() -> [(&'static str, &'static str); 3] {
  [
    ("PATH", CHILD_PATH),
    ("LANG", CHILD_LOCALE),
    ("LC_ALL", CHILD_LOCALE),
  ]
}

fn require_non_empty(field: &str, value: &str) -> Result<(), ScheduledFailure> {
  if value.trim().is_empty() || value != value.trim() {
    return Err(preflight(format!("{field}_invalid")));
  }
  Ok(())
}

fn require_sha256(field: &str, value: &str) -> Result<(), ScheduledFailure> {
  if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
    return Err(preflight(format!("{field}_invalid")));
  }
  Ok(())
}

fn preflight(message: impl AsRef<str>) -> ScheduledFailure {
  ScheduledFailure::new(ScheduledFailureKind::InvalidRequest, message)
}

fn capability(message: impl AsRef<str>) -> ScheduledFailure {
  ScheduledFailure::new(ScheduledFailureKind::CapabilityMismatch, message)
}

fn output_violation(message: impl AsRef<str>) -> ScheduledFailure {
  ScheduledFailure::new(ScheduledFailureKind::OutputSchemaViolation, message)
}

fn protocol_failure(failure: ScheduledFailure) -> ScheduledExecutionResult {
  match failure.kind {
    ScheduledFailureKind::Interrupted => ScheduledExecutionResult::Interrupted {
      thread_id: None,
      turn_id: None,
    },
    ScheduledFailureKind::TimedOut => ScheduledExecutionResult::TransportLost(failure),
    _ => ScheduledExecutionResult::PreflightRejected(failure),
  }
}

fn transport_failure(message: impl AsRef<str>) -> ScheduledExecutionResult {
  ScheduledExecutionResult::TransportLost(ScheduledFailure::new(
    ScheduledFailureKind::Transport,
    message,
  ))
}

fn bounded(value: &str, max_bytes: usize) -> String {
  if value.len() <= max_bytes {
    return value.to_owned();
  }
  let mut boundary = max_bytes;
  while !value.is_char_boundary(boundary) {
    boundary -= 1;
  }
  format!("{}[truncated]", &value[..boundary])
}

fn sha256_hex(value: &[u8]) -> String {
  hex_encode(&Sha256::digest(value))
}

fn hex_encode(value: &[u8]) -> String {
  let mut output = String::with_capacity(64);
  for byte in value {
    use std::fmt::Write as _;
    write!(&mut output, "{byte:02x}").expect("write to string");
  }
  output
}

#[cfg_attr(
  not(test),
  allow(dead_code, reason = "reserved for the issue 09 deployment verifier")
)]
fn sha256_file(path: &Path) -> Result<String, String> {
  use std::io::Read;
  let mut file = fs::File::open(path)
    .map_err(|error| format!("open file for sha256 {}: {error}", path.display()))?;
  let mut digest = Sha256::new();
  let mut buffer = [0_u8; 8 * 1024];
  loop {
    let bytes = file
      .read(&mut buffer)
      .map_err(|error| format!("read file for sha256 {}: {error}", path.display()))?;
    if bytes == 0 {
      break;
    }
    digest.update(&buffer[..bytes]);
  }
  Ok(hex_encode(&digest.finalize()))
}

fn now_unix_seconds() -> u64 {
  SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .map_or(0, |duration| duration.as_secs())
}

#[cfg(test)]
fn issue_test_isolation_permit(request: &ScheduledCodexRequest) -> ScheduledIsolationPermit {
  static NEXT_TEST_NONCE: AtomicU64 = AtomicU64::new(1);
  ScheduledIsolationPermit {
    identity: request.identity.clone(),
    deployment_epoch: 1,
    attestation_id: "a".repeat(64),
    profile_digest: isolation_profile_binding_digest(&request.profile).expect("profile digest"),
    nonce: format!("{:064x}", NEXT_TEST_NONCE.fetch_add(1, Ordering::Relaxed)),
    permit_id: format!("{:064x}", NEXT_TEST_NONCE.fetch_add(1, Ordering::Relaxed)),
    isolation_revision: "test-only-process-isolation-v1".to_owned(),
    expires_at_unix_seconds: now_unix_seconds().saturating_add(TEST_PERMIT_TTL.as_secs()),
  }
}

fn validate_isolation_permit(
  permit: ScheduledIsolationPermit,
  request: &ScheduledCodexRequest,
) -> Result<ScheduledIsolationPermit, ScheduledFailure> {
  if permit.expires_at_unix_seconds <= now_unix_seconds()
    || permit.identity != request.identity
    || permit.profile_digest != isolation_profile_binding_digest(&request.profile)?
    || permit.deployment_epoch <= 0
    || !is_lowercase_hex(&permit.attestation_id, 64)
    || !is_lowercase_hex(&permit.nonce, 64)
    || !is_lowercase_hex(&permit.permit_id, 64)
    || permit.isolation_revision.trim().is_empty()
  {
    return Err(ScheduledFailure::new(
      ScheduledFailureKind::CredentialIsolationUnproven,
      "credential_isolation_permit_expired_or_mismatched",
    ));
  }
  Ok(permit)
}

#[cfg(test)]
mod tests {
  use std::collections::VecDeque;
  use std::os::unix::fs::MetadataExt;
  use std::sync::{Arc, Mutex};

  use codeoff_agent_contract::{InvocationPrincipal, SessionMode};
  use ring::rand::SystemRandom;
  use ring::signature::{Ed25519KeyPair, KeyPair};
  use tempfile::TempDir;

  use super::*;

  #[derive(Debug, Default)]
  struct Actions {
    writes: Vec<Value>,
    events: Vec<String>,
    close_count: usize,
    terminate_count: usize,
    kill_count: usize,
    reap_results: VecDeque<ProcessExit>,
  }

  struct MockTransport {
    evidence: ScheduledRuntimeEvidence,
    reads: VecDeque<TimedRead>,
    actions: Arc<Mutex<Actions>>,
  }

  impl JsonlTransport for MockTransport {
    fn write_json(&mut self, value: Value) -> Result<(), String> {
      let mut actions = self.actions.lock().expect("actions");
      actions.events.push(format!(
        "write:{}",
        value["method"].as_str().unwrap_or("response")
      ));
      actions.writes.push(value);
      Ok(())
    }

    fn read_json(&mut self) -> Result<Value, String> {
      Err("scheduled transport must use bounded reads".to_owned())
    }
  }

  impl ScheduledJsonlTransport for MockTransport {
    fn runtime_evidence(&self) -> &ScheduledRuntimeEvidence {
      &self.evidence
    }

    fn read_json_until(&mut self, _deadline: Instant) -> Result<TimedRead, String> {
      self
        .actions
        .lock()
        .expect("actions")
        .events
        .push("read".to_owned());
      Ok(self.reads.pop_front().unwrap_or(TimedRead::TimedOut))
    }

    fn close_stdin(&mut self) -> Result<(), String> {
      let mut actions = self.actions.lock().expect("actions");
      actions.close_count += 1;
      actions.events.push("close".to_owned());
      Ok(())
    }

    fn terminate_process_group(&mut self) -> Result<(), String> {
      let mut actions = self.actions.lock().expect("actions");
      actions.terminate_count += 1;
      actions.events.push("term".to_owned());
      Ok(())
    }

    fn kill_process_group(&mut self) -> Result<(), String> {
      let mut actions = self.actions.lock().expect("actions");
      actions.kill_count += 1;
      actions.events.push("kill".to_owned());
      Ok(())
    }

    fn reap_until(&mut self, _deadline: Instant) -> Result<ProcessExit, String> {
      let mut actions = self.actions.lock().expect("actions");
      actions.events.push("wait_group".to_owned());
      Ok(
        actions
          .reap_results
          .pop_front()
          .unwrap_or(ProcessExit::Exited),
      )
    }
  }

  fn profile() -> RequestedCapabilityProfile {
    let mut profile = RequestedCapabilityProfile {
      codex_program: PathBuf::from("/usr/local/bin/codex"),
      codex_program_sha256: "a".repeat(64),
      codex_home: PathBuf::from("/var/lib/codeoff-scheduled/codex-home"),
      cwd: PathBuf::from("/var/lib/codeoff-scheduled/workspace"),
      github_mcp_url: "http://127.0.0.1:18081/mcp".to_owned(),
      github_mcp_artifact_sha256: GITHUB_MCP_ARTIFACT_SHA256_X86_64.to_owned(),
      github_mcp_endpoint_identity: "github-readonly-sidecar".to_owned(),
      github_mcp_access_auth_mode: GITHUB_MCP_ACCESS_AUTH_MODE.to_owned(),
      github_mcp_access_token_revision: "mcp-channel-v1".to_owned(),
      credential_reference: "github-readonly-service-account".to_owned(),
      permission_policy_revision: "github-issues-read-v1".to_owned(),
      config_revision: "scheduled-codex-v1".to_owned(),
      config_sha256: String::new(),
      gateway_image_digest: format!("sha256:{}", "e".repeat(64)),
      runner_image_digest: format!("sha256:{}", "f".repeat(64)),
      runner_workload_identity: "spiffe://codeoff/runner/production".to_owned(),
      runner_client_cert_public_key_fingerprint: "1".repeat(64),
      credential_revision: "github-readonly-2026-07".to_owned(),
    };
    profile.config_sha256 = sha256_hex(profile.dedicated_config().as_bytes());
    profile
  }

  fn remote_config(profile: &RequestedCapabilityProfile) -> ScheduledCodexConfig {
    ScheduledCodexConfig {
      execution_backend: codeoff_config::ScheduledExecutionBackend::default(),
      remote_runner: codeoff_config::ScheduledRemoteRunnerConfig::default(),
      codex_program: profile.codex_program.clone(),
      codex_program_sha256: profile.codex_program_sha256.clone(),
      codex_home: profile.codex_home.clone(),
      cwd: profile.cwd.clone(),
      github_mcp_url: profile.github_mcp_url.clone(),
      github_mcp_artifact_path: "/opt/codeoff/bin/github-mcp-server".into(),
      github_mcp_artifact_sha256: profile.github_mcp_artifact_sha256.clone(),
      github_mcp_endpoint_identity: profile.github_mcp_endpoint_identity.clone(),
      github_mcp_access_auth_mode: profile.github_mcp_access_auth_mode.clone(),
      github_mcp_access_token_revision: profile.github_mcp_access_token_revision.clone(),
      credential_reference: profile.credential_reference.clone(),
      permission_policy_revision: profile.permission_policy_revision.clone(),
      config_revision: profile.config_revision.clone(),
      config_sha256: profile.config_sha256.clone(),
      gateway_image_digest: profile.gateway_image_digest.clone(),
      runner_image_digest: profile.runner_image_digest.clone(),
      runner_workload_identity: profile.runner_workload_identity.clone(),
      runner_client_cert_public_key_fingerprint: profile
        .runner_client_cert_public_key_fingerprint
        .clone(),
      credential_revision: profile.credential_revision.clone(),
      isolation_attestation_path: "/var/run/codeoff/isolation-attestation.json".into(),
      isolation_trust_bundle_path: "/opt/codeoff/attestation/isolation-trust-bundle.json".into(),
      trusted_owner_uid: 0,
      trusted_owner_gid: 0,
      runtime_uid: 65_534,
      runtime_gid: 65_534,
    }
  }

  fn evidence(profile: &RequestedCapabilityProfile) -> ScheduledRuntimeEvidence {
    ScheduledRuntimeEvidence {
      codex_version: CODEX_CLI_VERSION.to_owned(),
      app_server_schema_sha256: CODEX_APP_SERVER_SCHEMA_SHA256.to_owned(),
      codex_program_sha256: profile.codex_program_sha256.clone(),
      config_sha256: profile.config_sha256.clone(),
      runner_image_digest: profile.runner_image_digest.clone(),
    }
  }

  fn task() -> AgentTask {
    AgentTask {
      task_id: "task-1".to_owned(),
      instruction: "Inspect GitHub issues".to_owned(),
      source: InvocationSource::ScheduledRun {
        job_id: "job-1".to_owned(),
        run_id: "run-1".to_owned(),
        scheduled_for: "2026-07-21T20:00:00Z".to_owned(),
      },
      principal: InvocationPrincipal::service("scheduler"),
      session: SessionMode::Fresh,
      channel: None,
      previous_success: None,
      tool_policy: ToolPolicy::None,
      feedback_target: None,
    }
  }

  fn request(profile: RequestedCapabilityProfile) -> ScheduledCodexRequest {
    ScheduledCodexRequest {
      task: task(),
      identity: ScheduledExecutionIdentity {
        run_id: "run-1".to_owned(),
        job_id: "job-1".to_owned(),
        attempt: 1,
        fence: 1,
      },
      profile,
      cancellation: Arc::new(AtomicBool::new(false)),
      timeout: Duration::from_secs(30),
      interrupt_grace: Duration::from_secs(2),
      terminate_grace: Duration::from_secs(2),
      kill_grace: Duration::from_secs(2),
    }
  }

  fn response(id: u64, result: Value) -> TimedRead {
    let mut message = json!({"jsonrpc": "2.0", "id": id});
    message["result"] = result;
    TimedRead::Message(message)
  }

  fn signing_key() -> Ed25519KeyPair {
    let key = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("generate signing key");
    Ed25519KeyPair::from_pkcs8(key.as_ref()).expect("parse signing key")
  }

  fn lowercase_hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut output, byte| {
      use std::fmt::Write as _;
      write!(output, "{byte:02x}").expect("write hex");
      output
    })
  }

  fn isolation_trust_bundle(keys: &[(&Ed25519KeyPair, i64, Option<i64>)]) -> String {
    let keys = keys
      .iter()
      .map(|(key, not_before, not_after)| {
        let public_key = lowercase_hex(key.public_key().as_ref());
        json!({
          "key_id": sha256_hex(key.public_key().as_ref()),
          "not_after_deployment_epoch": not_after,
          "not_before_deployment_epoch": not_before,
          "public_key": public_key,
        })
      })
      .collect::<Vec<_>>();
    json!({"keys": keys, "schema_version": 1}).to_string()
  }

  fn isolation_payload(profile: &RequestedCapabilityProfile) -> Value {
    let now = now_unix_seconds();
    json!({
      "schema_version": ISOLATION_ATTESTATION_SCHEMA_VERSION,
      "deployment_epoch": 1,
      "attestation_id": "ab".repeat(32),
      "issued_at_unix_seconds": now.saturating_sub(1),
      "expires_at_unix_seconds": now.saturating_add(300),
      "profile_binding_digest": isolation_profile_binding_digest(profile).expect("binding"),
      "credential_isolation_revision": "deployment-isolation-v1",
      "negative_test_revision": NEGATIVE_TEST_REVISION,
    })
  }

  fn write_signed_attestation(temp: &TempDir, key: &Ed25519KeyPair, payload: &Value) -> PathBuf {
    let canonical_payload = payload.to_string();
    let document = json!({
      "payload": payload,
      "signature_algorithm": "ed25519",
      "signature": lowercase_hex(key.sign(canonical_payload.as_bytes()).as_ref()),
    });
    let path = temp.path().join("isolation-attestation.json");
    fs::write(&path, document.to_string()).expect("write attestation");
    path
  }

  fn inventory() -> Value {
    let tools = EXPECTED_GITHUB_TOOLS
      .iter()
      .map(|name| {
        (
          (*name).to_owned(),
          json!({
            "name": name,
            "inputSchema": {"type": "object"},
            "annotations": {"readOnlyHint": true},
          }),
        )
      })
      .collect::<serde_json::Map<_, _>>();
    json!({
      "data": [{
        "name": GITHUB_MCP_NAME,
        "authStatus": "bearerToken",
        "serverInfo": {"name": GITHUB_MCP_SERVER_INFO_NAME, "version": GITHUB_MCP_SERVER_VERSION},
        "tools": tools,
        "resources": [],
        "resourceTemplates": [],
      }],
      "nextCursor": null,
    })
  }

  fn health() -> Value {
    json!({
      "content": [{"type": "text", "text": "authenticated as codeoff-test"}],
      "isError": false,
      "structuredContent": {"login": "codeoff-test"},
    })
  }

  fn successful_reads() -> VecDeque<TimedRead> {
    VecDeque::from([
      response(1, json!({"server": "codex-app-server"})),
      response(2, json!({"thread": {"id": "thread-1"}})),
      response(3, inventory()),
      response(4, health()),
      response(5, json!({"turn": {"id": "turn-1"}})),
      TimedRead::Message(json!({
        "jsonrpc": "2.0",
        "method": "item/completed",
        "params": {
          "threadId": "thread-1",
          "turnId": "turn-1",
          "item": {"type": "agentMessage", "phase": "commentary", "text": "Working"},
        }
      })),
      TimedRead::Message(json!({
        "jsonrpc": "2.0",
        "method": "turn/completed",
        "params": {
          "threadId": "thread-1",
          "turn": {
            "id": "turn-1",
            "status": "completed",
            "usage": {"inputTokens": 10, "cachedInputTokens": 2, "outputTokens": 3},
            "items": [
              {"type": "agentMessage", "phase": "final_answer", "text": "{\"schema_version\":1,\"summary\":\"First\"}"},
              {"type": "agentMessage", "phase": "final_answer", "text": "{\"schema_version\":1,\"summary\":\"Last\"}"}
            ]
          }
        }
      })),
    ])
  }

  fn reads_with_final_text(text: &str) -> VecDeque<TimedRead> {
    let mut reads = successful_reads();
    reads[6] = TimedRead::Message(json!({
      "jsonrpc": "2.0",
      "method": "turn/completed",
      "params": {
        "threadId": "thread-1",
        "turn": {
          "id": "turn-1",
          "status": "completed",
          "items": [{"type": "agentMessage", "phase": "final_answer", "text": text}],
        }
      }
    }));
    reads
  }

  fn executor_for(
    transport: MockTransport,
    _request: &ScheduledCodexRequest,
  ) -> ScheduledCodexExecutor<
    impl Fn(RequestedCapabilityProfile) -> Result<MockTransport, String> + use<>,
  > {
    let transport = Arc::new(Mutex::new(Some(transport)));
    ScheduledCodexExecutor::new(move |_| {
      transport
        .lock()
        .expect("transport")
        .take()
        .ok_or_else(|| "mock transport already used".to_owned())
    })
  }

  fn execute_test<F, T>(
    executor: &ScheduledCodexExecutor<F>,
    request: ScheduledCodexRequest,
  ) -> ScheduledExecutionResult
  where
    F: Fn(RequestedCapabilityProfile) -> Result<T, String> + Send + Sync,
    T: ScheduledJsonlTransport + Send + 'static,
  {
    let permit = issue_test_isolation_permit(&request);
    executor.execute(request, permit)
  }

  #[allow(
    clippy::result_large_err,
    reason = "the test helper preserves the production trait result without lossy conversion"
  )]
  fn prepare_test<F, T>(
    executor: &ScheduledCodexExecutor<F>,
    request: ScheduledCodexRequest,
  ) -> Result<Box<dyn PreparedScheduledCodexExecution>, ScheduledExecutionResult>
  where
    F: Fn(RequestedCapabilityProfile) -> Result<T, String> + Send + Sync,
    T: ScheduledJsonlTransport + Send + 'static,
  {
    let permit = issue_test_isolation_permit(&request);
    executor.prepare(request, permit)
  }

  #[test]
  fn scheduled_execution_attests_before_turn_and_selects_last_final_answer() {
    let profile = profile();
    let actions = Arc::new(Mutex::new(Actions::default()));
    let transport = MockTransport {
      evidence: evidence(&profile),
      reads: successful_reads(),
      actions: Arc::clone(&actions),
    };
    let request = request(profile);
    let executor = executor_for(transport, &request);
    let result = execute_test(&executor, request);
    let ScheduledExecutionResult::Completed {
      output,
      usage,
      attested_profile,
      ..
    } = result
    else {
      panic!("unexpected result: {result:?}");
    };
    assert_eq!(output.schema_version, OUTPUT_SCHEMA_VERSION);
    assert_eq!(output.summary, "Last");
    assert_eq!(usage.input, Some(10));
    assert!(!attested_profile.profile_sha256.is_empty());
    assert_eq!(
      attested_profile.github_mcp_access_auth_mode,
      GITHUB_MCP_ACCESS_AUTH_MODE
    );
    assert_eq!(
      attested_profile.github_mcp_access_token_revision,
      "mcp-channel-v1"
    );
    assert_eq!(
      attested_profile.github_mcp_health_checked_at_unix_seconds,
      attested_profile.attested_at_unix_seconds
    );
    assert_eq!(
      attested_profile.github_mcp_health_credential_revision,
      attested_profile.credential_revision
    );
    assert_eq!(
      attested_profile.github_mcp_health_result_sha256,
      sha256_hex(health().to_string().as_bytes())
    );
    let writes = &actions.lock().expect("actions").writes;
    let methods: Vec<_> = writes
      .iter()
      .filter_map(|message| message["method"].as_str())
      .collect();
    let thread_start = writes
      .iter()
      .find(|message| message["method"] == "thread/start")
      .expect("thread start request");
    assert_eq!(
      thread_start["params"]["config"]["shell_environment_policy"],
      json!({
        "inherit": "none",
        "ignore_default_excludes": false,
        "exclude": [GITHUB_MCP_ACCESS_TOKEN_ENV],
        "include_only": ["PATH", "LANG", "LC_ALL"],
        "set": {
          "PATH": CHILD_PATH,
          "LANG": CHILD_LOCALE,
          "LC_ALL": CHILD_LOCALE,
        },
      })
    );
    assert_eq!(
      methods,
      [
        "initialize",
        "initialized",
        "thread/start",
        "mcpServerStatus/list",
        "mcpServer/tool/call",
        "turn/start"
      ]
    );
    let turn = writes
      .iter()
      .find(|message| message["method"] == "turn/start")
      .expect("turn request");
    assert_eq!(turn["params"]["approvalPolicy"], "never");
    assert_eq!(
      turn["params"]["sandboxPolicy"],
      json!({"type": "readOnly", "networkAccess": false})
    );
    assert_eq!(turn["params"]["outputSchema"], fixed_output_schema());
  }

  #[test]
  fn production_executor_without_internal_issuer_rejects_before_transport() {
    let profile = profile();
    let executor = ScheduledCodexExecutor::new(
      |_: RequestedCapabilityProfile| -> Result<MockTransport, String> {
        panic!("disabled production executor must not start transport")
      },
    );
    let request = request(profile);
    let mut permit = issue_test_isolation_permit(&request);
    permit.profile_digest = "0".repeat(64);
    let result = executor.execute(request, permit);
    assert!(matches!(
      result,
      ScheduledExecutionResult::PreflightRejected(ScheduledFailure {
        kind: ScheduledFailureKind::CredentialIsolationUnproven,
        ..
      })
    ));
  }

  #[test]
  fn production_profile_round_trips_remote_v3_recovery_contract() {
    let requested = profile();
    let scheduled_request = request(requested.clone());
    let permit = issue_test_isolation_permit(&scheduled_request);
    let mut observed = attest_runtime(&requested, &evidence(&requested), permit)
      .expect("production attested profile");
    observed.github_mcp_health_checked_at_unix_seconds = observed.attested_at_unix_seconds;
    observed.github_mcp_health_credential_revision = observed.credential_revision.clone();
    observed.github_mcp_health_result_sha256 = "8".repeat(64);
    observed.profile_sha256 = observed.computed_profile_sha256();
    observed.validate().expect("canonical profile");
    let authority =
      codeoff_state::ScheduledPrepareAuthority::for_remote_session_test("run-1", "job-1", 1, 1);
    let deployment_digest = "9".repeat(64);
    let recovery = authority
      .remote_recovery_attestation_json(&observed.canonical_json(), &deployment_digest, 1)
      .expect("remote v3 recovery");
    assert!(authority.remote_recovery_attestation_matches(
      &recovery,
      &sha256_hex(recovery.as_bytes()),
      &deployment_digest,
      1,
    ));
  }

  #[test]
  fn production_executor_requires_the_observed_unprivileged_runtime_identity() {
    let mut profile = profile();
    profile.runner_workload_identity = "spiffe://codeoff/runner/fake".to_owned();
    profile.runner_client_cert_public_key_fingerprint = "9".repeat(64);
    let config = remote_config(&profile);
    let Err(failure) = build_production_scheduled_codex_executor(&config) else {
      panic!("configured values cannot replace the observed process identity");
    };
    assert_eq!(
      failure.message,
      "scheduled_artifact_verification_failed:scheduled_runtime_identity_mismatch"
    );
  }

  #[test]
  fn remote_permit_envelope_is_canonical_redacted_and_exactly_session_bound() {
    let scheduled_request = request(profile());
    let permit = issue_test_isolation_permit(&scheduled_request);
    let authority = ScheduledDeploymentAuthority {
      schema_version: 1,
      deployment_epoch: permit.deployment_epoch,
      attestation_id: permit.attestation_id.clone(),
      attestation_digest: "b".repeat(64),
      trust_key_id: "c".repeat(64),
      profile_digest: permit.profile_digest.clone(),
      github_mcp_access_auth_mode: scheduled_request
        .profile
        .github_mcp_access_auth_mode
        .clone(),
      github_mcp_access_token_revision: scheduled_request
        .profile
        .github_mcp_access_token_revision
        .clone(),
      isolation_revision: permit.isolation_revision.clone(),
      issued_at_unix_seconds: now_unix_seconds().saturating_sub(1),
      expires_at_unix_seconds: permit.expires_at_unix_seconds,
    };
    let authority_digest = "d".repeat(64);
    let session_nonce = "e".repeat(64);
    let envelope = permit
      .into_remote_envelope(
        &authority_digest,
        &scheduled_request.profile.credential_revision,
        &session_nonce,
      )
      .expect("remote envelope");
    assert!(!format!("{envelope:?}").contains(&authority_digest));
    let imported = RemoteIsolationPermitEnvelope::import(
      envelope.as_json(),
      &authority,
      &scheduled_request.identity,
      &authority_digest,
      &scheduled_request.profile.credential_revision,
      &session_nonce,
    )
    .expect("exact session import");
    assert_eq!(imported.identity, scheduled_request.identity);

    assert!(
      RemoteIsolationPermitEnvelope::import(
        envelope.as_json(),
        &authority,
        &scheduled_request.identity,
        &authority_digest,
        &scheduled_request.profile.credential_revision,
        &"f".repeat(64),
      )
      .is_err()
    );
    let noncanonical = envelope.as_json().replace('{', "{ ");
    assert!(
      RemoteIsolationPermitEnvelope::import(
        &noncanonical,
        &authority,
        &scheduled_request.identity,
        &authority_digest,
        &scheduled_request.profile.credential_revision,
        &session_nonce,
      )
      .is_err()
    );
  }

  #[test]
  fn test_isolation_permit_is_exactly_bound_and_expiring() {
    let profile = profile();
    let scheduled_request = request(profile.clone());
    let first_nonce = issue_test_isolation_permit(&scheduled_request).nonce;
    let second_nonce = issue_test_isolation_permit(&scheduled_request).nonce;
    assert_ne!(first_nonce, second_nonce);

    let original = request(profile.clone());
    let executor = ScheduledCodexExecutor::new(
      |_: RequestedCapabilityProfile| -> Result<MockTransport, String> {
        panic!("mismatched permit must not start transport")
      },
    );
    let mut mismatched_permit = issue_test_isolation_permit(&original);
    mismatched_permit.identity.run_id = "different-run".to_owned();
    assert!(matches!(
      executor.execute(original, mismatched_permit),
      ScheduledExecutionResult::PreflightRejected(ScheduledFailure {
        kind: ScheduledFailureKind::CredentialIsolationUnproven,
        ..
      })
    ));

    let expired_request = request(profile);
    let mut expired_permit = issue_test_isolation_permit(&expired_request);
    expired_permit.expires_at_unix_seconds = now_unix_seconds();
    let executor = ScheduledCodexExecutor::new(
      |_: RequestedCapabilityProfile| -> Result<MockTransport, String> {
        panic!("expired permit must not start transport")
      },
    );
    assert!(matches!(
      executor.execute(expired_request, expired_permit),
      ScheduledExecutionResult::PreflightRejected(ScheduledFailure {
        kind: ScheduledFailureKind::CredentialIsolationUnproven,
        ..
      })
    ));
  }

  #[test]
  fn signed_isolation_attestation_accepts_only_current_exact_profile() {
    let profile = profile();
    let key = signing_key();
    let trust_bundle = isolation_trust_bundle(&[(&key, 1, None)]);
    let temp = TempDir::new().expect("tempdir");

    let path = write_signed_attestation(&temp, &key, &isolation_payload(&profile));
    let authority = load_signed_isolation_authority(&profile, &path, &trust_bundle)
      .expect("valid signed attestation");
    assert_eq!(authority.deployment_epoch, 1);
    assert_eq!(
      authority.github_mcp_access_auth_mode,
      profile.github_mcp_access_auth_mode
    );
    assert_eq!(
      authority.github_mcp_access_token_revision,
      profile.github_mcp_access_token_revision
    );

    let mut other_profile = profile.clone();
    other_profile.github_mcp_endpoint_identity = "different-endpoint".to_owned();
    let path = write_signed_attestation(&temp, &key, &isolation_payload(&other_profile));
    let failure = load_signed_isolation_authority(&profile, &path, &trust_bundle)
      .expect_err("mismatched profile must fail");
    assert_eq!(
      failure.message,
      "scheduled_isolation_profile_binding_mismatch"
    );

    for mutation in ["auth-mode", "token-revision"] {
      let mut other_profile = profile.clone();
      match mutation {
        "auth-mode" => other_profile.github_mcp_access_auth_mode = "legacy-bearer".to_owned(),
        "token-revision" => {
          other_profile.github_mcp_access_token_revision = "mcp-channel-v0".to_owned();
        }
        _ => unreachable!(),
      }
      let path = write_signed_attestation(&temp, &key, &isolation_payload(&other_profile));
      let failure = load_signed_isolation_authority(&profile, &path, &trust_bundle)
        .expect_err("MCP access authority mutation must fail");
      assert_eq!(
        failure.message, "scheduled_isolation_profile_binding_mismatch",
        "mutation={mutation}"
      );
    }

    let now = now_unix_seconds();
    let mut expired = isolation_payload(&profile);
    expired["issued_at_unix_seconds"] = json!(now.saturating_sub(10));
    expired["expires_at_unix_seconds"] = json!(now.saturating_sub(1));
    let path = write_signed_attestation(&temp, &key, &expired);
    assert!(load_signed_isolation_authority(&profile, &path, &trust_bundle).is_err());
  }

  #[test]
  fn signed_isolation_attestation_rejects_stale_future_and_overlong_windows() {
    let profile = profile();
    let key = signing_key();
    let trust_bundle = isolation_trust_bundle(&[(&key, 1, None)]);
    let temp = TempDir::new().expect("tempdir");
    let now = now_unix_seconds();
    let cases = [
      (
        now.saturating_sub(ISOLATION_ATTESTATION_MAX_ISSUED_AGE_SECONDS + 1),
        now.saturating_add(30),
      ),
      (
        now.saturating_add(ISOLATION_ATTESTATION_FUTURE_SKEW_SECONDS + 1),
        now.saturating_add(ISOLATION_ATTESTATION_FUTURE_SKEW_SECONDS + 60),
      ),
      (
        now.saturating_sub(1),
        now.saturating_add(ISOLATION_ATTESTATION_MAX_VALIDITY_SECONDS + 1),
      ),
    ];
    for (issued_at, expires_at) in cases {
      let mut payload = isolation_payload(&profile);
      payload["issued_at_unix_seconds"] = json!(issued_at);
      payload["expires_at_unix_seconds"] = json!(expires_at);
      let path = write_signed_attestation(&temp, &key, &payload);
      assert!(load_signed_isolation_authority(&profile, &path, &trust_bundle).is_err());
    }
  }

  #[test]
  fn isolation_trust_bundle_enforces_rotation_epochs_and_overlap() {
    let profile = profile();
    let old_key = signing_key();
    let new_key = signing_key();
    let trust_bundle = isolation_trust_bundle(&[(&old_key, 1, Some(2)), (&new_key, 2, None)]);
    let temp = TempDir::new().expect("tempdir");
    let cases = [
      (1, &old_key, true),
      (1, &new_key, false),
      (2, &old_key, true),
      (2, &new_key, true),
      (3, &old_key, false),
      (3, &new_key, true),
    ];
    for (epoch, key, accepted) in cases {
      let mut payload = isolation_payload(&profile);
      payload["deployment_epoch"] = json!(epoch);
      let path = write_signed_attestation(&temp, key, &payload);
      let result = load_signed_isolation_authority(&profile, &path, &trust_bundle);
      assert_eq!(
        result.is_ok(),
        accepted,
        "epoch={epoch} accepted={accepted}"
      );
      if let Ok(authority) = result {
        assert_eq!(
          authority.trust_key_id,
          sha256_hex(key.public_key().as_ref())
        );
      }
    }
  }

  #[test]
  fn isolation_trust_bundle_rejects_unknown_duplicate_and_mismatched_keys() {
    let profile = profile();
    let key = signing_key();
    let temp = TempDir::new().expect("tempdir");
    let path = write_signed_attestation(&temp, &key, &isolation_payload(&profile));
    let valid = isolation_trust_bundle(&[(&key, 1, None)]);

    let mut unknown: Value = serde_json::from_str(&valid).expect("parse bundle");
    unknown["unexpected"] = json!(true);
    assert!(load_signed_isolation_authority(&profile, &path, &unknown.to_string()).is_err());

    let mut duplicate: Value = serde_json::from_str(&valid).expect("parse bundle");
    let duplicate_key = duplicate["keys"][0].clone();
    duplicate["keys"]
      .as_array_mut()
      .expect("keys")
      .push(duplicate_key);
    assert!(load_signed_isolation_authority(&profile, &path, &duplicate.to_string()).is_err());

    let mut mismatched: Value = serde_json::from_str(&valid).expect("parse bundle");
    mismatched["keys"][0]["key_id"] = json!("0".repeat(64));
    assert!(load_signed_isolation_authority(&profile, &path, &mismatched.to_string()).is_err());
  }

  #[cfg(unix)]
  #[test]
  fn production_components_accept_exact_protected_signed_profile() {
    let temp = TempDir::new_in("/code/helixbox").expect("tempdir");
    let codex_program = temp.path().join("codex");
    fs::write(&codex_program, "#!/bin/sh\nprintf 'codex-cli 0.144.6\\n'\n")
      .expect("write codex probe");
    fs::set_permissions(&codex_program, fs::Permissions::from_mode(0o555))
      .expect("protect codex probe");
    let github_mcp_artifact = temp.path().join("github-mcp-server");
    fs::write(&github_mcp_artifact, "test github mcp artifact").expect("write github MCP artifact");
    fs::set_permissions(&github_mcp_artifact, fs::Permissions::from_mode(0o555))
      .expect("protect github MCP artifact");
    let codex_home = temp.path().join("codex-home");
    let cwd = temp.path().join("workspace");
    fs::create_dir(&cwd).expect("create workspace");
    fs::set_permissions(&cwd, fs::Permissions::from_mode(0o555)).expect("protect workspace");
    let attestation_path = temp.path().join("isolation-attestation.json");
    let key = signing_key();
    let trust_bundle_path = temp.path().join("isolation-trust-bundle.json");
    fs::write(
      &trust_bundle_path,
      isolation_trust_bundle(&[(&key, 1, None)]),
    )
    .expect("write trust bundle");
    fs::set_permissions(&trust_bundle_path, fs::Permissions::from_mode(0o444))
      .expect("protect trust bundle");
    let mut config = ScheduledCodexConfig {
      execution_backend: codeoff_config::ScheduledExecutionBackend::default(),
      remote_runner: codeoff_config::ScheduledRemoteRunnerConfig::default(),
      codex_program: codex_program.clone(),
      codex_program_sha256: sha256_file(&codex_program).expect("program digest"),
      codex_home: codex_home.clone(),
      cwd,
      github_mcp_url: "http://127.0.0.1:18081/mcp".to_owned(),
      github_mcp_artifact_path: github_mcp_artifact.clone(),
      github_mcp_artifact_sha256: sha256_file(&github_mcp_artifact).expect("MCP digest"),
      github_mcp_endpoint_identity: "github-readonly-sidecar".to_owned(),
      github_mcp_access_auth_mode: GITHUB_MCP_ACCESS_AUTH_MODE.to_owned(),
      github_mcp_access_token_revision: "mcp-channel-v1".to_owned(),
      credential_reference: "github-readonly-service-account".to_owned(),
      permission_policy_revision: "github-issues-read-v1".to_owned(),
      config_revision: "scheduled-codex-v1".to_owned(),
      config_sha256: String::new(),
      gateway_image_digest: format!("sha256:{}", "e".repeat(64)),
      runner_image_digest: format!("sha256:{}", "f".repeat(64)),
      runner_workload_identity: "spiffe://codeoff/runner/production".to_owned(),
      runner_client_cert_public_key_fingerprint: "1".repeat(64),
      credential_revision: "github-readonly-2026-07".to_owned(),
      isolation_attestation_path: attestation_path.clone(),
      isolation_trust_bundle_path: trust_bundle_path,
      trusted_owner_uid: fs::metadata(&codex_program)
        .expect("program metadata")
        .uid(),
      trusted_owner_gid: fs::metadata(&codex_program)
        .expect("program metadata")
        .gid(),
      runtime_uid: 65_534,
      runtime_gid: 65_534,
    };
    let mut requested = requested_profile(&config);
    config.config_sha256 = sha256_hex(requested.dedicated_config().as_bytes());
    requested.config_sha256.clone_from(&config.config_sha256);
    prepare_scheduled_codex_home(&requested).expect("prepare codex home");
    write_signed_attestation(&temp, &key, &isolation_payload(&requested));
    fs::set_permissions(&attestation_path, fs::Permissions::from_mode(0o444))
      .expect("protect attestation");
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o555)).expect("protect tempdir");

    let artifacts = Arc::new(
      verify_scheduled_artifacts_for_test(&config, &requested).expect("verified artifacts"),
    );
    verify_codex_version(&artifacts, None).expect("version probe");
    let authority = load_signed_isolation_authority_contents(
      &requested,
      &artifacts.attestation_contents,
      &artifacts.trust_bundle_contents,
    )
    .expect("signed authority");
    assert_eq!(authority.deployment_epoch, 1);

    for mutation in ["gateway_image", "runner_image", "credential_revision"] {
      let mut replayed = requested.clone();
      match mutation {
        "gateway_image" => replayed.gateway_image_digest = format!("sha256:{}", "a".repeat(64)),
        "runner_image" => replayed.runner_image_digest = format!("sha256:{}", "b".repeat(64)),
        "credential_revision" => {
          replayed.credential_revision = "github-readonly-rotated".to_owned();
        }
        _ => unreachable!(),
      }
      let failure = load_signed_isolation_authority_contents(
        &replayed,
        &artifacts.attestation_contents,
        &artifacts.trust_bundle_contents,
      )
      .expect_err("attestation replay against changed deployment identity must fail");
      assert_eq!(
        failure.message,
        "scheduled_isolation_profile_binding_mismatch"
      );
    }
  }

  #[test]
  fn signed_isolation_attestation_rejects_bad_signature_and_legacy_or_unknown_shapes() {
    let profile = profile();
    let key = signing_key();
    let trust_bundle = isolation_trust_bundle(&[(&key, 1, None)]);
    let temp = TempDir::new().expect("tempdir");

    let path = write_signed_attestation(&temp, &key, &isolation_payload(&profile));
    let mut bad_signature: Value =
      serde_json::from_str(&fs::read_to_string(&path).expect("read attestation"))
        .expect("parse attestation");
    bad_signature["signature"] = json!("00".repeat(64));
    fs::write(&path, bad_signature.to_string()).expect("write bad signature");
    assert!(load_signed_isolation_authority(&profile, &path, &trust_bundle).is_err());

    let mut legacy = isolation_payload(&profile);
    legacy["schema_version"] = json!(0);
    let path = write_signed_attestation(&temp, &key, &legacy);
    assert!(load_signed_isolation_authority(&profile, &path, &trust_bundle).is_err());

    let mut unknown = isolation_payload(&profile);
    unknown["unexpected"] = json!(true);
    let path = write_signed_attestation(&temp, &key, &unknown);
    assert!(load_signed_isolation_authority(&profile, &path, &trust_bundle).is_err());
  }

  #[test]
  fn malformed_mismatched_and_oversize_final_outputs_are_rejected() {
    let oversized = format!(
      "{{\"schema_version\":1,\"summary\":\"{}\"}}",
      "x".repeat(MAX_FINAL_SUMMARY_BYTES + 1)
    );
    for text in [
      "not-json".to_owned(),
      "{\"schema_version\":2,\"summary\":\"wrong version\"}".to_owned(),
      "{\"schema_version\":1,\"summary\":\"ok\",\"extra\":true}".to_owned(),
      "{\"schema_version\":1,\"summary\":\"   \"}".to_owned(),
      oversized,
    ] {
      let profile = profile();
      let transport = MockTransport {
        evidence: evidence(&profile),
        reads: reads_with_final_text(&text),
        actions: Arc::new(Mutex::new(Actions::default())),
      };
      let request = request(profile);
      assert!(matches!(
        execute_test(&executor_for(transport, &request), request),
        ScheduledExecutionResult::Failed(ScheduledFailure {
          kind: ScheduledFailureKind::OutputSchemaViolation,
          ..
        })
      ));
    }
  }

  #[test]
  fn cumulative_final_answer_deltas_are_bounded() {
    let profile = profile();
    let reads = VecDeque::from([
      response(1, json!({"server": "codex-app-server"})),
      response(2, json!({"thread": {"id": "thread-1"}})),
      response(3, inventory()),
      response(4, health()),
      response(5, json!({"turn": {"id": "turn-1"}})),
      TimedRead::Message(json!({
        "jsonrpc": "2.0",
        "method": "item/started",
        "params": {
          "threadId": "thread-1",
          "turnId": "turn-1",
          "item": {"id": "final-1", "type": "agentMessage", "phase": "final_answer"},
        }
      })),
      TimedRead::Message(json!({
        "jsonrpc": "2.0",
        "method": "item/agentMessage/delta",
        "params": {
          "threadId": "thread-1",
          "turnId": "turn-1",
          "itemId": "final-1",
          "delta": "x".repeat(MAX_FINAL_RESPONSE_BYTES + 1),
        }
      })),
    ]);
    let transport = MockTransport {
      evidence: evidence(&profile),
      reads,
      actions: Arc::new(Mutex::new(Actions::default())),
    };
    let request = request(profile);
    assert!(matches!(
      execute_test(&executor_for(transport, &request), request),
      ScheduledExecutionResult::Failed(ScheduledFailure {
        kind: ScheduledFailureKind::OutputSchemaViolation,
        ..
      })
    ));
  }

  #[test]
  fn deeply_nested_final_json_is_rejected_by_depth_limit() {
    let mut nested = json!(null);
    for _ in 0..=MAX_OUTPUT_SCHEMA_DEPTH {
      nested = json!({"nested": nested});
    }
    let final_text = json!({
      "schema_version": OUTPUT_SCHEMA_VERSION,
      "summary": "looks valid at the surface",
      "unexpected": nested,
    })
    .to_string();
    let profile = profile();
    let transport = MockTransport {
      evidence: evidence(&profile),
      reads: reads_with_final_text(&final_text),
      actions: Arc::new(Mutex::new(Actions::default())),
    };
    let request = request(profile);
    assert!(matches!(
      execute_test(&executor_for(transport, &request), request),
      ScheduledExecutionResult::Failed(ScheduledFailure {
        kind: ScheduledFailureKind::OutputSchemaViolation,
        message,
      }) if message == "scheduled_final_response_too_deep"
    ));
  }

  #[test]
  fn instruction_and_time_budgets_reject_extreme_inputs_before_transport() {
    let cases = ["instruction", "timeout", "interrupt", "terminate", "kill"];
    for case in cases {
      let mut request = request(profile());
      match case {
        "instruction" => request.task.instruction = "x".repeat(MAX_INSTRUCTION_BYTES + 1),
        "timeout" => request.timeout = MAX_RUN_TIMEOUT + Duration::from_nanos(1),
        "interrupt" => request.interrupt_grace = MAX_INTERRUPT_GRACE + Duration::from_nanos(1),
        "terminate" => request.terminate_grace = MAX_TERMINATE_GRACE + Duration::from_nanos(1),
        "kill" => request.kill_grace = MAX_KILL_GRACE + Duration::from_nanos(1),
        _ => unreachable!(),
      }
      let executor = ScheduledCodexExecutor::new(
        |_: RequestedCapabilityProfile| -> Result<MockTransport, String> {
          panic!("invalid limits must not start transport")
        },
      );
      assert!(matches!(
        execute_test(&executor, request),
        ScheduledExecutionResult::PreflightRejected(ScheduledFailure {
          kind: ScheduledFailureKind::InvalidRequest,
          ..
        })
      ));
    }
    assert!(validate_fixed_output_schema().is_ok());
    let schema = fixed_output_schema();
    assert!(serde_json::to_vec(&schema).expect("schema").len() <= MAX_OUTPUT_SCHEMA_BYTES);
    assert!(json_depth(&schema) <= MAX_OUTPUT_SCHEMA_DEPTH);
  }

  #[test]
  fn unexpected_or_writable_mcp_tool_fails_before_turn_start() {
    for mutation in ["unexpected", "writable"] {
      let profile = profile();
      let runtime = evidence(&profile);
      let mut reads = successful_reads();
      let mut inventory = inventory();
      if mutation == "unexpected" {
        inventory["data"][0]["tools"]["create_issue"] = json!({
          "name": "create_issue",
          "annotations": {"readOnlyHint": false},
          "inputSchema": {"type": "object"},
        });
      } else {
        inventory["data"][0]["tools"]["issue_read"]["annotations"]["readOnlyHint"] = json!(false);
      }
      reads[2] = response(3, inventory);
      let actions = Arc::new(Mutex::new(Actions::default()));
      let transport = MockTransport {
        evidence: runtime,
        reads,
        actions: Arc::clone(&actions),
      };
      let request = request(profile);
      let executor = executor_for(transport, &request);
      assert!(matches!(
        execute_test(&executor, request),
        ScheduledExecutionResult::PreflightRejected(_)
      ));
      assert!(
        actions
          .lock()
          .expect("actions")
          .writes
          .iter()
          .all(|message| message["method"] != "turn/start")
      );
    }
  }

  #[test]
  fn timeout_interrupts_once_then_terminates_and_kills_process_group() {
    let profile = profile();
    let runtime = evidence(&profile);
    let mut reads = successful_reads();
    reads.pop_back();
    reads.pop_back();
    reads.push_back(TimedRead::TimedOut);
    reads.push_back(TimedRead::TimedOut);
    let actions = Arc::new(Mutex::new(Actions {
      reap_results: VecDeque::from([ProcessExit::TimedOut, ProcessExit::Exited]),
      ..Actions::default()
    }));
    let transport = MockTransport {
      evidence: runtime,
      reads,
      actions: Arc::clone(&actions),
    };
    let mut request = request(profile);
    request.timeout = Duration::from_millis(10);
    let executor = executor_for(transport, &request);
    let prepared = prepare_test(&executor, request).expect("prepare execution");
    std::thread::sleep(Duration::from_millis(15));
    assert!(matches!(
      prepared.execute(),
      ScheduledExecutionResult::TransportLost(ScheduledFailure {
        kind: ScheduledFailureKind::TimedOut,
        ..
      })
    ));
    let actions = actions.lock().expect("actions");
    assert_eq!(
      actions
        .writes
        .iter()
        .filter(|message| message["method"] == "turn/interrupt")
        .count(),
      1
    );
    assert_eq!(actions.close_count, 1);
    assert_eq!(actions.terminate_count, 1);
    assert_eq!(actions.kill_count, 1);
    let interrupt = actions
      .events
      .iter()
      .position(|event| event == "write:turn/interrupt")
      .expect("interrupt event");
    assert_eq!(
      &actions.events[interrupt..],
      [
        "write:turn/interrupt",
        "read",
        "close",
        "term",
        "wait_group",
        "kill",
        "wait_group",
      ]
    );
  }

  #[test]
  fn fixed_child_environment_contains_no_credential_or_injection_keys() {
    let environment = fixed_child_environment();
    assert_eq!(
      environment,
      [
        ("PATH", CHILD_PATH),
        ("LANG", CHILD_LOCALE),
        ("LC_ALL", CHILD_LOCALE)
      ]
    );
    assert!(environment.iter().all(|(key, _)| {
      ![
        "OPENAI_API_KEY",
        "GITHUB_PAT",
        "LD_PRELOAD",
        "NODE_OPTIONS",
        "HOME",
        "HTTP_PROXY",
        "HTTPS_PROXY",
      ]
      .contains(key)
    }));
  }

  #[test]
  fn config_contains_only_pinned_read_only_github_mcp() {
    let profile = profile();
    let config = profile.dedicated_config();
    assert!(config.contains("web_search = \"disabled\""));
    assert!(config.contains("[shell_environment_policy]"));
    assert!(config.contains("inherit = \"none\""));
    assert!(config.contains("ignore_default_excludes = false"));
    assert!(config.contains(&format!("exclude = [\"{GITHUB_MCP_ACCESS_TOKEN_ENV}\"]")));
    assert!(config.contains("include_only = [\"PATH\", \"LANG\", \"LC_ALL\"]"));
    assert!(config.contains(&format!(
      "set = {{ PATH = {CHILD_PATH:?}, LANG = {CHILD_LOCALE:?}, LC_ALL = {CHILD_LOCALE:?} }}"
    )));
    assert!(config.contains("[mcp_servers.github]"));
    assert!(config.contains("required = true"));
    assert!(config.contains(&format!(
      "bearer_token_env_var = \"{GITHUB_MCP_ACCESS_TOKEN_ENV}\""
    )));
    assert!(!config.contains("github-readonly-service-account"));
    assert!(!config.contains("slack"));
    for tool in EXPECTED_GITHUB_TOOLS {
      assert!(config.contains(tool));
    }
  }

  #[test]
  fn github_mcp_bearer_token_and_health_proof_are_strictly_bounded() {
    for valid in [
      "x".repeat(MIN_MCP_ACCESS_TOKEN_BYTES),
      "x".repeat(MAX_MCP_ACCESS_TOKEN_BYTES),
    ] {
      assert!(validate_github_mcp_access_token(&valid).is_ok());
    }
    for invalid in [
      String::new(),
      "x".repeat(MIN_MCP_ACCESS_TOKEN_BYTES - 1),
      "x".repeat(MAX_MCP_ACCESS_TOKEN_BYTES + 1),
      format!("{} ", "x".repeat(MIN_MCP_ACCESS_TOKEN_BYTES)),
    ] {
      assert!(validate_github_mcp_access_token(&invalid).is_err());
    }

    let valid_health = health();
    assert_eq!(
      attest_mcp_health(&valid_health).expect("valid health proof"),
      sha256_hex(valid_health.to_string().as_bytes())
    );
    for invalid in [
      json!({}),
      json!({"content": []}),
      json!({"content": [{"type": "text", "text": "   "}]}),
      json!({"content": [{"type": "text", "text": "identity"}], "isError": true}),
      json!({"content": [{"type": "text", "text": "identity"}], "isError": "false"}),
      json!({"content": [{"type": "text", "text": "identity"}], "isError": null}),
      json!({"content": [{"type": "text", "text": "identity"}], "unexpected": true}),
    ] {
      assert!(attest_mcp_health(&invalid).is_err(), "invalid={invalid}");
    }
    let oversized = json!({
      "content": [{"type": "text", "text": "x".repeat(MAX_MCP_HEALTH_RESULT_BYTES)}]
    });
    assert!(attest_mcp_health(&oversized).is_err());
    let mut deep = json!({"identity": "codeoff-test"});
    for _ in 0..=MAX_MCP_HEALTH_RESULT_DEPTH {
      deep = json!({"nested": deep});
    }
    assert!(
      attest_mcp_health(&json!({
        "content": [{"type": "text", "text": "identity"}],
        "structuredContent": deep,
      }))
      .is_err()
    );
  }

  #[test]
  fn github_mcp_runtime_pins_installed_binaries_not_release_archives() {
    assert!(is_pinned_github_mcp_artifact(
      GITHUB_MCP_ARTIFACT_SHA256_X86_64
    ));
    assert!(is_pinned_github_mcp_artifact(
      GITHUB_MCP_ARTIFACT_SHA256_ARM64
    ));
    for archive_digest in [
      "27443d173f209e60d4af9777e624bfea3de1af24897d46cc7324f01cf279a41d",
      "25f8028304202674ec2e9977fec3ca0897cac33866dabb51aefd418bc0ce7ef2",
    ] {
      assert!(!is_pinned_github_mcp_artifact(archive_digest));
    }
  }

  #[test]
  fn runtime_version_schema_executable_and_image_drift_fail_closed() {
    for field in ["version", "schema", "executable", "image"] {
      let profile = profile();
      let mut runtime = evidence(&profile);
      match field {
        "version" => runtime.codex_version = "0.145.0".to_owned(),
        "schema" => runtime.app_server_schema_sha256 = "b".repeat(64),
        "executable" => runtime.codex_program_sha256 = "c".repeat(64),
        "image" => runtime.runner_image_digest = format!("sha256:{}", "d".repeat(64)),
        _ => unreachable!(),
      }
      let actions = Arc::new(Mutex::new(Actions::default()));
      let transport = MockTransport {
        evidence: runtime,
        reads: successful_reads(),
        actions: Arc::clone(&actions),
      };
      let request = request(profile);
      assert!(matches!(
        execute_test(&executor_for(transport, &request), request),
        ScheduledExecutionResult::PreflightRejected(ScheduledFailure {
          kind: ScheduledFailureKind::CapabilityMismatch,
          ..
        })
      ));
      assert!(actions.lock().expect("actions").writes.is_empty());
    }
  }

  #[test]
  fn ambient_server_unhealthy_auth_or_wrong_version_fail_before_turn() {
    for mutation in ["ambient", "auth", "version"] {
      let profile = profile();
      let runtime = evidence(&profile);
      let mut reads = successful_reads();
      let mut inventory = inventory();
      match mutation {
        "ambient" => inventory["data"]
          .as_array_mut()
          .expect("inventory")
          .push(json!({
            "name": "ambient-slack",
            "authStatus": "bearerToken",
            "serverInfo": {"name": "slack", "version": "1"},
            "tools": {},
            "resources": [],
            "resourceTemplates": [],
          })),
        "auth" => inventory["data"][0]["authStatus"] = json!("unsupported"),
        "version" => inventory["data"][0]["serverInfo"]["version"] = json!("1.7.0"),
        _ => unreachable!(),
      }
      reads[2] = response(3, inventory);
      let actions = Arc::new(Mutex::new(Actions::default()));
      let transport = MockTransport {
        evidence: runtime,
        reads,
        actions: Arc::clone(&actions),
      };
      let request = request(profile);
      assert!(matches!(
        execute_test(&executor_for(transport, &request), request),
        ScheduledExecutionResult::PreflightRejected(_)
      ));
      assert!(
        actions
          .lock()
          .expect("actions")
          .writes
          .iter()
          .all(|message| message["method"] != "turn/start")
      );
    }
  }

  #[test]
  fn commentary_only_completion_is_output_schema_violation() {
    let profile = profile();
    let runtime = evidence(&profile);
    let mut reads = successful_reads();
    reads.pop_back();
    reads.pop_back();
    reads.push_back(TimedRead::Message(json!({
      "jsonrpc": "2.0",
      "method": "turn/completed",
      "params": {
        "threadId": "thread-1",
        "turn": {
          "id": "turn-1",
          "status": "completed",
          "items": [{"type": "agentMessage", "phase": "commentary", "text": "Only progress"}],
        }
      }
    })));
    let transport = MockTransport {
      evidence: runtime,
      reads,
      actions: Arc::new(Mutex::new(Actions::default())),
    };
    let request = request(profile);
    assert!(matches!(
      execute_test(&executor_for(transport, &request), request),
      ScheduledExecutionResult::Failed(ScheduledFailure {
        kind: ScheduledFailureKind::OutputSchemaViolation,
        ..
      })
    ));
  }

  #[test]
  fn confirmed_interrupt_is_typed_and_sent_once() {
    let profile = profile();
    let runtime = evidence(&profile);
    let mut reads = successful_reads();
    reads.pop_back();
    reads.pop_back();
    reads.push_back(TimedRead::TimedOut);
    reads.push_back(response(5, json!({})));
    reads.push_back(TimedRead::Message(json!({
      "jsonrpc": "2.0",
      "method": "turn/completed",
      "params": {
        "threadId": "thread-1",
        "turn": {"id": "turn-1", "status": "interrupted", "items": []},
      }
    })));
    let actions = Arc::new(Mutex::new(Actions::default()));
    let transport = MockTransport {
      evidence: runtime,
      reads,
      actions: Arc::clone(&actions),
    };
    let mut request = request(profile);
    request.timeout = Duration::from_millis(10);
    let prepared =
      prepare_test(&executor_for(transport, &request), request).expect("prepare execution");
    std::thread::sleep(Duration::from_millis(15));
    assert!(matches!(
      prepared.execute(),
      ScheduledExecutionResult::Interrupted { .. }
    ));
    assert_eq!(
      actions
        .lock()
        .expect("actions")
        .writes
        .iter()
        .filter(|message| message["method"] == "turn/interrupt")
        .count(),
      1
    );
  }

  #[cfg(unix)]
  #[test]
  fn verified_command_executes_opened_inode_after_path_replacement() {
    let temp = TempDir::new().expect("tempdir");
    let program = temp.path().join("program");
    fs::write(&program, "#!/bin/sh\nprintf 'trusted-inode\\n'\n").expect("program");
    fs::set_permissions(&program, fs::Permissions::from_mode(0o555)).expect("protect program");
    let codex_home = temp.path().join("codex-home");
    let cwd = temp.path().join("cwd");
    fs::create_dir(&codex_home).expect("CODEX_HOME");
    fs::create_dir(&cwd).expect("cwd");
    let artifacts = Arc::new(test_artifacts(&program, &codex_home, &cwd));
    let replacement = temp.path().join("replacement");
    fs::write(&replacement, "#!/bin/sh\nprintf 'replacement\\n'\n").expect("replacement");
    fs::set_permissions(&replacement, fs::Permissions::from_mode(0o555))
      .expect("protect replacement");
    fs::rename(&replacement, &program).expect("swap program path");

    let output = verified_command(&artifacts, &["program"], false, None)
      .expect("verified command")
      .command
      .output()
      .expect("execute verified descriptor");
    assert!(output.status.success());
    assert_eq!(output.stdout, b"trusted-inode\n");
  }

  #[cfg(unix)]
  #[test]
  fn direct_transport_drop_kills_and_reaps_its_process_group() {
    let unique = format!(
      "codeoff-scheduled-process-test-{}-{}",
      std::process::id(),
      now_unix_seconds()
    );
    let base = std::env::temp_dir().join(unique);
    let cwd = base.join("workspace");
    let codex_home = base.join("codex-home");
    let pid_file = cwd.join("grandchild.pid");
    fs::create_dir(&base).expect("base");
    fs::create_dir(&cwd).expect("cwd");
    let program =
      PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/process-tree-app-server.sh");
    let mut profile = profile();
    profile.codex_program = program.clone();
    profile.codex_program_sha256 = sha256_file(&program).expect("program hash");
    profile.codex_home = codex_home.clone();
    profile.cwd = cwd.clone();
    profile.config_sha256 = sha256_hex(profile.dedicated_config().as_bytes());
    prepare_scheduled_codex_home(&profile).expect("codex home");
    let runtime = evidence(&profile);
    let started = Instant::now();
    let artifacts = Arc::new(test_artifacts(&program, &codex_home, &cwd));
    let transport = StdioScheduledJsonlTransport::spawn(
      &profile,
      runtime,
      &artifacts,
      None,
      &"t".repeat(MIN_MCP_ACCESS_TOKEN_BYTES),
    )
    .expect("spawn");
    let pid_deadline = Instant::now() + Duration::from_secs(2);
    while !pid_file.exists() && Instant::now() < pid_deadline {
      thread::sleep(Duration::from_millis(5));
    }
    let grandchild_pid = fs::read_to_string(&pid_file)
      .expect("grandchild pid")
      .trim()
      .to_owned();
    assert!(Path::new(&format!("/proc/{grandchild_pid}")).exists());
    drop(transport);
    assert!(started.elapsed() < Duration::from_secs(3));
    let reap_deadline = Instant::now() + Duration::from_secs(1);
    while Path::new(&format!("/proc/{grandchild_pid}")).exists() && Instant::now() < reap_deadline {
      thread::sleep(Duration::from_millis(5));
    }
    assert!(!Path::new(&format!("/proc/{grandchild_pid}")).exists());

    fs::set_permissions(&codex_home, fs::Permissions::from_mode(0o700)).expect("unprotect home");
    fs::remove_file(codex_home.join("config.toml")).expect("remove config");
    fs::remove_file(&pid_file).expect("remove pid");
    fs::remove_dir(&codex_home).expect("remove home");
    fs::remove_dir(&cwd).expect("remove cwd");
    fs::remove_dir(&base).expect("remove base");
  }
}
