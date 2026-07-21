//! Fail-closed Codex execution boundary for scheduled tasks.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::process::{Child, ChildStdin, Command, Stdio};
#[cfg(unix)]
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
#[cfg(unix)]
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use codeoff_agent_contract::{AgentTask, InvocationSource, SessionMode, ToolPolicy};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[cfg(unix)]
use nix::errno::Errno;
#[cfg(unix)]
use nix::sys::signal::{Signal, killpg};
#[cfg(unix)]
use nix::unistd::Pid;

use crate::{JsonlTransport, send_notification, send_request};

pub const CODEX_CLI_VERSION: &str = "0.144.6";
pub const CODEX_APP_SERVER_SCHEMA_SHA256: &str =
  "2bc9867446f03c818018ee33c249f4d1da22c3e19a68d606b0e435faba04f1d1";
pub const GITHUB_MCP_SERVER_VERSION: &str = "1.6.0";
pub const GITHUB_MCP_ARTIFACT_SHA256_X86_64: &str =
  "27443d173f209e60d4af9777e624bfea3de1af24897d46cc7324f01cf279a41d";
pub const GITHUB_MCP_ARTIFACT_SHA256_ARM64: &str =
  "25f8028304202674ec2e9977fec3ca0897cac33866dabb51aefd418bc0ce7ef2";

const GITHUB_MCP_NAME: &str = "github";
const GITHUB_MCP_SERVER_INFO_NAME: &str = "github-mcp-server";
const OUTPUT_SCHEMA_REVISION: &str = "scheduled-result-v1";
const CREDENTIAL_DENY_POLICY_REVISION: &str = "scheduled-credential-isolation-v1";
const NEGATIVE_TEST_REVISION: &str = "scheduled-secret-falsifier-v1";
const MAX_FAILURE_BYTES: usize = 2 * 1024;
const MAX_FINAL_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_ISOLATION_EVIDENCE_AGE: Duration = Duration::from_mins(5);
const EXPECTED_GITHUB_TOOLS: [&str; 4] =
  ["issue_read", "list_issues", "search_issues", "search_orgs"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestedCapabilityProfile {
  pub codex_program: PathBuf,
  pub codex_program_sha256: String,
  pub codex_home: PathBuf,
  pub cwd: PathBuf,
  pub github_mcp_url: String,
  pub github_mcp_artifact_sha256: String,
  pub github_mcp_endpoint_identity: String,
  pub credential_reference: String,
  pub permission_policy_revision: String,
  pub config_revision: String,
  pub config_sha256: String,
  pub non_secret_env: BTreeMap<String, String>,
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
      "web_search = \"disabled\"\n\n[mcp_servers.{GITHUB_MCP_NAME}]\nurl = {url:?}\nenabled = true\nrequired = true\nenabled_tools = [{tools}]\n",
      url = self.github_mcp_url,
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
    if !matches!(
      self.github_mcp_artifact_sha256.as_str(),
      GITHUB_MCP_ARTIFACT_SHA256_X86_64 | GITHUB_MCP_ARTIFACT_SHA256_ARM64
    ) {
      return Err(preflight("github_mcp_artifact_digest_not_pinned_v1_6_0"));
    }
    let actual_config_hash = sha256_hex(self.dedicated_config().as_bytes());
    if self.config_sha256 != actual_config_hash {
      return Err(preflight("scheduled_config_digest_mismatch"));
    }
    for (key, value) in &self.non_secret_env {
      validate_non_secret_env(key, value)?;
    }
    Ok(())
  }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialIsolationEvidence {
  pub endpoint_identity: String,
  pub github_mcp_artifact_sha256: String,
  pub credential_reference: String,
  pub permission_policy_revision: String,
  pub isolation_revision: String,
  pub negative_test_revision: String,
  pub verified_at_unix_seconds: u64,
  pub app_server_has_no_credentials: IsolationCheck,
  pub parent_and_sibling_environ_denied: IsolationCheck,
  pub secret_mounts_denied: IsolationCheck,
  pub endpoint_holds_credential_out_of_process: IsolationCheck,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsolationCheck {
  Verified,
  Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduledRuntimeEvidence {
  pub codex_version: String,
  pub app_server_schema_sha256: String,
  pub codex_program_sha256: String,
  pub config_sha256: String,
  pub credential_isolation: CredentialIsolationEvidence,
}

#[derive(Debug, Clone)]
pub struct ScheduledCodexRequest {
  pub task: AgentTask,
  pub profile: RequestedCapabilityProfile,
  pub output_schema: Value,
  pub timeout: Duration,
  pub interrupt_grace: Duration,
  pub terminate_grace: Duration,
  pub kill_grace: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestedCapabilityProfile {
  pub codex_version: String,
  pub app_server_schema_sha256: String,
  pub codex_program_sha256: String,
  pub github_mcp_version: String,
  pub github_mcp_artifact_sha256: String,
  pub github_mcp_endpoint_identity: String,
  pub github_tools: BTreeSet<String>,
  pub credential_reference: String,
  pub permission_policy_revision: String,
  pub config_revision: String,
  pub config_sha256: String,
  pub credential_isolation_revision: String,
  pub credential_deny_policy_revision: String,
  pub negative_test_revision: String,
  pub output_schema_revision: String,
  pub attested_at_unix_seconds: u64,
  pub profile_sha256: String,
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
    final_response: Option<String>,
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

  /// Reaps the process leader without waiting past `deadline`.
  ///
  /// # Errors
  ///
  /// Returns an error when child status cannot be inspected or reaped.
  fn reap_until(&mut self, deadline: Instant) -> Result<ProcessExit, String>;
}

#[cfg(unix)]
enum ReaderEvent {
  Message(Value),
  Error(String),
  Eof,
}

/// Direct, process-group-owned stdio transport for scheduled Codex App Server runs.
///
/// The runtime evidence is produced by the caller's startup verifier. This constructor independently
/// re-hashes the executable and dedicated config before spawning, but deliberately does not invent
/// version, schema, or credential-isolation evidence that the child protocol cannot observe.
#[cfg(unix)]
pub struct StdioScheduledJsonlTransport {
  child: Child,
  stdin: Option<ChildStdin>,
  reader: Option<JoinHandle<()>>,
  receiver: Receiver<ReaderEvent>,
  process_group: Pid,
  runtime_evidence: ScheduledRuntimeEvidence,
}

#[cfg(unix)]
impl StdioScheduledJsonlTransport {
  /// Starts the pinned Codex App Server directly, with a clean allowlisted environment and its own
  /// process group.
  ///
  /// # Errors
  ///
  /// Returns an error before spawn when executable/config digests drift, an environment key looks
  /// secret-bearing, or the process and stdio cannot be established.
  pub fn spawn(
    profile: &RequestedCapabilityProfile,
    runtime_evidence: ScheduledRuntimeEvidence,
  ) -> Result<Self, String> {
    profile.validate().map_err(|failure| failure.message)?;
    let executable_hash = sha256_file(&profile.codex_program)?;
    if executable_hash != profile.codex_program_sha256
      || executable_hash != runtime_evidence.codex_program_sha256
    {
      return Err("codex_program_digest_mismatch_before_spawn".to_owned());
    }
    let config_path = profile.codex_home.join("config.toml");
    let config_hash = sha256_file(&config_path)?;
    if config_hash != profile.config_sha256 || config_hash != runtime_evidence.config_sha256 {
      return Err("scheduled_config_digest_mismatch_before_spawn".to_owned());
    }
    let mut command = Command::new(&profile.codex_program);
    command
      .args(["app-server", "--listen", "stdio://"])
      .env_clear()
      .env("CODEX_HOME", &profile.codex_home)
      .envs(&profile.non_secret_env)
      .current_dir(&profile.cwd)
      .stdin(Stdio::piped())
      .stdout(Stdio::piped())
      .stderr(Stdio::null())
      .process_group(0);
    let mut child = command
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
        use std::io::{BufRead, BufReader};
        let mut stdout = BufReader::new(stdout);
        loop {
          let mut line = String::new();
          match stdout.read_line(&mut line) {
            Ok(0) => {
              let _ = sender.send(ReaderEvent::Eof);
              return;
            }
            Ok(_) => match serde_json::from_str(&line) {
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
    loop {
      match self
        .child
        .try_wait()
        .map_err(|error| format!("reap scheduled codex app server: {error}"))?
      {
        Some(_) => {
          self.join_finished_reader();
          return Ok(ProcessExit::Exited);
        }
        None if Instant::now() >= deadline => return Ok(ProcessExit::TimedOut),
        None => thread::sleep(Duration::from_millis(5)),
      }
    }
  }
}

#[cfg(unix)]
impl Drop for StdioScheduledJsonlTransport {
  fn drop(&mut self) {
    self.stdin.take();
    let _ = self.signal_process_group(Signal::SIGTERM);
    let terminate_deadline = Instant::now() + Duration::from_millis(100);
    while Instant::now() < terminate_deadline {
      if self.child.try_wait().ok().flatten().is_some() {
        self.join_finished_reader();
        return;
      }
      thread::sleep(Duration::from_millis(5));
    }
    let _ = self.signal_process_group(Signal::SIGKILL);
    let kill_deadline = Instant::now() + Duration::from_millis(100);
    while Instant::now() < kill_deadline {
      if self.child.try_wait().ok().flatten().is_some() {
        self.join_finished_reader();
        return;
      }
      thread::sleep(Duration::from_millis(5));
    }
  }
}

pub trait ScheduledCodexExecution {
  fn execute(&self, request: ScheduledCodexRequest) -> ScheduledExecutionResult;
}

pub struct ScheduledCodexExecutor<F> {
  transport_factory: F,
}

impl<F> ScheduledCodexExecutor<F> {
  pub const fn new(transport_factory: F) -> Self {
    Self { transport_factory }
  }
}

impl<F, T> ScheduledCodexExecution for ScheduledCodexExecutor<F>
where
  F: Fn(RequestedCapabilityProfile) -> Result<T, String>,
  T: ScheduledJsonlTransport,
{
  fn execute(&self, request: ScheduledCodexRequest) -> ScheduledExecutionResult {
    if let Err(failure) = validate_request(&request) {
      return ScheduledExecutionResult::PreflightRejected(failure);
    }
    let mut transport = match (self.transport_factory)(request.profile.clone()) {
      Ok(transport) => transport,
      Err(error) => {
        return ScheduledExecutionResult::PreflightRejected(ScheduledFailure::new(
          ScheduledFailureKind::Transport,
          error,
        ));
      }
    };
    let attested_profile = match attest_runtime(&request.profile, transport.runtime_evidence()) {
      Ok(profile) => profile,
      Err(failure) => {
        let _ = bounded_shutdown(&mut transport, &request);
        return ScheduledExecutionResult::PreflightRejected(failure);
      }
    };
    let deadline = Instant::now() + request.timeout;
    let result = execute_protocol(&mut transport, &request, attested_profile, deadline);
    match bounded_shutdown(&mut transport, &request) {
      Ok(()) => result,
      Err(failure) => ScheduledExecutionResult::TransportLost(failure),
    }
  }
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
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o400)).map_err(|error| {
      ScheduledFailure::new(
        ScheduledFailureKind::InvalidRequest,
        format!("protect scheduled config: {error}"),
      )
    })?;
    fs::set_permissions(&profile.codex_home, fs::Permissions::from_mode(0o500)).map_err(
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
  if request.output_schema.as_object().is_none() {
    return Err(preflight("scheduled_output_schema_must_be_object"));
  }
  if request.timeout.is_zero()
    || request.interrupt_grace.is_zero()
    || request.terminate_grace.is_zero()
    || request.kill_grace.is_zero()
  {
    return Err(preflight("scheduled_timeouts_must_be_positive"));
  }
  request.profile.validate()
}

fn attest_runtime(
  requested: &RequestedCapabilityProfile,
  evidence: &ScheduledRuntimeEvidence,
) -> Result<AttestedCapabilityProfile, ScheduledFailure> {
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
  let isolation = &evidence.credential_isolation;
  let now = now_unix_seconds();
  let evidence_is_fresh = isolation.verified_at_unix_seconds <= now
    && now.saturating_sub(isolation.verified_at_unix_seconds)
      <= MAX_ISOLATION_EVIDENCE_AGE.as_secs();
  if isolation.endpoint_identity != requested.github_mcp_endpoint_identity
    || isolation.github_mcp_artifact_sha256 != requested.github_mcp_artifact_sha256
    || isolation.credential_reference != requested.credential_reference
    || isolation.permission_policy_revision != requested.permission_policy_revision
    || isolation.isolation_revision.trim().is_empty()
    || isolation.negative_test_revision != NEGATIVE_TEST_REVISION
    || !evidence_is_fresh
    || isolation.app_server_has_no_credentials != IsolationCheck::Verified
    || isolation.parent_and_sibling_environ_denied != IsolationCheck::Verified
    || isolation.secret_mounts_denied != IsolationCheck::Verified
    || isolation.endpoint_holds_credential_out_of_process != IsolationCheck::Verified
  {
    return Err(ScheduledFailure::new(
      ScheduledFailureKind::CredentialIsolationUnproven,
      "credential_isolation_evidence_missing_or_mismatched",
    ));
  }
  Ok(AttestedCapabilityProfile {
    codex_version: evidence.codex_version.clone(),
    app_server_schema_sha256: evidence.app_server_schema_sha256.clone(),
    codex_program_sha256: evidence.codex_program_sha256.clone(),
    github_mcp_version: GITHUB_MCP_SERVER_VERSION.to_owned(),
    github_mcp_artifact_sha256: requested.github_mcp_artifact_sha256.clone(),
    github_mcp_endpoint_identity: requested.github_mcp_endpoint_identity.clone(),
    github_tools: RequestedCapabilityProfile::github_tool_inventory(),
    credential_reference: requested.credential_reference.clone(),
    permission_policy_revision: requested.permission_policy_revision.clone(),
    config_revision: requested.config_revision.clone(),
    config_sha256: requested.config_sha256.clone(),
    credential_isolation_revision: isolation.isolation_revision.clone(),
    credential_deny_policy_revision: CREDENTIAL_DENY_POLICY_REVISION.to_owned(),
    negative_test_revision: isolation.negative_test_revision.clone(),
    output_schema_revision: OUTPUT_SCHEMA_REVISION.to_owned(),
    attested_at_unix_seconds: now_unix_seconds(),
    profile_sha256: String::new(),
  })
}

fn execute_protocol<T: ScheduledJsonlTransport>(
  transport: &mut T,
  request: &ScheduledCodexRequest,
  mut attested_profile: AttestedCapabilityProfile,
  deadline: Instant,
) -> ScheduledExecutionResult {
  let initialize = json!({
    "clientInfo": {"name": "codeoff-scheduler", "version": env!("CARGO_PKG_VERSION")},
  });
  if let Err(failure) = scheduled_request(transport, 1, "initialize", &initialize, deadline) {
    return protocol_failure(failure);
  }
  if let Err(error) = send_notification(transport, "initialized") {
    return transport_failure(error);
  }
  let thread_params = json!({
    "approvalPolicy": "never",
    "cwd": request.profile.cwd,
    "ephemeral": true,
    "sandbox": "read-only",
    "config": {
      "web_search": "disabled",
      "mcp_servers": {
        GITHUB_MCP_NAME: {
          "url": request.profile.github_mcp_url,
          "enabled": true,
          "required": true,
          "enabled_tools": EXPECTED_GITHUB_TOOLS,
        }
      }
    }
  });
  let thread = match scheduled_request(transport, 2, "thread/start", &thread_params, deadline) {
    Ok(thread) => thread,
    Err(failure) => return protocol_failure(failure),
  };
  let Some(thread_id) = thread["thread"]["id"].as_str().map(str::to_owned) else {
    return protocol_failure(capability("thread_start_missing_thread_id"));
  };
  let inventory = match scheduled_request(
    transport,
    3,
    "mcpServerStatus/list",
    &json!({"threadId": thread_id, "detail": "full", "limit": 100}),
    deadline,
  ) {
    Ok(inventory) => inventory,
    Err(failure) => return protocol_failure(failure),
  };
  if let Err(failure) = attest_mcp_inventory(&inventory) {
    return ScheduledExecutionResult::PreflightRejected(failure);
  }
  attested_profile.profile_sha256 = profile_sha256(&attested_profile);
  let turn_params = json!({
    "threadId": thread_id,
    "clientUserMessageId": request.task.task_id,
    "cwd": request.profile.cwd,
    "approvalPolicy": "never",
    "sandboxPolicy": {"type": "readOnly", "networkAccess": false},
    "outputSchema": request.output_schema,
    "input": [{"type": "text", "text": request.task.instruction}],
  });
  let turn = match scheduled_request(transport, 4, "turn/start", &turn_params, deadline) {
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
    &thread_id,
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
) -> Result<Value, ScheduledFailure> {
  send_request(transport, id, method, params)
    .map_err(|error| ScheduledFailure::new(ScheduledFailureKind::Transport, error))?;
  loop {
    match transport.read_json_until(deadline) {
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
  if server["authStatus"].as_str() != Some("unsupported") {
    return Err(capability("github_mcp_client_auth_must_be_unsupported"));
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

fn wait_for_scheduled_turn<T: ScheduledJsonlTransport>(
  transport: &mut T,
  request: &ScheduledCodexRequest,
  thread_id: &str,
  turn_id: &str,
  attested_profile: AttestedCapabilityProfile,
  deadline: Instant,
) -> ScheduledExecutionResult {
  let mut phased_final = None;
  let mut unphased_final = None;
  loop {
    match transport.read_json_until(deadline) {
      Ok(TimedRead::Message(message)) => {
        let params = &message["params"];
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
            record_agent_message(&params["item"], &mut phased_final, &mut unphased_final);
          }
          Some("turn/completed") if params["threadId"].as_str() == Some(thread_id) => {
            let turn = &params["turn"];
            if turn["id"].as_str() != Some(turn_id) {
              continue;
            }
            if let Some(items) = turn["items"].as_array() {
              for item in items {
                record_agent_message(item, &mut phased_final, &mut unphased_final);
              }
            }
            return match turn["status"].as_str() {
              Some("completed") => {
                let final_response = phased_final.or(unphased_final);
                if final_response
                  .as_ref()
                  .is_some_and(|value: &String| value.len() > MAX_FINAL_RESPONSE_BYTES)
                {
                  ScheduledExecutionResult::Failed(ScheduledFailure::new(
                    ScheduledFailureKind::OutputSchemaViolation,
                    "scheduled_final_response_too_large",
                  ))
                } else {
                  ScheduledExecutionResult::Completed {
                    final_response,
                    thread_id: thread_id.to_owned(),
                    turn_id: turn_id.to_owned(),
                    usage: parse_usage(turn),
                    attested_profile: Box::new(attested_profile),
                  }
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
      Ok(TimedRead::TimedOut) => {
        return interrupt_timed_out_turn(transport, request, thread_id, turn_id);
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

fn interrupt_timed_out_turn<T: ScheduledJsonlTransport>(
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
  let deadline = Instant::now() + request.interrupt_grace;
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
  if transport
    .reap_until(Instant::now() + request.terminate_grace)
    .map_err(|error| ScheduledFailure::new(ScheduledFailureKind::Transport, error))?
    == ProcessExit::Exited
  {
    return Ok(());
  }
  transport
    .terminate_process_group()
    .map_err(|error| ScheduledFailure::new(ScheduledFailureKind::Transport, error))?;
  if transport
    .reap_until(Instant::now() + request.terminate_grace)
    .map_err(|error| ScheduledFailure::new(ScheduledFailureKind::Transport, error))?
    == ProcessExit::Exited
  {
    return Ok(());
  }
  transport
    .kill_process_group()
    .map_err(|error| ScheduledFailure::new(ScheduledFailureKind::Transport, error))?;
  if transport
    .reap_until(Instant::now() + request.kill_grace)
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
  unphased_final: &mut Option<String>,
) {
  if item["type"].as_str() != Some("agentMessage") {
    return;
  }
  let Some(text) = item["text"]
    .as_str()
    .map(str::trim)
    .filter(|text| !text.is_empty())
  else {
    return;
  };
  match item["phase"].as_str() {
    Some("final_answer") => *phased_final = Some(text.to_owned()),
    None => *unphased_final = Some(text.to_owned()),
    _ => {}
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

fn profile_sha256(profile: &AttestedCapabilityProfile) -> String {
  let tools: Vec<_> = profile.github_tools.iter().collect();
  let canonical = json!({
    "app_server_schema_sha256": profile.app_server_schema_sha256,
    "codex_program_sha256": profile.codex_program_sha256,
    "codex_version": profile.codex_version,
    "config_revision": profile.config_revision,
    "config_sha256": profile.config_sha256,
    "credential_deny_policy_revision": profile.credential_deny_policy_revision,
    "credential_isolation_revision": profile.credential_isolation_revision,
    "credential_reference": profile.credential_reference,
    "github_mcp_artifact_sha256": profile.github_mcp_artifact_sha256,
    "github_mcp_endpoint_identity": profile.github_mcp_endpoint_identity,
    "github_mcp_version": profile.github_mcp_version,
    "github_tools": tools,
    "negative_test_revision": profile.negative_test_revision,
    "output_schema_revision": profile.output_schema_revision,
    "permission_policy_revision": profile.permission_policy_revision,
  });
  sha256_hex(canonical.to_string().as_bytes())
}

fn is_loopback_http_url(url: &str) -> bool {
  ["http://127.0.0.1:", "http://[::1]:", "http://localhost:"]
    .iter()
    .any(|prefix| url.starts_with(prefix))
    && url.ends_with("/mcp")
}

fn validate_non_secret_env(key: &str, value: &str) -> Result<(), ScheduledFailure> {
  if key.trim() != key || key.is_empty() || value.contains('\0') {
    return Err(preflight("invalid_non_secret_child_environment"));
  }
  let upper = key.to_ascii_uppercase();
  if [
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "CREDENTIAL",
    "AUTH",
    "COOKIE",
  ]
  .iter()
  .any(|marker| upper.contains(marker))
  {
    return Err(ScheduledFailure::new(
      ScheduledFailureKind::CredentialIsolationUnproven,
      "secret_like_child_environment_key_rejected",
    ));
  }
  Ok(())
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

fn protocol_failure(failure: ScheduledFailure) -> ScheduledExecutionResult {
  if failure.kind == ScheduledFailureKind::TimedOut {
    ScheduledExecutionResult::TransportLost(failure)
  } else {
    ScheduledExecutionResult::PreflightRejected(failure)
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
mod tests {
  use std::collections::VecDeque;
  use std::sync::{Arc, Mutex};

  use codeoff_agent_contract::{InvocationPrincipal, SessionMode};

  use super::*;

  #[derive(Debug, Default)]
  struct Actions {
    writes: Vec<Value>,
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
      self.actions.lock().expect("actions").writes.push(value);
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
      Ok(self.reads.pop_front().unwrap_or(TimedRead::TimedOut))
    }

    fn close_stdin(&mut self) -> Result<(), String> {
      self.actions.lock().expect("actions").close_count += 1;
      Ok(())
    }

    fn terminate_process_group(&mut self) -> Result<(), String> {
      self.actions.lock().expect("actions").terminate_count += 1;
      Ok(())
    }

    fn kill_process_group(&mut self) -> Result<(), String> {
      self.actions.lock().expect("actions").kill_count += 1;
      Ok(())
    }

    fn reap_until(&mut self, _deadline: Instant) -> Result<ProcessExit, String> {
      Ok(
        self
          .actions
          .lock()
          .expect("actions")
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
      credential_reference: "github-readonly-service-account".to_owned(),
      permission_policy_revision: "github-issues-read-v1".to_owned(),
      config_revision: "scheduled-codex-v1".to_owned(),
      config_sha256: String::new(),
      non_secret_env: BTreeMap::from([
        ("LANG".to_owned(), "C.UTF-8".to_owned()),
        ("PATH".to_owned(), "/usr/local/bin:/usr/bin:/bin".to_owned()),
      ]),
    };
    profile.config_sha256 = sha256_hex(profile.dedicated_config().as_bytes());
    profile
  }

  fn evidence(profile: &RequestedCapabilityProfile) -> ScheduledRuntimeEvidence {
    ScheduledRuntimeEvidence {
      codex_version: CODEX_CLI_VERSION.to_owned(),
      app_server_schema_sha256: CODEX_APP_SERVER_SCHEMA_SHA256.to_owned(),
      codex_program_sha256: profile.codex_program_sha256.clone(),
      config_sha256: profile.config_sha256.clone(),
      credential_isolation: CredentialIsolationEvidence {
        endpoint_identity: profile.github_mcp_endpoint_identity.clone(),
        github_mcp_artifact_sha256: profile.github_mcp_artifact_sha256.clone(),
        credential_reference: profile.credential_reference.clone(),
        permission_policy_revision: profile.permission_policy_revision.clone(),
        isolation_revision: "pod-process-isolation-v1".to_owned(),
        negative_test_revision: NEGATIVE_TEST_REVISION.to_owned(),
        verified_at_unix_seconds: now_unix_seconds(),
        app_server_has_no_credentials: IsolationCheck::Verified,
        parent_and_sibling_environ_denied: IsolationCheck::Verified,
        secret_mounts_denied: IsolationCheck::Verified,
        endpoint_holds_credential_out_of_process: IsolationCheck::Verified,
      },
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
      profile,
      output_schema: json!({
        "type": "object",
        "required": ["summary"],
        "properties": {"summary": {"type": "string"}},
        "additionalProperties": false,
      }),
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
        "authStatus": "unsupported",
        "serverInfo": {"name": GITHUB_MCP_SERVER_INFO_NAME, "version": GITHUB_MCP_SERVER_VERSION},
        "tools": tools,
        "resources": [],
        "resourceTemplates": [],
      }],
      "nextCursor": null,
    })
  }

  fn successful_reads() -> VecDeque<TimedRead> {
    VecDeque::from([
      response(1, json!({"server": "codex-app-server"})),
      response(2, json!({"thread": {"id": "thread-1"}})),
      response(3, inventory()),
      response(4, json!({"turn": {"id": "turn-1"}})),
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
              {"type": "agentMessage", "phase": "final_answer", "text": "First"},
              {"type": "agentMessage", "phase": "final_answer", "text": "Last"}
            ]
          }
        }
      })),
    ])
  }

  fn executor_for(
    transport: MockTransport,
  ) -> ScheduledCodexExecutor<impl Fn(RequestedCapabilityProfile) -> Result<MockTransport, String>>
  {
    let transport = Arc::new(Mutex::new(Some(transport)));
    ScheduledCodexExecutor::new(move |_| {
      transport
        .lock()
        .expect("transport")
        .take()
        .ok_or_else(|| "mock transport already used".to_owned())
    })
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
    let executor = executor_for(transport);
    let result = executor.execute(request(profile));
    let ScheduledExecutionResult::Completed {
      final_response,
      usage,
      attested_profile,
      ..
    } = result
    else {
      panic!("unexpected result: {result:?}");
    };
    assert_eq!(final_response.as_deref(), Some("Last"));
    assert_eq!(usage.input, Some(10));
    assert!(!attested_profile.profile_sha256.is_empty());
    let writes = &actions.lock().expect("actions").writes;
    let methods: Vec<_> = writes
      .iter()
      .filter_map(|message| message["method"].as_str())
      .collect();
    assert_eq!(
      methods,
      [
        "initialize",
        "initialized",
        "thread/start",
        "mcpServerStatus/list",
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
    assert!(turn["params"]["outputSchema"].is_object());
  }

  #[test]
  fn missing_credential_isolation_rejects_before_protocol() {
    let profile = profile();
    let mut runtime = evidence(&profile);
    runtime
      .credential_isolation
      .parent_and_sibling_environ_denied = IsolationCheck::Failed;
    let actions = Arc::new(Mutex::new(Actions::default()));
    let transport = MockTransport {
      evidence: runtime,
      reads: successful_reads(),
      actions: Arc::clone(&actions),
    };
    let executor = executor_for(transport);
    let result = executor.execute(request(profile));
    assert!(matches!(
      result,
      ScheduledExecutionResult::PreflightRejected(ScheduledFailure {
        kind: ScheduledFailureKind::CredentialIsolationUnproven,
        ..
      })
    ));
    assert!(actions.lock().expect("actions").writes.is_empty());
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
      let executor = executor_for(transport);
      assert!(matches!(
        executor.execute(request(profile)),
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
      reap_results: VecDeque::from([
        ProcessExit::TimedOut,
        ProcessExit::TimedOut,
        ProcessExit::Exited,
      ]),
      ..Actions::default()
    }));
    let transport = MockTransport {
      evidence: runtime,
      reads,
      actions: Arc::clone(&actions),
    };
    let executor = executor_for(transport);
    assert!(matches!(
      executor.execute(request(profile)),
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
  }

  #[test]
  fn child_environment_rejects_secret_like_keys() {
    let mut profile = profile();
    profile
      .non_secret_env
      .insert("SLACK_BOT_TOKEN".to_owned(), "sentinel".to_owned());
    let executor = ScheduledCodexExecutor::new(
      |_: RequestedCapabilityProfile| -> Result<MockTransport, String> {
        panic!("transport must not start")
      },
    );
    assert!(matches!(
      executor.execute(request(profile)),
      ScheduledExecutionResult::PreflightRejected(ScheduledFailure {
        kind: ScheduledFailureKind::CredentialIsolationUnproven,
        ..
      })
    ));
  }

  #[test]
  fn config_contains_only_pinned_read_only_github_mcp() {
    let profile = profile();
    let config = profile.dedicated_config();
    assert!(config.contains("web_search = \"disabled\""));
    assert!(config.contains("[mcp_servers.github]"));
    assert!(config.contains("required = true"));
    assert!(!config.contains("token"));
    assert!(!config.contains("slack"));
    for tool in EXPECTED_GITHUB_TOOLS {
      assert!(config.contains(tool));
    }
  }

  #[test]
  fn runtime_version_schema_and_executable_drift_fail_closed() {
    for field in ["version", "schema", "executable"] {
      let profile = profile();
      let mut runtime = evidence(&profile);
      match field {
        "version" => runtime.codex_version = "0.145.0".to_owned(),
        "schema" => runtime.app_server_schema_sha256 = "b".repeat(64),
        "executable" => runtime.codex_program_sha256 = "c".repeat(64),
        _ => unreachable!(),
      }
      let actions = Arc::new(Mutex::new(Actions::default()));
      let transport = MockTransport {
        evidence: runtime,
        reads: successful_reads(),
        actions: Arc::clone(&actions),
      };
      assert!(matches!(
        executor_for(transport).execute(request(profile)),
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
        "auth" => inventory["data"][0]["authStatus"] = json!("bearerToken"),
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
      assert!(matches!(
        executor_for(transport).execute(request(profile)),
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
  fn commentary_only_completion_returns_no_final_response() {
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
    assert!(matches!(
      executor_for(transport).execute(request(profile)),
      ScheduledExecutionResult::Completed {
        final_response: None,
        ..
      }
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
    assert!(matches!(
      executor_for(transport).execute(request(profile)),
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
  fn direct_transport_drop_kills_and_reaps_its_process_group() {
    let unique = format!(
      "codeoff-scheduled-process-test-{}-{}",
      std::process::id(),
      now_unix_seconds()
    );
    let base = std::env::temp_dir().join(unique);
    let cwd = base.join("workspace");
    let codex_home = base.join("codex-home");
    let pid_file = base.join("grandchild.pid");
    fs::create_dir(&base).expect("base");
    fs::create_dir(&cwd).expect("cwd");
    let program =
      PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/process-tree-app-server.sh");
    let mut profile = profile();
    profile.codex_program = program.clone();
    profile.codex_program_sha256 = sha256_file(&program).expect("program hash");
    profile.codex_home = codex_home.clone();
    profile.cwd = cwd.clone();
    profile.non_secret_env.insert(
      "TEST_GRANDCHILD_PID_FILE".to_owned(),
      pid_file.display().to_string(),
    );
    profile.config_sha256 = sha256_hex(profile.dedicated_config().as_bytes());
    prepare_scheduled_codex_home(&profile).expect("codex home");
    let runtime = evidence(&profile);
    let started = Instant::now();
    let transport = StdioScheduledJsonlTransport::spawn(&profile, runtime).expect("spawn");
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
