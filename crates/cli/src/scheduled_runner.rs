use std::error::Error;
use std::io;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use codeoff_agent_codex::{
  RemoteIsolationPermitEnvelope, ScheduledCodexRequest, ScheduledExecutionIdentity,
  ScheduledExecutionResult, ScheduledFailureKind, build_production_scheduled_codex_executor,
  load_trusted_owner_scheduled_deployment_authority,
};
use codeoff_config::{CodeoffConfig, ScheduledRunnerRole};
use codeoff_runtime::scheduled_remote_protocol::{
  AdmissionFrame, ErrorFrame, MAX_READY_TTL_MILLIS, PreparedFrame, REMOTE_PROTOCOL_VERSION,
  ReadyFrame, RemoteFrame, RemoteMessage, RemoteResultKind, ResultFrame, RunBinding, StartFrame,
};
use codeoff_runtime::scheduled_runner_control::{
  ProtectedScheduledExecutorListener, ScheduledRunnerControlConfig as LocalControlConfig,
};
use codeoff_runtime::scheduled_runner_executor::{
  ScheduledRunnerExecutorConfig, ScheduledRunnerExecutorConnection, current_process_credentials,
  decode_scheduled_remote_task,
};
use codeoff_runtime::scheduled_runner_tls::{
  ScheduledRunnerIoPolicy, ScheduledRunnerTlsClient, ScheduledRunnerTlsError,
  ScheduledRunnerTlsPaths, session_challenge, session_nonce,
};
use serde_json::json;
use sha2::{Digest, Sha256};

pub(crate) fn run_control(
  config: CodeoffConfig,
  config_path: Option<PathBuf>,
) -> Result<(), Box<dyn Error>> {
  config
    .agent
    .scheduled_codex
    .validate_remote_runner_role(ScheduledRunnerRole::Control)?;
  let observed = current_process_credentials();
  if observed.uid != config.agent.scheduled_codex.trusted_owner_uid
    || observed.gid != config.agent.scheduled_codex.trusted_owner_gid
  {
    return Err(io::Error::other("scheduled runner control process identity mismatch").into());
  }
  let runtime = tokio::runtime::Runtime::new()?;
  runtime.block_on(run_control_async(config, config_path))
}

#[allow(
  clippy::too_many_lines,
  reason = "the one-shot control keeps TLS, child, and relay ownership in one auditable scope"
)]
async fn run_control_async(
  config: CodeoffConfig,
  config_path: Option<PathBuf>,
) -> Result<(), Box<dyn Error>> {
  let role = config
    .agent
    .scheduled_codex
    .remote_runner
    .control
    .as_ref()
    .ok_or_else(|| io::Error::other("scheduled runner control configuration missing"))?;
  let frame_timeout = Duration::from_millis(role.frame_timeout_ms);
  let listener = ProtectedScheduledExecutorListener::bind(LocalControlConfig {
    socket_path: role.local_socket_path.clone(),
    executor_uid: role.expected_executor_uid,
    executor_gid: role.expected_executor_gid,
    accept_timeout: Duration::from_millis(role.connect_timeout_ms),
  })?;
  let (profile, authority) =
    load_trusted_owner_scheduled_deployment_authority(&config.agent.scheduled_codex)
      .map_err(|failure| io::Error::other(failure.message))?;
  let client = ScheduledRunnerTlsClient::load(
    &ScheduledRunnerTlsPaths {
      certificate_chain: role.client_certificate_path.clone(),
      private_key: role.client_private_key_path.clone(),
      trust_bundle: role.server_ca_bundle_path.clone(),
    },
    &role.gateway_server_name,
    ScheduledRunnerIoPolicy {
      handshake_timeout: Duration::from_millis(role.connect_timeout_ms),
      read_timeout: frame_timeout,
      write_timeout: frame_timeout,
    },
  )?;
  let address = tokio::net::lookup_host(&role.gateway_address)
    .await?
    .next()
    .ok_or_else(|| io::Error::other("scheduled runner gateway address did not resolve"))?;
  let mut remote = client.connect(address).await?;
  let runner_session_nonce = session_nonce(&remote.channel_binding);
  let challenge = session_challenge(&remote.channel_binding);
  let now = unix_millis()?;
  let configured_ttl = MAX_READY_TTL_MILLIS.min(
    authority
      .expires_at_unix_seconds
      .saturating_mul(1_000)
      .saturating_sub(now),
  );
  if configured_ttl == 0 {
    return Err(io::Error::other("scheduled runner authority expired before readiness").into());
  }
  remote
    .framed
    .write_frame(&RemoteFrame {
      version: REMOTE_PROTOCOL_VERSION,
      session_nonce: runner_session_nonce.clone(),
      sequence: 1,
      message: RemoteMessage::Ready(ReadyFrame {
        challenge,
        ready_until_unix_millis: now.saturating_add(configured_ttl),
        deployment_epoch: u64::try_from(authority.deployment_epoch)?,
        profile_digest: authority.profile_digest,
        gateway_image_digest: profile.gateway_image_digest,
        runner_image_digest: profile.runner_image_digest,
        runner_workload_identity: profile.runner_workload_identity,
        runner_client_cert_public_key_fingerprint: profile
          .runner_client_cert_public_key_fingerprint,
        credential_revision: profile.credential_revision,
      }),
    })
    .await?;
  let mut child = spawn_executor(
    config_path.as_ref(),
    role.expected_executor_uid,
    role.expected_executor_gid,
  )?;
  let accepted = match listener.accept().await {
    Ok(connection) => connection,
    Err(error) => {
      stop_child(&mut child);
      return Err(error.into());
    }
  };
  let mut local = accepted.into_framed(frame_timeout, frame_timeout);
  let relay = relay_runner_frames(&mut remote.framed, &mut local, &runner_session_nonce).await;
  stop_child(&mut child);
  relay
}

#[allow(
  clippy::similar_names,
  reason = "UID and GID are an exact paired process identity"
)]
fn spawn_executor(
  config_path: Option<&PathBuf>,
  executor_uid: u32,
  executor_gid: u32,
) -> Result<Child, Box<dyn Error>> {
  let executable = std::env::current_exe()?;
  let mut command = Command::new(executable);
  command
    .env_clear()
    .env("LANG", "C.UTF-8")
    .env("LC_ALL", "C.UTF-8")
    .env("PATH", "/usr/local/bin:/usr/bin:/bin")
    .uid(executor_uid)
    .gid(executor_gid)
    .stdin(Stdio::null())
    .stdout(Stdio::inherit())
    .stderr(Stdio::inherit());
  if let Some(path) = config_path {
    command.arg("--config").arg(path);
  }
  command.args(["worker", "scheduled-runner-executor"]);
  Ok(command.spawn()?)
}

fn stop_child(child: &mut Child) {
  if child.try_wait().ok().flatten().is_none() {
    let _ = child.kill();
  }
  let _ = child.wait();
}

async fn relay_runner_frames<R, L>(
  remote: &mut codeoff_runtime::scheduled_runner_tls::ScheduledRunnerFramed<R>,
  local: &mut codeoff_runtime::scheduled_runner_tls::ScheduledRunnerFramed<L>,
  expected_session_nonce: &str,
) -> Result<(), Box<dyn Error>>
where
  R: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
  L: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
  let mut gateway_sequence = 0_u64;
  let mut runner_sequence = 1_u64;
  loop {
    tokio::select! {
      incoming = remote.read_frame(unix_millis()?) => {
        let Some(frame) = incoming? else {
          return Err(io::Error::other("scheduled runner gateway disconnected").into());
        };
        gateway_sequence = gateway_sequence.saturating_add(1);
        if frame.session_nonce != expected_session_nonce
          || frame.sequence != gateway_sequence
          || !matches!(frame.message, RemoteMessage::Admission(_) | RemoteMessage::Prepare(_) | RemoteMessage::Start(_) | RemoteMessage::Cancel(_))
        {
          return Err(io::Error::other("scheduled runner gateway frame rejected").into());
        }
        let terminal = matches!(frame.message, RemoteMessage::Cancel(_));
        local.write_frame(&frame).await?;
        if terminal {
          return Ok(());
        }
      }
      incoming = local.read_frame(unix_millis()?) => {
        let Some(frame) = incoming? else {
          return Err(io::Error::other("scheduled runner executor disconnected").into());
        };
        runner_sequence = runner_sequence.saturating_add(1);
        if frame.session_nonce != expected_session_nonce
          || frame.sequence != runner_sequence
          || !matches!(frame.message, RemoteMessage::Prepared(_) | RemoteMessage::Heartbeat(_) | RemoteMessage::Result(_) | RemoteMessage::Error(_))
        {
          return Err(io::Error::other("scheduled runner executor frame rejected").into());
        }
        let terminal = matches!(frame.message, RemoteMessage::Result(_) | RemoteMessage::Error(_));
        remote.write_frame(&frame).await?;
        if terminal {
          return Ok(());
        }
      }
    }
  }
}

pub(crate) fn run_executor(config: CodeoffConfig) -> Result<(), Box<dyn Error>> {
  config
    .agent
    .scheduled_codex
    .validate_remote_runner_role(ScheduledRunnerRole::Executor)?;
  let observed = current_process_credentials();
  if observed.uid != config.agent.scheduled_codex.runtime_uid
    || observed.gid != config.agent.scheduled_codex.runtime_gid
  {
    return Err(io::Error::other("scheduled runner executor process identity mismatch").into());
  }
  let runtime = tokio::runtime::Runtime::new()?;
  runtime.block_on(run_executor_async(config))
}

#[allow(
  clippy::result_large_err,
  clippy::too_many_lines,
  reason = "the one-shot executor keeps the complete protocol phase order auditable"
)]
async fn run_executor_async(config: CodeoffConfig) -> Result<(), Box<dyn Error>> {
  let role = config
    .agent
    .scheduled_codex
    .remote_runner
    .executor
    .as_ref()
    .ok_or_else(|| io::Error::other("scheduled runner executor configuration missing"))?;
  let frame_timeout = Duration::from_millis(role.frame_timeout_ms);
  let connection = ScheduledRunnerExecutorConnection::connect(&ScheduledRunnerExecutorConfig {
    socket_path: role.local_socket_path.clone(),
    control_uid: role.expected_control_uid,
    control_gid: role.expected_control_gid,
    connect_timeout: Duration::from_millis(role.accept_timeout_ms),
    read_timeout: frame_timeout,
    write_timeout: frame_timeout,
  })
  .await?;
  let mut framed = connection.framed;
  let built = build_production_scheduled_codex_executor(&config.agent.scheduled_codex)
    .map_err(|failure| io::Error::other(failure.message))?;
  let now = unix_millis()?;
  let admission_frame = framed
    .read_frame(now)
    .await?
    .ok_or_else(|| io::Error::other("scheduled runner control closed before admission"))?;
  let RemoteMessage::Admission(admission) = &admission_frame.message else {
    return Err(io::Error::other("scheduled runner expected admission").into());
  };
  validate_admission(&admission_frame, admission, &built.authority, now)?;
  let prepare_frame = framed
    .read_frame(unix_millis()?)
    .await?
    .ok_or_else(|| io::Error::other("scheduled runner control closed before prepare"))?;
  let RemoteMessage::Prepare(prepare) = &prepare_frame.message else {
    return Err(io::Error::other("scheduled runner expected prepare").into());
  };
  if prepare_frame.session_nonce != admission_frame.session_nonce || prepare_frame.sequence != 2 {
    return Err(io::Error::other("scheduled runner prepare sequence mismatch").into());
  }
  validate_binding(
    &prepare.binding,
    &built.authority,
    &built.profile.credential_revision,
  )?;
  let identity = execution_identity(&prepare.binding)?;
  let permit = RemoteIsolationPermitEnvelope::import(
    &prepare.isolation_permit_envelope_json,
    &built.authority,
    &identity,
    &prepare.binding.authority_digest,
    &prepare.binding.credential_revision,
    &prepare_frame.session_nonce,
  )
  .map_err(|failure| io::Error::other(failure.message))?;
  let task = decode_scheduled_remote_task(&prepare.task_json, &prepare.binding)?;
  let cancellation = Arc::new(AtomicBool::new(false));
  let request = scheduled_request(
    &config,
    task,
    identity,
    Arc::clone(&cancellation),
    &built.profile,
  );
  let executor = Arc::clone(&built.executor);
  let prepared = tokio::task::spawn_blocking(move || executor.prepare(request, permit))
    .await
    .map_err(|_| io::Error::other("scheduled runner prepare task failed"))?;
  let prepared = match prepared {
    Ok(prepared) => prepared,
    Err(result) => {
      let error = preparation_error(&prepare.binding, result);
      framed
        .write_frame(&runner_frame(&prepare_frame, 2, error))
        .await?;
      return Ok(());
    }
  };
  let capability_profile = prepared.attested_profile().canonical_json();
  let preparation_nonce = preparation_nonce(
    &prepare.isolation_permit_envelope_json,
    &prepare_frame.session_nonce,
    &capability_profile,
  );
  let prepared_message = PreparedFrame {
    binding: prepare.binding.clone(),
    preparation_nonce: preparation_nonce.clone(),
    attested_profile_digest: sha256_hex(capability_profile.as_bytes()),
    attested_profile_json: capability_profile,
  };
  framed
    .write_frame(&runner_frame(
      &prepare_frame,
      2,
      RemoteMessage::Prepared(prepared_message),
    ))
    .await?;
  let start_frame = framed
    .read_frame(unix_millis()?)
    .await?
    .ok_or_else(|| io::Error::other("scheduled runner control closed before start"))?;
  let RemoteMessage::Start(start) = &start_frame.message else {
    return Err(io::Error::other("scheduled runner expected start").into());
  };
  validate_start(
    &start_frame,
    start,
    &prepare.binding,
    &preparation_nonce,
    &prepare_frame.session_nonce,
  )?;
  let binding = prepare.binding.clone();
  let mut execution = tokio::task::spawn_blocking(move || prepared.execute());
  let result = loop {
    tokio::select! {
      completed = &mut execution => {
        break completed.map_err(|_| io::Error::other("scheduled runner execution task failed"))?;
      }
      incoming = framed.read_frame(unix_millis()?) => {
        match incoming {
          Err(ScheduledRunnerTlsError::FrameTimeout) => {}
          Ok(Some(frame)) if frame.session_nonce == prepare_frame.session_nonce => {
            if let RemoteMessage::Cancel(cancel) = frame.message {
              if cancel.binding != binding {
                return Err(io::Error::other("scheduled runner cancel binding mismatch").into());
              }
              cancellation.store(true, Ordering::Release);
            } else {
              return Err(io::Error::other("scheduled runner received invalid execution frame").into());
            }
          }
          Ok(None) => {
            cancellation.store(true, Ordering::Release);
            return Err(io::Error::other("scheduled runner control disconnected during execution").into());
          }
          Ok(Some(_)) | Err(_) => {
            cancellation.store(true, Ordering::Release);
            return Err(io::Error::other("scheduled runner control transport failed").into());
          }
        }
      }
    }
  };
  framed
    .write_frame(&runner_frame(
      &prepare_frame,
      3,
      execution_result(binding, preparation_nonce, result),
    ))
    .await?;
  Ok(())
}

fn validate_admission(
  frame: &RemoteFrame,
  admission: &AdmissionFrame,
  authority: &codeoff_agent_codex::ScheduledDeploymentAuthority,
  now: u64,
) -> Result<(), Box<dyn Error>> {
  if frame.version != REMOTE_PROTOCOL_VERSION
    || frame.sequence != 1
    || admission.expires_at_unix_millis <= now
    || admission.deployment_epoch != u64::try_from(authority.deployment_epoch)?
    || admission.profile_digest != authority.profile_digest
  {
    return Err(io::Error::other("scheduled runner admission binding mismatch").into());
  }
  Ok(())
}

fn validate_binding(
  binding: &RunBinding,
  authority: &codeoff_agent_codex::ScheduledDeploymentAuthority,
  credential_revision: &str,
) -> Result<(), Box<dyn Error>> {
  if binding.deployment_epoch != u64::try_from(authority.deployment_epoch)?
    || binding.profile_digest != authority.profile_digest
    || binding.credential_revision != credential_revision
  {
    return Err(io::Error::other("scheduled runner binding profile mismatch").into());
  }
  Ok(())
}

fn execution_identity(binding: &RunBinding) -> Result<ScheduledExecutionIdentity, Box<dyn Error>> {
  Ok(ScheduledExecutionIdentity {
    run_id: binding.run_id.clone(),
    job_id: binding.job_id.clone(),
    attempt: i64::from(binding.attempt),
    fence: i64::try_from(binding.fence_token)?,
  })
}

fn scheduled_request(
  config: &CodeoffConfig,
  task: codeoff_agent_contract::AgentTask,
  identity: ScheduledExecutionIdentity,
  cancellation: Arc<AtomicBool>,
  profile: &codeoff_agent_codex::RequestedCapabilityProfile,
) -> ScheduledCodexRequest {
  let cancellation_grace = Duration::from_millis(config.scheduler.run_cancellation_grace_ms);
  let third = cancellation_grace / 3;
  ScheduledCodexRequest {
    task,
    identity,
    profile: profile.clone(),
    cancellation,
    timeout: Duration::from_secs(u64::from(config.scheduler.run_timeout_seconds)),
    interrupt_grace: third,
    terminate_grace: third,
    kill_grace: cancellation_grace
      .saturating_sub(third)
      .saturating_sub(third),
  }
}

fn validate_start(
  frame: &RemoteFrame,
  start: &StartFrame,
  binding: &RunBinding,
  preparation_nonce: &str,
  session_nonce: &str,
) -> Result<(), Box<dyn Error>> {
  if frame.sequence != 3
    || frame.session_nonce != session_nonce
    || &start.binding != binding
    || start.preparation_nonce != preparation_nonce
  {
    return Err(io::Error::other("scheduled runner start binding mismatch").into());
  }
  Ok(())
}

fn preparation_error(binding: &RunBinding, result: ScheduledExecutionResult) -> RemoteMessage {
  let (code, message, retryable) = match result {
    ScheduledExecutionResult::PreflightRejected(failure)
    | ScheduledExecutionResult::Failed(failure) => {
      ("runner-preflight-rejected", failure.message, false)
    }
    ScheduledExecutionResult::TransportLost(failure) => {
      ("runner-transport-lost", failure.message, true)
    }
    ScheduledExecutionResult::Interrupted { .. } => (
      "runner-preflight-interrupted",
      "scheduled runner preparation was interrupted".to_owned(),
      true,
    ),
    ScheduledExecutionResult::Completed { .. } => (
      "runner-protocol-rejected",
      "scheduled prepare completed before START".to_owned(),
      false,
    ),
  };
  RemoteMessage::Error(ErrorFrame {
    binding: Some(binding.clone()),
    preparation_nonce: None,
    code: code.to_owned(),
    message,
    retryable,
  })
}

fn execution_result(
  binding: RunBinding,
  preparation_nonce: String,
  result: ScheduledExecutionResult,
) -> RemoteMessage {
  let (kind, result_json) = match result {
    ScheduledExecutionResult::Completed { output, .. } => (
      RemoteResultKind::Completed,
      json!({"schema_version": 1, "summary": output.summary}).to_string(),
    ),
    ScheduledExecutionResult::TransportLost(_) => (
      RemoteResultKind::OutcomeUnknown,
      json!({"schema_version": 1}).to_string(),
    ),
    ScheduledExecutionResult::Failed(failure)
    | ScheduledExecutionResult::PreflightRejected(failure) => (
      RemoteResultKind::Completed,
      json!({
        "failure_kind": failure_kind(failure.kind),
        "message": failure.message,
        "schema_version": 1,
      })
      .to_string(),
    ),
    ScheduledExecutionResult::Interrupted { .. } => (
      RemoteResultKind::Completed,
      json!({
        "failure_kind": "interrupted",
        "message": "scheduled runner execution was interrupted",
        "schema_version": 1,
      })
      .to_string(),
    ),
  };
  RemoteMessage::Result(ResultFrame {
    binding,
    preparation_nonce,
    kind,
    result_json,
  })
}

const fn failure_kind(kind: ScheduledFailureKind) -> &'static str {
  match kind {
    ScheduledFailureKind::InvalidRequest => "invalid_request",
    ScheduledFailureKind::ProtocolIncompatible => "protocol_incompatible",
    ScheduledFailureKind::CapabilityMismatch => "capability_mismatch",
    ScheduledFailureKind::CredentialIsolationUnproven => "credential_isolation_unproven",
    ScheduledFailureKind::OutputSchemaViolation => "output_schema_violation",
    ScheduledFailureKind::TurnFailed => "turn_failed",
    ScheduledFailureKind::TimedOut => "timed_out",
    ScheduledFailureKind::Interrupted => "interrupted",
    ScheduledFailureKind::Transport => "transport",
  }
}

fn runner_frame(source: &RemoteFrame, sequence: u64, message: RemoteMessage) -> RemoteFrame {
  RemoteFrame {
    version: REMOTE_PROTOCOL_VERSION,
    session_nonce: source.session_nonce.clone(),
    sequence,
    message,
  }
}

fn preparation_nonce(envelope: &str, session_nonce: &str, capability_profile: &str) -> String {
  sha256_hex(
    json!({
      "capability_profile": capability_profile,
      "domain": "scheduled-runner-preparation-nonce-v1",
      "permit_envelope": envelope,
      "session_nonce": session_nonce,
    })
    .to_string()
    .as_bytes(),
  )
}

fn unix_millis() -> Result<u64, Box<dyn Error>> {
  Ok(u64::try_from(
    SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
  )?)
}

fn sha256_hex(bytes: &[u8]) -> String {
  format!("{:x}", Sha256::digest(bytes))
}
