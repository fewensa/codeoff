use std::error::Error;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(test)]
use codeoff_agent_codex::ScheduledFailure;
use codeoff_agent_codex::{
  GITHUB_MCP_ACCESS_TOKEN_ENV, RemoteIsolationPermitEnvelope, ScheduledCodexRequest,
  ScheduledExecutionIdentity, ScheduledExecutionResult, ScheduledFailureKind,
  build_supervised_scheduled_codex_executor, enable_scheduled_executor_subreaper,
  load_trusted_owner_scheduled_deployment_authority,
};
use codeoff_config::{
  CodeoffConfig, ScheduledRunnerGatewayConfig, ScheduledRunnerRole, SchedulerRuntimeConfig,
  SlackConfig,
};
use codeoff_runtime::scheduled_execution::ScheduledExecutor;
use codeoff_runtime::scheduled_remote_protocol::{
  AdmissionFrame, ErrorFrame, MAX_READY_TTL_MILLIS, PreparedFrame, REMOTE_PROTOCOL_VERSION,
  ReadinessRequestFrame, ReadyFrame, RemoteFrame, RemoteMessage, RemoteResultKind, ResultFrame,
  RunBinding, StartFrame,
};
use codeoff_runtime::scheduled_runner_broker::{
  RemoteScheduledExecutionBackend, ScheduledRunnerBroker, ScheduledRunnerBrokerConfig,
};
use codeoff_runtime::scheduled_runner_control::{
  ScheduledRunnerControlConfig as LocalControlConfig, ScheduledRunnerControlConnection,
  relay_runner_frames,
};
use codeoff_runtime::scheduled_runner_evidence::{
  RunnerEvidenceClaims, RunnerEvidenceKind, RunnerEvidenceSigner, cleanup_evidence_payload_digest,
  prepared_evidence_payload_digest, ready_evidence_payload_digest, result_evidence_payload_digest,
};
#[cfg(test)]
use codeoff_runtime::scheduled_runner_evidence::{RunnerEvidenceVerifier, SignedRunnerEvidence};
use codeoff_runtime::scheduled_runner_executor::{
  ProtectedScheduledExecutorListener, ScheduledRunnerExecutorConfig, current_process_credentials,
  decode_scheduled_remote_task, harden_scheduled_executor_process,
};
use codeoff_runtime::scheduled_runner_grant::{
  ExpectedRemoteExecutionGrant, RemoteExecutionGrantSigner, RemoteExecutionGrantVerifier,
  SignedRemoteExecutionGrant,
};
use codeoff_runtime::scheduled_runner_tls::{
  ScheduledRunnerIoPolicy, ScheduledRunnerTlsClient, ScheduledRunnerTlsError,
  ScheduledRunnerTlsPaths, ScheduledRunnerTlsServer, load_root_owned_bounded_file,
  session_challenge, session_nonce,
};
use codeoff_state::{ScheduledExecutorEpochAuthority, StateStore};
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;

use crate::scheduled_codex::RemoteCodexPermitIssuer;

pub(crate) struct ScheduledRunnerGateway {
  listener: TcpListener,
  tls: Arc<ScheduledRunnerTlsServer>,
  broker: ScheduledRunnerBroker,
  connections: Arc<Semaphore>,
}

impl ScheduledRunnerGateway {
  pub(crate) async fn run_until(
    self,
    mut shutdown: watch::Receiver<bool>,
  ) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut tasks = JoinSet::new();
    loop {
      let permit = tokio::select! {
        changed = shutdown.changed() => {
          if changed.is_err() || *shutdown.borrow() {
            break;
          }
          continue;
        }
        permit = Arc::clone(&self.connections).acquire_owned() => permit?,
      };
      let accepted = tokio::select! {
        changed = shutdown.changed() => {
          if changed.is_err() || *shutdown.borrow() {
            break;
          }
          continue;
        }
        accepted = self.listener.accept() => accepted,
      };
      let (stream, _) = accepted?;
      let tls = Arc::clone(&self.tls);
      let broker = self.broker.clone();
      tasks.spawn(async move {
        let _permit = permit;
        let result = async {
          let connection = tls.accept(stream).await.map_err(|error| {
            io::Error::other(format!("scheduled runner TLS rejected connection: {error}"))
          })?;
          broker.run_connection(connection).await.map_err(|error| {
            io::Error::other(format!(
              "scheduled runner broker rejected connection: {error}"
            ))
          })
        }
        .await;
        if let Err(error) = result {
          eprintln!("scheduled runner connection closed: {error}");
        }
      });
      while tasks.try_join_next().is_some() {}
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
  }
}

fn load_gateway_grant_signer(
  role: &ScheduledRunnerGatewayConfig,
) -> Result<Arc<RemoteExecutionGrantSigner>, Box<dyn Error>> {
  Ok(Arc::new(RemoteExecutionGrantSigner::load(
    &role.execution_grant_private_key_path,
    &role.execution_grant_key_id,
  )?))
}

pub(crate) async fn build_gateway(
  config: &CodeoffConfig,
  state: StateStore,
) -> Result<(ScheduledExecutor, ScheduledRunnerGateway), Box<dyn Error>> {
  config
    .agent
    .scheduled_codex
    .validate_remote_runner_role(ScheduledRunnerRole::Gateway)?;
  validate_gateway_environment(|name| std::env::var_os(name).is_some())?;
  let role = config
    .agent
    .scheduled_codex
    .remote_runner
    .gateway
    .as_ref()
    .ok_or_else(|| io::Error::other("scheduled runner gateway configuration missing"))?;
  let (profile, authority) =
    load_trusted_owner_scheduled_deployment_authority(&config.agent.scheduled_codex)
      .map_err(|failure| io::Error::other(failure.message))?;
  let now_seconds = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
  state
    .register_scheduled_executor_epoch(
      &ScheduledExecutorEpochAuthority {
        schema_version: authority.schema_version,
        deployment_epoch: authority.deployment_epoch,
        attestation_id: authority.attestation_id.clone(),
        attestation_digest: authority.attestation_digest.clone(),
        profile_digest: authority.profile_digest.clone(),
        issued_at: i64::try_from(authority.issued_at_unix_seconds)?,
        expires_at: i64::try_from(authority.expires_at_unix_seconds)?,
      },
      now_seconds,
    )
    .await?;
  let grant_signer = load_gateway_grant_signer(role)?;
  let broker = ScheduledRunnerBroker::new(
    ScheduledRunnerBrokerConfig {
      schema_version: authority.schema_version,
      deployment_epoch: u64::try_from(authority.deployment_epoch)?,
      attestation_id: authority.attestation_id.clone(),
      profile_digest: authority.profile_digest.clone(),
      signed_not_after_unix_seconds: i64::try_from(authority.expires_at_unix_seconds)?,
      gateway_image_digest: profile.gateway_image_digest.clone(),
      runner_image_digest: profile.runner_image_digest.clone(),
      runner_workload_identity: profile.runner_workload_identity.clone(),
      runner_client_spki_sha256: profile.runner_client_cert_public_key_fingerprint.clone(),
      credential_revision: profile.credential_revision.clone(),
      github_mcp_configured_artifact_sha256: profile.github_mcp_configured_artifact_sha256.clone(),
      github_mcp_configured_endpoint_identity: profile
        .github_mcp_configured_endpoint_identity
        .clone(),
      github_mcp_access_auth_mode: authority.github_mcp_access_auth_mode.clone(),
      github_mcp_access_token_revision: authority.github_mcp_access_token_revision.clone(),
      execution_grant_key_revision: role.execution_grant_key_revision.clone(),
      execution_grant_signer_identity: role.execution_grant_signer_identity.clone(),
      executor_evidence_public_key: load_root_owned_bounded_file(
        &role.executor_evidence_public_key_path,
        32,
      )?,
      executor_evidence_key_id: role.executor_evidence_key_id.clone(),
      executor_evidence_key_revision: role.executor_evidence_key_revision.clone(),
      executor_evidence_signer_identity: role.executor_evidence_signer_identity.clone(),
      executor_identity: format!(
        "uid:{}:gid:{}",
        config.agent.scheduled_codex.trusted_owner_uid,
        config.agent.scheduled_codex.trusted_owner_gid
      ),
      max_connections: role.max_connections,
      admission_ttl: Duration::from_millis(role.readiness_ttl_ms),
    },
    grant_signer,
  )?;
  let tls = Arc::new(ScheduledRunnerTlsServer::load(
    &ScheduledRunnerTlsPaths {
      certificate_chain: role.server_certificate_path.clone(),
      private_key: role.server_private_key_path.clone(),
      trust_bundle: role.client_ca_bundle_path.clone(),
    },
    broker.expected_authorized_peer(),
    ScheduledRunnerIoPolicy {
      handshake_timeout: Duration::from_millis(role.handshake_timeout_ms),
      read_timeout: Duration::from_millis(role.frame_timeout_ms),
      write_timeout: Duration::from_millis(role.frame_timeout_ms),
    },
  )?);
  let listener = TcpListener::bind(&role.bind).await?;
  let issuer = Arc::new(RemoteCodexPermitIssuer::new(
    state,
    authority,
    profile.credential_revision,
  ));
  let backend =
    RemoteScheduledExecutionBackend::new(broker.clone(), tokio::runtime::Handle::current(), issuer);
  Ok((
    ScheduledExecutor::new(Arc::new(backend)),
    ScheduledRunnerGateway {
      listener,
      tls,
      broker,
      connections: Arc::new(Semaphore::new(role.max_connections)),
    },
  ))
}

pub(crate) fn run_control(config: CodeoffConfig) -> Result<(), Box<dyn Error>> {
  config
    .agent
    .scheduled_codex
    .validate_remote_runner_role(ScheduledRunnerRole::Control)?;
  validate_dedicated_worker_surface(&config, ScheduledRunnerRole::Control)?;
  let observed = current_process_credentials();
  let role = config
    .agent
    .scheduled_codex
    .remote_runner
    .control
    .as_ref()
    .ok_or_else(|| io::Error::other("scheduled runner control configuration missing"))?;
  if observed.uid != role.control_uid || observed.gid != role.control_gid {
    return Err(io::Error::other("scheduled runner control process identity mismatch").into());
  }
  let runtime = tokio::runtime::Runtime::new()?;
  runtime.block_on(run_control_loop(config))
}

async fn run_control_loop(config: CodeoffConfig) -> Result<(), Box<dyn Error>> {
  let mut attempt = 0_u32;
  loop {
    let session = run_control_session(config.clone());
    tokio::pin!(session);
    let failed = tokio::select! {
      signal = tokio::signal::ctrl_c() => {
        signal?;
        return Ok(());
      }
      result = &mut session => {
        if let Err(error) = result {
          eprintln!("scheduled runner session ended: {error}");
          true
        } else {
          false
        }
      }
    };
    attempt = if failed {
      attempt.saturating_add(1).min(16)
    } else {
      0
    };
    let delay = reconnect_delay(attempt.saturating_sub(1));
    tokio::select! {
      signal = tokio::signal::ctrl_c() => {
        signal?;
        return Ok(());
      }
      () = tokio::time::sleep(delay) => {}
    }
  }
}

fn reconnect_delay(attempt: u32) -> Duration {
  let exponent = attempt.min(6);
  let base = 250_u64.saturating_mul(1_u64 << exponent).min(15_000);
  let jitter = unix_millis().unwrap_or(0) % 251;
  Duration::from_millis(base.saturating_add(jitter).min(15_250))
}

#[allow(
  clippy::too_many_lines,
  reason = "the one-shot control keeps TLS and relay ownership in one auditable scope"
)]
async fn run_control_session(config: CodeoffConfig) -> Result<(), Box<dyn Error>> {
  let role = config
    .agent
    .scheduled_codex
    .remote_runner
    .control
    .as_ref()
    .ok_or_else(|| io::Error::other("scheduled runner control configuration missing"))?;
  let frame_timeout = Duration::from_millis(role.frame_timeout_ms);
  let client = ScheduledRunnerTlsClient::load_for_owner(
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
    role.control_uid,
    role.control_gid,
  )?;
  let address = tokio::net::lookup_host(&role.gateway_address)
    .await?
    .next()
    .ok_or_else(|| io::Error::other("scheduled runner gateway address did not resolve"))?;
  let mut remote = client.connect(address).await?;
  let runner_session_nonce = session_nonce(&remote.channel_binding);
  let challenge = session_challenge(&remote.channel_binding);
  let now = unix_millis()?;
  let configured_ttl = role.readiness_ttl_ms.min(MAX_READY_TTL_MILLIS);
  if configured_ttl == 0 {
    return Err(io::Error::other("scheduled runner readiness TTL is zero").into());
  }
  let ready_until_unix_millis = now.saturating_add(configured_ttl);
  let mut local = ScheduledRunnerControlConnection::connect(&LocalControlConfig {
    socket_path: role.local_socket_path.clone(),
    executor_uid: role.expected_executor_uid,
    executor_gid: role.expected_executor_gid,
    connect_timeout: Duration::from_millis(role.connect_timeout_ms),
    read_timeout: frame_timeout,
    write_timeout: frame_timeout,
  })
  .await?
  .framed;
  local
    .write_frame(&RemoteFrame {
      version: REMOTE_PROTOCOL_VERSION,
      session_nonce: runner_session_nonce.clone(),
      sequence: 1,
      message: RemoteMessage::ReadinessRequest(ReadinessRequestFrame {
        challenge: challenge.clone(),
        ready_until_unix_millis,
      }),
    })
    .await?;
  let ready_frame = local
    .read_frame(unix_millis()?)
    .await?
    .ok_or_else(|| io::Error::other("scheduled runner executor closed before readiness"))?;
  let RemoteMessage::Ready(ready) = &ready_frame.message else {
    return Err(io::Error::other("scheduled runner executor did not provide readiness").into());
  };
  if ready_frame.session_nonce != runner_session_nonce
    || ready_frame.sequence != 1
    || ready.challenge != challenge
    || ready.ready_until_unix_millis != ready_until_unix_millis
  {
    return Err(io::Error::other("scheduled runner executor readiness binding mismatch").into());
  }
  remote.framed.write_frame(&ready_frame).await?;
  relay_runner_frames(&mut remote.framed, &mut local, &runner_session_nonce).await?;
  Ok(())
}

pub(crate) fn run_executor(config: CodeoffConfig) -> Result<(), Box<dyn Error>> {
  config
    .agent
    .scheduled_codex
    .validate_remote_runner_role(ScheduledRunnerRole::Executor)?;
  validate_dedicated_worker_surface(&config, ScheduledRunnerRole::Executor)?;
  let observed = current_process_credentials();
  if observed.uid != config.agent.scheduled_codex.trusted_owner_uid
    || observed.gid != config.agent.scheduled_codex.trusted_owner_gid
  {
    return Err(io::Error::other("scheduled runner executor process identity mismatch").into());
  }
  enable_scheduled_executor_subreaper().map_err(io::Error::other)?;
  harden_scheduled_executor_process()?;
  let runtime = tokio::runtime::Runtime::new()?;
  runtime.block_on(run_executor_loop(config))
}

async fn run_executor_loop(config: CodeoffConfig) -> Result<(), Box<dyn Error>> {
  loop {
    let session = run_executor_session(config.clone());
    tokio::pin!(session);
    tokio::select! {
      signal = tokio::signal::ctrl_c() => {
        signal?;
        return Ok(());
      }
      result = &mut session => {
        if let Err(error) = result {
          eprintln!("scheduled executor session ended: {error}");
        }
      }
    }
    tokio::select! {
      signal = tokio::signal::ctrl_c() => {
        signal?;
        return Ok(());
      }
      () = tokio::time::sleep(Duration::from_millis(250)) => {}
    }
  }
}

#[allow(
  clippy::result_large_err,
  clippy::too_many_lines,
  reason = "the one-shot executor keeps the complete protocol phase order auditable"
)]
async fn run_executor_session(config: CodeoffConfig) -> Result<(), Box<dyn Error>> {
  let role = config
    .agent
    .scheduled_codex
    .remote_runner
    .executor
    .as_ref()
    .ok_or_else(|| io::Error::other("scheduled runner executor configuration missing"))?;
  let frame_timeout = Duration::from_millis(role.frame_timeout_ms);
  let listener = ProtectedScheduledExecutorListener::bind(ScheduledRunnerExecutorConfig {
    socket_path: role.local_socket_path.clone(),
    control_uid: role.expected_control_uid,
    control_gid: role.expected_control_gid,
    accept_timeout: Duration::from_millis(role.accept_timeout_ms),
    read_timeout: frame_timeout,
    write_timeout: frame_timeout,
  })?;
  let connection = listener.accept().await?;
  let mut framed = connection.framed;
  let built = build_supervised_scheduled_codex_executor(
    &config.agent.scheduled_codex,
    role.codex_child_uid,
    role.codex_child_gid,
  )
  .map_err(|failure| io::Error::other(failure.message))?;
  let evidence_signer =
    RunnerEvidenceSigner::load(&role.evidence_private_key_path, &role.evidence_key_id)?;
  let grant_verifier = RemoteExecutionGrantVerifier::load(
    &role.execution_grant_public_key_path,
    &role.execution_grant_key_id,
  )?;
  let now = unix_millis()?;
  let readiness_frame = framed
    .read_frame(now)
    .await?
    .ok_or_else(|| io::Error::other("scheduled runner control closed before readiness request"))?;
  let RemoteMessage::ReadinessRequest(readiness) = &readiness_frame.message else {
    return Err(io::Error::other("scheduled runner expected readiness request").into());
  };
  if readiness_frame.sequence != 1 {
    return Err(io::Error::other("scheduled runner readiness sequence mismatch").into());
  }
  let remaining = readiness.ready_until_unix_millis.saturating_sub(now);
  if remaining == 0 || remaining > MAX_READY_TTL_MILLIS {
    return Err(io::Error::other("scheduled runner readiness deadline invalid").into());
  }
  let attested = built
    .probe_readiness(Duration::from_millis(remaining))
    .map_err(|_| io::Error::other("scheduled runner readiness failed"))?;
  let attested_profile_json = attested.canonical_json();
  let attested_profile_digest = sha256_hex(attested_profile_json.as_bytes());
  let mut ready_message = ReadyFrame {
    signed_evidence_json: String::new(),
    challenge: readiness.challenge.clone(),
    ready_until_unix_millis: readiness.ready_until_unix_millis,
    attested_profile_digest: attested_profile_digest.clone(),
    attested_profile_json: attested_profile_json.clone(),
    deployment_epoch: u64::try_from(built.authority.deployment_epoch)?,
    profile_digest: built.authority.profile_digest.clone(),
    gateway_image_digest: attested.gateway_image_digest.clone(),
    runner_image_digest: attested.runner_image_digest.clone(),
    runner_workload_identity: attested.runner_workload_identity.clone(),
    runner_client_cert_public_key_fingerprint: attested
      .runner_client_cert_public_key_fingerprint
      .clone(),
    credential_revision: attested.credential_revision.clone(),
    github_mcp_access_auth_mode: attested.github_mcp_access_auth_mode.clone(),
    github_mcp_access_token_revision: attested.github_mcp_access_token_revision.clone(),
  };
  let ready_payload_digest = ready_evidence_payload_digest(&ready_message);
  ready_message.signed_evidence_json = evidence_signer
    .sign(&runner_evidence_claims(
      role,
      RunnerEvidenceKind::Ready,
      &readiness_frame.session_nonce,
      &readiness.challenge,
      1,
      now,
      readiness.ready_until_unix_millis,
      u64::try_from(built.authority.deployment_epoch)?,
      &built.authority.profile_digest,
      &attested_profile_digest,
      &attested.credential_revision,
      &ready_payload_digest,
    ))?
    .canonical_json();
  framed
    .write_frame(&RemoteFrame {
      version: REMOTE_PROTOCOL_VERSION,
      session_nonce: readiness_frame.session_nonce.clone(),
      sequence: 1,
      message: RemoteMessage::Ready(ready_message),
    })
    .await?;
  let admission_frame = framed
    .read_frame(unix_millis()?)
    .await?
    .ok_or_else(|| io::Error::other("scheduled runner control closed before admission"))?;
  let RemoteMessage::Admission(admission) = &admission_frame.message else {
    return Err(io::Error::other("scheduled runner expected admission").into());
  };
  validate_admission(
    &admission_frame,
    admission,
    &built.authority,
    &readiness.challenge,
    unix_millis()?,
  )?;
  let prepare_frame = framed
    .read_frame(unix_millis()?)
    .await?
    .ok_or_else(|| io::Error::other("scheduled runner control closed before prepare"))?;
  let RemoteMessage::Prepare(prepare) = &prepare_frame.message else {
    return Err(io::Error::other("scheduled runner expected prepare").into());
  };
  if prepare_frame.session_nonce != admission_frame.session_nonce || prepare_frame.sequence != 3 {
    return Err(io::Error::other("scheduled runner prepare sequence mismatch").into());
  }
  validate_binding(
    &prepare.binding,
    &built.authority,
    &built.profile.credential_revision,
  )?;
  let signed_grant =
    SignedRemoteExecutionGrant::parse_canonical_json(&prepare.execution_grant_json)?;
  grant_verifier.verify_and_consume(
    &signed_grant,
    &ExpectedRemoteExecutionGrant {
      signer_identity: &role.execution_grant_signer_identity,
      key_revision: &role.execution_grant_key_revision,
      grant_sequence: 1,
      session_nonce: &prepare_frame.session_nonce,
      challenge: &readiness.challenge,
      admission_nonce: &admission.admission_nonce,
      expires_at_unix_millis: admission.expires_at_unix_millis,
      deployment_epoch: u64::try_from(built.authority.deployment_epoch)?,
      profile_digest: &built.authority.profile_digest,
      now_unix_millis: unix_millis()?,
    },
    prepare,
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
  let capability_profile_digest = sha256_hex(capability_profile.as_bytes());
  let preparation_nonce = preparation_nonce(
    &prepare.isolation_permit_envelope_json,
    &prepare_frame.session_nonce,
    &capability_profile,
  );
  let mut prepared_message = PreparedFrame {
    signed_evidence_json: String::new(),
    binding: prepare.binding.clone(),
    preparation_nonce: preparation_nonce.clone(),
    attested_profile_digest: capability_profile_digest.clone(),
    attested_profile_json: capability_profile,
    github_mcp_access_auth_mode: prepared
      .attested_profile()
      .github_mcp_access_auth_mode
      .clone(),
    github_mcp_access_token_revision: prepared
      .attested_profile()
      .github_mcp_access_token_revision
      .clone(),
  };
  let prepared_payload_digest = prepared_evidence_payload_digest(&prepared_message);
  prepared_message.signed_evidence_json = evidence_signer
    .sign(&runner_evidence_claims(
      role,
      RunnerEvidenceKind::Prepared,
      &prepare_frame.session_nonce,
      &readiness.challenge,
      2,
      unix_millis()?,
      admission.expires_at_unix_millis,
      u64::try_from(built.authority.deployment_epoch)?,
      &built.authority.profile_digest,
      &capability_profile_digest,
      &built.profile.credential_revision,
      &prepared_payload_digest,
    ))?
    .canonical_json();
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
      execution_result(
        binding,
        preparation_nonce,
        result,
        &evidence_signer,
        role,
        &prepare_frame.session_nonce,
        &readiness.challenge,
        &capability_profile_digest,
      )?,
    ))
    .await?;
  Ok(())
}

fn validate_admission(
  frame: &RemoteFrame,
  admission: &AdmissionFrame,
  authority: &codeoff_agent_codex::ScheduledDeploymentAuthority,
  expected_challenge: &str,
  now: u64,
) -> Result<(), Box<dyn Error>> {
  if frame.version != REMOTE_PROTOCOL_VERSION
    || frame.sequence != 2
    || admission.challenge != expected_challenge
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
  if frame.sequence != 4
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
    | ScheduledExecutionResult::Failed(failure) => (
      "runner-preflight-rejected",
      safe_failure_summary(failure.kind).to_owned(),
      false,
    ),
    ScheduledExecutionResult::TransportLost(_) => (
      "runner-transport-lost",
      "scheduled runner transport was lost".to_owned(),
      true,
    ),
    ScheduledExecutionResult::CleanupUnproven(_) => (
      "runner-cleanup-unproven",
      "scheduled runner cleanup was not proven".to_owned(),
      true,
    ),
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

#[allow(
  clippy::too_many_arguments,
  reason = "terminal evidence binds the complete runner session"
)]
fn execution_result(
  binding: RunBinding,
  preparation_nonce: String,
  result: ScheduledExecutionResult,
  signer: &RunnerEvidenceSigner,
  role: &codeoff_config::ScheduledRunnerExecutorConfig,
  session_nonce: &str,
  challenge: &str,
  observed_profile_digest: &str,
) -> Result<RemoteMessage, Box<dyn Error>> {
  if matches!(result, ScheduledExecutionResult::CleanupUnproven(_)) {
    return Ok(RemoteMessage::Error(ErrorFrame {
      binding: Some(binding),
      preparation_nonce: Some(preparation_nonce),
      code: "runner-cleanup-unproven".to_owned(),
      message: "scheduled runner cleanup was not proven".to_owned(),
      retryable: true,
    }));
  }
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
        "message": safe_failure_summary(failure.kind),
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
    ScheduledExecutionResult::CleanupUnproven(_) => unreachable!("handled before result signing"),
  };
  let now = unix_millis()?;
  let mut result = ResultFrame {
    signed_evidence_json: String::new(),
    signed_cleanup_evidence_json: String::new(),
    binding,
    preparation_nonce,
    kind,
    result_json,
  };
  let result_payload_digest = result_evidence_payload_digest(&result);
  result.signed_evidence_json = signer
    .sign(&runner_evidence_claims(
      role,
      RunnerEvidenceKind::Result,
      session_nonce,
      challenge,
      3,
      now,
      now.saturating_add(MAX_READY_TTL_MILLIS),
      result.binding.deployment_epoch,
      &result.binding.profile_digest,
      observed_profile_digest,
      &result.binding.credential_revision,
      &result_payload_digest,
    ))?
    .canonical_json();
  let cleanup_payload_digest = cleanup_evidence_payload_digest(&result);
  result.signed_cleanup_evidence_json = signer
    .sign(&runner_evidence_claims(
      role,
      RunnerEvidenceKind::Cleanup,
      session_nonce,
      challenge,
      3,
      now,
      now.saturating_add(MAX_READY_TTL_MILLIS),
      result.binding.deployment_epoch,
      &result.binding.profile_digest,
      observed_profile_digest,
      &result.binding.credential_revision,
      &cleanup_payload_digest,
    ))?
    .canonical_json();
  Ok(RemoteMessage::Result(result))
}

#[allow(clippy::too_many_arguments)]
fn runner_evidence_claims(
  role: &codeoff_config::ScheduledRunnerExecutorConfig,
  kind: RunnerEvidenceKind,
  session_nonce: &str,
  challenge: &str,
  sequence: u64,
  issued_at_unix_millis: u64,
  expires_at_unix_millis: u64,
  deployment_epoch: u64,
  deployment_profile_digest: &str,
  observed_profile_digest: &str,
  credential_revision: &str,
  payload_digest: &str,
) -> RunnerEvidenceClaims {
  RunnerEvidenceClaims {
    kind,
    algorithm_version: "ed25519-v1".to_owned(),
    signer_identity: role.evidence_signer_identity.clone(),
    key_revision: role.evidence_key_revision.clone(),
    session_nonce: session_nonce.to_owned(),
    challenge: challenge.to_owned(),
    sequence,
    issued_at_unix_millis,
    expires_at_unix_millis,
    deployment_epoch,
    deployment_profile_digest: deployment_profile_digest.to_owned(),
    observed_profile_digest: observed_profile_digest.to_owned(),
    executor_identity: format!(
      "uid:{}:gid:{}",
      current_process_credentials().uid,
      current_process_credentials().gid
    ),
    credential_revision: credential_revision.to_owned(),
    payload_digest: payload_digest.to_owned(),
  }
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

const fn safe_failure_summary(kind: ScheduledFailureKind) -> &'static str {
  match kind {
    ScheduledFailureKind::InvalidRequest => "scheduled runner request was rejected",
    ScheduledFailureKind::ProtocolIncompatible => "scheduled runner protocol was rejected",
    ScheduledFailureKind::CapabilityMismatch => "scheduled runner capability was rejected",
    ScheduledFailureKind::CredentialIsolationUnproven => {
      "scheduled runner credential isolation was not proven"
    }
    ScheduledFailureKind::OutputSchemaViolation => "scheduled runner output was rejected",
    ScheduledFailureKind::TurnFailed => "scheduled runner turn failed",
    ScheduledFailureKind::TimedOut => "scheduled runner timed out",
    ScheduledFailureKind::Interrupted => "scheduled runner was interrupted",
    ScheduledFailureKind::Transport => "scheduled runner transport failed",
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

const DEDICATED_RUNNER_SECRET_ENVIRONMENT: [&str; 4] = [
  "CODEOFF_SCHEDULED_GITHUB_PAT",
  "CODEOFF_SCHEDULED_RUNNER_CLIENT_PRIVATE_KEY",
  "CODEOFF_SCHEDULED_RUNNER_ISSUER_PRIVATE_KEY",
  "GITHUB_PAT",
];

fn validate_gateway_environment(present: impl Fn(&str) -> bool) -> Result<(), Box<dyn Error>> {
  if let Some(name) = DEDICATED_RUNNER_SECRET_ENVIRONMENT
    .iter()
    .copied()
    .chain(std::iter::once(GITHUB_MCP_ACCESS_TOKEN_ENV))
    .find(|name| present(name))
  {
    return Err(
      io::Error::other(format!(
        "scheduled runner gateway forbids dedicated secret environment {name}"
      ))
      .into(),
    );
  }
  Ok(())
}

fn validate_dedicated_worker_surface(
  config: &CodeoffConfig,
  role: ScheduledRunnerRole,
) -> Result<(), Box<dyn Error>> {
  validate_dedicated_worker_surface_with(config, role, |name| std::env::var_os(name).is_some())
}

#[allow(
  clippy::default_trait_access,
  reason = "MCP and live Codex config types are intentionally not exported by codeoff-config"
)]
fn validate_dedicated_worker_surface_with(
  config: &CodeoffConfig,
  role: ScheduledRunnerRole,
  present: impl Fn(&str) -> bool,
) -> Result<(), Box<dyn Error>> {
  if config.database_url().is_some()
    || config.state_dir() != std::path::Path::new("./.codeoff")
    || config.scheduler != SchedulerRuntimeConfig::default()
  {
    return Err(
      io::Error::other(
        "scheduled runner worker forbids database, state-directory, and scheduler surfaces",
      )
      .into(),
    );
  }
  if config.slack != SlackConfig::default()
    || config.mcp != Default::default()
    || config.agent.codex_app_server != Default::default()
  {
    return Err(
      io::Error::other(
        "scheduled runner worker forbids Slack, live Codex, and MCP server configuration",
      )
      .into(),
    );
  }
  let mut forbidden = vec![
    "CODEOFF_DATABASE_URL",
    "CODEOFF_STATE_DIR",
    "DATABASE_URL",
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "OPENAI_API_KEY",
    config.slack.app_token_env.as_str(),
    config.slack.bot_token_env.as_str(),
    config.slack.signing_secret_env.as_str(),
  ];
  forbidden.extend(DEDICATED_RUNNER_SECRET_ENVIRONMENT);
  if role != ScheduledRunnerRole::Executor {
    forbidden.push(GITHUB_MCP_ACCESS_TOKEN_ENV);
  }
  forbidden.extend(
    config
      .slack
      .user_tokens
      .values()
      .map(|token| token.token_env.as_str()),
  );
  if let Some(name) = forbidden.into_iter().find(|name| present(name)) {
    let role_name = match role {
      ScheduledRunnerRole::Gateway => "gateway",
      ScheduledRunnerRole::Control => "control",
      ScheduledRunnerRole::Executor => "executor",
    };
    return Err(
      io::Error::other(format!(
        "scheduled runner {role_name} forbids ambient secret environment {name}"
      ))
      .into(),
    );
  }
  if role == ScheduledRunnerRole::Executor && !present(GITHUB_MCP_ACCESS_TOKEN_ENV) {
    return Err(
      io::Error::other(format!(
        "scheduled runner executor requires {GITHUB_MCP_ACCESS_TOKEN_ENV}"
      ))
      .into(),
    );
  }
  Ok(())
}

fn unix_millis() -> Result<u64, Box<dyn Error>> {
  Ok(u64::try_from(
    SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
  )?)
}

fn sha256_hex(bytes: &[u8]) -> String {
  format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
  use super::*;
  use codeoff_runtime::scheduled_remote_protocol::{PrepareFrame, PreparedFrame};
  use codeoff_runtime::scheduled_runner_tls::ScheduledRunnerFramed;
  use ring::rand::SystemRandom;
  use ring::signature::{Ed25519KeyPair, KeyPair};
  use std::fs;
  use std::os::unix::fs::PermissionsExt;

  #[test]
  fn gateway_rejects_only_dedicated_runner_secret_environment() {
    assert!(validate_gateway_environment(|name| name == "SLACK_BOT_TOKEN").is_ok());
    assert!(
      validate_gateway_environment(|name| name == "CODEOFF_SCHEDULED_RUNNER_CLIENT_PRIVATE_KEY")
        .is_err()
    );
    assert!(validate_gateway_environment(|name| name == GITHUB_MCP_ACCESS_TOKEN_ENV).is_err());
  }

  #[test]
  fn dedicated_workers_reject_state_live_and_secret_surfaces() {
    let config = CodeoffConfig::default();
    assert!(
      validate_dedicated_worker_surface_with(&config, ScheduledRunnerRole::Control, |_| false)
        .is_ok()
    );
    assert!(
      validate_dedicated_worker_surface_with(&config, ScheduledRunnerRole::Control, |name| {
        name == GITHUB_MCP_ACCESS_TOKEN_ENV
      })
      .is_err()
    );
    assert!(
      validate_dedicated_worker_surface_with(&config, ScheduledRunnerRole::Executor, |_| false)
        .is_err()
    );
    assert!(
      validate_dedicated_worker_surface_with(&config, ScheduledRunnerRole::Executor, |name| {
        name == GITHUB_MCP_ACCESS_TOKEN_ENV
      })
      .is_ok()
    );
    assert!(
      validate_dedicated_worker_surface_with(&config, ScheduledRunnerRole::Executor, |name| {
        name == "OPENAI_API_KEY"
      })
      .is_err()
    );

    let mut live = config.clone();
    live.mcp.enabled = true;
    assert!(
      validate_dedicated_worker_surface_with(&live, ScheduledRunnerRole::Executor, |_| false)
        .is_err()
    );

    let mut stateful = config;
    stateful.database.url = Some("sqlite:///run/codeoff/state.db".to_owned());
    assert!(
      validate_dedicated_worker_surface_with(&stateful, ScheduledRunnerRole::Control, |_| false)
        .is_err()
    );
  }

  #[test]
  fn preparation_error_frames_use_only_fixed_safe_summaries() {
    const SENTINEL: &str = "rpc-controlled-secret-sentinel";
    let binding = RunBinding {
      run_id: "run-1".to_owned(),
      job_id: "job-1".to_owned(),
      attempt: 1,
      fence_token: 1,
      authority_digest: "a".repeat(64),
      profile_digest: "b".repeat(64),
      deployment_epoch: 1,
      credential_revision: "credential-v1".to_owned(),
    };
    let message = preparation_error(
      &binding,
      ScheduledExecutionResult::PreflightRejected(ScheduledFailure {
        kind: ScheduledFailureKind::ProtocolIncompatible,
        message: SENTINEL.to_owned(),
      }),
    );
    let RemoteMessage::Error(error) = message else {
      panic!("error frame expected");
    };
    assert_eq!(error.code, "runner-preflight-rejected");
    assert_eq!(error.message, "scheduled runner protocol was rejected");
    assert!(!error.message.contains(SENTINEL));
  }

  #[test]
  fn cleanup_unproven_execution_result_sends_error_without_cleanup_evidence() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("evidence key");
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("parse evidence key");
    let private_key = temp.path().join("executor.pk8");
    let public_key = temp.path().join("executor.pub");
    fs::write(&private_key, pkcs8.as_ref()).expect("private key");
    fs::write(&public_key, key_pair.public_key().as_ref()).expect("public key");
    fs::set_permissions(&private_key, fs::Permissions::from_mode(0o400)).expect("private mode");
    fs::set_permissions(&public_key, fs::Permissions::from_mode(0o400)).expect("public mode");
    let signer = RunnerEvidenceSigner::load(&private_key, "executor-key-1").expect("signer");
    let binding = RunBinding {
      run_id: "run-1".to_owned(),
      job_id: "job-1".to_owned(),
      attempt: 1,
      fence_token: 1,
      authority_digest: "a".repeat(64),
      profile_digest: "b".repeat(64),
      deployment_epoch: 1,
      credential_revision: "credential-v1".to_owned(),
    };
    let role = codeoff_config::ScheduledRunnerExecutorConfig {
      local_socket_path: temp.path().join("executor.sock"),
      execution_grant_public_key_path: public_key,
      execution_grant_key_id: "gateway-grant-key-1".to_owned(),
      execution_grant_key_revision: "gateway-grant-2026-07".to_owned(),
      execution_grant_signer_identity: "spiffe://codeoff/gateway/production".to_owned(),
      evidence_private_key_path: private_key,
      evidence_key_id: "executor-key-1".to_owned(),
      evidence_key_revision: "executor-evidence-2026-07".to_owned(),
      evidence_signer_identity: "spiffe://codeoff/executor/production".to_owned(),
      expected_control_uid: current_process_credentials().uid,
      expected_control_gid: current_process_credentials().gid,
      codex_child_uid: 65_534,
      codex_child_gid: 65_534,
      accept_timeout_ms: 2_000,
      frame_timeout_ms: 2_000,
    };
    let message = execution_result(
      binding.clone(),
      "c".repeat(64),
      ScheduledExecutionResult::CleanupUnproven(ScheduledFailure {
        kind: ScheduledFailureKind::Transport,
        message: "cleanup sentinel".to_owned(),
      }),
      &signer,
      &role,
      &"d".repeat(64),
      &"e".repeat(64),
      &"f".repeat(64),
    )
    .expect("cleanup-unproven result");
    let RemoteMessage::Error(error) = message else {
      panic!("cleanup-unproven execution must not emit a result frame");
    };
    assert_eq!(error.binding, Some(binding));
    assert_eq!(error.preparation_nonce, Some("c".repeat(64)));
    assert_eq!(error.code, "runner-cleanup-unproven");
    assert_eq!(error.message, "scheduled runner cleanup was not proven");
    assert!(error.retryable);
  }

  #[test]
  fn reconnect_delay_is_bounded() {
    assert!(reconnect_delay(0) >= Duration::from_millis(250));
    assert!(reconnect_delay(32) <= Duration::from_millis(15_250));
  }

  #[test]
  fn production_executor_rejects_arbitrary_mcp_artifact_before_opening_files() {
    let mut profile = codeoff_agent_codex::RequestedCapabilityProfile {
      codex_program: "/opt/codeoff/bin/codex".into(),
      codex_program_sha256: "1".repeat(64),
      codex_home: "/var/lib/codeoff/scheduled-codex".into(),
      cwd: "/work/codeoff-scheduled".into(),
      github_mcp_url: "http://127.0.0.1:8090/mcp".to_owned(),
      github_mcp_configured_artifact_sha256: "2".repeat(64),
      github_mcp_configured_endpoint_identity: "github-mcp-scheduled-v1".to_owned(),
      github_mcp_access_auth_mode: "supervisor-dynamic-tools-v1".to_owned(),
      github_mcp_access_token_revision: "mcp-channel-v1".to_owned(),
      credential_reference: "kubernetes:codeoff/github-mcp".to_owned(),
      permission_policy_revision: "scheduled-read-only-v1".to_owned(),
      config_revision: "scheduled-codex-v1".to_owned(),
      config_sha256: String::new(),
      gateway_image_digest: format!("sha256:{}", "3".repeat(64)),
      runner_image_digest: format!("sha256:{}", "4".repeat(64)),
      runner_workload_identity: "spiffe://codeoff/runner/production".to_owned(),
      runner_client_cert_public_key_fingerprint: "5".repeat(64),
      credential_revision: "github-readonly-2026-07".to_owned(),
    };
    profile.config_sha256 = sha256_hex(profile.dedicated_config().as_bytes());
    let config = codeoff_config::ScheduledCodexConfig {
      execution_backend: codeoff_config::ScheduledExecutionBackend::RemoteRunner,
      remote_runner: codeoff_config::ScheduledRemoteRunnerConfig::default(),
      codex_program: profile.codex_program,
      codex_program_sha256: profile.codex_program_sha256,
      codex_home: profile.codex_home,
      cwd: profile.cwd,
      github_mcp_url: profile.github_mcp_url,
      github_mcp_artifact_path: "/opt/codeoff/bin/untrusted-github-mcp".into(),
      github_mcp_artifact_sha256: profile.github_mcp_configured_artifact_sha256,
      github_mcp_endpoint_identity: profile.github_mcp_configured_endpoint_identity,
      github_mcp_access_auth_mode: profile.github_mcp_access_auth_mode,
      github_mcp_access_token_revision: profile.github_mcp_access_token_revision,
      credential_reference: profile.credential_reference,
      permission_policy_revision: profile.permission_policy_revision,
      config_revision: profile.config_revision,
      config_sha256: profile.config_sha256,
      gateway_image_digest: profile.gateway_image_digest,
      runner_image_digest: profile.runner_image_digest,
      runner_workload_identity: profile.runner_workload_identity,
      runner_client_cert_public_key_fingerprint: profile.runner_client_cert_public_key_fingerprint,
      credential_revision: profile.credential_revision,
      isolation_attestation_path: "/run/codeoff/isolation-attestation.json".into(),
      isolation_trust_bundle_path: "/opt/codeoff/isolation-trust-bundle.json".into(),
      trusted_owner_uid: 0,
      trusted_owner_gid: 0,
      runtime_uid: 65_534,
      runtime_gid: 65_534,
    };
    let failure = build_supervised_scheduled_codex_executor(&config, 65_534, 65_534)
      .err()
      .expect("arbitrary MCP artifact must fail closed");
    assert_eq!(
      failure.message,
      "github_mcp_artifact_digest_not_pinned_v1_6_0"
    );
  }

  #[tokio::test]
  #[allow(
    clippy::too_many_lines,
    reason = "the protocol integration test keeps the complete bidirectional phase order visible"
  )]
  async fn relay_carries_complete_prepare_start_result_exchange() {
    let nonce = "a".repeat(64);
    let binding = RunBinding {
      run_id: "run-1".to_owned(),
      job_id: "job-1".to_owned(),
      attempt: 1,
      fence_token: 1,
      authority_digest: "b".repeat(64),
      profile_digest: "c".repeat(64),
      deployment_epoch: 1,
      credential_revision: "credential-v1".to_owned(),
    };
    let preparation_nonce = "d".repeat(64);
    let temp = tempfile::tempdir().expect("temporary directory");
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("evidence key");
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("parse evidence key");
    let private_key = temp.path().join("executor.pk8");
    let public_key = temp.path().join("executor.pub");
    fs::write(&private_key, pkcs8.as_ref()).expect("private key");
    fs::write(&public_key, key_pair.public_key().as_ref()).expect("public key");
    fs::set_permissions(&private_key, fs::Permissions::from_mode(0o400)).expect("private mode");
    fs::set_permissions(&public_key, fs::Permissions::from_mode(0o400)).expect("public mode");
    let signer = RunnerEvidenceSigner::load(&private_key, "executor-key-1").expect("root signer");
    let verifier =
      RunnerEvidenceVerifier::load(&public_key, "executor-key-1").expect("gateway verifier");
    let evidence_role = codeoff_config::ScheduledRunnerExecutorConfig {
      local_socket_path: temp.path().join("executor.sock"),
      execution_grant_public_key_path: public_key.clone(),
      execution_grant_key_id: "gateway-grant-key-1".to_owned(),
      execution_grant_key_revision: "gateway-grant-2026-07".to_owned(),
      execution_grant_signer_identity: "spiffe://codeoff/gateway/production".to_owned(),
      evidence_private_key_path: private_key,
      evidence_key_id: "executor-key-1".to_owned(),
      evidence_key_revision: "executor-evidence-2026-07".to_owned(),
      evidence_signer_identity: "spiffe://codeoff/executor/production".to_owned(),
      expected_control_uid: current_process_credentials().uid,
      expected_control_gid: current_process_credentials().gid,
      codex_child_uid: 65_534,
      codex_child_gid: 65_534,
      accept_timeout_ms: 2_000,
      frame_timeout_ms: 2_000,
    };
    let (mut remote_relay, mut remote_gateway) =
      local_framed_pair(temp.path().join("remote.sock")).await;
    let (mut local_relay, mut local_executor) =
      local_framed_pair(temp.path().join("local.sock")).await;
    let executor_binding = binding.clone();
    let executor_preparation_nonce = preparation_nonce.clone();

    let relay = relay_runner_frames(&mut remote_relay, &mut local_relay, &nonce);
    let gateway = async {
      remote_gateway
        .write_frame(&test_remote_frame(
          &nonce,
          1,
          RemoteMessage::Admission(AdmissionFrame {
            challenge: "e".repeat(64),
            admission_nonce: "f".repeat(64),
            expires_at_unix_millis: unix_millis().expect("time") + 5_000,
            deployment_epoch: 1,
            profile_digest: binding.profile_digest.clone(),
          }),
        ))
        .await
        .expect("admission");
      remote_gateway
        .write_frame(&test_remote_frame(
          &nonce,
          2,
          RemoteMessage::Prepare(PrepareFrame {
            binding: binding.clone(),
            execution_grant_json: r#"{"schema_version":1}"#.to_owned(),
            isolation_permit_envelope_json: r#"{"schema_version":1}"#.to_owned(),
            task_json: r#"{"instruction":"check"}"#.to_owned(),
            definition_json: r#"{"prompt":"check"}"#.to_owned(),
            capability_json: r#"{"tools":[]}"#.to_owned(),
            targets_json: r#"{"targets":[]}"#.to_owned(),
          }),
        ))
        .await
        .expect("prepare");
      let prepared = remote_gateway
        .read_frame(unix_millis().expect("time"))
        .await
        .expect("prepared read")
        .expect("prepared frame");
      let RemoteMessage::Prepared(prepared_payload) = &prepared.message else {
        panic!("prepared frame expected")
      };
      let evidence =
        SignedRunnerEvidence::parse_canonical_json(&prepared_payload.signed_evidence_json)
          .expect("opaque prepared evidence");
      let claims = verifier
        .verify(&evidence, unix_millis().expect("time"))
        .expect("prepared verify");
      assert_eq!(claims.kind, RunnerEvidenceKind::Prepared);
      assert_eq!(
        claims.payload_digest,
        prepared_evidence_payload_digest(prepared_payload)
      );
      remote_gateway
        .write_frame(&test_remote_frame(
          &nonce,
          3,
          RemoteMessage::Start(StartFrame {
            binding: binding.clone(),
            preparation_nonce: preparation_nonce.clone(),
          }),
        ))
        .await
        .expect("start");
      let result = remote_gateway
        .read_frame(unix_millis().expect("time"))
        .await
        .expect("result read")
        .expect("result frame");
      let RemoteMessage::Result(result_payload) = &result.message else {
        panic!("result frame expected")
      };
      let evidence =
        SignedRunnerEvidence::parse_canonical_json(&result_payload.signed_evidence_json)
          .expect("opaque result evidence");
      let claims = verifier
        .verify(&evidence, unix_millis().expect("time"))
        .expect("result verify");
      assert_eq!(claims.kind, RunnerEvidenceKind::Result);
      assert_eq!(
        claims.payload_digest,
        result_evidence_payload_digest(result_payload)
      );
      let cleanup_evidence =
        SignedRunnerEvidence::parse_canonical_json(&result_payload.signed_cleanup_evidence_json)
          .expect("opaque cleanup evidence");
      let cleanup_claims = verifier
        .verify(&cleanup_evidence, unix_millis().expect("time"))
        .expect("cleanup verify");
      assert_eq!(cleanup_claims.kind, RunnerEvidenceKind::Cleanup);
      assert_eq!(
        cleanup_claims.payload_digest,
        cleanup_evidence_payload_digest(result_payload)
      );
    };
    let executor = async {
      for expected in ["admission", "prepare"] {
        let frame = local_executor
          .read_frame(unix_millis().expect("time"))
          .await
          .expect("gateway frame read")
          .expect("gateway frame");
        assert_eq!(
          match frame.message {
            RemoteMessage::Admission(_) => "admission",
            RemoteMessage::Prepare(_) => "prepare",
            _ => "unexpected",
          },
          expected
        );
      }
      let now = unix_millis().expect("time");
      let mut prepared = PreparedFrame {
        signed_evidence_json: String::new(),
        binding: executor_binding.clone(),
        preparation_nonce: executor_preparation_nonce.clone(),
        attested_profile_json: "{}".to_owned(),
        attested_profile_digest: "1".repeat(64),
        github_mcp_access_auth_mode: "supervisor-dynamic-tools-v1".to_owned(),
        github_mcp_access_token_revision: "mcp-channel-v1".to_owned(),
      };
      let payload_digest = prepared_evidence_payload_digest(&prepared);
      prepared.signed_evidence_json = signer
        .sign(&runner_evidence_claims(
          &evidence_role,
          RunnerEvidenceKind::Prepared,
          &nonce,
          &"e".repeat(64),
          2,
          now,
          now + 5_000,
          executor_binding.deployment_epoch,
          &executor_binding.profile_digest,
          &prepared.attested_profile_digest,
          &executor_binding.credential_revision,
          &payload_digest,
        ))
        .expect("prepared sign")
        .canonical_json();
      local_executor
        .write_frame(&test_remote_frame(
          &nonce,
          2,
          RemoteMessage::Prepared(prepared),
        ))
        .await
        .expect("prepared");
      let start = local_executor
        .read_frame(unix_millis().expect("time"))
        .await
        .expect("start read")
        .expect("start frame");
      assert_eq!(start.sequence, 4);
      assert!(matches!(start.message, RemoteMessage::Start(_)));
      let mut result = ResultFrame {
        signed_evidence_json: String::new(),
        signed_cleanup_evidence_json: String::new(),
        binding: executor_binding,
        preparation_nonce: executor_preparation_nonce,
        kind: RemoteResultKind::Completed,
        result_json: r#"{"schema_version":1,"summary":"ok"}"#.to_owned(),
      };
      let payload_digest = result_evidence_payload_digest(&result);
      result.signed_evidence_json = signer
        .sign(&runner_evidence_claims(
          &evidence_role,
          RunnerEvidenceKind::Result,
          &nonce,
          &"e".repeat(64),
          3,
          now,
          now + 5_000,
          result.binding.deployment_epoch,
          &result.binding.profile_digest,
          &"1".repeat(64),
          &result.binding.credential_revision,
          &payload_digest,
        ))
        .expect("result sign")
        .canonical_json();
      let cleanup_payload_digest = cleanup_evidence_payload_digest(&result);
      result.signed_cleanup_evidence_json = signer
        .sign(&runner_evidence_claims(
          &evidence_role,
          RunnerEvidenceKind::Cleanup,
          &nonce,
          &"e".repeat(64),
          3,
          now,
          now + 5_000,
          result.binding.deployment_epoch,
          &result.binding.profile_digest,
          &"1".repeat(64),
          &result.binding.credential_revision,
          &cleanup_payload_digest,
        ))
        .expect("cleanup sign")
        .canonical_json();
      local_executor
        .write_frame(&test_remote_frame(&nonce, 3, RemoteMessage::Result(result)))
        .await
        .expect("result");
    };
    let (relay, (), ()) = tokio::join!(relay, gateway, executor);
    relay.expect("relay exchange");
  }

  fn test_remote_frame(nonce: &str, sequence: u64, message: RemoteMessage) -> RemoteFrame {
    RemoteFrame {
      version: REMOTE_PROTOCOL_VERSION,
      session_nonce: nonce.to_owned(),
      sequence,
      message,
    }
  }

  async fn local_framed_pair(
    socket_path: std::path::PathBuf,
  ) -> (
    ScheduledRunnerFramed<tokio::net::UnixStream>,
    ScheduledRunnerFramed<tokio::net::UnixStream>,
  ) {
    let credentials = current_process_credentials();
    let timeout = Duration::from_secs(2);
    let listener = ProtectedScheduledExecutorListener::bind(ScheduledRunnerExecutorConfig {
      socket_path: socket_path.clone(),
      control_uid: credentials.uid,
      control_gid: credentials.gid,
      accept_timeout: timeout,
      read_timeout: timeout,
      write_timeout: timeout,
    })
    .expect("local listener");
    let accepted = listener.accept();
    let control_config = LocalControlConfig {
      socket_path,
      executor_uid: credentials.uid,
      executor_gid: credentials.gid,
      connect_timeout: timeout,
      read_timeout: timeout,
      write_timeout: timeout,
    };
    let connected = ScheduledRunnerControlConnection::connect(&control_config);
    let (accepted, connected) = tokio::join!(accepted, connected);
    (
      accepted.expect("accepted local peer").framed,
      connected.expect("connected local peer").framed,
    )
  }
}
