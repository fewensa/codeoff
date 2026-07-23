//! Gateway-owned broker and scheduled-execution backend for one remote runner session.
//!
//! The broker owns connection admission and protocol ordering.  Durable run authorization,
//! claiming, fencing, and terminal commits remain in `StateStore` through the existing
//! `ScheduledExecutionBackend` seam.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use codeoff_agent_contract::{InvocationPrincipalRef, InvocationSource, SessionMode, ToolPolicy};
use codeoff_core::{AttestedCapabilityProfile, CredentialRevision, EvidenceKeyId};
use codeoff_state::{ScheduledExecutorAdmission, ScheduledPrepareAuthority};
use rustls::crypto::CryptoProvider;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::runtime::Handle;
use tokio::sync::{Semaphore, mpsc, oneshot};

use crate::scheduled_execution::{
  BackendAuthorization, BackendPrepared, ExecutionResult, ExecutorReadiness, PrepareFailure,
  PrepareInput, PreparedExecution, RefreshedExecutorAdmission, ScheduledExecutionBackend,
};
use crate::scheduled_remote_protocol::{
  AdmissionFrame, CancelFrame, ErrorFrame, MAX_ADMISSION_TTL_MILLIS, PrepareFrame, PreparedFrame,
  REMOTE_PROTOCOL_VERSION, ReadyFrame, RemoteFrame, RemoteHeartbeatPhase, RemoteMessage,
  RemoteResultKind, ResultFrame, RunBinding, StartFrame,
};
use crate::scheduled_remote_session::{
  RemoteDisconnectOutcome, RemoteSessionRole, RemoteSessionState, RemoteTerminalDisposition,
};
use crate::scheduled_runner_evidence::{
  RunnerEvidenceKind, SignedRunnerEvidence, prepared_evidence_payload_digest,
  ready_evidence_payload_digest, result_evidence_payload_digest, verify_runner_evidence,
};
use crate::scheduled_runner_tls::{
  ScheduledRunnerAuthorizedPeer, ScheduledRunnerServerConnection, session_challenge, session_nonce,
};

const MAX_BROKER_CONNECTIONS: usize = 16;
const BROKER_COMMAND_CAPACITY: usize = 2;
const CANCELLATION_POLL_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduledRunnerBrokerConfig {
  pub schema_version: u32,
  pub deployment_epoch: u64,
  pub attestation_id: String,
  pub profile_digest: String,
  pub signed_not_after_unix_seconds: i64,
  pub gateway_image_digest: String,
  pub runner_image_digest: String,
  pub runner_workload_identity: String,
  pub runner_client_spki_sha256: String,
  pub credential_revision: String,
  pub github_mcp_access_auth_mode: String,
  pub github_mcp_access_token_revision: String,
  pub executor_evidence_public_key: Vec<u8>,
  pub executor_evidence_key_id: String,
  pub executor_evidence_key_revision: String,
  pub executor_evidence_signer_identity: String,
  pub executor_identity: String,
  pub max_connections: usize,
  pub admission_ttl: Duration,
}

impl ScheduledRunnerBrokerConfig {
  pub fn validate(&self) -> Result<(), ScheduledRunnerBrokerError> {
    if self.schema_version != 1
      || self.deployment_epoch == 0
      || self.signed_not_after_unix_seconds <= 0
      || !(1..=MAX_BROKER_CONNECTIONS).contains(&self.max_connections)
      || self.admission_ttl.is_zero()
      || self.admission_ttl > Duration::from_millis(MAX_ADMISSION_TTL_MILLIS)
      || self.executor_evidence_public_key.len() != 32
      || EvidenceKeyId::parse(&self.executor_evidence_key_id).is_err()
    {
      return Err(ScheduledRunnerBrokerError::InvalidConfiguration);
    }
    if !is_lowercase_sha256(&self.attestation_id)
      || !is_lowercase_sha256(&self.profile_digest)
      || !is_oci_digest(&self.gateway_image_digest)
      || !is_oci_digest(&self.runner_image_digest)
    {
      return Err(ScheduledRunnerBrokerError::InvalidConfiguration);
    }
    ScheduledRunnerAuthorizedPeer::new(
      &self.runner_workload_identity,
      &self.runner_client_spki_sha256,
    )
    .map_err(|_| ScheduledRunnerBrokerError::InvalidConfiguration)?;
    CredentialRevision::parse(&self.credential_revision)
      .map_err(|_| ScheduledRunnerBrokerError::InvalidConfiguration)?;
    if self.github_mcp_access_auth_mode != "bearer-token-env-v1"
      || CredentialRevision::parse(&self.github_mcp_access_token_revision).is_err()
    {
      return Err(ScheduledRunnerBrokerError::InvalidConfiguration);
    }
    Ok(())
  }
}

#[derive(Debug)]
pub enum ScheduledRunnerBrokerError {
  InvalidConfiguration,
  CapacityExceeded,
  ConnectionClosed,
  FirstFrameNotReady,
  SessionBindingMismatch,
  ReadyIdentityMismatch,
  DuplicateSession,
  StaleSession,
  SessionUnavailable,
  SessionExpired,
  SessionBusy,
  RandomnessUnavailable,
  ProtocolRejected,
  RunnerRejected,
  Transport,
  ResultInvalid,
}

impl fmt::Display for ScheduledRunnerBrokerError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(formatter, "{self:?}")
  }
}

impl std::error::Error for ScheduledRunnerBrokerError {}

#[derive(Clone)]
pub struct ScheduledRunnerBroker {
  inner: Arc<BrokerInner>,
}

struct BrokerInner {
  config: ScheduledRunnerBrokerConfig,
  connections: Arc<Semaphore>,
  current: Mutex<Option<Arc<RegisteredRunnerSession>>>,
}

impl ScheduledRunnerBroker {
  pub fn new(config: ScheduledRunnerBrokerConfig) -> Result<Self, ScheduledRunnerBrokerError> {
    config.validate()?;
    Ok(Self {
      inner: Arc::new(BrokerInner {
        connections: Arc::new(Semaphore::new(config.max_connections)),
        config,
        current: Mutex::new(None),
      }),
    })
  }

  #[must_use]
  pub fn expected_authorized_peer(&self) -> ScheduledRunnerAuthorizedPeer {
    ScheduledRunnerAuthorizedPeer::new(
      &self.inner.config.runner_workload_identity,
      &self.inner.config.runner_client_spki_sha256,
    )
    .expect("broker configuration is validated")
  }

  /// Registers and drives one already-authenticated TLS connection until terminal or disconnect.
  pub async fn run_connection(
    &self,
    mut connection: ScheduledRunnerServerConnection,
  ) -> Result<(), ScheduledRunnerBrokerError> {
    let permit = Arc::clone(&self.inner.connections)
      .try_acquire_owned()
      .map_err(|_| ScheduledRunnerBrokerError::CapacityExceeded)?;
    let now = unix_millis()?;
    let expected_session_nonce = session_nonce(&connection.channel_binding);
    let expected_challenge = session_challenge(&connection.channel_binding);
    let ready_frame = connection
      .framed
      .read_frame(now)
      .await
      .map_err(|_| ScheduledRunnerBrokerError::Transport)?
      .ok_or(ScheduledRunnerBrokerError::ConnectionClosed)?;
    let RemoteMessage::Ready(ready) = &ready_frame.message else {
      return Err(ScheduledRunnerBrokerError::FirstFrameNotReady);
    };
    let ready = ready.clone();
    self.validate_ready(
      &connection.authorized_peer,
      &ready_frame,
      &ready,
      &expected_session_nonce,
      &expected_challenge,
    )?;
    let (commands, receiver) = mpsc::channel(BROKER_COMMAND_CAPACITY);
    let session = Arc::new(RegisteredRunnerSession {
      session_nonce: expected_session_nonce,
      ready_frame,
      ready,
      commands,
      evidence_config: self.inner.config.clone(),
      connected: AtomicBool::new(true),
      slot: Mutex::new(None),
    });
    self.register(&session)?;
    let _registration = SessionRegistration {
      broker: self.clone(),
      session: Arc::clone(&session),
      _permit: permit,
    };
    run_registered_connection(connection, session, receiver).await
  }

  fn validate_ready(
    &self,
    authorized_peer: &ScheduledRunnerAuthorizedPeer,
    frame: &RemoteFrame,
    ready: &ReadyFrame,
    expected_session_nonce: &str,
    expected_challenge: &str,
  ) -> Result<(), ScheduledRunnerBrokerError> {
    if frame.version != REMOTE_PROTOCOL_VERSION
      || frame.sequence != 1
      || frame.session_nonce != expected_session_nonce
      || ready.challenge != expected_challenge
    {
      return Err(ScheduledRunnerBrokerError::SessionBindingMismatch);
    }
    let config = &self.inner.config;
    let now = unix_millis()?;
    let readiness_ttl_millis = u64::try_from(config.admission_ttl.as_millis())
      .map_err(|_| ScheduledRunnerBrokerError::InvalidConfiguration)?;
    let signed_not_after_millis = u64::try_from(config.signed_not_after_unix_seconds)
      .unwrap_or(0)
      .saturating_mul(1_000);
    if ready.ready_until_unix_millis <= now
      || ready.ready_until_unix_millis > now.saturating_add(readiness_ttl_millis)
      || ready.ready_until_unix_millis > signed_not_after_millis
    {
      return Err(ScheduledRunnerBrokerError::SessionExpired);
    }
    if ready.deployment_epoch < config.deployment_epoch {
      return Err(ScheduledRunnerBrokerError::StaleSession);
    }
    if ready.deployment_epoch != config.deployment_epoch
      || ready.profile_digest != config.profile_digest
      || ready.gateway_image_digest != config.gateway_image_digest
      || ready.runner_image_digest != config.runner_image_digest
      || ready.runner_workload_identity != config.runner_workload_identity
      || ready.runner_client_cert_public_key_fingerprint != config.runner_client_spki_sha256
      || ready.credential_revision != config.credential_revision
      || ready.github_mcp_access_auth_mode != config.github_mcp_access_auth_mode
      || ready.github_mcp_access_token_revision != config.github_mcp_access_token_revision
      || authorized_peer.runner_identity.as_str() != config.runner_workload_identity
      || authorized_peer.client_spki_sha256 != config.runner_client_spki_sha256
    {
      return Err(ScheduledRunnerBrokerError::ReadyIdentityMismatch);
    }
    let attested = AttestedCapabilityProfile::parse_canonical_json(&ready.attested_profile_json)
      .map_err(|_| ScheduledRunnerBrokerError::ReadyIdentityMismatch)?;
    let observed_digest = format!(
      "{:x}",
      Sha256::digest(ready.attested_profile_json.as_bytes())
    );
    if observed_digest != ready.attested_profile_digest
      || attested.gateway_image_digest != config.gateway_image_digest
      || attested.runner_image_digest != config.runner_image_digest
      || attested.runner_workload_identity != config.runner_workload_identity
      || attested.runner_client_cert_public_key_fingerprint != config.runner_client_spki_sha256
      || attested.credential_revision != config.credential_revision
      || attested.github_mcp_access_auth_mode != config.github_mcp_access_auth_mode
      || attested.github_mcp_access_token_revision != config.github_mcp_access_token_revision
    {
      return Err(ScheduledRunnerBrokerError::ReadyIdentityMismatch);
    }
    let evidence = SignedRunnerEvidence::parse_canonical_json(&ready.signed_evidence_json)
      .map_err(|_| ScheduledRunnerBrokerError::ReadyIdentityMismatch)?;
    if evidence.key_id != config.executor_evidence_key_id {
      return Err(ScheduledRunnerBrokerError::ReadyIdentityMismatch);
    }
    let claims = verify_runner_evidence(&evidence, &config.executor_evidence_public_key, now)
      .map_err(|_| ScheduledRunnerBrokerError::ReadyIdentityMismatch)?;
    if claims.kind != RunnerEvidenceKind::Ready
      || claims.session_nonce != expected_session_nonce
      || claims.challenge != expected_challenge
      || claims.sequence != frame.sequence
      || claims.expires_at_unix_millis != ready.ready_until_unix_millis
      || claims.deployment_epoch != config.deployment_epoch
      || claims.deployment_profile_digest != config.profile_digest
      || claims.observed_profile_digest != ready.attested_profile_digest
      || claims.signer_identity != config.executor_evidence_signer_identity
      || claims.executor_identity != config.executor_identity
      || claims.key_revision != config.executor_evidence_key_revision
      || claims.credential_revision != config.credential_revision
      || claims.payload_digest != ready_evidence_payload_digest(ready)
    {
      return Err(ScheduledRunnerBrokerError::ReadyIdentityMismatch);
    }
    Ok(())
  }

  fn register(
    &self,
    session: &Arc<RegisteredRunnerSession>,
  ) -> Result<(), ScheduledRunnerBrokerError> {
    let mut current = self.inner.current.lock().expect("runner session registry");
    if current
      .as_ref()
      .is_some_and(|registered| registered.is_connected())
    {
      return Err(ScheduledRunnerBrokerError::DuplicateSession);
    }
    *current = Some(Arc::clone(session));
    Ok(())
  }

  fn unregister(&self, session: &Arc<RegisteredRunnerSession>) {
    session.connected.store(false, Ordering::Release);
    session.release_slot();
    let mut current = self.inner.current.lock().expect("runner session registry");
    if current
      .as_ref()
      .is_some_and(|registered| Arc::ptr_eq(registered, session))
    {
      *current = None;
    }
  }

  fn session(&self) -> Option<Arc<RegisteredRunnerSession>> {
    self
      .inner
      .current
      .lock()
      .expect("runner session registry")
      .as_ref()
      .filter(|session| session.is_connected())
      .cloned()
  }

  fn state_admission(
    &self,
    reserve_slot: bool,
  ) -> Result<(ScheduledExecutorAdmission, Arc<RegisteredRunnerSession>), ScheduledRunnerBrokerError>
  {
    let now_millis = unix_millis()?;
    let now_seconds =
      i64::try_from(now_millis / 1_000).map_err(|_| ScheduledRunnerBrokerError::SessionExpired)?;
    let session = self
      .session()
      .ok_or(ScheduledRunnerBrokerError::SessionUnavailable)?;
    let ready_deadline_seconds = i64::try_from(session.ready.ready_until_unix_millis / 1_000)
      .map_err(|_| ScheduledRunnerBrokerError::SessionExpired)?;
    let ttl_seconds = i64::try_from(self.inner.config.admission_ttl.as_secs().max(1))
      .map_err(|_| ScheduledRunnerBrokerError::SessionExpired)?;
    let operation_deadline = now_seconds
      .checked_add(ttl_seconds)
      .ok_or(ScheduledRunnerBrokerError::SessionExpired)?
      .min(
        self
          .inner
          .config
          .signed_not_after_unix_seconds
          .saturating_sub(1),
      )
      .min(ready_deadline_seconds.saturating_sub(1));
    if operation_deadline <= now_seconds || !session.slot_available(now_millis) {
      return Err(ScheduledRunnerBrokerError::SessionUnavailable);
    }
    if reserve_slot {
      let ttl_millis = u64::try_from(self.inner.config.admission_ttl.as_millis())
        .map_err(|_| ScheduledRunnerBrokerError::SessionExpired)?;
      let expires_at = now_millis
        .checked_add(ttl_millis)
        .ok_or(ScheduledRunnerBrokerError::SessionExpired)?
        .min(session.ready.ready_until_unix_millis)
        .min(
          u64::try_from(self.inner.config.signed_not_after_unix_seconds)
            .unwrap_or(0)
            .saturating_mul(1_000),
        );
      session.reserve(now_millis, expires_at)?;
    }
    Ok((
      ScheduledExecutorAdmission {
        schema_version: self.inner.config.schema_version,
        deployment_epoch: i64::try_from(self.inner.config.deployment_epoch)
          .map_err(|_| ScheduledRunnerBrokerError::InvalidConfiguration)?,
        attestation_id: self.inner.config.attestation_id.clone(),
        profile_digest: self.inner.config.profile_digest.clone(),
        signed_not_after: self.inner.config.signed_not_after_unix_seconds,
        operation_deadline,
      },
      session,
    ))
  }
}

struct ExpectedRunnerEvidence<'a> {
  kind: RunnerEvidenceKind,
  sequence: u64,
  observed_profile_digest: &'a str,
  payload_digest: &'a str,
}

fn validate_executor_evidence(
  config: &ScheduledRunnerBrokerConfig,
  ready_frame: &RemoteFrame,
  expected: ExpectedRunnerEvidence<'_>,
  encoded: &str,
  now: u64,
) -> Result<(), ScheduledRunnerBrokerError> {
  let RemoteMessage::Ready(ready) = &ready_frame.message else {
    return Err(ScheduledRunnerBrokerError::ProtocolRejected);
  };
  let evidence = SignedRunnerEvidence::parse_canonical_json(encoded)
    .map_err(|_| ScheduledRunnerBrokerError::ProtocolRejected)?;
  if evidence.key_id != config.executor_evidence_key_id {
    return Err(ScheduledRunnerBrokerError::ProtocolRejected);
  }
  let claims = verify_runner_evidence(&evidence, &config.executor_evidence_public_key, now)
    .map_err(|_| ScheduledRunnerBrokerError::ProtocolRejected)?;
  if claims.kind != expected.kind
    || claims.session_nonce != ready_frame.session_nonce
    || claims.challenge != ready.challenge
    || claims.sequence != expected.sequence
    || claims.deployment_epoch != config.deployment_epoch
    || claims.deployment_profile_digest != config.profile_digest
    || claims.observed_profile_digest != expected.observed_profile_digest
    || claims.signer_identity != config.executor_evidence_signer_identity
    || claims.key_revision != config.executor_evidence_key_revision
    || claims.executor_identity != config.executor_identity
    || claims.credential_revision != config.credential_revision
    || claims.payload_digest != expected.payload_digest
  {
    return Err(ScheduledRunnerBrokerError::ProtocolRejected);
  }
  Ok(())
}

fn accept_authenticated_prepared(
  session: &mut RemoteSessionState,
  config: &ScheduledRunnerBrokerConfig,
  ready: &RemoteFrame,
  frame: &RemoteFrame,
  now: u64,
) -> Result<(), ScheduledRunnerBrokerError> {
  let RemoteMessage::Prepared(prepared) = &frame.message else {
    return Err(ScheduledRunnerBrokerError::ProtocolRejected);
  };
  if prepared.github_mcp_access_auth_mode != config.github_mcp_access_auth_mode
    || prepared.github_mcp_access_token_revision != config.github_mcp_access_token_revision
  {
    return Err(ScheduledRunnerBrokerError::ProtocolRejected);
  }
  let attested = AttestedCapabilityProfile::parse_canonical_json(&prepared.attested_profile_json)
    .map_err(|_| ScheduledRunnerBrokerError::ProtocolRejected)?;
  if attested.github_mcp_access_auth_mode != config.github_mcp_access_auth_mode
    || attested.github_mcp_access_token_revision != config.github_mcp_access_token_revision
  {
    return Err(ScheduledRunnerBrokerError::ProtocolRejected);
  }
  let payload_digest = prepared_evidence_payload_digest(prepared);
  validate_executor_evidence(
    config,
    ready,
    ExpectedRunnerEvidence {
      kind: RunnerEvidenceKind::Prepared,
      sequence: frame.sequence,
      observed_profile_digest: &prepared.attested_profile_digest,
      payload_digest: &payload_digest,
    },
    &prepared.signed_evidence_json,
    now,
  )?;
  session
    .accept(RemoteSessionRole::Runner, frame.clone(), now)
    .map_err(|_| ScheduledRunnerBrokerError::ProtocolRejected)?;
  Ok(())
}

fn accept_authenticated_result(
  session: &mut RemoteSessionState,
  config: &ScheduledRunnerBrokerConfig,
  ready: &ReadyFrame,
  executor_observed_profile_digest: &str,
  frame: &RemoteFrame,
  now: u64,
) -> Result<(), ScheduledRunnerBrokerError> {
  let RemoteMessage::Result(result) = &frame.message else {
    return Err(ScheduledRunnerBrokerError::ProtocolRejected);
  };
  let payload_digest = result_evidence_payload_digest(result);
  validate_executor_evidence(
    config,
    &RemoteFrame {
      version: REMOTE_PROTOCOL_VERSION,
      session_nonce: frame.session_nonce.clone(),
      sequence: 1,
      message: RemoteMessage::Ready(ready.clone()),
    },
    ExpectedRunnerEvidence {
      kind: RunnerEvidenceKind::Result,
      sequence: frame.sequence,
      observed_profile_digest: executor_observed_profile_digest,
      payload_digest: &payload_digest,
    },
    &result.signed_evidence_json,
    now,
  )?;
  session
    .accept(RemoteSessionRole::Runner, frame.clone(), now)
    .map_err(|_| ScheduledRunnerBrokerError::ProtocolRejected)?;
  Ok(())
}

struct SessionRegistration {
  broker: ScheduledRunnerBroker,
  session: Arc<RegisteredRunnerSession>,
  _permit: tokio::sync::OwnedSemaphorePermit,
}

impl Drop for SessionRegistration {
  fn drop(&mut self) {
    self.broker.unregister(&self.session);
  }
}

#[derive(Debug, Clone)]
struct ProtocolAdmission {
  nonce: String,
  expires_at_unix_millis: u64,
}

struct RegisteredRunnerSession {
  session_nonce: String,
  ready_frame: RemoteFrame,
  ready: ReadyFrame,
  commands: mpsc::Sender<BrokerCommand>,
  evidence_config: ScheduledRunnerBrokerConfig,
  connected: AtomicBool,
  slot: Mutex<Option<ProtocolAdmission>>,
}

impl RegisteredRunnerSession {
  fn is_connected(&self) -> bool {
    self.connected.load(Ordering::Acquire)
  }

  fn slot_available(&self, now: u64) -> bool {
    let mut slot = self.slot.lock().expect("runner execution slot");
    if slot
      .as_ref()
      .is_some_and(|reservation| reservation.expires_at_unix_millis <= now)
    {
      *slot = None;
    }
    slot.is_none()
  }

  fn reserve(&self, now: u64, expires_at: u64) -> Result<(), ScheduledRunnerBrokerError> {
    if !self.is_connected() || expires_at <= now {
      return Err(ScheduledRunnerBrokerError::SessionUnavailable);
    }
    let mut slot = self.slot.lock().expect("runner execution slot");
    if slot
      .as_ref()
      .is_some_and(|reservation| reservation.expires_at_unix_millis > now)
    {
      return Err(ScheduledRunnerBrokerError::SessionBusy);
    }
    *slot = Some(ProtocolAdmission {
      nonce: random_sha256()?,
      expires_at_unix_millis: expires_at,
    });
    Ok(())
  }

  fn reservation(&self, now: u64) -> Result<ProtocolAdmission, ScheduledRunnerBrokerError> {
    let mut slot = self.slot.lock().expect("runner execution slot");
    let Some(reservation) = slot.as_ref() else {
      return Err(ScheduledRunnerBrokerError::SessionUnavailable);
    };
    if reservation.expires_at_unix_millis <= now || !self.is_connected() {
      *slot = None;
      return Err(ScheduledRunnerBrokerError::SessionExpired);
    }
    Ok(reservation.clone())
  }

  fn release_slot(&self) {
    *self.slot.lock().expect("runner execution slot") = None;
  }

  async fn prepare(
    &self,
    input: &PrepareInput,
    isolation_permit_envelope_json: String,
  ) -> Result<VerifiedPrepared, ScheduledRunnerBrokerError> {
    let reservation = self.reservation(unix_millis()?)?;
    let binding = remote_binding(input, &self.ready)?;
    let task_json = remote_task_json(input, &binding)?;
    let admission = RemoteFrame {
      version: REMOTE_PROTOCOL_VERSION,
      session_nonce: self.session_nonce.clone(),
      sequence: 1,
      message: RemoteMessage::Admission(AdmissionFrame {
        challenge: self.ready.challenge.clone(),
        admission_nonce: reservation.nonce,
        expires_at_unix_millis: reservation.expires_at_unix_millis,
        deployment_epoch: self.ready.deployment_epoch,
        profile_digest: self.ready.profile_digest.clone(),
      }),
    };
    let prepare = RemoteFrame {
      version: REMOTE_PROTOCOL_VERSION,
      session_nonce: self.session_nonce.clone(),
      sequence: 2,
      message: RemoteMessage::Prepare(PrepareFrame {
        binding,
        isolation_permit_envelope_json,
        task_json,
        definition_json: input.definition_json.clone(),
        capability_json: input.capability_json.clone(),
        targets_json: input.targets_json.clone(),
      }),
    };
    let (response, receiver) = oneshot::channel();
    self
      .commands
      .send(BrokerCommand::Prepare {
        authority: input.authority.clone(),
        admission: Box::new(admission),
        prepare: Box::new(prepare),
        cancellation: Arc::clone(&input.cancellation),
        response,
      })
      .await
      .map_err(|_| ScheduledRunnerBrokerError::SessionUnavailable)?;
    receiver
      .await
      .map_err(|_| ScheduledRunnerBrokerError::SessionUnavailable)?
  }

  async fn start(
    &self,
    binding: RunBinding,
    preparation_nonce: String,
    executor_observed_profile_digest: String,
    cancellation: Arc<AtomicBool>,
  ) -> Result<RemoteExecutionTerminal, ScheduledRunnerBrokerError> {
    if !self.is_connected() {
      return Ok(RemoteExecutionTerminal::FailedBeforeStart);
    }
    let (response, receiver) = oneshot::channel();
    self
      .commands
      .send(BrokerCommand::Start {
        frame: Box::new(RemoteFrame {
          version: REMOTE_PROTOCOL_VERSION,
          session_nonce: self.session_nonce.clone(),
          sequence: 3,
          message: RemoteMessage::Start(StartFrame {
            binding,
            preparation_nonce,
          }),
        }),
        executor_observed_profile_digest,
        cancellation,
        response,
      })
      .await
      .map_err(|_| ScheduledRunnerBrokerError::SessionUnavailable)?;
    receiver
      .await
      .map_err(|_| ScheduledRunnerBrokerError::SessionUnavailable)?
  }
}

enum BrokerCommand {
  Prepare {
    authority: ScheduledPrepareAuthority,
    admission: Box<RemoteFrame>,
    prepare: Box<RemoteFrame>,
    cancellation: Arc<AtomicBool>,
    response: oneshot::Sender<Result<VerifiedPrepared, ScheduledRunnerBrokerError>>,
  },
  Start {
    frame: Box<RemoteFrame>,
    executor_observed_profile_digest: String,
    cancellation: Arc<AtomicBool>,
    response: oneshot::Sender<Result<RemoteExecutionTerminal, ScheduledRunnerBrokerError>>,
  },
}

async fn run_registered_connection(
  mut connection: ScheduledRunnerServerConnection,
  session: Arc<RegisteredRunnerSession>,
  mut commands: mpsc::Receiver<BrokerCommand>,
) -> Result<(), ScheduledRunnerBrokerError> {
  let mut state = None;
  loop {
    tokio::select! {
      biased;
      command = commands.recv() => {
        let Some(command) = command else {
          return Ok(());
        };
        match command {
          BrokerCommand::Prepare {
            authority,
            admission,
            prepare,
            cancellation,
            response,
          } => {
            let result = drive_prepare(
              &mut connection,
              &session.ready_frame,
              authority,
              *admission,
              *prepare,
              cancellation,
              &mut state,
              &session.evidence_config,
            ).await;
            let failed = result.is_err();
            let _ = response.send(result);
            if failed {
              return Err(ScheduledRunnerBrokerError::RunnerRejected);
            }
          }
          BrokerCommand::Start { frame, executor_observed_profile_digest, cancellation, response } => {
            let result = drive_start(&mut connection, *frame, cancellation, &mut state, &session.evidence_config, &session.ready, &executor_observed_profile_digest).await;
            let failed = result.is_err();
            let _ = response.send(result);
            return if failed {
              Err(ScheduledRunnerBrokerError::Transport)
            } else {
              Ok(())
            };
          }
        }
      }
      incoming = connection.framed.read_frame(unix_millis()?) => {
        let frame = incoming.map_err(|_| ScheduledRunnerBrokerError::Transport)?;
        let Some(frame) = frame else {
          return Ok(());
        };
        let Some(session_state) = state.as_mut() else {
          return Err(ScheduledRunnerBrokerError::ProtocolRejected);
        };
        session_state
          .accept(RemoteSessionRole::Runner, frame, unix_millis()?)
          .map_err(|_| ScheduledRunnerBrokerError::ProtocolRejected)?;
        if session_state.terminal_disposition().is_some() {
          return Ok(());
        }
      }
    }
  }
}

#[allow(
  clippy::too_many_arguments,
  reason = "the driver receives the complete one-shot PREPARE protocol authority"
)]
async fn drive_prepare(
  connection: &mut ScheduledRunnerServerConnection,
  ready: &RemoteFrame,
  authority: ScheduledPrepareAuthority,
  admission: RemoteFrame,
  prepare: RemoteFrame,
  cancellation: Arc<AtomicBool>,
  state: &mut Option<RemoteSessionState>,
  evidence_config: &ScheduledRunnerBrokerConfig,
) -> Result<VerifiedPrepared, ScheduledRunnerBrokerError> {
  if state.is_some() {
    return Err(ScheduledRunnerBrokerError::SessionBusy);
  }
  let mut session = RemoteSessionState::new(ready.session_nonce.clone(), authority.clone())
    .map_err(|_| ScheduledRunnerBrokerError::ProtocolRejected)?;
  session
    .accept(RemoteSessionRole::Runner, ready.clone(), unix_millis()?)
    .map_err(|_| ScheduledRunnerBrokerError::ProtocolRejected)?;
  session
    .accept(
      RemoteSessionRole::Gateway,
      admission.clone(),
      unix_millis()?,
    )
    .map_err(|_| ScheduledRunnerBrokerError::ProtocolRejected)?;
  connection
    .framed
    .write_frame(&admission)
    .await
    .map_err(|_| ScheduledRunnerBrokerError::Transport)?;
  session
    .accept(RemoteSessionRole::Gateway, prepare.clone(), unix_millis()?)
    .map_err(|_| ScheduledRunnerBrokerError::ProtocolRejected)?;
  connection
    .framed
    .write_frame(&prepare)
    .await
    .map_err(|_| ScheduledRunnerBrokerError::Transport)?;
  let binding = match &prepare.message {
    RemoteMessage::Prepare(prepare) => prepare.binding.clone(),
    _ => return Err(ScheduledRunnerBrokerError::ProtocolRejected),
  };
  loop {
    if cancellation.load(Ordering::Acquire) {
      let cancel = RemoteFrame {
        version: REMOTE_PROTOCOL_VERSION,
        session_nonce: ready.session_nonce.clone(),
        sequence: 3,
        message: RemoteMessage::Cancel(CancelFrame {
          binding,
          reason: "gateway_preflight_cancelled".to_owned(),
        }),
      };
      session
        .accept(RemoteSessionRole::Gateway, cancel.clone(), unix_millis()?)
        .map_err(|_| ScheduledRunnerBrokerError::ProtocolRejected)?;
      let _ = connection.framed.write_frame(&cancel).await;
      return Err(ScheduledRunnerBrokerError::SessionUnavailable);
    }
    let frame = connection
      .framed
      .read_frame(unix_millis()?)
      .await
      .map_err(|_| ScheduledRunnerBrokerError::Transport)?
      .ok_or(ScheduledRunnerBrokerError::ConnectionClosed)?;
    match &frame.message {
      RemoteMessage::Prepared(_) => {
        accept_authenticated_prepared(
          &mut session,
          evidence_config,
          ready,
          &frame,
          unix_millis()?,
        )?;
      }
      RemoteMessage::Heartbeat(heartbeat) if heartbeat.phase == RemoteHeartbeatPhase::Preparing => {
      }
      RemoteMessage::Error(ErrorFrame { .. }) => {
        return Err(ScheduledRunnerBrokerError::RunnerRejected);
      }
      _ => return Err(ScheduledRunnerBrokerError::ProtocolRejected),
    }
    if !matches!(frame.message, RemoteMessage::Prepared(_)) {
      session
        .accept(RemoteSessionRole::Runner, frame.clone(), unix_millis()?)
        .map_err(|_| ScheduledRunnerBrokerError::ProtocolRejected)?;
    }
    match frame.message {
      RemoteMessage::Prepared(mut prepared) => {
        let executor_observed_profile_digest = prepared.attested_profile_digest.clone();
        let RemoteMessage::Ready(ready_identity) = &ready.message else {
          return Err(ScheduledRunnerBrokerError::ProtocolRejected);
        };
        let recovery = authority
          .remote_recovery_attestation_json(
            &prepared.attested_profile_json,
            &ready_identity.profile_digest,
            ready_identity.deployment_epoch,
          )
          .map_err(|_| ScheduledRunnerBrokerError::RunnerRejected)?;
        prepared.attested_profile_digest = format!("{:x}", Sha256::digest(recovery.as_bytes()));
        prepared.attested_profile_json = recovery;
        *state = Some(session);
        return Ok(VerifiedPrepared {
          frame: prepared,
          executor_observed_profile_digest,
        });
      }
      RemoteMessage::Heartbeat(heartbeat) if heartbeat.phase == RemoteHeartbeatPhase::Preparing => {
      }
      RemoteMessage::Error(ErrorFrame { .. }) => {
        return Err(ScheduledRunnerBrokerError::RunnerRejected);
      }
      _ => return Err(ScheduledRunnerBrokerError::ProtocolRejected),
    }
  }
}

async fn drive_start(
  connection: &mut ScheduledRunnerServerConnection,
  frame: RemoteFrame,
  cancellation: Arc<AtomicBool>,
  state: &mut Option<RemoteSessionState>,
  evidence_config: &ScheduledRunnerBrokerConfig,
  ready: &ReadyFrame,
  executor_observed_profile_digest: &str,
) -> Result<RemoteExecutionTerminal, ScheduledRunnerBrokerError> {
  let session = state
    .as_mut()
    .ok_or(ScheduledRunnerBrokerError::SessionUnavailable)?;
  let binding = match &frame.message {
    RemoteMessage::Start(start) => start.binding.clone(),
    _ => return Err(ScheduledRunnerBrokerError::ProtocolRejected),
  };
  session
    .accept(RemoteSessionRole::Gateway, frame.clone(), unix_millis()?)
    .map_err(|_| ScheduledRunnerBrokerError::ProtocolRejected)?;
  connection
    .framed
    .write_frame(&frame)
    .await
    .map_err(|_| ScheduledRunnerBrokerError::Transport)?;
  loop {
    tokio::select! {
      biased;
      () = tokio::time::sleep(CANCELLATION_POLL_INTERVAL), if cancellation.load(Ordering::Acquire) => {
        let cancel = RemoteFrame {
          version: REMOTE_PROTOCOL_VERSION,
          session_nonce: frame.session_nonce.clone(),
          sequence: 4,
          message: RemoteMessage::Cancel(CancelFrame {
            binding,
            reason: "gateway_execution_cancelled".to_owned(),
          }),
        };
        session
          .accept(RemoteSessionRole::Gateway, cancel.clone(), unix_millis()?)
          .map_err(|_| ScheduledRunnerBrokerError::ProtocolRejected)?;
        let _ = connection.framed.write_frame(&cancel).await;
        return Ok(RemoteExecutionTerminal::OutcomeUnknown);
      }
      incoming = connection.framed.read_frame(unix_millis()?) => {
        let Ok(Some(frame)) = incoming else {
          return Ok(disconnect_terminal(session.disconnect()));
        };
        if matches!(frame.message, RemoteMessage::Result(_)) {
          accept_authenticated_result(
            session,
            evidence_config,
            ready,
            executor_observed_profile_digest,
            &frame,
            unix_millis()?,
          )?;
        } else {
          session
            .accept(RemoteSessionRole::Runner, frame.clone(), unix_millis()?)
            .map_err(|_| ScheduledRunnerBrokerError::ProtocolRejected)?;
        }
        match frame.message {
          RemoteMessage::Result(result) => return Ok(RemoteExecutionTerminal::Result(result)),
          RemoteMessage::Heartbeat(heartbeat)
            if heartbeat.phase == RemoteHeartbeatPhase::Started => {}
          RemoteMessage::Error(ErrorFrame { .. }) => {
            return Ok(RemoteExecutionTerminal::OutcomeUnknown);
          }
          _ => return Err(ScheduledRunnerBrokerError::ProtocolRejected),
        }
      }
    }
  }
}

fn disconnect_terminal(outcome: RemoteDisconnectOutcome) -> RemoteExecutionTerminal {
  match outcome {
    RemoteDisconnectOutcome::PreflightNoExecution => RemoteExecutionTerminal::FailedBeforeStart,
    RemoteDisconnectOutcome::OutcomeUnknown => RemoteExecutionTerminal::OutcomeUnknown,
    RemoteDisconnectOutcome::AlreadyConclusive(disposition) => match disposition {
      RemoteTerminalDisposition::FailedBeforeStart => RemoteExecutionTerminal::FailedBeforeStart,
      RemoteTerminalDisposition::Completed | RemoteTerminalDisposition::OutcomeUnknown => {
        RemoteExecutionTerminal::OutcomeUnknown
      }
    },
  }
}

#[allow(
  clippy::large_enum_variant,
  reason = "one terminal result is consumed immediately"
)]
enum RemoteExecutionTerminal {
  Result(ResultFrame),
  FailedBeforeStart,
  OutcomeUnknown,
}

pub struct RemoteScheduledExecutionBackend {
  broker: ScheduledRunnerBroker,
  runtime: Handle,
  permit_issuer: Arc<dyn RemoteIsolationPermitIssuer>,
}

#[async_trait]
pub trait RemoteIsolationPermitIssuer: Send + Sync {
  async fn issue(
    &self,
    input: &PrepareInput,
    session_nonce: &str,
  ) -> Result<String, PrepareFailure>;
}

impl RemoteScheduledExecutionBackend {
  #[must_use]
  pub fn new(
    broker: ScheduledRunnerBroker,
    runtime: Handle,
    permit_issuer: Arc<dyn RemoteIsolationPermitIssuer>,
  ) -> Self {
    Self {
      broker,
      runtime,
      permit_issuer,
    }
  }
}

struct RemoteAuthorization {
  session: Arc<RegisteredRunnerSession>,
  prepared: VerifiedPrepared,
}

struct VerifiedPrepared {
  frame: PreparedFrame,
  executor_observed_profile_digest: String,
}

#[async_trait]
impl ScheduledExecutionBackend for RemoteScheduledExecutionBackend {
  fn is_configured(&self) -> bool {
    true
  }

  fn readiness(&self) -> ExecutorReadiness {
    self
      .broker
      .session()
      .map_or(ExecutorReadiness::Unavailable, |session| {
        if session.slot_available(unix_millis().unwrap_or(u64::MAX)) {
          ExecutorReadiness::Ready
        } else {
          ExecutorReadiness::Unavailable
        }
      })
  }

  async fn refresh_materialization_admission(&self) -> RefreshedExecutorAdmission {
    self
      .broker
      .state_admission(false)
      .map_or(RefreshedExecutorAdmission::Unavailable, |(admission, _)| {
        RefreshedExecutorAdmission::Authority(admission)
      })
  }

  async fn refresh_admission(&self) -> RefreshedExecutorAdmission {
    self
      .broker
      .state_admission(true)
      .map_or(RefreshedExecutorAdmission::Unavailable, |(admission, _)| {
        RefreshedExecutorAdmission::Authority(admission)
      })
  }

  async fn authorize(&self, input: &PrepareInput) -> Result<BackendAuthorization, PrepareFailure> {
    let session = self
      .broker
      .session()
      .ok_or_else(|| PrepareFailure::fatal("scheduled_remote_session_unavailable"))?;
    let isolation_permit_envelope_json = self
      .permit_issuer
      .issue(input, &session.session_nonce)
      .await?;
    let prepared = session
      .prepare(input, isolation_permit_envelope_json)
      .await
      .map_err(remote_prepare_failure)?;
    Ok(BackendAuthorization::new(RemoteAuthorization {
      session,
      prepared,
    }))
  }

  fn prepare(
    &self,
    input: PrepareInput,
    authorization: BackendAuthorization,
  ) -> Result<BackendPrepared, PrepareFailure> {
    let RemoteAuthorization { session, prepared } = authorization.downcast()?;
    let prepared_frame = prepared.frame;
    Ok(BackendPrepared::new_remote(
      input.authority,
      prepared_frame.attested_profile_json,
      prepared_frame.attested_profile_digest,
      session.ready.profile_digest.clone(),
      session.ready.deployment_epoch,
      Box::new(RemotePreparedExecution {
        runtime: self.runtime.clone(),
        session,
        binding: prepared_frame.binding,
        preparation_nonce: prepared_frame.preparation_nonce,
        executor_observed_profile_digest: prepared.executor_observed_profile_digest,
      }),
    ))
  }
}

struct RemotePreparedExecution {
  runtime: Handle,
  session: Arc<RegisteredRunnerSession>,
  binding: RunBinding,
  preparation_nonce: String,
  executor_observed_profile_digest: String,
}

impl PreparedExecution for RemotePreparedExecution {
  fn execute(self: Box<Self>, cancellation: Arc<AtomicBool>) -> ExecutionResult {
    let this = *self;
    let result = if this.session.is_connected() {
      this.runtime.block_on(this.session.start(
        this.binding,
        this.preparation_nonce,
        this.executor_observed_profile_digest,
        cancellation,
      ))
    } else {
      Ok(RemoteExecutionTerminal::FailedBeforeStart)
    };
    this.session.release_slot();
    match result {
      Ok(RemoteExecutionTerminal::Result(result)) => remote_execution_result(result),
      Ok(RemoteExecutionTerminal::FailedBeforeStart) => ExecutionResult::Interrupted {
        transport_converged: true,
      },
      Ok(RemoteExecutionTerminal::OutcomeUnknown) | Err(_) => ExecutionResult::TransportLost {
        message: "scheduled remote runner outcome is unknown".to_owned(),
      },
    }
  }
}

fn remote_binding(
  input: &PrepareInput,
  ready: &ReadyFrame,
) -> Result<RunBinding, ScheduledRunnerBrokerError> {
  Ok(RunBinding {
    run_id: input.binding.run_id().to_owned(),
    job_id: input.binding.job_id().to_owned(),
    attempt: u32::try_from(input.binding.attempt())
      .map_err(|_| ScheduledRunnerBrokerError::ProtocolRejected)?,
    fence_token: u64::try_from(input.binding.fence())
      .map_err(|_| ScheduledRunnerBrokerError::ProtocolRejected)?,
    authority_digest: input.authority.digest().to_owned(),
    profile_digest: ready.profile_digest.clone(),
    deployment_epoch: ready.deployment_epoch,
    credential_revision: ready.credential_revision.clone(),
  })
}

fn remote_task_json(
  input: &PrepareInput,
  binding: &RunBinding,
) -> Result<String, ScheduledRunnerBrokerError> {
  let InvocationSource::ScheduledRun {
    job_id,
    run_id,
    scheduled_for,
  } = &input.task.source
  else {
    return Err(ScheduledRunnerBrokerError::ProtocolRejected);
  };
  if job_id != &binding.job_id
    || run_id != &binding.run_id
    || !matches!(input.task.session, SessionMode::Fresh)
    || input.task.channel.is_some()
    || input.task.feedback_target.is_some()
    || !matches!(input.task.tool_policy, ToolPolicy::None)
    || !matches!(
      input.task.principal.as_ref(),
      InvocationPrincipalRef::Service {
        service: "codeoff-scheduler"
      }
    )
  {
    return Err(ScheduledRunnerBrokerError::ProtocolRejected);
  }
  let previous_success = input.task.previous_success.as_ref().map(|context| {
    serde_json::json!({
      "content": context.content,
      "was_truncated": context.was_truncated,
    })
  });
  Ok(
    serde_json::json!({
      "instruction": input.task.instruction,
      "previous_success": previous_success,
      "scheduled_for": scheduled_for,
      "schema_version": 1,
      "task_id": input.task.task_id,
    })
    .to_string(),
  )
}

fn remote_execution_result(result: ResultFrame) -> ExecutionResult {
  match result.kind {
    RemoteResultKind::Completed => {
      let value: Result<Value, _> = serde_json::from_str(&result.result_json);
      let Some(object) = value.ok().and_then(|value| value.as_object().cloned()) else {
        return invalid_remote_result();
      };
      if object.get("schema_version").and_then(Value::as_u64) != Some(1) {
        return invalid_remote_result();
      }
      if object.len() == 2
        && let Some(summary) = object.get("summary").and_then(Value::as_str)
      {
        return ExecutionResult::Completed {
          summary: summary.to_owned(),
        };
      }
      if object.len() == 3
        && let (Some(kind), Some(message)) = (
          object.get("failure_kind").and_then(Value::as_str),
          object.get("message").and_then(Value::as_str),
        )
      {
        return ExecutionResult::Failed {
          kind: kind.to_owned(),
          message: message.to_owned(),
        };
      }
      invalid_remote_result()
    }
    RemoteResultKind::FailedBeforeStart => ExecutionResult::Interrupted {
      transport_converged: true,
    },
    RemoteResultKind::OutcomeUnknown => ExecutionResult::TransportLost {
      message: "scheduled remote runner reported outcome unknown".to_owned(),
    },
  }
}

fn invalid_remote_result() -> ExecutionResult {
  ExecutionResult::Failed {
    kind: "remote_result_invalid".to_owned(),
    message: "scheduled remote result did not match schema".to_owned(),
  }
}

fn remote_prepare_failure(error: ScheduledRunnerBrokerError) -> PrepareFailure {
  let message = match error {
    ScheduledRunnerBrokerError::SessionUnavailable
    | ScheduledRunnerBrokerError::SessionExpired
    | ScheduledRunnerBrokerError::ConnectionClosed
    | ScheduledRunnerBrokerError::Transport => "scheduled_remote_preflight_unavailable",
    ScheduledRunnerBrokerError::RunnerRejected => "scheduled_remote_preflight_rejected",
    _ => "scheduled_remote_protocol_rejected",
  };
  PrepareFailure::fatal(message)
}

fn random_sha256() -> Result<String, ScheduledRunnerBrokerError> {
  let provider = CryptoProvider::get_default()
    .cloned()
    .unwrap_or_else(|| Arc::new(rustls::crypto::ring::default_provider()));
  let mut random = [0_u8; 32];
  provider
    .secure_random
    .fill(&mut random)
    .map_err(|_| ScheduledRunnerBrokerError::RandomnessUnavailable)?;
  Ok(format!("{:x}", Sha256::digest(random)))
}

fn unix_millis() -> Result<u64, ScheduledRunnerBrokerError> {
  SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .map_err(|_| ScheduledRunnerBrokerError::SessionExpired)
    .and_then(|duration| {
      u64::try_from(duration.as_millis()).map_err(|_| ScheduledRunnerBrokerError::SessionExpired)
    })
}

fn is_lowercase_sha256(value: &str) -> bool {
  value.len() == 64
    && value
      .bytes()
      .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_oci_digest(value: &str) -> bool {
  value
    .strip_prefix("sha256:")
    .is_some_and(is_lowercase_sha256)
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::scheduled_runner_evidence::{
    RunnerEvidenceClaims, RunnerEvidenceKind, SignedRunnerEvidence, sign_runner_evidence,
  };
  use ring::rand::SystemRandom;
  use ring::signature::{Ed25519KeyPair, KeyPair};
  use std::fs;
  use std::os::unix::fs::PermissionsExt;
  use std::os::unix::process::CommandExt;
  use std::path::PathBuf;
  use std::process::{Command, Stdio};
  use std::sync::OnceLock;

  use crate::scheduled_remote_protocol::ReadinessRequestFrame;
  use crate::scheduled_runner_control::{
    ScheduledRunnerControlConfig, ScheduledRunnerControlConnection, relay_runner_frames,
  };
  use crate::scheduled_runner_evidence::RunnerEvidenceSigner;
  use crate::scheduled_runner_executor::{
    ProtectedScheduledExecutorListener, ScheduledRunnerExecutorConfig,
  };
  use crate::scheduled_runner_tls::integration_tests::CertificateFixture;
  use crate::scheduled_runner_tls::{
    ScheduledRunnerIoPolicy, ScheduledRunnerTlsClient, ScheduledRunnerTlsPaths,
    ScheduledRunnerTlsServer, session_challenge, session_nonce,
  };
  use codeoff_agent_contract::{AgentTask, InvocationPrincipal};
  use codeoff_state::RunLeaseBinding;
  use nix::unistd::{Gid, Uid, chown, getegid, geteuid};
  use tokio::net::TcpListener;

  const PRODUCTION_RELAY_HELPER_ENV: &str = "CODEOFF_PRODUCTION_RELAY_HELPER";
  const PRODUCTION_RELAY_ADDRESS_ENV: &str = "CODEOFF_PRODUCTION_RELAY_ADDRESS";
  const PRODUCTION_RELAY_CA_ENV: &str = "CODEOFF_PRODUCTION_RELAY_CA";
  const PRODUCTION_RELAY_CERT_ENV: &str = "CODEOFF_PRODUCTION_RELAY_CERT";
  const PRODUCTION_RELAY_KEY_ENV: &str = "CODEOFF_PRODUCTION_RELAY_KEY";
  const PRODUCTION_RELAY_SOCKET_ENV: &str = "CODEOFF_PRODUCTION_RELAY_SOCKET";
  const PRODUCTION_RELAY_EVIDENCE_KEY_ENV: &str = "CODEOFF_PRODUCTION_RELAY_EVIDENCE_KEY";
  const TEST_SERVER_NAME: &str = "gateway.codeoff.test";
  const TEST_CONTROL_UID: u32 = 65_533;
  const TEST_CONTROL_GID: u32 = 65_533;

  fn evidence_keys() -> &'static (Vec<u8>, Vec<u8>) {
    static KEYS: OnceLock<(Vec<u8>, Vec<u8>)> = OnceLock::new();
    KEYS.get_or_init(|| {
      let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("key");
      let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("pair");
      (pkcs8.as_ref().to_vec(), pair.public_key().as_ref().to_vec())
    })
  }

  #[test]
  fn production_relay_subprocess_helper() {
    if std::env::var_os(PRODUCTION_RELAY_HELPER_ENV).is_none() {
      return;
    }
    let value = |name: &str| std::env::var(name).expect("production relay helper environment");
    let evidence_key = PathBuf::from(value(PRODUCTION_RELAY_EVIDENCE_KEY_ENV));
    assert!(
      RunnerEvidenceSigner::load(&evidence_key, "executor-key-1").is_err(),
      "non-root control must not read executor evidence key"
    );
    let address = value(PRODUCTION_RELAY_ADDRESS_ENV)
      .parse()
      .expect("gateway address");
    let paths = ScheduledRunnerTlsPaths {
      certificate_chain: value(PRODUCTION_RELAY_CERT_ENV).into(),
      private_key: value(PRODUCTION_RELAY_KEY_ENV).into(),
      trust_bundle: value(PRODUCTION_RELAY_CA_ENV).into(),
    };
    let runtime = tokio::runtime::Runtime::new().expect("relay runtime");
    runtime.block_on(async move {
      let timeout = Duration::from_secs(5);
      let policy = ScheduledRunnerIoPolicy {
        handshake_timeout: timeout,
        read_timeout: timeout,
        write_timeout: timeout,
      };
      let client = ScheduledRunnerTlsClient::load_for_owner(
        &paths,
        TEST_SERVER_NAME,
        policy,
        geteuid().as_raw(),
        getegid().as_raw(),
      )
      .expect("control TLS client");
      let mut remote = client.connect(address).await.expect("control TLS connect");
      let nonce = session_nonce(&remote.channel_binding);
      let challenge = session_challenge(&remote.channel_binding);
      let mut local = ScheduledRunnerControlConnection::connect(&ScheduledRunnerControlConfig {
        socket_path: value(PRODUCTION_RELAY_SOCKET_ENV).into(),
        executor_uid: 0,
        executor_gid: 0,
        connect_timeout: timeout,
        read_timeout: timeout,
        write_timeout: timeout,
      })
      .await
      .expect("control local connect")
      .framed;
      let ready_until_unix_millis = unix_millis().expect("time") + 4_000;
      local
        .write_frame(&RemoteFrame {
          version: REMOTE_PROTOCOL_VERSION,
          session_nonce: nonce.clone(),
          sequence: 1,
          message: RemoteMessage::ReadinessRequest(ReadinessRequestFrame {
            challenge: challenge.clone(),
            ready_until_unix_millis,
          }),
        })
        .await
        .expect("readiness request");
      let ready = local
        .read_frame(unix_millis().expect("time"))
        .await
        .expect("ready read")
        .expect("ready frame");
      remote
        .framed
        .write_frame(&ready)
        .await
        .expect("relay ready");
      relay_runner_frames(&mut remote.framed, &mut local, &nonce)
        .await
        .expect("production relay");
    });
  }

  struct TestPermitIssuer;

  #[async_trait]
  impl RemoteIsolationPermitIssuer for TestPermitIssuer {
    async fn issue(
      &self,
      _input: &PrepareInput,
      _session_nonce: &str,
    ) -> Result<String, PrepareFailure> {
      Ok(r#"{"schema_version":1}"#.to_owned())
    }
  }

  fn ready_frame(
    session_nonce: &str,
    challenge: &str,
    deployment_epoch: u64,
    workload_identity: &str,
    spki: &str,
  ) -> RemoteFrame {
    let config = config();
    let mut profile = AttestedCapabilityProfile {
      codex_version: "test-codex".to_owned(),
      app_server_schema_sha256: "1".repeat(64),
      codex_program_sha256: "2".repeat(64),
      github_mcp_version: "test-mcp".to_owned(),
      github_mcp_artifact_sha256: "3".repeat(64),
      github_mcp_endpoint_identity: "test-endpoint".to_owned(),
      github_mcp_access_auth_mode: "bearer-token-env-v1".to_owned(),
      github_mcp_access_token_revision: "mcp-channel-v1".to_owned(),
      github_mcp_health_checked_at_unix_seconds: 1,
      github_mcp_health_credential_revision: config.credential_revision.clone(),
      github_mcp_health_result_sha256: "8".repeat(64),
      github_mcp_health_tool: "get_me".to_owned(),
      github_tools: [
        "get_me",
        "issue_read",
        "list_issues",
        "search_issues",
        "search_orgs",
      ]
      .into_iter()
      .map(str::to_owned)
      .collect(),
      credential_reference: "test-credential".to_owned(),
      permission_policy_revision: "test-policy".to_owned(),
      config_revision: "test-config".to_owned(),
      config_sha256: "4".repeat(64),
      gateway_image_digest: config.gateway_image_digest.clone(),
      runner_image_digest: config.runner_image_digest.clone(),
      runner_workload_identity: workload_identity.to_owned(),
      runner_client_cert_public_key_fingerprint: spki.to_owned(),
      credential_revision: config.credential_revision.clone(),
      credential_isolation_revision: "test-isolation".to_owned(),
      credential_deny_policy_revision: "test-deny".to_owned(),
      negative_test_revision: "test-negative".to_owned(),
      output_schema_revision: "test-output".to_owned(),
      attested_at_unix_seconds: 1,
      profile_sha256: String::new(),
    };
    profile.profile_sha256 = profile.computed_profile_sha256();
    let attested_profile_json = profile.canonical_json();
    let attested_profile_digest = format!("{:x}", Sha256::digest(attested_profile_json.as_bytes()));
    let now = unix_millis().expect("time");
    let ready_until = now + 4_000;
    let mut ready = ReadyFrame {
      signed_evidence_json: String::new(),
      challenge: challenge.to_owned(),
      ready_until_unix_millis: ready_until,
      attested_profile_digest: attested_profile_digest.clone(),
      attested_profile_json,
      deployment_epoch,
      profile_digest: config.profile_digest.clone(),
      gateway_image_digest: config.gateway_image_digest.clone(),
      runner_image_digest: config.runner_image_digest.clone(),
      runner_workload_identity: workload_identity.to_owned(),
      runner_client_cert_public_key_fingerprint: spki.to_owned(),
      credential_revision: config.credential_revision.clone(),
      github_mcp_access_auth_mode: config.github_mcp_access_auth_mode.clone(),
      github_mcp_access_token_revision: config.github_mcp_access_token_revision.clone(),
    };
    let payload_digest = ready_evidence_payload_digest(&ready);
    ready.signed_evidence_json = sign_runner_evidence(
      &RunnerEvidenceClaims {
        kind: RunnerEvidenceKind::Ready,
        algorithm_version: "ed25519-v1".to_owned(),
        signer_identity: config.executor_evidence_signer_identity.clone(),
        key_revision: config.executor_evidence_key_revision.clone(),
        session_nonce: session_nonce.to_owned(),
        challenge: challenge.to_owned(),
        sequence: 1,
        issued_at_unix_millis: now,
        expires_at_unix_millis: ready_until,
        deployment_epoch,
        deployment_profile_digest: config.profile_digest.clone(),
        observed_profile_digest: attested_profile_digest.clone(),
        executor_identity: config.executor_identity.clone(),
        credential_revision: config.credential_revision.clone(),
        payload_digest,
      },
      &config.executor_evidence_key_id,
      &evidence_keys().0,
    )
    .expect("sign")
    .canonical_json();
    RemoteFrame {
      version: REMOTE_PROTOCOL_VERSION,
      session_nonce: session_nonce.to_owned(),
      sequence: 1,
      message: RemoteMessage::Ready(ready),
    }
  }

  fn capability_profile(config: &ScheduledRunnerBrokerConfig) -> AttestedCapabilityProfile {
    let mut profile = AttestedCapabilityProfile {
      codex_version: "test-codex".to_owned(),
      app_server_schema_sha256: "1".repeat(64),
      codex_program_sha256: "2".repeat(64),
      github_mcp_version: "test-mcp".to_owned(),
      github_mcp_artifact_sha256: "3".repeat(64),
      github_mcp_endpoint_identity: "test-endpoint".to_owned(),
      github_mcp_access_auth_mode: "bearer-token-env-v1".to_owned(),
      github_mcp_access_token_revision: "mcp-channel-v1".to_owned(),
      github_mcp_health_checked_at_unix_seconds: 1,
      github_mcp_health_credential_revision: config.credential_revision.clone(),
      github_mcp_health_result_sha256: "8".repeat(64),
      github_mcp_health_tool: "get_me".to_owned(),
      github_tools: [
        "get_me",
        "issue_read",
        "list_issues",
        "search_issues",
        "search_orgs",
      ]
      .into_iter()
      .map(str::to_owned)
      .collect(),
      credential_reference: "test-credential".to_owned(),
      permission_policy_revision: "test-policy".to_owned(),
      config_revision: "test-config".to_owned(),
      config_sha256: "4".repeat(64),
      gateway_image_digest: config.gateway_image_digest.clone(),
      runner_image_digest: config.runner_image_digest.clone(),
      runner_workload_identity: config.runner_workload_identity.clone(),
      runner_client_cert_public_key_fingerprint: config.runner_client_spki_sha256.clone(),
      credential_revision: config.credential_revision.clone(),
      credential_isolation_revision: "test-isolation".to_owned(),
      credential_deny_policy_revision: "test-deny".to_owned(),
      negative_test_revision: "test-negative".to_owned(),
      output_schema_revision: "test-output".to_owned(),
      attested_at_unix_seconds: 1,
      profile_sha256: String::new(),
    };
    profile.profile_sha256 = profile.computed_profile_sha256();
    profile
  }

  #[allow(
    clippy::too_many_arguments,
    reason = "test evidence binds every production claim"
  )]
  fn production_claims(
    config: &ScheduledRunnerBrokerConfig,
    kind: RunnerEvidenceKind,
    session_nonce: &str,
    challenge: &str,
    sequence: u64,
    expires_at_unix_millis: u64,
    observed_profile_digest: &str,
    payload_digest: String,
  ) -> RunnerEvidenceClaims {
    RunnerEvidenceClaims {
      kind,
      algorithm_version: "ed25519-v1".to_owned(),
      signer_identity: config.executor_evidence_signer_identity.clone(),
      key_revision: config.executor_evidence_key_revision.clone(),
      session_nonce: session_nonce.to_owned(),
      challenge: challenge.to_owned(),
      sequence,
      issued_at_unix_millis: unix_millis().expect("time"),
      expires_at_unix_millis,
      deployment_epoch: config.deployment_epoch,
      deployment_profile_digest: config.profile_digest.clone(),
      observed_profile_digest: observed_profile_digest.to_owned(),
      executor_identity: config.executor_identity.clone(),
      credential_revision: config.credential_revision.clone(),
      payload_digest,
    }
  }

  fn registered_session(session_nonce: &str) -> Arc<RegisteredRunnerSession> {
    let config = config();
    let frame = ready_frame(
      session_nonce,
      &"f".repeat(64),
      config.deployment_epoch,
      &config.runner_workload_identity,
      &config.runner_client_spki_sha256,
    );
    let RemoteMessage::Ready(ready) = frame.message.clone() else {
      unreachable!()
    };
    let (commands, _receiver) = mpsc::channel(BROKER_COMMAND_CAPACITY);
    Arc::new(RegisteredRunnerSession {
      session_nonce: session_nonce.to_owned(),
      ready_frame: frame,
      ready,
      commands,
      evidence_config: config,
      connected: AtomicBool::new(true),
      slot: Mutex::new(None),
    })
  }

  #[test]
  fn prepared_and_result_evidence_reject_tamper_replay_and_wrong_kind() {
    let config = config();
    let nonce = "9".repeat(64);
    let challenge = "8".repeat(64);
    let ready = ready_frame(
      &nonce,
      &challenge,
      config.deployment_epoch,
      &config.runner_workload_identity,
      &config.runner_client_spki_sha256,
    );
    let now = unix_millis().expect("time");
    for (kind, sequence, payload) in [
      (RunnerEvidenceKind::Prepared, 2, "6".repeat(64)),
      (RunnerEvidenceKind::Result, 3, "7".repeat(64)),
    ] {
      let claims = RunnerEvidenceClaims {
        kind,
        algorithm_version: "ed25519-v1".to_owned(),
        signer_identity: config.executor_evidence_signer_identity.clone(),
        key_revision: config.executor_evidence_key_revision.clone(),
        session_nonce: nonce.clone(),
        challenge: challenge.clone(),
        sequence,
        issued_at_unix_millis: now,
        expires_at_unix_millis: now + 4_000,
        deployment_epoch: config.deployment_epoch,
        deployment_profile_digest: config.profile_digest.clone(),
        observed_profile_digest: "5".repeat(64),
        executor_identity: config.executor_identity.clone(),
        credential_revision: config.credential_revision.clone(),
        payload_digest: payload.clone(),
      };
      let signed = sign_runner_evidence(
        &claims,
        &config.executor_evidence_key_id,
        &evidence_keys().0,
      )
      .expect("signed evidence")
      .canonical_json();
      assert!(
        validate_executor_evidence(
          &config,
          &ready,
          ExpectedRunnerEvidence {
            kind,
            sequence,
            observed_profile_digest: &"5".repeat(64),
            payload_digest: &payload,
          },
          &signed,
          now
        )
        .is_ok()
      );
      assert!(
        validate_executor_evidence(
          &config,
          &ready,
          ExpectedRunnerEvidence {
            kind,
            sequence,
            observed_profile_digest: &"5".repeat(64),
            payload_digest: &"0".repeat(64),
          },
          &signed,
          now
        )
        .is_err()
      );
      assert!(
        validate_executor_evidence(
          &config,
          &ready,
          ExpectedRunnerEvidence {
            kind: RunnerEvidenceKind::Ready,
            sequence,
            observed_profile_digest: &"5".repeat(64),
            payload_digest: &payload,
          },
          &signed,
          now
        )
        .is_err()
      );
    }
  }

  #[test]
  fn prepared_nonce_translation_and_result_kind_translation_are_rejected() {
    let config = config();
    let nonce = "9".repeat(64);
    let challenge = "8".repeat(64);
    let ready = ready_frame(
      &nonce,
      &challenge,
      config.deployment_epoch,
      &config.runner_workload_identity,
      &config.runner_client_spki_sha256,
    );
    let now = unix_millis().expect("time");
    let binding = RunBinding {
      run_id: "01J00000000000000000000000".to_owned(),
      job_id: "01J00000000000000000000001".to_owned(),
      attempt: 1,
      fence_token: 2,
      authority_digest: "1".repeat(64),
      profile_digest: config.profile_digest.clone(),
      deployment_epoch: config.deployment_epoch,
      credential_revision: config.credential_revision.clone(),
    };
    let mut prepared = PreparedFrame {
      signed_evidence_json: String::new(),
      binding: binding.clone(),
      preparation_nonce: "3".repeat(64),
      attested_profile_json: "{\"profile\":1}".to_owned(),
      attested_profile_digest: "4".repeat(64),
      github_mcp_access_auth_mode: config.github_mcp_access_auth_mode.clone(),
      github_mcp_access_token_revision: config.github_mcp_access_token_revision.clone(),
    };
    let payload_digest = prepared_evidence_payload_digest(&prepared);
    prepared.signed_evidence_json = sign_runner_evidence(
      &RunnerEvidenceClaims {
        kind: RunnerEvidenceKind::Prepared,
        algorithm_version: "ed25519-v1".to_owned(),
        signer_identity: config.executor_evidence_signer_identity.clone(),
        key_revision: config.executor_evidence_key_revision.clone(),
        session_nonce: nonce.clone(),
        challenge: challenge.clone(),
        sequence: 2,
        issued_at_unix_millis: now,
        expires_at_unix_millis: now + 4_000,
        deployment_epoch: config.deployment_epoch,
        deployment_profile_digest: config.profile_digest.clone(),
        observed_profile_digest: prepared.attested_profile_digest.clone(),
        executor_identity: config.executor_identity.clone(),
        credential_revision: config.credential_revision.clone(),
        payload_digest,
      },
      &config.executor_evidence_key_id,
      &evidence_keys().0,
    )
    .expect("prepared signature")
    .canonical_json();
    prepared.preparation_nonce = "5".repeat(64);
    assert!(
      validate_executor_evidence(
        &config,
        &ready,
        ExpectedRunnerEvidence {
          kind: RunnerEvidenceKind::Prepared,
          sequence: 2,
          observed_profile_digest: &prepared.attested_profile_digest,
          payload_digest: &prepared_evidence_payload_digest(&prepared),
        },
        &prepared.signed_evidence_json,
        now,
      )
      .is_err()
    );

    let mut result = ResultFrame {
      signed_evidence_json: String::new(),
      binding,
      preparation_nonce: "3".repeat(64),
      kind: RemoteResultKind::Completed,
      result_json: "{\"schema_version\":1,\"summary\":\"done\"}".to_owned(),
    };
    let payload_digest = result_evidence_payload_digest(&result);
    result.signed_evidence_json = sign_runner_evidence(
      &RunnerEvidenceClaims {
        kind: RunnerEvidenceKind::Result,
        algorithm_version: "ed25519-v1".to_owned(),
        signer_identity: config.executor_evidence_signer_identity.clone(),
        key_revision: config.executor_evidence_key_revision.clone(),
        session_nonce: nonce,
        challenge,
        sequence: 3,
        issued_at_unix_millis: now,
        expires_at_unix_millis: now + 4_000,
        deployment_epoch: config.deployment_epoch,
        deployment_profile_digest: config.profile_digest.clone(),
        observed_profile_digest: "4".repeat(64),
        executor_identity: config.executor_identity.clone(),
        credential_revision: config.credential_revision.clone(),
        payload_digest,
      },
      &config.executor_evidence_key_id,
      &evidence_keys().0,
    )
    .expect("result signature")
    .canonical_json();
    result.kind = RemoteResultKind::OutcomeUnknown;
    assert!(
      validate_executor_evidence(
        &config,
        &ready,
        ExpectedRunnerEvidence {
          kind: RunnerEvidenceKind::Result,
          sequence: 3,
          observed_profile_digest: &"4".repeat(64),
          payload_digest: &result_evidence_payload_digest(&result),
        },
        &result.signed_evidence_json,
        now,
      )
      .is_err()
    );
  }

  #[test]
  fn authenticated_runner_failures_do_not_advance_prepare_or_result_state() {
    let config = config();
    let nonce = "9".repeat(64);
    let challenge = "8".repeat(64);
    let ready = ready_frame(
      &nonce,
      &challenge,
      config.deployment_epoch,
      &config.runner_workload_identity,
      &config.runner_client_spki_sha256,
    );
    let authority = ScheduledPrepareAuthority::for_remote_session_test("run-1", "job-1", 1, 7);
    let mut session =
      RemoteSessionState::new(nonce.clone(), authority.clone()).expect("session state");
    let now = unix_millis().expect("time");
    session
      .accept(RemoteSessionRole::Runner, ready.clone(), now)
      .expect("ready");
    session
      .accept(
        RemoteSessionRole::Gateway,
        RemoteFrame {
          version: REMOTE_PROTOCOL_VERSION,
          session_nonce: nonce.clone(),
          sequence: 1,
          message: RemoteMessage::Admission(AdmissionFrame {
            challenge: challenge.clone(),
            admission_nonce: "7".repeat(64),
            expires_at_unix_millis: now + 4_000,
            deployment_epoch: config.deployment_epoch,
            profile_digest: config.profile_digest.clone(),
          }),
        },
        now,
      )
      .expect("admission");
    let binding = RunBinding {
      run_id: "run-1".to_owned(),
      job_id: "job-1".to_owned(),
      attempt: 1,
      fence_token: 7,
      authority_digest: authority.digest().to_owned(),
      profile_digest: config.profile_digest.clone(),
      deployment_epoch: config.deployment_epoch,
      credential_revision: config.credential_revision.clone(),
    };
    session
      .accept(
        RemoteSessionRole::Gateway,
        RemoteFrame {
          version: REMOTE_PROTOCOL_VERSION,
          session_nonce: nonce.clone(),
          sequence: 2,
          message: RemoteMessage::Prepare(PrepareFrame {
            binding: binding.clone(),
            isolation_permit_envelope_json: "{\"schema_version\":1}".to_owned(),
            task_json: "{\"schema_version\":1}".to_owned(),
            definition_json: "{\"schema_version\":1}".to_owned(),
            capability_json: "{\"schema_version\":1}".to_owned(),
            targets_json: "[]".to_owned(),
          }),
        },
        now,
      )
      .expect("prepare");

    let profile_json = capability_profile(&config).canonical_json();
    let profile_digest = format!("{:x}", Sha256::digest(profile_json.as_bytes()));
    let mut prepared = PreparedFrame {
      signed_evidence_json: String::new(),
      binding: binding.clone(),
      preparation_nonce: "6".repeat(64),
      attested_profile_json: profile_json,
      attested_profile_digest: profile_digest.clone(),
      github_mcp_access_auth_mode: config.github_mcp_access_auth_mode.clone(),
      github_mcp_access_token_revision: config.github_mcp_access_token_revision.clone(),
    };
    let prepared_payload = prepared_evidence_payload_digest(&prepared);
    prepared.signed_evidence_json = sign_runner_evidence(
      &RunnerEvidenceClaims {
        kind: RunnerEvidenceKind::Prepared,
        algorithm_version: "ed25519-v1".to_owned(),
        signer_identity: config.executor_evidence_signer_identity.clone(),
        key_revision: config.executor_evidence_key_revision.clone(),
        session_nonce: nonce.clone(),
        challenge: challenge.clone(),
        sequence: 2,
        issued_at_unix_millis: now,
        expires_at_unix_millis: now + 4_000,
        deployment_epoch: config.deployment_epoch,
        deployment_profile_digest: config.profile_digest.clone(),
        observed_profile_digest: profile_digest.clone(),
        executor_identity: config.executor_identity.clone(),
        credential_revision: config.credential_revision.clone(),
        payload_digest: prepared_payload,
      },
      &config.executor_evidence_key_id,
      &evidence_keys().0,
    )
    .expect("prepared signature")
    .canonical_json();
    let prepared_frame = RemoteFrame {
      version: REMOTE_PROTOCOL_VERSION,
      session_nonce: nonce.clone(),
      sequence: 2,
      message: RemoteMessage::Prepared(prepared),
    };
    for mutation in 0..3 {
      let mut translated = prepared_frame.clone();
      let RemoteMessage::Prepared(translated_payload) = &mut translated.message else {
        unreachable!()
      };
      match mutation {
        0 => translated_payload.preparation_nonce = "5".repeat(64),
        1 => translated_payload.github_mcp_access_auth_mode = "legacy-bearer".to_owned(),
        2 => translated_payload.github_mcp_access_token_revision = "mcp-channel-v0".to_owned(),
        _ => unreachable!(),
      }
      assert!(
        accept_authenticated_prepared(&mut session, &config, &ready, &translated, now).is_err(),
        "prepared auth mutation {mutation} advanced state"
      );
    }
    accept_authenticated_prepared(&mut session, &config, &ready, &prepared_frame, now)
      .expect("valid prepared remains acceptable");
    assert!(
      accept_authenticated_prepared(&mut session, &config, &ready, &prepared_frame, now).is_err(),
      "exact same-kind prepared replay must fail closed"
    );
    session
      .accept(
        RemoteSessionRole::Gateway,
        RemoteFrame {
          version: REMOTE_PROTOCOL_VERSION,
          session_nonce: nonce.clone(),
          sequence: 3,
          message: RemoteMessage::Start(StartFrame {
            binding: binding.clone(),
            preparation_nonce: "6".repeat(64),
          }),
        },
        now,
      )
      .expect("start");

    let mut result = ResultFrame {
      signed_evidence_json: String::new(),
      binding,
      preparation_nonce: "6".repeat(64),
      kind: RemoteResultKind::Completed,
      result_json: "{\"schema_version\":1,\"summary\":\"done\"}".to_owned(),
    };
    let result_payload = result_evidence_payload_digest(&result);
    result.signed_evidence_json = sign_runner_evidence(
      &RunnerEvidenceClaims {
        kind: RunnerEvidenceKind::Result,
        algorithm_version: "ed25519-v1".to_owned(),
        signer_identity: config.executor_evidence_signer_identity.clone(),
        key_revision: config.executor_evidence_key_revision.clone(),
        session_nonce: nonce.clone(),
        challenge,
        sequence: 3,
        issued_at_unix_millis: now,
        expires_at_unix_millis: now + 4_000,
        deployment_epoch: config.deployment_epoch,
        deployment_profile_digest: config.profile_digest.clone(),
        observed_profile_digest: profile_digest.clone(),
        executor_identity: config.executor_identity.clone(),
        credential_revision: config.credential_revision.clone(),
        payload_digest: result_payload,
      },
      &config.executor_evidence_key_id,
      &evidence_keys().0,
    )
    .expect("result signature")
    .canonical_json();
    let result_frame = RemoteFrame {
      version: REMOTE_PROTOCOL_VERSION,
      session_nonce: nonce,
      sequence: 3,
      message: RemoteMessage::Result(result),
    };
    for mutation in 0..11 {
      let mut translated = result_frame.clone();
      let RemoteMessage::Result(translated_payload) = &mut translated.message else {
        unreachable!()
      };
      match mutation {
        0 => translated_payload.binding.run_id.push('x'),
        1 => translated_payload.binding.job_id.push('x'),
        2 => translated_payload.binding.attempt += 1,
        3 => translated_payload.binding.fence_token += 1,
        4 => translated_payload.binding.authority_digest = "0".repeat(64),
        5 => translated_payload.binding.profile_digest = "0".repeat(64),
        6 => translated_payload.binding.deployment_epoch += 1,
        7 => translated_payload.binding.credential_revision = "credential-v2".to_owned(),
        8 => translated_payload.preparation_nonce = "5".repeat(64),
        9 => translated_payload.kind = RemoteResultKind::OutcomeUnknown,
        10 => translated_payload.result_json.push(' '),
        _ => unreachable!(),
      }
      assert!(
        accept_authenticated_result(
          &mut session,
          &config,
          match &ready.message {
            RemoteMessage::Ready(ready) => ready,
            _ => unreachable!(),
          },
          &profile_digest,
          &translated,
          now,
        )
        .is_err(),
        "result mutation {mutation} advanced authenticated state"
      );
    }
    accept_authenticated_result(
      &mut session,
      &config,
      match &ready.message {
        RemoteMessage::Ready(ready) => ready,
        _ => unreachable!(),
      },
      &profile_digest,
      &result_frame,
      now,
    )
    .expect("valid result remains acceptable");
    assert!(
      accept_authenticated_result(
        &mut session,
        &config,
        match &ready.message {
          RemoteMessage::Ready(ready) => ready,
          _ => unreachable!(),
        },
        &profile_digest,
        &result_frame,
        now,
      )
      .is_err(),
      "exact same-kind result replay must fail closed"
    );

    let reconnect_nonce = "a".repeat(64);
    let reconnect_ready = ready_frame(
      &reconnect_nonce,
      &"b".repeat(64),
      config.deployment_epoch,
      &config.runner_workload_identity,
      &config.runner_client_spki_sha256,
    );
    let RemoteMessage::Result(result) = &result_frame.message else {
      unreachable!()
    };
    assert!(
      validate_executor_evidence(
        &config,
        &reconnect_ready,
        ExpectedRunnerEvidence {
          kind: RunnerEvidenceKind::Result,
          sequence: result_frame.sequence,
          observed_profile_digest: &profile_digest,
          payload_digest: &result_evidence_payload_digest(result),
        },
        &result.signed_evidence_json,
        now,
      )
      .is_err(),
      "evidence from an old connection must not replay after reconnect"
    );
  }

  #[test]
  fn broker_configuration_rejects_noncanonical_identity_and_unbounded_capacity() {
    let mut candidate = config();
    assert!(candidate.validate().is_ok());
    candidate.runner_workload_identity = "SPIFFE://codeoff/runner".to_owned();
    assert!(matches!(
      candidate.validate(),
      Err(ScheduledRunnerBrokerError::InvalidConfiguration)
    ));
    candidate = config();
    candidate.max_connections = MAX_BROKER_CONNECTIONS + 1;
    assert!(matches!(
      candidate.validate(),
      Err(ScheduledRunnerBrokerError::InvalidConfiguration)
    ));
  }

  #[test]
  fn ready_admission_rejects_stale_or_mismatched_runner_authority() {
    let config = config();
    let broker = ScheduledRunnerBroker::new(config.clone()).expect("broker");
    let authorized_peer = broker.expected_authorized_peer();
    let nonce = "1".repeat(64);
    let challenge = "2".repeat(64);

    let valid = ready_frame(
      &nonce,
      &challenge,
      config.deployment_epoch,
      &config.runner_workload_identity,
      &config.runner_client_spki_sha256,
    );
    let RemoteMessage::Ready(valid_ready) = &valid.message else {
      unreachable!()
    };
    assert!(
      broker
        .validate_ready(&authorized_peer, &valid, valid_ready, &nonce, &challenge)
        .is_ok()
    );

    let stale = ready_frame(
      &nonce,
      &challenge,
      config.deployment_epoch - 1,
      &config.runner_workload_identity,
      &config.runner_client_spki_sha256,
    );
    let RemoteMessage::Ready(stale_ready) = &stale.message else {
      unreachable!()
    };
    assert!(matches!(
      broker.validate_ready(&authorized_peer, &stale, stale_ready, &nonce, &challenge,),
      Err(ScheduledRunnerBrokerError::StaleSession)
    ));

    let wrong_workload = ready_frame(
      &nonce,
      &challenge,
      config.deployment_epoch,
      "spiffe://codeoff/runner/staging",
      &config.runner_client_spki_sha256,
    );
    let RemoteMessage::Ready(wrong_workload_ready) = &wrong_workload.message else {
      unreachable!()
    };
    assert!(matches!(
      broker.validate_ready(
        &authorized_peer,
        &wrong_workload,
        wrong_workload_ready,
        &nonce,
        &challenge,
      ),
      Err(ScheduledRunnerBrokerError::ReadyIdentityMismatch)
    ));

    let mut wrong_binding = valid.clone();
    wrong_binding.session_nonce = "3".repeat(64);
    assert!(matches!(
      broker.validate_ready(
        &authorized_peer,
        &wrong_binding,
        valid_ready,
        &nonce,
        &challenge,
      ),
      Err(ScheduledRunnerBrokerError::SessionBindingMismatch)
    ));

    let wrong_mapping = ScheduledRunnerAuthorizedPeer::new(
      "spiffe://codeoff/runner/staging",
      &config.runner_client_spki_sha256,
    )
    .expect("alternate authorization mapping");
    assert!(matches!(
      broker.validate_ready(&wrong_mapping, &valid, valid_ready, &nonce, &challenge),
      Err(ScheduledRunnerBrokerError::ReadyIdentityMismatch)
    ));
    let mut legacy_mode = valid.clone();
    let RemoteMessage::Ready(legacy_mode_ready) = &mut legacy_mode.message else {
      unreachable!()
    };
    legacy_mode_ready.github_mcp_access_auth_mode = "legacy-bearer".to_owned();
    let legacy_mode_ready = legacy_mode_ready.clone();
    assert!(matches!(
      broker.validate_ready(
        &authorized_peer,
        &legacy_mode,
        &legacy_mode_ready,
        &nonce,
        &challenge,
      ),
      Err(ScheduledRunnerBrokerError::ReadyIdentityMismatch)
    ));
    let mut rotated_config = config.clone();
    rotated_config.github_mcp_access_token_revision = "mcp-channel-v2".to_owned();
    let rotated = ScheduledRunnerBroker::new(rotated_config).expect("rotated broker");
    assert!(matches!(
      rotated.validate_ready(
        &rotated.expected_authorized_peer(),
        &valid,
        valid_ready,
        &nonce,
        &challenge,
      ),
      Err(ScheduledRunnerBrokerError::ReadyIdentityMismatch)
    ));
    assert!(broker.session().is_none());
  }

  #[test]
  fn broker_allows_one_active_session_and_one_claim_reservation() {
    let broker = ScheduledRunnerBroker::new(config()).expect("broker");
    let first = registered_session(&"1".repeat(64));
    let second = registered_session(&"2".repeat(64));
    broker.register(&first).expect("first registration");
    assert!(matches!(
      broker.register(&second),
      Err(ScheduledRunnerBrokerError::DuplicateSession)
    ));

    let (materialization, materialization_session) = broker
      .state_admission(false)
      .expect("materialization admission");
    assert_eq!(materialization.deployment_epoch, 9);
    assert!(materialization_session.slot.lock().expect("slot").is_none());

    let (_, claim_session) = broker.state_admission(true).expect("claim admission");
    assert!(claim_session.slot.lock().expect("slot").is_some());
    assert!(matches!(
      broker.state_admission(true),
      Err(ScheduledRunnerBrokerError::SessionUnavailable)
    ));
    claim_session.release_slot();
    assert!(broker.state_admission(true).is_ok());

    first.connected.store(false, Ordering::Release);
    broker.register(&second).expect("replacement registration");
  }

  #[test]
  fn disconnect_semantics_distinguish_pre_start_from_unknown_outcome() {
    assert!(matches!(
      disconnect_terminal(RemoteDisconnectOutcome::PreflightNoExecution),
      RemoteExecutionTerminal::FailedBeforeStart
    ));
    for outcome in [
      RemoteDisconnectOutcome::OutcomeUnknown,
      RemoteDisconnectOutcome::AlreadyConclusive(RemoteTerminalDisposition::Completed),
      RemoteDisconnectOutcome::AlreadyConclusive(RemoteTerminalDisposition::OutcomeUnknown),
    ] {
      assert!(matches!(
        disconnect_terminal(outcome),
        RemoteExecutionTerminal::OutcomeUnknown
      ));
    }
    assert!(matches!(
      disconnect_terminal(RemoteDisconnectOutcome::AlreadyConclusive(
        RemoteTerminalDisposition::FailedBeforeStart,
      )),
      RemoteExecutionTerminal::FailedBeforeStart
    ));
  }

  #[tokio::test]
  #[allow(
    clippy::too_many_lines,
    reason = "one root-only integration keeps TLS, setuid relay, broker state, and evidence visible"
  )]
  async fn production_setuid_relay_drives_signed_broker_session_to_result() {
    if geteuid().as_raw() != 0 {
      return;
    }
    let fixture = CertificateFixture::new("broker-production-relay");
    fs::set_permissions(
      fixture
        .client_paths()
        .certificate_chain
        .parent()
        .expect("fixture root"),
      fs::Permissions::from_mode(0o755),
    )
    .expect("fixture root permissions");
    let timeout = Duration::from_secs(5);
    let policy = ScheduledRunnerIoPolicy {
      handshake_timeout: timeout,
      read_timeout: timeout,
      write_timeout: timeout,
    };
    let mut broker_config = config();
    broker_config.runner_client_spki_sha256 = fixture.client_spki_sha256.clone();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("evidence key");
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("evidence pair");
    broker_config.executor_evidence_public_key = pair.public_key().as_ref().to_vec();
    let evidence_key_path = fixture
      .client_paths()
      .certificate_chain
      .parent()
      .expect("fixture root")
      .join("executor.pk8");
    fs::write(&evidence_key_path, pkcs8.as_ref()).expect("evidence private key");
    fs::set_permissions(&evidence_key_path, fs::Permissions::from_mode(0o400))
      .expect("evidence private key mode");
    let signer =
      RunnerEvidenceSigner::load(&evidence_key_path, &broker_config.executor_evidence_key_id)
        .expect("root evidence signer");
    let broker = ScheduledRunnerBroker::new(broker_config.clone()).expect("broker");
    let server = ScheduledRunnerTlsServer::load(
      &fixture.server_paths(),
      broker.expected_authorized_peer(),
      policy,
    )
    .expect("TLS server");
    let tcp = TcpListener::bind("127.0.0.1:0")
      .await
      .expect("gateway bind");
    let address = tcp.local_addr().expect("gateway address");
    let socket_path = evidence_key_path
      .parent()
      .expect("fixture root")
      .join("executor.sock");
    let helper_executable = evidence_key_path
      .parent()
      .expect("fixture root")
      .join("production-relay-helper");
    fs::copy(
      std::env::current_exe().expect("test executable"),
      &helper_executable,
    )
    .expect("copy relay helper");
    fs::set_permissions(&helper_executable, fs::Permissions::from_mode(0o755))
      .expect("relay helper permissions");
    let executor_listener =
      ProtectedScheduledExecutorListener::bind(ScheduledRunnerExecutorConfig {
        socket_path: socket_path.clone(),
        control_uid: TEST_CONTROL_UID,
        control_gid: TEST_CONTROL_GID,
        accept_timeout: timeout,
        read_timeout: timeout,
        write_timeout: timeout,
      })
      .expect("protected executor listener");

    let client_paths = fixture.client_paths();
    for path in [
      &client_paths.certificate_chain,
      &client_paths.private_key,
      &client_paths.trust_bundle,
    ] {
      chown(
        path,
        Some(Uid::from_raw(TEST_CONTROL_UID)),
        Some(Gid::from_raw(TEST_CONTROL_GID)),
      )
      .expect("control TLS file owner");
    }
    let child = Command::new(&helper_executable)
      .arg("--exact")
      .arg("scheduled_runner_broker::tests::production_relay_subprocess_helper")
      .arg("--nocapture")
      .env_clear()
      .env(PRODUCTION_RELAY_HELPER_ENV, "1")
      .env(PRODUCTION_RELAY_ADDRESS_ENV, address.to_string())
      .env(PRODUCTION_RELAY_CA_ENV, &client_paths.trust_bundle)
      .env(PRODUCTION_RELAY_CERT_ENV, &client_paths.certificate_chain)
      .env(PRODUCTION_RELAY_KEY_ENV, &client_paths.private_key)
      .env(PRODUCTION_RELAY_SOCKET_ENV, &socket_path)
      .env(PRODUCTION_RELAY_EVIDENCE_KEY_ENV, &evidence_key_path)
      .uid(TEST_CONTROL_UID)
      .gid(TEST_CONTROL_GID)
      .stdin(Stdio::null())
      .stdout(Stdio::piped())
      .stderr(Stdio::piped())
      .spawn()
      .expect("spawn setuid control relay");

    let broker_for_connection = broker.clone();
    let connection_task = tokio::spawn(async move {
      let (stream, _) = tcp.accept().await.expect("gateway accept");
      let connection = server.accept(stream).await.expect("TLS accept");
      broker_for_connection.run_connection(connection).await
    });
    let mut local = executor_listener
      .accept()
      .await
      .expect("root executor accepted setuid control")
      .framed;
    let readiness_request = local
      .read_frame(unix_millis().expect("time"))
      .await
      .expect("readiness request read")
      .expect("readiness request");
    let RemoteMessage::ReadinessRequest(readiness) = &readiness_request.message else {
      panic!("readiness request expected")
    };
    let profile = capability_profile(&broker_config);
    let profile_json = profile.canonical_json();
    let profile_digest = format!("{:x}", Sha256::digest(profile_json.as_bytes()));
    let mut ready = ReadyFrame {
      signed_evidence_json: String::new(),
      challenge: readiness.challenge.clone(),
      ready_until_unix_millis: readiness.ready_until_unix_millis,
      attested_profile_digest: profile_digest.clone(),
      attested_profile_json: profile_json.clone(),
      deployment_epoch: broker_config.deployment_epoch,
      profile_digest: broker_config.profile_digest.clone(),
      gateway_image_digest: broker_config.gateway_image_digest.clone(),
      runner_image_digest: broker_config.runner_image_digest.clone(),
      runner_workload_identity: broker_config.runner_workload_identity.clone(),
      runner_client_cert_public_key_fingerprint: broker_config.runner_client_spki_sha256.clone(),
      credential_revision: broker_config.credential_revision.clone(),
      github_mcp_access_auth_mode: broker_config.github_mcp_access_auth_mode.clone(),
      github_mcp_access_token_revision: broker_config.github_mcp_access_token_revision.clone(),
    };
    ready.signed_evidence_json = signer
      .sign(&production_claims(
        &broker_config,
        RunnerEvidenceKind::Ready,
        &readiness_request.session_nonce,
        &readiness.challenge,
        1,
        readiness.ready_until_unix_millis,
        &profile_digest,
        ready_evidence_payload_digest(&ready),
      ))
      .expect("sign ready")
      .canonical_json();
    local
      .write_frame(&RemoteFrame {
        version: REMOTE_PROTOCOL_VERSION,
        session_nonce: readiness_request.session_nonce.clone(),
        sequence: 1,
        message: RemoteMessage::Ready(ready.clone()),
      })
      .await
      .expect("ready");

    let session = tokio::time::timeout(timeout, async {
      loop {
        if let Some(session) = broker.session() {
          break session;
        }
        tokio::task::yield_now().await;
      }
    })
    .await
    .expect("broker registration");
    broker
      .state_admission(true)
      .expect("reserve broker session");
    let authority = ScheduledPrepareAuthority::for_remote_session_test("run-1", "job-1", 1, 7);
    let input = PrepareInput {
      task: AgentTask {
        task_id: "scheduled:run-1:1:7".to_owned(),
        instruction: "check".to_owned(),
        source: InvocationSource::ScheduledRun {
          job_id: "job-1".to_owned(),
          run_id: "run-1".to_owned(),
          scheduled_for: "2026-07-23T00:00:00Z".to_owned(),
        },
        principal: InvocationPrincipal::service("codeoff-scheduler"),
        session: SessionMode::Fresh,
        channel: None,
        previous_success: None,
        tool_policy: ToolPolicy::None,
        feedback_target: None,
      },
      binding: RunLeaseBinding::for_remote_session_test("run-1", "job-1", 1, 7),
      authority,
      definition_json: "{\"schema_version\":1}".to_owned(),
      capability_json: "{\"schema_version\":1}".to_owned(),
      capability_digest: "3".repeat(64),
      targets_json: "[]".to_owned(),
      cancellation: Arc::new(AtomicBool::new(false)),
    };

    let executor_config = broker_config.clone();
    let executor_signer =
      RunnerEvidenceSigner::load(&evidence_key_path, &broker_config.executor_evidence_key_id)
        .expect("root executor evidence signer");
    let executor_profile_json = profile_json.clone();
    let executor_profile_digest = profile_digest.clone();
    let executor_ready = ready.clone();
    let executor_authority_digest = input.authority.digest().to_owned();
    let executor = tokio::spawn(async move {
      for expected in ["admission", "prepare"] {
        let frame = local
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
      let binding = RunBinding {
        run_id: "run-1".to_owned(),
        job_id: "job-1".to_owned(),
        attempt: 1,
        fence_token: 7,
        authority_digest: executor_authority_digest,
        profile_digest: executor_config.profile_digest.clone(),
        deployment_epoch: executor_config.deployment_epoch,
        credential_revision: executor_config.credential_revision.clone(),
      };
      let mut prepared = PreparedFrame {
        signed_evidence_json: String::new(),
        binding: binding.clone(),
        preparation_nonce: "6".repeat(64),
        attested_profile_digest: executor_profile_digest.clone(),
        attested_profile_json: executor_profile_json,
        github_mcp_access_auth_mode: executor_config.github_mcp_access_auth_mode.clone(),
        github_mcp_access_token_revision: executor_config.github_mcp_access_token_revision.clone(),
      };
      prepared.signed_evidence_json = executor_signer
        .sign(&production_claims(
          &executor_config,
          RunnerEvidenceKind::Prepared,
          &readiness_request.session_nonce,
          &executor_ready.challenge,
          2,
          executor_ready.ready_until_unix_millis,
          &executor_profile_digest,
          prepared_evidence_payload_digest(&prepared),
        ))
        .expect("sign prepared")
        .canonical_json();
      local
        .write_frame(&RemoteFrame {
          version: REMOTE_PROTOCOL_VERSION,
          session_nonce: readiness_request.session_nonce.clone(),
          sequence: 2,
          message: RemoteMessage::Prepared(prepared),
        })
        .await
        .expect("prepared");
      let start = local
        .read_frame(unix_millis().expect("time"))
        .await
        .expect("start read")
        .expect("start frame");
      assert_eq!(start.sequence, 4, "local relay sequence includes readiness");
      let RemoteMessage::Start(start) = start.message else {
        panic!("start expected")
      };
      let mut result = ResultFrame {
        signed_evidence_json: String::new(),
        binding,
        preparation_nonce: start.preparation_nonce,
        kind: RemoteResultKind::Completed,
        result_json: "{\"schema_version\":1,\"summary\":\"done\"}".to_owned(),
      };
      result.signed_evidence_json = executor_signer
        .sign(&production_claims(
          &executor_config,
          RunnerEvidenceKind::Result,
          &readiness_request.session_nonce,
          &executor_ready.challenge,
          3,
          executor_ready.ready_until_unix_millis,
          &executor_profile_digest,
          result_evidence_payload_digest(&result),
        ))
        .expect("sign result")
        .canonical_json();
      local
        .write_frame(&RemoteFrame {
          version: REMOTE_PROTOCOL_VERSION,
          session_nonce: readiness_request.session_nonce,
          sequence: 3,
          message: RemoteMessage::Result(result),
        })
        .await
        .expect("result");
    });

    let verified = session
      .prepare(&input, "{\"schema_version\":1}".to_owned())
      .await
      .expect("stateful authenticated prepare");
    let terminal = session
      .start(
        verified.frame.binding,
        verified.frame.preparation_nonce,
        verified.executor_observed_profile_digest,
        Arc::new(AtomicBool::new(false)),
      )
      .await
      .expect("stateful authenticated result");
    assert!(matches!(
      terminal,
      RemoteExecutionTerminal::Result(ResultFrame {
        kind: RemoteResultKind::Completed,
        ..
      })
    ));
    executor.await.expect("executor task");
    assert!(connection_task.await.expect("connection task").is_ok());
    let output = tokio::task::spawn_blocking(move || child.wait_with_output())
      .await
      .expect("join control child")
      .expect("control child output");
    assert!(
      output.status.success(),
      "control relay failed: stdout={} stderr={}",
      String::from_utf8_lossy(&output.stdout),
      String::from_utf8_lossy(&output.stderr)
    );
    assert!(
      broker.session().is_none(),
      "terminal session must unregister"
    );
  }

  #[tokio::test]
  async fn invalid_signed_ready_through_real_tls_run_connection_never_registers() {
    if geteuid().as_raw() != 0 {
      return;
    }
    let fixture = CertificateFixture::new("broker-invalid-ready");
    let timeout = Duration::from_secs(5);
    let policy = ScheduledRunnerIoPolicy {
      handshake_timeout: timeout,
      read_timeout: timeout,
      write_timeout: timeout,
    };
    let mut broker_config = config();
    broker_config.runner_client_spki_sha256 = fixture.client_spki_sha256.clone();
    let broker = ScheduledRunnerBroker::new(broker_config.clone()).expect("broker");
    let server = ScheduledRunnerTlsServer::load(
      &fixture.server_paths(),
      broker.expected_authorized_peer(),
      policy,
    )
    .expect("TLS server");
    let client = ScheduledRunnerTlsClient::load(&fixture.client_paths(), TEST_SERVER_NAME, policy)
      .expect("TLS client");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("address");
    let broker_for_connection = broker.clone();
    let accepted = tokio::spawn(async move {
      let (stream, _) = listener.accept().await.expect("accept");
      let connection = server.accept(stream).await.expect("TLS accept");
      broker_for_connection.run_connection(connection).await
    });
    let mut connection = client.connect(address).await.expect("TLS connect");
    let nonce = session_nonce(&connection.channel_binding);
    let challenge = session_challenge(&connection.channel_binding);
    let mut frame = ready_frame(
      &nonce,
      &challenge,
      broker_config.deployment_epoch,
      &broker_config.runner_workload_identity,
      &broker_config.runner_client_spki_sha256,
    );
    let RemoteMessage::Ready(ready) = &mut frame.message else {
      unreachable!()
    };
    let mut evidence = SignedRunnerEvidence::parse_canonical_json(&ready.signed_evidence_json)
      .expect("signed ready evidence");
    let replacement = if evidence.signature_hex.starts_with('0') {
      "1"
    } else {
      "0"
    };
    evidence.signature_hex.replace_range(0..1, replacement);
    ready.signed_evidence_json = evidence.canonical_json();
    connection
      .framed
      .write_frame(&frame)
      .await
      .expect("invalid ready frame");
    assert!(matches!(
      accepted.await.expect("connection task"),
      Err(ScheduledRunnerBrokerError::ReadyIdentityMismatch)
    ));
    assert!(
      broker.session().is_none(),
      "invalid READY passed run_connection registry boundary"
    );
  }

  #[tokio::test]
  async fn remote_backend_is_configured_but_fail_closed_without_a_ready_session() {
    let broker = ScheduledRunnerBroker::new(config()).expect("broker");
    let backend =
      RemoteScheduledExecutionBackend::new(broker, Handle::current(), Arc::new(TestPermitIssuer));
    assert!(backend.is_configured());
    assert_eq!(backend.readiness(), ExecutorReadiness::Unavailable);
    assert_eq!(
      backend.refresh_materialization_admission().await,
      RefreshedExecutorAdmission::Unavailable
    );
    assert_eq!(
      backend.refresh_admission().await,
      RefreshedExecutorAdmission::Unavailable
    );
  }

  #[test]
  fn remote_result_requires_the_exact_versioned_summary_shape() {
    let result = |result_json: &str| {
      remote_execution_result(ResultFrame {
        signed_evidence_json: "{}".to_owned(),
        binding: RunBinding {
          run_id: "run-1".to_owned(),
          job_id: "job-1".to_owned(),
          attempt: 1,
          fence_token: 1,
          authority_digest: "a".repeat(64),
          profile_digest: "b".repeat(64),
          deployment_epoch: 1,
          credential_revision: "credential-v1".to_owned(),
        },
        preparation_nonce: "c".repeat(64),
        kind: RemoteResultKind::Completed,
        result_json: result_json.to_owned(),
      })
    };
    assert!(matches!(
      result(r#"{"schema_version":1,"summary":"done"}"#),
      ExecutionResult::Completed { summary } if summary == "done"
    ));
    assert!(matches!(
      result(r#"{"failure_kind":"turn_failed","message":"turn rejected","schema_version":1}"#),
      ExecutionResult::Failed { kind, message }
        if kind == "turn_failed" && message == "turn rejected"
    ));
    for invalid in [
      r#"{"schema_version":2,"summary":"done"}"#,
      r#"{"schema_version":1,"summary":"done","extra":true}"#,
      r#"{"schema_version":1,"summary":1}"#,
    ] {
      assert!(matches!(result(invalid), ExecutionResult::Failed { .. }));
    }
  }

  fn config() -> ScheduledRunnerBrokerConfig {
    ScheduledRunnerBrokerConfig {
      schema_version: 1,
      deployment_epoch: 9,
      attestation_id: "a".repeat(64),
      profile_digest: "b".repeat(64),
      signed_not_after_unix_seconds: i64::MAX,
      gateway_image_digest: format!("sha256:{}", "c".repeat(64)),
      runner_image_digest: format!("sha256:{}", "d".repeat(64)),
      runner_workload_identity: "spiffe://codeoff/runner/production".to_owned(),
      runner_client_spki_sha256: "e".repeat(64),
      credential_revision: "credential-v1".to_owned(),
      github_mcp_access_auth_mode: "bearer-token-env-v1".to_owned(),
      github_mcp_access_token_revision: "mcp-channel-v1".to_owned(),
      executor_evidence_public_key: evidence_keys().1.clone(),
      executor_evidence_key_id: "executor-key-1".to_owned(),
      executor_evidence_key_revision: "executor-evidence-2026-07".to_owned(),
      executor_evidence_signer_identity: "spiffe://codeoff/executor/production".to_owned(),
      executor_identity: "uid:0:gid:0".to_owned(),
      max_connections: 2,
      admission_ttl: Duration::from_secs(5),
    }
  }
}
