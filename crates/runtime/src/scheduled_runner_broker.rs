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
use codeoff_core::CredentialRevision;
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
      || authorized_peer.runner_identity.as_str() != config.runner_workload_identity
      || authorized_peer.client_spki_sha256 != config.runner_client_spki_sha256
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
  ) -> Result<PreparedFrame, ScheduledRunnerBrokerError> {
    let reservation = self.reservation(unix_millis()?)?;
    let binding = remote_binding(input, &self.ready)?;
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
    response: oneshot::Sender<Result<PreparedFrame, ScheduledRunnerBrokerError>>,
  },
  Start {
    frame: Box<RemoteFrame>,
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
            ).await;
            let failed = result.is_err();
            let _ = response.send(result);
            if failed {
              return Err(ScheduledRunnerBrokerError::RunnerRejected);
            }
          }
          BrokerCommand::Start { frame, cancellation, response } => {
            let result = drive_start(&mut connection, *frame, cancellation, &mut state).await;
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
) -> Result<PreparedFrame, ScheduledRunnerBrokerError> {
  if state.is_some() {
    return Err(ScheduledRunnerBrokerError::SessionBusy);
  }
  let mut session = RemoteSessionState::new(ready.session_nonce.clone(), authority)
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
    session
      .accept(RemoteSessionRole::Runner, frame.clone(), unix_millis()?)
      .map_err(|_| ScheduledRunnerBrokerError::ProtocolRejected)?;
    match frame.message {
      RemoteMessage::Prepared(prepared) => {
        *state = Some(session);
        return Ok(prepared);
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
        session
          .accept(RemoteSessionRole::Runner, frame.clone(), unix_millis()?)
          .map_err(|_| ScheduledRunnerBrokerError::ProtocolRejected)?;
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
  prepared: PreparedFrame,
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
    Ok(BackendPrepared::new_remote(
      input.authority,
      prepared.attested_profile_json,
      prepared.attested_profile_digest,
      session.ready.profile_digest.clone(),
      session.ready.deployment_epoch,
      Box::new(RemotePreparedExecution {
        runtime: self.runtime.clone(),
        session,
        binding: prepared.binding,
        preparation_nonce: prepared.preparation_nonce,
      }),
    ))
  }
}

struct RemotePreparedExecution {
  runtime: Handle,
  session: Arc<RegisteredRunnerSession>,
  binding: RunBinding,
  preparation_nonce: String,
}

impl PreparedExecution for RemotePreparedExecution {
  fn execute(self: Box<Self>, cancellation: Arc<AtomicBool>) -> ExecutionResult {
    let this = *self;
    let result = if this.session.is_connected() {
      this.runtime.block_on(
        this
          .session
          .start(this.binding, this.preparation_nonce, cancellation),
      )
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

fn remote_execution_result(result: ResultFrame) -> ExecutionResult {
  match result.kind {
    RemoteResultKind::Completed => {
      let value: Result<Value, _> = serde_json::from_str(&result.result_json);
      let summary = value.ok().and_then(|value| {
        let object = value.as_object()?;
        if object.len() != 2 || object.get("schema_version")?.as_u64()? != 1 {
          return None;
        }
        object.get("summary")?.as_str().map(str::to_owned)
      });
      summary.map_or_else(
        || ExecutionResult::Failed {
          kind: "remote_result_invalid".to_owned(),
          message: "scheduled remote result did not match schema".to_owned(),
        },
        |summary| ExecutionResult::Completed { summary },
      )
    }
    RemoteResultKind::FailedBeforeStart => ExecutionResult::Interrupted {
      transport_converged: true,
    },
    RemoteResultKind::OutcomeUnknown => ExecutionResult::TransportLost {
      message: "scheduled remote runner reported outcome unknown".to_owned(),
    },
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
    RemoteFrame {
      version: REMOTE_PROTOCOL_VERSION,
      session_nonce: session_nonce.to_owned(),
      sequence: 1,
      message: RemoteMessage::Ready(ReadyFrame {
        challenge: challenge.to_owned(),
        ready_until_unix_millis: unix_millis().expect("time") + 10_000,
        deployment_epoch,
        profile_digest: config.profile_digest,
        gateway_image_digest: config.gateway_image_digest,
        runner_image_digest: config.runner_image_digest,
        runner_workload_identity: workload_identity.to_owned(),
        runner_client_cert_public_key_fingerprint: spki.to_owned(),
        credential_revision: config.credential_revision,
      }),
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
      connected: AtomicBool::new(true),
      slot: Mutex::new(None),
    })
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
      max_connections: 2,
      admission_ttl: Duration::from_secs(5),
    }
  }
}
