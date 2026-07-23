//! Role-aware lifecycle validation for one scheduled remote execution session.

use sha2::{Digest, Sha256};

use crate::scheduled_remote_protocol::{
  AdmissionFrame, MAX_ADMISSION_TTL_MILLIS, RemoteFrame, RemoteFrameSequencer,
  RemoteHeartbeatPhase, RemoteMessage, RemoteProtocolError, RunBinding, SequenceAcceptance,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteSessionRole {
  Gateway,
  Runner,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteSessionAcceptance {
  Accepted,
  ExactDuplicate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteDisconnectOutcome {
  PreflightNoExecution,
  OutcomeUnknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SessionPhase {
  WaitingReady,
  WaitingAdmission,
  WaitingPrepare,
  WaitingPrepared,
  WaitingStart,
  WaitingResult,
  Terminal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteSessionError {
  Protocol(RemoteProtocolError),
  WrongSender,
  InvalidPhase,
  SessionIdentityMismatch,
  AdmissionExpired,
  AdmissionTtlInvalid,
  AdmissionConsumed,
  RunBindingMismatch,
  PreparationNonceMismatch,
  AttestedProfileDigestMismatch,
  HeartbeatPhaseRegression,
  HeartbeatAheadOfSession,
  Terminal,
}

impl From<RemoteProtocolError> for RemoteSessionError {
  fn from(error: RemoteProtocolError) -> Self {
    Self::Protocol(error)
  }
}

#[derive(Debug, Clone)]
struct ReadyIdentity {
  challenge: String,
  ready_until_unix_millis: u64,
  deployment_epoch: u64,
  profile_digest: String,
  credential_revision: String,
}

#[derive(Debug, Clone)]
struct AdmissionState {
  nonce: String,
  expires_at_unix_millis: u64,
  consumed: bool,
}

#[derive(Debug, Clone)]
pub struct RemoteSessionState {
  sequencer: RemoteFrameSequencer,
  phase: SessionPhase,
  ready: Option<ReadyIdentity>,
  admission: Option<AdmissionState>,
  binding: Option<RunBinding>,
  preparation_nonce: Option<String>,
  heartbeat_phase: Option<RemoteHeartbeatPhase>,
  last_sender: Option<RemoteSessionRole>,
  started: bool,
}

impl RemoteSessionState {
  pub fn new(session_nonce: String) -> Result<Self, RemoteSessionError> {
    Ok(Self {
      sequencer: RemoteFrameSequencer::new(session_nonce)?,
      phase: SessionPhase::WaitingReady,
      ready: None,
      admission: None,
      binding: None,
      preparation_nonce: None,
      heartbeat_phase: None,
      last_sender: None,
      started: false,
    })
  }

  pub fn accept(
    &mut self,
    sender: RemoteSessionRole,
    frame: RemoteFrame,
    now_unix_millis: u64,
  ) -> Result<RemoteSessionAcceptance, RemoteSessionError> {
    let mut next_sequencer = self.sequencer.clone();
    match next_sequencer.accept(frame.clone(), now_unix_millis)? {
      SequenceAcceptance::ExactDuplicate => {
        if self.last_sender != Some(sender) {
          return Err(RemoteSessionError::WrongSender);
        }
        return Ok(RemoteSessionAcceptance::ExactDuplicate);
      }
      SequenceAcceptance::Accepted => {}
    }
    if self.phase == SessionPhase::Terminal {
      return Err(RemoteSessionError::Terminal);
    }
    self.accept_message(sender, &frame.message, now_unix_millis)?;
    self.sequencer = next_sequencer;
    self.last_sender = Some(sender);
    Ok(RemoteSessionAcceptance::Accepted)
  }

  #[must_use]
  pub fn disconnect(&self) -> RemoteDisconnectOutcome {
    if self.started {
      RemoteDisconnectOutcome::OutcomeUnknown
    } else {
      RemoteDisconnectOutcome::PreflightNoExecution
    }
  }

  fn accept_message(
    &mut self,
    sender: RemoteSessionRole,
    message: &RemoteMessage,
    now: u64,
  ) -> Result<(), RemoteSessionError> {
    match message {
      RemoteMessage::Ready(ready) => {
        self.require(
          sender,
          RemoteSessionRole::Runner,
          SessionPhase::WaitingReady,
        )?;
        self.ready = Some(ReadyIdentity {
          challenge: ready.challenge.clone(),
          ready_until_unix_millis: ready.ready_until_unix_millis,
          deployment_epoch: ready.deployment_epoch,
          profile_digest: ready.profile_digest.clone(),
          credential_revision: ready.credential_revision.clone(),
        });
        self.phase = SessionPhase::WaitingAdmission;
      }
      RemoteMessage::Admission(admission) => {
        self.require(
          sender,
          RemoteSessionRole::Gateway,
          SessionPhase::WaitingAdmission,
        )?;
        self.validate_admission(admission, now)?;
        self.admission = Some(AdmissionState {
          nonce: admission.admission_nonce.clone(),
          expires_at_unix_millis: admission.expires_at_unix_millis,
          consumed: false,
        });
        self.phase = SessionPhase::WaitingPrepare;
      }
      RemoteMessage::Prepare(prepare) => {
        if sender != RemoteSessionRole::Gateway {
          return Err(RemoteSessionError::WrongSender);
        }
        if self.phase == SessionPhase::WaitingPrepared {
          return Err(RemoteSessionError::AdmissionConsumed);
        }
        if self.phase != SessionPhase::WaitingPrepare {
          return Err(RemoteSessionError::InvalidPhase);
        }
        self.require_live_admission(now, false)?;
        self.validate_binding(&prepare.binding)?;
        self
          .admission
          .as_mut()
          .expect("admission is present")
          .consumed = true;
        self.binding = Some(prepare.binding.clone());
        self.phase = SessionPhase::WaitingPrepared;
      }
      RemoteMessage::Prepared(prepared) => {
        self.require(
          sender,
          RemoteSessionRole::Runner,
          SessionPhase::WaitingPrepared,
        )?;
        self.require_binding(&prepared.binding)?;
        let digest = hex_sha256(prepared.attested_profile_json.as_bytes());
        let profile_digest = &self
          .ready
          .as_ref()
          .expect("ready is present")
          .profile_digest;
        if digest != prepared.attested_profile_digest
          || prepared.attested_profile_digest != *profile_digest
        {
          return Err(RemoteSessionError::AttestedProfileDigestMismatch);
        }
        self.preparation_nonce = Some(prepared.preparation_nonce.clone());
        self.phase = SessionPhase::WaitingStart;
      }
      RemoteMessage::Start(start) => {
        self.require(
          sender,
          RemoteSessionRole::Gateway,
          SessionPhase::WaitingStart,
        )?;
        self.require_live_admission(now, true)?;
        self.require_binding(&start.binding)?;
        self.require_preparation_nonce(&start.preparation_nonce)?;
        self.started = true;
        self.phase = SessionPhase::WaitingResult;
      }
      RemoteMessage::Result(result) => {
        self.require(
          sender,
          RemoteSessionRole::Runner,
          SessionPhase::WaitingResult,
        )?;
        self.require_binding(&result.binding)?;
        self.require_preparation_nonce(&result.preparation_nonce)?;
        self.phase = SessionPhase::Terminal;
      }
      RemoteMessage::Heartbeat(heartbeat) => {
        if sender != RemoteSessionRole::Runner {
          return Err(RemoteSessionError::WrongSender);
        }
        self.require_binding(&heartbeat.binding)?;
        self.accept_heartbeat(heartbeat.phase)?;
      }
      RemoteMessage::Cancel(cancel) => {
        if sender != RemoteSessionRole::Gateway {
          return Err(RemoteSessionError::WrongSender);
        }
        self.require_binding(&cancel.binding)?;
        self.phase = SessionPhase::Terminal;
      }
      RemoteMessage::Error(_) => {
        if sender != RemoteSessionRole::Runner {
          return Err(RemoteSessionError::WrongSender);
        }
        self.phase = SessionPhase::Terminal;
      }
    }
    Ok(())
  }

  fn require(
    &self,
    actual_sender: RemoteSessionRole,
    expected_sender: RemoteSessionRole,
    expected_phase: SessionPhase,
  ) -> Result<(), RemoteSessionError> {
    if actual_sender != expected_sender {
      return Err(RemoteSessionError::WrongSender);
    }
    if self.phase != expected_phase {
      return Err(RemoteSessionError::InvalidPhase);
    }
    Ok(())
  }

  fn validate_admission(
    &self,
    admission: &AdmissionFrame,
    now: u64,
  ) -> Result<(), RemoteSessionError> {
    let ready = self.ready.as_ref().expect("ready is present");
    if admission.challenge != ready.challenge
      || admission.deployment_epoch != ready.deployment_epoch
      || admission.profile_digest != ready.profile_digest
    {
      return Err(RemoteSessionError::SessionIdentityMismatch);
    }
    if ready.ready_until_unix_millis <= now {
      return Err(RemoteSessionError::AdmissionExpired);
    }
    let Some(max_expiry) = now.checked_add(MAX_ADMISSION_TTL_MILLIS) else {
      return Err(RemoteSessionError::AdmissionTtlInvalid);
    };
    if admission.expires_at_unix_millis <= now {
      return Err(RemoteSessionError::AdmissionExpired);
    }
    if admission.expires_at_unix_millis > max_expiry {
      return Err(RemoteSessionError::AdmissionTtlInvalid);
    }
    Ok(())
  }

  fn require_live_admission(
    &self,
    now: u64,
    must_be_consumed: bool,
  ) -> Result<(), RemoteSessionError> {
    let admission = self.admission.as_ref().expect("admission is present");
    debug_assert!(!admission.nonce.is_empty());
    if admission.expires_at_unix_millis <= now {
      return Err(RemoteSessionError::AdmissionExpired);
    }
    if admission.consumed != must_be_consumed {
      return Err(RemoteSessionError::AdmissionConsumed);
    }
    Ok(())
  }

  fn validate_binding(&self, binding: &RunBinding) -> Result<(), RemoteSessionError> {
    let ready = self.ready.as_ref().expect("ready is present");
    if binding.deployment_epoch != ready.deployment_epoch
      || binding.profile_digest != ready.profile_digest
      || binding.credential_revision != ready.credential_revision
    {
      return Err(RemoteSessionError::SessionIdentityMismatch);
    }
    Ok(())
  }

  fn require_binding(&self, binding: &RunBinding) -> Result<(), RemoteSessionError> {
    if self.binding.as_ref() != Some(binding) {
      return Err(RemoteSessionError::RunBindingMismatch);
    }
    Ok(())
  }

  fn require_preparation_nonce(&self, nonce: &str) -> Result<(), RemoteSessionError> {
    if self.preparation_nonce.as_deref() != Some(nonce) {
      return Err(RemoteSessionError::PreparationNonceMismatch);
    }
    Ok(())
  }

  fn accept_heartbeat(&mut self, phase: RemoteHeartbeatPhase) -> Result<(), RemoteSessionError> {
    let maximum = match self.phase {
      SessionPhase::WaitingPrepared => RemoteHeartbeatPhase::Preparing,
      SessionPhase::WaitingStart => RemoteHeartbeatPhase::Prepared,
      SessionPhase::WaitingResult => RemoteHeartbeatPhase::Started,
      _ => return Err(RemoteSessionError::InvalidPhase),
    };
    if heartbeat_rank(phase) > heartbeat_rank(maximum) {
      return Err(RemoteSessionError::HeartbeatAheadOfSession);
    }
    if self
      .heartbeat_phase
      .is_some_and(|previous| heartbeat_rank(phase) < heartbeat_rank(previous))
    {
      return Err(RemoteSessionError::HeartbeatPhaseRegression);
    }
    self.heartbeat_phase = Some(phase);
    Ok(())
  }
}

fn heartbeat_rank(phase: RemoteHeartbeatPhase) -> u8 {
  match phase {
    RemoteHeartbeatPhase::Preparing => 0,
    RemoteHeartbeatPhase::Prepared => 1,
    RemoteHeartbeatPhase::Started => 2,
  }
}

fn hex_sha256(bytes: &[u8]) -> String {
  format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::scheduled_remote_protocol::{
    AdmissionFrame, HeartbeatFrame, PrepareFrame, PreparedFrame, REMOTE_PROTOCOL_VERSION,
    ReadyFrame, RemoteMessage, RemoteResultKind, ResultFrame, StartFrame,
  };

  const NOW: u64 = 1_000_000;

  fn frame(sequence: u64, message: RemoteMessage) -> RemoteFrame {
    RemoteFrame {
      version: REMOTE_PROTOCOL_VERSION,
      session_nonce: "c".repeat(64),
      sequence,
      message,
    }
  }

  fn binding() -> RunBinding {
    RunBinding {
      run_id: "run-1".to_owned(),
      job_id: "job-1".to_owned(),
      attempt: 1,
      fence_token: 7,
      authority_digest: "a".repeat(64),
      profile_digest: profile_digest(),
      deployment_epoch: 9,
      credential_revision: "github-readonly-2026-07".to_owned(),
    }
  }

  fn profile_json() -> String {
    r#"{"profile":"bound"}"#.to_owned()
  }

  fn profile_digest() -> String {
    hex_sha256(profile_json().as_bytes())
  }

  fn ready() -> RemoteMessage {
    RemoteMessage::Ready(ReadyFrame {
      challenge: "d".repeat(64),
      ready_until_unix_millis: NOW + 10_000,
      deployment_epoch: 9,
      profile_digest: profile_digest(),
      gateway_image_digest: format!("sha256:{}", "e".repeat(64)),
      runner_image_digest: format!("sha256:{}", "f".repeat(64)),
      runner_workload_identity: "spiffe://codeoff/runner/production".to_owned(),
      runner_client_cert_public_key_fingerprint: "1".repeat(64),
      credential_revision: "github-readonly-2026-07".to_owned(),
    })
  }

  fn admission(expiry: u64) -> RemoteMessage {
    RemoteMessage::Admission(AdmissionFrame {
      challenge: "d".repeat(64),
      admission_nonce: "2".repeat(64),
      expires_at_unix_millis: expiry,
      deployment_epoch: 9,
      profile_digest: profile_digest(),
    })
  }

  fn prepare(binding: RunBinding) -> RemoteMessage {
    RemoteMessage::Prepare(PrepareFrame {
      binding,
      definition_json: r#"{"prompt":"check"}"#.to_owned(),
      capability_json: r#"{"tools":["github"]}"#.to_owned(),
      targets_json: "[]".to_owned(),
    })
  }

  fn prepared(binding: RunBinding) -> RemoteMessage {
    RemoteMessage::Prepared(PreparedFrame {
      binding,
      preparation_nonce: "3".repeat(64),
      attested_profile_json: profile_json(),
      attested_profile_digest: profile_digest(),
    })
  }

  fn start(binding: RunBinding) -> RemoteMessage {
    RemoteMessage::Start(StartFrame {
      binding,
      preparation_nonce: "3".repeat(64),
    })
  }

  fn session_through_prepare(expiry: u64) -> RemoteSessionState {
    let mut session = RemoteSessionState::new("c".repeat(64)).expect("session");
    session
      .accept(RemoteSessionRole::Runner, frame(1, ready()), NOW)
      .expect("ready");
    session
      .accept(RemoteSessionRole::Gateway, frame(2, admission(expiry)), NOW)
      .expect("admission");
    session
      .accept(
        RemoteSessionRole::Gateway,
        frame(3, prepare(binding())),
        NOW,
      )
      .expect("prepare");
    session
  }

  #[test]
  fn complete_session_is_role_phase_binding_and_digest_bound() {
    let mut session = session_through_prepare(NOW + 5_000);
    session
      .accept(
        RemoteSessionRole::Runner,
        frame(4, prepared(binding())),
        NOW,
      )
      .expect("prepared");
    session
      .accept(RemoteSessionRole::Gateway, frame(5, start(binding())), NOW)
      .expect("start");
    assert_eq!(
      session.disconnect(),
      RemoteDisconnectOutcome::OutcomeUnknown
    );
    let result = frame(
      6,
      RemoteMessage::Result(ResultFrame {
        binding: binding(),
        preparation_nonce: "3".repeat(64),
        kind: RemoteResultKind::Completed,
        result_json: "{}".to_owned(),
      }),
    );
    session
      .accept(RemoteSessionRole::Runner, result.clone(), NOW)
      .expect("result");
    assert_eq!(
      session.accept(RemoteSessionRole::Runner, result, NOW),
      Ok(RemoteSessionAcceptance::ExactDuplicate)
    );
    assert_eq!(
      session.accept(RemoteSessionRole::Runner, frame(7, ready()), NOW),
      Err(RemoteSessionError::Terminal)
    );
  }

  #[test]
  fn wrong_role_and_out_of_order_messages_do_not_advance_the_session() {
    let mut session = RemoteSessionState::new("c".repeat(64)).expect("session");
    assert_eq!(
      session.accept(RemoteSessionRole::Gateway, frame(1, ready()), NOW),
      Err(RemoteSessionError::WrongSender)
    );
    session
      .accept(RemoteSessionRole::Runner, frame(1, ready()), NOW)
      .expect("retry valid ready");
    assert_eq!(
      session.accept(
        RemoteSessionRole::Gateway,
        frame(2, prepare(binding())),
        NOW
      ),
      Err(RemoteSessionError::InvalidPhase)
    );
  }

  #[test]
  fn admission_has_checked_hard_ttl_and_expires_at_prepare_and_start() {
    let mut overflow = RemoteSessionState::new("c".repeat(64)).expect("session");
    overflow
      .accept(RemoteSessionRole::Runner, frame(1, ready()), NOW)
      .expect("ready");
    assert!(matches!(
      overflow.accept(
        RemoteSessionRole::Gateway,
        frame(2, admission(u64::MAX)),
        u64::MAX - 1
      ),
      Err(RemoteSessionError::Protocol(
        RemoteProtocolError::InvalidField("admission.validity")
      ))
    ));

    let mut at_prepare = RemoteSessionState::new("c".repeat(64)).expect("session");
    at_prepare
      .accept(RemoteSessionRole::Runner, frame(1, ready()), NOW)
      .expect("ready");
    at_prepare
      .accept(
        RemoteSessionRole::Gateway,
        frame(2, admission(NOW + 1)),
        NOW,
      )
      .expect("admission");
    assert_eq!(
      at_prepare.accept(
        RemoteSessionRole::Gateway,
        frame(3, prepare(binding())),
        NOW + 1
      ),
      Err(RemoteSessionError::AdmissionExpired)
    );

    let mut at_start = session_through_prepare(NOW + 1);
    at_start
      .accept(
        RemoteSessionRole::Runner,
        frame(4, prepared(binding())),
        NOW,
      )
      .expect("prepared");
    assert_eq!(
      at_start.accept(
        RemoteSessionRole::Gateway,
        frame(5, start(binding())),
        NOW + 1
      ),
      Err(RemoteSessionError::AdmissionExpired)
    );
  }

  #[test]
  fn admission_and_binding_cannot_be_reused_or_changed() {
    let mut session = session_through_prepare(NOW + 5_000);
    assert_eq!(
      session.accept(
        RemoteSessionRole::Gateway,
        frame(4, prepare(binding())),
        NOW
      ),
      Err(RemoteSessionError::AdmissionConsumed)
    );
    let mut changed = binding();
    changed.fence_token += 1;
    assert_eq!(
      session.accept(RemoteSessionRole::Runner, frame(4, prepared(changed)), NOW),
      Err(RemoteSessionError::RunBindingMismatch)
    );
  }

  #[test]
  fn exact_duplicate_is_idempotent_but_conflict_and_sender_change_are_rejected() {
    let mut session = RemoteSessionState::new("c".repeat(64)).expect("session");
    let ready_frame = frame(1, ready());
    session
      .accept(RemoteSessionRole::Runner, ready_frame.clone(), NOW)
      .expect("ready");
    assert_eq!(
      session.accept(RemoteSessionRole::Runner, ready_frame.clone(), NOW),
      Ok(RemoteSessionAcceptance::ExactDuplicate)
    );
    assert_eq!(
      session.accept(RemoteSessionRole::Gateway, ready_frame, NOW),
      Err(RemoteSessionError::WrongSender)
    );
  }

  #[test]
  fn prepared_recomputes_digest_and_heartbeat_phase_is_monotonic() {
    let mut session = session_through_prepare(NOW + 5_000);
    let mut bad = prepared(binding());
    let RemoteMessage::Prepared(payload) = &mut bad else {
      unreachable!()
    };
    payload.attested_profile_json = r#"{"profile":"different"}"#.to_owned();
    assert_eq!(
      session.accept(RemoteSessionRole::Runner, frame(4, bad), NOW),
      Err(RemoteSessionError::AttestedProfileDigestMismatch)
    );
    session
      .accept(
        RemoteSessionRole::Runner,
        frame(
          4,
          RemoteMessage::Heartbeat(HeartbeatFrame {
            binding: binding(),
            phase: RemoteHeartbeatPhase::Preparing,
          }),
        ),
        NOW,
      )
      .expect("preparing heartbeat");
    assert_eq!(
      session.accept(
        RemoteSessionRole::Runner,
        frame(
          5,
          RemoteMessage::Heartbeat(HeartbeatFrame {
            binding: binding(),
            phase: RemoteHeartbeatPhase::Started,
          }),
        ),
        NOW
      ),
      Err(RemoteSessionError::HeartbeatAheadOfSession)
    );
  }

  #[test]
  fn disconnect_before_start_is_explicitly_non_executing() {
    let session = session_through_prepare(NOW + 5_000);
    assert_eq!(
      session.disconnect(),
      RemoteDisconnectOutcome::PreflightNoExecution
    );
  }
}
