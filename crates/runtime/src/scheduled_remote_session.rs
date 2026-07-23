//! Role-aware lifecycle validation for one scheduled remote execution session.

use codeoff_state::ScheduledPrepareAuthority;
use sha2::{Digest, Sha256};

use crate::scheduled_remote_protocol::{
  AdmissionFrame, MAX_ADMISSION_TTL_MILLIS, RemoteFrame, RemoteFrameSequencer,
  RemoteHeartbeatPhase, RemoteMessage, RemoteProtocolError, RemoteResultKind, RunBinding,
  SequenceAcceptance,
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
  AlreadyConclusive(RemoteTerminalDisposition),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteTerminalDisposition {
  Completed,
  FailedBeforeStart,
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
  EvidenceReplay,
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
  effective_expires_at_unix_millis: u64,
  consumed: bool,
}

#[derive(Debug, Clone, Copy)]
struct TerminalState {
  disposition: RemoteTerminalDisposition,
  conclusive_result: bool,
}

#[derive(Debug, Clone)]
pub struct RemoteSessionState {
  gateway_sequencer: RemoteFrameSequencer,
  runner_sequencer: RemoteFrameSequencer,
  expected_authority: ScheduledPrepareAuthority,
  phase: SessionPhase,
  ready: Option<ReadyIdentity>,
  admission: Option<AdmissionState>,
  binding: Option<RunBinding>,
  preparation_nonce: Option<String>,
  heartbeat_phase: Option<RemoteHeartbeatPhase>,
  started: bool,
  terminal: Option<TerminalState>,
}

impl RemoteSessionState {
  pub fn new(
    session_nonce: String,
    expected_authority: ScheduledPrepareAuthority,
  ) -> Result<Self, RemoteSessionError> {
    Ok(Self {
      gateway_sequencer: RemoteFrameSequencer::new(session_nonce.clone())?,
      runner_sequencer: RemoteFrameSequencer::new(session_nonce)?,
      expected_authority,
      phase: SessionPhase::WaitingReady,
      ready: None,
      admission: None,
      binding: None,
      preparation_nonce: None,
      heartbeat_phase: None,
      started: false,
      terminal: None,
    })
  }

  pub fn accept(
    &mut self,
    sender: RemoteSessionRole,
    frame: RemoteFrame,
    now_unix_millis: u64,
  ) -> Result<RemoteSessionAcceptance, RemoteSessionError> {
    let mut next_sequencer = match sender {
      RemoteSessionRole::Gateway => self.gateway_sequencer.clone(),
      RemoteSessionRole::Runner => self.runner_sequencer.clone(),
    };
    match next_sequencer.accept(frame.clone(), now_unix_millis)? {
      SequenceAcceptance::ExactDuplicate => {
        if matches!(
          frame.message,
          RemoteMessage::Prepared(_) | RemoteMessage::Result(_)
        ) {
          return Err(RemoteSessionError::EvidenceReplay);
        }
        return Ok(RemoteSessionAcceptance::ExactDuplicate);
      }
      SequenceAcceptance::Accepted => {}
    }
    if self.phase == SessionPhase::Terminal {
      return Err(RemoteSessionError::Terminal);
    }
    self.accept_message(sender, &frame.message, now_unix_millis)?;
    match sender {
      RemoteSessionRole::Gateway => self.gateway_sequencer = next_sequencer,
      RemoteSessionRole::Runner => self.runner_sequencer = next_sequencer,
    }
    Ok(RemoteSessionAcceptance::Accepted)
  }

  #[must_use]
  pub fn disconnect(&self) -> RemoteDisconnectOutcome {
    if let Some(terminal) = self.terminal.filter(|terminal| terminal.conclusive_result) {
      RemoteDisconnectOutcome::AlreadyConclusive(terminal.disposition)
    } else if self.started {
      RemoteDisconnectOutcome::OutcomeUnknown
    } else {
      RemoteDisconnectOutcome::PreflightNoExecution
    }
  }

  #[must_use]
  pub fn terminal_disposition(&self) -> Option<RemoteTerminalDisposition> {
    self.terminal.map(|terminal| terminal.disposition)
  }

  fn accept_message(
    &mut self,
    sender: RemoteSessionRole,
    message: &RemoteMessage,
    now: u64,
  ) -> Result<(), RemoteSessionError> {
    match message {
      RemoteMessage::ReadinessRequest(_) => {
        return Err(RemoteSessionError::InvalidPhase);
      }
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
        let effective_expiry = self.validate_admission(admission, now)?;
        self.admission = Some(AdmissionState {
          nonce: admission.admission_nonce.clone(),
          effective_expires_at_unix_millis: effective_expiry,
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
        if digest != prepared.attested_profile_digest {
          return Err(RemoteSessionError::AttestedProfileDigestMismatch);
        }
        debug_assert!(!profile_digest.is_empty());
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
        if sender != RemoteSessionRole::Runner {
          return Err(RemoteSessionError::WrongSender);
        }
        let expected_phase = match result.kind {
          RemoteResultKind::FailedBeforeStart => SessionPhase::WaitingStart,
          RemoteResultKind::Completed | RemoteResultKind::OutcomeUnknown => {
            SessionPhase::WaitingResult
          }
        };
        if self.phase != expected_phase {
          return Err(RemoteSessionError::InvalidPhase);
        }
        self.require_binding(&result.binding)?;
        self.require_preparation_nonce(&result.preparation_nonce)?;
        let disposition = match result.kind {
          RemoteResultKind::Completed => RemoteTerminalDisposition::Completed,
          RemoteResultKind::FailedBeforeStart => RemoteTerminalDisposition::FailedBeforeStart,
          RemoteResultKind::OutcomeUnknown => RemoteTerminalDisposition::OutcomeUnknown,
        };
        self.terminal = Some(TerminalState {
          disposition,
          conclusive_result: true,
        });
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
        self.terminal = Some(TerminalState {
          disposition: if self.started {
            RemoteTerminalDisposition::OutcomeUnknown
          } else {
            RemoteTerminalDisposition::FailedBeforeStart
          },
          conclusive_result: false,
        });
        self.phase = SessionPhase::Terminal;
      }
      RemoteMessage::Error(error) => {
        if sender != RemoteSessionRole::Runner {
          return Err(RemoteSessionError::WrongSender);
        }
        self.validate_error_binding(error.binding.as_ref(), error.preparation_nonce.as_deref())?;
        self.terminal = Some(TerminalState {
          disposition: if self.started {
            RemoteTerminalDisposition::OutcomeUnknown
          } else {
            RemoteTerminalDisposition::FailedBeforeStart
          },
          conclusive_result: false,
        });
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
  ) -> Result<u64, RemoteSessionError> {
    let ready = self.ready.as_ref().expect("ready is present");
    if admission.challenge != ready.challenge
      || admission.deployment_epoch != ready.deployment_epoch
      || admission.profile_digest != ready.profile_digest
    {
      return Err(RemoteSessionError::SessionIdentityMismatch);
    }
    let Some(max_expiry) = now.checked_add(MAX_ADMISSION_TTL_MILLIS) else {
      return Err(RemoteSessionError::AdmissionTtlInvalid);
    };
    if ready.ready_until_unix_millis <= now {
      return Err(RemoteSessionError::AdmissionExpired);
    }
    if admission.expires_at_unix_millis <= now {
      return Err(RemoteSessionError::AdmissionExpired);
    }
    Ok(
      ready
        .ready_until_unix_millis
        .min(admission.expires_at_unix_millis)
        .min(max_expiry),
    )
  }

  fn require_live_admission(
    &self,
    now: u64,
    must_be_consumed: bool,
  ) -> Result<(), RemoteSessionError> {
    let admission = self.admission.as_ref().expect("admission is present");
    debug_assert!(!admission.nonce.is_empty());
    if admission.effective_expires_at_unix_millis <= now {
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
    if !self.expected_authority.matches_remote_binding(
      &binding.run_id,
      &binding.job_id,
      binding.attempt,
      binding.fence_token,
      &binding.authority_digest,
    ) {
      return Err(RemoteSessionError::RunBindingMismatch);
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

  fn validate_error_binding(
    &self,
    binding: Option<&RunBinding>,
    preparation_nonce: Option<&str>,
  ) -> Result<(), RemoteSessionError> {
    match (&self.binding, binding) {
      (None, None) => {}
      (Some(expected), Some(actual)) if expected == actual => {}
      _ => return Err(RemoteSessionError::RunBindingMismatch),
    }
    match (self.preparation_nonce.as_deref(), preparation_nonce) {
      (None, None) => Ok(()),
      (Some(expected), Some(actual)) if expected == actual => Ok(()),
      _ => Err(RemoteSessionError::PreparationNonceMismatch),
    }
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
    AdmissionFrame, CancelFrame, ErrorFrame, HeartbeatFrame, PrepareFrame, PreparedFrame,
    REMOTE_PROTOCOL_VERSION, ReadyFrame, RemoteMessage, RemoteResultKind, ResultFrame, StartFrame,
  };
  use codeoff_core::AttestedCapabilityProfile;
  use std::collections::BTreeSet;

  const NOW: u64 = 1_000_000;

  fn authority() -> ScheduledPrepareAuthority {
    ScheduledPrepareAuthority::for_remote_session_test("run-1", "job-1", 1, 7)
  }

  fn session() -> RemoteSessionState {
    RemoteSessionState::new("c".repeat(64), authority()).expect("session")
  }

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
      authority_digest: authority().digest().to_owned(),
      profile_digest: profile_digest(),
      deployment_epoch: 9,
      credential_revision: "github-readonly-2026-07".to_owned(),
    }
  }

  fn capability_profile_json() -> String {
    let mut profile = AttestedCapabilityProfile {
      codex_version: "test-codex".to_owned(),
      app_server_schema_sha256: "1".repeat(64),
      codex_program_sha256: "2".repeat(64),
      github_mcp_version: "test-mcp".to_owned(),
      github_mcp_configured_artifact_sha256: "4".repeat(64),
      github_mcp_configured_endpoint_identity: "test-github-mcp".to_owned(),
      github_mcp_access_auth_mode: "bearer-token-env-v1".to_owned(),
      github_mcp_access_token_revision: "mcp-channel-v1".to_owned(),
      github_mcp_health_checked_at_unix_seconds: 100,
      github_mcp_health_credential_revision: "credential-v1".to_owned(),
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
      .collect::<BTreeSet<_>>(),
      credential_reference: "test-read-only-credential".to_owned(),
      permission_policy_revision: "test-read-only-v1".to_owned(),
      config_revision: "test-config-v1".to_owned(),
      config_sha256: "3".repeat(64),
      gateway_image_digest: format!("sha256:{}", "5".repeat(64)),
      runner_image_digest: format!("sha256:{}", "6".repeat(64)),
      runner_workload_identity: "spiffe://codeoff/runner/test".to_owned(),
      runner_client_cert_public_key_fingerprint: "7".repeat(64),
      credential_revision: "credential-v1".to_owned(),
      credential_isolation_revision: "test-isolation-v1".to_owned(),
      credential_deny_policy_revision: "test-deny-v1".to_owned(),
      negative_test_revision: "test-negative-v1".to_owned(),
      output_schema_revision: "test-output-v1".to_owned(),
      attested_at_unix_seconds: 100,
      profile_sha256: String::new(),
    };
    profile.profile_sha256 = profile.computed_profile_sha256();
    profile.canonical_json()
  }

  fn profile_digest() -> String {
    "b".repeat(64)
  }

  fn ready() -> RemoteMessage {
    ready_until(NOW + 10_000)
  }

  fn ready_until(expiry: u64) -> RemoteMessage {
    RemoteMessage::Ready(ReadyFrame {
      signed_evidence_json: "{}".to_owned(),
      challenge: "d".repeat(64),
      ready_until_unix_millis: expiry,
      attested_profile_json: capability_profile_json(),
      attested_profile_digest: "a".repeat(64),
      deployment_epoch: 9,
      profile_digest: profile_digest(),
      gateway_image_digest: format!("sha256:{}", "e".repeat(64)),
      runner_image_digest: format!("sha256:{}", "f".repeat(64)),
      runner_workload_identity: "spiffe://codeoff/runner/production".to_owned(),
      runner_client_cert_public_key_fingerprint: "1".repeat(64),
      credential_revision: "github-readonly-2026-07".to_owned(),
      github_mcp_access_auth_mode: "bearer-token-env-v1".to_owned(),
      github_mcp_access_token_revision: "mcp-channel-v1".to_owned(),
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
      isolation_permit_envelope_json: r#"{"schema_version":1}"#.to_owned(),
      task_json: r#"{"instruction":"check"}"#.to_owned(),
      definition_json: r#"{"prompt":"check"}"#.to_owned(),
      capability_json: r#"{"tools":["github"]}"#.to_owned(),
      targets_json: "[]".to_owned(),
    })
  }

  fn prepared(binding: RunBinding) -> RemoteMessage {
    let attested_profile_json = authority()
      .remote_recovery_attestation_json(&capability_profile_json(), &profile_digest(), 9)
      .expect("remote recovery attestation");
    RemoteMessage::Prepared(PreparedFrame {
      signed_evidence_json: "{}".to_owned(),
      binding,
      preparation_nonce: "3".repeat(64),
      attested_profile_digest: hex_sha256(attested_profile_json.as_bytes()),
      attested_profile_json,
      github_mcp_access_auth_mode: "bearer-token-env-v1".to_owned(),
      github_mcp_access_token_revision: "mcp-channel-v1".to_owned(),
    })
  }

  fn start(binding: RunBinding) -> RemoteMessage {
    RemoteMessage::Start(StartFrame {
      binding,
      preparation_nonce: "3".repeat(64),
    })
  }

  fn session_through_prepare(expiry: u64) -> RemoteSessionState {
    let mut session = session();
    session
      .accept(RemoteSessionRole::Runner, frame(1, ready()), NOW)
      .expect("ready");
    session
      .accept(RemoteSessionRole::Gateway, frame(1, admission(expiry)), NOW)
      .expect("admission");
    session
      .accept(
        RemoteSessionRole::Gateway,
        frame(2, prepare(binding())),
        NOW,
      )
      .expect("prepare");
    session
  }

  fn session_through_prepared(expiry: u64) -> RemoteSessionState {
    let mut session = session_through_prepare(expiry);
    session
      .accept(
        RemoteSessionRole::Runner,
        frame(2, prepared(binding())),
        NOW,
      )
      .expect("prepared");
    session
  }

  fn session_through_start(expiry: u64) -> RemoteSessionState {
    let mut session = session_through_prepared(expiry);
    session
      .accept(RemoteSessionRole::Gateway, frame(3, start(binding())), NOW)
      .expect("start");
    session
  }

  fn error(binding: Option<RunBinding>, preparation_nonce: Option<String>) -> RemoteMessage {
    RemoteMessage::Error(ErrorFrame {
      binding,
      preparation_nonce,
      code: "runner_unavailable".to_owned(),
      message: "runner slot unavailable".to_owned(),
      retryable: true,
    })
  }

  #[test]
  fn complete_session_is_role_phase_binding_and_digest_bound() {
    let mut session = session_through_prepare(NOW + 5_000);
    session
      .accept(
        RemoteSessionRole::Runner,
        frame(2, prepared(binding())),
        NOW,
      )
      .expect("prepared");
    session
      .accept(RemoteSessionRole::Gateway, frame(3, start(binding())), NOW)
      .expect("start");
    assert_eq!(
      session.disconnect(),
      RemoteDisconnectOutcome::OutcomeUnknown
    );
    let result = frame(
      3,
      RemoteMessage::Result(ResultFrame {
        signed_evidence_json: "{}".to_owned(),
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
      session.disconnect(),
      RemoteDisconnectOutcome::AlreadyConclusive(RemoteTerminalDisposition::Completed)
    );
    assert_eq!(
      session.accept(RemoteSessionRole::Runner, result, NOW),
      Err(RemoteSessionError::EvidenceReplay)
    );
    assert_eq!(
      session.accept(RemoteSessionRole::Runner, frame(4, ready()), NOW),
      Err(RemoteSessionError::Terminal)
    );
  }

  #[test]
  fn wrong_role_and_out_of_order_messages_do_not_advance_the_session() {
    let mut session = session();
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
        frame(1, prepare(binding())),
        NOW
      ),
      Err(RemoteSessionError::InvalidPhase)
    );
  }

  #[test]
  fn admission_has_checked_hard_ttl_and_expires_at_prepare_and_start() {
    let mut overflow = session();
    overflow
      .accept(RemoteSessionRole::Runner, frame(1, ready()), NOW)
      .expect("ready");
    assert!(matches!(
      overflow.accept(
        RemoteSessionRole::Gateway,
        frame(1, admission(u64::MAX)),
        u64::MAX - 1
      ),
      Err(RemoteSessionError::AdmissionTtlInvalid)
    ));

    let mut at_prepare = session();
    at_prepare
      .accept(RemoteSessionRole::Runner, frame(1, ready()), NOW)
      .expect("ready");
    at_prepare
      .accept(
        RemoteSessionRole::Gateway,
        frame(1, admission(NOW + 1)),
        NOW,
      )
      .expect("admission");
    assert_eq!(
      at_prepare.accept(
        RemoteSessionRole::Gateway,
        frame(2, prepare(binding())),
        NOW + 1
      ),
      Err(RemoteSessionError::AdmissionExpired)
    );

    let mut at_start = session_through_prepare(NOW + 1);
    at_start
      .accept(
        RemoteSessionRole::Runner,
        frame(2, prepared(binding())),
        NOW,
      )
      .expect("prepared");
    assert_eq!(
      at_start.accept(
        RemoteSessionRole::Gateway,
        frame(3, start(binding())),
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
        frame(3, prepare(binding())),
        NOW
      ),
      Err(RemoteSessionError::AdmissionConsumed)
    );
    let mut changed = binding();
    changed.fence_token += 1;
    assert_eq!(
      session.accept(RemoteSessionRole::Runner, frame(2, prepared(changed)), NOW),
      Err(RemoteSessionError::RunBindingMismatch)
    );
  }

  #[test]
  fn exact_duplicate_is_idempotent_but_conflict_and_sender_change_are_rejected() {
    let mut session = session();
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
      session.accept(RemoteSessionRole::Runner, frame(2, bad), NOW),
      Err(RemoteSessionError::AttestedProfileDigestMismatch)
    );
    session
      .accept(
        RemoteSessionRole::Runner,
        frame(
          2,
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
          3,
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

  #[test]
  fn prepared_requires_the_exact_runner_capability_payload_digest() {
    let mut session = session_through_prepare(NOW + 5_000);
    let valid = prepared(binding());
    let RemoteMessage::Prepared(valid_payload) = &valid else {
      unreachable!()
    };
    assert_ne!(valid_payload.attested_profile_digest, profile_digest());
    session
      .accept(RemoteSessionRole::Runner, frame(2, valid), NOW)
      .expect("runner capability payload");

    let mut old_false_fixture = session_through_prepare(NOW + 5_000);
    let mut false_prepared = prepared(binding());
    let RemoteMessage::Prepared(payload) = &mut false_prepared else {
      unreachable!()
    };
    payload.attested_profile_digest = profile_digest();
    assert_eq!(
      old_false_fixture.accept(RemoteSessionRole::Runner, frame(2, false_prepared), NOW),
      Err(RemoteSessionError::AttestedProfileDigestMismatch)
    );
  }

  #[test]
  fn effective_admission_expiry_is_the_shortest_ready_requested_or_hard_cap() {
    for (ready_expiry, admission_expiry, effective_expiry) in [
      (NOW + 5, NOW + 20, NOW + 5),
      (NOW + 20, NOW + 5, NOW + 5),
      (
        NOW + MAX_ADMISSION_TTL_MILLIS,
        u64::MAX,
        NOW + MAX_ADMISSION_TTL_MILLIS,
      ),
    ] {
      let mut at_boundary = session();
      at_boundary
        .accept(
          RemoteSessionRole::Runner,
          frame(1, ready_until(ready_expiry)),
          NOW,
        )
        .expect("ready");
      at_boundary
        .accept(
          RemoteSessionRole::Gateway,
          frame(1, admission(admission_expiry)),
          NOW,
        )
        .expect("admission");
      assert_eq!(
        at_boundary.accept(
          RemoteSessionRole::Gateway,
          frame(2, prepare(binding())),
          effective_expiry
        ),
        Err(RemoteSessionError::AdmissionExpired)
      );

      let mut before_boundary = session();
      before_boundary
        .accept(
          RemoteSessionRole::Runner,
          frame(1, ready_until(ready_expiry)),
          NOW,
        )
        .expect("ready");
      before_boundary
        .accept(
          RemoteSessionRole::Gateway,
          frame(1, admission(admission_expiry)),
          NOW,
        )
        .expect("admission");
      before_boundary
        .accept(
          RemoteSessionRole::Gateway,
          frame(2, prepare(binding())),
          effective_expiry - 1,
        )
        .expect("valid immediately before effective expiry");
    }

    let mut exact_now = session();
    exact_now
      .accept(RemoteSessionRole::Runner, frame(1, ready()), NOW)
      .expect("ready");
    assert!(
      exact_now
        .accept(RemoteSessionRole::Gateway, frame(1, admission(NOW)), NOW)
        .is_err()
    );
  }

  #[test]
  fn every_result_kind_is_terminal_and_disconnect_is_already_conclusive() {
    for (kind, expected, started) in [
      (
        RemoteResultKind::FailedBeforeStart,
        RemoteTerminalDisposition::FailedBeforeStart,
        false,
      ),
      (
        RemoteResultKind::Completed,
        RemoteTerminalDisposition::Completed,
        true,
      ),
      (
        RemoteResultKind::OutcomeUnknown,
        RemoteTerminalDisposition::OutcomeUnknown,
        true,
      ),
    ] {
      let mut session = if started {
        session_through_start(NOW + 5_000)
      } else {
        session_through_prepared(NOW + 5_000)
      };
      session
        .accept(
          RemoteSessionRole::Runner,
          frame(
            3,
            RemoteMessage::Result(ResultFrame {
              signed_evidence_json: "{}".to_owned(),
              binding: binding(),
              preparation_nonce: "3".repeat(64),
              kind,
              result_json: "{}".to_owned(),
            }),
          ),
          NOW,
        )
        .expect("typed result");
      assert_eq!(session.terminal_disposition(), Some(expected));
      assert_eq!(
        session.disconnect(),
        RemoteDisconnectOutcome::AlreadyConclusive(expected)
      );
    }
  }

  #[test]
  fn error_and_cancel_are_exactly_bound_and_typed_before_and_after_start() {
    let mut early_error = session();
    early_error
      .accept(RemoteSessionRole::Runner, frame(1, error(None, None)), NOW)
      .expect("preflight error");
    assert_eq!(
      early_error.terminal_disposition(),
      Some(RemoteTerminalDisposition::FailedBeforeStart)
    );
    assert_eq!(
      early_error.disconnect(),
      RemoteDisconnectOutcome::PreflightNoExecution
    );

    let mut prestart_cancel = session_through_prepared(NOW + 5_000);
    prestart_cancel
      .accept(
        RemoteSessionRole::Gateway,
        frame(
          3,
          RemoteMessage::Cancel(CancelFrame {
            binding: binding(),
            reason: "operator_cancelled".to_owned(),
          }),
        ),
        NOW,
      )
      .expect("pre-start cancel");
    assert_eq!(
      prestart_cancel.terminal_disposition(),
      Some(RemoteTerminalDisposition::FailedBeforeStart)
    );

    let mut poststart_error = session_through_start(NOW + 5_000);
    assert_eq!(
      poststart_error.accept(RemoteSessionRole::Runner, frame(3, error(None, None)), NOW),
      Err(RemoteSessionError::RunBindingMismatch)
    );
    poststart_error
      .accept(
        RemoteSessionRole::Runner,
        frame(3, error(Some(binding()), Some("3".repeat(64)))),
        NOW,
      )
      .expect("bound post-start error");
    assert_eq!(
      poststart_error.terminal_disposition(),
      Some(RemoteTerminalDisposition::OutcomeUnknown)
    );
    assert_eq!(
      poststart_error.disconnect(),
      RemoteDisconnectOutcome::OutcomeUnknown
    );

    let mut poststart_cancel = session_through_start(NOW + 5_000);
    poststart_cancel
      .accept(
        RemoteSessionRole::Gateway,
        frame(
          4,
          RemoteMessage::Cancel(CancelFrame {
            binding: binding(),
            reason: "lease_lost".to_owned(),
          }),
        ),
        NOW,
      )
      .expect("bound post-start cancel");
    assert_eq!(
      poststart_cancel.terminal_disposition(),
      Some(RemoteTerminalDisposition::OutcomeUnknown)
    );
    assert_eq!(
      poststart_cancel.disconnect(),
      RemoteDisconnectOutcome::OutcomeUnknown
    );
  }

  #[test]
  fn role_sequences_are_independent_and_terminal_interleavings_fail_closed() {
    let mut session = session_through_prepare(NOW + 5_000);
    session
      .accept(
        RemoteSessionRole::Runner,
        frame(
          2,
          RemoteMessage::Heartbeat(HeartbeatFrame {
            binding: binding(),
            phase: RemoteHeartbeatPhase::Preparing,
          }),
        ),
        NOW,
      )
      .expect("runner sequence two after gateway sequence two");
    session
      .accept(
        RemoteSessionRole::Gateway,
        frame(
          3,
          RemoteMessage::Cancel(CancelFrame {
            binding: binding(),
            reason: "lease_lost".to_owned(),
          }),
        ),
        NOW,
      )
      .expect("gateway cancel interleaves after runner heartbeat");
    assert_eq!(
      session.accept(
        RemoteSessionRole::Runner,
        frame(3, error(Some(binding()), None)),
        NOW
      ),
      Err(RemoteSessionError::Terminal)
    );

    let mut result_first = session_through_start(NOW + 5_000);
    result_first
      .accept(
        RemoteSessionRole::Runner,
        frame(
          3,
          RemoteMessage::Result(ResultFrame {
            signed_evidence_json: "{}".to_owned(),
            binding: binding(),
            preparation_nonce: "3".repeat(64),
            kind: RemoteResultKind::Completed,
            result_json: "{}".to_owned(),
          }),
        ),
        NOW,
      )
      .expect("result wins");
    assert_eq!(
      result_first.accept(
        RemoteSessionRole::Gateway,
        frame(
          4,
          RemoteMessage::Cancel(CancelFrame {
            binding: binding(),
            reason: "late_cancel".to_owned(),
          }),
        ),
        NOW
      ),
      Err(RemoteSessionError::Terminal)
    );
  }
}
