//! Versioned, bounded protocol shared by the gateway scheduler and remote runner control plane.
//!
//! Durable state and claim authority remain gateway-owned. These frames only coordinate a
//! challenge-bound runner session and a single prepared execution. A disconnect after `START`
//! is represented as `outcome_unknown`; it is never promoted to an exactly-once guarantee.

use std::fmt;

use codeoff_core::{CredentialRevision, CriticalId, RunnerWorkloadIdentity};
use serde_json::{Map, Value, json};

pub const REMOTE_PROTOCOL_VERSION: u64 = 1;
pub const MAX_REMOTE_FRAME_BYTES: usize = 64 * 1024;
pub const MAX_READY_TTL_MILLIS: u64 = 30_000;
pub const MAX_ADMISSION_TTL_MILLIS: u64 = 30_000;

const MAX_JSON_FIELD_BYTES: usize = 32 * 1024;
const MAX_ERROR_BYTES: usize = 2 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteFrame {
  pub version: u64,
  pub session_nonce: String,
  pub sequence: u64,
  pub message: RemoteMessage,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteMessage {
  ReadinessRequest(ReadinessRequestFrame),
  Ready(ReadyFrame),
  Admission(AdmissionFrame),
  Prepare(PrepareFrame),
  Prepared(PreparedFrame),
  Start(StartFrame),
  Result(ResultFrame),
  Cancel(CancelFrame),
  Heartbeat(HeartbeatFrame),
  Error(ErrorFrame),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadinessRequestFrame {
  pub challenge: String,
  pub ready_until_unix_millis: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadyFrame {
  pub challenge: String,
  pub ready_until_unix_millis: u64,
  pub attested_profile_json: String,
  pub attested_profile_digest: String,
  pub deployment_epoch: u64,
  pub profile_digest: String,
  pub gateway_image_digest: String,
  pub runner_image_digest: String,
  pub runner_workload_identity: String,
  pub runner_client_cert_public_key_fingerprint: String,
  pub credential_revision: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionFrame {
  pub challenge: String,
  pub admission_nonce: String,
  pub expires_at_unix_millis: u64,
  pub deployment_epoch: u64,
  pub profile_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunBinding {
  pub run_id: String,
  pub job_id: String,
  pub attempt: u32,
  pub fence_token: u64,
  pub authority_digest: String,
  pub profile_digest: String,
  pub deployment_epoch: u64,
  pub credential_revision: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrepareFrame {
  pub binding: RunBinding,
  pub isolation_permit_envelope_json: String,
  pub task_json: String,
  pub definition_json: String,
  pub capability_json: String,
  pub targets_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedFrame {
  pub binding: RunBinding,
  pub preparation_nonce: String,
  pub attested_profile_json: String,
  pub attested_profile_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartFrame {
  pub binding: RunBinding,
  pub preparation_nonce: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteResultKind {
  Completed,
  FailedBeforeStart,
  OutcomeUnknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResultFrame {
  pub binding: RunBinding,
  pub preparation_nonce: String,
  pub kind: RemoteResultKind,
  pub result_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CancelFrame {
  pub binding: RunBinding,
  pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteHeartbeatPhase {
  Preparing,
  Prepared,
  Started,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeartbeatFrame {
  pub binding: RunBinding,
  pub phase: RemoteHeartbeatPhase,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorFrame {
  pub binding: Option<RunBinding>,
  pub preparation_nonce: Option<String>,
  pub code: String,
  pub message: String,
  pub retryable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteProtocolError {
  FrameTooLarge,
  InvalidJson,
  NonCanonicalJson,
  InvalidShape(&'static str),
  InvalidField(&'static str),
  VersionMismatch,
  SessionMismatch,
  SequenceStartsAfterOne,
  SequenceGap,
  SequenceReplay,
  SequenceConflict,
}

impl fmt::Display for RemoteProtocolError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(formatter, "{self:?}")
  }
}

impl std::error::Error for RemoteProtocolError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SequenceAcceptance {
  Accepted,
  ExactDuplicate,
}

#[derive(Debug, Clone)]
pub struct RemoteFrameSequencer {
  session_nonce: String,
  last: Option<RemoteFrame>,
}

impl RemoteFrameSequencer {
  pub fn new(session_nonce: String) -> Result<Self, RemoteProtocolError> {
    require_hex("session_nonce", &session_nonce, 64)?;
    Ok(Self {
      session_nonce,
      last: None,
    })
  }

  pub fn accept(
    &mut self,
    frame: RemoteFrame,
    now_unix_millis: u64,
  ) -> Result<SequenceAcceptance, RemoteProtocolError> {
    frame.validate_at(now_unix_millis)?;
    if frame.session_nonce != self.session_nonce {
      return Err(RemoteProtocolError::SessionMismatch);
    }
    let Some(last) = &self.last else {
      if frame.sequence != 1 {
        return Err(RemoteProtocolError::SequenceStartsAfterOne);
      }
      self.last = Some(frame);
      return Ok(SequenceAcceptance::Accepted);
    };
    if frame.sequence == last.sequence {
      return if &frame == last {
        Ok(SequenceAcceptance::ExactDuplicate)
      } else {
        Err(RemoteProtocolError::SequenceConflict)
      };
    }
    if frame.sequence < last.sequence {
      return Err(RemoteProtocolError::SequenceReplay);
    }
    if frame.sequence != last.sequence.saturating_add(1) {
      return Err(RemoteProtocolError::SequenceGap);
    }
    self.last = Some(frame);
    Ok(SequenceAcceptance::Accepted)
  }
}

impl RemoteFrame {
  pub fn encode(&self) -> Result<Vec<u8>, RemoteProtocolError> {
    self.validate_at(0)?;
    let encoded =
      serde_json::to_vec(&self.to_value()).map_err(|_| RemoteProtocolError::InvalidJson)?;
    if encoded.len() > MAX_REMOTE_FRAME_BYTES {
      return Err(RemoteProtocolError::FrameTooLarge);
    }
    Ok(encoded)
  }

  pub fn decode(bytes: &[u8], now_unix_millis: u64) -> Result<Self, RemoteProtocolError> {
    if bytes.len() > MAX_REMOTE_FRAME_BYTES {
      return Err(RemoteProtocolError::FrameTooLarge);
    }
    let value: Value =
      serde_json::from_slice(bytes).map_err(|_| RemoteProtocolError::InvalidJson)?;
    let object = exact_object(
      &value,
      &["version", "session_nonce", "sequence", "message"],
      "frame",
    )?;
    let frame = Self {
      version: required_u64(object, "version")?,
      session_nonce: required_string(object, "session_nonce")?,
      sequence: required_u64(object, "sequence")?,
      message: RemoteMessage::from_value(required(object, "message")?)?,
    };
    frame.validate_at(now_unix_millis)?;
    if frame.encode()?.as_slice() != bytes {
      return Err(RemoteProtocolError::NonCanonicalJson);
    }
    Ok(frame)
  }

  fn validate_at(&self, now_unix_millis: u64) -> Result<(), RemoteProtocolError> {
    if self.version != REMOTE_PROTOCOL_VERSION {
      return Err(RemoteProtocolError::VersionMismatch);
    }
    require_hex("session_nonce", &self.session_nonce, 64)?;
    if self.sequence == 0 {
      return Err(RemoteProtocolError::InvalidField("sequence"));
    }
    self.message.validate_at(now_unix_millis)
  }

  fn to_value(&self) -> Value {
    json!({
      "version": self.version,
      "session_nonce": self.session_nonce,
      "sequence": self.sequence,
      "message": self.message.to_value(),
    })
  }
}

impl RemoteMessage {
  fn validate_at(&self, now: u64) -> Result<(), RemoteProtocolError> {
    match self {
      Self::ReadinessRequest(request) => request.validate_at(now),
      Self::Ready(ready) => ready.validate_at(now),
      Self::Admission(admission) => admission.validate_at(now),
      Self::Prepare(prepare) => prepare.validate(),
      Self::Prepared(prepared) => prepared.validate(),
      Self::Start(start) => start.validate(),
      Self::Result(result) => result.validate(),
      Self::Cancel(cancel) => cancel.validate(),
      Self::Heartbeat(heartbeat) => heartbeat.binding.validate(),
      Self::Error(error) => error.validate(),
    }
  }

  fn to_value(&self) -> Value {
    let (kind, payload) = match self {
      Self::ReadinessRequest(value) => ("readiness_request", value.to_value()),
      Self::Ready(value) => ("ready", value.to_value()),
      Self::Admission(value) => ("admission", value.to_value()),
      Self::Prepare(value) => ("prepare", value.to_value()),
      Self::Prepared(value) => ("prepared", value.to_value()),
      Self::Start(value) => ("start", value.to_value()),
      Self::Result(value) => ("result", value.to_value()),
      Self::Cancel(value) => ("cancel", value.to_value()),
      Self::Heartbeat(value) => ("heartbeat", value.to_value()),
      Self::Error(value) => ("error", value.to_value()),
    };
    json!({"kind": kind, "payload": payload})
  }

  fn from_value(value: &Value) -> Result<Self, RemoteProtocolError> {
    let object = exact_object(value, &["kind", "payload"], "message")?;
    let kind = required_str(object, "kind")?;
    let payload = required(object, "payload")?;
    match kind {
      "readiness_request" => Ok(Self::ReadinessRequest(ReadinessRequestFrame::from_value(
        payload,
      )?)),
      "ready" => Ok(Self::Ready(ReadyFrame::from_value(payload)?)),
      "admission" => Ok(Self::Admission(AdmissionFrame::from_value(payload)?)),
      "prepare" => Ok(Self::Prepare(PrepareFrame::from_value(payload)?)),
      "prepared" => Ok(Self::Prepared(PreparedFrame::from_value(payload)?)),
      "start" => Ok(Self::Start(StartFrame::from_value(payload)?)),
      "result" => Ok(Self::Result(ResultFrame::from_value(payload)?)),
      "cancel" => Ok(Self::Cancel(CancelFrame::from_value(payload)?)),
      "heartbeat" => Ok(Self::Heartbeat(HeartbeatFrame::from_value(payload)?)),
      "error" => Ok(Self::Error(ErrorFrame::from_value(payload)?)),
      _ => Err(RemoteProtocolError::InvalidField("message.kind")),
    }
  }
}

impl ReadinessRequestFrame {
  fn validate_at(&self, now: u64) -> Result<(), RemoteProtocolError> {
    require_hex("readiness_request.challenge", &self.challenge, 64)?;
    if now != 0
      && (self.ready_until_unix_millis <= now
        || self.ready_until_unix_millis.saturating_sub(now) > MAX_READY_TTL_MILLIS)
    {
      return Err(RemoteProtocolError::InvalidField(
        "readiness_request.validity",
      ));
    }
    Ok(())
  }

  fn to_value(&self) -> Value {
    json!({
      "challenge": self.challenge,
      "ready_until_unix_millis": self.ready_until_unix_millis,
    })
  }

  fn from_value(value: &Value) -> Result<Self, RemoteProtocolError> {
    let object = exact_object(
      value,
      &["challenge", "ready_until_unix_millis"],
      "readiness_request",
    )?;
    Ok(Self {
      challenge: required_string(object, "challenge")?,
      ready_until_unix_millis: required_u64(object, "ready_until_unix_millis")?,
    })
  }
}

impl ReadyFrame {
  fn validate_at(&self, now: u64) -> Result<(), RemoteProtocolError> {
    require_hex("ready.challenge", &self.challenge, 64)?;
    require_json_field("ready.attested_profile_json", &self.attested_profile_json)?;
    require_hex(
      "ready.attested_profile_digest",
      &self.attested_profile_digest,
      64,
    )?;
    require_hex("ready.profile_digest", &self.profile_digest, 64)?;
    require_image_digest("ready.gateway_image_digest", &self.gateway_image_digest)?;
    require_image_digest("ready.runner_image_digest", &self.runner_image_digest)?;
    RunnerWorkloadIdentity::parse(&self.runner_workload_identity)
      .map_err(|_| RemoteProtocolError::InvalidField("ready.runner_workload_identity"))?;
    require_hex(
      "ready.runner_client_cert_public_key_fingerprint",
      &self.runner_client_cert_public_key_fingerprint,
      64,
    )?;
    require_credential_revision("ready.credential_revision", &self.credential_revision)?;
    if self.deployment_epoch == 0
      || (now != 0
        && (self.ready_until_unix_millis <= now
          || self.ready_until_unix_millis.saturating_sub(now) > MAX_READY_TTL_MILLIS))
    {
      return Err(RemoteProtocolError::InvalidField("ready.validity"));
    }
    Ok(())
  }

  fn to_value(&self) -> Value {
    json!({
      "challenge": self.challenge,
      "ready_until_unix_millis": self.ready_until_unix_millis,
      "attested_profile_json": self.attested_profile_json,
      "attested_profile_digest": self.attested_profile_digest,
      "deployment_epoch": self.deployment_epoch,
      "profile_digest": self.profile_digest,
      "gateway_image_digest": self.gateway_image_digest,
      "runner_image_digest": self.runner_image_digest,
      "runner_workload_identity": self.runner_workload_identity,
      "runner_client_cert_public_key_fingerprint": self.runner_client_cert_public_key_fingerprint,
      "credential_revision": self.credential_revision,
    })
  }

  fn from_value(value: &Value) -> Result<Self, RemoteProtocolError> {
    let object = exact_object(
      value,
      &[
        "challenge",
        "ready_until_unix_millis",
        "attested_profile_json",
        "attested_profile_digest",
        "deployment_epoch",
        "profile_digest",
        "gateway_image_digest",
        "runner_image_digest",
        "runner_workload_identity",
        "runner_client_cert_public_key_fingerprint",
        "credential_revision",
      ],
      "ready",
    )?;
    Ok(Self {
      challenge: required_string(object, "challenge")?,
      ready_until_unix_millis: required_u64(object, "ready_until_unix_millis")?,
      attested_profile_json: required_string(object, "attested_profile_json")?,
      attested_profile_digest: required_string(object, "attested_profile_digest")?,
      deployment_epoch: required_u64(object, "deployment_epoch")?,
      profile_digest: required_string(object, "profile_digest")?,
      gateway_image_digest: required_string(object, "gateway_image_digest")?,
      runner_image_digest: required_string(object, "runner_image_digest")?,
      runner_workload_identity: required_string(object, "runner_workload_identity")?,
      runner_client_cert_public_key_fingerprint: required_string(
        object,
        "runner_client_cert_public_key_fingerprint",
      )?,
      credential_revision: required_string(object, "credential_revision")?,
    })
  }
}

impl AdmissionFrame {
  fn validate_at(&self, now: u64) -> Result<(), RemoteProtocolError> {
    require_hex("admission.challenge", &self.challenge, 64)?;
    require_hex("admission.admission_nonce", &self.admission_nonce, 64)?;
    require_hex("admission.profile_digest", &self.profile_digest, 64)?;
    if self.deployment_epoch == 0 || (now != 0 && self.expires_at_unix_millis <= now) {
      return Err(RemoteProtocolError::InvalidField("admission.validity"));
    }
    Ok(())
  }

  fn to_value(&self) -> Value {
    json!({
      "challenge": self.challenge,
      "admission_nonce": self.admission_nonce,
      "expires_at_unix_millis": self.expires_at_unix_millis,
      "deployment_epoch": self.deployment_epoch,
      "profile_digest": self.profile_digest,
    })
  }

  fn from_value(value: &Value) -> Result<Self, RemoteProtocolError> {
    let object = exact_object(
      value,
      &[
        "challenge",
        "admission_nonce",
        "expires_at_unix_millis",
        "deployment_epoch",
        "profile_digest",
      ],
      "admission",
    )?;
    Ok(Self {
      challenge: required_string(object, "challenge")?,
      admission_nonce: required_string(object, "admission_nonce")?,
      expires_at_unix_millis: required_u64(object, "expires_at_unix_millis")?,
      deployment_epoch: required_u64(object, "deployment_epoch")?,
      profile_digest: required_string(object, "profile_digest")?,
    })
  }
}

impl RunBinding {
  fn validate(&self) -> Result<(), RemoteProtocolError> {
    require_critical_id("binding.run_id", &self.run_id)?;
    require_critical_id("binding.job_id", &self.job_id)?;
    require_hex("binding.authority_digest", &self.authority_digest, 64)?;
    require_hex("binding.profile_digest", &self.profile_digest, 64)?;
    require_credential_revision("binding.credential_revision", &self.credential_revision)?;
    if self.attempt == 0 || self.fence_token == 0 || self.deployment_epoch == 0 {
      return Err(RemoteProtocolError::InvalidField("binding.authority"));
    }
    Ok(())
  }

  fn to_value(&self) -> Value {
    json!({
      "run_id": self.run_id,
      "job_id": self.job_id,
      "attempt": self.attempt,
      "fence_token": self.fence_token,
      "authority_digest": self.authority_digest,
      "profile_digest": self.profile_digest,
      "deployment_epoch": self.deployment_epoch,
      "credential_revision": self.credential_revision,
    })
  }

  fn from_value(value: &Value) -> Result<Self, RemoteProtocolError> {
    let object = exact_object(
      value,
      &[
        "run_id",
        "job_id",
        "attempt",
        "fence_token",
        "authority_digest",
        "profile_digest",
        "deployment_epoch",
        "credential_revision",
      ],
      "binding",
    )?;
    Ok(Self {
      run_id: required_string(object, "run_id")?,
      job_id: required_string(object, "job_id")?,
      attempt: u32::try_from(required_u64(object, "attempt")?)
        .map_err(|_| RemoteProtocolError::InvalidField("binding.attempt"))?,
      fence_token: required_u64(object, "fence_token")?,
      authority_digest: required_string(object, "authority_digest")?,
      profile_digest: required_string(object, "profile_digest")?,
      deployment_epoch: required_u64(object, "deployment_epoch")?,
      credential_revision: required_string(object, "credential_revision")?,
    })
  }
}

impl PrepareFrame {
  fn validate(&self) -> Result<(), RemoteProtocolError> {
    self.binding.validate()?;
    require_json_field(
      "prepare.isolation_permit_envelope_json",
      &self.isolation_permit_envelope_json,
    )?;
    require_json_field("prepare.task_json", &self.task_json)?;
    require_json_field("prepare.definition_json", &self.definition_json)?;
    require_json_field("prepare.capability_json", &self.capability_json)?;
    require_json_field("prepare.targets_json", &self.targets_json)
  }

  fn to_value(&self) -> Value {
    json!({
      "binding": self.binding.to_value(),
      "isolation_permit_envelope_json": self.isolation_permit_envelope_json,
      "task_json": self.task_json,
      "definition_json": self.definition_json,
      "capability_json": self.capability_json,
      "targets_json": self.targets_json,
    })
  }

  fn from_value(value: &Value) -> Result<Self, RemoteProtocolError> {
    let object = exact_object(
      value,
      &[
        "binding",
        "isolation_permit_envelope_json",
        "task_json",
        "definition_json",
        "capability_json",
        "targets_json",
      ],
      "prepare",
    )?;
    Ok(Self {
      binding: RunBinding::from_value(required(object, "binding")?)?,
      isolation_permit_envelope_json: required_string(object, "isolation_permit_envelope_json")?,
      task_json: required_string(object, "task_json")?,
      definition_json: required_string(object, "definition_json")?,
      capability_json: required_string(object, "capability_json")?,
      targets_json: required_string(object, "targets_json")?,
    })
  }
}

impl PreparedFrame {
  fn validate(&self) -> Result<(), RemoteProtocolError> {
    self.binding.validate()?;
    require_hex("prepared.preparation_nonce", &self.preparation_nonce, 64)?;
    require_json_field(
      "prepared.attested_profile_json",
      &self.attested_profile_json,
    )?;
    require_hex(
      "prepared.attested_profile_digest",
      &self.attested_profile_digest,
      64,
    )
  }

  fn to_value(&self) -> Value {
    json!({
      "binding": self.binding.to_value(),
      "preparation_nonce": self.preparation_nonce,
      "attested_profile_json": self.attested_profile_json,
      "attested_profile_digest": self.attested_profile_digest,
    })
  }

  fn from_value(value: &Value) -> Result<Self, RemoteProtocolError> {
    let object = exact_object(
      value,
      &[
        "binding",
        "preparation_nonce",
        "attested_profile_json",
        "attested_profile_digest",
      ],
      "prepared",
    )?;
    Ok(Self {
      binding: RunBinding::from_value(required(object, "binding")?)?,
      preparation_nonce: required_string(object, "preparation_nonce")?,
      attested_profile_json: required_string(object, "attested_profile_json")?,
      attested_profile_digest: required_string(object, "attested_profile_digest")?,
    })
  }
}

impl StartFrame {
  fn validate(&self) -> Result<(), RemoteProtocolError> {
    self.binding.validate()?;
    require_hex("start.preparation_nonce", &self.preparation_nonce, 64)
  }

  fn to_value(&self) -> Value {
    json!({"binding": self.binding.to_value(), "preparation_nonce": self.preparation_nonce})
  }

  fn from_value(value: &Value) -> Result<Self, RemoteProtocolError> {
    let object = exact_object(value, &["binding", "preparation_nonce"], "start")?;
    Ok(Self {
      binding: RunBinding::from_value(required(object, "binding")?)?,
      preparation_nonce: required_string(object, "preparation_nonce")?,
    })
  }
}

impl ResultFrame {
  fn validate(&self) -> Result<(), RemoteProtocolError> {
    self.binding.validate()?;
    require_hex("result.preparation_nonce", &self.preparation_nonce, 64)?;
    if self.result_json.len() > MAX_JSON_FIELD_BYTES {
      return Err(RemoteProtocolError::InvalidField("result.result_json"));
    }
    Ok(())
  }

  fn to_value(&self) -> Value {
    let kind = match self.kind {
      RemoteResultKind::Completed => "completed",
      RemoteResultKind::FailedBeforeStart => "failed_before_start",
      RemoteResultKind::OutcomeUnknown => "outcome_unknown",
    };
    json!({
      "binding": self.binding.to_value(),
      "preparation_nonce": self.preparation_nonce,
      "kind": kind,
      "result_json": self.result_json,
    })
  }

  fn from_value(value: &Value) -> Result<Self, RemoteProtocolError> {
    let object = exact_object(
      value,
      &["binding", "preparation_nonce", "kind", "result_json"],
      "result",
    )?;
    let kind = match required_str(object, "kind")? {
      "completed" => RemoteResultKind::Completed,
      "failed_before_start" => RemoteResultKind::FailedBeforeStart,
      "outcome_unknown" => RemoteResultKind::OutcomeUnknown,
      _ => return Err(RemoteProtocolError::InvalidField("result.kind")),
    };
    Ok(Self {
      binding: RunBinding::from_value(required(object, "binding")?)?,
      preparation_nonce: required_string(object, "preparation_nonce")?,
      kind,
      result_json: required_string(object, "result_json")?,
    })
  }
}

impl CancelFrame {
  fn validate(&self) -> Result<(), RemoteProtocolError> {
    self.binding.validate()?;
    require_bounded("cancel.reason", &self.reason, MAX_ERROR_BYTES)
  }

  fn to_value(&self) -> Value {
    json!({"binding": self.binding.to_value(), "reason": self.reason})
  }

  fn from_value(value: &Value) -> Result<Self, RemoteProtocolError> {
    let object = exact_object(value, &["binding", "reason"], "cancel")?;
    Ok(Self {
      binding: RunBinding::from_value(required(object, "binding")?)?,
      reason: required_string(object, "reason")?,
    })
  }
}

impl HeartbeatFrame {
  fn to_value(&self) -> Value {
    let phase = match self.phase {
      RemoteHeartbeatPhase::Preparing => "preparing",
      RemoteHeartbeatPhase::Prepared => "prepared",
      RemoteHeartbeatPhase::Started => "started",
    };
    json!({"binding": self.binding.to_value(), "phase": phase})
  }

  fn from_value(value: &Value) -> Result<Self, RemoteProtocolError> {
    let object = exact_object(value, &["binding", "phase"], "heartbeat")?;
    let phase = match required_str(object, "phase")? {
      "preparing" => RemoteHeartbeatPhase::Preparing,
      "prepared" => RemoteHeartbeatPhase::Prepared,
      "started" => RemoteHeartbeatPhase::Started,
      _ => return Err(RemoteProtocolError::InvalidField("heartbeat.phase")),
    };
    Ok(Self {
      binding: RunBinding::from_value(required(object, "binding")?)?,
      phase,
    })
  }
}

impl ErrorFrame {
  fn validate(&self) -> Result<(), RemoteProtocolError> {
    if let Some(binding) = &self.binding {
      binding.validate()?;
    }
    if let Some(nonce) = &self.preparation_nonce {
      require_hex("error.preparation_nonce", nonce, 64)?;
    }
    require_credential_revision("error.code", &self.code)?;
    require_bounded("error.message", &self.message, MAX_ERROR_BYTES)
  }

  fn to_value(&self) -> Value {
    json!({
      "binding": self.binding.as_ref().map(RunBinding::to_value),
      "preparation_nonce": self.preparation_nonce,
      "code": self.code,
      "message": self.message,
      "retryable": self.retryable,
    })
  }

  fn from_value(value: &Value) -> Result<Self, RemoteProtocolError> {
    let object = exact_object(
      value,
      &[
        "binding",
        "preparation_nonce",
        "code",
        "message",
        "retryable",
      ],
      "error",
    )?;
    Ok(Self {
      binding: optional_object(object, "binding", RunBinding::from_value)?,
      preparation_nonce: optional_string(object, "preparation_nonce")?,
      code: required_string(object, "code")?,
      message: required_string(object, "message")?,
      retryable: required(object, "retryable")?
        .as_bool()
        .ok_or(RemoteProtocolError::InvalidField("error.retryable"))?,
    })
  }
}

fn exact_object<'a>(
  value: &'a Value,
  fields: &[&str],
  label: &'static str,
) -> Result<&'a Map<String, Value>, RemoteProtocolError> {
  let object = value
    .as_object()
    .ok_or(RemoteProtocolError::InvalidShape(label))?;
  if object.len() != fields.len() || fields.iter().any(|field| !object.contains_key(*field)) {
    return Err(RemoteProtocolError::InvalidShape(label));
  }
  Ok(object)
}

fn required<'a>(
  object: &'a Map<String, Value>,
  field: &'static str,
) -> Result<&'a Value, RemoteProtocolError> {
  object
    .get(field)
    .ok_or(RemoteProtocolError::InvalidField(field))
}

fn required_str<'a>(
  object: &'a Map<String, Value>,
  field: &'static str,
) -> Result<&'a str, RemoteProtocolError> {
  required(object, field)?
    .as_str()
    .ok_or(RemoteProtocolError::InvalidField(field))
}

fn required_string(
  object: &Map<String, Value>,
  field: &'static str,
) -> Result<String, RemoteProtocolError> {
  required_str(object, field).map(str::to_owned)
}

fn required_u64(
  object: &Map<String, Value>,
  field: &'static str,
) -> Result<u64, RemoteProtocolError> {
  required(object, field)?
    .as_u64()
    .ok_or(RemoteProtocolError::InvalidField(field))
}

fn optional_string(
  object: &Map<String, Value>,
  field: &'static str,
) -> Result<Option<String>, RemoteProtocolError> {
  match required(object, field)? {
    Value::Null => Ok(None),
    Value::String(value) => Ok(Some(value.clone())),
    _ => Err(RemoteProtocolError::InvalidField(field)),
  }
}

fn optional_object<T>(
  object: &Map<String, Value>,
  field: &'static str,
  parse: impl FnOnce(&Value) -> Result<T, RemoteProtocolError>,
) -> Result<Option<T>, RemoteProtocolError> {
  match required(object, field)? {
    Value::Null => Ok(None),
    value => parse(value).map(Some),
  }
}

fn require_critical_id(field: &'static str, value: &str) -> Result<(), RemoteProtocolError> {
  CriticalId::parse(value)
    .map(|_| ())
    .map_err(|_| RemoteProtocolError::InvalidField(field))
}

fn require_credential_revision(
  field: &'static str,
  value: &str,
) -> Result<(), RemoteProtocolError> {
  CredentialRevision::parse(value)
    .map(|_| ())
    .map_err(|_| RemoteProtocolError::InvalidField(field))
}

fn require_json_field(field: &'static str, value: &str) -> Result<(), RemoteProtocolError> {
  require_bounded(field, value, MAX_JSON_FIELD_BYTES)?;
  let parsed: Value =
    serde_json::from_str(value).map_err(|_| RemoteProtocolError::InvalidField(field))?;
  if parsed.is_null() {
    return Err(RemoteProtocolError::InvalidField(field));
  }
  Ok(())
}

fn require_bounded(
  field: &'static str,
  value: &str,
  max: usize,
) -> Result<(), RemoteProtocolError> {
  if value.is_empty() || value != value.trim() || value.len() > max {
    return Err(RemoteProtocolError::InvalidField(field));
  }
  Ok(())
}

fn require_hex(field: &'static str, value: &str, len: usize) -> Result<(), RemoteProtocolError> {
  if value.len() != len
    || !value
      .bytes()
      .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
  {
    return Err(RemoteProtocolError::InvalidField(field));
  }
  Ok(())
}

fn require_image_digest(field: &'static str, value: &str) -> Result<(), RemoteProtocolError> {
  value
    .strip_prefix("sha256:")
    .ok_or(RemoteProtocolError::InvalidField(field))
    .and_then(|digest| require_hex(field, digest, 64))
}

#[cfg(test)]
mod tests {
  use super::*;

  const NOW: u64 = 1_000_000;

  fn binding() -> RunBinding {
    RunBinding {
      run_id: "run-1".to_owned(),
      job_id: "job-1".to_owned(),
      attempt: 1,
      fence_token: 7,
      authority_digest: "a".repeat(64),
      profile_digest: "b".repeat(64),
      deployment_epoch: 9,
      credential_revision: "github-readonly-2026-07".to_owned(),
    }
  }

  fn ready(sequence: u64) -> RemoteFrame {
    RemoteFrame {
      version: REMOTE_PROTOCOL_VERSION,
      session_nonce: "c".repeat(64),
      sequence,
      message: RemoteMessage::Ready(ReadyFrame {
        challenge: "d".repeat(64),
        ready_until_unix_millis: NOW + 10_000,
        attested_profile_json: r#"{"schema_version":1}"#.to_owned(),
        attested_profile_digest: "1".repeat(64),
        deployment_epoch: 9,
        profile_digest: "b".repeat(64),
        gateway_image_digest: format!("sha256:{}", "e".repeat(64)),
        runner_image_digest: format!("sha256:{}", "f".repeat(64)),
        runner_workload_identity: "spiffe://codeoff/runner/production".to_owned(),
        runner_client_cert_public_key_fingerprint: "1".repeat(64),
        credential_revision: "github-readonly-2026-07".to_owned(),
      }),
    }
  }

  fn prepare(sequence: u64) -> RemoteFrame {
    RemoteFrame {
      version: REMOTE_PROTOCOL_VERSION,
      session_nonce: "c".repeat(64),
      sequence,
      message: RemoteMessage::Prepare(PrepareFrame {
        binding: binding(),
        isolation_permit_envelope_json: r#"{"schema_version":1}"#.to_owned(),
        task_json: r#"{"instruction":"check"}"#.to_owned(),
        definition_json: r#"{"prompt":"check"}"#.to_owned(),
        capability_json: r#"{"tools":["github"]}"#.to_owned(),
        targets_json: "[]".to_owned(),
      }),
    }
  }

  #[test]
  fn every_frame_round_trips_with_strict_shape() {
    let frames = [
      ready(1),
      RemoteFrame {
        sequence: 2,
        message: RemoteMessage::Admission(AdmissionFrame {
          challenge: "d".repeat(64),
          admission_nonce: "2".repeat(64),
          expires_at_unix_millis: NOW + 5_000,
          deployment_epoch: 9,
          profile_digest: "b".repeat(64),
        }),
        ..ready(2)
      },
      prepare(3),
      RemoteFrame {
        sequence: 4,
        message: RemoteMessage::Prepared(PreparedFrame {
          binding: binding(),
          preparation_nonce: "3".repeat(64),
          attested_profile_json: r#"{"profile":"bound"}"#.to_owned(),
          attested_profile_digest: "4".repeat(64),
        }),
        ..ready(4)
      },
      RemoteFrame {
        sequence: 5,
        message: RemoteMessage::Start(StartFrame {
          binding: binding(),
          preparation_nonce: "3".repeat(64),
        }),
        ..ready(5)
      },
      RemoteFrame {
        sequence: 6,
        message: RemoteMessage::Heartbeat(HeartbeatFrame {
          binding: binding(),
          phase: RemoteHeartbeatPhase::Started,
        }),
        ..ready(6)
      },
      RemoteFrame {
        sequence: 7,
        message: RemoteMessage::Result(ResultFrame {
          binding: binding(),
          preparation_nonce: "3".repeat(64),
          kind: RemoteResultKind::OutcomeUnknown,
          result_json: "{}".to_owned(),
        }),
        ..ready(7)
      },
      RemoteFrame {
        sequence: 8,
        message: RemoteMessage::Cancel(CancelFrame {
          binding: binding(),
          reason: "lease_lost".to_owned(),
        }),
        ..ready(8)
      },
      RemoteFrame {
        sequence: 9,
        message: RemoteMessage::Error(ErrorFrame {
          binding: Some(binding()),
          preparation_nonce: Some("3".repeat(64)),
          code: "runner_unavailable".to_owned(),
          message: "runner slot unavailable".to_owned(),
          retryable: true,
        }),
        ..ready(9)
      },
    ];
    for frame in frames {
      let encoded = frame.encode().expect("encode");
      assert_eq!(RemoteFrame::decode(&encoded, NOW).expect("decode"), frame);
    }
  }

  #[test]
  fn unknown_fields_and_oversized_frames_are_rejected() {
    let mut value = ready(1).to_value();
    value
      .as_object_mut()
      .expect("frame object")
      .insert("unknown".to_owned(), Value::Bool(true));
    assert!(matches!(
      RemoteFrame::decode(value.to_string().as_bytes(), NOW),
      Err(RemoteProtocolError::InvalidShape("frame"))
    ));
    assert_eq!(
      RemoteFrame::decode(&vec![b'x'; MAX_REMOTE_FRAME_BYTES + 1], NOW),
      Err(RemoteProtocolError::FrameTooLarge)
    );
  }

  #[test]
  fn decode_rejects_every_noncanonical_json_representation() {
    let canonical = ready(1).encode().expect("canonical frame");
    let canonical_text = String::from_utf8(canonical.clone()).expect("UTF-8 frame");
    let value: Value = serde_json::from_slice(&canonical).expect("frame value");
    let object = value.as_object().expect("frame object");
    let reordered = format!(
      r#"{{"version":{},"session_nonce":{},"sequence":{},"message":{}}}"#,
      object["version"], object["session_nonce"], object["sequence"], object["message"]
    );
    let duplicate = format!("{},\"version\":1}}", canonical_text.trim_end_matches('}'));
    let trailing = format!("{canonical_text}\n");
    let leading = format!(" {canonical_text}");

    for encoded in [reordered, duplicate, trailing, leading] {
      assert_eq!(
        RemoteFrame::decode(encoded.as_bytes(), NOW),
        Err(RemoteProtocolError::NonCanonicalJson)
      );
    }
    assert_eq!(
      RemoteFrame::decode(&canonical, NOW).expect("canonical decode"),
      ready(1)
    );
  }

  #[test]
  fn readiness_is_challenge_bound_short_lived_and_image_bound() {
    let mut stale = ready(1);
    let RemoteMessage::Ready(payload) = &mut stale.message else {
      unreachable!()
    };
    payload.ready_until_unix_millis = NOW;
    assert!(stale.encode().is_ok());
    assert!(RemoteFrame::decode(&stale.encode().expect("encode"), NOW).is_err());

    let mut movable = ready(1);
    let RemoteMessage::Ready(payload) = &mut movable.message else {
      unreachable!()
    };
    payload.runner_image_digest = "sha-runner-latest".to_owned();
    assert!(movable.encode().is_err());
  }

  #[test]
  fn sequencer_distinguishes_duplicate_conflict_replay_gap_and_session() {
    let mut sequencer = RemoteFrameSequencer::new("c".repeat(64)).expect("sequencer");
    assert_eq!(
      sequencer.accept(ready(1), NOW),
      Ok(SequenceAcceptance::Accepted)
    );
    assert_eq!(
      sequencer.accept(ready(1), NOW),
      Ok(SequenceAcceptance::ExactDuplicate)
    );
    let mut conflict = ready(1);
    let RemoteMessage::Ready(payload) = &mut conflict.message else {
      unreachable!()
    };
    payload.credential_revision = "rotated".to_owned();
    assert_eq!(
      sequencer.accept(conflict, NOW),
      Err(RemoteProtocolError::SequenceConflict)
    );
    assert_eq!(
      sequencer.accept(prepare(3), NOW),
      Err(RemoteProtocolError::SequenceGap)
    );
    assert_eq!(
      sequencer.accept(prepare(2), NOW),
      Ok(SequenceAcceptance::Accepted)
    );
    assert_eq!(
      sequencer.accept(ready(1), NOW),
      Err(RemoteProtocolError::SequenceReplay)
    );
    let mut wrong_session = ready(3);
    wrong_session.session_nonce = "9".repeat(64);
    assert_eq!(
      sequencer.accept(wrong_session, NOW),
      Err(RemoteProtocolError::SessionMismatch)
    );
  }

  #[test]
  fn stale_fence_epoch_and_credential_revision_change_are_not_duplicates() {
    let original = prepare(1);
    let mut sequencer = RemoteFrameSequencer::new("c".repeat(64)).expect("sequencer");
    assert!(sequencer.accept(original.clone(), NOW).is_ok());
    for mutation in ["fence", "epoch", "credential"] {
      let mut changed = original.clone();
      let RemoteMessage::Prepare(payload) = &mut changed.message else {
        unreachable!()
      };
      match mutation {
        "fence" => payload.binding.fence_token += 1,
        "epoch" => payload.binding.deployment_epoch += 1,
        "credential" => payload.binding.credential_revision.push_str("-rotated"),
        _ => unreachable!(),
      }
      assert_eq!(
        sequencer.accept(changed, NOW),
        Err(RemoteProtocolError::SequenceConflict)
      );
    }
  }
}
