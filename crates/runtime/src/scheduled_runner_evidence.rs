//! Canonical Ed25519 evidence exchanged across the untrusted runner-control relay.

use std::fmt;
use std::fmt::Write;

use codeoff_core::EvidenceKeyId;
use ring::signature::{ED25519, Ed25519KeyPair, UnparsedPublicKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::Path;

use crate::scheduled_remote_protocol::{
  PreparedFrame, ReadyFrame, RemoteResultKind, ResultFrame, RunBinding,
};
use crate::scheduled_runner_tls::load_root_owned_bounded_file;

const EVIDENCE_SCHEMA_VERSION: u64 = 1;
const EVIDENCE_ALGORITHM_VERSION: &str = "ed25519-v1";
const EVIDENCE_DOMAIN: &[u8] = b"codeoff-scheduled-runner-evidence-v1";
const MAX_EVIDENCE_BYTES: usize = 64 * 1024;
const MAX_EVIDENCE_KEY_BYTES: u64 = 4 * 1024;
const ED25519_SIGNATURE_HEX_BYTES: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunnerEvidenceKind {
  Ready,
  Prepared,
  Result,
  Cleanup,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunnerEvidenceClaims {
  pub kind: RunnerEvidenceKind,
  pub algorithm_version: String,
  pub signer_identity: String,
  pub key_revision: String,
  pub session_nonce: String,
  pub challenge: String,
  pub sequence: u64,
  pub issued_at_unix_millis: u64,
  pub expires_at_unix_millis: u64,
  pub deployment_epoch: u64,
  pub deployment_profile_digest: String,
  pub observed_profile_digest: String,
  pub executor_identity: String,
  pub credential_revision: String,
  pub payload_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedRunnerEvidence {
  pub claims_json: String,
  pub key_id: String,
  pub signature_hex: String,
}

impl SignedRunnerEvidence {
  #[must_use]
  pub fn canonical_json(&self) -> String {
    json!({"claims_json": self.claims_json, "key_id": self.key_id, "signature_hex": self.signature_hex}).to_string()
  }

  #[allow(
    clippy::cmp_owned,
    reason = "byte-exact canonical JSON comparison is the contract"
  )]
  pub fn parse_canonical_json(encoded: &str) -> Result<Self, RunnerEvidenceError> {
    if encoded.len() > MAX_EVIDENCE_BYTES {
      return Err(RunnerEvidenceError::TooLarge);
    }
    let value: Value =
      serde_json::from_str(encoded).map_err(|_| RunnerEvidenceError::InvalidClaims)?;
    if value.to_string() != encoded {
      return Err(RunnerEvidenceError::InvalidClaims);
    }
    let object = value
      .as_object()
      .ok_or(RunnerEvidenceError::InvalidClaims)?;
    if object.len() != 3
      || ["claims_json", "key_id", "signature_hex"]
        .iter()
        .any(|field| !object.contains_key(*field))
    {
      return Err(RunnerEvidenceError::InvalidClaims);
    }
    let string = |field| {
      object
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(RunnerEvidenceError::InvalidClaims)
    };
    let evidence = Self {
      claims_json: string("claims_json")?,
      key_id: string("key_id")?,
      signature_hex: string("signature_hex")?,
    };
    validate_outer_fields(&evidence)?;
    Ok(evidence)
  }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunnerEvidenceError {
  InvalidClaims,
  InvalidKey,
  InvalidSignature,
  Expired,
  NotYetValid,
  TooLarge,
}

pub struct RunnerEvidenceSigner {
  key_pair: Ed25519KeyPair,
  key_id: String,
}

impl RunnerEvidenceSigner {
  pub fn load(path: &Path, key_id: &str) -> Result<Self, RunnerEvidenceError> {
    let bytes = load_root_owned_bounded_file(path, MAX_EVIDENCE_KEY_BYTES)
      .map_err(|_| RunnerEvidenceError::InvalidKey)?;
    let key_pair =
      Ed25519KeyPair::from_pkcs8(&bytes).map_err(|_| RunnerEvidenceError::InvalidKey)?;
    if EvidenceKeyId::parse(key_id).is_err() {
      return Err(RunnerEvidenceError::InvalidKey);
    }
    Ok(Self {
      key_pair,
      key_id: key_id.to_owned(),
    })
  }

  pub fn sign(
    &self,
    claims: &RunnerEvidenceClaims,
  ) -> Result<SignedRunnerEvidence, RunnerEvidenceError> {
    sign_with_key_pair(claims, &self.key_id, &self.key_pair)
  }
}

pub struct RunnerEvidenceVerifier {
  public_key: Vec<u8>,
  key_id: String,
}

impl RunnerEvidenceVerifier {
  pub fn load(path: &Path, key_id: &str) -> Result<Self, RunnerEvidenceError> {
    let public_key =
      load_root_owned_bounded_file(path, 32).map_err(|_| RunnerEvidenceError::InvalidKey)?;
    if public_key.len() != 32 || EvidenceKeyId::parse(key_id).is_err() {
      return Err(RunnerEvidenceError::InvalidKey);
    }
    Ok(Self {
      public_key,
      key_id: key_id.to_owned(),
    })
  }

  pub fn verify(
    &self,
    evidence: &SignedRunnerEvidence,
    now: u64,
  ) -> Result<RunnerEvidenceClaims, RunnerEvidenceError> {
    if evidence.key_id != self.key_id {
      return Err(RunnerEvidenceError::InvalidKey);
    }
    verify_runner_evidence(evidence, &self.public_key, now)
  }
}

impl fmt::Display for RunnerEvidenceError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(formatter, "{self:?}")
  }
}

impl std::error::Error for RunnerEvidenceError {}

impl RunnerEvidenceClaims {
  #[must_use]
  pub fn canonical_json(&self) -> String {
    json!({
      "schema_version": EVIDENCE_SCHEMA_VERSION,
      "kind": kind_name(self.kind),
      "algorithm_version": self.algorithm_version,
      "signer_identity": self.signer_identity,
      "key_revision": self.key_revision,
      "session_nonce": self.session_nonce,
      "challenge": self.challenge,
      "sequence": self.sequence,
      "issued_at_unix_millis": self.issued_at_unix_millis,
      "expires_at_unix_millis": self.expires_at_unix_millis,
      "deployment_epoch": self.deployment_epoch,
      "deployment_profile_digest": self.deployment_profile_digest,
      "observed_profile_digest": self.observed_profile_digest,
      "executor_identity": self.executor_identity,
      "credential_revision": self.credential_revision,
      "payload_digest": self.payload_digest,
    })
    .to_string()
  }
}

pub fn sign_runner_evidence(
  claims: &RunnerEvidenceClaims,
  key_id: &str,
  pkcs8: &[u8],
) -> Result<SignedRunnerEvidence, RunnerEvidenceError> {
  validate_claims(claims, claims.issued_at_unix_millis)?;
  let claims_json = claims.canonical_json();
  if claims_json.len() > MAX_EVIDENCE_BYTES {
    return Err(RunnerEvidenceError::TooLarge);
  }
  let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8).map_err(|_| RunnerEvidenceError::InvalidKey)?;
  sign_with_key_pair(claims, key_id, &key_pair)
}

fn sign_with_key_pair(
  claims: &RunnerEvidenceClaims,
  key_id: &str,
  key_pair: &Ed25519KeyPair,
) -> Result<SignedRunnerEvidence, RunnerEvidenceError> {
  if EvidenceKeyId::parse(key_id).is_err() {
    return Err(RunnerEvidenceError::InvalidKey);
  }
  validate_claims(claims, claims.issued_at_unix_millis)?;
  let claims_json = claims.canonical_json();
  if claims_json.len() > MAX_EVIDENCE_BYTES {
    return Err(RunnerEvidenceError::TooLarge);
  }
  let signed = signing_input(claims.kind, &claims_json);
  Ok(SignedRunnerEvidence {
    signature_hex: hex(key_pair.sign(&signed).as_ref()),
    claims_json,
    key_id: key_id.to_owned(),
  })
}

pub fn verify_runner_evidence(
  evidence: &SignedRunnerEvidence,
  public_key: &[u8],
  now_unix_millis: u64,
) -> Result<RunnerEvidenceClaims, RunnerEvidenceError> {
  validate_outer_fields(evidence)?;
  if evidence.claims_json.len() > MAX_EVIDENCE_BYTES {
    return Err(RunnerEvidenceError::TooLarge);
  }
  let claims = parse_claims(&evidence.claims_json)?;
  let signature = decode_hex(&evidence.signature_hex)?;
  UnparsedPublicKey::new(&ED25519, public_key)
    .verify(
      &signing_input(claims.kind, &evidence.claims_json),
      &signature,
    )
    .map_err(|_| RunnerEvidenceError::InvalidSignature)?;
  if claims.issued_at_unix_millis > now_unix_millis {
    return Err(RunnerEvidenceError::NotYetValid);
  }
  if claims.expires_at_unix_millis <= now_unix_millis {
    return Err(RunnerEvidenceError::Expired);
  }
  validate_claims(&claims, claims.issued_at_unix_millis)?;
  Ok(claims)
}

#[allow(
  clippy::cmp_owned,
  reason = "byte-exact canonical JSON comparison is the contract"
)]
fn parse_claims(encoded: &str) -> Result<RunnerEvidenceClaims, RunnerEvidenceError> {
  let value: Value =
    serde_json::from_str(encoded).map_err(|_| RunnerEvidenceError::InvalidClaims)?;
  if value.to_string() != encoded {
    return Err(RunnerEvidenceError::InvalidClaims);
  }
  let object = value
    .as_object()
    .ok_or(RunnerEvidenceError::InvalidClaims)?;
  let fields = [
    "algorithm_version",
    "challenge",
    "credential_revision",
    "deployment_epoch",
    "deployment_profile_digest",
    "executor_identity",
    "expires_at_unix_millis",
    "issued_at_unix_millis",
    "key_revision",
    "kind",
    "observed_profile_digest",
    "payload_digest",
    "schema_version",
    "sequence",
    "session_nonce",
    "signer_identity",
  ];
  if object.len() != fields.len() || fields.iter().any(|field| !object.contains_key(*field)) {
    return Err(RunnerEvidenceError::InvalidClaims);
  }
  let string = |field| {
    object
      .get(field)
      .and_then(Value::as_str)
      .map(str::to_owned)
      .ok_or(RunnerEvidenceError::InvalidClaims)
  };
  let number = |field| {
    object
      .get(field)
      .and_then(Value::as_u64)
      .ok_or(RunnerEvidenceError::InvalidClaims)
  };
  if number("schema_version")? != EVIDENCE_SCHEMA_VERSION {
    return Err(RunnerEvidenceError::InvalidClaims);
  }
  let kind = match string("kind")?.as_str() {
    "ready" => RunnerEvidenceKind::Ready,
    "prepared" => RunnerEvidenceKind::Prepared,
    "result" => RunnerEvidenceKind::Result,
    "cleanup" => RunnerEvidenceKind::Cleanup,
    _ => return Err(RunnerEvidenceError::InvalidClaims),
  };
  Ok(RunnerEvidenceClaims {
    kind,
    algorithm_version: string("algorithm_version")?,
    signer_identity: string("signer_identity")?,
    key_revision: string("key_revision")?,
    session_nonce: string("session_nonce")?,
    challenge: string("challenge")?,
    sequence: number("sequence")?,
    issued_at_unix_millis: number("issued_at_unix_millis")?,
    expires_at_unix_millis: number("expires_at_unix_millis")?,
    deployment_epoch: number("deployment_epoch")?,
    deployment_profile_digest: string("deployment_profile_digest")?,
    observed_profile_digest: string("observed_profile_digest")?,
    executor_identity: string("executor_identity")?,
    credential_revision: string("credential_revision")?,
    payload_digest: string("payload_digest")?,
  })
}

fn validate_claims(claims: &RunnerEvidenceClaims, now: u64) -> Result<(), RunnerEvidenceError> {
  if claims.algorithm_version != EVIDENCE_ALGORITHM_VERSION
    || claims.signer_identity.is_empty()
    || claims.key_revision.is_empty()
    || claims.sequence == 0
    || claims.deployment_epoch == 0
    || claims.expires_at_unix_millis <= now
  {
    return Err(RunnerEvidenceError::InvalidClaims);
  }
  for digest in [
    &claims.session_nonce,
    &claims.challenge,
    &claims.deployment_profile_digest,
    &claims.observed_profile_digest,
    &claims.payload_digest,
  ] {
    if digest.len() != 64
      || !digest
        .bytes()
        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
      return Err(RunnerEvidenceError::InvalidClaims);
    }
  }
  if claims.executor_identity.is_empty() || claims.credential_revision.is_empty() {
    return Err(RunnerEvidenceError::InvalidClaims);
  }
  Ok(())
}

fn kind_name(kind: RunnerEvidenceKind) -> &'static str {
  match kind {
    RunnerEvidenceKind::Ready => "ready",
    RunnerEvidenceKind::Prepared => "prepared",
    RunnerEvidenceKind::Result => "result",
    RunnerEvidenceKind::Cleanup => "cleanup",
  }
}
fn signing_input(kind: RunnerEvidenceKind, claims_json: &str) -> Vec<u8> {
  let mut input = Vec::with_capacity(EVIDENCE_DOMAIN.len() + claims_json.len() + 8);
  input.extend_from_slice(EVIDENCE_DOMAIN);
  input.push(0);
  input.extend_from_slice(kind_name(kind).as_bytes());
  input.push(0);
  input.extend_from_slice(claims_json.as_bytes());
  input
}
fn hex(bytes: &[u8]) -> String {
  bytes.iter().fold(
    String::with_capacity(bytes.len() * 2),
    |mut output, byte| {
      write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
      output
    },
  )
}
fn decode_hex(value: &str) -> Result<Vec<u8>, RunnerEvidenceError> {
  if value.len() != ED25519_SIGNATURE_HEX_BYTES
    || !value
      .bytes()
      .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
  {
    return Err(RunnerEvidenceError::InvalidSignature);
  }
  (0..value.len())
    .step_by(2)
    .map(|i| {
      u8::from_str_radix(&value[i..i + 2], 16).map_err(|_| RunnerEvidenceError::InvalidSignature)
    })
    .collect()
}

#[must_use]
pub fn evidence_payload_digest(bytes: &[u8]) -> String {
  format!("{:x}", Sha256::digest(bytes))
}

#[must_use]
pub fn ready_evidence_payload_digest(ready: &ReadyFrame) -> String {
  evidence_payload_digest(
    json!({
      "attested_profile_digest": ready.attested_profile_digest,
      "attested_profile_json": ready.attested_profile_json,
      "challenge": ready.challenge,
      "credential_revision": ready.credential_revision,
      "deployment_epoch": ready.deployment_epoch,
      "gateway_image_digest": ready.gateway_image_digest,
      "github_mcp_access_auth_mode": ready.github_mcp_access_auth_mode,
      "github_mcp_access_token_revision": ready.github_mcp_access_token_revision,
      "kind": "ready",
      "profile_digest": ready.profile_digest,
      "ready_until_unix_millis": ready.ready_until_unix_millis,
      "runner_client_cert_public_key_fingerprint": ready.runner_client_cert_public_key_fingerprint,
      "runner_image_digest": ready.runner_image_digest,
      "runner_workload_identity": ready.runner_workload_identity,
      "schema_version": 1,
    })
    .to_string()
    .as_bytes(),
  )
}

#[must_use]
pub fn prepared_evidence_payload_digest(prepared: &PreparedFrame) -> String {
  evidence_payload_digest(
    json!({
      "attested_profile_digest": prepared.attested_profile_digest,
      "attested_profile_json": prepared.attested_profile_json,
      "binding": binding_value(&prepared.binding),
      "kind": "prepared",
      "github_mcp_access_auth_mode": prepared.github_mcp_access_auth_mode,
      "github_mcp_access_token_revision": prepared.github_mcp_access_token_revision,
      "preparation_nonce": prepared.preparation_nonce,
      "schema_version": 1,
    })
    .to_string()
    .as_bytes(),
  )
}

#[must_use]
pub fn result_evidence_payload_digest(result: &ResultFrame) -> String {
  let kind = match result.kind {
    RemoteResultKind::Completed => "completed",
    RemoteResultKind::FailedBeforeStart => "failed_before_start",
    RemoteResultKind::OutcomeUnknown => "outcome_unknown",
  };
  evidence_payload_digest(
    json!({
      "binding": binding_value(&result.binding),
      "kind": "result",
      "preparation_nonce": result.preparation_nonce,
      "result_json": result.result_json,
      "result_kind": kind,
      "schema_version": 1,
    })
    .to_string()
    .as_bytes(),
  )
}

fn binding_value(binding: &RunBinding) -> Value {
  json!({
    "attempt": binding.attempt,
    "authority_digest": binding.authority_digest,
    "credential_revision": binding.credential_revision,
    "deployment_epoch": binding.deployment_epoch,
    "fence_token": binding.fence_token,
    "job_id": binding.job_id,
    "profile_digest": binding.profile_digest,
    "run_id": binding.run_id,
  })
}

fn validate_outer_fields(evidence: &SignedRunnerEvidence) -> Result<(), RunnerEvidenceError> {
  if EvidenceKeyId::parse(&evidence.key_id).is_err() {
    return Err(RunnerEvidenceError::InvalidKey);
  }
  if evidence.signature_hex.len() != ED25519_SIGNATURE_HEX_BYTES
    || !evidence
      .signature_hex
      .bytes()
      .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
  {
    return Err(RunnerEvidenceError::InvalidSignature);
  }
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;
  use ring::rand::SystemRandom;
  use ring::signature::KeyPair;
  use std::fs;
  use std::os::unix::fs::PermissionsExt;
  use std::os::unix::fs::symlink;

  fn claims(kind: RunnerEvidenceKind) -> RunnerEvidenceClaims {
    RunnerEvidenceClaims {
      kind,
      algorithm_version: EVIDENCE_ALGORITHM_VERSION.to_owned(),
      signer_identity: "spiffe://codeoff/executor/production".to_owned(),
      key_revision: "executor-evidence-2026-07".to_owned(),
      session_nonce: "1".repeat(64),
      challenge: "2".repeat(64),
      sequence: 1,
      issued_at_unix_millis: 1_000,
      expires_at_unix_millis: 2_000,
      deployment_epoch: 9,
      deployment_profile_digest: "3".repeat(64),
      observed_profile_digest: "4".repeat(64),
      executor_identity: "uid:0:gid:0".to_owned(),
      credential_revision: "github-readonly-v1".to_owned(),
      payload_digest: "5".repeat(64),
    }
  }

  fn key_pair() -> (Vec<u8>, Vec<u8>) {
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("generate key");
    let key = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("parse key");
    (pkcs8.as_ref().to_vec(), key.public_key().as_ref().to_vec())
  }

  #[test]
  fn all_evidence_kinds_are_domain_separated_and_freshness_checked() {
    let (private, public) = key_pair();
    for kind in [
      RunnerEvidenceKind::Ready,
      RunnerEvidenceKind::Prepared,
      RunnerEvidenceKind::Result,
      RunnerEvidenceKind::Cleanup,
    ] {
      let signed = sign_runner_evidence(&claims(kind), "key-1", &private).expect("sign");
      assert_eq!(
        verify_runner_evidence(&signed, &public, 1_500)
          .expect("verify")
          .kind,
        kind
      );
      assert!(matches!(
        verify_runner_evidence(&signed, &public, 999),
        Err(RunnerEvidenceError::NotYetValid)
      ));
      assert!(matches!(
        verify_runner_evidence(&signed, &public, 2_000),
        Err(RunnerEvidenceError::Expired)
      ));
    }
  }

  #[test]
  fn rejects_tamper_unknown_missing_duplicate_and_noncanonical_claims() {
    let (private, public) = key_pair();
    let signed =
      sign_runner_evidence(&claims(RunnerEvidenceKind::Ready), "key-1", &private).expect("sign");
    for mutated in [
      signed.claims_json.replace(&"5".repeat(64), &"6".repeat(64)),
      signed.claims_json.replacen('{', "{\"unknown\":true,", 1),
      signed.claims_json.replace("\"sequence\":1,", ""),
      signed
        .claims_json
        .replace("\"sequence\":1", "\"sequence\":1,\"sequence\":1"),
      format!(" {}", signed.claims_json),
    ] {
      let mut candidate = signed.clone();
      candidate.claims_json = mutated;
      assert!(verify_runner_evidence(&candidate, &public, 1_500).is_err());
    }
  }

  #[test]
  fn rejects_cross_kind_replay_and_key_rotation_mismatch() {
    let (private, public) = key_pair();
    let (_, other_public) = key_pair();
    let mut signed =
      sign_runner_evidence(&claims(RunnerEvidenceKind::Ready), "key-1", &private).expect("sign");
    assert!(matches!(
      verify_runner_evidence(&signed, &other_public, 1_500),
      Err(RunnerEvidenceError::InvalidSignature)
    ));
    signed.claims_json = signed
      .claims_json
      .replace("\"kind\":\"ready\"", "\"kind\":\"result\"");
    assert!(matches!(
      verify_runner_evidence(&signed, &public, 1_500),
      Err(RunnerEvidenceError::InvalidSignature)
    ));
  }

  #[test]
  fn root_owned_key_loaders_require_exact_bounded_material() {
    let (private, public) = key_pair();
    let temp = tempfile::tempdir().expect("temp");
    let private_path = temp.path().join("executor.pk8");
    let public_path = temp.path().join("executor.pub");
    fs::write(&private_path, private).expect("private");
    fs::write(&public_path, public).expect("public");
    fs::set_permissions(&private_path, fs::Permissions::from_mode(0o400)).expect("private mode");
    fs::set_permissions(&public_path, fs::Permissions::from_mode(0o400)).expect("public mode");
    let signer = RunnerEvidenceSigner::load(&private_path, "key-1").expect("signer");
    let verifier = RunnerEvidenceVerifier::load(&public_path, "key-1").expect("verifier");
    let evidence = signer
      .sign(&claims(RunnerEvidenceKind::Ready))
      .expect("signed");
    assert!(verifier.verify(&evidence, 1_500).is_ok());
    fs::set_permissions(&private_path, fs::Permissions::from_mode(0o600)).expect("loose mode");
    assert!(RunnerEvidenceSigner::load(&private_path, "key-1").is_err());
  }

  #[test]
  fn outer_envelope_requires_bounded_key_id_and_exact_lowercase_signature() {
    let (private, public) = key_pair();
    let signed =
      sign_runner_evidence(&claims(RunnerEvidenceKind::Ready), "key-1", &private).expect("sign");
    for signature in [
      signed.signature_hex.to_ascii_uppercase(),
      signed.signature_hex[..126].to_owned(),
      format!("{}00", signed.signature_hex),
    ] {
      let mut candidate = signed.clone();
      candidate.signature_hex = signature;
      assert!(matches!(
        verify_runner_evidence(&candidate, &public, 1_500),
        Err(RunnerEvidenceError::InvalidSignature)
      ));
      assert!(SignedRunnerEvidence::parse_canonical_json(&candidate.canonical_json()).is_err());
    }
    for key_id in [
      String::new(),
      "a".repeat(codeoff_core::MAX_EVIDENCE_KEY_ID_BYTES + 1),
      "KEY-1".to_owned(),
    ] {
      let mut candidate = signed.clone();
      candidate.key_id = key_id;
      assert!(matches!(
        verify_runner_evidence(&candidate, &public, 1_500),
        Err(RunnerEvidenceError::InvalidKey)
      ));
    }
  }

  #[test]
  fn key_loaders_reject_zero_oversize_wrong_length_and_symlink_material() {
    let temp = tempfile::tempdir().expect("temp");
    let zero = temp.path().join("zero");
    let oversized = temp.path().join("oversized");
    let public_wrong = temp.path().join("public-wrong");
    let private_boundary = temp.path().join("private-boundary");
    let linked = temp.path().join("linked");
    fs::write(&zero, []).expect("zero");
    fs::write(
      &oversized,
      vec![0_u8; usize::try_from(MAX_EVIDENCE_KEY_BYTES + 1).unwrap()],
    )
    .expect("oversized");
    fs::write(&public_wrong, [0_u8; 31]).expect("public wrong");
    fs::write(
      &private_boundary,
      vec![0_u8; usize::try_from(MAX_EVIDENCE_KEY_BYTES).unwrap()],
    )
    .expect("private boundary");
    for path in [&zero, &oversized, &public_wrong, &private_boundary] {
      fs::set_permissions(path, fs::Permissions::from_mode(0o400)).expect("mode");
    }
    symlink(&zero, &linked).expect("symlink");
    assert!(RunnerEvidenceSigner::load(&zero, "key-1").is_err());
    assert!(RunnerEvidenceSigner::load(&oversized, "key-1").is_err());
    assert!(RunnerEvidenceSigner::load(&private_boundary, "key-1").is_err());
    assert!(RunnerEvidenceVerifier::load(&public_wrong, "key-1").is_err());
    assert!(RunnerEvidenceSigner::load(&linked, "key-1").is_err());
    assert!(RunnerEvidenceVerifier::load(&linked, "key-1").is_err());
  }

  fn binding() -> RunBinding {
    RunBinding {
      run_id: "01J00000000000000000000000".to_owned(),
      job_id: "01J00000000000000000000001".to_owned(),
      attempt: 1,
      fence_token: 2,
      authority_digest: "1".repeat(64),
      profile_digest: "2".repeat(64),
      deployment_epoch: 3,
      credential_revision: "credential-v1".to_owned(),
    }
  }

  #[test]
  fn kind_specific_payload_digests_cover_every_relayed_field() {
    let ready = ReadyFrame {
      signed_evidence_json: String::new(),
      challenge: "1".repeat(64),
      ready_until_unix_millis: 10,
      attested_profile_json: "{\"profile\":1}".to_owned(),
      attested_profile_digest: "2".repeat(64),
      deployment_epoch: 3,
      profile_digest: "4".repeat(64),
      gateway_image_digest: format!("sha256:{}", "5".repeat(64)),
      runner_image_digest: format!("sha256:{}", "6".repeat(64)),
      runner_workload_identity: "spiffe://codeoff/runner".to_owned(),
      runner_client_cert_public_key_fingerprint: "7".repeat(64),
      credential_revision: "credential-v1".to_owned(),
      github_mcp_access_auth_mode: "bearer-token-env-v1".to_owned(),
      github_mcp_access_token_revision: "mcp-channel-v1".to_owned(),
    };
    let ready_digest = ready_evidence_payload_digest(&ready);
    let mut mutations = Vec::new();
    let mut value = ready.clone();
    value.challenge = "8".repeat(64);
    mutations.push(value);
    let mut value = ready.clone();
    value.ready_until_unix_millis += 1;
    mutations.push(value);
    let mut value = ready.clone();
    value.attested_profile_json.push(' ');
    mutations.push(value);
    let mut value = ready.clone();
    value.attested_profile_digest = "8".repeat(64);
    mutations.push(value);
    let mut value = ready.clone();
    value.deployment_epoch += 1;
    mutations.push(value);
    let mut value = ready.clone();
    value.profile_digest = "8".repeat(64);
    mutations.push(value);
    let mut value = ready.clone();
    value.gateway_image_digest.push('x');
    mutations.push(value);
    let mut value = ready.clone();
    value.runner_image_digest.push('x');
    mutations.push(value);
    let mut value = ready.clone();
    value.runner_workload_identity.push('x');
    mutations.push(value);
    let mut value = ready.clone();
    value.runner_client_cert_public_key_fingerprint = "8".repeat(64);
    mutations.push(value);
    let mut value = ready.clone();
    value.credential_revision.push('x');
    mutations.push(value);
    let mut value = ready.clone();
    value.github_mcp_access_auth_mode.push('x');
    mutations.push(value);
    let mut value = ready.clone();
    value.github_mcp_access_token_revision.push('x');
    mutations.push(value);
    assert!(
      mutations
        .iter()
        .all(|value| ready_evidence_payload_digest(value) != ready_digest)
    );

    let prepared = PreparedFrame {
      signed_evidence_json: String::new(),
      binding: binding(),
      preparation_nonce: "3".repeat(64),
      attested_profile_json: "{\"profile\":1}".to_owned(),
      attested_profile_digest: "4".repeat(64),
      github_mcp_access_auth_mode: "bearer-token-env-v1".to_owned(),
      github_mcp_access_token_revision: "mcp-channel-v1".to_owned(),
    };
    let prepared_digest = prepared_evidence_payload_digest(&prepared);
    let mut value = prepared.clone();
    value.preparation_nonce = "5".repeat(64);
    assert_ne!(prepared_evidence_payload_digest(&value), prepared_digest);
    let mut value = prepared.clone();
    value.attested_profile_json.push(' ');
    assert_ne!(prepared_evidence_payload_digest(&value), prepared_digest);
    let mut value = prepared.clone();
    value.attested_profile_digest = "5".repeat(64);
    assert_ne!(prepared_evidence_payload_digest(&value), prepared_digest);
    let mut value = prepared.clone();
    value.github_mcp_access_auth_mode.push('x');
    assert_ne!(prepared_evidence_payload_digest(&value), prepared_digest);
    let mut value = prepared.clone();
    value.github_mcp_access_token_revision.push('x');
    assert_ne!(prepared_evidence_payload_digest(&value), prepared_digest);
    for index in 0..8 {
      let mut value = prepared.clone();
      match index {
        0 => value.binding.run_id.push('x'),
        1 => value.binding.job_id.push('x'),
        2 => value.binding.attempt += 1,
        3 => value.binding.fence_token += 1,
        4 => value.binding.authority_digest = "5".repeat(64),
        5 => value.binding.profile_digest = "5".repeat(64),
        6 => value.binding.deployment_epoch += 1,
        7 => value.binding.credential_revision.push('x'),
        _ => unreachable!(),
      }
      assert_ne!(prepared_evidence_payload_digest(&value), prepared_digest);
    }

    let result = ResultFrame {
      signed_evidence_json: String::new(),
      binding: binding(),
      preparation_nonce: "3".repeat(64),
      kind: RemoteResultKind::Completed,
      result_json: "{\"schema_version\":1}".to_owned(),
    };
    let result_digest = result_evidence_payload_digest(&result);
    let mut value = result.clone();
    value.preparation_nonce = "4".repeat(64);
    assert_ne!(result_evidence_payload_digest(&value), result_digest);
    let mut value = result.clone();
    value.kind = RemoteResultKind::OutcomeUnknown;
    assert_ne!(result_evidence_payload_digest(&value), result_digest);
    let mut value = result;
    value.result_json.push(' ');
    assert_ne!(result_evidence_payload_digest(&value), result_digest);
  }
}
