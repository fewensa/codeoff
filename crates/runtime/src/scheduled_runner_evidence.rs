//! Canonical Ed25519 evidence exchanged across the untrusted runner-control relay.

use std::fmt;
use std::fmt::Write;

use ring::signature::{ED25519, Ed25519KeyPair, UnparsedPublicKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::Path;

use crate::scheduled_runner_tls::load_root_owned_bounded_file;

const EVIDENCE_SCHEMA_VERSION: u64 = 1;
const EVIDENCE_ALGORITHM_VERSION: &str = "ed25519-v1";
const EVIDENCE_DOMAIN: &[u8] = b"codeoff-scheduled-runner-evidence-v1";
const MAX_EVIDENCE_BYTES: usize = 64 * 1024;
const MAX_EVIDENCE_KEY_BYTES: u64 = 4 * 1024;

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
    Ok(Self {
      claims_json: string("claims_json")?,
      key_id: string("key_id")?,
      signature_hex: string("signature_hex")?,
    })
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
    if key_id.is_empty() || key_id.len() > 128 {
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
    if public_key.len() != 32 || key_id.is_empty() || key_id.len() > 128 {
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
  if evidence.claims_json.len() > MAX_EVIDENCE_BYTES || evidence.key_id.is_empty() {
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
  if !value.len().is_multiple_of(2) {
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

#[cfg(test)]
mod tests {
  use super::*;
  use ring::rand::SystemRandom;
  use ring::signature::KeyPair;
  use std::fs;
  use std::os::unix::fs::PermissionsExt;

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
}
