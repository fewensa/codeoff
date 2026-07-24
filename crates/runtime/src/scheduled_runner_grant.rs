//! Canonical gateway authorization for one exact remote executor preparation.

use std::fmt;
use std::fmt::Write;
use std::path::Path;
use std::sync::Mutex;

use codeoff_core::EvidenceKeyId;
use ring::signature::{ED25519, Ed25519KeyPair, UnparsedPublicKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::scheduled_remote_protocol::{PrepareFrame, RunBinding};
use crate::scheduled_runner_tls::load_root_owned_bounded_file;

const GRANT_SCHEMA_VERSION: u64 = 1;
const GRANT_ALGORITHM_VERSION: &str = "ed25519-v1";
const GRANT_KIND: &str = "remote_execution_grant";
const GRANT_DOMAIN: &[u8] = b"codeoff-scheduled-remote-execution-grant-v1";
const MAX_GRANT_BYTES: usize = 64 * 1024;
const MAX_GRANT_KEY_BYTES: u64 = 4 * 1024;
const ED25519_SIGNATURE_HEX_BYTES: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteExecutionGrantClaims {
  pub algorithm_version: String,
  pub grant_id: String,
  pub grant_sequence: u64,
  pub signer_identity: String,
  pub key_revision: String,
  pub session_nonce: String,
  pub challenge: String,
  pub admission_nonce: String,
  pub issued_at_unix_millis: u64,
  pub expires_at_unix_millis: u64,
  pub deployment_epoch: u64,
  pub profile_digest: String,
  pub binding: RunBinding,
  pub isolation_permit_sha256: String,
  pub task_sha256: String,
  pub definition_sha256: String,
  pub capability_sha256: String,
  pub targets_sha256: String,
}

impl RemoteExecutionGrantClaims {
  #[allow(clippy::too_many_arguments)]
  #[must_use]
  pub fn for_prepare(
    grant_id: String,
    grant_sequence: u64,
    signer_identity: String,
    key_revision: String,
    session_nonce: String,
    challenge: String,
    admission_nonce: String,
    issued_at_unix_millis: u64,
    expires_at_unix_millis: u64,
    deployment_epoch: u64,
    profile_digest: String,
    prepare: &PrepareFrame,
  ) -> Self {
    Self {
      algorithm_version: GRANT_ALGORITHM_VERSION.to_owned(),
      grant_id,
      grant_sequence,
      signer_identity,
      key_revision,
      session_nonce,
      challenge,
      admission_nonce,
      issued_at_unix_millis,
      expires_at_unix_millis,
      deployment_epoch,
      profile_digest,
      binding: prepare.binding.clone(),
      isolation_permit_sha256: snapshot_digest(&prepare.isolation_permit_envelope_json),
      task_sha256: snapshot_digest(&prepare.task_json),
      definition_sha256: snapshot_digest(&prepare.definition_json),
      capability_sha256: snapshot_digest(&prepare.capability_json),
      targets_sha256: snapshot_digest(&prepare.targets_json),
    }
  }

  #[must_use]
  pub fn canonical_json(&self) -> String {
    json!({
      "schema_version": GRANT_SCHEMA_VERSION,
      "algorithm_version": self.algorithm_version,
      "grant_id": self.grant_id,
      "grant_sequence": self.grant_sequence,
      "signer_identity": self.signer_identity,
      "key_revision": self.key_revision,
      "session_nonce": self.session_nonce,
      "challenge": self.challenge,
      "admission_nonce": self.admission_nonce,
      "issued_at_unix_millis": self.issued_at_unix_millis,
      "expires_at_unix_millis": self.expires_at_unix_millis,
      "deployment_epoch": self.deployment_epoch,
      "profile_digest": self.profile_digest,
      "binding": self.binding.to_value(),
      "isolation_permit_sha256": self.isolation_permit_sha256,
      "task_sha256": self.task_sha256,
      "definition_sha256": self.definition_sha256,
      "capability_sha256": self.capability_sha256,
      "targets_sha256": self.targets_sha256,
    })
    .to_string()
  }

  pub fn verify_prepare(
    &self,
    expected: &ExpectedRemoteExecutionGrant<'_>,
    prepare: &PrepareFrame,
  ) -> Result<(), RemoteExecutionGrantError> {
    validate_claims(self, expected.now_unix_millis)?;
    if self.signer_identity != expected.signer_identity
      || self.key_revision != expected.key_revision
      || self.grant_sequence != expected.grant_sequence
      || self.session_nonce != expected.session_nonce
      || self.challenge != expected.challenge
      || self.admission_nonce != expected.admission_nonce
      || self.expires_at_unix_millis != expected.expires_at_unix_millis
      || self.deployment_epoch != expected.deployment_epoch
      || self.profile_digest != expected.profile_digest
      || self.binding != prepare.binding
      || self.isolation_permit_sha256 != snapshot_digest(&prepare.isolation_permit_envelope_json)
      || self.task_sha256 != snapshot_digest(&prepare.task_json)
      || self.definition_sha256 != snapshot_digest(&prepare.definition_json)
      || self.capability_sha256 != snapshot_digest(&prepare.capability_json)
      || self.targets_sha256 != snapshot_digest(&prepare.targets_json)
    {
      return Err(RemoteExecutionGrantError::BindingMismatch);
    }
    Ok(())
  }
}

pub struct ExpectedRemoteExecutionGrant<'a> {
  pub signer_identity: &'a str,
  pub key_revision: &'a str,
  pub grant_sequence: u64,
  pub session_nonce: &'a str,
  pub challenge: &'a str,
  pub admission_nonce: &'a str,
  pub expires_at_unix_millis: u64,
  pub deployment_epoch: u64,
  pub profile_digest: &'a str,
  pub now_unix_millis: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedRemoteExecutionGrant {
  pub kind: String,
  pub claims_json: String,
  pub key_id: String,
  pub signature_hex: String,
}

impl SignedRemoteExecutionGrant {
  #[must_use]
  pub fn canonical_json(&self) -> String {
    json!({
      "kind": self.kind,
      "claims_json": self.claims_json,
      "key_id": self.key_id,
      "signature_hex": self.signature_hex,
    })
    .to_string()
  }

  #[allow(
    clippy::cmp_owned,
    reason = "byte-exact canonical JSON comparison is the grant contract"
  )]
  pub fn parse_canonical_json(encoded: &str) -> Result<Self, RemoteExecutionGrantError> {
    if encoded.len() > MAX_GRANT_BYTES {
      return Err(RemoteExecutionGrantError::TooLarge);
    }
    let value: Value =
      serde_json::from_str(encoded).map_err(|_| RemoteExecutionGrantError::InvalidGrant)?;
    if value.to_string() != encoded {
      return Err(RemoteExecutionGrantError::NonCanonical);
    }
    let object = value
      .as_object()
      .ok_or(RemoteExecutionGrantError::InvalidGrant)?;
    if object.len() != 4
      || ["claims_json", "key_id", "kind", "signature_hex"]
        .iter()
        .any(|field| !object.contains_key(*field))
    {
      return Err(RemoteExecutionGrantError::InvalidGrant);
    }
    let string = |field| {
      object
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(RemoteExecutionGrantError::InvalidGrant)
    };
    let grant = Self {
      kind: string("kind")?,
      claims_json: string("claims_json")?,
      key_id: string("key_id")?,
      signature_hex: string("signature_hex")?,
    };
    validate_outer(&grant)?;
    Ok(grant)
  }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteExecutionGrantError {
  InvalidGrant,
  InvalidKey,
  InvalidSignature,
  NonCanonical,
  NotYetValid,
  Expired,
  BindingMismatch,
  Replayed,
  TooLarge,
}

impl fmt::Display for RemoteExecutionGrantError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(formatter, "{self:?}")
  }
}

impl std::error::Error for RemoteExecutionGrantError {}

pub struct RemoteExecutionGrantSigner {
  key_pair: Ed25519KeyPair,
  key_id: String,
}

impl RemoteExecutionGrantSigner {
  pub fn load(path: &Path, key_id: &str) -> Result<Self, RemoteExecutionGrantError> {
    let bytes = load_root_owned_bounded_file(path, MAX_GRANT_KEY_BYTES)
      .map_err(|_| RemoteExecutionGrantError::InvalidKey)?;
    let key_pair =
      Ed25519KeyPair::from_pkcs8(&bytes).map_err(|_| RemoteExecutionGrantError::InvalidKey)?;
    if EvidenceKeyId::parse(key_id).is_err() {
      return Err(RemoteExecutionGrantError::InvalidKey);
    }
    Ok(Self {
      key_pair,
      key_id: key_id.to_owned(),
    })
  }

  #[cfg(test)]
  pub(crate) fn from_pkcs8(bytes: &[u8], key_id: &str) -> Result<Self, RemoteExecutionGrantError> {
    let key_pair =
      Ed25519KeyPair::from_pkcs8(bytes).map_err(|_| RemoteExecutionGrantError::InvalidKey)?;
    if EvidenceKeyId::parse(key_id).is_err() {
      return Err(RemoteExecutionGrantError::InvalidKey);
    }
    Ok(Self {
      key_pair,
      key_id: key_id.to_owned(),
    })
  }

  pub fn sign(
    &self,
    claims: &RemoteExecutionGrantClaims,
  ) -> Result<SignedRemoteExecutionGrant, RemoteExecutionGrantError> {
    validate_claims(claims, claims.issued_at_unix_millis)?;
    let claims_json = claims.canonical_json();
    if claims_json.len() > MAX_GRANT_BYTES {
      return Err(RemoteExecutionGrantError::TooLarge);
    }
    Ok(SignedRemoteExecutionGrant {
      kind: GRANT_KIND.to_owned(),
      signature_hex: hex(self.key_pair.sign(&signing_input(&claims_json)).as_ref()),
      claims_json,
      key_id: self.key_id.clone(),
    })
  }
}

pub struct RemoteExecutionGrantVerifier {
  public_key: Vec<u8>,
  key_id: String,
  consumed_grant_id: Mutex<Option<String>>,
}

impl RemoteExecutionGrantVerifier {
  pub fn load(path: &Path, key_id: &str) -> Result<Self, RemoteExecutionGrantError> {
    let public_key =
      load_root_owned_bounded_file(path, 32).map_err(|_| RemoteExecutionGrantError::InvalidKey)?;
    Self::new(public_key, key_id)
  }

  pub fn new(public_key: Vec<u8>, key_id: &str) -> Result<Self, RemoteExecutionGrantError> {
    if public_key.len() != 32 || EvidenceKeyId::parse(key_id).is_err() {
      return Err(RemoteExecutionGrantError::InvalidKey);
    }
    Ok(Self {
      public_key,
      key_id: key_id.to_owned(),
      consumed_grant_id: Mutex::new(None),
    })
  }

  pub fn verify(
    &self,
    grant: &SignedRemoteExecutionGrant,
    now_unix_millis: u64,
  ) -> Result<RemoteExecutionGrantClaims, RemoteExecutionGrantError> {
    validate_outer(grant)?;
    if grant.key_id != self.key_id {
      return Err(RemoteExecutionGrantError::InvalidKey);
    }
    let claims = parse_claims(&grant.claims_json)?;
    let signature = decode_hex(&grant.signature_hex)?;
    UnparsedPublicKey::new(&ED25519, &self.public_key)
      .verify(&signing_input(&grant.claims_json), &signature)
      .map_err(|_| RemoteExecutionGrantError::InvalidSignature)?;
    validate_claims(&claims, now_unix_millis)?;
    Ok(claims)
  }

  pub fn verify_and_consume(
    &self,
    grant: &SignedRemoteExecutionGrant,
    expected: &ExpectedRemoteExecutionGrant<'_>,
    prepare: &PrepareFrame,
  ) -> Result<RemoteExecutionGrantClaims, RemoteExecutionGrantError> {
    let claims = self.verify(grant, expected.now_unix_millis)?;
    claims.verify_prepare(expected, prepare)?;
    let mut consumed = self
      .consumed_grant_id
      .lock()
      .map_err(|_| RemoteExecutionGrantError::InvalidGrant)?;
    if consumed.is_some() {
      return Err(RemoteExecutionGrantError::Replayed);
    }
    *consumed = Some(claims.grant_id.clone());
    Ok(claims)
  }
}

#[allow(
  clippy::cmp_owned,
  reason = "byte-exact canonical JSON comparison is the grant contract"
)]
fn parse_claims(encoded: &str) -> Result<RemoteExecutionGrantClaims, RemoteExecutionGrantError> {
  if encoded.len() > MAX_GRANT_BYTES {
    return Err(RemoteExecutionGrantError::TooLarge);
  }
  let value: Value =
    serde_json::from_str(encoded).map_err(|_| RemoteExecutionGrantError::InvalidGrant)?;
  if value.to_string() != encoded {
    return Err(RemoteExecutionGrantError::NonCanonical);
  }
  let object = value
    .as_object()
    .ok_or(RemoteExecutionGrantError::InvalidGrant)?;
  let fields = [
    "admission_nonce",
    "algorithm_version",
    "binding",
    "capability_sha256",
    "challenge",
    "definition_sha256",
    "deployment_epoch",
    "expires_at_unix_millis",
    "grant_id",
    "grant_sequence",
    "isolation_permit_sha256",
    "issued_at_unix_millis",
    "key_revision",
    "profile_digest",
    "schema_version",
    "session_nonce",
    "signer_identity",
    "targets_sha256",
    "task_sha256",
  ];
  if object.len() != fields.len() || fields.iter().any(|field| !object.contains_key(*field)) {
    return Err(RemoteExecutionGrantError::InvalidGrant);
  }
  let string = |field| {
    object
      .get(field)
      .and_then(Value::as_str)
      .map(str::to_owned)
      .ok_or(RemoteExecutionGrantError::InvalidGrant)
  };
  let number = |field| {
    object
      .get(field)
      .and_then(Value::as_u64)
      .ok_or(RemoteExecutionGrantError::InvalidGrant)
  };
  if number("schema_version")? != GRANT_SCHEMA_VERSION {
    return Err(RemoteExecutionGrantError::InvalidGrant);
  }
  Ok(RemoteExecutionGrantClaims {
    algorithm_version: string("algorithm_version")?,
    grant_id: string("grant_id")?,
    grant_sequence: number("grant_sequence")?,
    signer_identity: string("signer_identity")?,
    key_revision: string("key_revision")?,
    session_nonce: string("session_nonce")?,
    challenge: string("challenge")?,
    admission_nonce: string("admission_nonce")?,
    issued_at_unix_millis: number("issued_at_unix_millis")?,
    expires_at_unix_millis: number("expires_at_unix_millis")?,
    deployment_epoch: number("deployment_epoch")?,
    profile_digest: string("profile_digest")?,
    binding: RunBinding::from_value(
      object
        .get("binding")
        .ok_or(RemoteExecutionGrantError::InvalidGrant)?,
    )
    .map_err(|_| RemoteExecutionGrantError::InvalidGrant)?,
    isolation_permit_sha256: string("isolation_permit_sha256")?,
    task_sha256: string("task_sha256")?,
    definition_sha256: string("definition_sha256")?,
    capability_sha256: string("capability_sha256")?,
    targets_sha256: string("targets_sha256")?,
  })
}

fn validate_claims(
  claims: &RemoteExecutionGrantClaims,
  now_unix_millis: u64,
) -> Result<(), RemoteExecutionGrantError> {
  if claims.algorithm_version != GRANT_ALGORITHM_VERSION
    || claims.grant_sequence == 0
    || claims.signer_identity.is_empty()
    || claims.signer_identity != claims.signer_identity.trim()
    || claims.signer_identity.len() > 128
    || claims.key_revision.is_empty()
    || claims.key_revision != claims.key_revision.trim()
    || claims.key_revision.len() > 128
    || claims.issued_at_unix_millis > now_unix_millis
  {
    return Err(if claims.issued_at_unix_millis > now_unix_millis {
      RemoteExecutionGrantError::NotYetValid
    } else {
      RemoteExecutionGrantError::InvalidGrant
    });
  }
  if claims.expires_at_unix_millis <= now_unix_millis {
    return Err(RemoteExecutionGrantError::Expired);
  }
  claims
    .binding
    .validate()
    .map_err(|_| RemoteExecutionGrantError::InvalidGrant)?;
  for digest in [
    &claims.grant_id,
    &claims.session_nonce,
    &claims.challenge,
    &claims.admission_nonce,
    &claims.profile_digest,
    &claims.isolation_permit_sha256,
    &claims.task_sha256,
    &claims.definition_sha256,
    &claims.capability_sha256,
    &claims.targets_sha256,
  ] {
    require_sha256(digest)?;
  }
  if claims.deployment_epoch == 0 {
    return Err(RemoteExecutionGrantError::InvalidGrant);
  }
  Ok(())
}

fn validate_outer(grant: &SignedRemoteExecutionGrant) -> Result<(), RemoteExecutionGrantError> {
  if grant.kind != GRANT_KIND {
    return Err(RemoteExecutionGrantError::InvalidGrant);
  }
  if EvidenceKeyId::parse(&grant.key_id).is_err() {
    return Err(RemoteExecutionGrantError::InvalidKey);
  }
  if grant.signature_hex.len() != ED25519_SIGNATURE_HEX_BYTES
    || !grant
      .signature_hex
      .bytes()
      .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
  {
    return Err(RemoteExecutionGrantError::InvalidSignature);
  }
  Ok(())
}

fn require_sha256(value: &str) -> Result<(), RemoteExecutionGrantError> {
  if value.len() == 64
    && value
      .bytes()
      .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
  {
    Ok(())
  } else {
    Err(RemoteExecutionGrantError::InvalidGrant)
  }
}

fn snapshot_digest(value: &str) -> String {
  format!("{:x}", Sha256::digest(value.as_bytes()))
}

fn signing_input(claims_json: &str) -> Vec<u8> {
  let mut input = Vec::with_capacity(GRANT_DOMAIN.len() + claims_json.len() + 1);
  input.extend_from_slice(GRANT_DOMAIN);
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

fn decode_hex(value: &str) -> Result<Vec<u8>, RemoteExecutionGrantError> {
  if value.len() != ED25519_SIGNATURE_HEX_BYTES {
    return Err(RemoteExecutionGrantError::InvalidSignature);
  }
  (0..value.len())
    .step_by(2)
    .map(|index| {
      u8::from_str_radix(&value[index..index + 2], 16)
        .map_err(|_| RemoteExecutionGrantError::InvalidSignature)
    })
    .collect()
}

#[cfg(test)]
mod tests {
  use ring::rand::SystemRandom;
  use ring::signature::{Ed25519KeyPair, KeyPair};

  use super::*;

  fn prepare() -> PrepareFrame {
    PrepareFrame {
      binding: RunBinding {
        run_id: "run-1".to_owned(),
        job_id: "job-1".to_owned(),
        attempt: 1,
        fence_token: 2,
        authority_digest: "a".repeat(64),
        profile_digest: "b".repeat(64),
        deployment_epoch: 3,
        credential_revision: "credential-v1".to_owned(),
      },
      execution_grant_json: String::new(),
      isolation_permit_envelope_json: r#"{"permit":"exact"}"#.to_owned(),
      task_json: r#"{"instruction":"check"}"#.to_owned(),
      definition_json: r#"{"schedule":"0 * * * *"}"#.to_owned(),
      capability_json: r#"{"tools":["github.issue_read"]}"#.to_owned(),
      targets_json: r#"{"delivery":"slack-dm"}"#.to_owned(),
    }
  }

  fn key_pair() -> (Vec<u8>, Vec<u8>) {
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("grant key");
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("grant key pair");
    (pkcs8.as_ref().to_vec(), pair.public_key().as_ref().to_vec())
  }

  fn claims(prepare: &PrepareFrame) -> RemoteExecutionGrantClaims {
    RemoteExecutionGrantClaims::for_prepare(
      "f".repeat(64),
      1,
      "spiffe://codeoff/gateway/production".to_owned(),
      "gateway-grant-2026-07".to_owned(),
      "c".repeat(64),
      "d".repeat(64),
      "e".repeat(64),
      1_000,
      2_000,
      3,
      "b".repeat(64),
      prepare,
    )
  }

  fn expected<'a>(
    signer_identity: &'a str,
    key_revision: &'a str,
    session_nonce: &'a str,
    challenge: &'a str,
    admission_nonce: &'a str,
    profile_digest: &'a str,
    now_unix_millis: u64,
  ) -> ExpectedRemoteExecutionGrant<'a> {
    ExpectedRemoteExecutionGrant {
      signer_identity,
      key_revision,
      grant_sequence: 1,
      session_nonce,
      challenge,
      admission_nonce,
      expires_at_unix_millis: 2_000,
      deployment_epoch: 3,
      profile_digest,
      now_unix_millis,
    }
  }

  #[test]
  fn signed_grant_round_trips_and_binds_exact_prepare() {
    let (private_key, public_key) = key_pair();
    let issuer = RemoteExecutionGrantSigner::from_pkcs8(&private_key, "gateway-grant-key-1")
      .expect("grant signer");
    let consumer =
      RemoteExecutionGrantVerifier::new(public_key, "gateway-grant-key-1").expect("grant verifier");
    let prepare = prepare();
    let envelope = issuer.sign(&claims(&prepare)).expect("signed grant");
    let encoded = envelope.canonical_json();
    let decoded =
      SignedRemoteExecutionGrant::parse_canonical_json(&encoded).expect("canonical grant");
    assert_eq!(decoded, envelope);
    let verified_claims = consumer.verify(&decoded, 1_500).expect("verified grant");
    verified_claims
      .verify_prepare(
        &expected(
          "spiffe://codeoff/gateway/production",
          "gateway-grant-2026-07",
          &"c".repeat(64),
          &"d".repeat(64),
          &"e".repeat(64),
          &"b".repeat(64),
          1_500,
        ),
        &prepare,
      )
      .expect("exact prepare binding");
  }

  #[test]
  fn signed_grant_rejects_snapshot_tampering_and_cross_session_replay() {
    let (private_key, public_key) = key_pair();
    let issuer = RemoteExecutionGrantSigner::from_pkcs8(&private_key, "gateway-grant-key-1")
      .expect("grant signer");
    let consumer =
      RemoteExecutionGrantVerifier::new(public_key, "gateway-grant-key-1").expect("grant verifier");
    let original = prepare();
    let verified_claims = consumer
      .verify(
        &issuer.sign(&claims(&original)).expect("signed grant"),
        1_500,
      )
      .expect("verified grant");
    let tampered_snapshots = [
      {
        let mut value = original.clone();
        value.isolation_permit_envelope_json.push(' ');
        value
      },
      {
        let mut value = original.clone();
        value.task_json = r#"{ "instruction":"check"}"#.to_owned();
        value
      },
      {
        let mut value = original.clone();
        value.definition_json.push(' ');
        value
      },
      {
        let mut value = original.clone();
        value.capability_json.push(' ');
        value
      },
      {
        let mut value = original.clone();
        value.targets_json.push(' ');
        value
      },
      {
        let mut value = original.clone();
        value.binding.fence_token += 1;
        value
      },
    ];
    for tampered in tampered_snapshots {
      assert_eq!(
        verified_claims.verify_prepare(
          &expected(
            "spiffe://codeoff/gateway/production",
            "gateway-grant-2026-07",
            &"c".repeat(64),
            &"d".repeat(64),
            &"e".repeat(64),
            &"b".repeat(64),
            1_500,
          ),
          &tampered,
        ),
        Err(RemoteExecutionGrantError::BindingMismatch)
      );
    }
    assert_eq!(
      verified_claims.verify_prepare(
        &expected(
          "spiffe://codeoff/gateway/production",
          "gateway-grant-2026-07",
          &"f".repeat(64),
          &"d".repeat(64),
          &"e".repeat(64),
          &"b".repeat(64),
          1_500,
        ),
        &original,
      ),
      Err(RemoteExecutionGrantError::BindingMismatch)
    );
  }

  #[test]
  fn signed_grant_consumer_rejects_duplicate_and_wrong_sequence() {
    let (private_key, public_key) = key_pair();
    let issuer = RemoteExecutionGrantSigner::from_pkcs8(&private_key, "gateway-grant-key-1")
      .expect("grant signer");
    let consumer =
      RemoteExecutionGrantVerifier::new(public_key, "gateway-grant-key-1").expect("grant verifier");
    let prepare = prepare();
    let envelope = issuer.sign(&claims(&prepare)).expect("signed grant");
    let session_nonce = "c".repeat(64);
    let challenge = "d".repeat(64);
    let admission_nonce = "e".repeat(64);
    let profile_digest = "b".repeat(64);
    let expected = expected(
      "spiffe://codeoff/gateway/production",
      "gateway-grant-2026-07",
      &session_nonce,
      &challenge,
      &admission_nonce,
      &profile_digest,
      1_500,
    );
    consumer
      .verify_and_consume(&envelope, &expected, &prepare)
      .expect("first one-shot grant consumption");
    assert_eq!(
      consumer.verify_and_consume(&envelope, &expected, &prepare),
      Err(RemoteExecutionGrantError::Replayed)
    );
    let mut distinct_claims = claims(&prepare);
    distinct_claims.grant_id = "0".repeat(64);
    let distinct_envelope = issuer
      .sign(&distinct_claims)
      .expect("distinct signed grant");
    assert_eq!(
      consumer.verify_and_consume(&distinct_envelope, &expected, &prepare),
      Err(RemoteExecutionGrantError::Replayed),
      "a session consumer accepts only one grant even when the grant ID is new"
    );
    let mut wrong_sequence = expected;
    wrong_sequence.grant_sequence = 2;
    let fresh_consumer =
      RemoteExecutionGrantVerifier::new(consumer.public_key.clone(), "gateway-grant-key-1")
        .expect("fresh verifier");
    assert_eq!(
      fresh_consumer.verify_and_consume(&envelope, &wrong_sequence, &prepare),
      Err(RemoteExecutionGrantError::BindingMismatch)
    );
  }

  #[test]
  fn signed_grant_rejects_wrong_key_signature_and_time_window() {
    let (private_key, public_key) = key_pair();
    let issuer = RemoteExecutionGrantSigner::from_pkcs8(&private_key, "gateway-grant-key-1")
      .expect("grant signer");
    let consumer =
      RemoteExecutionGrantVerifier::new(public_key, "gateway-grant-key-1").expect("grant verifier");
    let envelope = issuer.sign(&claims(&prepare())).expect("signed grant");
    let mut wrong_kind = envelope.clone();
    wrong_kind.kind = "runner_evidence".to_owned();
    assert_eq!(
      consumer.verify(&wrong_kind, 1_500),
      Err(RemoteExecutionGrantError::InvalidGrant)
    );
    assert_eq!(
      consumer.verify(&envelope, 999),
      Err(RemoteExecutionGrantError::NotYetValid)
    );
    assert_eq!(
      consumer.verify(&envelope, 2_000),
      Err(RemoteExecutionGrantError::Expired)
    );

    let wrong_id = RemoteExecutionGrantVerifier::new(consumer.public_key.clone(), "other-key")
      .expect("wrong key ID verifier");
    assert_eq!(
      wrong_id.verify(&envelope, 1_500),
      Err(RemoteExecutionGrantError::InvalidKey)
    );
    let mut bad_signature = envelope;
    let replacement = if &bad_signature.signature_hex[..2] == "00" {
      "01"
    } else {
      "00"
    };
    bad_signature.signature_hex.replace_range(0..2, replacement);
    assert_eq!(
      consumer.verify(&bad_signature, 1_500),
      Err(RemoteExecutionGrantError::InvalidSignature)
    );
  }

  #[test]
  fn signed_grant_decoder_rejects_noncanonical_unknown_and_oversize_input() {
    assert_eq!(
      SignedRemoteExecutionGrant::parse_canonical_json(
        r#"{ "claims_json":"{}","key_id":"key-1","signature_hex":"00"}"#
      ),
      Err(RemoteExecutionGrantError::NonCanonical)
    );
    assert_eq!(
      SignedRemoteExecutionGrant::parse_canonical_json(
        r#"{"claims_json":"{}","extra":true,"key_id":"key-1","signature_hex":"00"}"#
      ),
      Err(RemoteExecutionGrantError::InvalidGrant)
    );
    assert_eq!(
      SignedRemoteExecutionGrant::parse_canonical_json(&"x".repeat(MAX_GRANT_BYTES + 1)),
      Err(RemoteExecutionGrantError::TooLarge)
    );
  }
}
