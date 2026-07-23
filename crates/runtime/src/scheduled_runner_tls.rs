//! TLS and framed-I/O authority for the scheduled runner transport.
//!
//! The gateway terminates mutual TLS in-process.  Certificate-chain verification is delegated to
//! rustls/webpki; this module adds the deployment-specific exact SPKI check. Trusted static
//! configuration maps that pinned key to one canonical application runner identifier, and the
//! TLS exporter binds the resulting authorization mapping to the session challenge. The
//! application identifier is not asserted to be a certificate URI SAN.

use std::ffi::OsStr;
use std::fmt;
use std::fs::File;
use std::io::{self, BufReader, Read};
use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use codeoff_core::RunnerWorkloadIdentity;
use nix::fcntl::{OFlag, openat};
use nix::sys::stat::{Mode, fstat};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::server::{ParsedCertificate, WebPkiClientVerifier};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream as ClientTlsStream;
use tokio_rustls::server::TlsStream as ServerTlsStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::scheduled_remote_protocol::{MAX_REMOTE_FRAME_BYTES, RemoteFrame, RemoteProtocolError};

pub const RUNNER_TLS_EXPORTER_LABEL: &[u8] = b"EXPORTER-codeoff-scheduled-runner-v1";
const SESSION_NONCE_DOMAIN: &[u8] = b"codeoff-runner-session-nonce-v1";
const SESSION_CHALLENGE_DOMAIN: &[u8] = b"codeoff-runner-session-challenge-v1";
const TLS_EXPORTER_BYTES: usize = 32;
const FRAME_LENGTH_BYTES: usize = 4;
const MAX_TLS_PEM_BYTES: u64 = 256 * 1024;
const MAX_TLS_PRIVATE_KEY_BYTES: u64 = 64 * 1024;
const MAX_TLS_CERTIFICATES: usize = 16;
const ROOT_FILE_OWNER: ExpectedFileOwner = ExpectedFileOwner { uid: 0, gid: 0 };

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ExpectedFileOwner {
  uid: u32,
  gid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduledRunnerAuthorizedPeer {
  pub runner_identity: RunnerWorkloadIdentity,
  pub client_spki_sha256: String,
}

impl ScheduledRunnerAuthorizedPeer {
  /// Parses the configured application runner identifier and binds it to one expected client key.
  pub fn new(
    workload_identity: &str,
    client_spki_sha256: &str,
  ) -> Result<Self, ScheduledRunnerTlsError> {
    let runner_identity = RunnerWorkloadIdentity::parse(workload_identity)
      .map_err(|_| ScheduledRunnerTlsError::InvalidRunnerIdentifier)?;
    if !is_lowercase_sha256(client_spki_sha256) {
      return Err(ScheduledRunnerTlsError::InvalidSpkiFingerprint);
    }
    Ok(Self {
      runner_identity,
      client_spki_sha256: client_spki_sha256.to_owned(),
    })
  }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduledRunnerTlsPaths {
  pub certificate_chain: PathBuf,
  pub private_key: PathBuf,
  pub trust_bundle: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScheduledRunnerIoPolicy {
  pub handshake_timeout: Duration,
  pub read_timeout: Duration,
  pub write_timeout: Duration,
}

impl ScheduledRunnerIoPolicy {
  pub fn validate(self) -> Result<Self, ScheduledRunnerTlsError> {
    if self.handshake_timeout.is_zero()
      || self.read_timeout.is_zero()
      || self.write_timeout.is_zero()
    {
      return Err(ScheduledRunnerTlsError::InvalidTimeout);
    }
    Ok(self)
  }
}

#[derive(Debug)]
pub enum ScheduledRunnerTlsError {
  InvalidTimeout,
  InvalidRunnerIdentifier,
  InvalidSpkiFingerprint,
  InvalidServerName,
  InvalidPath,
  FileRejected(&'static str),
  CertificateRejected,
  PrivateKeyRejected,
  TlsConfiguration,
  TlsHandshake,
  PeerCertificateMissing,
  PeerSpkiMismatch,
  ExporterFailed,
  FrameTooLarge,
  FrameTruncated,
  FrameTimeout,
  Protocol(RemoteProtocolError),
  Io(io::Error),
}

impl fmt::Display for ScheduledRunnerTlsError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(formatter, "{self:?}")
  }
}

impl std::error::Error for ScheduledRunnerTlsError {}

impl From<io::Error> for ScheduledRunnerTlsError {
  fn from(error: io::Error) -> Self {
    Self::Io(error)
  }
}

impl From<RemoteProtocolError> for ScheduledRunnerTlsError {
  fn from(error: RemoteProtocolError) -> Self {
    Self::Protocol(error)
  }
}

pub struct ScheduledRunnerTlsServer {
  acceptor: TlsAcceptor,
  expected_peer: ScheduledRunnerAuthorizedPeer,
  io_policy: ScheduledRunnerIoPolicy,
}

impl ScheduledRunnerTlsServer {
  /// Loads root-owned TLS material without following symlinks and constructs a TLS1.3-only server.
  pub fn load(
    paths: &ScheduledRunnerTlsPaths,
    expected_peer: ScheduledRunnerAuthorizedPeer,
    io_policy: ScheduledRunnerIoPolicy,
  ) -> Result<Self, ScheduledRunnerTlsError> {
    Self::load_with_owner(paths, expected_peer, io_policy, ROOT_FILE_OWNER)
  }

  fn load_with_owner(
    paths: &ScheduledRunnerTlsPaths,
    expected_peer: ScheduledRunnerAuthorizedPeer,
    io_policy: ScheduledRunnerIoPolicy,
    expected_owner: ExpectedFileOwner,
  ) -> Result<Self, ScheduledRunnerTlsError> {
    let io_policy = io_policy.validate()?;
    let certificates = load_certificates(&paths.certificate_chain, expected_owner)?;
    let private_key = load_private_key(&paths.private_key, expected_owner)?;
    let roots = load_roots(&paths.trust_bundle, expected_owner)?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
      .build()
      .map_err(|_| ScheduledRunnerTlsError::TlsConfiguration)?;
    let config = ServerConfig::builder_with_provider(provider)
      .with_protocol_versions(&[&rustls::version::TLS13])
      .map_err(|_| ScheduledRunnerTlsError::TlsConfiguration)?
      .with_client_cert_verifier(verifier)
      .with_single_cert(certificates, private_key)
      .map_err(|_| ScheduledRunnerTlsError::TlsConfiguration)?;
    Ok(Self {
      acceptor: TlsAcceptor::from(Arc::new(config)),
      expected_peer,
      io_policy,
    })
  }

  /// Completes mutual TLS, authorizes the actual validated client SPKI, and derives channel binding.
  pub async fn accept(
    &self,
    stream: TcpStream,
  ) -> Result<ScheduledRunnerServerConnection, ScheduledRunnerTlsError> {
    let stream = tokio::time::timeout(
      self.io_policy.handshake_timeout,
      self.acceptor.accept(stream),
    )
    .await
    .map_err(|_| ScheduledRunnerTlsError::FrameTimeout)?
    .map_err(|_| ScheduledRunnerTlsError::TlsHandshake)?;
    let connection = stream.get_ref().1;
    let peer = connection
      .peer_certificates()
      .and_then(|certificates| certificates.first())
      .ok_or(ScheduledRunnerTlsError::PeerCertificateMissing)?;
    let parsed = ParsedCertificate::try_from(peer)
      .map_err(|_| ScheduledRunnerTlsError::CertificateRejected)?;
    let client_spki_sha256 = sha256_hex(parsed.subject_public_key_info().as_ref());
    if client_spki_sha256 != self.expected_peer.client_spki_sha256 {
      return Err(ScheduledRunnerTlsError::PeerSpkiMismatch);
    }
    let channel_binding = export_server_channel_binding(connection)?;
    Ok(ScheduledRunnerServerConnection {
      authorized_peer: self.expected_peer.clone(),
      channel_binding,
      framed: ScheduledRunnerFramed::new(
        stream,
        self.io_policy.read_timeout,
        self.io_policy.write_timeout,
      ),
    })
  }
}

pub struct ScheduledRunnerTlsClient {
  connector: TlsConnector,
  server_name: ServerName<'static>,
  io_policy: ScheduledRunnerIoPolicy,
}

impl ScheduledRunnerTlsClient {
  /// Loads root-owned client material and constructs a TLS1.3-only mutual-TLS client.
  pub fn load(
    paths: &ScheduledRunnerTlsPaths,
    server_name: &str,
    io_policy: ScheduledRunnerIoPolicy,
  ) -> Result<Self, ScheduledRunnerTlsError> {
    Self::load_with_owner(paths, server_name, io_policy, ROOT_FILE_OWNER)
  }

  /// Loads client material owned by the dedicated non-root control identity.
  #[allow(clippy::similar_names)]
  pub fn load_for_owner(
    paths: &ScheduledRunnerTlsPaths,
    server_name: &str,
    io_policy: ScheduledRunnerIoPolicy,
    expected_uid: u32,
    expected_gid: u32,
  ) -> Result<Self, ScheduledRunnerTlsError> {
    Self::load_with_owner(
      paths,
      server_name,
      io_policy,
      ExpectedFileOwner {
        uid: expected_uid,
        gid: expected_gid,
      },
    )
  }

  fn load_with_owner(
    paths: &ScheduledRunnerTlsPaths,
    server_name: &str,
    io_policy: ScheduledRunnerIoPolicy,
    expected_owner: ExpectedFileOwner,
  ) -> Result<Self, ScheduledRunnerTlsError> {
    let io_policy = io_policy.validate()?;
    let certificates = load_certificates(&paths.certificate_chain, expected_owner)?;
    let private_key = load_private_key(&paths.private_key, expected_owner)?;
    let roots = load_roots(&paths.trust_bundle, expected_owner)?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
      .build()
      .map_err(|_| ScheduledRunnerTlsError::TlsConfiguration)?;
    let config = ClientConfig::builder_with_provider(provider)
      .with_protocol_versions(&[&rustls::version::TLS13])
      .map_err(|_| ScheduledRunnerTlsError::TlsConfiguration)?
      .dangerous()
      .with_custom_certificate_verifier(verifier)
      .with_client_auth_cert(certificates, private_key)
      .map_err(|_| ScheduledRunnerTlsError::TlsConfiguration)?;
    let server_name = ServerName::try_from(server_name.to_owned())
      .map_err(|_| ScheduledRunnerTlsError::InvalidServerName)?;
    Ok(Self {
      connector: TlsConnector::from(Arc::new(config)),
      server_name,
      io_policy,
    })
  }

  pub async fn connect(
    &self,
    address: SocketAddr,
  ) -> Result<ScheduledRunnerClientConnection, ScheduledRunnerTlsError> {
    let tcp = tokio::time::timeout(
      self.io_policy.handshake_timeout,
      TcpStream::connect(address),
    )
    .await
    .map_err(|_| ScheduledRunnerTlsError::FrameTimeout)??;
    let stream = tokio::time::timeout(
      self.io_policy.handshake_timeout,
      self.connector.connect(self.server_name.clone(), tcp),
    )
    .await
    .map_err(|_| ScheduledRunnerTlsError::FrameTimeout)?
    .map_err(|_| ScheduledRunnerTlsError::TlsHandshake)?;
    let channel_binding = export_client_channel_binding(stream.get_ref().1)?;
    Ok(ScheduledRunnerClientConnection {
      channel_binding,
      framed: ScheduledRunnerFramed::new(
        stream,
        self.io_policy.read_timeout,
        self.io_policy.write_timeout,
      ),
    })
  }
}

pub struct ScheduledRunnerServerConnection {
  pub authorized_peer: ScheduledRunnerAuthorizedPeer,
  pub channel_binding: [u8; TLS_EXPORTER_BYTES],
  pub framed: ScheduledRunnerFramed<ServerTlsStream<TcpStream>>,
}

pub struct ScheduledRunnerClientConnection {
  pub channel_binding: [u8; TLS_EXPORTER_BYTES],
  pub framed: ScheduledRunnerFramed<ClientTlsStream<TcpStream>>,
}

#[must_use]
pub fn session_nonce(channel_binding: &[u8; TLS_EXPORTER_BYTES]) -> String {
  domain_bound_sha256(SESSION_NONCE_DOMAIN, channel_binding)
}

#[must_use]
pub fn session_challenge(channel_binding: &[u8; TLS_EXPORTER_BYTES]) -> String {
  domain_bound_sha256(SESSION_CHALLENGE_DOMAIN, channel_binding)
}

pub struct ScheduledRunnerFramed<S> {
  stream: S,
  read_timeout: Duration,
  write_timeout: Duration,
}

impl<S> ScheduledRunnerFramed<S> {
  pub(crate) fn new(stream: S, read_timeout: Duration, write_timeout: Duration) -> Self {
    Self {
      stream,
      read_timeout,
      write_timeout,
    }
  }

  pub fn into_inner(self) -> S {
    self.stream
  }
}

impl<S> ScheduledRunnerFramed<S>
where
  S: AsyncRead + AsyncWrite + Unpin,
{
  /// Reads one length-delimited frame. Clean EOF is accepted only before a new frame begins.
  pub async fn read_frame(
    &mut self,
    now_unix_millis: u64,
  ) -> Result<Option<RemoteFrame>, ScheduledRunnerTlsError> {
    let mut length = [0_u8; FRAME_LENGTH_BYTES];
    let first = tokio::time::timeout(self.read_timeout, self.stream.read(&mut length[..1]))
      .await
      .map_err(|_| ScheduledRunnerTlsError::FrameTimeout)??;
    if first == 0 {
      return Ok(None);
    }
    tokio::time::timeout(self.read_timeout, self.stream.read_exact(&mut length[1..]))
      .await
      .map_err(|_| ScheduledRunnerTlsError::FrameTimeout)?
      .map_err(|error| {
        if error.kind() == io::ErrorKind::UnexpectedEof {
          ScheduledRunnerTlsError::FrameTruncated
        } else {
          ScheduledRunnerTlsError::Io(error)
        }
      })?;
    let length = usize::try_from(u32::from_be_bytes(length))
      .map_err(|_| ScheduledRunnerTlsError::FrameTooLarge)?;
    if length == 0 || length > MAX_REMOTE_FRAME_BYTES {
      return Err(ScheduledRunnerTlsError::FrameTooLarge);
    }
    let mut encoded = vec![0_u8; length];
    tokio::time::timeout(self.read_timeout, self.stream.read_exact(&mut encoded))
      .await
      .map_err(|_| ScheduledRunnerTlsError::FrameTimeout)?
      .map_err(|error| {
        if error.kind() == io::ErrorKind::UnexpectedEof {
          ScheduledRunnerTlsError::FrameTruncated
        } else {
          ScheduledRunnerTlsError::Io(error)
        }
      })?;
    Ok(Some(RemoteFrame::decode(&encoded, now_unix_millis)?))
  }

  pub async fn write_frame(&mut self, frame: &RemoteFrame) -> Result<(), ScheduledRunnerTlsError> {
    let encoded = frame.encode()?;
    let length =
      u32::try_from(encoded.len()).map_err(|_| ScheduledRunnerTlsError::FrameTooLarge)?;
    let write = async {
      self.stream.write_all(&length.to_be_bytes()).await?;
      self.stream.write_all(&encoded).await?;
      self.stream.flush().await
    };
    tokio::time::timeout(self.write_timeout, write)
      .await
      .map_err(|_| ScheduledRunnerTlsError::FrameTimeout)??;
    Ok(())
  }
}

fn load_roots(
  path: &Path,
  expected_owner: ExpectedFileOwner,
) -> Result<RootCertStore, ScheduledRunnerTlsError> {
  let mut roots = RootCertStore::empty();
  for certificate in load_certificates(path, expected_owner)? {
    roots
      .add(certificate)
      .map_err(|_| ScheduledRunnerTlsError::CertificateRejected)?;
  }
  if roots.is_empty() {
    return Err(ScheduledRunnerTlsError::CertificateRejected);
  }
  Ok(roots)
}

/// Loads a bounded root-owned 0400 file through the anchored no-symlink path walker.
pub fn load_root_owned_bounded_file(
  path: &Path,
  max_bytes: u64,
) -> Result<Vec<u8>, ScheduledRunnerTlsError> {
  let mut file = open_owned_file(path, ROOT_FILE_OWNER, max_bytes)?;
  let mut bytes = Vec::new();
  file.read_to_end(&mut bytes)?;
  if bytes.is_empty() || u64::try_from(bytes.len()).map_or(true, |len| len > max_bytes) {
    return Err(ScheduledRunnerTlsError::FileRejected("size"));
  }
  Ok(bytes)
}

fn load_certificates(
  path: &Path,
  expected_owner: ExpectedFileOwner,
) -> Result<Vec<CertificateDer<'static>>, ScheduledRunnerTlsError> {
  let file = open_owned_file(path, expected_owner, MAX_TLS_PEM_BYTES)?;
  let certificates = CertificateDer::pem_reader_iter(BufReader::new(file))
    .collect::<Result<Vec<_>, _>>()
    .map_err(|_| ScheduledRunnerTlsError::CertificateRejected)?;
  if certificates.is_empty() {
    return Err(ScheduledRunnerTlsError::CertificateRejected);
  }
  if certificates.len() > MAX_TLS_CERTIFICATES {
    return Err(ScheduledRunnerTlsError::CertificateRejected);
  }
  Ok(certificates)
}

fn load_private_key(
  path: &Path,
  expected_owner: ExpectedFileOwner,
) -> Result<PrivateKeyDer<'static>, ScheduledRunnerTlsError> {
  let file = open_owned_file(path, expected_owner, MAX_TLS_PRIVATE_KEY_BYTES)?;
  PrivateKeyDer::from_pem_reader(BufReader::new(file))
    .map_err(|_| ScheduledRunnerTlsError::PrivateKeyRejected)
}

fn open_owned_file(
  path: &Path,
  expected_owner: ExpectedFileOwner,
  max_bytes: u64,
) -> Result<File, ScheduledRunnerTlsError> {
  if !path.is_absolute() {
    return Err(ScheduledRunnerTlsError::InvalidPath);
  }
  let mut current = File::open("/")?;
  let components = path
    .components()
    .filter_map(|component| match component {
      Component::RootDir => None,
      Component::Normal(value) => Some(Ok(value)),
      _ => Some(Err(ScheduledRunnerTlsError::InvalidPath)),
    })
    .collect::<Result<Vec<_>, _>>()?;
  if components.is_empty() {
    return Err(ScheduledRunnerTlsError::InvalidPath);
  }
  for (index, component) in components.iter().enumerate() {
    let final_component = index + 1 == components.len();
    let flags = if final_component {
      OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC
    } else {
      OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC
    };
    let opened = openat(&current, *component, flags, Mode::empty())
      .map_err(|_| ScheduledRunnerTlsError::FileRejected("open"))?;
    let opened = File::from(opened);
    verify_owned_component(
      &opened,
      component,
      final_component,
      expected_owner,
      max_bytes,
    )?;
    current = opened;
  }
  Ok(current)
}

fn verify_owned_component(
  file: &File,
  _name: impl AsRef<OsStr>,
  final_component: bool,
  expected_owner: ExpectedFileOwner,
  max_bytes: u64,
) -> Result<(), ScheduledRunnerTlsError> {
  let stat = fstat(file).map_err(|_| ScheduledRunnerTlsError::FileRejected("metadata"))?;
  let expected_component_owner =
    stat.st_uid == expected_owner.uid && stat.st_gid == expected_owner.gid;
  let safe_root_ancestor = !final_component && stat.st_uid == 0 && stat.st_gid == 0;
  if !expected_component_owner && !safe_root_ancestor {
    return Err(ScheduledRunnerTlsError::FileRejected("owner"));
  }
  let file_type = file
    .metadata()
    .map_err(|_| ScheduledRunnerTlsError::FileRejected("metadata"))?
    .file_type();
  if final_component && !file_type.is_file() {
    return Err(ScheduledRunnerTlsError::FileRejected("type"));
  }
  if !final_component && !file_type.is_dir() {
    return Err(ScheduledRunnerTlsError::FileRejected("type"));
  }
  if final_component
    && (stat.st_mode & 0o777 != 0o400
      || u64::try_from(stat.st_size).map_or(true, |size| size > max_bytes))
  {
    return Err(ScheduledRunnerTlsError::FileRejected("permissions"));
  }
  let sticky_directory = !final_component && stat.st_mode & Mode::S_ISVTX.bits() != 0;
  if !final_component && stat.st_mode & 0o022 != 0 && !sticky_directory {
    return Err(ScheduledRunnerTlsError::FileRejected(
      "directory_permissions",
    ));
  }
  Ok(())
}

fn export_server_channel_binding(
  connection: &rustls::ServerConnection,
) -> Result<[u8; TLS_EXPORTER_BYTES], ScheduledRunnerTlsError> {
  let mut output = [0_u8; TLS_EXPORTER_BYTES];
  connection
    .export_keying_material(&mut output, RUNNER_TLS_EXPORTER_LABEL, None)
    .map_err(|_| ScheduledRunnerTlsError::ExporterFailed)?;
  Ok(output)
}

fn export_client_channel_binding(
  connection: &rustls::ClientConnection,
) -> Result<[u8; TLS_EXPORTER_BYTES], ScheduledRunnerTlsError> {
  let mut output = [0_u8; TLS_EXPORTER_BYTES];
  connection
    .export_keying_material(&mut output, RUNNER_TLS_EXPORTER_LABEL, None)
    .map_err(|_| ScheduledRunnerTlsError::ExporterFailed)?;
  Ok(output)
}

fn is_lowercase_sha256(value: &str) -> bool {
  value.len() == 64
    && value
      .bytes()
      .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sha256_hex(bytes: &[u8]) -> String {
  format!("{:x}", Sha256::digest(bytes))
}

fn domain_bound_sha256(domain: &[u8], value: &[u8]) -> String {
  let mut digest = Sha256::new();
  digest.update(domain);
  digest.update([0]);
  digest.update(value);
  format!("{:x}", digest.finalize())
}

#[cfg(all(test, unix))]
#[path = "scheduled_runner_tls_integration_tests.rs"]
mod integration_tests;

#[cfg(test)]
mod tests {
  use super::*;
  use crate::scheduled_remote_protocol::{REMOTE_PROTOCOL_VERSION, ReadyFrame, RemoteMessage};
  use std::fs;
  use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
  use tokio::io::{AsyncWriteExt, duplex};

  const NOW: u64 = 1_000_000;

  fn ready() -> RemoteFrame {
    RemoteFrame {
      version: REMOTE_PROTOCOL_VERSION,
      session_nonce: "a".repeat(64),
      sequence: 1,
      message: RemoteMessage::Ready(ReadyFrame {
        signed_evidence_json: "{}".to_owned(),
        challenge: "b".repeat(64),
        ready_until_unix_millis: NOW + 5_000,
        attested_profile_json: r#"{"schema_version":1}"#.to_owned(),
        attested_profile_digest: "1".repeat(64),
        deployment_epoch: 1,
        profile_digest: "c".repeat(64),
        gateway_image_digest: format!("sha256:{}", "d".repeat(64)),
        runner_image_digest: format!("sha256:{}", "e".repeat(64)),
        runner_workload_identity: "spiffe://codeoff/runner/production".to_owned(),
        runner_client_cert_public_key_fingerprint: "f".repeat(64),
        credential_revision: "credential-v1".to_owned(),
      }),
    }
  }

  fn framed(stream: tokio::io::DuplexStream) -> ScheduledRunnerFramed<tokio::io::DuplexStream> {
    ScheduledRunnerFramed::new(stream, Duration::from_millis(20), Duration::from_millis(20))
  }

  #[tokio::test]
  async fn framed_io_round_trips_canonical_frame_and_accepts_only_clean_boundary_eof() {
    let (writer_stream, reader_stream) = duplex(MAX_REMOTE_FRAME_BYTES + FRAME_LENGTH_BYTES);
    let mut writer = framed(writer_stream);
    let mut reader = framed(reader_stream);
    writer.write_frame(&ready()).await.expect("frame write");
    assert_eq!(
      reader.read_frame(NOW).await.expect("frame read"),
      Some(ready())
    );
    drop(writer);
    assert_eq!(reader.read_frame(NOW).await.expect("clean EOF"), None);
  }

  #[tokio::test]
  async fn framed_io_rejects_truncated_length_body_and_oversized_length() {
    for bytes in [vec![0, 0], [4_u32.to_be_bytes().as_slice(), b"{}"].concat()] {
      let (mut writer, reader_stream) = duplex(32);
      writer.write_all(&bytes).await.expect("partial frame write");
      drop(writer);
      assert!(matches!(
        framed(reader_stream).read_frame(NOW).await,
        Err(ScheduledRunnerTlsError::FrameTruncated)
      ));
    }

    let (mut writer, reader_stream) = duplex(32);
    let oversized = u32::try_from(MAX_REMOTE_FRAME_BYTES + 1).expect("bounded test length");
    writer
      .write_all(&oversized.to_be_bytes())
      .await
      .expect("oversized length write");
    assert!(matches!(
      framed(reader_stream).read_frame(NOW).await,
      Err(ScheduledRunnerTlsError::FrameTooLarge)
    ));
  }

  #[tokio::test]
  async fn framed_io_times_out_at_length_and_body_boundaries() {
    let (_writer, reader_stream) = duplex(32);
    assert!(matches!(
      framed(reader_stream).read_frame(NOW).await,
      Err(ScheduledRunnerTlsError::FrameTimeout)
    ));

    let (mut writer, reader_stream) = duplex(32);
    writer
      .write_all(&4_u32.to_be_bytes())
      .await
      .expect("length write");
    assert!(matches!(
      framed(reader_stream).read_frame(NOW).await,
      Err(ScheduledRunnerTlsError::FrameTimeout)
    ));
  }

  #[tokio::test]
  async fn framed_io_rejects_noncanonical_and_trailing_json() {
    for encoded in [
      format!(
        " {}",
        String::from_utf8(ready().encode().expect("encode")).expect("UTF-8")
      ),
      format!(
        "{}\n",
        String::from_utf8(ready().encode().expect("encode")).expect("UTF-8")
      ),
    ] {
      let (mut writer, reader_stream) = duplex(MAX_REMOTE_FRAME_BYTES + FRAME_LENGTH_BYTES);
      writer
        .write_all(
          &[
            u32::try_from(encoded.len())
              .expect("bounded frame")
              .to_be_bytes()
              .as_slice(),
            encoded.as_bytes(),
          ]
          .concat(),
        )
        .await
        .expect("noncanonical write");
      assert!(matches!(
        framed(reader_stream).read_frame(NOW).await,
        Err(ScheduledRunnerTlsError::Protocol(
          RemoteProtocolError::NonCanonicalJson
        ))
      ));
    }
  }

  #[test]
  fn secure_file_loader_enforces_explicit_owner_mode_and_no_symlinks() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let path = temp.path().join("tls.pem");
    fs::write(&path, b"test").expect("fixture write");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).expect("fixture permissions");
    let metadata = fs::metadata(temp.path()).expect("fixture metadata");
    let owner = ExpectedFileOwner {
      uid: metadata.uid(),
      gid: metadata.gid(),
    };
    open_owned_file(&path, owner, MAX_TLS_PEM_BYTES).expect("matching owner");

    let wrong_owner = ExpectedFileOwner {
      uid: owner.uid.saturating_add(1),
      gid: owner.gid,
    };
    assert!(matches!(
      open_owned_file(&path, wrong_owner, MAX_TLS_PEM_BYTES),
      Err(ScheduledRunnerTlsError::FileRejected("owner"))
    ));

    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("loose permissions");
    assert!(matches!(
      open_owned_file(&path, owner, MAX_TLS_PEM_BYTES),
      Err(ScheduledRunnerTlsError::FileRejected("permissions"))
    ));

    fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).expect("restore permissions");
    let link = temp.path().join("tls-link.pem");
    symlink(&path, &link).expect("fixture symlink");
    assert!(matches!(
      open_owned_file(&link, owner, MAX_TLS_PEM_BYTES),
      Err(ScheduledRunnerTlsError::FileRejected("open"))
    ));
  }
}
