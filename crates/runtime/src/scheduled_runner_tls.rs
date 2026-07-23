//! TLS and framed-I/O authority for the scheduled runner transport.
//!
//! The gateway terminates mutual TLS in-process.  Certificate-chain verification is delegated to
//! rustls/webpki; this module adds the deployment-specific exact SPKI check and binds the
//! canonical runner workload identity to the TLS exporter used by the session challenge.

use std::ffi::OsStr;
use std::fmt;
use std::fs::File;
use std::io::{self, BufReader};
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
const TLS_EXPORTER_BYTES: usize = 32;
const FRAME_LENGTH_BYTES: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduledRunnerTlsIdentity {
  pub workload_identity: RunnerWorkloadIdentity,
  pub client_spki_sha256: String,
}

impl ScheduledRunnerTlsIdentity {
  /// Parses and binds the configured SPIFFE workload identity to the expected client SPKI.
  pub fn new(
    workload_identity: &str,
    client_spki_sha256: &str,
  ) -> Result<Self, ScheduledRunnerTlsError> {
    let workload_identity = RunnerWorkloadIdentity::parse(workload_identity)
      .map_err(|_| ScheduledRunnerTlsError::InvalidWorkloadIdentity)?;
    if !is_lowercase_sha256(client_spki_sha256) {
      return Err(ScheduledRunnerTlsError::InvalidSpkiFingerprint);
    }
    Ok(Self {
      workload_identity,
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
  InvalidWorkloadIdentity,
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
  expected_identity: ScheduledRunnerTlsIdentity,
  io_policy: ScheduledRunnerIoPolicy,
}

impl ScheduledRunnerTlsServer {
  /// Loads root-owned TLS material without following symlinks and constructs a TLS1.3-only server.
  pub fn load(
    paths: &ScheduledRunnerTlsPaths,
    expected_identity: ScheduledRunnerTlsIdentity,
    io_policy: ScheduledRunnerIoPolicy,
  ) -> Result<Self, ScheduledRunnerTlsError> {
    let io_policy = io_policy.validate()?;
    let certificates = load_certificates(&paths.certificate_chain)?;
    let private_key = load_private_key(&paths.private_key)?;
    let roots = load_roots(&paths.trust_bundle)?;
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
      expected_identity,
      io_policy,
    })
  }

  /// Completes mutual TLS, checks the actual validated client SPKI, and derives channel binding.
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
    if client_spki_sha256 != self.expected_identity.client_spki_sha256 {
      return Err(ScheduledRunnerTlsError::PeerSpkiMismatch);
    }
    let channel_binding = export_server_channel_binding(connection)?;
    Ok(ScheduledRunnerServerConnection {
      identity: self.expected_identity.clone(),
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
    let io_policy = io_policy.validate()?;
    let certificates = load_certificates(&paths.certificate_chain)?;
    let private_key = load_private_key(&paths.private_key)?;
    let roots = load_roots(&paths.trust_bundle)?;
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
  pub identity: ScheduledRunnerTlsIdentity,
  pub channel_binding: [u8; TLS_EXPORTER_BYTES],
  pub framed: ScheduledRunnerFramed<ServerTlsStream<TcpStream>>,
}

pub struct ScheduledRunnerClientConnection {
  pub channel_binding: [u8; TLS_EXPORTER_BYTES],
  pub framed: ScheduledRunnerFramed<ClientTlsStream<TcpStream>>,
}

pub struct ScheduledRunnerFramed<S> {
  stream: S,
  read_timeout: Duration,
  write_timeout: Duration,
}

impl<S> ScheduledRunnerFramed<S> {
  fn new(stream: S, read_timeout: Duration, write_timeout: Duration) -> Self {
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

fn load_roots(path: &Path) -> Result<RootCertStore, ScheduledRunnerTlsError> {
  let mut roots = RootCertStore::empty();
  for certificate in load_certificates(path)? {
    roots
      .add(certificate)
      .map_err(|_| ScheduledRunnerTlsError::CertificateRejected)?;
  }
  if roots.is_empty() {
    return Err(ScheduledRunnerTlsError::CertificateRejected);
  }
  Ok(roots)
}

fn load_certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>, ScheduledRunnerTlsError> {
  let file = open_root_owned_file(path)?;
  let certificates = CertificateDer::pem_reader_iter(BufReader::new(file))
    .collect::<Result<Vec<_>, _>>()
    .map_err(|_| ScheduledRunnerTlsError::CertificateRejected)?;
  if certificates.is_empty() {
    return Err(ScheduledRunnerTlsError::CertificateRejected);
  }
  Ok(certificates)
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, ScheduledRunnerTlsError> {
  let file = open_root_owned_file(path)?;
  PrivateKeyDer::from_pem_reader(BufReader::new(file))
    .map_err(|_| ScheduledRunnerTlsError::PrivateKeyRejected)
}

fn open_root_owned_file(path: &Path) -> Result<File, ScheduledRunnerTlsError> {
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
    verify_root_owned_component(&opened, component, final_component)?;
    current = opened;
  }
  Ok(current)
}

fn verify_root_owned_component(
  file: &File,
  _name: impl AsRef<OsStr>,
  final_component: bool,
) -> Result<(), ScheduledRunnerTlsError> {
  let stat = fstat(file).map_err(|_| ScheduledRunnerTlsError::FileRejected("metadata"))?;
  if stat.st_uid != 0 || stat.st_gid != 0 {
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
  if final_component && stat.st_mode & 0o077 != 0 {
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
