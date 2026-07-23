#![cfg(unix)]

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::{
  ExpectedFileOwner, ScheduledRunnerAuthorizedPeer, ScheduledRunnerIoPolicy,
  ScheduledRunnerTlsClient, ScheduledRunnerTlsError, ScheduledRunnerTlsPaths,
  ScheduledRunnerTlsServer,
};
use crate::scheduled_remote_protocol::{
  AdmissionFrame, REMOTE_PROTOCOL_VERSION, ReadyFrame, RemoteFrame, RemoteMessage,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

const SERVER_NAME: &str = "gateway.codeoff.test";
const WORKLOAD_IDENTITY: &str = "spiffe://codeoff/runner/production";

struct CertificateFixture {
  temp: TempDir,
  ca_certificate: PathBuf,
  server_certificate: PathBuf,
  server_key: PathBuf,
  client_certificate: PathBuf,
  client_key: PathBuf,
  client_spki_sha256: String,
}

impl CertificateFixture {
  #[allow(
    clippy::too_many_lines,
    reason = "keeps one ephemeral OpenSSL CA/server/client fixture lifecycle auditable"
  )]
  fn new(label: &str) -> Self {
    let temp = tempfile::Builder::new()
      .prefix("codeoff-runner-tls-")
      .tempdir()
      .expect("temporary certificate directory");
    let root = temp.path();
    let ca_key = root.join("ca.key.pem");
    let ca_certificate = root.join("ca.cert.pem");
    let server_key = root.join("server.key.pem");
    let server_request = root.join("server.csr.pem");
    let server_certificate = root.join("server.cert.pem");
    let server_extensions = root.join("server.ext");
    let client_key = root.join("client.key.pem");
    let client_request = root.join("client.csr.pem");
    let client_certificate = root.join("client.cert.pem");
    let client_extensions = root.join("client.ext");
    let client_spki = root.join("client.spki.der");

    openssl(&["genpkey", "-algorithm", "ED25519", "-out", path(&ca_key)]);
    restrict(&ca_key);
    openssl(&[
      "req",
      "-x509",
      "-new",
      "-key",
      path(&ca_key),
      "-out",
      path(&ca_certificate),
      "-days",
      "1",
      "-subj",
      &format!("/CN=codeoff-{label}-ca"),
    ]);

    openssl(&[
      "genpkey",
      "-algorithm",
      "ED25519",
      "-out",
      path(&server_key),
    ]);
    restrict(&server_key);
    openssl(&[
      "req",
      "-new",
      "-key",
      path(&server_key),
      "-out",
      path(&server_request),
      "-subj",
      &format!("/CN=codeoff-{label}-gateway"),
    ]);
    fs::write(
      &server_extensions,
      format!(
        "basicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:{SERVER_NAME}\n"
      ),
    )
    .expect("server extensions");
    openssl(&[
      "x509",
      "-req",
      "-in",
      path(&server_request),
      "-CA",
      path(&ca_certificate),
      "-CAkey",
      path(&ca_key),
      "-CAcreateserial",
      "-out",
      path(&server_certificate),
      "-days",
      "1",
      "-extfile",
      path(&server_extensions),
    ]);

    openssl(&[
      "genpkey",
      "-algorithm",
      "ED25519",
      "-out",
      path(&client_key),
    ]);
    restrict(&client_key);
    openssl(&[
      "req",
      "-new",
      "-key",
      path(&client_key),
      "-out",
      path(&client_request),
      "-subj",
      &format!("/CN=codeoff-{label}-runner"),
    ]);
    fs::write(
      &client_extensions,
      "basicConstraints=CA:FALSE\nextendedKeyUsage=clientAuth\n",
    )
    .expect("client extensions");
    openssl(&[
      "x509",
      "-req",
      "-in",
      path(&client_request),
      "-CA",
      path(&ca_certificate),
      "-CAkey",
      path(&ca_key),
      "-CAcreateserial",
      "-out",
      path(&client_certificate),
      "-days",
      "1",
      "-extfile",
      path(&client_extensions),
    ]);
    openssl(&[
      "pkey",
      "-in",
      path(&client_key),
      "-pubout",
      "-outform",
      "DER",
      "-out",
      path(&client_spki),
    ]);

    for file in [
      &ca_certificate,
      &server_certificate,
      &client_certificate,
      &server_key,
      &client_key,
    ] {
      restrict(file);
    }
    assert_eq!(
      fs::metadata(&server_key)
        .expect("server key metadata")
        .permissions()
        .mode()
        & 0o777,
      0o400
    );
    assert_eq!(
      fs::metadata(&client_key)
        .expect("client key metadata")
        .permissions()
        .mode()
        & 0o777,
      0o400
    );
    let client_spki_sha256 = format!(
      "{:x}",
      Sha256::digest(fs::read(client_spki).expect("client SPKI"))
    );
    Self {
      temp,
      ca_certificate,
      server_certificate,
      server_key,
      client_certificate,
      client_key,
      client_spki_sha256,
    }
  }

  fn server_paths(&self) -> ScheduledRunnerTlsPaths {
    ScheduledRunnerTlsPaths {
      certificate_chain: self.server_certificate.clone(),
      private_key: self.server_key.clone(),
      trust_bundle: self.ca_certificate.clone(),
    }
  }

  fn client_paths(&self) -> ScheduledRunnerTlsPaths {
    ScheduledRunnerTlsPaths {
      certificate_chain: self.client_certificate.clone(),
      private_key: self.client_key.clone(),
      trust_bundle: self.ca_certificate.clone(),
    }
  }

  fn owner(&self) -> ExpectedFileOwner {
    let metadata = fs::metadata(self.temp.path()).expect("fixture owner metadata");
    ExpectedFileOwner {
      uid: metadata.uid(),
      gid: metadata.gid(),
    }
  }
}

fn path(path: &Path) -> &str {
  path.to_str().expect("UTF-8 temporary path")
}

fn openssl(arguments: &[&str]) {
  let status = Command::new("openssl")
    .args(arguments)
    .stdin(Stdio::null())
    .stdout(Stdio::null())
    .stderr(Stdio::null())
    .status()
    .expect("run OpenSSL");
  assert!(status.success(), "OpenSSL command failed");
}

fn restrict(path: &Path) {
  fs::set_permissions(path, fs::Permissions::from_mode(0o400)).expect("restrict TLS fixture");
}

fn io_policy() -> ScheduledRunnerIoPolicy {
  ScheduledRunnerIoPolicy {
    handshake_timeout: Duration::from_secs(5),
    read_timeout: Duration::from_secs(5),
    write_timeout: Duration::from_secs(5),
  }
}

fn now_millis() -> u64 {
  u64::try_from(
    SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .expect("system time")
      .as_millis(),
  )
  .expect("timestamp")
}

fn ready(session_nonce: &str, challenge: String, fingerprint: &str, now: u64) -> RemoteFrame {
  RemoteFrame {
    version: REMOTE_PROTOCOL_VERSION,
    session_nonce: session_nonce.to_owned(),
    sequence: 1,
    message: RemoteMessage::Ready(ReadyFrame {
      challenge,
      ready_until_unix_millis: now + 5_000,
      attested_profile_json: r#"{"schema_version":1}"#.to_owned(),
      attested_profile_digest: "1".repeat(64),
      deployment_epoch: 9,
      profile_digest: "a".repeat(64),
      gateway_image_digest: format!("sha256:{}", "b".repeat(64)),
      runner_image_digest: format!("sha256:{}", "c".repeat(64)),
      runner_workload_identity: WORKLOAD_IDENTITY.to_owned(),
      runner_client_cert_public_key_fingerprint: fingerprint.to_owned(),
      credential_revision: "github-readonly-2026-07".to_owned(),
    }),
  }
}

#[tokio::test]
async fn real_mutual_tls_exchanges_challenge_bound_ready_and_admission() {
  let fixture = CertificateFixture::new("good");
  let authorized_peer =
    ScheduledRunnerAuthorizedPeer::new(WORKLOAD_IDENTITY, &fixture.client_spki_sha256)
      .expect("authorized peer");
  let server = Arc::new(
    ScheduledRunnerTlsServer::load_with_owner(
      &fixture.server_paths(),
      authorized_peer,
      io_policy(),
      fixture.owner(),
    )
    .expect("TLS server"),
  );
  let client = ScheduledRunnerTlsClient::load_with_owner(
    &fixture.client_paths(),
    SERVER_NAME,
    io_policy(),
    fixture.owner(),
  )
  .expect("TLS client");
  let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
  let address = listener.local_addr().expect("listener address");
  let session_nonce = "d".repeat(64);
  let server_session_nonce = session_nonce.clone();
  let expected_fingerprint = fixture.client_spki_sha256.clone();
  let server_task = tokio::spawn(async move {
    let (stream, _) = listener.accept().await.expect("TCP accept");
    let mut connection = server.accept(stream).await.expect("mTLS accept");
    let challenge = format!("{:x}", Sha256::digest(connection.channel_binding));
    let frame = connection
      .framed
      .read_frame(now_millis())
      .await
      .expect("READY read")
      .expect("READY frame");
    let RemoteMessage::Ready(ready) = frame.message else {
      panic!("expected READY")
    };
    assert_eq!(frame.session_nonce, server_session_nonce);
    assert_eq!(ready.challenge, challenge);
    assert_eq!(
      ready.runner_client_cert_public_key_fingerprint,
      expected_fingerprint
    );
    assert_eq!(
      ready.runner_workload_identity,
      connection.authorized_peer.runner_identity.as_str()
    );
    connection
      .framed
      .write_frame(&RemoteFrame {
        version: REMOTE_PROTOCOL_VERSION,
        session_nonce: frame.session_nonce,
        sequence: 1,
        message: RemoteMessage::Admission(AdmissionFrame {
          challenge,
          admission_nonce: "e".repeat(64),
          expires_at_unix_millis: now_millis() + 1_000,
          deployment_epoch: ready.deployment_epoch,
          profile_digest: ready.profile_digest,
        }),
      })
      .await
      .expect("ADMISSION write");
  });

  let mut connection = client.connect(address).await.expect("mTLS connect");
  let challenge = format!("{:x}", Sha256::digest(connection.channel_binding));
  connection
    .framed
    .write_frame(&ready(
      &session_nonce,
      challenge.clone(),
      &fixture.client_spki_sha256,
      now_millis(),
    ))
    .await
    .expect("READY write");
  let response = connection
    .framed
    .read_frame(now_millis())
    .await
    .expect("ADMISSION read")
    .expect("ADMISSION frame");
  let RemoteMessage::Admission(admission) = response.message else {
    panic!("expected ADMISSION")
  };
  assert_eq!(admission.challenge, challenge);
  server_task.await.expect("server task");
}

#[tokio::test]
async fn mutual_tls_rejects_missing_client_certificate() {
  let fixture = CertificateFixture::new("missing-client");
  let server = Arc::new(
    ScheduledRunnerTlsServer::load_with_owner(
      &fixture.server_paths(),
      ScheduledRunnerAuthorizedPeer::new(WORKLOAD_IDENTITY, &fixture.client_spki_sha256)
        .expect("authorized peer"),
      io_policy(),
      fixture.owner(),
    )
    .expect("TLS server"),
  );
  let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
  let address = listener.local_addr().expect("address");
  let server_task = tokio::spawn(async move {
    let (stream, _) = listener.accept().await.expect("TCP accept");
    assert!(server.accept(stream).await.is_err());
  });

  let mut roots = RootCertStore::empty();
  roots
    .add(CertificateDer::from_pem_file(&fixture.ca_certificate).expect("CA"))
    .expect("root");
  let provider = Arc::new(rustls::crypto::ring::default_provider());
  let client = ClientConfig::builder_with_provider(provider)
    .with_protocol_versions(&[&rustls::version::TLS13])
    .expect("TLS1.3")
    .with_root_certificates(roots)
    .with_no_client_auth();
  let tcp = TcpStream::connect(address).await.expect("TCP connect");
  let result = TlsConnector::from(Arc::new(client))
    .connect(ServerName::try_from(SERVER_NAME).expect("server name"), tcp)
    .await;
  if let Ok(mut stream) = result {
    let mut byte = [0_u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut byte))
      .await
      .expect("server rejection is bounded");
    assert!(matches!(read, Ok(0) | Err(_)));
  }
  server_task.await.expect("server task");
}

#[tokio::test]
async fn mutual_tls_rejects_wrong_ca_hostname_tls12_and_spki() {
  let fixture = CertificateFixture::new("primary");
  let other = CertificateFixture::new("other");

  let wrong_ca_client = ScheduledRunnerTlsClient::load_with_owner(
    &ScheduledRunnerTlsPaths {
      certificate_chain: fixture.client_certificate.clone(),
      private_key: fixture.client_key.clone(),
      trust_bundle: other.ca_certificate.clone(),
    },
    SERVER_NAME,
    io_policy(),
    fixture.owner(),
  )
  .expect("wrong CA client config");
  assert_handshake_fails(&fixture, wrong_ca_client).await;

  let wrong_name_client = ScheduledRunnerTlsClient::load_with_owner(
    &fixture.client_paths(),
    "wrong.codeoff.test",
    io_policy(),
    fixture.owner(),
  )
  .expect("wrong hostname client config");
  assert_handshake_fails(&fixture, wrong_name_client).await;

  assert_tls12_fails(&fixture).await;

  let server = Arc::new(
    ScheduledRunnerTlsServer::load_with_owner(
      &fixture.server_paths(),
      ScheduledRunnerAuthorizedPeer::new(WORKLOAD_IDENTITY, &other.client_spki_sha256)
        .expect("wrong SPKI authorization mapping"),
      io_policy(),
      fixture.owner(),
    )
    .expect("TLS server"),
  );
  let client = ScheduledRunnerTlsClient::load_with_owner(
    &fixture.client_paths(),
    SERVER_NAME,
    io_policy(),
    fixture.owner(),
  )
  .expect("TLS client");
  let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
  let address = listener.local_addr().expect("address");
  let server_task = tokio::spawn(async move {
    let (stream, _) = listener.accept().await.expect("TCP accept");
    assert!(matches!(
      server.accept(stream).await,
      Err(ScheduledRunnerTlsError::PeerSpkiMismatch)
    ));
  });
  let _client_connection = client.connect(address).await.expect("client handshake");
  server_task.await.expect("server task");
}

async fn assert_handshake_fails(fixture: &CertificateFixture, client: ScheduledRunnerTlsClient) {
  let server = Arc::new(
    ScheduledRunnerTlsServer::load_with_owner(
      &fixture.server_paths(),
      ScheduledRunnerAuthorizedPeer::new(WORKLOAD_IDENTITY, &fixture.client_spki_sha256)
        .expect("authorized peer"),
      io_policy(),
      fixture.owner(),
    )
    .expect("TLS server"),
  );
  let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
  let address = listener.local_addr().expect("address");
  let server_task = tokio::spawn(async move {
    let (stream, _) = listener.accept().await.expect("TCP accept");
    assert!(server.accept(stream).await.is_err());
  });
  assert!(client.connect(address).await.is_err());
  server_task.await.expect("server task");
}

async fn assert_tls12_fails(fixture: &CertificateFixture) {
  let server = Arc::new(
    ScheduledRunnerTlsServer::load_with_owner(
      &fixture.server_paths(),
      ScheduledRunnerAuthorizedPeer::new(WORKLOAD_IDENTITY, &fixture.client_spki_sha256)
        .expect("authorized peer"),
      io_policy(),
      fixture.owner(),
    )
    .expect("TLS server"),
  );
  let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
  let address = listener.local_addr().expect("address");
  let server_task = tokio::spawn(async move {
    let (stream, _) = listener.accept().await.expect("TCP accept");
    assert!(server.accept(stream).await.is_err());
  });

  let client_certificate = fixture.client_certificate.clone();
  let client_key = fixture.client_key.clone();
  let ca_certificate = fixture.ca_certificate.clone();
  let result = tokio::task::spawn_blocking(move || {
    Command::new("openssl")
      .args([
        "s_client",
        "-connect",
        &address.to_string(),
        "-tls1_2",
        "-cert",
        path(&client_certificate),
        "-key",
        path(&client_key),
        "-CAfile",
        path(&ca_certificate),
        "-servername",
        SERVER_NAME,
        "-verify_return_error",
      ])
      .stdin(Stdio::null())
      .stdout(Stdio::null())
      .stderr(Stdio::null())
      .status()
      .expect("run OpenSSL TLS1.2 client")
  })
  .await
  .expect("OpenSSL task");
  assert!(!result.success());
  server_task.await.expect("server task");
}
