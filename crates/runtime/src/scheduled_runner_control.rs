//! Credential-owning runner-control connection to the protected local executor channel.

use std::fmt;
use std::os::fd::AsFd;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use nix::fcntl::{FcntlArg, FdFlag, fcntl};
use tokio::net::UnixStream;

use crate::scheduled_runner_tls::ScheduledRunnerFramed;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduledRunnerControlConfig {
  pub socket_path: PathBuf,
  pub executor_uid: u32,
  pub executor_gid: u32,
  pub connect_timeout: Duration,
  pub read_timeout: Duration,
  pub write_timeout: Duration,
}

impl ScheduledRunnerControlConfig {
  pub fn validate(&self) -> Result<(), ScheduledRunnerControlError> {
    if self.connect_timeout.is_zero()
      || self.read_timeout.is_zero()
      || self.write_timeout.is_zero()
      || !is_canonical_absolute_path(&self.socket_path)
    {
      return Err(ScheduledRunnerControlError::InvalidConfiguration);
    }
    Ok(())
  }
}

#[derive(Debug)]
pub enum ScheduledRunnerControlError {
  InvalidConfiguration,
  CloseOnExecMissing,
  ConnectTimeout,
  PeerCredentialUnavailable,
  PeerCredentialMismatch,
  Io(std::io::Error),
}

impl fmt::Display for ScheduledRunnerControlError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(formatter, "{self:?}")
  }
}

impl std::error::Error for ScheduledRunnerControlError {}

impl From<std::io::Error> for ScheduledRunnerControlError {
  fn from(error: std::io::Error) -> Self {
    Self::Io(error)
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScheduledExecutorPeerCredentials {
  pub uid: u32,
  pub gid: u32,
  pub pid: Option<u32>,
}

pub struct ScheduledRunnerControlConnection {
  pub peer: ScheduledExecutorPeerCredentials,
  pub framed: ScheduledRunnerFramed<UnixStream>,
}

impl ScheduledRunnerControlConnection {
  pub async fn connect(
    config: &ScheduledRunnerControlConfig,
  ) -> Result<Self, ScheduledRunnerControlError> {
    config.validate()?;
    let deadline = tokio::time::Instant::now() + config.connect_timeout;
    let stream = loop {
      match UnixStream::connect(&config.socket_path).await {
        Ok(stream) => break stream,
        Err(_) if tokio::time::Instant::now() < deadline => {
          tokio::time::sleep(Duration::from_millis(50)).await;
        }
        Err(_) => return Err(ScheduledRunnerControlError::ConnectTimeout),
      }
    };
    require_cloexec(&stream)?;
    let credentials = stream
      .peer_cred()
      .map_err(|_| ScheduledRunnerControlError::PeerCredentialUnavailable)?;
    let peer = ScheduledExecutorPeerCredentials {
      uid: credentials.uid(),
      gid: credentials.gid(),
      pid: credentials.pid().and_then(|pid| u32::try_from(pid).ok()),
    };
    if peer.uid != config.executor_uid || peer.gid != config.executor_gid {
      return Err(ScheduledRunnerControlError::PeerCredentialMismatch);
    }
    Ok(Self {
      peer,
      framed: ScheduledRunnerFramed::new(stream, config.read_timeout, config.write_timeout),
    })
  }
}

pub(crate) fn require_cloexec(fd: &impl AsFd) -> Result<(), ScheduledRunnerControlError> {
  let flags =
    fcntl(fd, FcntlArg::F_GETFD).map_err(|error| ScheduledRunnerControlError::Io(error.into()))?;
  if FdFlag::from_bits_truncate(flags).contains(FdFlag::FD_CLOEXEC) {
    Ok(())
  } else {
    Err(ScheduledRunnerControlError::CloseOnExecMissing)
  }
}

fn is_canonical_absolute_path(path: &Path) -> bool {
  path.is_absolute()
    && path
      .components()
      .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
    && path.file_name().is_some()
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::fs;
  use std::os::unix::fs::MetadataExt;
  use tokio::net::UnixListener;

  fn config(path: PathBuf) -> ScheduledRunnerControlConfig {
    let metadata = fs::metadata(path.parent().expect("socket parent")).expect("parent metadata");
    ScheduledRunnerControlConfig {
      socket_path: path,
      executor_uid: metadata.uid(),
      executor_gid: metadata.gid(),
      connect_timeout: Duration::from_secs(2),
      read_timeout: Duration::from_secs(2),
      write_timeout: Duration::from_secs(2),
    }
  }

  #[tokio::test]
  async fn connects_only_to_the_exact_executor_peer() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let path = temp.path().join("executor.sock");
    let listener = UnixListener::bind(&path).expect("bind");
    let accepted = listener.accept();
    let expected = config(path);
    let client = ScheduledRunnerControlConnection::connect(&expected);
    let (accepted, client) = tokio::join!(accepted, client);
    let _accepted = accepted.expect("accept");
    assert_eq!(
      client.expect("authorized peer").peer.uid,
      expected.executor_uid
    );
  }

  #[tokio::test]
  async fn rejects_wrong_executor_credentials() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let path = temp.path().join("executor.sock");
    let mut wrong = config(path.clone());
    wrong.executor_uid = wrong.executor_uid.saturating_add(1);
    let listener = UnixListener::bind(&path).expect("bind");
    let accepted = listener.accept();
    let client = ScheduledRunnerControlConnection::connect(&wrong);
    let (accepted, client) = tokio::join!(accepted, client);
    let _accepted = accepted.expect("accept");
    assert!(matches!(
      client,
      Err(ScheduledRunnerControlError::PeerCredentialMismatch)
    ));
  }

  #[tokio::test]
  async fn connect_timeout_is_bounded() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let path = temp.path().join("executor.sock");
    let mut candidate = config(path.clone());
    candidate.connect_timeout = Duration::from_millis(5);
    assert!(matches!(
      ScheduledRunnerControlConnection::connect(&candidate).await,
      Err(ScheduledRunnerControlError::ConnectTimeout)
    ));
  }

  #[test]
  fn rejects_relative_or_traversing_socket_paths_and_zero_timeout() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let mut candidate = config(temp.path().join("executor.sock"));
    candidate.socket_path = PathBuf::from("executor.sock");
    assert!(matches!(
      candidate.validate(),
      Err(ScheduledRunnerControlError::InvalidConfiguration)
    ));
    candidate = config(temp.path().join("executor.sock"));
    candidate.socket_path = temp.path().join("nested/../executor.sock");
    assert!(matches!(
      candidate.validate(),
      Err(ScheduledRunnerControlError::InvalidConfiguration)
    ));
    candidate = config(temp.path().join("executor.sock"));
    candidate.connect_timeout = Duration::ZERO;
    assert!(matches!(
      candidate.validate(),
      Err(ScheduledRunnerControlError::InvalidConfiguration)
    ));
  }
}
