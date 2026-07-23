//! Unprivileged executor-side connection to the protected local runner-control channel.

use std::fmt;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use tokio::net::{UnixStream, unix::UCred};

use crate::scheduled_runner_control::{ScheduledRunnerControlError, require_cloexec};
use crate::scheduled_runner_tls::ScheduledRunnerFramed;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduledRunnerExecutorConfig {
  pub socket_path: PathBuf,
  pub control_uid: u32,
  pub control_gid: u32,
  pub connect_timeout: Duration,
  pub read_timeout: Duration,
  pub write_timeout: Duration,
}

impl ScheduledRunnerExecutorConfig {
  pub fn validate(&self) -> Result<(), ScheduledRunnerExecutorError> {
    if !is_canonical_absolute_path(&self.socket_path)
      || self.connect_timeout.is_zero()
      || self.read_timeout.is_zero()
      || self.write_timeout.is_zero()
    {
      return Err(ScheduledRunnerExecutorError::InvalidConfiguration);
    }
    Ok(())
  }
}

#[derive(Debug)]
pub enum ScheduledRunnerExecutorError {
  InvalidConfiguration,
  ConnectTimeout,
  ControlCredentialUnavailable,
  ControlCredentialMismatch,
  ControlChannel(ScheduledRunnerControlError),
  Io(std::io::Error),
}

impl fmt::Display for ScheduledRunnerExecutorError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(formatter, "{self:?}")
  }
}

impl std::error::Error for ScheduledRunnerExecutorError {}

impl From<std::io::Error> for ScheduledRunnerExecutorError {
  fn from(error: std::io::Error) -> Self {
    Self::Io(error)
  }
}

impl From<ScheduledRunnerControlError> for ScheduledRunnerExecutorError {
  fn from(error: ScheduledRunnerControlError) -> Self {
    Self::ControlChannel(error)
  }
}

pub struct ScheduledRunnerExecutorConnection {
  pub control_peer: ScheduledRunnerControlPeer,
  pub framed: ScheduledRunnerFramed<UnixStream>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScheduledRunnerControlPeer {
  pub uid: u32,
  pub gid: u32,
  pub pid: Option<u32>,
}

impl ScheduledRunnerExecutorConnection {
  pub async fn connect(
    config: &ScheduledRunnerExecutorConfig,
  ) -> Result<Self, ScheduledRunnerExecutorError> {
    config.validate()?;
    let stream = tokio::time::timeout(
      config.connect_timeout,
      UnixStream::connect(&config.socket_path),
    )
    .await
    .map_err(|_| ScheduledRunnerExecutorError::ConnectTimeout)??;
    require_cloexec(&stream)?;
    let credentials = stream
      .peer_cred()
      .map_err(|_| ScheduledRunnerExecutorError::ControlCredentialUnavailable)?;
    let control_peer = peer(credentials);
    if control_peer.uid != config.control_uid || control_peer.gid != config.control_gid {
      return Err(ScheduledRunnerExecutorError::ControlCredentialMismatch);
    }
    Ok(Self {
      control_peer,
      framed: ScheduledRunnerFramed::new(stream, config.read_timeout, config.write_timeout),
    })
  }
}

fn peer(credentials: UCred) -> ScheduledRunnerControlPeer {
  ScheduledRunnerControlPeer {
    uid: credentials.uid(),
    gid: credentials.gid(),
    pid: credentials.pid().and_then(|pid| u32::try_from(pid).ok()),
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

  fn config(path: PathBuf) -> ScheduledRunnerExecutorConfig {
    let owner = fs::metadata(path.parent().expect("socket parent")).expect("parent metadata");
    ScheduledRunnerExecutorConfig {
      socket_path: path,
      control_uid: owner.uid(),
      control_gid: owner.gid(),
      connect_timeout: Duration::from_secs(2),
      read_timeout: Duration::from_secs(2),
      write_timeout: Duration::from_secs(2),
    }
  }

  #[tokio::test]
  async fn connects_only_to_the_expected_control_credentials() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let path = temp.path().join("control.sock");
    let listener = UnixListener::bind(&path).expect("listener");
    let expected = config(path);
    let accept = listener.accept();
    let connect = ScheduledRunnerExecutorConnection::connect(&expected);
    let (server, client) = tokio::join!(accept, connect);
    let (_server, _) = server.expect("server accept");
    let client = client.expect("authorized control");
    assert_eq!(client.control_peer.uid, expected.control_uid);
  }

  #[tokio::test]
  async fn rejects_a_control_process_outside_the_pinned_mapping() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let path = temp.path().join("control.sock");
    let listener = UnixListener::bind(&path).expect("listener");
    let mut wrong = config(path.clone());
    wrong.control_uid = wrong.control_uid.saturating_add(1);
    let accept = listener.accept();
    let connect = ScheduledRunnerExecutorConnection::connect(&wrong);
    let (server, client) = tokio::join!(accept, connect);
    let (_server, _) = server.expect("server accept");
    assert!(matches!(
      client,
      Err(ScheduledRunnerExecutorError::ControlCredentialMismatch)
    ));
  }

  #[test]
  fn rejects_relative_paths_and_zero_timeouts() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let mut candidate = config(temp.path().join("control.sock"));
    candidate.socket_path = PathBuf::from("control.sock");
    assert!(matches!(
      candidate.validate(),
      Err(ScheduledRunnerExecutorError::InvalidConfiguration)
    ));
    candidate = config(temp.path().join("control.sock"));
    candidate.connect_timeout = Duration::ZERO;
    assert!(matches!(
      candidate.validate(),
      Err(ScheduledRunnerExecutorError::InvalidConfiguration)
    ));
  }
}
