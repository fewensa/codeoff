//! Protected one-shot local channel between the credential-owning runner control process and the
//! unprivileged scheduled executor.

use std::fmt;
use std::fs;
use std::os::fd::AsFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use nix::fcntl::{FcntlArg, FdFlag, fcntl};
use nix::unistd::{Gid, chown};
use tokio::net::{UnixListener, UnixStream};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduledRunnerControlConfig {
  pub socket_path: PathBuf,
  pub executor_uid: u32,
  pub executor_gid: u32,
  pub accept_timeout: Duration,
}

impl ScheduledRunnerControlConfig {
  pub fn validate(&self) -> Result<(), ScheduledRunnerControlError> {
    if self.accept_timeout.is_zero() || !is_canonical_absolute_path(&self.socket_path) {
      return Err(ScheduledRunnerControlError::InvalidConfiguration);
    }
    let parent = self
      .socket_path
      .parent()
      .ok_or(ScheduledRunnerControlError::InvalidConfiguration)?;
    let metadata = fs::metadata(parent).map_err(ScheduledRunnerControlError::Io)?;
    if !metadata.is_dir() {
      return Err(ScheduledRunnerControlError::InvalidConfiguration);
    }
    let sticky = metadata.permissions().mode() & 0o1000 != 0;
    if metadata.permissions().mode() & 0o022 != 0 && !sticky {
      return Err(ScheduledRunnerControlError::InsecureParentDirectory);
    }
    Ok(())
  }
}

#[derive(Debug)]
pub enum ScheduledRunnerControlError {
  InvalidConfiguration,
  InsecureParentDirectory,
  SocketPathExists,
  SocketOwnershipMismatch,
  SocketTypeMismatch,
  CloseOnExecMissing,
  AcceptTimeout,
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

pub struct ProtectedScheduledExecutorConnection {
  stream: UnixStream,
  pub peer: ScheduledExecutorPeerCredentials,
}

impl ProtectedScheduledExecutorConnection {
  #[must_use]
  pub fn into_inner(self) -> UnixStream {
    self.stream
  }
}

/// A listener that can accept at most one executor connection.
pub struct ProtectedScheduledExecutorListener {
  listener: UnixListener,
  socket_path: OwnedSocketPath,
  config: ScheduledRunnerControlConfig,
}

struct OwnedSocketPath {
  path: PathBuf,
  device: u64,
  inode: u64,
  unlink_armed: bool,
}

impl OwnedSocketPath {
  fn capture(path: PathBuf) -> Result<Self, ScheduledRunnerControlError> {
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.file_type().is_socket() {
      return Err(ScheduledRunnerControlError::SocketTypeMismatch);
    }
    Ok(Self {
      path,
      device: metadata.dev(),
      inode: metadata.ino(),
      unlink_armed: true,
    })
  }

  fn unlink(&mut self) -> Result<(), ScheduledRunnerControlError> {
    if !self.unlink_armed {
      return Ok(());
    }
    let metadata = fs::symlink_metadata(&self.path)?;
    if !metadata.file_type().is_socket() {
      return Err(ScheduledRunnerControlError::SocketTypeMismatch);
    }
    if metadata.dev() != self.device || metadata.ino() != self.inode {
      return Err(ScheduledRunnerControlError::SocketOwnershipMismatch);
    }
    fs::remove_file(&self.path)?;
    self.unlink_armed = false;
    Ok(())
  }
}

impl Drop for OwnedSocketPath {
  fn drop(&mut self) {
    let _ = self.unlink();
  }
}

impl ProtectedScheduledExecutorListener {
  pub fn bind(config: ScheduledRunnerControlConfig) -> Result<Self, ScheduledRunnerControlError> {
    config.validate()?;
    if fs::symlink_metadata(&config.socket_path).is_ok() {
      return Err(ScheduledRunnerControlError::SocketPathExists);
    }
    let listener = UnixListener::bind(&config.socket_path)?;
    let socket_path = OwnedSocketPath::capture(config.socket_path.clone())?;
    require_cloexec(&listener)?;
    let mut metadata = fs::symlink_metadata(&config.socket_path)?;
    if !metadata.file_type().is_socket() {
      return Err(ScheduledRunnerControlError::SocketTypeMismatch);
    }
    if metadata.gid() != config.executor_gid {
      chown(
        &config.socket_path,
        None,
        Some(Gid::from_raw(config.executor_gid)),
      )
      .map_err(|error| ScheduledRunnerControlError::Io(error.into()))?;
    }
    fs::set_permissions(&config.socket_path, fs::Permissions::from_mode(0o620))?;
    metadata = fs::symlink_metadata(&config.socket_path)?;
    if metadata.dev() != socket_path.device || metadata.ino() != socket_path.inode {
      return Err(ScheduledRunnerControlError::SocketOwnershipMismatch);
    }
    Ok(Self {
      listener,
      socket_path,
      config,
    })
  }

  pub async fn accept(
    mut self,
  ) -> Result<ProtectedScheduledExecutorConnection, ScheduledRunnerControlError> {
    let accepted = tokio::time::timeout(self.config.accept_timeout, self.listener.accept())
      .await
      .map_err(|_| ScheduledRunnerControlError::AcceptTimeout)??;
    self.socket_path.unlink()?;
    let stream = accepted.0;
    require_cloexec(&stream)?;
    let credentials = stream
      .peer_cred()
      .map_err(|_| ScheduledRunnerControlError::PeerCredentialUnavailable)?;
    let peer = ScheduledExecutorPeerCredentials {
      uid: credentials.uid(),
      gid: credentials.gid(),
      pid: credentials.pid().and_then(|pid| u32::try_from(pid).ok()),
    };
    if peer.uid != self.config.executor_uid || peer.gid != self.config.executor_gid {
      return Err(ScheduledRunnerControlError::PeerCredentialMismatch);
    }
    Ok(ProtectedScheduledExecutorConnection { stream, peer })
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

  fn config(path: PathBuf) -> ScheduledRunnerControlConfig {
    let metadata = fs::metadata(path.parent().expect("socket parent")).expect("parent metadata");
    ScheduledRunnerControlConfig {
      socket_path: path,
      executor_uid: metadata.uid(),
      executor_gid: metadata.gid(),
      accept_timeout: Duration::from_secs(2),
    }
  }

  #[tokio::test]
  async fn accepts_exact_peer_once_then_unlinks_the_listener() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let path = temp.path().join("executor.sock");
    let listener = ProtectedScheduledExecutorListener::bind(config(path.clone())).expect("bind");
    let client = UnixStream::connect(&path);
    let (accepted, client) = tokio::join!(listener.accept(), client);
    let accepted = accepted.expect("authorized peer");
    let _client = client.expect("client connect");
    assert!(!path.exists());
    assert_eq!(accepted.peer.uid, config(path).executor_uid);
  }

  #[tokio::test]
  async fn rejects_wrong_peer_credentials_after_unlinking() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let path = temp.path().join("executor.sock");
    let mut wrong = config(path.clone());
    wrong.executor_uid = wrong.executor_uid.saturating_add(1);
    let listener = ProtectedScheduledExecutorListener::bind(wrong).expect("bind");
    let client = UnixStream::connect(&path);
    let (accepted, client) = tokio::join!(listener.accept(), client);
    let _client = client.expect("client connect");
    assert!(matches!(
      accepted,
      Err(ScheduledRunnerControlError::PeerCredentialMismatch)
    ));
    assert!(!path.exists());
  }

  #[tokio::test]
  async fn accept_timeout_unlinks_the_owned_listener() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let path = temp.path().join("executor.sock");
    let mut candidate = config(path.clone());
    candidate.accept_timeout = Duration::from_millis(5);
    let listener = ProtectedScheduledExecutorListener::bind(candidate).expect("bind");
    assert!(matches!(
      listener.accept().await,
      Err(ScheduledRunnerControlError::AcceptTimeout)
    ));
    assert!(!path.exists());
  }

  #[tokio::test]
  async fn refuses_to_replace_preexisting_path_and_drop_unlinks_only_its_socket() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let path = temp.path().join("executor.sock");
    fs::write(&path, b"owned elsewhere").expect("preexisting path");
    assert!(matches!(
      ProtectedScheduledExecutorListener::bind(config(path.clone())),
      Err(ScheduledRunnerControlError::SocketPathExists)
    ));
    assert_eq!(fs::read(&path).expect("preserved path"), b"owned elsewhere");
    fs::remove_file(&path).expect("remove test fixture");

    let listener = ProtectedScheduledExecutorListener::bind(config(path.clone())).expect("bind");
    assert!(path.exists());
    drop(listener);
    assert!(!path.exists());
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
    candidate.accept_timeout = Duration::ZERO;
    assert!(matches!(
      candidate.validate(),
      Err(ScheduledRunnerControlError::InvalidConfiguration)
    ));
  }
}
