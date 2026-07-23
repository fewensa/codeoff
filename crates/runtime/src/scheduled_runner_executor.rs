//! Trusted executor-side listener for the protected local runner-control channel.

use std::fmt;
use std::fs;
use std::os::fd::AsFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use codeoff_agent_contract::{
  AgentTask, InvocationPrincipal, InvocationSource, PreviousSuccessContext, SessionMode, ToolPolicy,
};
use nix::fcntl::{FcntlArg, FdFlag, Flock, FlockArg, OFlag, fcntl, open};
use nix::sys::stat::Mode;
use nix::unistd::{Gid, chown, getegid, geteuid};
use serde_json::{Map, Value};
use tokio::net::{UnixListener, UnixStream, unix::UCred};

use crate::scheduled_remote_protocol::RunBinding;
use crate::scheduled_runner_tls::ScheduledRunnerFramed;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduledRunnerExecutorConfig {
  pub socket_path: PathBuf,
  pub control_uid: u32,
  pub control_gid: u32,
  pub accept_timeout: Duration,
  pub read_timeout: Duration,
  pub write_timeout: Duration,
}

impl ScheduledRunnerExecutorConfig {
  pub fn validate(&self) -> Result<(), ScheduledRunnerExecutorError> {
    if !is_canonical_absolute_path(&self.socket_path)
      || self.accept_timeout.is_zero()
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
  InsecureParentDirectory,
  ProcessHardening,
  SocketPathExists,
  LifecycleLocked,
  SocketOwnershipMismatch,
  SocketTypeMismatch,
  CloseOnExecMissing,
  AcceptTimeout,
  ControlCredentialUnavailable,
  ControlCredentialMismatch,
  InvalidTask,
  Io(std::io::Error),
}

pub fn harden_scheduled_executor_process() -> Result<(), ScheduledRunnerExecutorError> {
  nix::sys::prctl::set_dumpable(false)
    .map_err(|_| ScheduledRunnerExecutorError::ProcessHardening)?;
  if nix::sys::prctl::get_dumpable().map_err(|_| ScheduledRunnerExecutorError::ProcessHardening)? {
    return Err(ScheduledRunnerExecutorError::ProcessHardening);
  }
  Ok(())
}

pub fn decode_scheduled_remote_task(
  encoded: &str,
  binding: &RunBinding,
) -> Result<AgentTask, ScheduledRunnerExecutorError> {
  let value: Value =
    serde_json::from_str(encoded).map_err(|_| ScheduledRunnerExecutorError::InvalidTask)?;
  if serde_json::to_string(&value).ok().as_deref() != Some(encoded) {
    return Err(ScheduledRunnerExecutorError::InvalidTask);
  }
  let object = exact_object(
    &value,
    &[
      "instruction",
      "previous_success",
      "scheduled_for",
      "schema_version",
      "task_id",
    ],
  )?;
  if object.get("schema_version").and_then(Value::as_u64) != Some(1) {
    return Err(ScheduledRunnerExecutorError::InvalidTask);
  }
  let string = |field: &str| {
    object
      .get(field)
      .and_then(Value::as_str)
      .filter(|value| !value.is_empty() && *value == value.trim())
      .map(str::to_owned)
      .ok_or(ScheduledRunnerExecutorError::InvalidTask)
  };
  let task_id = string("task_id")?;
  if task_id
    != format!(
      "scheduled:{}:{}:{}",
      binding.run_id, binding.attempt, binding.fence_token
    )
  {
    return Err(ScheduledRunnerExecutorError::InvalidTask);
  }
  let previous_success = match object.get("previous_success") {
    Some(Value::Null) => None,
    Some(value) => {
      let previous = exact_object(value, &["content", "was_truncated"])?;
      Some(PreviousSuccessContext {
        content: previous
          .get("content")
          .and_then(Value::as_str)
          .map(str::to_owned)
          .ok_or(ScheduledRunnerExecutorError::InvalidTask)?,
        was_truncated: previous
          .get("was_truncated")
          .and_then(Value::as_bool)
          .ok_or(ScheduledRunnerExecutorError::InvalidTask)?,
      })
    }
    None => return Err(ScheduledRunnerExecutorError::InvalidTask),
  };
  let task = AgentTask {
    task_id,
    instruction: string("instruction")?,
    source: InvocationSource::ScheduledRun {
      job_id: binding.job_id.clone(),
      run_id: binding.run_id.clone(),
      scheduled_for: string("scheduled_for")?,
    },
    principal: InvocationPrincipal::service("codeoff-scheduler"),
    session: SessionMode::Fresh,
    channel: None,
    previous_success,
    tool_policy: ToolPolicy::None,
    feedback_target: None,
  };
  task
    .validate()
    .map_err(|_| ScheduledRunnerExecutorError::InvalidTask)?;
  Ok(task)
}

fn exact_object<'a>(
  value: &'a Value,
  fields: &[&str],
) -> Result<&'a Map<String, Value>, ScheduledRunnerExecutorError> {
  let object = value
    .as_object()
    .ok_or(ScheduledRunnerExecutorError::InvalidTask)?;
  if object.len() != fields.len() || fields.iter().any(|field| !object.contains_key(*field)) {
    return Err(ScheduledRunnerExecutorError::InvalidTask);
  }
  Ok(object)
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

pub struct ScheduledRunnerExecutorConnection {
  pub control_peer: ScheduledRunnerControlPeer,
  pub framed: ScheduledRunnerFramed<UnixStream>,
}

pub struct ProtectedScheduledExecutorListener {
  listener: UnixListener,
  socket_path: OwnedSocketPath,
  _lifecycle_lock: Flock<fs::File>,
  config: ScheduledRunnerExecutorConfig,
}

struct OwnedSocketPath {
  path: PathBuf,
  device: u64,
  inode: u64,
  unlink_armed: bool,
}

impl OwnedSocketPath {
  fn capture(path: PathBuf) -> Result<Self, ScheduledRunnerExecutorError> {
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.file_type().is_socket() {
      return Err(ScheduledRunnerExecutorError::SocketTypeMismatch);
    }
    Ok(Self {
      path,
      device: metadata.dev(),
      inode: metadata.ino(),
      unlink_armed: true,
    })
  }

  fn unlink(&mut self) -> Result<(), ScheduledRunnerExecutorError> {
    if !self.unlink_armed {
      return Ok(());
    }
    let metadata = fs::symlink_metadata(&self.path)?;
    if !metadata.file_type().is_socket() {
      return Err(ScheduledRunnerExecutorError::SocketTypeMismatch);
    }
    if metadata.dev() != self.device || metadata.ino() != self.inode {
      return Err(ScheduledRunnerExecutorError::SocketOwnershipMismatch);
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScheduledRunnerControlPeer {
  pub uid: u32,
  pub gid: u32,
  pub pid: Option<u32>,
}

#[must_use]
pub fn current_process_credentials() -> ScheduledRunnerControlPeer {
  ScheduledRunnerControlPeer {
    uid: geteuid().as_raw(),
    gid: getegid().as_raw(),
    pid: Some(std::process::id()),
  }
}

impl ProtectedScheduledExecutorListener {
  pub fn bind(config: ScheduledRunnerExecutorConfig) -> Result<Self, ScheduledRunnerExecutorError> {
    config.validate()?;
    let parent = config
      .socket_path
      .parent()
      .ok_or(ScheduledRunnerExecutorError::InvalidConfiguration)?;
    let parent_metadata = fs::metadata(parent)?;
    if !parent_metadata.is_dir() {
      return Err(ScheduledRunnerExecutorError::InvalidConfiguration);
    }
    let sticky = parent_metadata.permissions().mode() & 0o1000 != 0;
    if parent_metadata.permissions().mode() & 0o022 != 0 && !sticky {
      return Err(ScheduledRunnerExecutorError::InsecureParentDirectory);
    }
    let lock_path = config.socket_path.with_extension("sock.lock");
    let lock_file = fs::File::from(
      open(
        &lock_path,
        OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::from_bits_truncate(0o600),
      )
      .map_err(|error| ScheduledRunnerExecutorError::Io(error.into()))?,
    );
    let lock_metadata = lock_file.metadata()?;
    if lock_metadata.uid() != geteuid().as_raw()
      || lock_metadata.gid() != getegid().as_raw()
      || lock_metadata.permissions().mode() & 0o777 != 0o600
    {
      return Err(ScheduledRunnerExecutorError::SocketOwnershipMismatch);
    }
    let lifecycle_lock = Flock::lock(lock_file, FlockArg::LockExclusiveNonblock)
      .map_err(|_| ScheduledRunnerExecutorError::LifecycleLocked)?;
    if let Ok(existing) = fs::symlink_metadata(&config.socket_path) {
      if !existing.file_type().is_socket() {
        return Err(ScheduledRunnerExecutorError::SocketTypeMismatch);
      }
      if existing.uid() != geteuid().as_raw() || existing.gid() != getegid().as_raw() {
        return Err(ScheduledRunnerExecutorError::SocketOwnershipMismatch);
      }
      fs::remove_file(&config.socket_path)?;
    }
    let listener = UnixListener::bind(&config.socket_path)?;
    require_executor_cloexec(&listener)?;
    let socket_path = OwnedSocketPath::capture(config.socket_path.clone())?;
    let mut metadata = fs::symlink_metadata(&config.socket_path)?;
    if metadata.gid() != config.control_gid {
      chown(
        &config.socket_path,
        None,
        Some(Gid::from_raw(config.control_gid)),
      )
      .map_err(|error| ScheduledRunnerExecutorError::Io(error.into()))?;
    }
    fs::set_permissions(&config.socket_path, fs::Permissions::from_mode(0o620))?;
    metadata = fs::symlink_metadata(&config.socket_path)?;
    if metadata.dev() != socket_path.device || metadata.ino() != socket_path.inode {
      return Err(ScheduledRunnerExecutorError::SocketOwnershipMismatch);
    }
    Ok(Self {
      listener,
      socket_path,
      _lifecycle_lock: lifecycle_lock,
      config,
    })
  }

  pub async fn accept(
    mut self,
  ) -> Result<ScheduledRunnerExecutorConnection, ScheduledRunnerExecutorError> {
    let accepted = tokio::time::timeout(self.config.accept_timeout, self.listener.accept())
      .await
      .map_err(|_| ScheduledRunnerExecutorError::AcceptTimeout)??;
    self.socket_path.unlink()?;
    let stream = accepted.0;
    require_executor_cloexec(&stream)?;
    let credentials = stream
      .peer_cred()
      .map_err(|_| ScheduledRunnerExecutorError::ControlCredentialUnavailable)?;
    let control_peer = peer(credentials);
    if control_peer.uid != self.config.control_uid || control_peer.gid != self.config.control_gid {
      return Err(ScheduledRunnerExecutorError::ControlCredentialMismatch);
    }
    Ok(ScheduledRunnerExecutorConnection::new(
      stream,
      control_peer,
      self.config.read_timeout,
      self.config.write_timeout,
    ))
  }
}

impl ScheduledRunnerExecutorConnection {
  fn new(
    stream: UnixStream,
    control_peer: ScheduledRunnerControlPeer,
    read_timeout: Duration,
    write_timeout: Duration,
  ) -> Self {
    Self {
      control_peer,
      framed: ScheduledRunnerFramed::new(stream, read_timeout, write_timeout),
    }
  }
}

fn require_executor_cloexec(fd: &impl AsFd) -> Result<(), ScheduledRunnerExecutorError> {
  let flags =
    fcntl(fd, FcntlArg::F_GETFD).map_err(|error| ScheduledRunnerExecutorError::Io(error.into()))?;
  if FdFlag::from_bits_truncate(flags).contains(FdFlag::FD_CLOEXEC) {
    Ok(())
  } else {
    Err(ScheduledRunnerExecutorError::CloseOnExecMissing)
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
  use std::os::fd::AsRawFd;
  use std::os::unix::fs::MetadataExt;
  use std::os::unix::process::CommandExt;
  use std::process::{Command, Stdio};
  use std::sync::Mutex;

  use crate::scheduled_remote_protocol::{
    ErrorFrame, REMOTE_PROTOCOL_VERSION, RemoteFrame, RemoteMessage,
  };
  use crate::scheduled_runner_control::{
    ScheduledRunnerControlConfig, ScheduledRunnerControlConnection,
  };

  static PROCESS_HARDENING_TEST: Mutex<()> = Mutex::new(());

  struct RestoreDumpable(bool);

  impl Drop for RestoreDumpable {
    fn drop(&mut self) {
      let _ = nix::sys::prctl::set_dumpable(self.0);
    }
  }

  fn config(path: PathBuf) -> ScheduledRunnerExecutorConfig {
    let owner = fs::metadata(path.parent().expect("socket parent")).expect("parent metadata");
    ScheduledRunnerExecutorConfig {
      socket_path: path,
      control_uid: owner.uid(),
      control_gid: owner.gid(),
      accept_timeout: Duration::from_secs(2),
      read_timeout: Duration::from_secs(2),
      write_timeout: Duration::from_secs(2),
    }
  }

  fn binding() -> RunBinding {
    RunBinding {
      run_id: "run-1".to_owned(),
      job_id: "job-1".to_owned(),
      attempt: 2,
      fence_token: 3,
      authority_digest: "a".repeat(64),
      profile_digest: "b".repeat(64),
      deployment_epoch: 4,
      credential_revision: "credential-v1".to_owned(),
    }
  }

  #[test]
  fn scheduled_task_codec_is_canonical_and_exactly_binding_scoped() {
    let encoded = r#"{"instruction":"check issues","previous_success":{"content":"prior","was_truncated":false},"scheduled_for":"2026-07-23T00:00:00Z","schema_version":1,"task_id":"scheduled:run-1:2:3"}"#;
    let task = decode_scheduled_remote_task(encoded, &binding()).expect("scheduled task");
    assert_eq!(task.instruction, "check issues");
    assert_eq!(
      task
        .previous_success
        .as_ref()
        .map(|context| context.content.as_str()),
      Some("prior")
    );
    assert!(decode_scheduled_remote_task(&format!(" {encoded}"), &binding()).is_err());
    let wrong = encoded.replace("scheduled:run-1:2:3", "scheduled:run-1:2:4");
    assert!(decode_scheduled_remote_task(&wrong, &binding()).is_err());
  }

  #[test]
  fn distinct_runtime_uid_cannot_read_hardened_supervisor_proc_authority() {
    let _serial = PROCESS_HARDENING_TEST.lock().expect("hardening test lock");
    if geteuid().as_raw() != 0 || getegid().as_raw() != 0 {
      return;
    }
    let original = nix::sys::prctl::get_dumpable().expect("dumpable state");
    let _restore = RestoreDumpable(original);
    harden_scheduled_executor_process().expect("harden supervisor");
    let temp = tempfile::NamedTempFile::new().expect("sentinel file");
    fs::write(temp.path(), "supervisor-secret-sentinel").expect("write sentinel");
    let sentinel = fs::File::open(temp.path()).expect("open sentinel");
    let script = r"
if ls /proc/$PPID/fd >/dev/null 2>&1; then exit 10; fi
if cat /proc/$PPID/fd/$SUPERVISOR_FD >/dev/null 2>&1; then exit 11; fi
if cat /proc/$PPID/environ >/dev/null 2>&1; then exit 12; fi
printf normal-child-launch
";
    let output = Command::new("/bin/sh")
      .arg("-c")
      .arg(script)
      .env_clear()
      .env("PATH", "/usr/bin:/bin")
      .env("SUPERVISOR_FD", sentinel.as_raw_fd().to_string())
      .uid(65_534)
      .gid(65_534)
      .output()
      .expect("launch same-UID child");
    assert!(output.status.success(), "child status: {:?}", output.status);
    assert_eq!(output.stdout, b"normal-child-launch");
  }

  #[tokio::test]
  async fn accepts_only_the_expected_control_credentials_then_unlinks() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let path = temp.path().join("control.sock");
    let expected = config(path.clone());
    let listener = ProtectedScheduledExecutorListener::bind(expected.clone()).expect("listener");
    let accept = listener.accept();
    let connect = UnixStream::connect(&path);
    let (server, client) = tokio::join!(accept, connect);
    let _client = client.expect("connect");
    assert_eq!(
      server.expect("authorized control").control_peer.uid,
      expected.control_uid
    );
    assert!(!path.exists());
  }

  #[tokio::test]
  async fn rejects_a_control_process_outside_the_pinned_mapping() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let path = temp.path().join("control.sock");
    let mut wrong = config(path.clone());
    wrong.control_uid = wrong.control_uid.saturating_add(1);
    let listener = ProtectedScheduledExecutorListener::bind(wrong).expect("listener");
    let accept = listener.accept();
    let connect = UnixStream::connect(&path);
    let (server, client) = tokio::join!(accept, connect);
    let _client = client.expect("connect");
    assert!(matches!(
      server,
      Err(ScheduledRunnerExecutorError::ControlCredentialMismatch)
    ));
    assert!(!path.exists());
  }

  #[tokio::test]
  async fn accept_timeout_unlinks_the_owned_socket() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let path = temp.path().join("control.sock");
    let mut candidate = config(path.clone());
    candidate.accept_timeout = Duration::from_millis(5);
    let listener = ProtectedScheduledExecutorListener::bind(candidate).expect("listener");
    assert!(matches!(
      listener.accept().await,
      Err(ScheduledRunnerExecutorError::AcceptTimeout)
    ));
    assert!(!path.exists());
  }

  #[test]
  fn refuses_to_replace_a_preexisting_non_socket_path() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let path = temp.path().join("control.sock");
    fs::write(&path, b"owned elsewhere").expect("preexisting path");
    assert!(matches!(
      ProtectedScheduledExecutorListener::bind(config(path.clone())),
      Err(ScheduledRunnerExecutorError::SocketTypeMismatch)
    ));
    assert_eq!(fs::read(path).expect("preserved path"), b"owned elsewhere");
  }

  #[tokio::test]
  async fn lifecycle_lock_rejects_a_second_executor() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let path = temp.path().join("control.sock");
    let _first = ProtectedScheduledExecutorListener::bind(config(path.clone())).expect("first");
    assert!(matches!(
      ProtectedScheduledExecutorListener::bind(config(path)),
      Err(ScheduledRunnerExecutorError::LifecycleLocked)
    ));
  }

  #[tokio::test]
  async fn recovers_a_root_owned_stale_socket_only_while_holding_the_lock() {
    let temp = tempfile::tempdir().expect("temporary directory");
    let path = temp.path().join("control.sock");
    let stale = std::os::unix::net::UnixListener::bind(&path).expect("stale socket");
    drop(stale);
    let listener =
      ProtectedScheduledExecutorListener::bind(config(path.clone())).expect("recover stale socket");
    drop(listener);
    assert!(!path.exists());
  }

  #[test]
  fn independent_control_and_executor_processes_exchange_over_protected_socket() {
    if geteuid().as_raw() != 0 || getegid().as_raw() != 0 {
      return;
    }
    let temp = tempfile::tempdir().expect("temporary directory");
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o755))
      .expect("shared socket directory permissions");
    let socket_path = temp.path().join("executor.sock");
    let executable = temp.path().join("runner-process-helper");
    fs::copy(
      std::env::current_exe().expect("test executable"),
      &executable,
    )
    .expect("copy process helper");
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o755))
      .expect("process helper permissions");
    let helper = "scheduled_runner_executor::tests::independent_runner_process_helper";
    let executor = Command::new(&executable)
      .args(["--exact", helper, "--nocapture"])
      .env_clear()
      .env("CODEOFF_TEST_RUNNER_ROLE", "executor")
      .env("CODEOFF_TEST_RUNNER_SOCKET", &socket_path)
      .env("EXECUTOR_PROFILE_SENTINEL", "present")
      .stdin(Stdio::null())
      .stdout(Stdio::piped())
      .stderr(Stdio::piped())
      .spawn()
      .expect("spawn executor helper");
    let mut control_command = Command::new(executable);
    control_command
      .args(["--exact", helper, "--nocapture"])
      .env_clear()
      .env("CODEOFF_TEST_RUNNER_ROLE", "control")
      .env("CODEOFF_TEST_RUNNER_SOCKET", &socket_path)
      .env("CONTROL_BROKER_KEY_SENTINEL", "present")
      .uid(65_533)
      .gid(65_533)
      .stdin(Stdio::null())
      .stdout(Stdio::piped())
      .stderr(Stdio::piped());
    let control = control_command.output().expect("run control helper");
    let executor = executor.wait_with_output().expect("wait executor helper");
    assert!(
      control.status.success(),
      "control helper failed: {}",
      String::from_utf8_lossy(&control.stderr)
    );
    assert!(
      executor.status.success(),
      "executor helper failed: {}",
      String::from_utf8_lossy(&executor.stderr)
    );
    assert!(String::from_utf8_lossy(&control.stdout).contains("control-exchange-ok"));
    assert!(String::from_utf8_lossy(&executor.stdout).contains("executor-exchange-ok"));
  }

  #[test]
  fn independent_runner_process_helper() {
    let Ok(role) = std::env::var("CODEOFF_TEST_RUNNER_ROLE") else {
      return;
    };
    let path =
      PathBuf::from(std::env::var_os("CODEOFF_TEST_RUNNER_SOCKET").expect("runner socket path"));
    let runtime = tokio::runtime::Runtime::new().expect("test runtime");
    match role.as_str() {
      "executor" => {
        assert_eq!(
          std::env::var("EXECUTOR_PROFILE_SENTINEL").as_deref(),
          Ok("present")
        );
        assert!(std::env::var_os("CONTROL_BROKER_KEY_SENTINEL").is_none());
        assert!(std::env::var_os("GITHUB_PAT").is_none());
        runtime.block_on(async {
          let listener = ProtectedScheduledExecutorListener::bind(ScheduledRunnerExecutorConfig {
            socket_path: path,
            control_uid: 65_533,
            control_gid: 65_533,
            accept_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(2),
            write_timeout: Duration::from_secs(2),
          })
          .expect("executor listener");
          let mut connection = listener.accept().await.expect("control connection");
          let frame = connection
            .framed
            .read_frame(now_millis())
            .await
            .expect("read control frame")
            .expect("control frame");
          assert!(matches!(frame.message, RemoteMessage::Error(_)));
          connection
            .framed
            .write_frame(&process_test_frame("executor-response"))
            .await
            .expect("write executor response");
        });
        println!("executor-exchange-ok");
      }
      "control" => {
        assert_eq!(
          std::env::var("CONTROL_BROKER_KEY_SENTINEL").as_deref(),
          Ok("present")
        );
        assert!(std::env::var_os("OPENAI_API_KEY").is_none());
        assert!(std::env::var_os("GITHUB_PAT").is_none());
        runtime.block_on(async {
          let mut connection =
            ScheduledRunnerControlConnection::connect(&ScheduledRunnerControlConfig {
              socket_path: path,
              executor_uid: 0,
              executor_gid: 0,
              connect_timeout: Duration::from_secs(5),
              read_timeout: Duration::from_secs(2),
              write_timeout: Duration::from_secs(2),
            })
            .await
            .expect("executor connection");
          connection
            .framed
            .write_frame(&process_test_frame("control-request"))
            .await
            .expect("write control frame");
          let response = connection
            .framed
            .read_frame(now_millis())
            .await
            .expect("read executor response")
            .expect("executor response");
          assert!(matches!(response.message, RemoteMessage::Error(_)));
        });
        println!("control-exchange-ok");
      }
      _ => panic!("unexpected helper role"),
    }
  }

  fn process_test_frame(message: &str) -> RemoteFrame {
    RemoteFrame {
      version: REMOTE_PROTOCOL_VERSION,
      session_nonce: "a".repeat(64),
      sequence: 1,
      message: RemoteMessage::Error(ErrorFrame {
        binding: None,
        preparation_nonce: None,
        code: "process-test".to_owned(),
        message: message.to_owned(),
        retryable: false,
      }),
    }
  }

  fn now_millis() -> u64 {
    u64::try_from(
      std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_millis(),
    )
    .expect("millisecond timestamp")
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
    candidate.accept_timeout = Duration::ZERO;
    assert!(matches!(
      candidate.validate(),
      Err(ScheduledRunnerExecutorError::InvalidConfiguration)
    ));
  }
}
