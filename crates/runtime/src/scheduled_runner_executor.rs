//! Unprivileged executor-side connection to the protected local runner-control channel.

use std::fmt;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use codeoff_agent_contract::{
  AgentTask, InvocationPrincipal, InvocationSource, PreviousSuccessContext, SessionMode, ToolPolicy,
};
use serde_json::{Map, Value};
use tokio::net::{UnixStream, unix::UCred};

use crate::scheduled_remote_protocol::RunBinding;
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
  InvalidTask,
  ControlChannel(ScheduledRunnerControlError),
  Io(std::io::Error),
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
