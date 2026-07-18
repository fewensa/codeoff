use std::env;
use std::future::Future;

use codeoff_config::SlackConfig;
use serde::Deserialize;

use crate::{
  SlackConfigCheck, SlackConfigError, SlackSocketError, SlackSocketTransport, TransportReceive,
  validate_slack_config,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketWorkerOptions {
  pub max_reconnects: usize,
}

impl Default for SocketWorkerOptions {
  fn default() -> Self {
    Self { max_reconnects: 3 }
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketWorkerAction {
  Continue,
  Shutdown,
}

/// Performs the offline Slack worker configuration check.
///
/// # Errors
///
/// Returns an error when the Slack configuration or required environment secrets are invalid.
pub fn check_slack_worker(config: &SlackConfig) -> Result<SlackConfigCheck, SlackConfigError> {
  validate_slack_config(config, |env_var| env::var(env_var).ok())
}

/// Receives Socket Mode envelopes, acknowledges each valid envelope, then invokes the slow path.
///
/// The slow path is deliberately invoked only after acknowledgement so normalization, state, and
/// agent work cannot delay Slack's retry acknowledgement. Returning `Shutdown` stops the worker
/// at an envelope boundary.
///
/// # Errors
///
/// Returns transport errors, including a reconnect limit reached after disconnects.
pub async fn run_socket_worker<T, F, Fut>(
  transport: &mut T,
  app_token: &str,
  options: SocketWorkerOptions,
  mut process: F,
) -> Result<usize, SlackSocketError>
where
  T: SlackSocketTransport + Send,
  F: FnMut(String) -> Fut,
  Fut: Future<Output = SocketWorkerAction>,
{
  transport.open(app_token).await?;
  let mut acknowledged = 0;
  let mut reconnects = 0;

  loop {
    match transport.receive().await? {
      TransportReceive::Envelope(raw_envelope) => {
        let Ok(envelope) = serde_json::from_str::<SocketEnvelope>(&raw_envelope) else {
          continue;
        };

        if envelope.envelope_id.trim().is_empty() {
          continue;
        }

        transport.acknowledge(&envelope.envelope_id).await?;
        acknowledged += 1;

        if process(raw_envelope).await == SocketWorkerAction::Shutdown {
          return Ok(acknowledged);
        }
      }
      TransportReceive::Disconnected => {
        if reconnects == options.max_reconnects {
          return Err(SlackSocketError::ReconnectLimit);
        }

        reconnects += 1;
        transport.open(app_token).await?;
      }
      TransportReceive::Ignored => {}
    }
  }
}

#[derive(Debug, Deserialize)]
struct SocketEnvelope {
  envelope_id: String,
}
