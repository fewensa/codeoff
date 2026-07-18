use serde::Deserialize;
use serde_json::Value;

use async_trait::async_trait;

use crate::SlackSocketError;

/// Slack Socket Mode's transport envelope. This stays inside the Slack connector.
#[derive(Debug, Deserialize)]
pub struct SocketModeEnvelope {
  pub envelope_id: Option<String>,
  #[serde(rename = "type")]
  pub envelope_type: String,
  pub payload: Value,
}

/// The result of reading one item from a Slack Socket Mode connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportReceive {
  Envelope(String),
  Ignored,
  Disconnected,
}

/// Socket Mode operations used by the Slack receive worker.
#[async_trait]
pub trait SlackSocketTransport {
  /// Opens a new Socket Mode connection using the Slack app-level token.
  async fn open(&mut self, app_token: &str) -> Result<(), SlackSocketError>;

  /// Receives the next raw Socket Mode envelope or a connection close notification.
  async fn receive(&mut self) -> Result<TransportReceive, SlackSocketError>;

  /// Acknowledges a Socket Mode envelope without performing application work.
  async fn acknowledge(&mut self, envelope_id: &str) -> Result<(), SlackSocketError>;
}
