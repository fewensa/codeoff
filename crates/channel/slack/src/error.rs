use thiserror::Error;

#[derive(Debug, Error)]
pub enum SlackSocketError {
  #[error("failed to open Slack Socket Mode connection")]
  Open(#[source] reqwest::Error),

  #[error("Slack rejected Socket Mode connection: {0}")]
  OpenResponse(String),

  #[error("Slack Socket Mode open response did not include a WebSocket URL")]
  MissingSocketUrl,

  #[error("failed to open Slack Socket Mode WebSocket")]
  WebSocketOpen(#[source] tokio_tungstenite::tungstenite::Error),

  #[error("Slack Socket Mode connection is not open")]
  NotConnected,

  #[error("failed to receive from Slack Socket Mode")]
  Receive(#[source] tokio_tungstenite::tungstenite::Error),

  #[error("failed to acknowledge Slack Socket Mode envelope")]
  Acknowledge(#[source] tokio_tungstenite::tungstenite::Error),

  #[error("Slack Socket Mode reconnect limit reached")]
  ReconnectLimit,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SlackConfigError {
  #[error("slack.{field} must not be empty")]
  EmptyConfig { field: &'static str },

  #[error("missing required Slack secret in environment: {env_var}")]
  MissingSecret { env_var: String },
}
