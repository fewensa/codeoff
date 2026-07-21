use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum StateError {
  #[error("failed to create state directory {path}: {source}")]
  CreateStateDir {
    path: PathBuf,
    #[source]
    source: std::io::Error,
  },

  #[error("failed to write state directory probe {path}: {source}")]
  WriteProbe {
    path: PathBuf,
    #[source]
    source: std::io::Error,
  },

  #[error("failed to create state database directory {path}: {source}")]
  CreateDatabaseDir {
    path: PathBuf,
    #[source]
    source: std::io::Error,
  },

  #[error("failed to remove state directory probe {path}: {source}")]
  RemoveProbe {
    path: PathBuf,
    #[source]
    source: std::io::Error,
  },

  #[error("invalid state database URL: {reason}")]
  InvalidDatabaseUrl { reason: &'static str },

  #[error("failed to connect state database")]
  Connect,

  #[error("failed to run state database migrations: {source}")]
  Migrate {
    #[source]
    source: sqlx::migrate::MigrateError,
  },

  #[error("failed to claim idempotency key: {source}")]
  ClaimIdempotencyKey {
    #[source]
    source: sqlx::Error,
  },

  #[error("failed to persist Slack source event: {source}")]
  PersistSlackSourceEvent {
    #[source]
    source: sqlx::Error,
  },

  #[error("failed to serialize normalized channel event: {source}")]
  SerializeChannelEvent {
    #[source]
    source: serde_json::Error,
  },

  #[error("failed to serialize state payload {context}: {source}")]
  SerializeStatePayload {
    context: &'static str,
    #[source]
    source: serde_json::Error,
  },

  #[error("failed to query channel event state: {source}")]
  QueryChannelEventState {
    #[source]
    source: sqlx::Error,
  },

  #[error("failed to manage channel event queue state: {source}")]
  ChannelEventQueue {
    #[source]
    source: sqlx::Error,
  },

  #[error("failed to deserialize queued channel event: {source}")]
  DeserializeChannelEvent {
    #[source]
    source: serde_json::Error,
  },

  #[error("failed to manage Slack delivery state: {source}")]
  SlackDelivery {
    #[source]
    source: sqlx::Error,
  },

  #[error("failed to clean retained data: {source}")]
  CleanupRetainedData {
    #[source]
    source: sqlx::Error,
  },

  #[error("invalid persisted Slack delivery status: {status}")]
  InvalidSlackDeliveryStatus { status: String },

  #[error("invalid persisted Slack delivery operation: {operation}")]
  InvalidSlackDeliveryOperation { operation: String },

  #[error("invalid persisted Slack processing indicator status: {status}")]
  InvalidSlackProcessingIndicatorStatus { status: String },

  #[error("invalid persisted channel event status: {status}")]
  InvalidChannelEventStatus { status: String },

  #[error("failed to serialize Slack delivery response: {source}")]
  SerializeSlackDeliveryResponse {
    #[source]
    source: serde_json::Error,
  },

  #[error("failed to record context fetch attempt: {source}")]
  ContextFetchAttempt {
    #[source]
    source: sqlx::Error,
  },

  #[error("invalid scheduler state: {reason}")]
  InvalidSchedulerState { reason: String },

  #[error("scheduler generation conflict")]
  SchedulerGenerationConflict,

  #[error("scheduled once occurrence is expired and cannot be resumed")]
  ScheduledOnceExpired,

  #[error("failed to manage scheduler state: {source}")]
  Scheduler {
    #[source]
    source: sqlx::Error,
  },
}

impl StateError {
  #[must_use]
  pub fn is_transient_storage_contention(&self) -> bool {
    let (Self::SlackDelivery { source } | Self::Scheduler { source }) = self else {
      return false;
    };
    let sqlx::Error::Database(error) = source else {
      return false;
    };
    matches!(
      error.code().as_deref(),
      Some("5" | "6" | "261" | "262" | "517" | "518" | "773")
    )
  }
}
