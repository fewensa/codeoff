use std::collections::HashSet;

use codeoff_channel_contract::ChannelEventKind;
use codeoff_config::SlackConfig;
use codeoff_state::{StateError, StateStore};
use thiserror::Error;

use crate::{
  SlackMentionFilter, SlackNormalizeError, normalize_socket_mode_envelope_with_mention_filter,
};

#[derive(Debug, Error)]
pub enum SlackIntakeError {
  #[error(transparent)]
  Normalize(#[from] SlackNormalizeError),
  #[error(transparent)]
  State(#[from] StateError),
}

/// The outcome of accepting a Slack Socket Mode envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlackIntakeResult {
  /// A supported envelope was normalized and atomically queued.
  Queued,
  /// A supported envelope was already persisted, so no queue row was added.
  Duplicate,
  /// The envelope is a benign Socket Mode payload Codeoff does not handle.
  Ignored,
}

/// Slack intake boundary that normalizes and persists received Socket Mode envelopes.
#[derive(Debug, Clone)]
pub struct SlackIntake {
  state: StateStore,
  connector_id: String,
  mention_filter: SlackMentionFilter,
  allowed_dm_user_ids: HashSet<String>,
}

impl SlackIntake {
  pub fn new(state: StateStore, connector_id: impl Into<String>) -> Self {
    Self {
      state,
      connector_id: connector_id.into(),
      mention_filter: SlackMentionFilter::default(),
      allowed_dm_user_ids: HashSet::new(),
    }
  }

  #[must_use]
  pub fn with_slack_config(
    state: StateStore,
    connector_id: impl Into<String>,
    config: &SlackConfig,
  ) -> Self {
    Self {
      state,
      connector_id: connector_id.into(),
      mention_filter: SlackMentionFilter::from(config),
      allowed_dm_user_ids: config.allowed_dm_user_ids.iter().cloned().collect(),
    }
  }

  #[must_use]
  pub fn mention_filter(&self) -> &SlackMentionFilter {
    &self.mention_filter
  }

  /// Normalizes and atomically persists a raw Slack Socket Mode envelope.
  ///
  /// # Errors
  ///
  ///
  /// Unsupported-but-valid Socket Mode payloads are ignored so the live worker can continue.
  /// Returns an error for malformed envelopes or persistence failures.
  pub async fn accept(&self, raw_envelope: &str) -> Result<SlackIntakeResult, SlackIntakeError> {
    let normalized = match normalize_socket_mode_envelope_with_mention_filter(
      raw_envelope,
      &self.connector_id,
      Some(&self.mention_filter),
    ) {
      Ok(normalized) => normalized,
      Err(SlackNormalizeError::UnsupportedPayload { .. }) => return Ok(SlackIntakeResult::Ignored),
      Err(error) => return Err(error.into()),
    };
    if !self.allows_direct_message_sender(&normalized) {
      return Ok(SlackIntakeResult::Ignored);
    }
    let inserted = self
      .state
      .persist_slack_source_event(&normalized.source_event, &normalized.event)
      .await
      .map_err(SlackIntakeError::from)?;
    Ok(if inserted {
      SlackIntakeResult::Queued
    } else {
      SlackIntakeResult::Duplicate
    })
  }

  /// Returns the number of persisted normalized queue rows.
  ///
  /// # Errors
  ///
  /// Returns an error when the state store cannot read the queue table.
  pub async fn queued_event_count(&self) -> Result<i64, StateError> {
    self.state.channel_event_queue_count().await
  }

  /// Returns the number of persisted Slack source rows.
  ///
  /// # Errors
  ///
  /// Returns an error when the state store cannot read the source event table.
  pub async fn source_event_count(&self) -> Result<i64, StateError> {
    self.state.slack_source_event_count().await
  }

  fn allows_direct_message_sender(&self, normalized: &crate::NormalizedSlackEvent) -> bool {
    normalized.event.kind != ChannelEventKind::DirectMessageReceived
      || self.allowed_dm_user_ids.is_empty()
      || normalized
        .source_event
        .user_id
        .as_ref()
        .is_some_and(|user_id| self.allowed_dm_user_ids.contains(user_id))
  }
}
