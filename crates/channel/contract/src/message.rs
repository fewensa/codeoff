use crate::error::require_non_empty;
use crate::{ChannelConnectorCapabilities, ChannelContractError};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChannelReplyTarget {
  Channel {
    channel_id: String,
  },
  Thread {
    channel_id: String,
    thread_id: String,
  },
  DirectMessage {
    user_account_id: String,
  },
  Ephemeral {
    channel_id: String,
    user_account_id: String,
  },
}

impl ChannelReplyTarget {
  pub(crate) fn validate(&self) -> Result<(), ChannelContractError> {
    match self {
      Self::Channel { channel_id } => require_non_empty(channel_id, "channel_id"),
      Self::Thread {
        channel_id,
        thread_id,
      } => {
        require_non_empty(channel_id, "channel_id")?;
        require_non_empty(thread_id, "thread_id")
      }
      Self::DirectMessage { user_account_id } => {
        require_non_empty(user_account_id, "user_account_id")
      }
      Self::Ephemeral {
        channel_id,
        user_account_id,
      } => {
        require_non_empty(channel_id, "channel_id")?;
        require_non_empty(user_account_id, "user_account_id")
      }
    }
  }

  pub(crate) const fn kind_name(&self) -> &'static str {
    match self {
      Self::Channel { .. } => "channel",
      Self::Thread { .. } => "thread",
      Self::DirectMessage { .. } => "direct_message",
      Self::Ephemeral { .. } => "ephemeral",
    }
  }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelMessageRequest {
  pub connector_id: String,
  pub workspace_id: String,
  pub dedupe_key: String,
  pub target: ChannelReplyTarget,
  pub text: String,
}

impl ChannelMessageRequest {
  /// Creates a message request with validated identifiers, target, and text.
  ///
  /// # Errors
  ///
  /// Returns an error when a required identifier, target identifier, dedupe key, or text is empty.
  pub fn new(
    connector_id: impl Into<String>,
    workspace_id: impl Into<String>,
    dedupe_key: impl Into<String>,
    target: ChannelReplyTarget,
    text: impl Into<String>,
  ) -> Result<Self, ChannelContractError> {
    let connector_id = connector_id.into();
    let workspace_id = workspace_id.into();
    let dedupe_key = dedupe_key.into();
    let text = text.into();

    require_non_empty(&connector_id, "connector_id")?;
    require_non_empty(&workspace_id, "workspace_id")?;
    require_non_empty(&dedupe_key, "dedupe_key")?;
    require_non_empty(&text, "text")?;
    target.validate()?;

    Ok(Self {
      connector_id,
      workspace_id,
      dedupe_key,
      target,
      text,
    })
  }

  /// Validates that the connector capabilities permit this request target.
  ///
  /// # Errors
  ///
  /// Returns an error when the target needs an unsupported capability.
  pub fn validate_for(
    &self,
    capabilities: &ChannelConnectorCapabilities,
  ) -> Result<(), ChannelContractError> {
    if capabilities.supports_reply_target(&self.target) {
      Ok(())
    } else {
      Err(ChannelContractError::UnsupportedReplyTarget {
        target: self.target.kind_name(),
      })
    }
  }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelMessageReceipt {
  pub connector_id: String,
  pub workspace_id: String,
  pub request_dedupe_key: String,
  pub message_id: String,
}
