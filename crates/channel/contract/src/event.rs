use crate::ChannelContractError;
use crate::ChannelReplyTarget;
use crate::error::require_non_empty;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChannelEventKind {
  MessageReceived,
  MentionReceived,
  DirectMessageReceived,
  SlashCommandReceived,
  InteractionReceived,
  ReactionReceived,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelEvent {
  pub provider: String,
  pub connector_id: String,
  pub workspace_id: String,
  pub event_id: String,
  pub dedupe_key: String,
  pub kind: ChannelEventKind,
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub text: Option<String>,
  pub reply_target: Option<ChannelReplyTarget>,
  pub source_reference: Option<String>,
}

impl ChannelEvent {
  /// Creates a normalized channel event after validating its stable identifiers.
  ///
  /// # Errors
  ///
  /// Returns an error when a required identifier or dedupe key is empty.
  pub fn new(
    provider: impl Into<String>,
    connector_id: impl Into<String>,
    workspace_id: impl Into<String>,
    event_id: impl Into<String>,
    dedupe_key: impl Into<String>,
    kind: ChannelEventKind,
  ) -> Result<Self, ChannelContractError> {
    let provider = provider.into();
    let connector_id = connector_id.into();
    let workspace_id = workspace_id.into();
    let event_id = event_id.into();
    let dedupe_key = dedupe_key.into();

    require_non_empty(&provider, "provider")?;
    require_non_empty(&connector_id, "connector_id")?;
    require_non_empty(&workspace_id, "workspace_id")?;
    require_non_empty(&event_id, "event_id")?;
    require_non_empty(&dedupe_key, "dedupe_key")?;

    Ok(Self {
      provider,
      connector_id,
      workspace_id,
      event_id,
      dedupe_key,
      kind,
      text: None,
      reply_target: None,
      source_reference: None,
    })
  }

  #[must_use]
  pub fn with_text(mut self, text: Option<impl Into<String>>) -> Self {
    self.text = text.map(Into::into).and_then(|text| bounded_text(&text));
    self
  }

  /// Attaches an optional reply target and a provider-neutral source reference.
  ///
  /// # Errors
  ///
  /// Returns an error when a supplied source reference or reply target is invalid.
  pub fn with_source_details(
    mut self,
    reply_target: ChannelReplyTarget,
    source_reference: impl Into<String>,
  ) -> Result<Self, ChannelContractError> {
    let source_reference = source_reference.into();
    reply_target.validate()?;
    require_non_empty(&source_reference, "source_reference")?;
    self.reply_target = Some(reply_target);
    self.source_reference = Some(source_reference);
    Ok(self)
  }
}

fn bounded_text(text: &str) -> Option<String> {
  const MAX_TEXT_CHARS: usize = 4000;

  if text.is_empty() {
    return None;
  }

  Some(text.chars().take(MAX_TEXT_CHARS).collect())
}
