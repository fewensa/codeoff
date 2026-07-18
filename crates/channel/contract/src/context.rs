use crate::error::require_non_empty;
use crate::{ChannelContractError, ChannelEvent, ChannelReplyTarget};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelCurrentContextRequest {
  pub connector_id: String,
  pub workspace_id: String,
  pub event_dedupe_key: String,
}

impl ChannelCurrentContextRequest {
  /// Creates a request for context around one current channel event.
  ///
  /// # Errors
  ///
  /// Returns an error when the connector, workspace, or event dedupe key is empty.
  pub fn new(
    connector_id: impl Into<String>,
    workspace_id: impl Into<String>,
    event_dedupe_key: impl Into<String>,
  ) -> Result<Self, ChannelContractError> {
    let connector_id = connector_id.into();
    let workspace_id = workspace_id.into();
    let event_dedupe_key = event_dedupe_key.into();

    require_non_empty(&connector_id, "connector_id")?;
    require_non_empty(&workspace_id, "workspace_id")?;
    require_non_empty(&event_dedupe_key, "event_dedupe_key")?;

    Ok(Self {
      connector_id,
      workspace_id,
      event_dedupe_key,
    })
  }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelSourceReference {
  pub uri: String,
  pub provider: String,
  pub workspace_id: String,
  pub channel_id: Option<String>,
  pub thread_id: Option<String>,
  pub message_ts: Option<String>,
  pub user_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelSourceLink {
  pub url: String,
  pub text: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelSourceAttachment {
  pub title: Option<String>,
  pub text: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelCurrentEvent {
  pub source_provider: String,
  pub connector_id: String,
  pub workspace_id: String,
  pub event_id: String,
  pub event_dedupe_key: String,
  pub event_kind: String,
  pub text: Option<String>,
  pub channel_id: Option<String>,
  pub thread_id: Option<String>,
  pub thread_ts: Option<String>,
  pub message_ts: Option<String>,
  pub user_id: Option<String>,
  pub reply_target: Option<ChannelReplyTarget>,
  pub source_reference: ChannelSourceReference,
  pub links: Vec<ChannelSourceLink>,
  pub attachments: Vec<ChannelSourceAttachment>,
  pub files: Vec<ChannelResourceInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelCurrentConversation {
  pub source_provider: String,
  pub connector_id: String,
  pub workspace_id: String,
  pub conversation_kind: String,
  pub channel_id: Option<String>,
  pub thread_id: Option<String>,
  pub user_id: Option<String>,
  pub reply_target: Option<ChannelReplyTarget>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelAvailableToolHint {
  pub name: String,
  pub purpose: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelContextPack {
  pub current_event: ChannelCurrentEvent,
  pub current_conversation: ChannelCurrentConversation,
  pub available_tools: Vec<ChannelAvailableToolHint>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelContextRequest {
  pub connector_id: String,
  pub workspace_id: String,
  pub target: ChannelReplyTarget,
  pub limit: u16,
  pub cursor: Option<String>,
}

impl ChannelContextRequest {
  /// Creates a bounded context request with validated identifiers and reply target.
  ///
  /// # Errors
  ///
  /// Returns an error when a required identifier or target identifier is empty.
  pub fn new(
    connector_id: impl Into<String>,
    workspace_id: impl Into<String>,
    target: ChannelReplyTarget,
    limit: u16,
  ) -> Result<Self, ChannelContractError> {
    let connector_id = connector_id.into();
    let workspace_id = workspace_id.into();

    require_non_empty(&connector_id, "connector_id")?;
    require_non_empty(&workspace_id, "workspace_id")?;
    target.validate()?;
    if limit == 0 {
      return Err(ChannelContractError::InvalidLimit { field: "limit" });
    }

    Ok(Self {
      connector_id,
      workspace_id,
      target,
      limit,
      cursor: None,
    })
  }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelContextPage {
  pub events: Vec<ChannelEvent>,
  pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelMessageFetchRequest {
  pub connector_id: String,
  pub workspace_id: String,
  pub channel_id: String,
  pub thread_id: Option<String>,
  pub message_ts: String,
}

impl ChannelMessageFetchRequest {
  /// Creates a request for one exact provider message.
  ///
  /// # Errors
  ///
  /// Returns an error when a required connector, workspace, channel, or message identifier is empty.
  pub fn new(
    connector_id: impl Into<String>,
    workspace_id: impl Into<String>,
    channel_id: impl Into<String>,
    thread_id: Option<impl Into<String>>,
    message_ts: impl Into<String>,
  ) -> Result<Self, ChannelContractError> {
    let connector_id = connector_id.into();
    let workspace_id = workspace_id.into();
    let channel_id = channel_id.into();
    let thread_id = thread_id.map(Into::into);
    let message_ts = message_ts.into();

    require_non_empty(&connector_id, "connector_id")?;
    require_non_empty(&workspace_id, "workspace_id")?;
    require_non_empty(&channel_id, "channel_id")?;
    if let Some(thread_id) = thread_id.as_deref() {
      require_non_empty(thread_id, "thread_id")?;
    }
    require_non_empty(&message_ts, "message_ts")?;

    Ok(Self {
      connector_id,
      workspace_id,
      channel_id,
      thread_id,
      message_ts,
    })
  }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelResourceInfoRequest {
  pub connector_id: String,
  pub workspace_id: String,
  pub resource_id: String,
}

impl ChannelResourceInfoRequest {
  /// Creates a provider-neutral resource metadata request.
  ///
  /// # Errors
  ///
  /// Returns an error when a required connector, workspace, or resource identifier is empty.
  pub fn new(
    connector_id: impl Into<String>,
    workspace_id: impl Into<String>,
    resource_id: impl Into<String>,
  ) -> Result<Self, ChannelContractError> {
    let connector_id = connector_id.into();
    let workspace_id = workspace_id.into();
    let resource_id = resource_id.into();

    require_non_empty(&connector_id, "connector_id")?;
    require_non_empty(&workspace_id, "workspace_id")?;
    require_non_empty(&resource_id, "resource_id")?;

    Ok(Self {
      connector_id,
      workspace_id,
      resource_id,
    })
  }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelResourceTextRequest {
  pub connector_id: String,
  pub workspace_id: String,
  pub resource_id: String,
}

impl ChannelResourceTextRequest {
  /// Creates a best-effort resource text extraction request.
  ///
  /// # Errors
  ///
  /// Returns an error when a required connector, workspace, or resource identifier is empty.
  pub fn new(
    connector_id: impl Into<String>,
    workspace_id: impl Into<String>,
    resource_id: impl Into<String>,
  ) -> Result<Self, ChannelContractError> {
    let request = ChannelResourceInfoRequest::new(connector_id, workspace_id, resource_id)?;
    Ok(Self {
      connector_id: request.connector_id,
      workspace_id: request.workspace_id,
      resource_id: request.resource_id,
    })
  }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelResourceDownloadRequest {
  pub connector_id: String,
  pub workspace_id: String,
  pub resource_id: String,
}

impl ChannelResourceDownloadRequest {
  /// Creates a request to materialize a channel resource as a local artifact.
  ///
  /// # Errors
  ///
  /// Returns an error when a required connector, workspace, or resource identifier is empty.
  pub fn new(
    connector_id: impl Into<String>,
    workspace_id: impl Into<String>,
    resource_id: impl Into<String>,
  ) -> Result<Self, ChannelContractError> {
    let request = ChannelResourceInfoRequest::new(connector_id, workspace_id, resource_id)?;
    Ok(Self {
      connector_id: request.connector_id,
      workspace_id: request.workspace_id,
      resource_id: request.resource_id,
    })
  }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelResourceInfo {
  pub connector_id: String,
  pub workspace_id: String,
  pub resource_id: String,
  pub name: Option<String>,
  pub media_type: Option<String>,
  pub size_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelMessageSnapshot {
  pub connector_id: String,
  pub workspace_id: String,
  pub channel_id: String,
  pub thread_id: Option<String>,
  pub message_ts: String,
  pub text: Option<String>,
  pub resources: Vec<ChannelResourceInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelResourceText {
  pub connector_id: String,
  pub workspace_id: String,
  pub resource_id: String,
  pub text: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelResourceDownload {
  pub connector_id: String,
  pub workspace_id: String,
  pub resource_id: String,
  pub artifact_uri: String,
  pub local_path: Option<String>,
}
