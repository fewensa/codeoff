use crate::ChannelContractError;
use crate::error::require_non_empty;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelWorkspaceRequest {
  pub connector_id: String,
  pub workspace_id: String,
}

impl ChannelWorkspaceRequest {
  /// Creates a workspace-scoped provider-neutral channel request.
  ///
  /// # Errors
  ///
  /// Returns an error when the connector or workspace identifier is empty.
  pub fn new(
    connector_id: impl Into<String>,
    workspace_id: impl Into<String>,
  ) -> Result<Self, ChannelContractError> {
    let connector_id = connector_id.into();
    let workspace_id = workspace_id.into();

    require_non_empty(&connector_id, "connector_id")?;
    require_non_empty(&workspace_id, "workspace_id")?;

    Ok(Self {
      connector_id,
      workspace_id,
    })
  }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelLookupRequest {
  pub connector_id: String,
  pub workspace_id: String,
  pub id: String,
}

impl ChannelLookupRequest {
  /// Creates an exact provider-neutral lookup request.
  ///
  /// # Errors
  ///
  /// Returns an error when the connector, workspace, or identifier is empty.
  pub fn new(
    connector_id: impl Into<String>,
    workspace_id: impl Into<String>,
    id: impl Into<String>,
  ) -> Result<Self, ChannelContractError> {
    let base = ChannelWorkspaceRequest::new(connector_id, workspace_id)?;
    let id = id.into();
    require_non_empty(&id, "id")?;

    Ok(Self {
      connector_id: base.connector_id,
      workspace_id: base.workspace_id,
      id,
    })
  }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelSearchRequest {
  pub connector_id: String,
  pub workspace_id: String,
  pub query: String,
  pub limit: u16,
}

impl ChannelSearchRequest {
  /// Creates a bounded provider-neutral search request.
  ///
  /// # Errors
  ///
  /// Returns an error when identifiers or query are empty, or limit is zero.
  pub fn new(
    connector_id: impl Into<String>,
    workspace_id: impl Into<String>,
    query: impl Into<String>,
    limit: u16,
  ) -> Result<Self, ChannelContractError> {
    let base = ChannelWorkspaceRequest::new(connector_id, workspace_id)?;
    let query = query.into();
    require_non_empty(&query, "query")?;
    if limit == 0 {
      return Err(ChannelContractError::InvalidLimit { field: "limit" });
    }

    Ok(Self {
      connector_id: base.connector_id,
      workspace_id: base.workspace_id,
      query,
      limit,
    })
  }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelWorkspaceSummary {
  pub provider: String,
  pub connector_id: String,
  pub connector_name: Option<String>,
  pub workspace_id: String,
  pub workspace_name: Option<String>,
  pub display_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelUserSearchRequest {
  pub connector_id: String,
  pub workspace_id: String,
  pub query: String,
  pub limit: u16,
}

impl ChannelUserSearchRequest {
  /// Creates a bounded provider-neutral user search request.
  ///
  /// # Errors
  ///
  /// Returns an error when identifiers or query are empty, or limit is zero.
  pub fn new(
    connector_id: impl Into<String>,
    workspace_id: impl Into<String>,
    query: impl Into<String>,
    limit: u16,
  ) -> Result<Self, ChannelContractError> {
    let request = ChannelSearchRequest::new(connector_id, workspace_id, query, limit)?;
    Ok(Self {
      connector_id: request.connector_id,
      workspace_id: request.workspace_id,
      query: request.query,
      limit: request.limit,
    })
  }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelUserResolveRequest {
  pub connector_id: String,
  pub workspace_id: String,
  pub query: String,
}

impl ChannelUserResolveRequest {
  /// Creates a provider-neutral user resolution request.
  ///
  /// # Errors
  ///
  /// Returns an error when identifiers or query are empty.
  pub fn new(
    connector_id: impl Into<String>,
    workspace_id: impl Into<String>,
    query: impl Into<String>,
  ) -> Result<Self, ChannelContractError> {
    let base = ChannelWorkspaceRequest::new(connector_id, workspace_id)?;
    let query = query.into();
    require_non_empty(&query, "query")?;

    Ok(Self {
      connector_id: base.connector_id,
      workspace_id: base.workspace_id,
      query,
    })
  }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelUserSummary {
  pub connector_id: String,
  pub workspace_id: String,
  pub user_id: String,
  pub display_name: Option<String>,
  pub handle: Option<String>,
  pub email: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelUserResolveResult {
  pub user: Option<ChannelUserSummary>,
  pub candidates: Vec<ChannelUserSummary>,
}

impl ChannelUserResolveResult {
  #[must_use]
  pub fn resolved(user: ChannelUserSummary) -> Self {
    Self {
      user: Some(user),
      candidates: Vec::new(),
    }
  }

  #[must_use]
  pub fn ambiguous(candidates: Vec<ChannelUserSummary>) -> Self {
    Self {
      user: None,
      candidates,
    }
  }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelSummary {
  pub connector_id: String,
  pub workspace_id: String,
  pub channel_id: String,
  pub name: Option<String>,
  pub is_direct_message: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelResolveResult {
  pub channel: Option<ChannelSummary>,
  pub candidates: Vec<ChannelSummary>,
}

impl ChannelResolveResult {
  #[must_use]
  pub fn resolved(channel: ChannelSummary) -> Self {
    Self {
      channel: Some(channel),
      candidates: Vec::new(),
    }
  }

  #[must_use]
  pub fn ambiguous(candidates: Vec<ChannelSummary>) -> Self {
    Self {
      channel: None,
      candidates,
    }
  }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelSenderSummary {
  pub connector_id: String,
  pub workspace_id: String,
  pub sender_id: String,
  pub display_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelConnectorStatus {
  pub connector_id: String,
  pub workspace_id: String,
  pub connected: bool,
  pub status: String,
  pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelThreadReplyRequest {
  pub connector_id: String,
  pub workspace_id: String,
  pub channel_id: String,
  pub thread_id: String,
  pub request_dedupe_key: String,
  pub text: String,
  pub send_as: Option<String>,
}

impl ChannelThreadReplyRequest {
  /// Creates a provider-neutral thread reply request.
  ///
  /// # Errors
  ///
  /// Returns an error when a required identifier, dedupe key, or text is empty.
  pub fn new(
    connector_id: impl Into<String>,
    workspace_id: impl Into<String>,
    channel_id: impl Into<String>,
    thread_id: impl Into<String>,
    request_dedupe_key: impl Into<String>,
    text: impl Into<String>,
    send_as: Option<impl Into<String>>,
  ) -> Result<Self, ChannelContractError> {
    let base = ChannelWorkspaceRequest::new(connector_id, workspace_id)?;
    let channel_id = channel_id.into();
    let thread_id = thread_id.into();
    let request_dedupe_key = request_dedupe_key.into();
    let text = text.into();
    let send_as = send_as.map(Into::into);

    require_non_empty(&channel_id, "channel_id")?;
    require_non_empty(&thread_id, "thread_id")?;
    require_non_empty(&request_dedupe_key, "request_dedupe_key")?;
    require_non_empty(&text, "text")?;
    if let Some(send_as) = send_as.as_deref() {
      require_non_empty(send_as, "send_as")?;
    }

    Ok(Self {
      connector_id: base.connector_id,
      workspace_id: base.workspace_id,
      channel_id,
      thread_id,
      request_dedupe_key,
      text,
      send_as,
    })
  }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelThreadReplyReceipt {
  pub connector_id: String,
  pub workspace_id: String,
  pub channel_id: String,
  pub thread_id: String,
  pub request_dedupe_key: String,
  pub message_id: String,
  pub send_as: Option<String>,
}
