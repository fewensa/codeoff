use async_trait::async_trait;
use codeoff_channel_contract::{
  ChannelAvailableToolHint, ChannelConnectorStatus, ChannelContextPack, ChannelContextPage,
  ChannelContextRequest, ChannelContractError, ChannelCurrentContextRequest,
  ChannelCurrentConversation, ChannelCurrentEvent, ChannelEvent, ChannelEventKind,
  ChannelLookupRequest, ChannelMessageFetchRequest, ChannelMessageRequest, ChannelMessageSnapshot,
  ChannelReplyTarget, ChannelResolveResult, ChannelResourceDownload,
  ChannelResourceDownloadRequest, ChannelResourceInfo, ChannelResourceInfoRequest,
  ChannelResourceText, ChannelResourceTextRequest, ChannelSearchRequest, ChannelSenderSummary,
  ChannelSourceAttachment, ChannelSourceLink, ChannelSourceReference, ChannelSummary,
  ChannelThreadReplyReceipt, ChannelThreadReplyRequest, ChannelUserResolveRequest,
  ChannelUserResolveResult, ChannelUserSearchRequest, ChannelUserSummary, ChannelWorkspaceRequest,
  ChannelWorkspaceSummary,
};
use std::error::Error;
use std::fmt;

use crate::{ProcessingStreamFinishRequest, ProcessingStreamManager, StateProcessingStreamManager};
use codeoff_state::{
  SlackDeliveryRequest, SlackDeliverySender, SlackDeliveryStatus, SlackSourceReferences,
  StateError, StateStore,
};
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplyToEventRequest {
  pub connector_id: String,
  pub workspace_id: String,
  pub event_dedupe_key: String,
  pub request_dedupe_key: String,
  pub text: String,
  pub send_as: Option<String>,
  pub now_unix_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendMessageRequest {
  pub connector_id: String,
  pub workspace_id: String,
  pub request_dedupe_key: String,
  pub target: ChannelReplyTarget,
  pub text: String,
  pub send_as: Option<String>,
  pub now_unix_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueuedDelivery {
  pub request_dedupe_key: String,
  pub queued: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetDeliveryStatusRequest {
  pub workspace_id: String,
  pub request_dedupe_key: String,
  pub now_unix_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetThreadContextRequest {
  pub connector_id: String,
  pub workspace_id: String,
  pub channel_id: String,
  pub thread_id: String,
  pub limit: u16,
  pub cursor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetRecentMessagesRequest {
  pub connector_id: String,
  pub workspace_id: String,
  pub channel_id: String,
  pub limit: u16,
  pub cursor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlackContextBootstrapRequest {
  pub event: ChannelEvent,
  pub channel_id: Option<String>,
  pub thread_id: Option<String>,
  pub limit: u16,
}

#[derive(Debug)]
pub enum ChannelToolError {
  MissingSourceEvent,

  MissingReplyTarget,

  UnsupportedTarget,

  InvalidSender { value: String },

  InvalidRequest(ChannelContractError),

  ContextProvider(ChannelContextProviderError),

  ResourceProvider(ChannelResourceProviderError),

  State(StateError),
}

impl fmt::Display for ChannelToolError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::MissingSourceEvent => {
        write!(formatter, "source event was not found")
      }
      Self::MissingReplyTarget => {
        write!(
          formatter,
          "source event does not include a Slack channel/message target"
        )
      }
      Self::UnsupportedTarget => {
        write!(
          formatter,
          "channel operation supports only thread replies and direct messages"
        )
      }
      Self::InvalidSender { value } => write!(formatter, "invalid channel sender: {value}"),
      Self::InvalidRequest(error) => write!(formatter, "invalid channel request: {error}"),
      Self::ContextProvider(error) => write!(formatter, "channel context provider failed: {error}"),
      Self::ResourceProvider(error) => {
        write!(formatter, "channel resource provider failed: {error}")
      }
      Self::State(error) => write!(formatter, "state operation failed: {error}"),
    }
  }
}

impl Error for ChannelToolError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelContextProviderError {
  Request { message: String },

  RateLimited { retry_after_seconds: Option<u64> },

  Unavailable,

  InvalidResponse { message: String },

  Provider { message: String },

  UnsupportedTarget,

  Deferred { available_at: u64 },
}

impl fmt::Display for ChannelContextProviderError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Request { message } => write!(formatter, "context request failed: {message}"),
      Self::RateLimited {
        retry_after_seconds,
      } => {
        write!(
          formatter,
          "context provider was rate limited; retry after {retry_after_seconds:?} seconds"
        )
      }
      Self::Unavailable => write!(formatter, "context target is unavailable"),
      Self::InvalidResponse { message } => {
        write!(
          formatter,
          "context provider returned an invalid response: {message}"
        )
      }
      Self::Provider { message } => write!(formatter, "context provider error: {message}"),
      Self::UnsupportedTarget => write!(formatter, "context target is unsupported"),
      Self::Deferred { available_at } => {
        write!(formatter, "context fetch deferred until {available_at}")
      }
    }
  }
}

impl Error for ChannelContextProviderError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelResourceProviderError {
  Request { message: String },

  RateLimited { retry_after_seconds: Option<u64> },

  Unavailable,

  InvalidResponse { message: String },

  Provider { message: String },

  UnsupportedResource,

  Deferred { available_at: u64 },
}

impl fmt::Display for ChannelResourceProviderError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Request { message } => write!(formatter, "resource request failed: {message}"),
      Self::RateLimited {
        retry_after_seconds,
      } => {
        write!(
          formatter,
          "resource provider was rate limited; retry after {retry_after_seconds:?} seconds"
        )
      }
      Self::Unavailable => write!(formatter, "resource target is unavailable"),
      Self::InvalidResponse { message } => {
        write!(
          formatter,
          "resource provider returned an invalid response: {message}"
        )
      }
      Self::Provider { message } => write!(formatter, "resource provider error: {message}"),
      Self::UnsupportedResource => write!(formatter, "resource target is unsupported"),
      Self::Deferred { available_at } => {
        write!(formatter, "resource fetch deferred until {available_at}")
      }
    }
  }
}

impl Error for ChannelResourceProviderError {}

#[async_trait]
pub trait ChannelContextProvider: Send + Sync {
  async fn fetch_context(
    &self,
    request: ChannelContextRequest,
  ) -> Result<ChannelContextPage, ChannelContextProviderError>;
}

#[async_trait]
pub trait ChannelResourceProvider: Send + Sync {
  async fn fetch_message(
    &self,
    request: ChannelMessageFetchRequest,
  ) -> Result<ChannelMessageSnapshot, ChannelResourceProviderError>;

  async fn fetch_resource_info(
    &self,
    request: ChannelResourceInfoRequest,
  ) -> Result<ChannelResourceInfo, ChannelResourceProviderError>;

  async fn read_resource_text(
    &self,
    request: ChannelResourceTextRequest,
  ) -> Result<ChannelResourceText, ChannelResourceProviderError>;

  async fn download_resource(
    &self,
    request: ChannelResourceDownloadRequest,
  ) -> Result<ChannelResourceDownload, ChannelResourceProviderError>;
}

#[async_trait]
pub trait ChannelUserProvider: Send + Sync {
  async fn search_users(
    &self,
    request: ChannelUserSearchRequest,
  ) -> Result<Vec<ChannelUserSummary>, ChannelToolError>;

  async fn get_user(
    &self,
    request: ChannelLookupRequest,
  ) -> Result<Option<ChannelUserSummary>, ChannelToolError>;

  async fn resolve_user(
    &self,
    request: ChannelUserResolveRequest,
  ) -> Result<ChannelUserResolveResult, ChannelToolError>;
}

#[async_trait]
pub trait ChannelChannelProvider: Send + Sync {
  async fn search_channels(
    &self,
    request: ChannelSearchRequest,
  ) -> Result<Vec<ChannelSummary>, ChannelToolError>;

  async fn get_channel(
    &self,
    request: ChannelLookupRequest,
  ) -> Result<Option<ChannelSummary>, ChannelToolError>;

  async fn resolve_channel(
    &self,
    request: ChannelSearchRequest,
  ) -> Result<Vec<ChannelSummary>, ChannelToolError>;
}

#[async_trait]
pub trait ChannelSenderProvider: Send + Sync {
  async fn list_senders(
    &self,
    request: ChannelWorkspaceRequest,
  ) -> Result<Vec<ChannelSenderSummary>, ChannelToolError>;
}

#[async_trait]
pub trait ChannelStatusProvider: Send + Sync {
  async fn list_workspaces(&self) -> Result<Vec<ChannelWorkspaceSummary>, ChannelToolError>;

  async fn get_connector_status(
    &self,
    request: ChannelWorkspaceRequest,
  ) -> Result<ChannelConnectorStatus, ChannelToolError>;
}

#[async_trait]
pub trait ChannelThreadReplyProvider: Send + Sync {
  async fn reply_to_thread(
    &self,
    request: ChannelThreadReplyRequest,
  ) -> Result<ChannelThreadReplyReceipt, ChannelToolError>;
}

pub async fn reply_to_event(
  state: &StateStore,
  request: ReplyToEventRequest,
) -> Result<QueuedDelivery, ChannelToolError> {
  let processing_streams = StateProcessingStreamManager::new(state.clone());
  reply_to_event_with_processing_streams(state, &processing_streams, request).await
}

pub async fn reply_to_event_with_processing_streams(
  state: &StateStore,
  processing_streams: &dyn ProcessingStreamManager,
  request: ReplyToEventRequest,
) -> Result<QueuedDelivery, ChannelToolError> {
  let source = state
    .slack_source_references(&request.workspace_id, &request.event_dedupe_key)
    .await
    .map_err(ChannelToolError::from)?;
  if !source.found {
    return Err(ChannelToolError::MissingSourceEvent);
  }
  let channel_id = source
    .channel_id
    .ok_or(ChannelToolError::MissingReplyTarget)?;
  let source_thread_ts = source.thread_id;
  let source_message_ts = source.message_ts;
  let reply_thread_ts = source_thread_ts
    .clone()
    .or_else(|| source_message_ts.clone())
    .ok_or(ChannelToolError::MissingReplyTarget)?;
  let thread_ts = if is_slack_direct_message_channel(&channel_id) {
    match (source_thread_ts, source_message_ts) {
      (Some(thread_ts), Some(message_ts)) if thread_ts != message_ts => Some(thread_ts),
      _ => None,
    }
  } else {
    Some(reply_thread_ts)
  };
  let sender = parse_send_as(request.send_as.as_deref())?;
  let stream_completion = processing_streams
    .finish_processing_stream(ProcessingStreamFinishRequest {
      connector_id: request.connector_id.clone(),
      workspace_id: request.workspace_id.clone(),
      event_dedupe_key: request.event_dedupe_key,
      request_dedupe_key: request.request_dedupe_key.clone(),
      channel_id: channel_id.clone(),
      thread_ts: thread_ts.clone(),
      text: request.text.clone(),
      sender: sender.clone(),
      now_unix_seconds: request.now_unix_seconds,
    })
    .await
    .map_err(ChannelToolError::from)?;
  if stream_completion.completed_existing_stream {
    return Ok(QueuedDelivery {
      request_dedupe_key: stream_completion.request_dedupe_key,
      queued: stream_completion.queued,
    });
  }

  enqueue_slack_delivery(
    state,
    SlackDeliveryRequest {
      connector_id: request.connector_id,
      workspace_id: request.workspace_id,
      request_dedupe_key: request.request_dedupe_key,
      channel_id,
      thread_ts,
      text: request.text,
      sender,
    },
    request.now_unix_seconds,
  )
  .await
}

fn is_slack_direct_message_channel(channel_id: &str) -> bool {
  channel_id.starts_with('D')
}

pub async fn send_message(
  state: &StateStore,
  request: SendMessageRequest,
) -> Result<QueuedDelivery, ChannelToolError> {
  let message = ChannelMessageRequest::new(
    &request.connector_id,
    &request.workspace_id,
    &request.request_dedupe_key,
    request.target,
    &request.text,
  )
  .map_err(ChannelToolError::from)?;
  let (channel_id, thread_ts) = match message.target {
    ChannelReplyTarget::Thread {
      channel_id,
      thread_id,
    } => (channel_id, Some(thread_id)),
    ChannelReplyTarget::Channel { channel_id } => (channel_id, None),
    ChannelReplyTarget::DirectMessage { user_account_id } => (user_account_id, None),
    ChannelReplyTarget::Ephemeral { .. } => return Err(ChannelToolError::UnsupportedTarget),
  };
  let sender = parse_send_as(request.send_as.as_deref())?;

  enqueue_slack_delivery(
    state,
    SlackDeliveryRequest {
      connector_id: message.connector_id,
      workspace_id: message.workspace_id,
      request_dedupe_key: message.dedupe_key,
      channel_id,
      thread_ts,
      text: message.text,
      sender,
    },
    request.now_unix_seconds,
  )
  .await
}

fn parse_send_as(send_as: Option<&str>) -> Result<SlackDeliverySender, ChannelToolError> {
  let Some(send_as) = send_as else {
    return Ok(SlackDeliverySender::Bot);
  };
  if send_as == "bot" {
    return Ok(SlackDeliverySender::Bot);
  }
  let Some(key) = send_as.strip_prefix("user:") else {
    return Err(ChannelToolError::InvalidSender {
      value: send_as.to_owned(),
    });
  };
  if key.is_empty()
    || !key
      .chars()
      .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
  {
    return Err(ChannelToolError::InvalidSender {
      value: send_as.to_owned(),
    });
  }
  Ok(SlackDeliverySender::User {
    key: key.to_owned(),
  })
}

pub async fn get_delivery_status(
  state: &StateStore,
  request: GetDeliveryStatusRequest,
) -> Result<Option<SlackDeliveryStatus>, ChannelToolError> {
  state
    .slack_delivery_status(
      &request.workspace_id,
      &request.request_dedupe_key,
      request.now_unix_seconds,
    )
    .await
    .map_err(ChannelToolError::from)
}

#[derive(Clone)]
pub struct ChannelDynamicToolHandler {
  state: StateStore,
  context_provider: Option<Arc<dyn ChannelContextProvider>>,
  resource_provider: Option<Arc<dyn ChannelResourceProvider>>,
  address_providers: Option<ChannelAddressToolProviders>,
  now_unix_seconds: Option<u64>,
}

#[derive(Clone)]
struct ChannelAddressToolProviders {
  user_provider: Arc<dyn ChannelUserProvider>,
  channel_provider: Arc<dyn ChannelChannelProvider>,
  sender_provider: Arc<dyn ChannelSenderProvider>,
  status_provider: Arc<dyn ChannelStatusProvider>,
  thread_reply_provider: Arc<dyn ChannelThreadReplyProvider>,
}

impl ChannelDynamicToolHandler {
  #[must_use]
  pub fn new(state: StateStore) -> Self {
    Self {
      state,
      context_provider: None,
      resource_provider: None,
      address_providers: None,
      now_unix_seconds: None,
    }
  }

  #[must_use]
  pub const fn new_with_now(state: StateStore, now_unix_seconds: u64) -> Self {
    Self {
      state,
      context_provider: None,
      resource_provider: None,
      address_providers: None,
      now_unix_seconds: Some(now_unix_seconds),
    }
  }

  #[must_use]
  pub fn new_with_context_provider(
    state: StateStore,
    context_provider: Arc<dyn ChannelContextProvider>,
  ) -> Self {
    Self {
      state,
      context_provider: Some(context_provider),
      resource_provider: None,
      address_providers: None,
      now_unix_seconds: None,
    }
  }

  #[must_use]
  pub fn new_with_context_provider_and_now(
    state: StateStore,
    context_provider: Arc<dyn ChannelContextProvider>,
    now_unix_seconds: u64,
  ) -> Self {
    Self {
      state,
      context_provider: Some(context_provider),
      resource_provider: None,
      address_providers: None,
      now_unix_seconds: Some(now_unix_seconds),
    }
  }

  #[must_use]
  pub fn new_with_resource_provider(
    state: StateStore,
    resource_provider: Arc<dyn ChannelResourceProvider>,
  ) -> Self {
    Self {
      state,
      context_provider: None,
      resource_provider: Some(resource_provider),
      address_providers: None,
      now_unix_seconds: None,
    }
  }

  #[must_use]
  pub fn new_with_resource_provider_and_now(
    state: StateStore,
    resource_provider: Arc<dyn ChannelResourceProvider>,
    now_unix_seconds: u64,
  ) -> Self {
    Self {
      state,
      context_provider: None,
      resource_provider: Some(resource_provider),
      address_providers: None,
      now_unix_seconds: Some(now_unix_seconds),
    }
  }

  #[must_use]
  pub fn new_with_providers_and_now(
    state: StateStore,
    context_provider: Arc<dyn ChannelContextProvider>,
    resource_provider: Arc<dyn ChannelResourceProvider>,
    now_unix_seconds: u64,
  ) -> Self {
    Self {
      state,
      context_provider: Some(context_provider),
      resource_provider: Some(resource_provider),
      address_providers: None,
      now_unix_seconds: Some(now_unix_seconds),
    }
  }

  #[must_use]
  pub fn new_with_address_provider_and_now<A>(
    state: StateStore,
    address_provider: Arc<A>,
    now_unix_seconds: u64,
  ) -> Self
  where
    A: ChannelUserProvider
      + ChannelChannelProvider
      + ChannelSenderProvider
      + ChannelStatusProvider
      + ChannelThreadReplyProvider
      + Send
      + Sync
      + 'static,
  {
    Self {
      state,
      context_provider: None,
      resource_provider: None,
      address_providers: Some(ChannelAddressToolProviders {
        user_provider: address_provider.clone(),
        channel_provider: address_provider.clone(),
        sender_provider: address_provider.clone(),
        status_provider: address_provider.clone(),
        thread_reply_provider: address_provider,
      }),
      now_unix_seconds: Some(now_unix_seconds),
    }
  }

  #[must_use]
  pub fn new_with_all_providers_and_now<A>(
    state: StateStore,
    context_provider: Arc<dyn ChannelContextProvider>,
    resource_provider: Arc<dyn ChannelResourceProvider>,
    address_provider: Arc<A>,
    now_unix_seconds: u64,
  ) -> Self
  where
    A: ChannelUserProvider
      + ChannelChannelProvider
      + ChannelSenderProvider
      + ChannelStatusProvider
      + ChannelThreadReplyProvider
      + Send
      + Sync
      + 'static,
  {
    Self {
      state,
      context_provider: Some(context_provider),
      resource_provider: Some(resource_provider),
      address_providers: Some(ChannelAddressToolProviders {
        user_provider: address_provider.clone(),
        channel_provider: address_provider.clone(),
        sender_provider: address_provider.clone(),
        status_provider: address_provider.clone(),
        thread_reply_provider: address_provider,
      }),
      now_unix_seconds: Some(now_unix_seconds),
    }
  }

  #[must_use]
  pub fn tool_specs(&self) -> Vec<Value> {
    [
      (
        "channel_reply_to_event",
        "Queue a bounded reply to a known channel event.",
        reply_to_event_input_schema(),
      ),
      (
        "channel_send_message",
        "Queue a bounded channel message delivery.",
        send_message_input_schema(),
      ),
      (
        "channel_get_thread_context",
        "Fetch bounded context for a channel thread.",
        get_thread_context_input_schema(),
      ),
      (
        "channel_get_recent_messages",
        "Fetch bounded recent messages for a channel.",
        get_recent_messages_input_schema(),
      ),
      (
        "channel_get_current_event",
        "Read compact metadata for the current source channel event.",
        current_context_input_schema(),
      ),
      (
        "channel_get_current_conversation",
        "Read compact conversation coordinates for the current source channel event.",
        current_context_input_schema(),
      ),
      (
        "channel_get_context_pack",
        "Read compact current channel context and tool hints.",
        current_context_input_schema(),
      ),
      (
        "channel_get_delivery_status",
        "Read bounded channel delivery status.",
        get_delivery_status_input_schema(),
      ),
      (
        "channel_get_message",
        "Fetch one exact channel message by channel and message identifier.",
        get_message_input_schema(),
      ),
      (
        "channel_get_resource_info",
        "Fetch provider-neutral channel resource metadata.",
        get_resource_info_input_schema(),
      ),
      (
        "channel_read_resource_text",
        "Read best-effort text from a channel resource.",
        get_resource_info_input_schema(),
      ),
      (
        "channel_download_resource",
        "Download a channel resource to a local artifact.",
        get_resource_info_input_schema(),
      ),
      (
        "channel_search_users",
        "Search provider-neutral channel users.",
        search_users_input_schema(),
      ),
      (
        "channel_get_user",
        "Fetch one provider-neutral channel user by id.",
        lookup_input_schema("Provider-neutral channel user id."),
      ),
      (
        "channel_resolve_user",
        "Resolve a channel user without auto-picking ambiguous matches.",
        resolve_user_input_schema(),
      ),
      (
        "channel_search_channels",
        "Search provider-neutral channels.",
        search_channels_input_schema(),
      ),
      (
        "channel_get_channel",
        "Fetch one provider-neutral channel by id.",
        lookup_input_schema("Provider-neutral channel id."),
      ),
      (
        "channel_resolve_channel",
        "Resolve a channel without auto-picking ambiguous matches.",
        search_channels_input_schema(),
      ),
      (
        "channel_list_senders",
        "List provider-neutral senders available for a connector workspace.",
        workspace_input_schema(),
      ),
      (
        "channel_list_workspaces",
        "List provider-neutral channel connector workspaces.",
        empty_input_schema(),
      ),
      (
        "channel_get_connector_status",
        "Read provider-neutral connector status.",
        workspace_input_schema(),
      ),
      (
        "channel_reply_to_thread",
        "Send a provider-neutral reply to a channel thread.",
        reply_to_thread_input_schema(),
      ),
    ]
    .into_iter()
    .map(|(name, description, input_schema)| {
      json!({
        "name": name,
        "description": description,
        "inputSchema": input_schema,
      })
    })
    .collect()
  }

  pub async fn handle_tool_call_async(&self, tool: &str, arguments: Value) -> Value {
    match tool {
      "channel_reply_to_event" => self.handle_reply_to_event_async(arguments).await,
      "channel_send_message" => self.handle_send_message_async(arguments).await,
      "channel_get_thread_context" => self.handle_get_thread_context_async(arguments).await,
      "channel_get_recent_messages" => self.handle_get_recent_messages_async(arguments).await,
      "channel_get_current_event" => self.handle_get_current_event_async(arguments).await,
      "channel_get_current_conversation" => {
        self.handle_get_current_conversation_async(arguments).await
      }
      "channel_get_context_pack" => self.handle_get_context_pack_async(arguments).await,
      "channel_get_delivery_status" => self.handle_get_delivery_status_async(arguments).await,
      "channel_get_message" => self.handle_get_message_async(arguments).await,
      "channel_get_resource_info" => self.handle_get_resource_info_async(arguments).await,
      "channel_read_resource_text" => self.handle_read_resource_text_async(arguments).await,
      "channel_download_resource" => self.handle_download_resource_async(arguments).await,
      "channel_search_users" => self.handle_search_users_async(arguments).await,
      "channel_get_user" => self.handle_get_user_async(arguments).await,
      "channel_resolve_user" => self.handle_resolve_user_async(arguments).await,
      "channel_search_channels" => self.handle_search_channels_async(arguments).await,
      "channel_get_channel" => self.handle_get_channel_async(arguments).await,
      "channel_resolve_channel" => self.handle_resolve_channel_async(arguments).await,
      "channel_list_senders" => self.handle_list_senders_async(arguments).await,
      "channel_list_workspaces" => self.handle_list_workspaces_async().await,
      "channel_get_connector_status" => self.handle_get_connector_status_async(arguments).await,
      "channel_reply_to_thread" => self.handle_reply_to_thread_async(arguments).await,
      _ => dynamic_tool_failure(format!("unsupported dynamic tool: {tool}")),
    }
  }

  async fn handle_reply_to_event_async(&self, arguments: Value) -> Value {
    let request = match self.reply_to_event_request(arguments) {
      Ok(request) => request,
      Err(error) => return dynamic_tool_failure(error),
    };
    match reply_to_event(&self.state, request).await {
      Ok(result) => dynamic_tool_success(json!({
        "request_dedupe_key": result.request_dedupe_key,
        "queued": result.queued,
      })),
      Err(error) => dynamic_tool_failure(error.to_string()),
    }
  }

  async fn handle_send_message_async(&self, arguments: Value) -> Value {
    let request = match self.send_message_request(arguments) {
      Ok(request) => request,
      Err(error) => return dynamic_tool_failure(error),
    };
    match send_message(&self.state, request).await {
      Ok(result) => dynamic_tool_success(json!({
        "request_dedupe_key": result.request_dedupe_key,
        "queued": result.queued,
      })),
      Err(error) => dynamic_tool_failure(error.to_string()),
    }
  }

  async fn handle_get_thread_context_async(&self, arguments: Value) -> Value {
    let Some(context_provider) = self.context_provider.as_deref() else {
      return dynamic_tool_failure("channel context provider is unavailable");
    };
    let request = match self.get_thread_context_request(arguments) {
      Ok(request) => request,
      Err(error) => return dynamic_tool_failure(error),
    };
    match get_thread_context(context_provider, request).await {
      Ok(page) => dynamic_tool_success(channel_context_page_json(page)),
      Err(error) => dynamic_tool_failure(error.to_string()),
    }
  }

  async fn handle_get_recent_messages_async(&self, arguments: Value) -> Value {
    let Some(context_provider) = self.context_provider.as_deref() else {
      return dynamic_tool_failure("channel context provider is unavailable");
    };
    let request = match self.get_recent_messages_request(arguments) {
      Ok(request) => request,
      Err(error) => return dynamic_tool_failure(error),
    };
    match get_recent_messages(context_provider, request).await {
      Ok(page) => dynamic_tool_success(channel_context_page_json(page)),
      Err(error) => dynamic_tool_failure(error.to_string()),
    }
  }

  async fn handle_get_current_event_async(&self, arguments: Value) -> Value {
    let request = match self.current_context_request(arguments) {
      Ok(request) => request,
      Err(error) => return dynamic_tool_failure(error),
    };
    match get_current_event(&self.state, request).await {
      Ok(event) => dynamic_tool_success(json!(event)),
      Err(error) => dynamic_tool_failure(error.to_string()),
    }
  }

  async fn handle_get_current_conversation_async(&self, arguments: Value) -> Value {
    let request = match self.current_context_request(arguments) {
      Ok(request) => request,
      Err(error) => return dynamic_tool_failure(error),
    };
    match get_current_conversation(&self.state, request).await {
      Ok(conversation) => dynamic_tool_success(json!(conversation)),
      Err(error) => dynamic_tool_failure(error.to_string()),
    }
  }

  async fn handle_get_context_pack_async(&self, arguments: Value) -> Value {
    let request = match self.current_context_request(arguments) {
      Ok(request) => request,
      Err(error) => return dynamic_tool_failure(error),
    };
    match get_context_pack(&self.state, request).await {
      Ok(pack) => dynamic_tool_success(json!(pack)),
      Err(error) => dynamic_tool_failure(error.to_string()),
    }
  }

  async fn handle_get_delivery_status_async(&self, arguments: Value) -> Value {
    let request = match self.get_delivery_status_request(arguments) {
      Ok(request) => request,
      Err(error) => return dynamic_tool_failure(error),
    };
    match get_delivery_status(&self.state, request).await {
      Ok(delivery) => dynamic_tool_success(json!({
        "delivery": delivery.map(delivery_status_json),
      })),
      Err(error) => dynamic_tool_failure(error.to_string()),
    }
  }

  async fn handle_get_message_async(&self, arguments: Value) -> Value {
    let Some(resource_provider) = self.resource_provider.as_deref() else {
      return dynamic_tool_failure("channel resource provider is unavailable");
    };
    let request = match self.get_message_request(arguments) {
      Ok(request) => request,
      Err(error) => return dynamic_tool_failure(error),
    };
    match get_message(resource_provider, request).await {
      Ok(message) => dynamic_tool_success(json!(message)),
      Err(error) => dynamic_tool_failure(error.to_string()),
    }
  }

  async fn handle_get_resource_info_async(&self, arguments: Value) -> Value {
    let Some(resource_provider) = self.resource_provider.as_deref() else {
      return dynamic_tool_failure("channel resource provider is unavailable");
    };
    let request = match self.get_resource_info_request(arguments) {
      Ok(request) => request,
      Err(error) => return dynamic_tool_failure(error),
    };
    match get_resource_info(resource_provider, request).await {
      Ok(resource) => dynamic_tool_success(json!(resource)),
      Err(error) => dynamic_tool_failure(error.to_string()),
    }
  }

  async fn handle_read_resource_text_async(&self, arguments: Value) -> Value {
    let Some(resource_provider) = self.resource_provider.as_deref() else {
      return dynamic_tool_failure("channel resource provider is unavailable");
    };
    let request = match self.get_resource_text_request(arguments) {
      Ok(request) => request,
      Err(error) => return dynamic_tool_failure(error),
    };
    match read_resource_text(resource_provider, request).await {
      Ok(resource) => dynamic_tool_success(json!(resource)),
      Err(error) => dynamic_tool_failure(error.to_string()),
    }
  }

  async fn handle_download_resource_async(&self, arguments: Value) -> Value {
    let Some(resource_provider) = self.resource_provider.as_deref() else {
      return dynamic_tool_failure("channel resource provider is unavailable");
    };
    let request = match self.get_resource_download_request(arguments) {
      Ok(request) => request,
      Err(error) => return dynamic_tool_failure(error),
    };
    match download_resource(resource_provider, request).await {
      Ok(resource) => dynamic_tool_success(json!(resource)),
      Err(error) => dynamic_tool_failure(error.to_string()),
    }
  }

  async fn handle_search_users_async(&self, arguments: Value) -> Value {
    let Some(address_providers) = self.address_providers.as_ref() else {
      return dynamic_tool_failure("channel user provider is unavailable");
    };
    let request = match self.channel_user_search_request(arguments) {
      Ok(request) => request,
      Err(error) => return dynamic_tool_failure(error),
    };
    match search_users(address_providers.user_provider.as_ref(), request).await {
      Ok(users) => dynamic_tool_success(json!({ "users": users })),
      Err(error) => dynamic_tool_failure(error.to_string()),
    }
  }

  async fn handle_get_user_async(&self, arguments: Value) -> Value {
    let Some(address_providers) = self.address_providers.as_ref() else {
      return dynamic_tool_failure("channel user provider is unavailable");
    };
    let request = match self.channel_lookup_request(arguments) {
      Ok(request) => request,
      Err(error) => return dynamic_tool_failure(error),
    };
    match get_user(address_providers.user_provider.as_ref(), request).await {
      Ok(user) => dynamic_tool_success(json!({ "user": user })),
      Err(error) => dynamic_tool_failure(error.to_string()),
    }
  }

  async fn handle_resolve_user_async(&self, arguments: Value) -> Value {
    let Some(address_providers) = self.address_providers.as_ref() else {
      return dynamic_tool_failure("channel user provider is unavailable");
    };
    let request = match self.channel_user_resolve_request(arguments) {
      Ok(request) => request,
      Err(error) => return dynamic_tool_failure(error),
    };
    match resolve_user(address_providers.user_provider.as_ref(), request).await {
      Ok(result) => dynamic_tool_success(json!(result)),
      Err(error) => dynamic_tool_failure(error.to_string()),
    }
  }

  async fn handle_search_channels_async(&self, arguments: Value) -> Value {
    let Some(address_providers) = self.address_providers.as_ref() else {
      return dynamic_tool_failure("channel channel provider is unavailable");
    };
    let request = match self.channel_search_request(arguments) {
      Ok(request) => request,
      Err(error) => return dynamic_tool_failure(error),
    };
    match search_channels(address_providers.channel_provider.as_ref(), request).await {
      Ok(channels) => dynamic_tool_success(json!({ "channels": channels })),
      Err(error) => dynamic_tool_failure(error.to_string()),
    }
  }

  async fn handle_get_channel_async(&self, arguments: Value) -> Value {
    let Some(address_providers) = self.address_providers.as_ref() else {
      return dynamic_tool_failure("channel channel provider is unavailable");
    };
    let request = match self.channel_lookup_request(arguments) {
      Ok(request) => request,
      Err(error) => return dynamic_tool_failure(error),
    };
    match get_channel(address_providers.channel_provider.as_ref(), request).await {
      Ok(channel) => dynamic_tool_success(json!({ "channel": channel })),
      Err(error) => dynamic_tool_failure(error.to_string()),
    }
  }

  async fn handle_resolve_channel_async(&self, arguments: Value) -> Value {
    let Some(address_providers) = self.address_providers.as_ref() else {
      return dynamic_tool_failure("channel channel provider is unavailable");
    };
    let request = match self.channel_search_request(arguments) {
      Ok(request) => request,
      Err(error) => return dynamic_tool_failure(error),
    };
    match resolve_channel(address_providers.channel_provider.as_ref(), request).await {
      Ok(result) => dynamic_tool_success(json!(result)),
      Err(error) => dynamic_tool_failure(error.to_string()),
    }
  }

  async fn handle_list_senders_async(&self, arguments: Value) -> Value {
    let Some(address_providers) = self.address_providers.as_ref() else {
      return dynamic_tool_failure("channel sender provider is unavailable");
    };
    let request = match self.channel_workspace_request(arguments) {
      Ok(request) => request,
      Err(error) => return dynamic_tool_failure(error),
    };
    match list_senders(address_providers.sender_provider.as_ref(), request).await {
      Ok(senders) => dynamic_tool_success(json!({ "senders": senders })),
      Err(error) => dynamic_tool_failure(error.to_string()),
    }
  }

  async fn handle_list_workspaces_async(&self) -> Value {
    let Some(address_providers) = self.address_providers.as_ref() else {
      return dynamic_tool_failure("channel status provider is unavailable");
    };
    match list_workspaces(address_providers.status_provider.as_ref()).await {
      Ok(workspaces) => dynamic_tool_success(json!({ "workspaces": workspaces })),
      Err(error) => dynamic_tool_failure(error.to_string()),
    }
  }

  async fn handle_get_connector_status_async(&self, arguments: Value) -> Value {
    let Some(address_providers) = self.address_providers.as_ref() else {
      return dynamic_tool_failure("channel status provider is unavailable");
    };
    let request = match self.channel_workspace_request(arguments) {
      Ok(request) => request,
      Err(error) => return dynamic_tool_failure(error),
    };
    match get_connector_status(address_providers.status_provider.as_ref(), request).await {
      Ok(status) => dynamic_tool_success(json!({ "status": status })),
      Err(error) => dynamic_tool_failure(error.to_string()),
    }
  }

  async fn handle_reply_to_thread_async(&self, arguments: Value) -> Value {
    let Some(address_providers) = self.address_providers.as_ref() else {
      return dynamic_tool_failure("channel thread reply provider is unavailable");
    };
    let request = match self.channel_thread_reply_request(arguments) {
      Ok(request) => request,
      Err(error) => return dynamic_tool_failure(error),
    };
    match reply_to_thread(address_providers.thread_reply_provider.as_ref(), request).await {
      Ok(receipt) => dynamic_tool_success(json!(receipt)),
      Err(error) => dynamic_tool_failure(error.to_string()),
    }
  }

  fn reply_to_event_request(&self, arguments: Value) -> Result<ReplyToEventRequest, String> {
    Ok(ReplyToEventRequest {
      connector_id: required_string(&arguments, "connector_id")?,
      workspace_id: required_string(&arguments, "workspace_id")?,
      event_dedupe_key: required_string(&arguments, "event_dedupe_key")?,
      request_dedupe_key: required_string(&arguments, "request_dedupe_key")?,
      text: required_string(&arguments, "text")?,
      send_as: optional_string(&arguments, "send_as")?,
      now_unix_seconds: self.now_unix_seconds(),
    })
  }

  fn send_message_request(&self, arguments: Value) -> Result<SendMessageRequest, String> {
    let target = serde_json::from_value(arguments["target"].clone())
      .map_err(|error| format!("invalid target: {error}"))?;
    Ok(SendMessageRequest {
      connector_id: required_string(&arguments, "connector_id")?,
      workspace_id: required_string(&arguments, "workspace_id")?,
      request_dedupe_key: required_string(&arguments, "request_dedupe_key")?,
      target,
      text: required_string(&arguments, "text")?,
      send_as: optional_string(&arguments, "send_as")?,
      now_unix_seconds: self.now_unix_seconds(),
    })
  }

  fn get_thread_context_request(
    &self,
    arguments: Value,
  ) -> Result<GetThreadContextRequest, String> {
    Ok(GetThreadContextRequest {
      connector_id: required_string(&arguments, "connector_id")?,
      workspace_id: required_string(&arguments, "workspace_id")?,
      channel_id: required_string(&arguments, "channel_id")?,
      thread_id: required_string(&arguments, "thread_id")?,
      limit: required_u16(&arguments, "limit")?,
      cursor: optional_string(&arguments, "cursor")?,
    })
  }

  fn get_recent_messages_request(
    &self,
    arguments: Value,
  ) -> Result<GetRecentMessagesRequest, String> {
    Ok(GetRecentMessagesRequest {
      connector_id: required_string(&arguments, "connector_id")?,
      workspace_id: required_string(&arguments, "workspace_id")?,
      channel_id: required_string(&arguments, "channel_id")?,
      limit: required_u16(&arguments, "limit")?,
      cursor: optional_string(&arguments, "cursor")?,
    })
  }

  fn get_delivery_status_request(
    &self,
    arguments: Value,
  ) -> Result<GetDeliveryStatusRequest, String> {
    Ok(GetDeliveryStatusRequest {
      workspace_id: required_string(&arguments, "workspace_id")?,
      request_dedupe_key: required_string(&arguments, "request_dedupe_key")?,
      now_unix_seconds: self.now_unix_seconds(),
    })
  }

  fn current_context_request(
    &self,
    arguments: Value,
  ) -> Result<ChannelCurrentContextRequest, String> {
    Ok(ChannelCurrentContextRequest {
      connector_id: required_string(&arguments, "connector_id")?,
      workspace_id: required_string(&arguments, "workspace_id")?,
      event_dedupe_key: required_string(&arguments, "event_dedupe_key")?,
    })
  }

  fn get_message_request(&self, arguments: Value) -> Result<ChannelMessageFetchRequest, String> {
    Ok(ChannelMessageFetchRequest {
      connector_id: required_string(&arguments, "connector_id")?,
      workspace_id: required_string(&arguments, "workspace_id")?,
      channel_id: required_string(&arguments, "channel_id")?,
      thread_id: optional_string(&arguments, "thread_id")?,
      message_ts: required_string(&arguments, "message_ts")?,
    })
  }

  fn get_resource_info_request(
    &self,
    arguments: Value,
  ) -> Result<ChannelResourceInfoRequest, String> {
    Ok(ChannelResourceInfoRequest {
      connector_id: required_string(&arguments, "connector_id")?,
      workspace_id: required_string(&arguments, "workspace_id")?,
      resource_id: required_string(&arguments, "resource_id")?,
    })
  }

  fn get_resource_text_request(
    &self,
    arguments: Value,
  ) -> Result<ChannelResourceTextRequest, String> {
    Ok(ChannelResourceTextRequest {
      connector_id: required_string(&arguments, "connector_id")?,
      workspace_id: required_string(&arguments, "workspace_id")?,
      resource_id: required_string(&arguments, "resource_id")?,
    })
  }

  fn get_resource_download_request(
    &self,
    arguments: Value,
  ) -> Result<ChannelResourceDownloadRequest, String> {
    Ok(ChannelResourceDownloadRequest {
      connector_id: required_string(&arguments, "connector_id")?,
      workspace_id: required_string(&arguments, "workspace_id")?,
      resource_id: required_string(&arguments, "resource_id")?,
    })
  }

  fn channel_workspace_request(&self, arguments: Value) -> Result<ChannelWorkspaceRequest, String> {
    Ok(ChannelWorkspaceRequest {
      connector_id: required_string(&arguments, "connector_id")?,
      workspace_id: required_string(&arguments, "workspace_id")?,
    })
  }

  fn channel_lookup_request(&self, arguments: Value) -> Result<ChannelLookupRequest, String> {
    Ok(ChannelLookupRequest {
      connector_id: required_string(&arguments, "connector_id")?,
      workspace_id: required_string(&arguments, "workspace_id")?,
      id: required_string(&arguments, "id")?,
    })
  }

  fn channel_user_search_request(
    &self,
    arguments: Value,
  ) -> Result<ChannelUserSearchRequest, String> {
    Ok(ChannelUserSearchRequest {
      connector_id: required_string(&arguments, "connector_id")?,
      workspace_id: required_string(&arguments, "workspace_id")?,
      query: required_string(&arguments, "query")?,
      limit: required_u16(&arguments, "limit")?,
    })
  }

  fn channel_user_resolve_request(
    &self,
    arguments: Value,
  ) -> Result<ChannelUserResolveRequest, String> {
    Ok(ChannelUserResolveRequest {
      connector_id: required_string(&arguments, "connector_id")?,
      workspace_id: required_string(&arguments, "workspace_id")?,
      query: required_string(&arguments, "query")?,
    })
  }

  fn channel_search_request(&self, arguments: Value) -> Result<ChannelSearchRequest, String> {
    Ok(ChannelSearchRequest {
      connector_id: required_string(&arguments, "connector_id")?,
      workspace_id: required_string(&arguments, "workspace_id")?,
      query: required_string(&arguments, "query")?,
      limit: required_u16(&arguments, "limit")?,
    })
  }

  fn channel_thread_reply_request(
    &self,
    arguments: Value,
  ) -> Result<ChannelThreadReplyRequest, String> {
    Ok(ChannelThreadReplyRequest {
      connector_id: required_string(&arguments, "connector_id")?,
      workspace_id: required_string(&arguments, "workspace_id")?,
      channel_id: required_string(&arguments, "channel_id")?,
      thread_id: required_string(&arguments, "thread_id")?,
      request_dedupe_key: required_string(&arguments, "request_dedupe_key")?,
      text: required_string(&arguments, "text")?,
      send_as: optional_string(&arguments, "send_as")?,
    })
  }

  fn now_unix_seconds(&self) -> u64 {
    self.now_unix_seconds.unwrap_or_else(current_unix_seconds)
  }
}

fn current_unix_seconds() -> u64 {
  SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap_or_default()
    .as_secs()
}

fn required_string(arguments: &Value, field: &str) -> Result<String, String> {
  let value = arguments[field]
    .as_str()
    .ok_or_else(|| format!("missing or invalid string field: {field}"))?;
  if value.is_empty() {
    return Err(format!("missing or invalid string field: {field}"));
  }
  Ok(value.to_owned())
}

fn required_u16(arguments: &Value, field: &str) -> Result<u16, String> {
  let value = arguments[field]
    .as_u64()
    .ok_or_else(|| format!("missing or invalid integer field: {field}"))?;
  u16::try_from(value).map_err(|_| format!("missing or invalid integer field: {field}"))
}

fn optional_string(arguments: &Value, field: &str) -> Result<Option<String>, String> {
  if arguments.get(field).is_none() || arguments[field].is_null() {
    return Ok(None);
  }
  required_string(arguments, field).map(Some)
}

fn dynamic_tool_success(content: Value) -> Value {
  json!({
    "success": true,
    "contentItems": [
      {
        "type": "inputText",
        "text": content.to_string(),
      }
    ],
  })
}

fn dynamic_tool_failure(message: impl Into<String>) -> Value {
  json!({
    "success": false,
    "contentItems": [
      {
        "type": "inputText",
        "text": message.into(),
      }
    ],
  })
}

fn channel_context_page_json(page: ChannelContextPage) -> Value {
  json!({
    "events": page.events,
    "next_cursor": page.next_cursor,
  })
}

fn delivery_status_json(status: SlackDeliveryStatus) -> Value {
  json!({
    "connector_id": status.connector_id,
    "workspace_id": status.workspace_id,
    "channel_id": status.channel_id,
    "thread_ts": status.thread_ts,
    "message_ts": status.message_ts,
    "request_dedupe_key": status.request_dedupe_key,
    "status": slack_delivery_status_kind_name(status.status),
    "available_at": status.available_at,
    "attempt_count": status.attempt_count,
    "sender_kind": status.sender_kind,
    "sender_key": status.sender_key,
  })
}

const fn slack_delivery_status_kind_name(
  status: codeoff_state::SlackDeliveryStatusKind,
) -> &'static str {
  match status {
    codeoff_state::SlackDeliveryStatusKind::Pending => "pending",
    codeoff_state::SlackDeliveryStatusKind::Deferred => "deferred",
    codeoff_state::SlackDeliveryStatusKind::Processing => "processing",
    codeoff_state::SlackDeliveryStatusKind::Delivered => "delivered",
    codeoff_state::SlackDeliveryStatusKind::Failed => "failed",
  }
}

fn reply_to_event_input_schema() -> Value {
  json!({
    "type": "object",
    "properties": {
      "connector_id": string_schema("Codeoff connector id."),
      "workspace_id": string_schema("Slack workspace id."),
      "event_dedupe_key": string_schema("Dedupe key of the source channel event."),
      "request_dedupe_key": string_schema("Stable idempotency key for this delivery request."),
      "text": string_schema("Message text to queue for delivery."),
      "send_as": send_as_schema(),
    },
    "required": [
      "connector_id",
      "workspace_id",
      "event_dedupe_key",
      "request_dedupe_key",
      "text"
    ],
    "additionalProperties": false,
  })
}

fn send_message_input_schema() -> Value {
  json!({
    "type": "object",
    "properties": {
      "connector_id": string_schema("Codeoff connector id."),
      "workspace_id": string_schema("Slack workspace id."),
      "request_dedupe_key": string_schema("Stable idempotency key for this delivery request."),
      "target": target_schema(),
      "text": string_schema("Message text to queue for delivery."),
      "send_as": send_as_schema(),
    },
    "required": [
      "connector_id",
      "workspace_id",
      "request_dedupe_key",
      "target",
      "text"
    ],
    "additionalProperties": false,
  })
}

fn get_delivery_status_input_schema() -> Value {
  json!({
    "type": "object",
    "properties": {
      "workspace_id": string_schema("Slack workspace id."),
      "request_dedupe_key": string_schema("Stable idempotency key for the delivery request."),
    },
    "required": [
      "workspace_id",
      "request_dedupe_key"
    ],
    "additionalProperties": false,
  })
}

fn get_thread_context_input_schema() -> Value {
  json!({
    "type": "object",
    "properties": {
      "connector_id": string_schema("Codeoff connector id."),
      "workspace_id": string_schema("Slack workspace id."),
      "channel_id": string_schema("Slack channel id."),
      "thread_id": string_schema("Slack thread timestamp."),
      "limit": limit_schema(),
      "cursor": cursor_schema(),
    },
    "required": [
      "connector_id",
      "workspace_id",
      "channel_id",
      "thread_id",
      "limit"
    ],
    "additionalProperties": false,
  })
}

fn get_recent_messages_input_schema() -> Value {
  json!({
    "type": "object",
    "properties": {
      "connector_id": string_schema("Codeoff connector id."),
      "workspace_id": string_schema("Slack workspace id."),
      "channel_id": string_schema("Slack channel id."),
      "limit": limit_schema(),
      "cursor": cursor_schema(),
    },
    "required": [
      "connector_id",
      "workspace_id",
      "channel_id",
      "limit"
    ],
    "additionalProperties": false,
  })
}

fn current_context_input_schema() -> Value {
  json!({
    "type": "object",
    "properties": {
      "connector_id": string_schema("Codeoff connector id."),
      "workspace_id": string_schema("Channel workspace id."),
      "event_dedupe_key": string_schema("Dedupe key of the current source channel event."),
    },
    "required": [
      "connector_id",
      "workspace_id",
      "event_dedupe_key"
    ],
    "additionalProperties": false,
  })
}

fn get_message_input_schema() -> Value {
  json!({
    "type": "object",
    "properties": {
      "connector_id": string_schema("Codeoff connector id."),
      "workspace_id": string_schema("Channel workspace id."),
      "channel_id": string_schema("Channel id."),
      "thread_id": string_schema("Optional channel thread id when the message belongs to a thread."),
      "message_ts": string_schema("Channel message timestamp or id."),
    },
    "required": [
      "connector_id",
      "workspace_id",
      "channel_id",
      "message_ts"
    ],
    "additionalProperties": false,
  })
}

fn get_resource_info_input_schema() -> Value {
  json!({
    "type": "object",
    "properties": {
      "connector_id": string_schema("Codeoff connector id."),
      "workspace_id": string_schema("Channel workspace id."),
      "resource_id": string_schema("Provider-neutral channel resource id."),
    },
    "required": [
      "connector_id",
      "workspace_id",
      "resource_id"
    ],
    "additionalProperties": false,
  })
}

fn empty_input_schema() -> Value {
  json!({
    "type": "object",
    "properties": {},
    "additionalProperties": false,
  })
}

fn workspace_input_schema() -> Value {
  json!({
    "type": "object",
    "properties": {
      "connector_id": string_schema("Codeoff connector id."),
      "workspace_id": string_schema("Channel workspace id."),
    },
    "required": [
      "connector_id",
      "workspace_id"
    ],
    "additionalProperties": false,
  })
}

fn lookup_input_schema(id_description: &str) -> Value {
  json!({
    "type": "object",
    "properties": {
      "connector_id": string_schema("Codeoff connector id."),
      "workspace_id": string_schema("Channel workspace id."),
      "id": string_schema(id_description),
    },
    "required": [
      "connector_id",
      "workspace_id",
      "id"
    ],
    "additionalProperties": false,
  })
}

fn search_users_input_schema() -> Value {
  json!({
    "type": "object",
    "properties": {
      "connector_id": string_schema("Codeoff connector id."),
      "workspace_id": string_schema("Channel workspace id."),
      "query": string_schema("User id, handle, display name, real name, or email fragment."),
      "limit": limit_schema(),
    },
    "required": [
      "connector_id",
      "workspace_id",
      "query",
      "limit"
    ],
    "additionalProperties": false,
  })
}

fn resolve_user_input_schema() -> Value {
  json!({
    "type": "object",
    "properties": {
      "connector_id": string_schema("Codeoff connector id."),
      "workspace_id": string_schema("Channel workspace id."),
      "query": string_schema("User id, handle, display name, real name, or email."),
    },
    "required": [
      "connector_id",
      "workspace_id",
      "query"
    ],
    "additionalProperties": false,
  })
}

fn search_channels_input_schema() -> Value {
  json!({
    "type": "object",
    "properties": {
      "connector_id": string_schema("Codeoff connector id."),
      "workspace_id": string_schema("Channel workspace id."),
      "query": string_schema("Channel id, direct-message id, or channel name fragment."),
      "limit": limit_schema(),
    },
    "required": [
      "connector_id",
      "workspace_id",
      "query",
      "limit"
    ],
    "additionalProperties": false,
  })
}

fn reply_to_thread_input_schema() -> Value {
  json!({
    "type": "object",
    "properties": {
      "connector_id": string_schema("Codeoff connector id."),
      "workspace_id": string_schema("Channel workspace id."),
      "channel_id": string_schema("Channel id."),
      "thread_id": string_schema("Thread id."),
      "request_dedupe_key": string_schema("Stable idempotency key for this delivery request."),
      "text": string_schema("Message text to send."),
      "send_as": send_as_schema(),
    },
    "required": [
      "connector_id",
      "workspace_id",
      "channel_id",
      "thread_id",
      "request_dedupe_key",
      "text"
    ],
    "additionalProperties": false,
  })
}

fn target_schema() -> Value {
  json!({
    "oneOf": [
      {
        "type": "object",
        "properties": {
          "Channel": {
            "type": "object",
            "properties": {
              "channel_id": string_schema("Slack channel id."),
            },
            "required": ["channel_id"],
            "additionalProperties": false,
          }
        },
        "required": ["Channel"],
        "additionalProperties": false,
      },
      {
        "type": "object",
        "properties": {
          "Thread": {
            "type": "object",
            "properties": {
              "channel_id": string_schema("Slack channel id."),
              "thread_id": string_schema("Slack thread timestamp."),
            },
            "required": ["channel_id", "thread_id"],
            "additionalProperties": false,
          }
        },
        "required": ["Thread"],
        "additionalProperties": false,
      },
      {
        "type": "object",
        "properties": {
          "DirectMessage": {
            "type": "object",
            "properties": {
              "user_account_id": string_schema("Slack user id."),
            },
            "required": ["user_account_id"],
            "additionalProperties": false,
          }
        },
        "required": ["DirectMessage"],
        "additionalProperties": false,
      }
    ]
  })
}

fn limit_schema() -> Value {
  json!({
    "type": "integer",
    "description": "Maximum number of messages to fetch.",
    "minimum": 1,
    "maximum": u16::MAX,
  })
}

fn cursor_schema() -> Value {
  json!({
    "type": ["string", "null"],
    "description": "Optional Slack pagination cursor returned by the previous context page.",
    "minLength": 1,
  })
}

fn string_schema(description: &str) -> Value {
  json!({
    "type": "string",
    "description": description,
    "minLength": 1,
  })
}

fn send_as_schema() -> Value {
  json!({
    "type": ["string", "null"],
    "description": "Optional sender selector: bot or user:<key>.",
  })
}

pub async fn get_thread_context(
  provider: &dyn ChannelContextProvider,
  request: GetThreadContextRequest,
) -> Result<ChannelContextPage, ChannelToolError> {
  let mut context_request = ChannelContextRequest::new(
    request.connector_id,
    request.workspace_id,
    ChannelReplyTarget::Thread {
      channel_id: request.channel_id,
      thread_id: request.thread_id,
    },
    request.limit,
  )
  .map_err(ChannelToolError::from)?;
  context_request.cursor = request.cursor;
  provider
    .fetch_context(context_request)
    .await
    .map_err(ChannelToolError::from)
}

pub async fn get_recent_messages(
  provider: &dyn ChannelContextProvider,
  request: GetRecentMessagesRequest,
) -> Result<ChannelContextPage, ChannelToolError> {
  let mut context_request = ChannelContextRequest::new(
    request.connector_id,
    request.workspace_id,
    ChannelReplyTarget::Channel {
      channel_id: request.channel_id,
    },
    request.limit,
  )
  .map_err(ChannelToolError::from)?;
  context_request.cursor = request.cursor;
  provider
    .fetch_context(context_request)
    .await
    .map_err(ChannelToolError::from)
}

pub async fn get_message(
  provider: &dyn ChannelResourceProvider,
  request: ChannelMessageFetchRequest,
) -> Result<ChannelMessageSnapshot, ChannelToolError> {
  let request = ChannelMessageFetchRequest::new(
    request.connector_id,
    request.workspace_id,
    request.channel_id,
    request.thread_id,
    request.message_ts,
  )
  .map_err(ChannelToolError::from)?;
  provider
    .fetch_message(request)
    .await
    .map_err(ChannelToolError::from)
}

pub async fn get_resource_info(
  provider: &dyn ChannelResourceProvider,
  request: ChannelResourceInfoRequest,
) -> Result<ChannelResourceInfo, ChannelToolError> {
  let request = ChannelResourceInfoRequest::new(
    request.connector_id,
    request.workspace_id,
    request.resource_id,
  )
  .map_err(ChannelToolError::from)?;
  provider
    .fetch_resource_info(request)
    .await
    .map_err(ChannelToolError::from)
}

pub async fn read_resource_text(
  provider: &dyn ChannelResourceProvider,
  request: ChannelResourceTextRequest,
) -> Result<ChannelResourceText, ChannelToolError> {
  let request = ChannelResourceTextRequest::new(
    request.connector_id,
    request.workspace_id,
    request.resource_id,
  )
  .map_err(ChannelToolError::from)?;
  provider
    .read_resource_text(request)
    .await
    .map_err(ChannelToolError::from)
}

pub async fn download_resource(
  provider: &dyn ChannelResourceProvider,
  request: ChannelResourceDownloadRequest,
) -> Result<ChannelResourceDownload, ChannelToolError> {
  let request = ChannelResourceDownloadRequest::new(
    request.connector_id,
    request.workspace_id,
    request.resource_id,
  )
  .map_err(ChannelToolError::from)?;
  provider
    .download_resource(request)
    .await
    .map_err(ChannelToolError::from)
}

pub async fn search_users(
  provider: &dyn ChannelUserProvider,
  request: ChannelUserSearchRequest,
) -> Result<Vec<ChannelUserSummary>, ChannelToolError> {
  let request = ChannelUserSearchRequest::new(
    request.connector_id,
    request.workspace_id,
    request.query,
    request.limit,
  )
  .map_err(ChannelToolError::from)?;
  provider.search_users(request).await
}

pub async fn get_user(
  provider: &dyn ChannelUserProvider,
  request: ChannelLookupRequest,
) -> Result<Option<ChannelUserSummary>, ChannelToolError> {
  let request = ChannelLookupRequest::new(request.connector_id, request.workspace_id, request.id)
    .map_err(ChannelToolError::from)?;
  provider.get_user(request).await
}

pub async fn resolve_user(
  provider: &dyn ChannelUserProvider,
  request: ChannelUserResolveRequest,
) -> Result<ChannelUserResolveResult, ChannelToolError> {
  let request =
    ChannelUserResolveRequest::new(request.connector_id, request.workspace_id, request.query)
      .map_err(ChannelToolError::from)?;
  provider.resolve_user(request).await
}

pub async fn search_channels(
  provider: &dyn ChannelChannelProvider,
  request: ChannelSearchRequest,
) -> Result<Vec<ChannelSummary>, ChannelToolError> {
  let request = ChannelSearchRequest::new(
    request.connector_id,
    request.workspace_id,
    request.query,
    request.limit,
  )
  .map_err(ChannelToolError::from)?;
  provider.search_channels(request).await
}

pub async fn get_channel(
  provider: &dyn ChannelChannelProvider,
  request: ChannelLookupRequest,
) -> Result<Option<ChannelSummary>, ChannelToolError> {
  let request = ChannelLookupRequest::new(request.connector_id, request.workspace_id, request.id)
    .map_err(ChannelToolError::from)?;
  provider.get_channel(request).await
}

pub async fn resolve_channel(
  provider: &dyn ChannelChannelProvider,
  request: ChannelSearchRequest,
) -> Result<ChannelResolveResult, ChannelToolError> {
  let request = ChannelSearchRequest::new(
    request.connector_id,
    request.workspace_id,
    request.query,
    request.limit,
  )
  .map_err(ChannelToolError::from)?;
  let candidates = provider.resolve_channel(request).await?;
  if candidates.len() == 1 {
    Ok(ChannelResolveResult::resolved(candidates[0].clone()))
  } else {
    Ok(ChannelResolveResult::ambiguous(candidates))
  }
}

pub async fn list_senders(
  provider: &dyn ChannelSenderProvider,
  request: ChannelWorkspaceRequest,
) -> Result<Vec<ChannelSenderSummary>, ChannelToolError> {
  let request = ChannelWorkspaceRequest::new(request.connector_id, request.workspace_id)
    .map_err(ChannelToolError::from)?;
  provider.list_senders(request).await
}

pub async fn list_workspaces(
  provider: &dyn ChannelStatusProvider,
) -> Result<Vec<ChannelWorkspaceSummary>, ChannelToolError> {
  provider.list_workspaces().await
}

pub async fn get_connector_status(
  provider: &dyn ChannelStatusProvider,
  request: ChannelWorkspaceRequest,
) -> Result<ChannelConnectorStatus, ChannelToolError> {
  let request = ChannelWorkspaceRequest::new(request.connector_id, request.workspace_id)
    .map_err(ChannelToolError::from)?;
  provider.get_connector_status(request).await
}

pub async fn get_current_event(
  state: &StateStore,
  request: ChannelCurrentContextRequest,
) -> Result<ChannelCurrentEvent, ChannelToolError> {
  let request = ChannelCurrentContextRequest::new(
    request.connector_id,
    request.workspace_id,
    request.event_dedupe_key,
  )
  .map_err(ChannelToolError::from)?;
  let event = state
    .channel_event("slack", &request.workspace_id, &request.event_dedupe_key)
    .await?
    .ok_or(ChannelToolError::MissingSourceEvent)?;
  let source = state
    .slack_source_references(&request.workspace_id, &request.event_dedupe_key)
    .await?;
  Ok(current_event_from_parts(
    request.connector_id,
    event,
    source,
  ))
}

pub async fn get_current_conversation(
  state: &StateStore,
  request: ChannelCurrentContextRequest,
) -> Result<ChannelCurrentConversation, ChannelToolError> {
  let current_event = get_current_event(state, request).await?;
  Ok(current_conversation_from_event(&current_event))
}

pub async fn get_context_pack(
  state: &StateStore,
  request: ChannelCurrentContextRequest,
) -> Result<ChannelContextPack, ChannelToolError> {
  let current_event = get_current_event(state, request).await?;
  let current_conversation = current_conversation_from_event(&current_event);
  Ok(ChannelContextPack {
    current_event,
    current_conversation,
    available_tools: current_context_tool_hints(),
  })
}

pub async fn reply_to_thread(
  provider: &dyn ChannelThreadReplyProvider,
  request: ChannelThreadReplyRequest,
) -> Result<ChannelThreadReplyReceipt, ChannelToolError> {
  let request = ChannelThreadReplyRequest::new(
    request.connector_id,
    request.workspace_id,
    request.channel_id,
    request.thread_id,
    request.request_dedupe_key,
    request.text,
    request.send_as,
  )
  .map_err(ChannelToolError::from)?;
  provider.reply_to_thread(request).await
}

/// Fetches a bounded first page of Slack conversation context for prompt bootstrap.
///
/// Direct-message events use their Slack `D...` channel id as a channel history target so recent DM
/// context can be injected without requiring a separate direct-message context target.
///
/// # Errors
///
/// Returns an error when the source event does not identify a channel, the requested limit is
/// invalid, or the channel context provider rejects the fetch.
pub async fn bootstrap_slack_context(
  provider: &dyn ChannelContextProvider,
  request: SlackContextBootstrapRequest,
) -> Result<Value, ChannelToolError> {
  let channel_id = request
    .channel_id
    .or_else(|| source_channel_id(&request.event))
    .ok_or(ChannelToolError::MissingReplyTarget)?;
  let target_kind = if request.event.kind == ChannelEventKind::DirectMessageReceived {
    "direct_message"
  } else if request.thread_id.is_some() {
    "thread"
  } else {
    "channel"
  };
  let thread_id = request.thread_id.clone();
  let target = match (target_kind, request.thread_id) {
    ("thread", Some(thread_id)) => ChannelReplyTarget::Thread {
      channel_id: channel_id.clone(),
      thread_id,
    },
    _ => ChannelReplyTarget::Channel {
      channel_id: channel_id.clone(),
    },
  };
  let context_request = ChannelContextRequest::new(
    request.event.connector_id,
    request.event.workspace_id,
    target,
    request.limit,
  )
  .map_err(ChannelToolError::from)?;
  let page = provider
    .fetch_context(context_request)
    .await
    .map_err(ChannelToolError::from)?;
  let thread_id = if target_kind == "thread" {
    thread_id
  } else {
    None
  };
  Ok(json!({
    "target_kind": target_kind,
    "channel_id": channel_id,
    "thread_id": thread_id,
    "events": page.events,
    "next_cursor": page.next_cursor,
  }))
}

fn source_channel_id(event: &ChannelEvent) -> Option<String> {
  match event.reply_target.as_ref() {
    Some(
      ChannelReplyTarget::Channel { channel_id } | ChannelReplyTarget::Thread { channel_id, .. },
    ) => Some(channel_id.clone()),
    _ => None,
  }
}

fn source_thread_id(event: &ChannelEvent) -> Option<String> {
  match event.reply_target.as_ref() {
    Some(ChannelReplyTarget::Thread { thread_id, .. }) => Some(thread_id.clone()),
    _ => None,
  }
}

fn current_event_from_parts(
  connector_id: String,
  event: ChannelEvent,
  source: SlackSourceReferences,
) -> ChannelCurrentEvent {
  let source_provider = event.provider.clone();
  let workspace_id = event.workspace_id.clone();
  let event_id = event.event_id.clone();
  let event_dedupe_key = event.dedupe_key.clone();
  let event_kind = format!("{:?}", event.kind);
  let channel_id = source
    .channel_id
    .clone()
    .or_else(|| source_channel_id(&event));
  let thread_id = source
    .thread_id
    .clone()
    .or_else(|| source_thread_id(&event));
  let message_ts = source.message_ts.clone();
  let generated_source_reference =
    generated_slack_source_reference(&workspace_id, channel_id.as_deref(), message_ts.as_deref());
  let source_reference = ChannelSourceReference {
    uri: generated_source_reference,
    provider: source_provider.clone(),
    workspace_id: workspace_id.clone(),
    channel_id: channel_id.clone(),
    thread_id: thread_id.clone(),
    message_ts: message_ts.clone(),
    user_id: source.user_id.clone(),
  };
  ChannelCurrentEvent {
    source_provider,
    connector_id: connector_id.clone(),
    workspace_id: workspace_id.clone(),
    event_id,
    event_dedupe_key,
    event_kind,
    text: event.text,
    channel_id,
    thread_id: thread_id.clone(),
    thread_ts: thread_id,
    message_ts,
    user_id: source.user_id,
    reply_target: event.reply_target,
    source_reference,
    links: source
      .links
      .into_iter()
      .map(|link| ChannelSourceLink {
        url: link.url,
        text: link.text,
      })
      .collect(),
    attachments: source
      .attachments
      .into_iter()
      .map(|attachment| ChannelSourceAttachment {
        title: attachment.title,
        text: attachment.text,
      })
      .collect(),
    files: source
      .files
      .into_iter()
      .map(|file| ChannelResourceInfo {
        connector_id: connector_id.clone(),
        workspace_id: workspace_id.clone(),
        resource_id: file.resource_id.unwrap_or_default(),
        name: file.name.or(file.title),
        media_type: file.media_type,
        size_bytes: file.size_bytes,
      })
      .filter(|file| !file.resource_id.is_empty())
      .collect(),
  }
}

fn current_conversation_from_event(event: &ChannelCurrentEvent) -> ChannelCurrentConversation {
  let conversation_kind = if event
    .channel_id
    .as_deref()
    .is_some_and(is_slack_direct_message_channel)
  {
    "dm"
  } else if event.thread_id.is_some() {
    "thread"
  } else {
    "channel"
  };
  let thread_id = if conversation_kind == "thread" {
    event.thread_id.clone()
  } else {
    None
  };
  ChannelCurrentConversation {
    source_provider: event.source_provider.clone(),
    connector_id: event.connector_id.clone(),
    workspace_id: event.workspace_id.clone(),
    conversation_kind: conversation_kind.to_owned(),
    channel_id: event.channel_id.clone(),
    thread_id,
    user_id: event.user_id.clone(),
    reply_target: event.reply_target.clone(),
  }
}

fn current_context_tool_hints() -> Vec<ChannelAvailableToolHint> {
  vec![
    ChannelAvailableToolHint {
      name: "channel.reply_to_event".to_owned(),
      purpose: "Reply to the current source event with Codeoff-managed delivery.".to_owned(),
    },
    ChannelAvailableToolHint {
      name: "channel.get_thread_context".to_owned(),
      purpose: "Fetch bounded messages from the current conversation thread.".to_owned(),
    },
    ChannelAvailableToolHint {
      name: "channel.get_recent_messages".to_owned(),
      purpose: "Fetch bounded recent messages from the current channel or DM.".to_owned(),
    },
  ]
}

fn generated_slack_source_reference(
  workspace_id: &str,
  channel_id: Option<&str>,
  message_ts: Option<&str>,
) -> String {
  match (channel_id, message_ts) {
    (Some(channel_id), Some(message_ts)) => {
      format!("slack://{workspace_id}/{channel_id}/{message_ts}")
    }
    (Some(channel_id), None) => format!("slack://{workspace_id}/{channel_id}"),
    _ => format!("slack://{workspace_id}"),
  }
}

async fn enqueue_slack_delivery(
  state: &StateStore,
  request: SlackDeliveryRequest,
  now_unix_seconds: u64,
) -> Result<QueuedDelivery, ChannelToolError> {
  let request_dedupe_key = request.request_dedupe_key.clone();
  let queued = state
    .enqueue_slack_delivery(&request, now_unix_seconds)
    .await
    .map_err(ChannelToolError::from)?;
  Ok(QueuedDelivery {
    request_dedupe_key,
    queued,
  })
}

impl From<StateError> for ChannelToolError {
  fn from(error: StateError) -> Self {
    Self::State(error)
  }
}

impl From<ChannelContractError> for ChannelToolError {
  fn from(error: ChannelContractError) -> Self {
    Self::InvalidRequest(error)
  }
}

impl From<ChannelContextProviderError> for ChannelToolError {
  fn from(error: ChannelContextProviderError) -> Self {
    Self::ContextProvider(error)
  }
}

impl From<ChannelResourceProviderError> for ChannelToolError {
  fn from(error: ChannelResourceProviderError) -> Self {
    Self::ResourceProvider(error)
  }
}
