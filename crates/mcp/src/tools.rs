use codeoff_channel_contract::{
  ChannelCurrentContextRequest, ChannelLookupRequest, ChannelMessageFetchRequest,
  ChannelReplyTarget, ChannelResourceDownloadRequest, ChannelResourceInfoRequest,
  ChannelResourceTextRequest, ChannelSearchRequest, ChannelThreadReplyRequest,
  ChannelUserResolveRequest, ChannelUserSearchRequest, ChannelWorkspaceRequest,
};
use codeoff_runtime::channel_tools::{
  ChannelChannelProvider, ChannelContextProvider, ChannelSenderProvider, ChannelStatusProvider,
  ChannelThreadReplyProvider, ChannelToolError, ChannelUserProvider, GetDeliveryStatusRequest,
  GetRecentMessagesRequest, GetThreadContextRequest, ReplyToEventRequest, SendMessageRequest,
  get_channel, get_connector_status, get_context_pack, get_current_conversation, get_current_event,
  get_delivery_status, get_message, get_recent_messages, get_resource_info, get_thread_context,
  get_user, list_senders, list_workspaces, read_resource_text, reply_to_event, reply_to_thread,
  resolve_channel, resolve_user, search_channels, search_users, send_message,
};
use codeoff_runtime::channel_tools::{ChannelResourceProvider, download_resource};
use codeoff_state::{SlackDeliveryStatus, SlackDeliveryStatusKind, StateStore};
use serde::Deserialize;
use serde_json::{Value, json};
use std::time::{SystemTime, UNIX_EPOCH};

const TOOL_REPLY_TO_EVENT: &str = "channel.reply_to_event";
const TOOL_SEND_MESSAGE: &str = "channel.send_message";
const TOOL_GET_THREAD_CONTEXT: &str = "channel.get_thread_context";
const TOOL_GET_RECENT_MESSAGES: &str = "channel.get_recent_messages";
const TOOL_GET_CURRENT_EVENT: &str = "channel.get_current_event";
const TOOL_GET_CURRENT_CONVERSATION: &str = "channel.get_current_conversation";
const TOOL_GET_CONTEXT_PACK: &str = "channel.get_context_pack";
const TOOL_GET_DELIVERY_STATUS: &str = "channel.get_delivery_status";
const TOOL_GET_MESSAGE: &str = "channel.get_message";
const TOOL_GET_RESOURCE_INFO: &str = "channel.get_resource_info";
const TOOL_READ_RESOURCE_TEXT: &str = "channel.read_resource_text";
const TOOL_DOWNLOAD_RESOURCE: &str = "channel.download_resource";
const TOOL_SEARCH_USERS: &str = "channel.search_users";
const TOOL_GET_USER: &str = "channel.get_user";
const TOOL_RESOLVE_USER: &str = "channel.resolve_user";
const TOOL_SEARCH_CHANNELS: &str = "channel.search_channels";
const TOOL_GET_CHANNEL: &str = "channel.get_channel";
const TOOL_RESOLVE_CHANNEL: &str = "channel.resolve_channel";
const TOOL_LIST_SENDERS: &str = "channel.list_senders";
const TOOL_LIST_WORKSPACES: &str = "channel.list_workspaces";
const TOOL_GET_CONNECTOR_STATUS: &str = "channel.get_connector_status";
const TOOL_REPLY_TO_THREAD: &str = "channel.reply_to_thread";

pub struct ChannelToolDispatcher<'a> {
  state: &'a StateStore,
  context_provider: &'a dyn ChannelContextProvider,
  resource_provider: Option<&'a dyn ChannelResourceProvider>,
  user_provider: Option<&'a dyn ChannelUserProvider>,
  channel_provider: Option<&'a dyn ChannelChannelProvider>,
  sender_provider: Option<&'a dyn ChannelSenderProvider>,
  status_provider: Option<&'a dyn ChannelStatusProvider>,
  thread_reply_provider: Option<&'a dyn ChannelThreadReplyProvider>,
  now_unix_seconds: u64,
}

impl<'a> ChannelToolDispatcher<'a> {
  #[must_use]
  pub fn new(state: &'a StateStore, context_provider: &'a dyn ChannelContextProvider) -> Self {
    Self::new_with_now(state, context_provider, current_unix_seconds())
  }

  #[must_use]
  pub const fn new_with_now(
    state: &'a StateStore,
    context_provider: &'a dyn ChannelContextProvider,
    now_unix_seconds: u64,
  ) -> Self {
    Self {
      state,
      context_provider,
      resource_provider: None,
      user_provider: None,
      channel_provider: None,
      sender_provider: None,
      status_provider: None,
      thread_reply_provider: None,
      now_unix_seconds,
    }
  }

  #[must_use]
  pub const fn new_with_resource_provider_and_now(
    state: &'a StateStore,
    context_provider: &'a dyn ChannelContextProvider,
    resource_provider: &'a dyn ChannelResourceProvider,
    now_unix_seconds: u64,
  ) -> Self {
    Self {
      state,
      context_provider,
      resource_provider: Some(resource_provider),
      user_provider: None,
      channel_provider: None,
      sender_provider: None,
      status_provider: None,
      thread_reply_provider: None,
      now_unix_seconds,
    }
  }

  #[must_use]
  #[allow(clippy::too_many_arguments)]
  pub const fn new_with_address_providers_and_now(
    state: &'a StateStore,
    context_provider: &'a dyn ChannelContextProvider,
    user_provider: &'a dyn ChannelUserProvider,
    channel_provider: &'a dyn ChannelChannelProvider,
    sender_provider: &'a dyn ChannelSenderProvider,
    status_provider: &'a dyn ChannelStatusProvider,
    thread_reply_provider: &'a dyn ChannelThreadReplyProvider,
    now_unix_seconds: u64,
  ) -> Self {
    Self {
      state,
      context_provider,
      resource_provider: None,
      user_provider: Some(user_provider),
      channel_provider: Some(channel_provider),
      sender_provider: Some(sender_provider),
      status_provider: Some(status_provider),
      thread_reply_provider: Some(thread_reply_provider),
      now_unix_seconds,
    }
  }

  #[must_use]
  #[allow(clippy::too_many_arguments)]
  pub const fn new_with_resource_and_address_providers_and_now(
    state: &'a StateStore,
    context_provider: &'a dyn ChannelContextProvider,
    resource_provider: &'a dyn ChannelResourceProvider,
    user_provider: &'a dyn ChannelUserProvider,
    channel_provider: &'a dyn ChannelChannelProvider,
    sender_provider: &'a dyn ChannelSenderProvider,
    status_provider: &'a dyn ChannelStatusProvider,
    thread_reply_provider: &'a dyn ChannelThreadReplyProvider,
    now_unix_seconds: u64,
  ) -> Self {
    Self {
      state,
      context_provider,
      resource_provider: Some(resource_provider),
      user_provider: Some(user_provider),
      channel_provider: Some(channel_provider),
      sender_provider: Some(sender_provider),
      status_provider: Some(status_provider),
      thread_reply_provider: Some(thread_reply_provider),
      now_unix_seconds,
    }
  }

  #[must_use]
  pub fn list_tools(&self) -> Vec<Value> {
    [
      TOOL_REPLY_TO_EVENT,
      TOOL_SEND_MESSAGE,
      TOOL_GET_THREAD_CONTEXT,
      TOOL_GET_RECENT_MESSAGES,
      TOOL_GET_CURRENT_EVENT,
      TOOL_GET_CURRENT_CONVERSATION,
      TOOL_GET_CONTEXT_PACK,
      TOOL_GET_DELIVERY_STATUS,
      TOOL_GET_MESSAGE,
      TOOL_GET_RESOURCE_INFO,
      TOOL_READ_RESOURCE_TEXT,
      TOOL_DOWNLOAD_RESOURCE,
      TOOL_SEARCH_USERS,
      TOOL_GET_USER,
      TOOL_RESOLVE_USER,
      TOOL_SEARCH_CHANNELS,
      TOOL_GET_CHANNEL,
      TOOL_RESOLVE_CHANNEL,
      TOOL_LIST_SENDERS,
      TOOL_LIST_WORKSPACES,
      TOOL_GET_CONNECTOR_STATUS,
      TOOL_REPLY_TO_THREAD,
    ]
    .into_iter()
    .map(|name| {
      json!({
        "name": name,
        "description": tool_description(name),
        "inputSchema": tool_input_schema(name),
      })
    })
    .collect()
  }

  pub async fn call(&self, params: Option<Value>) -> Result<Value, ToolCallError> {
    let params: ToolCallParams =
      deserialize_params(params.ok_or(ToolCallError::InvalidParams {
        message: "tools/call params are required".to_owned(),
      })?)?;
    match params.name.as_str() {
      TOOL_REPLY_TO_EVENT => {
        let request = reply_to_event_request_from_args(
          deserialize_params::<ReplyToEventArgs>(params.arguments)?,
          self.now_unix_seconds,
        );
        let result = match reply_to_event(self.state, request).await {
          Ok(result) => result,
          Err(error) => return Ok(tool_execution_error(error)),
        };
        Ok(tool_result(json!({
          "request_dedupe_key": result.request_dedupe_key,
          "queued": result.queued,
        })))
      }
      TOOL_SEND_MESSAGE => {
        let request = send_message_request_from_args(
          deserialize_params::<SendMessageArgs>(params.arguments)?,
          self.now_unix_seconds,
        );
        let result = match send_message(self.state, request).await {
          Ok(result) => result,
          Err(error) => return Ok(tool_execution_error(error)),
        };
        Ok(tool_result(json!({
          "request_dedupe_key": result.request_dedupe_key,
          "queued": result.queued,
        })))
      }
      TOOL_GET_THREAD_CONTEXT => {
        let request = deserialize_params::<GetThreadContextArgs>(params.arguments)?.into();
        let page = match get_thread_context(self.context_provider, request).await {
          Ok(page) => page,
          Err(error) => return Ok(tool_execution_error(error)),
        };
        Ok(tool_result(json!({
          "events": page.events,
          "next_cursor": page.next_cursor,
        })))
      }
      TOOL_GET_RECENT_MESSAGES => {
        let request = deserialize_params::<GetRecentMessagesArgs>(params.arguments)?.into();
        let page = match get_recent_messages(self.context_provider, request).await {
          Ok(page) => page,
          Err(error) => return Ok(tool_execution_error(error)),
        };
        Ok(tool_result(json!({
          "events": page.events,
          "next_cursor": page.next_cursor,
        })))
      }
      TOOL_GET_CURRENT_EVENT => {
        let request = deserialize_params::<CurrentContextArgs>(params.arguments)?.into();
        let event = match get_current_event(self.state, request).await {
          Ok(event) => event,
          Err(error) => return Ok(tool_execution_error(error)),
        };
        Ok(tool_result(json!(event)))
      }
      TOOL_GET_CURRENT_CONVERSATION => {
        let request = deserialize_params::<CurrentContextArgs>(params.arguments)?.into();
        let conversation = match get_current_conversation(self.state, request).await {
          Ok(conversation) => conversation,
          Err(error) => return Ok(tool_execution_error(error)),
        };
        Ok(tool_result(json!(conversation)))
      }
      TOOL_GET_CONTEXT_PACK => {
        let request = deserialize_params::<CurrentContextArgs>(params.arguments)?.into();
        let pack = match get_context_pack(self.state, request).await {
          Ok(pack) => pack,
          Err(error) => return Ok(tool_execution_error(error)),
        };
        Ok(tool_result(json!(pack)))
      }
      TOOL_GET_DELIVERY_STATUS => {
        let request = get_delivery_status_request_from_args(
          deserialize_params::<GetDeliveryStatusArgs>(params.arguments)?,
          self.now_unix_seconds,
        );
        let delivery = match get_delivery_status(self.state, request).await {
          Ok(delivery) => delivery.map(delivery_status_json),
          Err(error) => return Ok(tool_execution_error(error)),
        };
        Ok(tool_result(json!({
          "delivery": delivery,
        })))
      }
      TOOL_GET_MESSAGE => {
        let Some(resource_provider) = self.resource_provider else {
          return Ok(resource_provider_unavailable());
        };
        let request = deserialize_params::<GetMessageArgs>(params.arguments)?.into();
        let message = match get_message(resource_provider, request).await {
          Ok(message) => message,
          Err(error) => return Ok(tool_execution_error(error)),
        };
        Ok(tool_result(json!(message)))
      }
      TOOL_GET_RESOURCE_INFO => {
        let Some(resource_provider) = self.resource_provider else {
          return Ok(resource_provider_unavailable());
        };
        let request = deserialize_params::<GetResourceInfoArgs>(params.arguments)?.into();
        let resource = match get_resource_info(resource_provider, request).await {
          Ok(resource) => resource,
          Err(error) => return Ok(tool_execution_error(error)),
        };
        Ok(tool_result(json!(resource)))
      }
      TOOL_READ_RESOURCE_TEXT => {
        let Some(resource_provider) = self.resource_provider else {
          return Ok(resource_provider_unavailable());
        };
        let request = deserialize_params::<ReadResourceTextArgs>(params.arguments)?.into();
        let resource = match read_resource_text(resource_provider, request).await {
          Ok(resource) => resource,
          Err(error) => return Ok(tool_execution_error(error)),
        };
        Ok(tool_result(json!(resource)))
      }
      TOOL_DOWNLOAD_RESOURCE => {
        let Some(resource_provider) = self.resource_provider else {
          return Ok(resource_provider_unavailable());
        };
        let request = deserialize_params::<DownloadResourceArgs>(params.arguments)?.into();
        let resource = match download_resource(resource_provider, request).await {
          Ok(resource) => resource,
          Err(error) => return Ok(tool_execution_error(error)),
        };
        Ok(tool_result(json!(resource)))
      }
      TOOL_SEARCH_USERS => {
        let Some(user_provider) = self.user_provider else {
          return Ok(provider_unavailable(
            "user_provider",
            "channel user provider is unavailable",
          ));
        };
        let request = deserialize_params::<SearchUsersArgs>(params.arguments)?.into();
        let users = match search_users(user_provider, request).await {
          Ok(users) => users,
          Err(error) => return Ok(tool_execution_error(error)),
        };
        Ok(tool_result(json!({ "users": users })))
      }
      TOOL_GET_USER => {
        let Some(user_provider) = self.user_provider else {
          return Ok(provider_unavailable(
            "user_provider",
            "channel user provider is unavailable",
          ));
        };
        let request = deserialize_params::<LookupArgs>(params.arguments)?.into();
        let user = match get_user(user_provider, request).await {
          Ok(user) => user,
          Err(error) => return Ok(tool_execution_error(error)),
        };
        Ok(tool_result(json!({ "user": user })))
      }
      TOOL_RESOLVE_USER => {
        let Some(user_provider) = self.user_provider else {
          return Ok(provider_unavailable(
            "user_provider",
            "channel user provider is unavailable",
          ));
        };
        let request = deserialize_params::<ResolveUserArgs>(params.arguments)?.into();
        let result = match resolve_user(user_provider, request).await {
          Ok(result) => result,
          Err(error) => return Ok(tool_execution_error(error)),
        };
        Ok(tool_result(json!(result)))
      }
      TOOL_SEARCH_CHANNELS => {
        let Some(channel_provider) = self.channel_provider else {
          return Ok(provider_unavailable(
            "channel_provider",
            "channel channel provider is unavailable",
          ));
        };
        let request = deserialize_params::<SearchChannelsArgs>(params.arguments)?.into();
        let channels = match search_channels(channel_provider, request).await {
          Ok(channels) => channels,
          Err(error) => return Ok(tool_execution_error(error)),
        };
        Ok(tool_result(json!({ "channels": channels })))
      }
      TOOL_GET_CHANNEL => {
        let Some(channel_provider) = self.channel_provider else {
          return Ok(provider_unavailable(
            "channel_provider",
            "channel channel provider is unavailable",
          ));
        };
        let request = deserialize_params::<LookupArgs>(params.arguments)?.into();
        let channel = match get_channel(channel_provider, request).await {
          Ok(channel) => channel,
          Err(error) => return Ok(tool_execution_error(error)),
        };
        Ok(tool_result(json!({ "channel": channel })))
      }
      TOOL_RESOLVE_CHANNEL => {
        let Some(channel_provider) = self.channel_provider else {
          return Ok(provider_unavailable(
            "channel_provider",
            "channel channel provider is unavailable",
          ));
        };
        let request = deserialize_params::<SearchChannelsArgs>(params.arguments)?.into();
        let result = match resolve_channel(channel_provider, request).await {
          Ok(result) => result,
          Err(error) => return Ok(tool_execution_error(error)),
        };
        Ok(tool_result(json!(result)))
      }
      TOOL_LIST_SENDERS => {
        let Some(sender_provider) = self.sender_provider else {
          return Ok(provider_unavailable(
            "sender_provider",
            "channel sender provider is unavailable",
          ));
        };
        let request = deserialize_params::<WorkspaceArgs>(params.arguments)?.into();
        let senders = match list_senders(sender_provider, request).await {
          Ok(senders) => senders,
          Err(error) => return Ok(tool_execution_error(error)),
        };
        Ok(tool_result(json!({ "senders": senders })))
      }
      TOOL_LIST_WORKSPACES => {
        let Some(status_provider) = self.status_provider else {
          return Ok(provider_unavailable(
            "status_provider",
            "channel status provider is unavailable",
          ));
        };
        let workspaces = match list_workspaces(status_provider).await {
          Ok(workspaces) => workspaces,
          Err(error) => return Ok(tool_execution_error(error)),
        };
        Ok(tool_result(json!({ "workspaces": workspaces })))
      }
      TOOL_GET_CONNECTOR_STATUS => {
        let Some(status_provider) = self.status_provider else {
          return Ok(provider_unavailable(
            "status_provider",
            "channel status provider is unavailable",
          ));
        };
        let request = deserialize_params::<WorkspaceArgs>(params.arguments)?.into();
        let status = match get_connector_status(status_provider, request).await {
          Ok(status) => status,
          Err(error) => return Ok(tool_execution_error(error)),
        };
        Ok(tool_result(json!({ "status": status })))
      }
      TOOL_REPLY_TO_THREAD => {
        let Some(thread_reply_provider) = self.thread_reply_provider else {
          return Ok(provider_unavailable(
            "thread_reply_provider",
            "channel thread reply provider is unavailable",
          ));
        };
        let request = deserialize_params::<ReplyToThreadArgs>(params.arguments)?.into();
        let receipt = match reply_to_thread(thread_reply_provider, request).await {
          Ok(receipt) => receipt,
          Err(error) => return Ok(tool_execution_error(error)),
        };
        Ok(tool_result(json!(receipt)))
      }
      _ => Err(ToolCallError::ToolNotFound { tool: params.name }),
    }
  }
}

fn current_unix_seconds() -> u64 {
  SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap_or_default()
    .as_secs()
}

fn tool_description(name: &str) -> &'static str {
  match name {
    TOOL_REPLY_TO_EVENT => "Queue a bounded reply to a known channel event.",
    TOOL_SEND_MESSAGE => "Queue a bounded channel message delivery.",
    TOOL_GET_THREAD_CONTEXT => "Fetch bounded context for a channel thread.",
    TOOL_GET_RECENT_MESSAGES => "Fetch bounded recent messages for a channel.",
    TOOL_GET_CURRENT_EVENT => "Read compact metadata for the current source channel event.",
    TOOL_GET_CURRENT_CONVERSATION => {
      "Read compact conversation coordinates for the current source channel event."
    }
    TOOL_GET_CONTEXT_PACK => "Read compact current channel context and tool hints.",
    TOOL_GET_DELIVERY_STATUS => "Read bounded channel delivery status.",
    TOOL_GET_MESSAGE => "Fetch one exact channel message by channel and message identifier.",
    TOOL_GET_RESOURCE_INFO => "Fetch provider-neutral channel resource metadata.",
    TOOL_READ_RESOURCE_TEXT => "Read best-effort text from a channel resource.",
    TOOL_DOWNLOAD_RESOURCE => "Download a channel resource to a local artifact.",
    TOOL_SEARCH_USERS => "Search provider-neutral channel users.",
    TOOL_GET_USER => "Fetch one provider-neutral channel user by id.",
    TOOL_RESOLVE_USER => "Resolve a channel user without auto-picking ambiguous matches.",
    TOOL_SEARCH_CHANNELS => "Search provider-neutral channels.",
    TOOL_GET_CHANNEL => "Fetch one provider-neutral channel by id.",
    TOOL_RESOLVE_CHANNEL => "Resolve a channel without auto-picking ambiguous matches.",
    TOOL_LIST_SENDERS => "List provider-neutral senders available for a connector workspace.",
    TOOL_LIST_WORKSPACES => "List provider-neutral channel connector workspaces.",
    TOOL_GET_CONNECTOR_STATUS => "Read provider-neutral connector status.",
    TOOL_REPLY_TO_THREAD => "Send a provider-neutral reply to a channel thread.",
    _ => "Unknown tool.",
  }
}

fn tool_input_schema(name: &str) -> Value {
  match name {
    TOOL_REPLY_TO_EVENT => json!({
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
    }),
    TOOL_SEND_MESSAGE => json!({
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
    }),
    TOOL_GET_THREAD_CONTEXT => json!({
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
    }),
    TOOL_GET_RECENT_MESSAGES => json!({
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
    }),
    TOOL_GET_CURRENT_EVENT | TOOL_GET_CURRENT_CONVERSATION | TOOL_GET_CONTEXT_PACK => {
      current_context_schema()
    }
    TOOL_GET_DELIVERY_STATUS => json!({
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
    }),
    TOOL_GET_MESSAGE => json!({
      "type": "object",
      "properties": {
        "connector_id": string_schema("Codeoff connector id."),
        "workspace_id": string_schema("Channel workspace id."),
        "channel_id": string_schema("Channel id."),
        "thread_id": cursor_schema(),
        "message_ts": string_schema("Channel message timestamp or id."),
      },
      "required": [
        "connector_id",
        "workspace_id",
        "channel_id",
        "message_ts"
      ],
      "additionalProperties": false,
    }),
    TOOL_GET_RESOURCE_INFO | TOOL_READ_RESOURCE_TEXT | TOOL_DOWNLOAD_RESOURCE => json!({
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
    }),
    TOOL_SEARCH_USERS => search_schema("Provider-neutral user search query."),
    TOOL_GET_USER | TOOL_GET_CHANNEL => lookup_schema(),
    TOOL_RESOLVE_USER => json!({
      "type": "object",
      "properties": {
        "connector_id": string_schema("Codeoff connector id."),
        "workspace_id": string_schema("Channel workspace id."),
        "query": string_schema("Provider-neutral user resolution query."),
      },
      "required": ["connector_id", "workspace_id", "query"],
      "additionalProperties": false,
    }),
    TOOL_SEARCH_CHANNELS | TOOL_RESOLVE_CHANNEL => {
      search_schema("Provider-neutral channel search query.")
    }
    TOOL_LIST_SENDERS | TOOL_GET_CONNECTOR_STATUS => workspace_schema(),
    TOOL_LIST_WORKSPACES => empty_schema(),
    TOOL_REPLY_TO_THREAD => json!({
      "type": "object",
      "properties": {
        "connector_id": string_schema("Codeoff connector id."),
        "workspace_id": string_schema("Channel workspace id."),
        "channel_id": string_schema("Provider-neutral channel id."),
        "thread_id": string_schema("Provider-neutral thread id."),
        "request_dedupe_key": string_schema("Stable idempotency key for this reply request."),
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
    }),
    _ => json!({ "type": "object" }),
  }
}

fn workspace_schema() -> Value {
  json!({
    "type": "object",
    "properties": {
      "connector_id": string_schema("Codeoff connector id."),
      "workspace_id": string_schema("Channel workspace id."),
    },
    "required": ["connector_id", "workspace_id"],
    "additionalProperties": false,
  })
}

fn current_context_schema() -> Value {
  json!({
    "type": "object",
    "properties": {
      "connector_id": string_schema("Codeoff connector id."),
      "workspace_id": string_schema("Channel workspace id."),
      "event_dedupe_key": string_schema("Dedupe key of the current source channel event."),
    },
    "required": ["connector_id", "workspace_id", "event_dedupe_key"],
    "additionalProperties": false,
  })
}

fn lookup_schema() -> Value {
  json!({
    "type": "object",
    "properties": {
      "connector_id": string_schema("Codeoff connector id."),
      "workspace_id": string_schema("Channel workspace id."),
      "id": string_schema("Provider-neutral identifier."),
    },
    "required": ["connector_id", "workspace_id", "id"],
    "additionalProperties": false,
  })
}

fn empty_schema() -> Value {
  json!({
    "type": "object",
    "properties": {},
    "additionalProperties": false,
  })
}

fn search_schema(query_description: &str) -> Value {
  json!({
    "type": "object",
    "properties": {
      "connector_id": string_schema("Codeoff connector id."),
      "workspace_id": string_schema("Channel workspace id."),
      "query": string_schema(query_description),
      "limit": limit_schema(),
    },
    "required": ["connector_id", "workspace_id", "query", "limit"],
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

fn string_schema(description: &str) -> Value {
  json!({
    "type": "string",
    "description": description,
    "minLength": 1,
  })
}

fn limit_schema() -> Value {
  json!({
    "type": "integer",
    "description": "Maximum number of messages to fetch.",
    "minimum": 1,
  })
}

fn cursor_schema() -> Value {
  json!({
    "type": ["string", "null"],
    "description": "Optional Slack pagination cursor returned by the previous context page.",
    "minLength": 1,
  })
}

fn send_as_schema() -> Value {
  json!({
    "type": ["string", "null"],
    "description": "Optional provider-neutral sender selector.",
  })
}

fn deserialize_params<T: for<'de> Deserialize<'de>>(value: Value) -> Result<T, ToolCallError> {
  serde_json::from_value(value).map_err(|source| ToolCallError::InvalidParams {
    message: source.to_string(),
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
    "status": status_kind_name(status.status),
    "available_at": status.available_at,
    "attempt_count": status.attempt_count,
    "sender_kind": status.sender_kind,
    "sender_key": status.sender_key,
  })
}

fn tool_result(structured_content: Value) -> Value {
  json!({
    "content": [
      {
        "type": "text",
        "text": structured_content.to_string(),
      }
    ],
    "structuredContent": structured_content,
    "isError": false,
  })
}

fn tool_execution_error(error: ChannelToolError) -> Value {
  let structured_content = json!({
    "kind": channel_error_kind(&error),
    "message": error.to_string(),
  });
  json!({
    "content": [
      {
        "type": "text",
        "text": structured_content.to_string(),
      }
    ],
    "structuredContent": structured_content,
    "isError": true,
  })
}

fn resource_provider_unavailable() -> Value {
  provider_unavailable(
    "resource_provider",
    "channel resource provider is unavailable",
  )
}

fn provider_unavailable(kind: &str, message: &str) -> Value {
  let structured_content = json!({
    "kind": kind,
    "message": message,
  });
  json!({
    "content": [
      {
        "type": "text",
        "text": structured_content.to_string(),
      }
    ],
    "structuredContent": structured_content,
    "isError": true,
  })
}

const fn status_kind_name(status: SlackDeliveryStatusKind) -> &'static str {
  match status {
    SlackDeliveryStatusKind::Pending => "pending",
    SlackDeliveryStatusKind::Deferred => "deferred",
    SlackDeliveryStatusKind::Processing => "processing",
    SlackDeliveryStatusKind::Delivered => "delivered",
    SlackDeliveryStatusKind::Failed => "failed",
  }
}

#[derive(Debug, Deserialize)]
struct ToolCallParams {
  name: String,
  #[serde(default)]
  arguments: Value,
}

#[derive(Debug, Deserialize)]
struct ReplyToEventArgs {
  connector_id: String,
  workspace_id: String,
  event_dedupe_key: String,
  request_dedupe_key: String,
  text: String,
  #[serde(default)]
  send_as: Option<String>,
}

fn reply_to_event_request_from_args(
  value: ReplyToEventArgs,
  now_unix_seconds: u64,
) -> ReplyToEventRequest {
  ReplyToEventRequest {
    connector_id: value.connector_id,
    workspace_id: value.workspace_id,
    event_dedupe_key: value.event_dedupe_key,
    request_dedupe_key: value.request_dedupe_key,
    text: value.text,
    send_as: value.send_as,
    now_unix_seconds,
  }
}

#[derive(Debug, Deserialize)]
struct SendMessageArgs {
  connector_id: String,
  workspace_id: String,
  request_dedupe_key: String,
  target: ChannelReplyTarget,
  text: String,
  #[serde(default)]
  send_as: Option<String>,
}

fn send_message_request_from_args(
  value: SendMessageArgs,
  now_unix_seconds: u64,
) -> SendMessageRequest {
  SendMessageRequest {
    connector_id: value.connector_id,
    workspace_id: value.workspace_id,
    request_dedupe_key: value.request_dedupe_key,
    target: value.target,
    text: value.text,
    send_as: value.send_as,
    now_unix_seconds,
  }
}

#[derive(Debug, Deserialize)]
struct GetDeliveryStatusArgs {
  workspace_id: String,
  request_dedupe_key: String,
}

fn get_delivery_status_request_from_args(
  value: GetDeliveryStatusArgs,
  now_unix_seconds: u64,
) -> GetDeliveryStatusRequest {
  GetDeliveryStatusRequest {
    workspace_id: value.workspace_id,
    request_dedupe_key: value.request_dedupe_key,
    now_unix_seconds,
  }
}

#[derive(Debug, Deserialize)]
struct GetThreadContextArgs {
  connector_id: String,
  workspace_id: String,
  channel_id: String,
  thread_id: String,
  limit: u16,
  #[serde(default)]
  cursor: Option<String>,
}

impl From<GetThreadContextArgs> for GetThreadContextRequest {
  fn from(value: GetThreadContextArgs) -> Self {
    Self {
      connector_id: value.connector_id,
      workspace_id: value.workspace_id,
      channel_id: value.channel_id,
      thread_id: value.thread_id,
      limit: value.limit,
      cursor: value.cursor,
    }
  }
}

#[derive(Debug, Deserialize)]
struct GetRecentMessagesArgs {
  connector_id: String,
  workspace_id: String,
  channel_id: String,
  limit: u16,
  #[serde(default)]
  cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GetMessageArgs {
  connector_id: String,
  workspace_id: String,
  channel_id: String,
  #[serde(default)]
  thread_id: Option<String>,
  message_ts: String,
}

impl From<GetMessageArgs> for ChannelMessageFetchRequest {
  fn from(value: GetMessageArgs) -> Self {
    Self {
      connector_id: value.connector_id,
      workspace_id: value.workspace_id,
      channel_id: value.channel_id,
      thread_id: value.thread_id,
      message_ts: value.message_ts,
    }
  }
}

#[derive(Debug, Deserialize)]
struct GetResourceInfoArgs {
  connector_id: String,
  workspace_id: String,
  resource_id: String,
}

impl From<GetResourceInfoArgs> for ChannelResourceInfoRequest {
  fn from(value: GetResourceInfoArgs) -> Self {
    Self {
      connector_id: value.connector_id,
      workspace_id: value.workspace_id,
      resource_id: value.resource_id,
    }
  }
}

#[derive(Debug, Deserialize)]
struct ReadResourceTextArgs {
  connector_id: String,
  workspace_id: String,
  resource_id: String,
}

impl From<ReadResourceTextArgs> for ChannelResourceTextRequest {
  fn from(value: ReadResourceTextArgs) -> Self {
    Self {
      connector_id: value.connector_id,
      workspace_id: value.workspace_id,
      resource_id: value.resource_id,
    }
  }
}

#[derive(Debug, Deserialize)]
struct DownloadResourceArgs {
  connector_id: String,
  workspace_id: String,
  resource_id: String,
}

impl From<DownloadResourceArgs> for ChannelResourceDownloadRequest {
  fn from(value: DownloadResourceArgs) -> Self {
    Self {
      connector_id: value.connector_id,
      workspace_id: value.workspace_id,
      resource_id: value.resource_id,
    }
  }
}

#[derive(Debug, Deserialize)]
struct WorkspaceArgs {
  connector_id: String,
  workspace_id: String,
}

impl From<WorkspaceArgs> for ChannelWorkspaceRequest {
  fn from(value: WorkspaceArgs) -> Self {
    Self {
      connector_id: value.connector_id,
      workspace_id: value.workspace_id,
    }
  }
}

#[derive(Debug, Deserialize)]
struct LookupArgs {
  connector_id: String,
  workspace_id: String,
  id: String,
}

impl From<LookupArgs> for ChannelLookupRequest {
  fn from(value: LookupArgs) -> Self {
    Self {
      connector_id: value.connector_id,
      workspace_id: value.workspace_id,
      id: value.id,
    }
  }
}

#[derive(Debug, Deserialize)]
struct SearchUsersArgs {
  connector_id: String,
  workspace_id: String,
  query: String,
  limit: u16,
}

impl From<SearchUsersArgs> for ChannelUserSearchRequest {
  fn from(value: SearchUsersArgs) -> Self {
    Self {
      connector_id: value.connector_id,
      workspace_id: value.workspace_id,
      query: value.query,
      limit: value.limit,
    }
  }
}

#[derive(Debug, Deserialize)]
struct ResolveUserArgs {
  connector_id: String,
  workspace_id: String,
  query: String,
}

impl From<ResolveUserArgs> for ChannelUserResolveRequest {
  fn from(value: ResolveUserArgs) -> Self {
    Self {
      connector_id: value.connector_id,
      workspace_id: value.workspace_id,
      query: value.query,
    }
  }
}

#[derive(Debug, Deserialize)]
struct SearchChannelsArgs {
  connector_id: String,
  workspace_id: String,
  query: String,
  limit: u16,
}

impl From<SearchChannelsArgs> for ChannelSearchRequest {
  fn from(value: SearchChannelsArgs) -> Self {
    Self {
      connector_id: value.connector_id,
      workspace_id: value.workspace_id,
      query: value.query,
      limit: value.limit,
    }
  }
}

#[derive(Debug, Deserialize)]
struct ReplyToThreadArgs {
  connector_id: String,
  workspace_id: String,
  channel_id: String,
  thread_id: String,
  request_dedupe_key: String,
  text: String,
  #[serde(default)]
  send_as: Option<String>,
}

impl From<ReplyToThreadArgs> for ChannelThreadReplyRequest {
  fn from(value: ReplyToThreadArgs) -> Self {
    Self {
      connector_id: value.connector_id,
      workspace_id: value.workspace_id,
      channel_id: value.channel_id,
      thread_id: value.thread_id,
      request_dedupe_key: value.request_dedupe_key,
      text: value.text,
      send_as: value.send_as,
    }
  }
}

impl From<GetRecentMessagesArgs> for GetRecentMessagesRequest {
  fn from(value: GetRecentMessagesArgs) -> Self {
    Self {
      connector_id: value.connector_id,
      workspace_id: value.workspace_id,
      channel_id: value.channel_id,
      limit: value.limit,
      cursor: value.cursor,
    }
  }
}

#[derive(Debug, Deserialize)]
struct CurrentContextArgs {
  connector_id: String,
  workspace_id: String,
  event_dedupe_key: String,
}

impl From<CurrentContextArgs> for ChannelCurrentContextRequest {
  fn from(value: CurrentContextArgs) -> Self {
    Self {
      connector_id: value.connector_id,
      workspace_id: value.workspace_id,
      event_dedupe_key: value.event_dedupe_key,
    }
  }
}

#[derive(Debug)]
pub enum ToolCallError {
  MethodNotFound { method: String },
  ToolNotFound { tool: String },
  InvalidParams { message: String },
}

impl ToolCallError {
  #[must_use]
  pub fn into_json_rpc_parts(self) -> (i64, String, Value) {
    match self {
      Self::MethodNotFound { method } => (
        -32601,
        "method not found".to_owned(),
        json!({ "method": method }),
      ),
      Self::ToolNotFound { tool } => (-32601, "tool not found".to_owned(), json!({ "tool": tool })),
      Self::InvalidParams { message } => (
        -32602,
        "invalid params".to_owned(),
        json!({ "message": message }),
      ),
    }
  }
}

const fn channel_error_kind(error: &ChannelToolError) -> &'static str {
  match error {
    ChannelToolError::MissingSourceEvent => "missing_source_event",
    ChannelToolError::MissingReplyTarget => "missing_reply_target",
    ChannelToolError::UnsupportedTarget => "unsupported_target",
    ChannelToolError::InvalidSender { .. } => "invalid_sender",
    ChannelToolError::InvalidRequest(_) => "invalid_request",
    ChannelToolError::ContextProvider(_) => "context_provider",
    ChannelToolError::ResourceProvider(_) => "resource_provider",
    ChannelToolError::State(_) => "state",
  }
}
