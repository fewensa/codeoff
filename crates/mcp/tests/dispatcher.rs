use std::sync::Mutex;

use codeoff_channel_contract::{
  ChannelConnectorStatus, ChannelContextPage, ChannelContextRequest, ChannelEvent,
  ChannelEventKind, ChannelLookupRequest, ChannelMessageFetchRequest, ChannelMessageSnapshot,
  ChannelReplyTarget, ChannelResourceDownload, ChannelResourceDownloadRequest, ChannelResourceInfo,
  ChannelResourceInfoRequest, ChannelResourceText, ChannelResourceTextRequest,
  ChannelSearchRequest, ChannelSenderSummary, ChannelSummary, ChannelThreadReplyReceipt,
  ChannelThreadReplyRequest, ChannelUserResolveRequest, ChannelUserResolveResult,
  ChannelUserSearchRequest, ChannelUserSummary, ChannelWorkspaceRequest, ChannelWorkspaceSummary,
};
use codeoff_mcp::{ChannelToolDispatcher, JsonRpcDispatcher, JsonRpcRequest};
use codeoff_runtime::channel_tools::{
  ChannelChannelProvider, ChannelResourceProvider, ChannelResourceProviderError,
  ChannelSenderProvider, ChannelStatusProvider, ChannelThreadReplyProvider, ChannelToolError,
  ChannelUserProvider,
};
use codeoff_runtime::channel_tools::{
  ChannelContextProvider, ChannelContextProviderError, GetDeliveryStatusRequest,
  get_delivery_status,
};
use codeoff_state::{SlackDeliveryStatusKind, SlackSourceEvent, StateStore};
use serde_json::{Value, json};
use tempfile::{TempDir, tempdir};

struct TestStore {
  _temp: TempDir,
  store: StateStore,
}

async fn store() -> TestStore {
  let temp = tempdir().expect("tempdir");
  let store = StateStore::initialize(temp.path(), None)
    .await
    .expect("store");
  TestStore { _temp: temp, store }
}

async fn persist_source(store: &StateStore, source: SlackSourceEvent) {
  let mut event = ChannelEvent::new(
    "slack",
    "slack-default",
    &source.workspace_id,
    source
      .event_id
      .clone()
      .unwrap_or_else(|| "event-1".to_owned()),
    &source.dedupe_key,
    ChannelEventKind::MentionReceived,
  )
  .expect("event");
  if let (Some(channel_id), Some(thread_id)) = (
    source.channel_id.clone(),
    source
      .thread_ts
      .clone()
      .or_else(|| source.message_ts.clone()),
  ) {
    event = event
      .with_source_details(
        ChannelReplyTarget::Thread {
          channel_id,
          thread_id,
        },
        "slack://workspace-1/C1/100.0",
      )
      .expect("source details");
  }
  store
    .persist_slack_source_event(&source, &event)
    .await
    .expect("persist source");
}

#[derive(Default)]
struct FakeContextProvider {
  requests: Mutex<Vec<ChannelContextRequest>>,
}

#[derive(Default)]
#[allow(clippy::struct_field_names)]
struct FakeResourceProvider {
  message_requests: Mutex<Vec<ChannelMessageFetchRequest>>,
  info_requests: Mutex<Vec<ChannelResourceInfoRequest>>,
  text_requests: Mutex<Vec<ChannelResourceTextRequest>>,
  download_requests: Mutex<Vec<ChannelResourceDownloadRequest>>,
}

#[derive(Default)]
#[allow(clippy::struct_field_names)]
struct FakeAddressProvider {
  user_search_requests: Mutex<Vec<ChannelUserSearchRequest>>,
  user_resolve_requests: Mutex<Vec<ChannelUserResolveRequest>>,
  reply_requests: Mutex<Vec<ChannelThreadReplyRequest>>,
}

#[async_trait::async_trait]
impl ChannelContextProvider for FakeContextProvider {
  async fn fetch_context(
    &self,
    request: ChannelContextRequest,
  ) -> Result<ChannelContextPage, ChannelContextProviderError> {
    self.requests.lock().expect("requests").push(request);
    Ok(ChannelContextPage {
      events: vec![
        ChannelEvent::new(
          "slack",
          "slack-default",
          "workspace-1",
          "event-2",
          "dedupe-2",
          ChannelEventKind::MessageReceived,
        )
        .expect("event")
        .with_source_details(
          ChannelReplyTarget::Thread {
            channel_id: "C1".to_owned(),
            thread_id: "100.0".to_owned(),
          },
          "slack://workspace-1/C1/100.0",
        )
        .expect("source details"),
      ],
      next_cursor: Some("cursor-2".to_owned()),
    })
  }
}

#[async_trait::async_trait]
impl ChannelResourceProvider for FakeResourceProvider {
  async fn fetch_message(
    &self,
    request: ChannelMessageFetchRequest,
  ) -> Result<ChannelMessageSnapshot, ChannelResourceProviderError> {
    self
      .message_requests
      .lock()
      .expect("message requests")
      .push(request.clone());
    Ok(ChannelMessageSnapshot {
      connector_id: request.connector_id,
      workspace_id: request.workspace_id,
      channel_id: request.channel_id,
      thread_id: request.thread_id,
      message_ts: request.message_ts,
      text: Some("hello".to_owned()),
      resources: vec![ChannelResourceInfo {
        connector_id: "slack-default".to_owned(),
        workspace_id: "workspace-1".to_owned(),
        resource_id: "F1".to_owned(),
        name: Some("notes.txt".to_owned()),
        media_type: Some("text/plain".to_owned()),
        size_bytes: Some(5),
      }],
    })
  }

  async fn fetch_resource_info(
    &self,
    request: ChannelResourceInfoRequest,
  ) -> Result<ChannelResourceInfo, ChannelResourceProviderError> {
    self
      .info_requests
      .lock()
      .expect("info requests")
      .push(request.clone());
    Ok(ChannelResourceInfo {
      connector_id: request.connector_id,
      workspace_id: request.workspace_id,
      resource_id: request.resource_id,
      name: Some("notes.txt".to_owned()),
      media_type: Some("text/plain".to_owned()),
      size_bytes: Some(5),
    })
  }

  async fn read_resource_text(
    &self,
    request: ChannelResourceTextRequest,
  ) -> Result<ChannelResourceText, ChannelResourceProviderError> {
    self
      .text_requests
      .lock()
      .expect("text requests")
      .push(request.clone());
    Ok(ChannelResourceText {
      connector_id: request.connector_id,
      workspace_id: request.workspace_id,
      resource_id: request.resource_id,
      text: Some("hello".to_owned()),
    })
  }

  async fn download_resource(
    &self,
    request: ChannelResourceDownloadRequest,
  ) -> Result<ChannelResourceDownload, ChannelResourceProviderError> {
    self
      .download_requests
      .lock()
      .expect("download requests")
      .push(request.clone());
    Ok(ChannelResourceDownload {
      connector_id: request.connector_id,
      workspace_id: request.workspace_id,
      resource_id: request.resource_id,
      artifact_uri: "artifact://slack/workspace-1/F1/notes.txt".to_owned(),
      local_path: Some("/tmp/notes.txt".to_owned()),
    })
  }
}

#[async_trait::async_trait]
impl ChannelUserProvider for FakeAddressProvider {
  async fn search_users(
    &self,
    request: ChannelUserSearchRequest,
  ) -> Result<Vec<ChannelUserSummary>, ChannelToolError> {
    self
      .user_search_requests
      .lock()
      .expect("user search requests")
      .push(request.clone());
    Ok(vec![ChannelUserSummary {
      connector_id: request.connector_id,
      workspace_id: request.workspace_id,
      user_id: "user-1".to_owned(),
      display_name: Some("Alex Chen".to_owned()),
      handle: Some("alex".to_owned()),
      email: None,
    }])
  }

  async fn get_user(
    &self,
    request: ChannelLookupRequest,
  ) -> Result<Option<ChannelUserSummary>, ChannelToolError> {
    Ok(Some(ChannelUserSummary {
      connector_id: request.connector_id,
      workspace_id: request.workspace_id,
      user_id: request.id,
      display_name: Some("Alex Chen".to_owned()),
      handle: Some("alex".to_owned()),
      email: None,
    }))
  }

  async fn resolve_user(
    &self,
    request: ChannelUserResolveRequest,
  ) -> Result<ChannelUserResolveResult, ChannelToolError> {
    self
      .user_resolve_requests
      .lock()
      .expect("user resolve requests")
      .push(request.clone());
    Ok(ChannelUserResolveResult::ambiguous(vec![
      ChannelUserSummary {
        connector_id: request.connector_id.clone(),
        workspace_id: request.workspace_id.clone(),
        user_id: "user-1".to_owned(),
        display_name: Some("Alex Chen".to_owned()),
        handle: Some("alex".to_owned()),
        email: None,
      },
      ChannelUserSummary {
        connector_id: request.connector_id,
        workspace_id: request.workspace_id,
        user_id: "user-2".to_owned(),
        display_name: Some("Alex Chao".to_owned()),
        handle: Some("alex.c".to_owned()),
        email: None,
      },
    ]))
  }
}

#[async_trait::async_trait]
impl ChannelChannelProvider for FakeAddressProvider {
  async fn search_channels(
    &self,
    request: ChannelSearchRequest,
  ) -> Result<Vec<ChannelSummary>, ChannelToolError> {
    Ok(vec![ChannelSummary {
      connector_id: request.connector_id,
      workspace_id: request.workspace_id,
      channel_id: "channel-1".to_owned(),
      name: Some("triage".to_owned()),
      is_direct_message: false,
    }])
  }

  async fn get_channel(
    &self,
    request: ChannelLookupRequest,
  ) -> Result<Option<ChannelSummary>, ChannelToolError> {
    Ok(Some(ChannelSummary {
      connector_id: request.connector_id,
      workspace_id: request.workspace_id,
      channel_id: request.id,
      name: Some("triage".to_owned()),
      is_direct_message: false,
    }))
  }

  async fn resolve_channel(
    &self,
    request: ChannelSearchRequest,
  ) -> Result<Vec<ChannelSummary>, ChannelToolError> {
    Ok(vec![ChannelSummary {
      connector_id: request.connector_id,
      workspace_id: request.workspace_id,
      channel_id: "channel-1".to_owned(),
      name: Some("triage".to_owned()),
      is_direct_message: false,
    }])
  }
}

#[async_trait::async_trait]
impl ChannelSenderProvider for FakeAddressProvider {
  async fn list_senders(
    &self,
    request: ChannelWorkspaceRequest,
  ) -> Result<Vec<ChannelSenderSummary>, ChannelToolError> {
    Ok(vec![ChannelSenderSummary {
      connector_id: request.connector_id,
      workspace_id: request.workspace_id,
      sender_id: "bot".to_owned(),
      display_name: Some("Codeoff".to_owned()),
    }])
  }
}

#[async_trait::async_trait]
impl ChannelStatusProvider for FakeAddressProvider {
  async fn list_workspaces(&self) -> Result<Vec<ChannelWorkspaceSummary>, ChannelToolError> {
    Ok(vec![ChannelWorkspaceSummary {
      provider: "slack".to_owned(),
      connector_id: "slack-default".to_owned(),
      connector_name: Some("Slack".to_owned()),
      workspace_id: "workspace-1".to_owned(),
      workspace_name: Some("Example Workspace".to_owned()),
      display_name: "Example Workspace (Slack)".to_owned(),
    }])
  }

  async fn get_connector_status(
    &self,
    request: ChannelWorkspaceRequest,
  ) -> Result<ChannelConnectorStatus, ChannelToolError> {
    Ok(ChannelConnectorStatus {
      connector_id: request.connector_id,
      workspace_id: request.workspace_id,
      connected: true,
      status: "ok".to_owned(),
      detail: None,
    })
  }
}

#[async_trait::async_trait]
impl ChannelThreadReplyProvider for FakeAddressProvider {
  async fn reply_to_thread(
    &self,
    request: ChannelThreadReplyRequest,
  ) -> Result<ChannelThreadReplyReceipt, ChannelToolError> {
    self
      .reply_requests
      .lock()
      .expect("reply requests")
      .push(request.clone());
    Ok(ChannelThreadReplyReceipt {
      connector_id: request.connector_id,
      workspace_id: request.workspace_id,
      channel_id: request.channel_id,
      thread_id: request.thread_id,
      request_dedupe_key: request.request_dedupe_key,
      message_id: "message-1".to_owned(),
      send_as: request.send_as,
    })
  }
}

async fn dispatch(
  dispatcher: &JsonRpcDispatcher<'_>,
  id: u64,
  method: &str,
  params: Value,
) -> Value {
  dispatcher
    .handle(JsonRpcRequest {
      jsonrpc: "2.0".to_owned(),
      id: Some(json!(id)),
      method: method.to_owned(),
      params: Some(params),
    })
    .await
    .expect("request response")
}

async fn notify(dispatcher: &JsonRpcDispatcher<'_>, method: &str, params: Value) -> Option<Value> {
  dispatcher
    .handle(JsonRpcRequest {
      jsonrpc: "2.0".to_owned(),
      id: None,
      method: method.to_owned(),
      params: Some(params),
    })
    .await
}

#[tokio::test]
async fn test_initialize_and_tools_list_return_channel_tools() {
  let state = store().await;
  let provider = FakeContextProvider::default();
  let tools = ChannelToolDispatcher::new_with_now(&state.store, &provider, 100);
  let dispatcher = JsonRpcDispatcher::new(&tools);

  let initialized = dispatch(&dispatcher, 1, "initialize", json!({})).await;
  assert_eq!(initialized["jsonrpc"], "2.0");
  assert_eq!(initialized["id"], 1);
  assert_eq!(initialized["result"]["protocolVersion"], "2024-11-05");
  assert_eq!(initialized["result"]["serverInfo"]["name"], "codeoff-mcp");

  let listed = dispatch(&dispatcher, 2, "tools/list", json!({})).await;
  let names = listed["result"]["tools"]
    .as_array()
    .expect("tools")
    .iter()
    .map(|tool| tool["name"].as_str().expect("tool name"))
    .collect::<Vec<_>>();
  assert_eq!(
    names,
    [
      "channel.reply_to_event",
      "channel.send_message",
      "channel.get_thread_context",
      "channel.get_recent_messages",
      "channel.get_current_event",
      "channel.get_current_conversation",
      "channel.get_context_pack",
      "channel.get_delivery_status",
      "channel.get_message",
      "channel.get_resource_info",
      "channel.read_resource_text",
      "channel.download_resource",
      "channel.search_users",
      "channel.get_user",
      "channel.resolve_user",
      "channel.search_channels",
      "channel.get_channel",
      "channel.resolve_channel",
      "channel.list_senders",
      "channel.list_workspaces",
      "channel.get_connector_status",
      "channel.reply_to_thread",
    ]
  );
  let tools = listed["result"]["tools"].as_array().expect("tools");
  let reply_tool = tools
    .iter()
    .find(|tool| tool["name"] == "channel.reply_to_event")
    .expect("reply tool");
  assert_eq!(
    reply_tool["inputSchema"]["required"],
    json!([
      "connector_id",
      "workspace_id",
      "event_dedupe_key",
      "request_dedupe_key",
      "text"
    ])
  );
  assert_eq!(
    reply_tool["inputSchema"]["properties"]["event_dedupe_key"]["type"],
    "string"
  );
  let send_tool = tools
    .iter()
    .find(|tool| tool["name"] == "channel.send_message")
    .expect("send tool");
  assert_eq!(
    send_tool["inputSchema"]["required"],
    json!([
      "connector_id",
      "workspace_id",
      "request_dedupe_key",
      "target",
      "text"
    ])
  );
  assert_eq!(
    send_tool["inputSchema"]["properties"]["target"]["oneOf"][0]["required"],
    json!(["Channel"])
  );
  assert_eq!(
    send_tool["inputSchema"]["properties"]["send_as"]["type"],
    json!(["string", "null"])
  );
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn test_tools_call_provider_neutral_address_tools_use_fake_providers() {
  let state = store().await;
  let context_provider = FakeContextProvider::default();
  let address_provider = FakeAddressProvider::default();
  let tools = ChannelToolDispatcher::new_with_address_providers_and_now(
    &state.store,
    &context_provider,
    &address_provider,
    &address_provider,
    &address_provider,
    &address_provider,
    &address_provider,
    100,
  );
  let dispatcher = JsonRpcDispatcher::new(&tools);

  let users = dispatch(
    &dispatcher,
    1,
    "tools/call",
    json!({
      "name": "channel.search_users",
      "arguments": {
        "connector_id": "connector-1",
        "workspace_id": "workspace-1",
        "query": "alex",
        "limit": 5
      }
    }),
  )
  .await;
  let resolved = dispatch(
    &dispatcher,
    2,
    "tools/call",
    json!({
      "name": "channel.resolve_user",
      "arguments": {
        "connector_id": "connector-1",
        "workspace_id": "workspace-1",
        "query": "alex"
      }
    }),
  )
  .await;
  let reply = dispatch(
    &dispatcher,
    3,
    "tools/call",
    json!({
      "name": "channel.reply_to_thread",
      "arguments": {
        "connector_id": "connector-1",
        "workspace_id": "workspace-1",
        "channel_id": "channel-1",
        "thread_id": "thread-1",
        "request_dedupe_key": "reply-1",
        "text": "hello",
        "send_as": "sender:triage"
      }
    }),
  )
  .await;
  let workspaces = dispatch(
    &dispatcher,
    4,
    "tools/call",
    json!({
      "name": "channel.list_workspaces",
      "arguments": {}
    }),
  )
  .await;

  assert_eq!(users["result"]["isError"], false);
  assert_eq!(
    users["result"]["structuredContent"]["users"][0]["user_id"],
    "user-1"
  );
  assert_eq!(resolved["result"]["structuredContent"]["user"], Value::Null);
  assert_eq!(
    resolved["result"]["structuredContent"]["candidates"]
      .as_array()
      .expect("candidates")
      .len(),
    2
  );
  assert_eq!(
    reply["result"]["structuredContent"]["send_as"],
    "sender:triage"
  );
  assert_eq!(
    workspaces["result"]["structuredContent"]["workspaces"][0]["display_name"],
    "Example Workspace (Slack)"
  );
  assert_eq!(
    workspaces["result"]["structuredContent"]["workspaces"][0]["connector_id"],
    "slack-default"
  );
  assert_eq!(
    address_provider
      .reply_requests
      .lock()
      .expect("reply requests")[0]
      .send_as
      .as_deref(),
    Some("sender:triage")
  );
}

#[tokio::test]
async fn test_tools_call_resource_tools_use_resource_provider() {
  let state = store().await;
  let context_provider = FakeContextProvider::default();
  let resource_provider = FakeResourceProvider::default();
  let tools = ChannelToolDispatcher::new_with_resource_provider_and_now(
    &state.store,
    &context_provider,
    &resource_provider,
    100,
  );
  let dispatcher = JsonRpcDispatcher::new(&tools);

  let message = dispatch(
    &dispatcher,
    1,
    "tools/call",
    json!({
      "name": "channel.get_message",
      "arguments": {
        "connector_id": "slack-default",
        "workspace_id": "workspace-1",
        "channel_id": "C1",
        "thread_id": "100.0",
        "message_ts": "100.1"
      }
    }),
  )
  .await;
  let info = dispatch(
    &dispatcher,
    2,
    "tools/call",
    json!({
      "name": "channel.get_resource_info",
      "arguments": {
        "connector_id": "slack-default",
        "workspace_id": "workspace-1",
        "resource_id": "F1"
      }
    }),
  )
  .await;
  let text = dispatch(
    &dispatcher,
    3,
    "tools/call",
    json!({
      "name": "channel.read_resource_text",
      "arguments": {
        "connector_id": "slack-default",
        "workspace_id": "workspace-1",
        "resource_id": "F1"
      }
    }),
  )
  .await;
  let download = dispatch(
    &dispatcher,
    4,
    "tools/call",
    json!({
      "name": "channel.download_resource",
      "arguments": {
        "connector_id": "slack-default",
        "workspace_id": "workspace-1",
        "resource_id": "F1"
      }
    }),
  )
  .await;

  assert_eq!(message["result"]["isError"], false);
  assert_eq!(
    message["result"]["structuredContent"]["message_ts"],
    "100.1"
  );
  assert_eq!(info["result"]["structuredContent"]["resource_id"], "F1");
  assert_eq!(text["result"]["structuredContent"]["text"], "hello");
  assert_eq!(
    download["result"]["structuredContent"]["artifact_uri"],
    "artifact://slack/workspace-1/F1/notes.txt"
  );
  assert_eq!(
    resource_provider
      .message_requests
      .lock()
      .expect("message requests")[0]
      .thread_id
      .as_deref(),
    Some("100.0")
  );
  assert_eq!(
    resource_provider
      .download_requests
      .lock()
      .expect("download requests")[0]
      .resource_id,
    "F1"
  );
}

#[tokio::test]
async fn test_tools_call_resource_tool_without_provider_returns_error() {
  let state = store().await;
  let provider = FakeContextProvider::default();
  let tools = ChannelToolDispatcher::new_with_now(&state.store, &provider, 100);
  let dispatcher = JsonRpcDispatcher::new(&tools);

  let response = dispatch(
    &dispatcher,
    1,
    "tools/call",
    json!({
      "name": "channel.get_resource_info",
      "arguments": {
        "connector_id": "slack-default",
        "workspace_id": "workspace-1",
        "resource_id": "F1"
      }
    }),
  )
  .await;

  assert_eq!(response["result"]["isError"], true);
  assert_eq!(
    response["result"]["structuredContent"]["kind"],
    "resource_provider"
  );
}

#[tokio::test]
async fn test_initialized_notification_returns_no_response() {
  let state = store().await;
  let provider = FakeContextProvider::default();
  let tools = ChannelToolDispatcher::new_with_now(&state.store, &provider, 100);
  let dispatcher = JsonRpcDispatcher::new(&tools);

  let response = notify(&dispatcher, "notifications/initialized", json!({})).await;

  assert!(response.is_none());
}

#[tokio::test]
async fn test_tools_call_reply_to_event_and_get_delivery_status_use_state_store() {
  let state = store().await;
  persist_source(
    &state.store,
    SlackSourceEvent {
      workspace_id: "workspace-1".to_owned(),
      event_kind: "app_mention".to_owned(),
      dedupe_key: "event-dedupe-1".to_owned(),
      envelope_id: Some("envelope-1".to_owned()),
      event_id: Some("event-1".to_owned()),
      channel_id: Some("C1".to_owned()),
      thread_ts: Some("100.0".to_owned()),
      message_ts: Some("100.0".to_owned()),
      user_id: Some("U1".to_owned()),
      raw_payload_json: r#"{"secret":"do-not-return"}"#.to_owned(),
    },
  )
  .await;

  let provider = FakeContextProvider::default();
  let tools = ChannelToolDispatcher::new_with_now(&state.store, &provider, 100);
  let dispatcher = JsonRpcDispatcher::new(&tools);
  let queued = dispatch(
    &dispatcher,
    1,
    "tools/call",
    json!({
      "name": "channel.reply_to_event",
      "arguments": {
        "connector_id": "slack-default",
        "workspace_id": "workspace-1",
        "event_dedupe_key": "event-dedupe-1",
        "request_dedupe_key": "reply-1",
        "text": "hello from MCP"
      }
    }),
  )
  .await;

  assert_eq!(queued["result"]["isError"], false);
  assert_eq!(queued["result"]["structuredContent"]["queued"], true);
  assert_eq!(
    queued["result"]["structuredContent"]["request_dedupe_key"],
    "reply-1"
  );
  assert_eq!(queued["result"]["content"][0]["type"], "text");
  assert!(!queued.to_string().contains("do-not-return"));

  let status = dispatch(
    &dispatcher,
    2,
    "tools/call",
    json!({
      "name": "channel.get_delivery_status",
      "arguments": {
        "workspace_id": "workspace-1",
        "request_dedupe_key": "reply-1"
      }
    }),
  )
  .await;

  assert_eq!(
    status["result"]["structuredContent"]["delivery"]["status"],
    "pending"
  );
  assert_eq!(
    status["result"]["structuredContent"]["delivery"]["channel_id"],
    "C1"
  );
  assert_eq!(
    status["result"]["structuredContent"]["delivery"]["thread_ts"],
    "100.0"
  );
  assert_eq!(
    get_delivery_status(
      &state.store,
      GetDeliveryStatusRequest {
        workspace_id: "workspace-1".to_owned(),
        request_dedupe_key: "reply-1".to_owned(),
        now_unix_seconds: 100,
      },
    )
    .await
    .expect("status")
    .expect("delivery")
    .status,
    SlackDeliveryStatusKind::Pending
  );
}

#[tokio::test]
async fn test_tools_call_current_context_reads_persisted_source_references() {
  let state = store().await;
  persist_source(
    &state.store,
    SlackSourceEvent {
      workspace_id: "workspace-1".to_owned(),
      event_kind: "app_mention".to_owned(),
      dedupe_key: "event-dedupe-1".to_owned(),
      envelope_id: Some("envelope-1".to_owned()),
      event_id: Some("event-1".to_owned()),
      channel_id: Some("C1".to_owned()),
      thread_ts: Some("100.0".to_owned()),
      message_ts: Some("100.1".to_owned()),
      user_id: Some("U1".to_owned()),
      raw_payload_json: "{}".to_owned(),
    },
  )
  .await;

  let provider = FakeContextProvider::default();
  let tools = ChannelToolDispatcher::new_with_now(&state.store, &provider, 100);
  let dispatcher = JsonRpcDispatcher::new(&tools);

  let event = dispatch(
    &dispatcher,
    1,
    "tools/call",
    json!({
      "name": "channel.get_current_event",
      "arguments": {
        "connector_id": "slack-default",
        "workspace_id": "workspace-1",
        "event_dedupe_key": "event-dedupe-1"
      }
    }),
  )
  .await;
  assert_eq!(event["result"]["isError"], false);
  assert_eq!(
    event["result"]["structuredContent"]["source_reference"]["uri"],
    "slack://workspace-1/C1/100.1"
  );

  let conversation = dispatch(
    &dispatcher,
    2,
    "tools/call",
    json!({
      "name": "channel.get_current_conversation",
      "arguments": {
        "connector_id": "slack-default",
        "workspace_id": "workspace-1",
        "event_dedupe_key": "event-dedupe-1"
      }
    }),
  )
  .await;
  assert_eq!(
    conversation["result"]["structuredContent"]["conversation_kind"],
    "thread"
  );

  let pack = dispatch(
    &dispatcher,
    3,
    "tools/call",
    json!({
      "name": "channel.get_context_pack",
      "arguments": {
        "connector_id": "slack-default",
        "workspace_id": "workspace-1",
        "event_dedupe_key": "event-dedupe-1"
      }
    }),
  )
  .await;
  assert_eq!(
    pack["result"]["structuredContent"]["available_tools"][0]["name"],
    "channel.reply_to_event"
  );
}

#[tokio::test]
async fn test_tools_call_get_thread_context_uses_context_provider() {
  let state = store().await;
  let provider = FakeContextProvider::default();
  let tools = ChannelToolDispatcher::new_with_now(&state.store, &provider, 100);
  let dispatcher = JsonRpcDispatcher::new(&tools);

  let response = dispatch(
    &dispatcher,
    1,
    "tools/call",
    json!({
      "name": "channel.get_thread_context",
      "arguments": {
        "connector_id": "slack-default",
        "workspace_id": "workspace-1",
        "channel_id": "C1",
        "thread_id": "100.0",
        "limit": 10
      }
    }),
  )
  .await;

  assert_eq!(
    response["result"]["structuredContent"]["events"][0]["event_id"],
    "event-2"
  );
  assert_eq!(
    response["result"]["structuredContent"]["next_cursor"],
    "cursor-2"
  );
  assert_eq!(
    *provider.requests.lock().expect("requests"),
    vec![ChannelContextRequest {
      connector_id: "slack-default".to_owned(),
      workspace_id: "workspace-1".to_owned(),
      target: ChannelReplyTarget::Thread {
        channel_id: "C1".to_owned(),
        thread_id: "100.0".to_owned(),
      },
      limit: 10,
      cursor: None,
    }]
  );
}

#[tokio::test]
async fn test_tools_call_send_message_queues_direct_message() {
  let state = store().await;
  let provider = FakeContextProvider::default();
  let tools = ChannelToolDispatcher::new_with_now(&state.store, &provider, 100);
  let dispatcher = JsonRpcDispatcher::new(&tools);

  let response = dispatch(
    &dispatcher,
    1,
    "tools/call",
    json!({
      "name": "channel.send_message",
      "arguments": {
        "connector_id": "slack-default",
        "workspace_id": "workspace-1",
        "request_dedupe_key": "dm-1",
        "target": {
          "DirectMessage": {
            "user_account_id": "U1"
          }
        },
        "text": "hello from MCP"
      }
    }),
  )
  .await;

  assert_eq!(response["result"]["isError"], false);
  assert_eq!(
    response["result"]["structuredContent"]["request_dedupe_key"],
    "dm-1"
  );
  assert_eq!(response["result"]["structuredContent"]["queued"], true);
}

#[tokio::test]
async fn test_tools_call_send_message_accepts_user_send_as() {
  let state = store().await;
  let provider = FakeContextProvider::default();
  let tools = ChannelToolDispatcher::new_with_now(&state.store, &provider, 100);
  let dispatcher = JsonRpcDispatcher::new(&tools);

  let response = dispatch(
    &dispatcher,
    1,
    "tools/call",
    json!({
      "name": "channel.send_message",
      "arguments": {
        "connector_id": "slack-default",
        "workspace_id": "workspace-1",
        "request_dedupe_key": "user-send-1",
        "target": {
          "Channel": {
            "channel_id": "C1"
          }
        },
        "text": "hello from MCP",
        "send_as": "user:example"
      }
    }),
  )
  .await;

  assert_eq!(response["result"]["isError"], false);
  let status = get_delivery_status(
    &state.store,
    GetDeliveryStatusRequest {
      workspace_id: "workspace-1".to_owned(),
      request_dedupe_key: "user-send-1".to_owned(),
      now_unix_seconds: 100,
    },
  )
  .await
  .expect("status")
  .expect("delivery");
  assert_eq!(status.sender_kind, "user");
  assert_eq!(status.sender_key.as_deref(), Some("example"));
}

#[tokio::test]
async fn test_tools_call_get_recent_messages_uses_context_provider() {
  let state = store().await;
  let provider = FakeContextProvider::default();
  let tools = ChannelToolDispatcher::new_with_now(&state.store, &provider, 100);
  let dispatcher = JsonRpcDispatcher::new(&tools);

  let response = dispatch(
    &dispatcher,
    1,
    "tools/call",
    json!({
      "name": "channel.get_recent_messages",
      "arguments": {
        "connector_id": "slack-default",
        "workspace_id": "workspace-1",
        "channel_id": "C1",
        "limit": 5,
        "cursor": "page-2"
      }
    }),
  )
  .await;

  assert_eq!(
    response["result"]["structuredContent"]["events"][0]["event_id"],
    "event-2"
  );
  assert_eq!(
    *provider.requests.lock().expect("requests"),
    vec![ChannelContextRequest {
      connector_id: "slack-default".to_owned(),
      workspace_id: "workspace-1".to_owned(),
      target: ChannelReplyTarget::Channel {
        channel_id: "C1".to_owned(),
      },
      limit: 5,
      cursor: Some("page-2".to_owned()),
    }]
  );
}

#[tokio::test]
async fn test_tools_call_unknown_tool_returns_structured_json_rpc_error() {
  let state = store().await;
  let provider = FakeContextProvider::default();
  let tools = ChannelToolDispatcher::new_with_now(&state.store, &provider, 100);
  let dispatcher = JsonRpcDispatcher::new(&tools);

  let response = dispatch(
    &dispatcher,
    1,
    "tools/call",
    json!({
      "name": "channel.unknown",
      "arguments": {}
    }),
  )
  .await;

  assert_eq!(response["error"]["code"], -32601);
  assert_eq!(response["error"]["data"]["tool"], "channel.unknown");
}

#[tokio::test]
async fn test_channel_tool_failure_returns_mcp_tool_error_result() {
  let state = store().await;
  let provider = FakeContextProvider::default();
  let tools = ChannelToolDispatcher::new_with_now(&state.store, &provider, 100);
  let dispatcher = JsonRpcDispatcher::new(&tools);

  let response = dispatch(
    &dispatcher,
    1,
    "tools/call",
    json!({
      "name": "channel.reply_to_event",
      "arguments": {
        "connector_id": "slack-default",
        "workspace_id": "workspace-1",
        "event_dedupe_key": "missing-event",
        "request_dedupe_key": "reply-1",
        "text": "hello from MCP"
      }
    }),
  )
  .await;

  assert!(response.get("error").is_none());
  assert_eq!(response["result"]["isError"], true);
  assert_eq!(
    response["result"]["structuredContent"]["kind"],
    "missing_source_event"
  );
  assert_eq!(response["result"]["content"][0]["type"], "text");
  assert!(!response.to_string().contains("hello from MCP"));
  assert!(!response.to_string().contains("missing-event"));
}
