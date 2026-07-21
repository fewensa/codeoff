use std::sync::{Arc, Mutex};

use codeoff_channel_contract::{
  ChannelConnectorStatus, ChannelContextPage, ChannelContextRequest, ChannelCurrentContextRequest,
  ChannelEvent, ChannelEventKind, ChannelLookupRequest, ChannelMessageFetchRequest,
  ChannelMessageSnapshot, ChannelReplyTarget, ChannelResourceDownload,
  ChannelResourceDownloadRequest, ChannelResourceInfo, ChannelResourceInfoRequest,
  ChannelResourceText, ChannelResourceTextRequest, ChannelSearchRequest, ChannelSenderSummary,
  ChannelSummary, ChannelThreadReplyReceipt, ChannelThreadReplyRequest, ChannelUserResolveRequest,
  ChannelUserResolveResult, ChannelUserSearchRequest, ChannelUserSummary, ChannelWorkspaceRequest,
  ChannelWorkspaceSummary,
};
use codeoff_runtime::channel_tools::{
  CHANNEL_DYNAMIC_TOOL_NAMES, ChannelChannelProvider, ChannelContextProvider,
  ChannelContextProviderError, ChannelSenderProvider, ChannelStatusProvider,
  ChannelThreadReplyProvider, ChannelToolError, ChannelUserProvider, GetDeliveryStatusRequest,
  GetRecentMessagesRequest, GetThreadContextRequest, ReplyToEventRequest, SendMessageRequest,
  SlackContextBootstrapRequest, bootstrap_slack_context, get_channel, get_connector_status,
  get_context_pack, get_current_conversation, get_current_event, get_delivery_status,
  get_recent_messages, get_thread_context, get_user, list_senders, list_workspaces, reply_to_event,
  reply_to_event_with_processing_streams, reply_to_thread, resolve_channel, resolve_user,
  search_channels, search_users, send_message,
};
use codeoff_runtime::channel_tools::{ChannelResourceProvider, ChannelResourceProviderError};
use codeoff_runtime::{
  ProcessingStreamFinishOutcome, ProcessingStreamFinishRequest, ProcessingStreamManager,
  ProcessingStreamStartRequest,
};
use codeoff_state::{
  SlackDeliveryOperationClaim, SlackDeliveryReceipt, SlackDeliverySender, SlackDeliveryStatusKind,
  SlackProcessingIndicatorStatusKind, SlackSourceEvent, StateError, StateStore,
};
use serde_json::Value;
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
  persist_source_with_kind(store, source, ChannelEventKind::MentionReceived).await;
}

async fn persist_source_with_kind(
  store: &StateStore,
  source: SlackSourceEvent,
  kind: ChannelEventKind,
) {
  let mut event = ChannelEvent::new(
    "slack",
    "slack-default",
    &source.workspace_id,
    source
      .event_id
      .clone()
      .unwrap_or_else(|| "event-1".to_owned()),
    &source.dedupe_key,
    kind,
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
  error: Mutex<Option<ChannelContextProviderError>>,
  page: Mutex<Option<ChannelContextPage>>,
}

#[derive(Default)]
struct FakeResourceProvider {
  message_requests: Mutex<Vec<ChannelMessageFetchRequest>>,
  info_requests: Mutex<Vec<ChannelResourceInfoRequest>>,
  text_requests: Mutex<Vec<ChannelResourceTextRequest>>,
  download_requests: Mutex<Vec<ChannelResourceDownloadRequest>>,
  error: Mutex<Option<ChannelResourceProviderError>>,
}

struct FakeProcessingStreamManager {
  finish_existing_stream: bool,
  starts: Mutex<Vec<ProcessingStreamStartRequest>>,
  finishes: Mutex<Vec<ProcessingStreamFinishRequest>>,
}

#[derive(Default)]
#[allow(clippy::struct_field_names)]
struct FakeAddressProvider {
  user_search_requests: Mutex<Vec<ChannelUserSearchRequest>>,
  user_lookup_requests: Mutex<Vec<ChannelLookupRequest>>,
  user_resolve_requests: Mutex<Vec<ChannelUserResolveRequest>>,
  channel_search_requests: Mutex<Vec<ChannelSearchRequest>>,
  channel_lookup_requests: Mutex<Vec<ChannelLookupRequest>>,
  channel_resolve_requests: Mutex<Vec<ChannelSearchRequest>>,
  sender_requests: Mutex<Vec<ChannelWorkspaceRequest>>,
  status_requests: Mutex<Vec<ChannelWorkspaceRequest>>,
  reply_requests: Mutex<Vec<ChannelThreadReplyRequest>>,
}

impl FakeProcessingStreamManager {
  fn finishing_existing_stream() -> Self {
    Self {
      finish_existing_stream: true,
      starts: Mutex::new(Vec::new()),
      finishes: Mutex::new(Vec::new()),
    }
  }
}

#[async_trait::async_trait]
impl ProcessingStreamManager for FakeProcessingStreamManager {
  async fn start_processing_stream(
    &self,
    request: ProcessingStreamStartRequest,
  ) -> Result<(), StateError> {
    self.starts.lock().expect("starts").push(request);
    Ok(())
  }

  async fn finish_processing_stream(
    &self,
    request: ProcessingStreamFinishRequest,
  ) -> Result<ProcessingStreamFinishOutcome, StateError> {
    self
      .finishes
      .lock()
      .expect("finishes")
      .push(request.clone());
    Ok(ProcessingStreamFinishOutcome {
      request_dedupe_key: request.request_dedupe_key,
      queued: true,
      completed_existing_stream: self.finish_existing_stream,
    })
  }
}

#[async_trait::async_trait]
impl ChannelContextProvider for FakeContextProvider {
  async fn fetch_context(
    &self,
    request: ChannelContextRequest,
  ) -> Result<ChannelContextPage, ChannelContextProviderError> {
    self.requests.lock().expect("requests").push(request);
    if let Some(error) = self.error.lock().expect("error").clone() {
      return Err(error);
    }
    Ok(
      self
        .page
        .lock()
        .expect("page")
        .clone()
        .unwrap_or(ChannelContextPage {
          events: Vec::new(),
          next_cursor: None,
        }),
    )
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
    if let Some(error) = self.error.lock().expect("error").clone() {
      return Err(error);
    }
    Ok(ChannelMessageSnapshot {
      connector_id: request.connector_id,
      workspace_id: request.workspace_id,
      channel_id: request.channel_id,
      thread_id: request.thread_id,
      message_ts: request.message_ts,
      text: Some("message body".to_owned()),
      resources: vec![ChannelResourceInfo {
        connector_id: "slack-default".to_owned(),
        workspace_id: "workspace-1".to_owned(),
        resource_id: "file-1".to_owned(),
        name: Some("notes.txt".to_owned()),
        media_type: Some("text/plain".to_owned()),
        size_bytes: Some(12),
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
    if let Some(error) = self.error.lock().expect("error").clone() {
      return Err(error);
    }
    Ok(ChannelResourceInfo {
      connector_id: request.connector_id,
      workspace_id: request.workspace_id,
      resource_id: request.resource_id,
      name: Some("notes.txt".to_owned()),
      media_type: Some("text/plain".to_owned()),
      size_bytes: Some(12),
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
    if let Some(error) = self.error.lock().expect("error").clone() {
      return Err(error);
    }
    Ok(ChannelResourceText {
      connector_id: request.connector_id,
      workspace_id: request.workspace_id,
      resource_id: request.resource_id,
      text: Some("resource text".to_owned()),
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
    if let Some(error) = self.error.lock().expect("error").clone() {
      return Err(error);
    }
    Ok(ChannelResourceDownload {
      connector_id: request.connector_id,
      workspace_id: request.workspace_id,
      resource_id: request.resource_id,
      artifact_uri: "artifact://channel/file-1".to_owned(),
      local_path: Some("/tmp/codeoff/file-1".to_owned()),
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
      email: Some("alex@example.test".to_owned()),
    }])
  }

  async fn get_user(
    &self,
    request: ChannelLookupRequest,
  ) -> Result<Option<ChannelUserSummary>, ChannelToolError> {
    self
      .user_lookup_requests
      .lock()
      .expect("user lookup requests")
      .push(request.clone());
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
    self
      .channel_search_requests
      .lock()
      .expect("channel search requests")
      .push(request.clone());
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
    self
      .channel_lookup_requests
      .lock()
      .expect("channel lookup requests")
      .push(request.clone());
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
    self
      .channel_resolve_requests
      .lock()
      .expect("channel resolve requests")
      .push(request.clone());
    Ok(vec![
      ChannelSummary {
        connector_id: request.connector_id.clone(),
        workspace_id: request.workspace_id.clone(),
        channel_id: "channel-1".to_owned(),
        name: Some("triage".to_owned()),
        is_direct_message: false,
      },
      ChannelSummary {
        connector_id: request.connector_id,
        workspace_id: request.workspace_id,
        channel_id: "channel-2".to_owned(),
        name: Some("triage-ops".to_owned()),
        is_direct_message: false,
      },
    ])
  }
}

#[async_trait::async_trait]
impl ChannelSenderProvider for FakeAddressProvider {
  async fn list_senders(
    &self,
    request: ChannelWorkspaceRequest,
  ) -> Result<Vec<ChannelSenderSummary>, ChannelToolError> {
    self
      .sender_requests
      .lock()
      .expect("sender requests")
      .push(request.clone());
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
    self
      .status_requests
      .lock()
      .expect("status requests")
      .push(request.clone());
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

#[tokio::test]
async fn provider_neutral_user_tools_delegate_to_user_provider() {
  let provider = FakeAddressProvider::default();

  let users = search_users(
    &provider,
    ChannelUserSearchRequest::new("connector-1", "workspace-1", "alex", 5).expect("request"),
  )
  .await
  .expect("users");
  let user = get_user(
    &provider,
    ChannelLookupRequest::new("connector-1", "workspace-1", "user-1").expect("request"),
  )
  .await
  .expect("user")
  .expect("found user");
  let resolved = resolve_user(
    &provider,
    ChannelUserResolveRequest::new("connector-1", "workspace-1", "alex").expect("request"),
  )
  .await
  .expect("resolved");

  assert_eq!(users[0].user_id, "user-1");
  assert_eq!(user.user_id, "user-1");
  assert!(resolved.user.is_none());
  assert_eq!(resolved.candidates.len(), 2);
  assert_eq!(
    provider
      .user_resolve_requests
      .lock()
      .expect("user resolve requests")[0]
      .query,
    "alex"
  );
}

#[tokio::test]
async fn provider_neutral_channel_sender_status_and_reply_tools_delegate_to_providers() {
  let provider = FakeAddressProvider::default();

  let channels = search_channels(
    &provider,
    ChannelSearchRequest::new("connector-1", "workspace-1", "triage", 5).expect("request"),
  )
  .await
  .expect("channels");
  let channel = get_channel(
    &provider,
    ChannelLookupRequest::new("connector-1", "workspace-1", "channel-1").expect("request"),
  )
  .await
  .expect("channel")
  .expect("found channel");
  let resolved = resolve_channel(
    &provider,
    ChannelSearchRequest::new("connector-1", "workspace-1", "triage", 5).expect("request"),
  )
  .await
  .expect("resolved");
  let senders = list_senders(
    &provider,
    ChannelWorkspaceRequest::new("connector-1", "workspace-1").expect("request"),
  )
  .await
  .expect("senders");
  let workspaces = list_workspaces(&provider).await.expect("workspaces");
  let status = get_connector_status(
    &provider,
    ChannelWorkspaceRequest::new("connector-1", "workspace-1").expect("request"),
  )
  .await
  .expect("status");
  let receipt = reply_to_thread(
    &provider,
    ChannelThreadReplyRequest::new(
      "connector-1",
      "workspace-1",
      "channel-1",
      "thread-1",
      "reply-1",
      "hello",
      Some("sender:triage".to_owned()),
    )
    .expect("request"),
  )
  .await
  .expect("reply");

  assert_eq!(channels[0].channel_id, "channel-1");
  assert_eq!(channel.channel_id, "channel-1");
  assert!(resolved.channel.is_none());
  assert_eq!(resolved.candidates.len(), 2);
  assert_eq!(senders[0].sender_id, "bot");
  assert_eq!(workspaces[0].connector_id, "slack-default");
  assert_eq!(workspaces[0].display_name, "Example Workspace (Slack)");
  assert!(status.connected);
  assert_eq!(receipt.send_as.as_deref(), Some("sender:triage"));
  assert_eq!(
    provider.reply_requests.lock().expect("reply requests")[0]
      .send_as
      .as_deref(),
    Some("sender:triage")
  );
}

#[tokio::test]
async fn get_thread_context_delegates_with_thread_target_and_requested_limit() {
  let provider = FakeContextProvider::default();

  let page = get_thread_context(
    &provider,
    GetThreadContextRequest {
      connector_id: "slack-default".to_owned(),
      workspace_id: "workspace-1".to_owned(),
      channel_id: "C1".to_owned(),
      thread_id: "100.0".to_owned(),
      limit: 12,
      cursor: None,
    },
  )
  .await
  .expect("context");

  assert_eq!(
    page,
    ChannelContextPage {
      events: Vec::new(),
      next_cursor: None,
    }
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
      limit: 12,
      cursor: None,
    }]
  );
}

#[tokio::test]
async fn get_recent_messages_delegates_with_channel_target_and_requested_limit() {
  let provider = FakeContextProvider::default();

  get_recent_messages(
    &provider,
    GetRecentMessagesRequest {
      connector_id: "slack-default".to_owned(),
      workspace_id: "workspace-1".to_owned(),
      channel_id: "C1".to_owned(),
      limit: 8,
      cursor: None,
    },
  )
  .await
  .expect("context");

  assert_eq!(
    *provider.requests.lock().expect("requests"),
    vec![ChannelContextRequest {
      connector_id: "slack-default".to_owned(),
      workspace_id: "workspace-1".to_owned(),
      target: ChannelReplyTarget::Channel {
        channel_id: "C1".to_owned(),
      },
      limit: 8,
      cursor: None,
    }]
  );
}

#[tokio::test]
async fn get_recent_messages_delegates_with_optional_cursor() {
  let provider = FakeContextProvider::default();

  get_recent_messages(
    &provider,
    GetRecentMessagesRequest {
      connector_id: "slack-default".to_owned(),
      workspace_id: "workspace-1".to_owned(),
      channel_id: "C1".to_owned(),
      limit: 8,
      cursor: Some("next-page".to_owned()),
    },
  )
  .await
  .expect("context");

  assert_eq!(
    *provider.requests.lock().expect("requests"),
    vec![ChannelContextRequest {
      connector_id: "slack-default".to_owned(),
      workspace_id: "workspace-1".to_owned(),
      target: ChannelReplyTarget::Channel {
        channel_id: "C1".to_owned(),
      },
      limit: 8,
      cursor: Some("next-page".to_owned()),
    }]
  );
}

#[tokio::test]
async fn get_thread_context_rejects_invalid_identifiers_before_provider() {
  let provider = FakeContextProvider::default();

  let error = get_thread_context(
    &provider,
    GetThreadContextRequest {
      connector_id: "slack-default".to_owned(),
      workspace_id: "workspace-1".to_owned(),
      channel_id: String::new(),
      thread_id: "100.0".to_owned(),
      limit: 12,
      cursor: None,
    },
  )
  .await
  .expect_err("invalid request");

  assert!(matches!(error, ChannelToolError::InvalidRequest(_)));
  assert!(provider.requests.lock().expect("requests").is_empty());
}

#[tokio::test]
async fn get_recent_messages_surfaces_typed_provider_errors() {
  let provider = FakeContextProvider::default();
  *provider.error.lock().expect("error") = Some(ChannelContextProviderError::RateLimited {
    retry_after_seconds: Some(30),
  });

  let error = get_recent_messages(
    &provider,
    GetRecentMessagesRequest {
      connector_id: "slack-default".to_owned(),
      workspace_id: "workspace-1".to_owned(),
      channel_id: "C1".to_owned(),
      limit: 8,
      cursor: None,
    },
  )
  .await
  .expect_err("provider error");

  assert!(matches!(
    error,
    ChannelToolError::ContextProvider(ChannelContextProviderError::RateLimited {
      retry_after_seconds: Some(30)
    })
  ));
}

#[tokio::test]
async fn get_recent_messages_rejects_zero_limit_before_provider() {
  let provider = FakeContextProvider::default();

  let error = get_recent_messages(
    &provider,
    GetRecentMessagesRequest {
      connector_id: "slack-default".to_owned(),
      workspace_id: "workspace-1".to_owned(),
      channel_id: "C1".to_owned(),
      limit: 0,
      cursor: None,
    },
  )
  .await
  .expect_err("zero limit fails");

  assert!(matches!(error, ChannelToolError::InvalidRequest(_)));
  assert!(provider.requests.lock().expect("requests").is_empty());
}

#[tokio::test]
async fn channel_dynamic_tool_handler_lists_context_tools() {
  let state = store().await;
  let provider = Arc::new(FakeContextProvider::default());
  let handler =
    codeoff_runtime::channel_tools::ChannelDynamicToolHandler::new_with_context_provider_and_now(
      state.store,
      provider,
      100,
    );

  let names = handler
    .tool_specs()
    .into_iter()
    .map(|tool| tool["name"].as_str().expect("tool name").to_owned())
    .collect::<Vec<_>>();

  assert_eq!(
    names,
    CHANNEL_DYNAMIC_TOOL_NAMES
      .iter()
      .map(|name| (*name).to_owned())
      .collect::<Vec<_>>()
  );

  let specs = handler.tool_specs();
  for tool_name in ["channel_get_thread_context", "channel_get_recent_messages"] {
    let spec = specs
      .iter()
      .find(|tool| tool["name"] == tool_name)
      .expect("context tool spec");
    assert_eq!(
      spec["inputSchema"]["properties"]["cursor"]["type"],
      serde_json::json!(["string", "null"])
    );
    assert!(
      !spec["inputSchema"]["required"]
        .as_array()
        .expect("required fields")
        .iter()
        .any(|field| field == "cursor")
    );
  }
}

#[tokio::test]
async fn current_event_and_conversation_derive_from_persisted_source_references() {
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
  let request = ChannelCurrentContextRequest::new("slack-default", "workspace-1", "event-dedupe-1")
    .expect("request");

  let event = get_current_event(&state.store, request.clone())
    .await
    .expect("current event");
  let conversation = get_current_conversation(&state.store, request)
    .await
    .expect("current conversation");

  assert_eq!(event.source_provider, "slack");
  assert_eq!(event.connector_id, "slack-default");
  assert_eq!(event.workspace_id, "workspace-1");
  assert_eq!(event.event_dedupe_key, "event-dedupe-1");
  assert_eq!(event.channel_id.as_deref(), Some("C1"));
  assert_eq!(event.message_ts.as_deref(), Some("100.1"));
  assert_eq!(event.thread_ts.as_deref(), Some("100.0"));
  assert_eq!(event.thread_id.as_deref(), Some("100.0"));
  assert_eq!(event.user_id.as_deref(), Some("U1"));
  assert_eq!(
    event.reply_target,
    Some(ChannelReplyTarget::Thread {
      channel_id: "C1".to_owned(),
      thread_id: "100.0".to_owned(),
    })
  );
  assert_eq!(event.source_reference.uri, "slack://workspace-1/C1/100.1");
  assert_eq!(conversation.conversation_kind, "thread");
  assert_eq!(conversation.channel_id.as_deref(), Some("C1"));
  assert_eq!(conversation.thread_id.as_deref(), Some("100.0"));
  assert_eq!(conversation.user_id.as_deref(), Some("U1"));
}

#[tokio::test]
async fn context_pack_composes_current_context_and_tool_hints() {
  let state = store().await;
  persist_source(
    &state.store,
    SlackSourceEvent {
      workspace_id: "workspace-1".to_owned(),
      event_kind: "message".to_owned(),
      dedupe_key: "dm-dedupe-1".to_owned(),
      envelope_id: Some("envelope-1".to_owned()),
      event_id: Some("event-1".to_owned()),
      channel_id: Some("D1".to_owned()),
      thread_ts: None,
      message_ts: Some("200.0".to_owned()),
      user_id: Some("U1".to_owned()),
      raw_payload_json: "{}".to_owned(),
    },
  )
  .await;
  let request = ChannelCurrentContextRequest::new("slack-default", "workspace-1", "dm-dedupe-1")
    .expect("request");

  let pack = get_context_pack(&state.store, request)
    .await
    .expect("context pack");

  assert_eq!(pack.current_event.channel_id.as_deref(), Some("D1"));
  assert_eq!(pack.current_conversation.conversation_kind, "dm");
  assert_eq!(pack.current_conversation.thread_id, None);
  assert_eq!(pack.available_tools.len(), 3);
  assert_eq!(pack.available_tools[0].name, "channel.reply_to_event");
  assert_eq!(pack.available_tools[1].name, "channel.get_thread_context");
  assert_eq!(pack.available_tools[2].name, "channel.get_recent_messages");
}

#[tokio::test]
async fn channel_dynamic_tool_handler_current_context_tools_use_persisted_source_references() {
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
  let handler =
    codeoff_runtime::channel_tools::ChannelDynamicToolHandler::new_with_now(state.store, 100);

  let event = handler
    .handle_tool_call_async(
      "channel_get_current_event",
      serde_json::json!({
        "connector_id": "slack-default",
        "workspace_id": "workspace-1",
        "event_dedupe_key": "event-dedupe-1"
      }),
    )
    .await;
  let conversation = handler
    .handle_tool_call_async(
      "channel_get_current_conversation",
      serde_json::json!({
        "connector_id": "slack-default",
        "workspace_id": "workspace-1",
        "event_dedupe_key": "event-dedupe-1"
      }),
    )
    .await;
  let pack = handler
    .handle_tool_call_async(
      "channel_get_context_pack",
      serde_json::json!({
        "connector_id": "slack-default",
        "workspace_id": "workspace-1",
        "event_dedupe_key": "event-dedupe-1"
      }),
    )
    .await;

  assert_eq!(event["success"], true);
  let event_content: Value = serde_json::from_str(
    event["contentItems"][0]["text"]
      .as_str()
      .expect("event text"),
  )
  .expect("event json");
  assert_eq!(event_content["thread_id"], "100.0");
  assert_eq!(event_content["reply_target"]["Thread"]["channel_id"], "C1");
  let conversation_content: Value = serde_json::from_str(
    conversation["contentItems"][0]["text"]
      .as_str()
      .expect("conversation text"),
  )
  .expect("conversation json");
  assert_eq!(conversation_content["conversation_kind"], "thread");
  let pack_content: Value =
    serde_json::from_str(pack["contentItems"][0]["text"].as_str().expect("pack text"))
      .expect("pack json");
  assert_eq!(pack_content["current_event"]["message_ts"], "100.1");
  assert_eq!(
    pack_content["available_tools"][0]["name"],
    "channel.reply_to_event"
  );
}

#[tokio::test]
async fn channel_dynamic_tool_handler_address_tools_call_address_provider() {
  let state = store().await;
  let provider = Arc::new(FakeAddressProvider::default());
  let handler =
    codeoff_runtime::channel_tools::ChannelDynamicToolHandler::new_with_address_provider_and_now(
      state.store,
      provider.clone(),
      100,
    );

  let names = handler
    .tool_specs()
    .into_iter()
    .map(|tool| tool["name"].as_str().expect("tool name").to_owned())
    .collect::<Vec<_>>();

  assert!(names.contains(&"channel_search_users".to_owned()));
  assert!(names.contains(&"channel_reply_to_thread".to_owned()));

  let response = handler
    .handle_tool_call_async(
      "channel_search_users",
      serde_json::json!({
        "connector_id": "slack-default",
        "workspace_id": "workspace-1",
        "query": "alex",
        "limit": 10
      }),
    )
    .await;

  assert_eq!(response["success"], true, "{response}");
  assert!(
    response["contentItems"][0]["text"]
      .as_str()
      .expect("response text")
      .contains("\"user_id\":\"user-1\"")
  );
  assert_eq!(
    *provider
      .user_search_requests
      .lock()
      .expect("user search requests"),
    vec![ChannelUserSearchRequest {
      connector_id: "slack-default".to_owned(),
      workspace_id: "workspace-1".to_owned(),
      query: "alex".to_owned(),
      limit: 10,
    }]
  );

  let response = handler
    .handle_tool_call_async("channel_list_workspaces", serde_json::json!({}))
    .await;

  assert_eq!(response["success"], true, "{response}");
  assert!(
    response["contentItems"][0]["text"]
      .as_str()
      .expect("response text")
      .contains("\"display_name\":\"Example Workspace (Slack)\"")
  );
}

#[tokio::test]
async fn channel_dynamic_tool_handler_resource_specs_do_not_expose_private_urls() {
  let state = store().await;
  let handler =
    codeoff_runtime::channel_tools::ChannelDynamicToolHandler::new_with_resource_provider_and_now(
      state.store,
      Arc::new(FakeResourceProvider::default()),
      100,
    );

  let specs = handler.tool_specs();
  for tool_name in [
    "channel_get_message",
    "channel_get_resource_info",
    "channel_read_resource_text",
    "channel_download_resource",
  ] {
    let spec = specs
      .iter()
      .find(|tool| tool["name"] == tool_name)
      .expect("resource tool spec");
    let spec_text = spec.to_string();
    assert!(spec_text.contains("connector_id"), "{spec_text}");
    assert!(spec_text.contains("workspace_id"), "{spec_text}");
    assert!(!spec_text.contains("url_private"), "{spec_text}");
    assert!(!spec_text.contains("token"), "{spec_text}");
  }
}

#[tokio::test]
async fn channel_dynamic_tool_handler_get_message_calls_resource_provider() {
  let state = store().await;
  let provider = Arc::new(FakeResourceProvider::default());
  let handler =
    codeoff_runtime::channel_tools::ChannelDynamicToolHandler::new_with_resource_provider_and_now(
      state.store,
      provider.clone(),
      100,
    );

  let response = handler
    .handle_tool_call_async(
      "channel_get_message",
      serde_json::json!({
        "connector_id": "slack-default",
        "workspace_id": "workspace-1",
        "channel_id": "C1",
        "thread_id": "100.0",
        "message_ts": "100.0"
      }),
    )
    .await;

  assert_eq!(response["success"], true, "{response}");
  assert!(
    response["contentItems"][0]["text"]
      .as_str()
      .expect("response text")
      .contains("\"resources\"")
  );
  assert_eq!(
    *provider.message_requests.lock().expect("message requests"),
    vec![ChannelMessageFetchRequest {
      connector_id: "slack-default".to_owned(),
      workspace_id: "workspace-1".to_owned(),
      channel_id: "C1".to_owned(),
      thread_id: Some("100.0".to_owned()),
      message_ts: "100.0".to_owned(),
    }]
  );
}

#[tokio::test]
async fn channel_dynamic_tool_handler_resource_tools_call_resource_provider() {
  let state = store().await;
  let provider = Arc::new(FakeResourceProvider::default());
  let handler =
    codeoff_runtime::channel_tools::ChannelDynamicToolHandler::new_with_resource_provider_and_now(
      state.store,
      provider.clone(),
      100,
    );

  let info = handler
    .handle_tool_call_async(
      "channel_get_resource_info",
      serde_json::json!({
        "connector_id": "slack-default",
        "workspace_id": "workspace-1",
        "resource_id": "file-1"
      }),
    )
    .await;
  let text = handler
    .handle_tool_call_async(
      "channel_read_resource_text",
      serde_json::json!({
        "connector_id": "slack-default",
        "workspace_id": "workspace-1",
        "resource_id": "file-1"
      }),
    )
    .await;
  let download = handler
    .handle_tool_call_async(
      "channel_download_resource",
      serde_json::json!({
        "connector_id": "slack-default",
        "workspace_id": "workspace-1",
        "resource_id": "file-1"
      }),
    )
    .await;

  assert_eq!(info["success"], true, "{info}");
  assert_eq!(text["success"], true, "{text}");
  assert_eq!(download["success"], true, "{download}");
  assert_eq!(
    *provider.info_requests.lock().expect("info requests"),
    vec![ChannelResourceInfoRequest {
      connector_id: "slack-default".to_owned(),
      workspace_id: "workspace-1".to_owned(),
      resource_id: "file-1".to_owned(),
    }]
  );
  assert_eq!(
    *provider.text_requests.lock().expect("text requests"),
    vec![ChannelResourceTextRequest {
      connector_id: "slack-default".to_owned(),
      workspace_id: "workspace-1".to_owned(),
      resource_id: "file-1".to_owned(),
    }]
  );
  assert_eq!(
    *provider
      .download_requests
      .lock()
      .expect("download requests"),
    vec![ChannelResourceDownloadRequest {
      connector_id: "slack-default".to_owned(),
      workspace_id: "workspace-1".to_owned(),
      resource_id: "file-1".to_owned(),
    }]
  );
}

#[tokio::test]
async fn channel_dynamic_tool_handler_resource_tools_fail_without_provider() {
  let state = store().await;
  let handler =
    codeoff_runtime::channel_tools::ChannelDynamicToolHandler::new_with_now(state.store, 100);

  for (tool_name, arguments) in [
    (
      "channel_get_message",
      serde_json::json!({
        "connector_id": "slack-default",
        "workspace_id": "workspace-1",
        "channel_id": "C1",
        "message_ts": "100.0"
      }),
    ),
    (
      "channel_get_resource_info",
      serde_json::json!({
        "connector_id": "slack-default",
        "workspace_id": "workspace-1",
        "resource_id": "file-1"
      }),
    ),
    (
      "channel_read_resource_text",
      serde_json::json!({
        "connector_id": "slack-default",
        "workspace_id": "workspace-1",
        "resource_id": "file-1"
      }),
    ),
    (
      "channel_download_resource",
      serde_json::json!({
        "connector_id": "slack-default",
        "workspace_id": "workspace-1",
        "resource_id": "file-1"
      }),
    ),
  ] {
    let response = handler.handle_tool_call_async(tool_name, arguments).await;

    assert_eq!(response["success"], false, "{response}");
    assert_eq!(
      response["contentItems"][0]["text"],
      "channel resource provider is unavailable"
    );
  }
}

#[tokio::test]
async fn channel_dynamic_tool_handler_get_recent_messages_calls_context_provider() {
  let state = store().await;
  let provider = Arc::new(FakeContextProvider::default());
  let handler =
    codeoff_runtime::channel_tools::ChannelDynamicToolHandler::new_with_context_provider_and_now(
      state.store,
      provider.clone(),
      100,
    );

  let response = handler
    .handle_tool_call_async(
      "channel_get_recent_messages",
      serde_json::json!({
        "connector_id": "slack-default",
        "workspace_id": "workspace-1",
        "channel_id": "C1",
        "limit": 5,
        "cursor": "page-2"
      }),
    )
    .await;

  assert_eq!(response["success"], true, "{response}");
  assert!(
    response["contentItems"][0]["text"]
      .as_str()
      .expect("response text")
      .contains("\"events\":[]")
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
async fn channel_dynamic_tool_handler_get_thread_context_calls_context_provider() {
  let state = store().await;
  let provider = Arc::new(FakeContextProvider::default());
  let handler =
    codeoff_runtime::channel_tools::ChannelDynamicToolHandler::new_with_context_provider_and_now(
      state.store,
      provider.clone(),
      100,
    );

  let response = handler
    .handle_tool_call_async(
      "channel_get_thread_context",
      serde_json::json!({
        "connector_id": "slack-default",
        "workspace_id": "workspace-1",
        "channel_id": "C1",
        "thread_id": "100.0",
        "limit": 7,
        "cursor": "thread-page-2"
      }),
    )
    .await;

  assert_eq!(response["success"], true, "{response}");
  assert_eq!(
    *provider.requests.lock().expect("requests"),
    vec![ChannelContextRequest {
      connector_id: "slack-default".to_owned(),
      workspace_id: "workspace-1".to_owned(),
      target: ChannelReplyTarget::Thread {
        channel_id: "C1".to_owned(),
        thread_id: "100.0".to_owned(),
      },
      limit: 7,
      cursor: Some("thread-page-2".to_owned()),
    }]
  );
}

#[tokio::test]
async fn bootstrap_slack_context_fetches_dm_channel_history_as_json_context() {
  let provider = FakeContextProvider::default();
  let mut event = ChannelEvent::new(
    "slack",
    "slack-default",
    "workspace-1",
    "dm-event-1",
    "dm-dedupe-1",
    ChannelEventKind::DirectMessageReceived,
  )
  .expect("event");
  event = event.with_text(Some("那火星呢？"));
  *provider.page.lock().expect("page") = Some(ChannelContextPage {
    events: vec![
      ChannelEvent::new(
        "slack",
        "slack-default",
        "workspace-1",
        "200.0",
        "slack:workspace-1:D1:200.0",
        ChannelEventKind::DirectMessageReceived,
      )
      .expect("history event")
      .with_text(Some("月球上都有什么")),
    ],
    next_cursor: Some("older-dm-page".to_owned()),
  });

  let context = bootstrap_slack_context(
    &provider,
    SlackContextBootstrapRequest {
      event,
      channel_id: Some("D1".to_owned()),
      thread_id: Some("200.0".to_owned()),
      limit: 4,
    },
  )
  .await
  .expect("bootstrap context");

  assert_eq!(context["target_kind"], "direct_message");
  assert_eq!(context["channel_id"], "D1");
  assert_eq!(context["thread_id"], serde_json::Value::Null);
  assert_eq!(context["next_cursor"], "older-dm-page");
  assert_eq!(context["events"][0]["text"], "月球上都有什么");
  assert_eq!(
    *provider.requests.lock().expect("requests"),
    vec![ChannelContextRequest {
      connector_id: "slack-default".to_owned(),
      workspace_id: "workspace-1".to_owned(),
      target: ChannelReplyTarget::Channel {
        channel_id: "D1".to_owned(),
      },
      limit: 4,
      cursor: None,
    }]
  );
}

#[tokio::test]
async fn bootstrap_slack_context_fetches_thread_context_as_json_context() {
  let provider = FakeContextProvider::default();
  let event = ChannelEvent::new(
    "slack",
    "slack-default",
    "workspace-1",
    "thread-event-1",
    "thread-dedupe-1",
    ChannelEventKind::MentionReceived,
  )
  .expect("event");

  let context = bootstrap_slack_context(
    &provider,
    SlackContextBootstrapRequest {
      event,
      channel_id: Some("C1".to_owned()),
      thread_id: Some("99.0".to_owned()),
      limit: 3,
    },
  )
  .await
  .expect("bootstrap context");

  assert_eq!(context["target_kind"], "thread");
  assert_eq!(context["channel_id"], "C1");
  assert_eq!(context["thread_id"], "99.0");
  assert_eq!(
    *provider.requests.lock().expect("requests"),
    vec![ChannelContextRequest {
      connector_id: "slack-default".to_owned(),
      workspace_id: "workspace-1".to_owned(),
      target: ChannelReplyTarget::Thread {
        channel_id: "C1".to_owned(),
        thread_id: "99.0".to_owned(),
      },
      limit: 3,
      cursor: None,
    }]
  );
}

#[tokio::test]
async fn reply_to_event_queues_thread_reply_from_slack_source_refs() {
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
      thread_ts: Some("99.0".to_owned()),
      message_ts: Some("100.0".to_owned()),
      user_id: Some("U1".to_owned()),
      raw_payload_json: "{}".to_owned(),
    },
  )
  .await;

  let response = reply_to_event(
    &state.store,
    ReplyToEventRequest {
      connector_id: "slack-default".to_owned(),
      workspace_id: "workspace-1".to_owned(),
      event_dedupe_key: "event-dedupe-1".to_owned(),
      request_dedupe_key: "reply-1".to_owned(),
      text: "hello from Codeoff".to_owned(),
      send_as: None,
      now_unix_seconds: 100,
    },
  )
  .await
  .expect("reply queued");

  assert!(response.queued);
  assert_eq!(response.request_dedupe_key, "reply-1");
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
    .expect("status"),
    Some(codeoff_state::SlackDeliveryStatus {
      connector_id: "slack-default".to_owned(),
      workspace_id: "workspace-1".to_owned(),
      channel_id: "C1".to_owned(),
      thread_ts: Some("99.0".to_owned()),
      message_ts: None,
      request_dedupe_key: "reply-1".to_owned(),
      status: SlackDeliveryStatusKind::Pending,
      available_at: Some(100),
      attempt_count: Some(0),
      sender_kind: "bot".to_owned(),
      sender_key: None,
    })
  );
}

#[tokio::test]
async fn reply_to_event_queues_post_message_when_no_processing_stream_exists() {
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
      thread_ts: Some("99.0".to_owned()),
      message_ts: Some("100.0".to_owned()),
      user_id: Some("U1".to_owned()),
      raw_payload_json: "{}".to_owned(),
    },
  )
  .await;

  let response = reply_to_event(
    &state.store,
    ReplyToEventRequest {
      connector_id: "slack-default".to_owned(),
      workspace_id: "workspace-1".to_owned(),
      event_dedupe_key: "event-dedupe-1".to_owned(),
      request_dedupe_key: "reply-1".to_owned(),
      text: "hello from Codeoff".to_owned(),
      send_as: None,
      now_unix_seconds: 100,
    },
  )
  .await
  .expect("reply queued");

  assert!(response.queued);
  let claim = state
    .store
    .claim_slack_delivery_operation("workspace-1", "reply-1", 100)
    .await
    .expect("claim delivery operation");
  let SlackDeliveryOperationClaim::PostMessage(message) = claim else {
    panic!("expected post_message delivery");
  };
  assert_eq!(message.channel_id, "C1");
  assert_eq!(message.thread_ts.as_deref(), Some("99.0"));
  assert_eq!(message.text, "hello from Codeoff");
}

#[tokio::test]
async fn reply_to_event_finishes_existing_processing_stream_without_post_message() {
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
      thread_ts: Some("99.0".to_owned()),
      message_ts: Some("100.0".to_owned()),
      user_id: Some("U1".to_owned()),
      raw_payload_json: "{}".to_owned(),
    },
  )
  .await;
  let streams = FakeProcessingStreamManager::finishing_existing_stream();

  let response = reply_to_event_with_processing_streams(
    &state.store,
    &streams,
    ReplyToEventRequest {
      connector_id: "slack-default".to_owned(),
      workspace_id: "workspace-1".to_owned(),
      event_dedupe_key: "event-dedupe-1".to_owned(),
      request_dedupe_key: "reply-1".to_owned(),
      text: "hello from Codeoff".to_owned(),
      send_as: None,
      now_unix_seconds: 100,
    },
  )
  .await
  .expect("stream completion queued");

  assert!(response.queued);
  assert_eq!(response.request_dedupe_key, "reply-1");
  assert_eq!(
    *streams.finishes.lock().expect("finishes"),
    vec![ProcessingStreamFinishRequest {
      connector_id: "slack-default".to_owned(),
      workspace_id: "workspace-1".to_owned(),
      event_dedupe_key: "event-dedupe-1".to_owned(),
      request_dedupe_key: "reply-1".to_owned(),
      channel_id: "C1".to_owned(),
      thread_ts: Some("99.0".to_owned()),
      text: "hello from Codeoff".to_owned(),
      sender: SlackDeliverySender::Bot,
      now_unix_seconds: 100,
    }]
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
    .expect("status"),
    None
  );
}

#[tokio::test]
async fn reply_to_event_queues_stop_stream_from_existing_processing_indicator() {
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
      thread_ts: Some("99.0".to_owned()),
      message_ts: Some("100.0".to_owned()),
      user_id: Some("U1".to_owned()),
      raw_payload_json: "{}".to_owned(),
    },
  )
  .await;
  state
    .store
    .create_slack_processing_indicator(
      "workspace-1",
      "event-dedupe-1",
      "C1",
      Some("99.0"),
      "stream-ts-1",
    )
    .await
    .expect("processing indicator");

  let response = reply_to_event(
    &state.store,
    ReplyToEventRequest {
      connector_id: "slack-default".to_owned(),
      workspace_id: "workspace-1".to_owned(),
      event_dedupe_key: "event-dedupe-1".to_owned(),
      request_dedupe_key: "reply-1".to_owned(),
      text: "hello from Codeoff".to_owned(),
      send_as: None,
      now_unix_seconds: 100,
    },
  )
  .await
  .expect("stream completion queued");

  assert!(response.queued);
  assert_eq!(
    state
      .store
      .slack_processing_indicator("workspace-1", "event-dedupe-1")
      .await
      .expect("indicator")
      .expect("indicator exists")
      .status,
    SlackProcessingIndicatorStatusKind::Completed
  );
  let claim = state
    .store
    .claim_slack_delivery_operation("workspace-1", "reply-1", 100)
    .await
    .expect("claim delivery operation");
  let SlackDeliveryOperationClaim::StopStream(stop_stream) = claim else {
    panic!("expected stop_stream delivery");
  };
  assert_eq!(stop_stream.channel_id, "C1");
  assert_eq!(stop_stream.thread_ts.as_deref(), Some("99.0"));
  assert_eq!(stop_stream.message_ts, "stream-ts-1");
  assert_eq!(stop_stream.text, "hello from Codeoff");
  assert!(!stop_stream.text.contains("Thinking"));
}

#[tokio::test]
async fn reply_to_event_queues_direct_message_without_thread_ts() {
  let state = store().await;
  persist_source_with_kind(
    &state.store,
    SlackSourceEvent {
      workspace_id: "workspace-1".to_owned(),
      event_kind: "message".to_owned(),
      dedupe_key: "dm-dedupe-1".to_owned(),
      envelope_id: Some("dm-envelope-1".to_owned()),
      event_id: Some("dm-event-1".to_owned()),
      channel_id: Some("D1".to_owned()),
      thread_ts: Some("200.0".to_owned()),
      message_ts: Some("200.0".to_owned()),
      user_id: Some("U1".to_owned()),
      raw_payload_json: "{}".to_owned(),
    },
    ChannelEventKind::DirectMessageReceived,
  )
  .await;

  let response = reply_to_event(
    &state.store,
    ReplyToEventRequest {
      connector_id: "slack-default".to_owned(),
      workspace_id: "workspace-1".to_owned(),
      event_dedupe_key: "dm-dedupe-1".to_owned(),
      request_dedupe_key: "dm-reply-1".to_owned(),
      text: "hello in the main DM".to_owned(),
      send_as: None,
      now_unix_seconds: 100,
    },
  )
  .await
  .expect("reply queued");

  assert!(response.queued);
  assert_eq!(response.request_dedupe_key, "dm-reply-1");
  assert_eq!(
    get_delivery_status(
      &state.store,
      GetDeliveryStatusRequest {
        workspace_id: "workspace-1".to_owned(),
        request_dedupe_key: "dm-reply-1".to_owned(),
        now_unix_seconds: 100,
      },
    )
    .await
    .expect("status"),
    Some(codeoff_state::SlackDeliveryStatus {
      connector_id: "slack-default".to_owned(),
      workspace_id: "workspace-1".to_owned(),
      channel_id: "D1".to_owned(),
      thread_ts: None,
      message_ts: None,
      request_dedupe_key: "dm-reply-1".to_owned(),
      status: SlackDeliveryStatusKind::Pending,
      available_at: Some(100),
      attempt_count: Some(0),
      sender_kind: "bot".to_owned(),
      sender_key: None,
    })
  );
}

#[tokio::test]
async fn reply_to_event_queues_direct_message_thread_reply_when_source_is_threaded() {
  let state = store().await;
  persist_source_with_kind(
    &state.store,
    SlackSourceEvent {
      workspace_id: "workspace-1".to_owned(),
      event_kind: "message".to_owned(),
      dedupe_key: "dm-thread-dedupe-1".to_owned(),
      envelope_id: Some("dm-thread-envelope-1".to_owned()),
      event_id: Some("dm-thread-event-1".to_owned()),
      channel_id: Some("D1".to_owned()),
      thread_ts: Some("200.0".to_owned()),
      message_ts: Some("201.0".to_owned()),
      user_id: Some("U1".to_owned()),
      raw_payload_json: "{}".to_owned(),
    },
    ChannelEventKind::DirectMessageReceived,
  )
  .await;

  let response = reply_to_event(
    &state.store,
    ReplyToEventRequest {
      connector_id: "slack-default".to_owned(),
      workspace_id: "workspace-1".to_owned(),
      event_dedupe_key: "dm-thread-dedupe-1".to_owned(),
      request_dedupe_key: "dm-thread-reply-1".to_owned(),
      text: "hello in the DM thread".to_owned(),
      send_as: None,
      now_unix_seconds: 100,
    },
  )
  .await
  .expect("reply queued");

  assert!(response.queued);
  assert_eq!(
    get_delivery_status(
      &state.store,
      GetDeliveryStatusRequest {
        workspace_id: "workspace-1".to_owned(),
        request_dedupe_key: "dm-thread-reply-1".to_owned(),
        now_unix_seconds: 100,
      },
    )
    .await
    .expect("status"),
    Some(codeoff_state::SlackDeliveryStatus {
      connector_id: "slack-default".to_owned(),
      workspace_id: "workspace-1".to_owned(),
      channel_id: "D1".to_owned(),
      thread_ts: Some("200.0".to_owned()),
      message_ts: None,
      request_dedupe_key: "dm-thread-reply-1".to_owned(),
      status: SlackDeliveryStatusKind::Pending,
      available_at: Some(100),
      attempt_count: Some(0),
      sender_kind: "bot".to_owned(),
      sender_key: None,
    })
  );
}

#[tokio::test]
async fn reply_to_event_fails_when_source_refs_do_not_identify_message_target() {
  let state = store().await;
  persist_source(
    &state.store,
    SlackSourceEvent {
      workspace_id: "workspace-1".to_owned(),
      event_kind: "app_mention".to_owned(),
      dedupe_key: "event-dedupe-1".to_owned(),
      envelope_id: Some("envelope-1".to_owned()),
      event_id: Some("event-1".to_owned()),
      channel_id: None,
      thread_ts: None,
      message_ts: None,
      user_id: Some("U1".to_owned()),
      raw_payload_json: "{}".to_owned(),
    },
  )
  .await;

  let error = reply_to_event(
    &state.store,
    ReplyToEventRequest {
      connector_id: "slack-default".to_owned(),
      workspace_id: "workspace-1".to_owned(),
      event_dedupe_key: "event-dedupe-1".to_owned(),
      request_dedupe_key: "reply-1".to_owned(),
      text: "hello".to_owned(),
      send_as: None,
      now_unix_seconds: 100,
    },
  )
  .await
  .expect_err("missing target fails");

  assert!(matches!(error, ChannelToolError::MissingReplyTarget));
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
    .expect("status"),
    None
  );
}

#[tokio::test]
async fn reply_to_event_fails_when_source_event_is_missing() {
  let state = store().await;

  let error = reply_to_event(
    &state.store,
    ReplyToEventRequest {
      connector_id: "slack-default".to_owned(),
      workspace_id: "workspace-1".to_owned(),
      event_dedupe_key: "missing-event".to_owned(),
      request_dedupe_key: "reply-1".to_owned(),
      text: "hello".to_owned(),
      send_as: None,
      now_unix_seconds: 100,
    },
  )
  .await
  .expect_err("missing source fails");

  assert!(matches!(error, ChannelToolError::MissingSourceEvent));
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
    .expect("status"),
    None
  );
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn send_message_queues_supported_channel_thread_and_dm_targets() {
  let state = store().await;

  let channel = send_message(
    &state.store,
    SendMessageRequest {
      connector_id: "slack-default".to_owned(),
      workspace_id: "workspace-1".to_owned(),
      request_dedupe_key: "channel-send-1".to_owned(),
      target: ChannelReplyTarget::Channel {
        channel_id: "C1".to_owned(),
      },
      text: "channel message".to_owned(),
      send_as: None,
      now_unix_seconds: 100,
    },
  )
  .await
  .expect("channel queued");
  let thread = send_message(
    &state.store,
    SendMessageRequest {
      connector_id: "slack-default".to_owned(),
      workspace_id: "workspace-1".to_owned(),
      request_dedupe_key: "thread-send-1".to_owned(),
      target: ChannelReplyTarget::Thread {
        channel_id: "C1".to_owned(),
        thread_id: "100.0".to_owned(),
      },
      text: "thread reply".to_owned(),
      send_as: None,
      now_unix_seconds: 100,
    },
  )
  .await
  .expect("thread queued");
  let dm = send_message(
    &state.store,
    SendMessageRequest {
      connector_id: "slack-default".to_owned(),
      workspace_id: "workspace-1".to_owned(),
      request_dedupe_key: "dm-send-1".to_owned(),
      target: ChannelReplyTarget::DirectMessage {
        user_account_id: "U1".to_owned(),
      },
      text: "dm reply".to_owned(),
      send_as: None,
      now_unix_seconds: 100,
    },
  )
  .await
  .expect("dm queued");

  assert!(channel.queued);
  assert!(thread.queued);
  assert!(dm.queued);
  assert_eq!(
    get_delivery_status(
      &state.store,
      GetDeliveryStatusRequest {
        workspace_id: "workspace-1".to_owned(),
        request_dedupe_key: "channel-send-1".to_owned(),
        now_unix_seconds: 100,
      },
    )
    .await
    .expect("channel status"),
    Some(codeoff_state::SlackDeliveryStatus {
      connector_id: "slack-default".to_owned(),
      workspace_id: "workspace-1".to_owned(),
      channel_id: "C1".to_owned(),
      thread_ts: None,
      message_ts: None,
      request_dedupe_key: "channel-send-1".to_owned(),
      status: SlackDeliveryStatusKind::Pending,
      available_at: Some(100),
      attempt_count: Some(0),
      sender_kind: "bot".to_owned(),
      sender_key: None,
    })
  );
  assert_eq!(
    get_delivery_status(
      &state.store,
      GetDeliveryStatusRequest {
        workspace_id: "workspace-1".to_owned(),
        request_dedupe_key: "thread-send-1".to_owned(),
        now_unix_seconds: 100,
      },
    )
    .await
    .expect("thread status"),
    Some(codeoff_state::SlackDeliveryStatus {
      connector_id: "slack-default".to_owned(),
      workspace_id: "workspace-1".to_owned(),
      channel_id: "C1".to_owned(),
      thread_ts: Some("100.0".to_owned()),
      message_ts: None,
      request_dedupe_key: "thread-send-1".to_owned(),
      status: SlackDeliveryStatusKind::Pending,
      available_at: Some(100),
      attempt_count: Some(0),
      sender_kind: "bot".to_owned(),
      sender_key: None,
    })
  );
  assert_eq!(
    get_delivery_status(
      &state.store,
      GetDeliveryStatusRequest {
        workspace_id: "workspace-1".to_owned(),
        request_dedupe_key: "dm-send-1".to_owned(),
        now_unix_seconds: 100,
      },
    )
    .await
    .expect("dm status"),
    Some(codeoff_state::SlackDeliveryStatus {
      connector_id: "slack-default".to_owned(),
      workspace_id: "workspace-1".to_owned(),
      channel_id: "U1".to_owned(),
      thread_ts: None,
      message_ts: None,
      request_dedupe_key: "dm-send-1".to_owned(),
      status: SlackDeliveryStatusKind::Pending,
      available_at: Some(100),
      attempt_count: Some(0),
      sender_kind: "bot".to_owned(),
      sender_key: None,
    })
  );
}

#[tokio::test]
async fn send_message_rejects_ephemeral_targets() {
  let state = store().await;

  let error = send_message(
    &state.store,
    SendMessageRequest {
      connector_id: "slack-default".to_owned(),
      workspace_id: "workspace-1".to_owned(),
      request_dedupe_key: "unsupported-send-1".to_owned(),
      target: ChannelReplyTarget::Ephemeral {
        channel_id: "C1".to_owned(),
        user_account_id: "U1".to_owned(),
      },
      text: "unsupported".to_owned(),
      send_as: None,
      now_unix_seconds: 100,
    },
  )
  .await
  .expect_err("unsupported target fails");

  assert!(matches!(error, ChannelToolError::UnsupportedTarget));
  assert_eq!(
    get_delivery_status(
      &state.store,
      GetDeliveryStatusRequest {
        workspace_id: "workspace-1".to_owned(),
        request_dedupe_key: "unsupported-send-1".to_owned(),
        now_unix_seconds: 100,
      },
    )
    .await
    .expect("status"),
    None
  );
}

#[tokio::test]
async fn send_message_queues_user_sender_metadata() {
  let state = store().await;

  send_message(
    &state.store,
    SendMessageRequest {
      connector_id: "slack-default".to_owned(),
      workspace_id: "workspace-1".to_owned(),
      request_dedupe_key: "user-send-1".to_owned(),
      target: ChannelReplyTarget::Channel {
        channel_id: "C1".to_owned(),
      },
      text: "channel message".to_owned(),
      send_as: Some("user:example".to_owned()),
      now_unix_seconds: 100,
    },
  )
  .await
  .expect("user sender queued");

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
async fn send_message_rejects_malformed_send_as() {
  let state = store().await;

  let error = send_message(
    &state.store,
    SendMessageRequest {
      connector_id: "slack-default".to_owned(),
      workspace_id: "workspace-1".to_owned(),
      request_dedupe_key: "bad-send-as-1".to_owned(),
      target: ChannelReplyTarget::Channel {
        channel_id: "C1".to_owned(),
      },
      text: "channel message".to_owned(),
      send_as: Some("example".to_owned()),
      now_unix_seconds: 100,
    },
  )
  .await
  .expect_err("malformed sender fails");

  assert!(matches!(error, ChannelToolError::InvalidSender { .. }));
}

#[tokio::test]
async fn get_delivery_status_reads_delivered_state() {
  let state = store().await;
  send_message(
    &state.store,
    SendMessageRequest {
      connector_id: "slack-default".to_owned(),
      workspace_id: "workspace-1".to_owned(),
      request_dedupe_key: "thread-send-1".to_owned(),
      target: ChannelReplyTarget::Thread {
        channel_id: "C1".to_owned(),
        thread_id: "100.0".to_owned(),
      },
      text: "thread reply".to_owned(),
      send_as: None,
      now_unix_seconds: 100,
    },
  )
  .await
  .expect("thread queued");
  state
    .store
    .complete_slack_delivery(
      &SlackDeliveryReceipt {
        connector_id: "slack-default".to_owned(),
        workspace_id: "workspace-1".to_owned(),
        channel_id: "C1".to_owned(),
        thread_ts: Some("100.0".to_owned()),
        message_ts: "101.0".to_owned(),
        request_dedupe_key: "thread-send-1".to_owned(),
        sender: codeoff_state::SlackDeliverySender::Bot,
      },
      r#"{"ok":true}"#,
      101,
    )
    .await
    .expect("complete");

  let status = get_delivery_status(
    &state.store,
    GetDeliveryStatusRequest {
      workspace_id: "workspace-1".to_owned(),
      request_dedupe_key: "thread-send-1".to_owned(),
      now_unix_seconds: 100,
    },
  )
  .await
  .expect("status");

  assert_eq!(
    status,
    Some(codeoff_state::SlackDeliveryStatus {
      connector_id: "slack-default".to_owned(),
      workspace_id: "workspace-1".to_owned(),
      channel_id: "C1".to_owned(),
      thread_ts: Some("100.0".to_owned()),
      message_ts: Some("101.0".to_owned()),
      request_dedupe_key: "thread-send-1".to_owned(),
      status: SlackDeliveryStatusKind::Delivered,
      available_at: None,
      attempt_count: None,
      sender_kind: "bot".to_owned(),
      sender_key: None,
    })
  );
}
