use std::sync::{Arc, Mutex};

use codeoff_channel_contract::{
  ChannelConnectorStatus, ChannelContextPage, ChannelContextRequest, ChannelEvent,
  ChannelEventKind, ChannelLookupRequest, ChannelMessageFetchRequest, ChannelMessageSnapshot,
  ChannelReplyTarget, ChannelResourceDownload, ChannelResourceDownloadRequest, ChannelResourceInfo,
  ChannelResourceInfoRequest, ChannelResourceText, ChannelResourceTextRequest,
  ChannelSearchRequest, ChannelSenderSummary, ChannelSummary, ChannelThreadReplyReceipt,
  ChannelThreadReplyRequest, ChannelUserResolveRequest, ChannelUserResolveResult,
  ChannelUserSearchRequest, ChannelUserSummary, ChannelWorkspaceRequest, ChannelWorkspaceSummary,
};
use codeoff_mcp::McpTcpServer;
use codeoff_runtime::channel_tools::{
  ChannelChannelProvider, ChannelContextProvider, ChannelContextProviderError,
  ChannelResourceProvider, ChannelResourceProviderError, ChannelSenderProvider,
  ChannelStatusProvider, ChannelThreadReplyProvider, ChannelToolError, ChannelUserProvider,
};
use codeoff_state::StateStore;
use serde_json::{Value, json};
use tempfile::{TempDir, tempdir};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::watch;

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

#[derive(Clone, Default)]
struct FakeContextProvider {
  requests: Arc<Mutex<Vec<ChannelContextRequest>>>,
}

#[derive(Clone, Default)]
struct FakeResourceProvider {
  info_requests: Arc<Mutex<Vec<ChannelResourceInfoRequest>>>,
}

#[derive(Clone, Default)]
struct FakeAddressProvider {
  user_requests: Arc<Mutex<Vec<ChannelUserSearchRequest>>>,
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
          "event-1",
          "dedupe-1",
          ChannelEventKind::MessageReceived,
        )
        .expect("event"),
      ],
      next_cursor: None,
    })
  }
}

#[async_trait::async_trait]
impl ChannelResourceProvider for FakeResourceProvider {
  async fn fetch_message(
    &self,
    request: ChannelMessageFetchRequest,
  ) -> Result<ChannelMessageSnapshot, ChannelResourceProviderError> {
    Ok(ChannelMessageSnapshot {
      connector_id: request.connector_id,
      workspace_id: request.workspace_id,
      channel_id: request.channel_id,
      thread_id: request.thread_id,
      message_ts: request.message_ts,
      text: Some("hello".to_owned()),
      resources: Vec::new(),
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
      .user_requests
      .lock()
      .expect("user requests")
      .push(request.clone());
    Ok(vec![ChannelUserSummary {
      connector_id: request.connector_id,
      workspace_id: request.workspace_id,
      user_id: "U1".to_owned(),
      display_name: Some("Example User".to_owned()),
      handle: Some("example".to_owned()),
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
      display_name: None,
      handle: None,
      email: None,
    }))
  }

  async fn resolve_user(
    &self,
    request: ChannelUserResolveRequest,
  ) -> Result<ChannelUserResolveResult, ChannelToolError> {
    Ok(ChannelUserResolveResult::resolved(ChannelUserSummary {
      connector_id: request.connector_id,
      workspace_id: request.workspace_id,
      user_id: request.query,
      display_name: None,
      handle: None,
      email: None,
    }))
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
      channel_id: "C1".to_owned(),
      name: Some(request.query),
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
      name: None,
      is_direct_message: false,
    }))
  }

  async fn resolve_channel(
    &self,
    request: ChannelSearchRequest,
  ) -> Result<Vec<ChannelSummary>, ChannelToolError> {
    self.search_channels(request).await
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
      display_name: Some("Bot".to_owned()),
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
    Ok(ChannelThreadReplyReceipt {
      connector_id: request.connector_id,
      workspace_id: request.workspace_id,
      channel_id: request.channel_id,
      thread_id: request.thread_id,
      request_dedupe_key: request.request_dedupe_key,
      message_id: "M1".to_owned(),
      send_as: request.send_as,
    })
  }
}

async fn write_json_line(stream: &mut TcpStream, value: Value) {
  stream
    .write_all(value.to_string().as_bytes())
    .await
    .expect("write request");
  stream.write_all(b"\n").await.expect("write newline");
}

async fn read_json_line(reader: &mut BufReader<TcpStream>) -> Value {
  let mut line = String::new();
  reader.read_line(&mut line).await.expect("read response");
  serde_json::from_str(&line).expect("json response")
}

#[tokio::test]
async fn test_tcp_server_shutdown_closes_and_joins_active_connections() {
  let state = store().await;
  let server = McpTcpServer::bind("127.0.0.1:0", state.store, FakeContextProvider::default())
    .await
    .expect("bind server");
  let address = server.local_addr().expect("local address");
  let (shutdown, shutdown_rx) = watch::channel(false);
  let server_task = tokio::spawn(server.run_until(shutdown_rx));
  let mut stream = TcpStream::connect(address).await.expect("connect server");
  write_json_line(
    &mut stream,
    json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}),
  )
  .await;
  let mut reader = BufReader::new(stream);
  let response = read_json_line(&mut reader).await;
  assert_eq!(response["id"], 1);

  shutdown.send(true).expect("request shutdown");
  tokio::time::timeout(std::time::Duration::from_secs(1), server_task)
    .await
    .expect("server shutdown deadline")
    .expect("server join")
    .expect("server shutdown");
  let mut trailing = String::new();
  assert_eq!(
    tokio::time::timeout(
      std::time::Duration::from_secs(1),
      reader.read_line(&mut trailing),
    )
    .await
    .expect("connection close deadline")
    .expect("connection close"),
    0
  );
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn test_tcp_server_handles_json_rpc_channel_tools() {
  let state = store().await;
  let provider = FakeContextProvider::default();
  let server = McpTcpServer::bind("127.0.0.1:0", state.store.clone(), provider.clone())
    .await
    .expect("bind server");
  let address = server.local_addr().expect("local address");
  let server_task = tokio::spawn(async move { server.run().await });

  let mut stream = TcpStream::connect(address).await.expect("connect server");
  write_json_line(
    &mut stream,
    json!({
      "jsonrpc": "2.0",
      "id": 1,
      "method": "initialize",
      "params": {}
    }),
  )
  .await;
  write_json_line(
    &mut stream,
    json!({
      "jsonrpc": "2.0",
      "id": 2,
      "method": "tools/list",
      "params": {}
    }),
  )
  .await;
  write_json_line(
    &mut stream,
    json!({
      "jsonrpc": "2.0",
      "id": 3,
      "method": "tools/call",
      "params": {
        "name": "channel.send_message",
        "arguments": {
          "connector_id": "slack-default",
          "workspace_id": "workspace-1",
          "request_dedupe_key": "tcp-send-1",
          "target": {
            "DirectMessage": {
              "user_account_id": "U1"
            }
          },
          "text": "hello over tcp"
        }
      }
    }),
  )
  .await;
  write_json_line(
    &mut stream,
    json!({
      "jsonrpc": "2.0",
      "id": 4,
      "method": "tools/call",
      "params": {
        "name": "channel.get_recent_messages",
        "arguments": {
          "connector_id": "slack-default",
          "workspace_id": "workspace-1",
          "channel_id": "C1",
          "limit": 5
        }
      }
    }),
  )
  .await;

  let mut reader = BufReader::new(stream);
  let initialize = read_json_line(&mut reader).await;
  let tools = read_json_line(&mut reader).await;
  let call = read_json_line(&mut reader).await;
  let context = read_json_line(&mut reader).await;

  assert_eq!(initialize["result"]["serverInfo"]["name"], "codeoff-mcp");
  assert_eq!(
    tools["result"]["tools"][0]["name"],
    "channel.reply_to_event"
  );
  assert_eq!(call["result"]["isError"], false);
  assert_eq!(
    call["result"]["structuredContent"]["request_dedupe_key"],
    "tcp-send-1"
  );
  assert_eq!(call["result"]["structuredContent"]["queued"], true);
  assert_eq!(
    context["result"]["structuredContent"]["events"][0]["event_id"],
    "event-1"
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
      cursor: None,
    }]
  );

  server_task.abort();
}

#[tokio::test]
async fn test_tcp_server_handles_resource_tools_when_provider_is_bound() {
  let state = store().await;
  let context_provider = FakeContextProvider::default();
  let resource_provider = Arc::new(FakeResourceProvider::default());
  let server = McpTcpServer::bind_with_resource_provider(
    "127.0.0.1:0",
    state.store.clone(),
    context_provider,
    resource_provider.clone(),
  )
  .await
  .expect("bind server");
  let address = server.local_addr().expect("local address");
  let server_task = tokio::spawn(async move { server.run().await });

  let mut stream = TcpStream::connect(address).await.expect("connect server");
  write_json_line(
    &mut stream,
    json!({
      "jsonrpc": "2.0",
      "id": 1,
      "method": "tools/call",
      "params": {
        "name": "channel.get_resource_info",
        "arguments": {
          "connector_id": "slack-default",
          "workspace_id": "workspace-1",
          "resource_id": "F1"
        }
      }
    }),
  )
  .await;

  let mut reader = BufReader::new(stream);
  let response = read_json_line(&mut reader).await;

  assert_eq!(response["result"]["isError"], false);
  assert_eq!(response["result"]["structuredContent"]["resource_id"], "F1");
  assert_eq!(
    resource_provider
      .info_requests
      .lock()
      .expect("info requests")
      .len(),
    1
  );

  server_task.abort();
}

#[tokio::test]
async fn test_tcp_server_handles_address_tools_when_provider_is_bound() {
  let state = store().await;
  let context_provider = FakeContextProvider::default();
  let address_provider = Arc::new(FakeAddressProvider::default());
  let server = McpTcpServer::bind_with_address_provider(
    "127.0.0.1:0",
    state.store.clone(),
    context_provider,
    address_provider.clone(),
  )
  .await
  .expect("bind server");
  let address = server.local_addr().expect("local address");
  let server_task = tokio::spawn(async move { server.run().await });

  let mut stream = TcpStream::connect(address).await.expect("connect server");
  write_json_line(
    &mut stream,
    json!({
      "jsonrpc": "2.0",
      "id": 1,
      "method": "tools/call",
      "params": {
        "name": "channel.search_users",
        "arguments": {
          "connector_id": "slack-default",
          "workspace_id": "workspace-1",
          "query": "example",
          "limit": 10
        }
      }
    }),
  )
  .await;

  let mut reader = BufReader::new(stream);
  let response = read_json_line(&mut reader).await;

  assert_eq!(response["result"]["isError"], false);
  assert_eq!(
    response["result"]["structuredContent"]["users"][0]["user_id"],
    "U1"
  );
  assert_eq!(
    *address_provider
      .user_requests
      .lock()
      .expect("user requests"),
    vec![ChannelUserSearchRequest {
      connector_id: "slack-default".to_owned(),
      workspace_id: "workspace-1".to_owned(),
      query: "example".to_owned(),
      limit: 10,
    }]
  );

  server_task.abort();
}
