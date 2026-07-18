use std::collections::BTreeMap;
use std::sync::Mutex;

use codeoff_channel_slack::{
  SlackHttpClient, SlackHttpRequest, SlackHttpResponse, SlackWebApiClient,
};
use codeoff_config::{SlackConfig, SlackUserTokenConfig};

#[derive(Default)]
struct FakeHttpClient {
  responses: Mutex<Vec<SlackHttpResponse>>,
  requests: Mutex<Vec<SlackHttpRequest>>,
}

impl FakeHttpClient {
  fn with_responses(responses: Vec<SlackHttpResponse>) -> Self {
    Self {
      responses: Mutex::new(responses.into_iter().rev().collect()),
      requests: Mutex::default(),
    }
  }
}

#[async_trait::async_trait]
impl SlackHttpClient for FakeHttpClient {
  async fn get(&self, request: SlackHttpRequest) -> Result<SlackHttpResponse, String> {
    self.requests.lock().expect("requests").push(request);
    self
      .responses
      .lock()
      .expect("responses")
      .pop()
      .ok_or_else(|| "unexpected GET request".to_owned())
  }
}

fn response(status: u16, body: &str) -> SlackHttpResponse {
  SlackHttpResponse::new(status, Vec::<(&str, &str)>::new(), body)
}

fn client(http: FakeHttpClient) -> SlackWebApiClient<FakeHttpClient> {
  SlackWebApiClient::new(
    http,
    "connector-1",
    "xoxb-secret-token",
    SlackConfig::default(),
    1_000_000,
  )
}

#[test]
fn workspace_summary_exposes_discoverable_connector_and_workspace_ids() {
  let connector = client(FakeHttpClient::default());

  let workspace = connector.workspace_summary();

  assert_eq!(workspace.provider, "slack");
  assert_eq!(workspace.connector_id, "connector-1");
  assert_eq!(workspace.connector_name.as_deref(), Some("Slack"));
  assert_eq!(workspace.workspace_id, "T00000000");
  assert_eq!(workspace.display_name, "Slack workspace T00000000");
}

#[tokio::test]
async fn user_search_maps_users_list_profiles_and_filters_deleted_users() {
  let connector = client(FakeHttpClient::with_responses(vec![response(
    200,
    r#"{"ok":true,"members":[
      {"id":"U1","name":"alice","real_name":"Alice Doe","profile":{"display_name":"Alice","email":"alice@example.com"}},
      {"id":"U2","name":"deleted","deleted":true,"profile":{"display_name":"Deleted"}},
      {"id":"USLACKBOT","name":"slackbot","is_bot":true}
    ]}"#,
  )]));

  let users = connector.search_users("ali").await.expect("users");

  assert_eq!(users.len(), 1);
  assert_eq!(users[0].connector_id, "connector-1");
  assert_eq!(users[0].workspace_id, "T00000000");
  assert_eq!(users[0].user_id, "U1");
  assert_eq!(users[0].handle.as_deref(), Some("alice"));
  assert_eq!(users[0].display_name.as_deref(), Some("Alice"));
  assert_eq!(users[0].real_name.as_deref(), Some("Alice Doe"));
  assert_eq!(users[0].email.as_deref(), Some("alice@example.com"));

  let requests = connector.http_client().requests.lock().expect("requests");
  assert_eq!(requests[0].path(), "users.list");
  assert!(requests[0].authorization_is_bearer_token("xoxb-secret-token"));
}

#[tokio::test]
async fn user_get_maps_users_info_response() {
  let connector = client(FakeHttpClient::with_responses(vec![response(
    200,
    r#"{"ok":true,"user":{"id":"U1","name":"alice","real_name":"Alice Doe","profile":{"display_name":"Alice"}}}"#,
  )]));

  let user = connector.get_user("U1").await.expect("user");

  assert_eq!(user.user_id, "U1");
  assert_eq!(user.handle.as_deref(), Some("alice"));

  let requests = connector.http_client().requests.lock().expect("requests");
  assert_eq!(requests[0].path(), "users.info");
  assert_eq!(requests[0].query_value("user"), Some("U1"));
}

#[tokio::test]
async fn user_resolve_returns_none_for_ambiguous_name_matches() {
  let connector = client(FakeHttpClient::with_responses(vec![response(
    200,
    r#"{"ok":true,"members":[
      {"id":"U1","name":"alex","profile":{"display_name":"Alex"}},
      {"id":"U2","name":"alex.c","profile":{"display_name":"Alex"}}
    ]}"#,
  )]));

  let resolved = connector.resolve_user("Alex").await.expect("resolution");

  assert!(resolved.is_none());
}

#[tokio::test]
async fn channel_search_maps_conversations_list() {
  let connector = client(FakeHttpClient::with_responses(vec![response(
    200,
    r#"{"ok":true,"channels":[
      {"id":"C1","name":"engineering","is_channel":true,"is_private":false,"is_archived":false},
      {"id":"G1","name":"ops-private","is_group":true,"is_private":true,"is_archived":false},
      {"id":"C2","name":"archived","is_archived":true}
    ]}"#,
  )]));

  let channels = connector.search_channels("eng").await.expect("channels");

  assert_eq!(channels.len(), 1);
  assert_eq!(channels[0].channel_id, "C1");
  assert_eq!(channels[0].name.as_deref(), Some("engineering"));
  assert!(!channels[0].is_private);

  let requests = connector.http_client().requests.lock().expect("requests");
  assert_eq!(requests[0].path(), "conversations.list");
  assert_eq!(
    requests[0].query_value("types"),
    Some("public_channel,private_channel,im")
  );
}

#[tokio::test]
async fn channel_get_maps_conversations_info() {
  let connector = client(FakeHttpClient::with_responses(vec![response(
    200,
    r#"{"ok":true,"channel":{"id":"C1","name":"engineering","is_channel":true,"is_private":false}}"#,
  )]));

  let channel = connector.get_channel("C1").await.expect("channel");

  assert_eq!(channel.channel_id, "C1");
  assert_eq!(channel.name.as_deref(), Some("engineering"));

  let requests = connector.http_client().requests.lock().expect("requests");
  assert_eq!(requests[0].path(), "conversations.info");
  assert_eq!(requests[0].query_value("channel"), Some("C1"));
}

#[tokio::test]
async fn channel_resolve_accepts_hash_prefixed_names() {
  let connector = client(FakeHttpClient::with_responses(vec![response(
    200,
    r#"{"ok":true,"channels":[{"id":"C1","name":"engineering","is_channel":true}]}"#,
  )]));

  let channel = connector
    .resolve_channel("#engineering")
    .await
    .expect("resolution")
    .expect("channel");

  assert_eq!(channel.channel_id, "C1");
}

#[test]
fn configured_senders_include_bot_and_user_tokens_without_secret_values() {
  let mut user_tokens = BTreeMap::new();
  user_tokens.insert(
    "example".to_owned(),
    SlackUserTokenConfig {
      user_id: "U0EXAMPLE".to_owned(),
      token_env: "SLACK_EXAMPLE_USER_TOKEN".to_owned(),
    },
  );
  let connector = SlackWebApiClient::new(
    FakeHttpClient::default(),
    "connector-1",
    "xoxb-secret-token",
    SlackConfig {
      user_tokens,
      ..SlackConfig::default()
    },
    1_000_000,
  );

  let senders = connector.configured_senders();

  assert_eq!(senders.len(), 2);
  assert_eq!(senders[0].kind, "bot");
  assert_eq!(senders[0].key, None);
  assert_eq!(senders[1].kind, "user");
  assert_eq!(senders[1].key.as_deref(), Some("example"));
  assert_eq!(senders[1].user_id.as_deref(), Some("U0EXAMPLE"));
  assert_eq!(
    senders[1].token_env.as_deref(),
    Some("SLACK_EXAMPLE_USER_TOKEN")
  );
  assert!(!format!("{senders:?}").contains("xoxb-secret-token"));
}

#[test]
fn connector_status_reports_workspace_capabilities_and_configured_senders() {
  let connector = client(FakeHttpClient::default());

  let status = connector.connector_status();

  assert_eq!(status.connector_id, "connector-1");
  assert_eq!(status.workspace_id, "T00000000");
  assert!(status.capabilities.receive_events);
  assert!(status.capabilities.send_messages);
  assert!(status.capabilities.thread_replies);
  assert!(status.capabilities.direct_messages);
  assert!(status.capabilities.ephemeral_messages);
  assert!(status.capabilities.history_fetch);
  assert!(status.capabilities.user_profile_fetch);
  assert!(status.capabilities.socket_transport);
  assert!(status.capabilities.http_transport);
  assert_eq!(status.senders.len(), 1);
}
