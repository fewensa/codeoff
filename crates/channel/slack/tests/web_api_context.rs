use std::sync::Mutex;

use codeoff_channel_contract::{ChannelContextRequest, ChannelReplyTarget};
use codeoff_channel_slack::{
  SlackApiErrorClass, SlackHttpClient, SlackHttpRequest, SlackHttpResponse,
  SlackReqwestWebApiClient, SlackWebApiClient, SlackWebApiError,
};
use codeoff_config::SlackConfig;

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
      .ok_or_else(|| "unexpected request".to_owned())
  }
}

fn response(status: u16, body: &str) -> SlackHttpResponse {
  SlackHttpResponse::new(status, Vec::<(&str, &str)>::new(), body)
}

fn client(http: FakeHttpClient) -> SlackWebApiClient<FakeHttpClient> {
  let config = SlackConfig {
    recent_message_limit: 2,
    thread_message_limit: 3,
    history_lookback_hours: 2,
    ..SlackConfig::default()
  };
  SlackWebApiClient::new(http, "connector-1", "xoxb-secret-token", config, 1_000_000)
}

#[test]
fn production_http_client_previews_get_requests_without_leaking_authorization() {
  let http = SlackReqwestWebApiClient::default();
  let request = SlackHttpRequest::new(
    "conversations.history",
    [
      ("channel".to_owned(), "C1".to_owned()),
      ("limit".to_owned(), "2".to_owned()),
    ],
    None,
    "Bearer xoxb-secret-token",
  );

  let built = http.build_request_preview(&request).expect("request");

  assert_eq!(built.method, reqwest::Method::GET);
  assert_eq!(
    built.url,
    "https://slack.com/api/conversations.history?channel=C1&limit=2"
  );
  assert!(!built.has_json_body);
  assert!(!format!("{built:?}").contains("xoxb-secret-token"));
  assert!(!format!("{request:?}").contains("xoxb-secret-token"));
}

#[test]
fn production_http_client_previews_post_json_requests_without_leaking_body_or_token() {
  let http = SlackReqwestWebApiClient::default();
  let request = SlackHttpRequest::new(
    "chat.postMessage",
    Vec::<(String, String)>::new(),
    Some(r#"{"channel":"C1","thread_ts":"100.0","text":"Hello"}"#.to_owned()),
    "Bearer xoxb-secret-token",
  );

  let built = http.build_request_preview(&request).expect("request");

  assert_eq!(built.method, reqwest::Method::POST);
  assert_eq!(built.url, "https://slack.com/api/chat.postMessage");
  assert!(built.has_json_body);
  assert!(!format!("{built:?}").contains("xoxb-secret-token"));
  assert!(!format!("{built:?}").contains("Hello"));
  let debug = format!("{request:?}");
  assert!(debug.contains("json_body: Some(\"<omitted>\")"));
  assert!(!debug.contains("xoxb-secret-token"));
  assert!(!debug.contains("Hello"));
}

#[test]
fn production_http_client_rejects_unsafe_paths_before_building_authorized_requests() {
  let http = SlackReqwestWebApiClient::default();

  for path in [
    "https://example.com/api/chat.postMessage",
    "//example.com/api/chat.postMessage",
    "/chat.postMessage",
    "../chat.postMessage",
  ] {
    let request = SlackHttpRequest::new(
      path,
      Vec::<(String, String)>::new(),
      None,
      "Bearer xoxb-secret-token",
    );
    let error = http
      .build_request_preview(&request)
      .expect_err("unsafe path should be rejected");

    assert_eq!(error, "unsafe slack web api path");
    assert!(!error.contains("xoxb-secret-token"));
  }
}

#[tokio::test]
async fn channel_context_applies_history_count_time_and_pagination_bounds() {
  let http = FakeHttpClient::with_responses(vec![
    response(200, r#"{"ok":true,"channels":[{"id":"C1"}]}"#),
    response(
      200,
      r#"{"ok":true,"messages":[{"ts":"999999.0"},{"ts":"992801.0"},{"ts":"992799.0"}],"response_metadata":{"next_cursor":"next-page"}}"#,
    ),
  ]);
  let connector = client(http);
  let request = ChannelContextRequest::new(
    "connector-1",
    "workspace-1",
    ChannelReplyTarget::Channel {
      channel_id: "C1".to_owned(),
    },
    10,
  )
  .expect("valid request");

  let page = connector
    .fetch_context(&request)
    .await
    .expect("context page");

  assert_eq!(page.events.len(), 2);
  assert_eq!(page.events[0].event_id, "999999.0");
  assert_eq!(page.events[1].event_id, "992801.0");
  assert_eq!(page.next_cursor.as_deref(), Some("next-page"));

  let requests = connector.http_client().requests.lock().expect("requests");
  assert_eq!(requests.len(), 2);
  assert_eq!(requests[0].path(), "conversations.list");
  assert_eq!(
    requests[0].query_value("types"),
    Some("public_channel,private_channel,im")
  );
  assert_eq!(requests[1].path(), "conversations.history");
  assert_eq!(requests[1].query_value("channel"), Some("C1"));
  assert_eq!(requests[1].query_value("limit"), Some("2"));
  assert_eq!(requests[1].query_value("oldest"), Some("992800"));
  assert!(!format!("{:?}", requests[1]).contains("xoxb-secret-token"));
}

#[tokio::test]
async fn channel_context_passes_cursor_to_history_request() {
  let http = FakeHttpClient::with_responses(vec![
    response(200, r#"{"ok":true,"channels":[{"id":"C1"}]}"#),
    response(200, r#"{"ok":true,"messages":[{"ts":"999999.0"}]}"#),
  ]);
  let connector = client(http);
  let mut request = ChannelContextRequest::new(
    "connector-1",
    "workspace-1",
    ChannelReplyTarget::Channel {
      channel_id: "C1".to_owned(),
    },
    1,
  )
  .expect("valid request");
  request.cursor = Some("history-page-2".to_owned());

  connector
    .fetch_context(&request)
    .await
    .expect("context page");

  let requests = connector.http_client().requests.lock().expect("requests");
  assert_eq!(requests[1].path(), "conversations.history");
  assert_eq!(requests[1].query_value("cursor"), Some("history-page-2"));
}

#[tokio::test]
async fn channel_context_fetches_direct_message_channel_history() {
  let http = FakeHttpClient::with_responses(vec![
    response(200, r#"{"ok":true,"channels":[{"id":"D1"}]}"#),
    response(
      200,
      r#"{"ok":true,"messages":[{"ts":"999999.0","text":"木星有相比地球大多少？"}]}"#,
    ),
  ]);
  let connector = client(http);
  let request = ChannelContextRequest::new(
    "connector-1",
    "workspace-1",
    ChannelReplyTarget::Channel {
      channel_id: "D1".to_owned(),
    },
    1,
  )
  .expect("valid request");

  let page = connector
    .fetch_context(&request)
    .await
    .expect("context page");

  assert_eq!(page.events.len(), 1);
  assert_eq!(
    page.events[0].text.as_deref(),
    Some("木星有相比地球大多少？")
  );
  let requests = connector.http_client().requests.lock().expect("requests");
  assert_eq!(
    requests[0].query_value("types"),
    Some("public_channel,private_channel,im")
  );
  assert_eq!(requests[1].path(), "conversations.history");
  assert_eq!(requests[1].query_value("channel"), Some("D1"));
}

#[tokio::test]
async fn channel_context_summarizes_rich_message_content() {
  let http = FakeHttpClient::with_responses(vec![
    response(200, r#"{"ok":true,"channels":[{"id":"D1"}]}"#),
    response(
      200,
      r#"{"ok":true,"messages":[{
        "ts":"999999.0",
        "text":"fallback text https://example.com/report",
        "blocks":[{
          "type":"rich_text",
          "elements":[{
            "type":"rich_text_section",
            "elements":[
              {"type":"text","text":"Block says "},
              {"type":"link","url":"https://example.com/block","text":"block link"}
            ]
          }]
        }],
        "attachments":[{
          "fallback":"attachment fallback",
          "title":"Quarterly report",
          "text":"attachment body"
        }],
        "files":[{
          "id":"F1",
          "name":"chart.png",
          "mimetype":"image/png",
          "filetype":"png",
          "size":12345
        }]
      }]}"#,
    ),
  ]);
  let connector = client(http);
  let request = ChannelContextRequest::new(
    "connector-1",
    "workspace-1",
    ChannelReplyTarget::Channel {
      channel_id: "D1".to_owned(),
    },
    1,
  )
  .expect("valid request");

  let page = connector
    .fetch_context(&request)
    .await
    .expect("context page");

  let text = page.events[0].text.as_deref().expect("summary text");
  assert!(text.contains("fallback text https://example.com/report"));
  assert!(text.contains("Block says block link <https://example.com/block>"));
  assert!(text.contains("Quarterly report"));
  assert!(text.contains("attachment body"));
  assert!(text.contains("file: chart.png"));
  assert!(text.contains("mimetype=image/png"));
  assert!(text.contains("size=12345"));
}

#[tokio::test]
async fn channel_context_checks_paginated_conversations_list_before_marking_unavailable() {
  let http = FakeHttpClient::with_responses(vec![
    response(
      200,
      r#"{"ok":true,"channels":[{"id":"C-other"}],"response_metadata":{"next_cursor":"page-2"}}"#,
    ),
    response(200, r#"{"ok":true,"channels":[{"id":"C1"}]}"#),
    response(200, r#"{"ok":true,"messages":[{"ts":"999999.0"}]}"#),
  ]);
  let connector = client(http);
  let request = ChannelContextRequest::new(
    "connector-1",
    "workspace-1",
    ChannelReplyTarget::Channel {
      channel_id: "C1".to_owned(),
    },
    1,
  )
  .expect("valid request");

  let page = connector
    .fetch_context(&request)
    .await
    .expect("context page");

  assert_eq!(page.events.len(), 1);
  let requests = connector.http_client().requests.lock().expect("requests");
  assert_eq!(requests.len(), 3);
  assert_eq!(requests[0].path(), "conversations.list");
  assert_eq!(requests[0].query_value("cursor"), None);
  assert_eq!(requests[1].path(), "conversations.list");
  assert_eq!(requests[1].query_value("cursor"), Some("page-2"));
  assert_eq!(requests[2].path(), "conversations.history");
}

#[tokio::test]
async fn thread_context_uses_replies_and_thread_message_limit() {
  let http = FakeHttpClient::with_responses(vec![
    response(200, r#"{"ok":true,"channels":[{"id":"C1"}]}"#),
    response(
      200,
      r#"{"ok":true,"messages":[{"ts":"999999.0"},{"ts":"999998.0"}],"response_metadata":{"next_cursor":"thread-next"}}"#,
    ),
  ]);
  let connector = client(http);
  let request = ChannelContextRequest::new(
    "connector-1",
    "workspace-1",
    ChannelReplyTarget::Thread {
      channel_id: "C1".to_owned(),
      thread_id: "999000.0".to_owned(),
    },
    2,
  )
  .expect("valid request");

  let page = connector
    .fetch_context(&request)
    .await
    .expect("thread page");

  assert_eq!(page.events.len(), 2);
  assert_eq!(page.next_cursor.as_deref(), Some("thread-next"));
  let requests = connector.http_client().requests.lock().expect("requests");
  assert_eq!(requests[1].path(), "conversations.replies");
  assert_eq!(requests[1].query_value("ts"), Some("999000.0"));
  assert_eq!(requests[1].query_value("limit"), Some("2"));
}

#[tokio::test]
async fn thread_context_passes_cursor_to_replies_request() {
  let http = FakeHttpClient::with_responses(vec![
    response(200, r#"{"ok":true,"channels":[{"id":"C1"}]}"#),
    response(200, r#"{"ok":true,"messages":[{"ts":"999999.0"}]}"#),
  ]);
  let connector = client(http);
  let mut request = ChannelContextRequest::new(
    "connector-1",
    "workspace-1",
    ChannelReplyTarget::Thread {
      channel_id: "C1".to_owned(),
      thread_id: "999000.0".to_owned(),
    },
    1,
  )
  .expect("valid request");
  request.cursor = Some("thread-page-2".to_owned());

  connector
    .fetch_context(&request)
    .await
    .expect("thread page");

  let requests = connector.http_client().requests.lock().expect("requests");
  assert_eq!(requests[1].path(), "conversations.replies");
  assert_eq!(requests[1].query_value("cursor"), Some("thread-page-2"));
}

#[tokio::test]
async fn missing_scope_channel_is_a_typed_non_retryable_authorization_error() {
  let http = FakeHttpClient::with_responses(vec![response(
    200,
    r#"{"ok":false,"error":"missing_scope"}"#,
  )]);
  let connector = client(http);
  let request = ChannelContextRequest::new(
    "connector-1",
    "workspace-1",
    ChannelReplyTarget::Channel {
      channel_id: "C-private".to_owned(),
    },
    1,
  )
  .expect("valid request");

  assert!(matches!(
    connector.fetch_context(&request).await,
    Err(SlackWebApiError::Api {
      classification: SlackApiErrorClass::Unauthorized,
      ..
    })
  ));
}

#[tokio::test]
async fn rate_limits_are_retryable_keep_retry_after_and_redact_tokens() {
  let response = SlackHttpResponse::new(
    429,
    [("Retry-After", "17")],
    "xoxb-secret-token rate limited",
  );
  assert!(!format!("{response:?}").contains("xoxb-secret-token"));
  let http = FakeHttpClient::with_responses(vec![response]);
  let connector = client(http);
  let request = ChannelContextRequest::new(
    "connector-1",
    "workspace-1",
    ChannelReplyTarget::Channel {
      channel_id: "C1".to_owned(),
    },
    1,
  )
  .expect("valid request");

  let error = connector
    .fetch_context(&request)
    .await
    .expect_err("rate limited");
  assert!(matches!(
    error,
    SlackWebApiError::RateLimited {
      retry_after_seconds: Some(17)
    }
  ));
  assert!(!error.to_string().contains("xoxb-secret-token"));
  assert!(error.is_retryable());
}
