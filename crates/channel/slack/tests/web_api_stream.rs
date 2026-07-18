use std::sync::Mutex;

use codeoff_channel_slack::{
  SlackHttpClient, SlackHttpRequest, SlackHttpResponse, SlackWebApiClient, SlackWebApiError,
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
  async fn get(&self, _request: SlackHttpRequest) -> Result<SlackHttpResponse, String> {
    Err("unexpected GET request".to_owned())
  }

  async fn post(&self, request: SlackHttpRequest) -> Result<SlackHttpResponse, String> {
    self.requests.lock().expect("requests").push(request);
    self
      .responses
      .lock()
      .expect("responses")
      .pop()
      .ok_or_else(|| "unexpected POST request".to_owned())
  }
}

fn response(
  status: u16,
  headers: impl IntoIterator<Item = (&'static str, &'static str)>,
  body: &str,
) -> SlackHttpResponse {
  SlackHttpResponse::new(status, headers, body)
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

#[tokio::test]
async fn start_stream_posts_markdown_text_and_returns_stream_message_ids() {
  let connector = client(FakeHttpClient::with_responses(vec![response(
    200,
    [],
    r#"{"ok":true,"channel":"C1","ts":"200.0"}"#,
  )]));

  let message = connector
    .start_stream("C1", "100.0", "Working on it")
    .await
    .expect("start stream");

  assert_eq!(message.channel_id, "C1");
  assert_eq!(message.message_ts, "200.0");
  assert_eq!(message.thread_ts.as_deref(), Some("100.0"));
  assert_eq!(
    message.response_body,
    r#"{"ok":true,"channel":"C1","ts":"200.0"}"#
  );
  let requests = connector.http_client().requests.lock().expect("requests");
  assert_eq!(requests.len(), 1);
  assert_eq!(requests[0].path(), "chat.startStream");
  assert!(requests[0].authorization_is_bearer_token("xoxb-secret-token"));
  assert_eq!(requests[0].json_value("channel").as_deref(), Some("C1"));
  assert_eq!(
    requests[0].json_value("thread_ts").as_deref(),
    Some("100.0")
  );
  assert_eq!(
    requests[0].json_value("markdown_text").as_deref(),
    Some("Working on it")
  );
  let request_debug = format!("{:?}", requests[0]);
  assert!(request_debug.contains("authorization: \"<redacted>\""));
  assert!(!request_debug.contains("xoxb-secret-token"));
  assert!(!request_debug.contains("Working on it"));
}

#[tokio::test]
async fn append_stream_posts_markdown_text_and_returns_status_ids() {
  let connector = client(FakeHttpClient::with_responses(vec![response(
    200,
    [],
    r#"{"ok":true,"channel":"C1","ts":"200.0"}"#,
  )]));

  let status = connector
    .append_stream("C1", "200.0", "Still working")
    .await
    .expect("append stream");

  assert_eq!(status.channel_id, "C1");
  assert_eq!(status.message_ts, "200.0");
  assert_eq!(
    status.response_body,
    r#"{"ok":true,"channel":"C1","ts":"200.0"}"#
  );
  let requests = connector.http_client().requests.lock().expect("requests");
  assert_eq!(requests[0].path(), "chat.appendStream");
  assert_eq!(requests[0].json_value("channel").as_deref(), Some("C1"));
  assert_eq!(requests[0].json_value("ts").as_deref(), Some("200.0"));
  assert_eq!(
    requests[0].json_value("markdown_text").as_deref(),
    Some("Still working")
  );
}

#[tokio::test]
async fn stop_stream_posts_final_markdown_text_and_returns_canonical_ids() {
  let connector = client(FakeHttpClient::with_responses(vec![response(
    200,
    [],
    r#"{"ok":true,"channel":"C-canonical","ts":"201.0","message":{"ts":"201.0"}}"#,
  )]));

  let message = connector
    .stop_stream("C1", "200.0", "Done")
    .await
    .expect("stop stream");

  assert_eq!(message.channel_id, "C-canonical");
  assert_eq!(message.message_ts, "201.0");
  assert_eq!(message.thread_ts, None);
  assert_eq!(
    message.response_body,
    r#"{"ok":true,"channel":"C-canonical","ts":"201.0","message":{"ts":"201.0"}}"#
  );
  let requests = connector.http_client().requests.lock().expect("requests");
  assert_eq!(requests[0].path(), "chat.stopStream");
  assert_eq!(requests[0].json_value("channel").as_deref(), Some("C1"));
  assert_eq!(requests[0].json_value("ts").as_deref(), Some("200.0"));
  assert_eq!(
    requests[0].json_value("markdown_text").as_deref(),
    Some("Done")
  );
}

#[tokio::test]
async fn stop_stream_rate_limit_preserves_retry_after_without_leaking_token() {
  let connector = client(FakeHttpClient::with_responses(vec![response(
    429,
    [("Retry-After", "17")],
    "xoxb-secret-token rate limited",
  )]));

  let error = connector
    .stop_stream("C1", "200.0", "Done")
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
  assert!(
    !format!(
      "{:?}",
      connector.http_client().requests.lock().expect("requests")[0]
    )
    .contains("Done")
  );
}

#[tokio::test]
async fn set_assistant_status_posts_status_and_loading_messages() {
  let connector = client(FakeHttpClient::with_responses(vec![response(
    200,
    [],
    r#"{"ok":true}"#,
  )]));

  connector
    .set_assistant_status(
      "C1",
      "100.0",
      "is thinking",
      &["Reading thread", "Checking context"],
    )
    .await
    .expect("set assistant status");

  let requests = connector.http_client().requests.lock().expect("requests");
  assert_eq!(requests.len(), 1);
  assert_eq!(requests[0].path(), "assistant.threads.setStatus");
  assert!(requests[0].authorization_is_bearer_token("xoxb-secret-token"));
  assert_eq!(requests[0].json_value("channel_id").as_deref(), Some("C1"));
  assert_eq!(
    requests[0].json_value("thread_ts").as_deref(),
    Some("100.0")
  );
  assert_eq!(
    requests[0].json_value("status").as_deref(),
    Some("is thinking")
  );
  assert_eq!(
    requests[0].json_string_array_value("loading_messages"),
    Some(vec![
      "Reading thread".to_owned(),
      "Checking context".to_owned()
    ])
  );
  let request_debug = format!("{:?}", requests[0]);
  assert!(request_debug.contains("authorization: \"<redacted>\""));
  assert!(!request_debug.contains("xoxb-secret-token"));
  assert!(!request_debug.contains("Reading thread"));
}

#[tokio::test]
async fn set_assistant_status_omits_empty_loading_messages() {
  let connector = client(FakeHttpClient::with_responses(vec![response(
    200,
    [],
    r#"{"ok":true}"#,
  )]));

  connector
    .set_assistant_status("C1", "100.0", "is thinking", &[])
    .await
    .expect("set assistant status");

  let requests = connector.http_client().requests.lock().expect("requests");
  assert_eq!(
    requests[0].json_value("status").as_deref(),
    Some("is thinking")
  );
  assert_eq!(
    requests[0].json_string_array_value("loading_messages"),
    None
  );
}

#[tokio::test]
async fn clear_assistant_status_posts_empty_status() {
  let connector = client(FakeHttpClient::with_responses(vec![response(
    200,
    [],
    r#"{"ok":true}"#,
  )]));

  connector
    .clear_assistant_status("C1", "100.0")
    .await
    .expect("clear assistant status");

  let requests = connector.http_client().requests.lock().expect("requests");
  assert_eq!(requests[0].path(), "assistant.threads.setStatus");
  assert_eq!(requests[0].json_value("channel_id").as_deref(), Some("C1"));
  assert_eq!(
    requests[0].json_value("thread_ts").as_deref(),
    Some("100.0")
  );
  assert_eq!(requests[0].json_value("status").as_deref(), Some(""));
  assert_eq!(
    requests[0].json_string_array_value("loading_messages"),
    None
  );
}

#[tokio::test]
async fn set_assistant_status_rate_limit_preserves_retry_after_without_leaking_token() {
  let connector = client(FakeHttpClient::with_responses(vec![response(
    429,
    [("Retry-After", "17")],
    "xoxb-secret-token rate limited",
  )]));

  let error = connector
    .set_assistant_status("C1", "100.0", "is thinking", &["Secret progress"])
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
  assert!(
    !format!(
      "{:?}",
      connector.http_client().requests.lock().expect("requests")[0]
    )
    .contains("Secret progress")
  );
}
