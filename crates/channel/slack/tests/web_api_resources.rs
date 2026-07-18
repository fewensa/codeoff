use std::sync::Mutex;

use codeoff_channel_contract::{
  ChannelMessageFetchRequest, ChannelResourceDownloadRequest, ChannelResourceInfoRequest,
  ChannelResourceTextRequest,
};
use codeoff_channel_slack::{
  SlackHttpClient, SlackHttpDownloadRequest, SlackHttpRequest, SlackHttpResponse, SlackWebApiClient,
};
use codeoff_config::SlackConfig;
use codeoff_runtime::channel_tools::{ChannelResourceProvider, ChannelResourceProviderError};

#[derive(Default)]
struct FakeHttpClient {
  responses: Mutex<Vec<SlackHttpResponse>>,
  byte_responses: Mutex<Vec<Vec<u8>>>,
  byte_error: Mutex<Option<String>>,
  requests: Mutex<Vec<SlackHttpRequest>>,
  byte_requests: Mutex<Vec<SlackHttpDownloadRequest>>,
}

impl FakeHttpClient {
  fn with_responses(responses: Vec<SlackHttpResponse>) -> Self {
    Self {
      responses: Mutex::new(responses.into_iter().rev().collect()),
      byte_responses: Mutex::default(),
      byte_error: Mutex::default(),
      requests: Mutex::default(),
      byte_requests: Mutex::default(),
    }
  }

  fn with_responses_and_bytes(responses: Vec<SlackHttpResponse>, bytes: Vec<Vec<u8>>) -> Self {
    Self {
      responses: Mutex::new(responses.into_iter().rev().collect()),
      byte_responses: Mutex::new(bytes.into_iter().rev().collect()),
      byte_error: Mutex::default(),
      requests: Mutex::default(),
      byte_requests: Mutex::default(),
    }
  }

  fn with_responses_and_byte_error(responses: Vec<SlackHttpResponse>, error: &str) -> Self {
    Self {
      responses: Mutex::new(responses.into_iter().rev().collect()),
      byte_responses: Mutex::default(),
      byte_error: Mutex::new(Some(error.to_owned())),
      requests: Mutex::default(),
      byte_requests: Mutex::default(),
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

  async fn get_bytes(&self, request: SlackHttpDownloadRequest) -> Result<Vec<u8>, String> {
    self
      .byte_requests
      .lock()
      .expect("byte requests")
      .push(request);
    if let Some(error) = self.byte_error.lock().expect("byte error").take() {
      return Err(error);
    }
    self
      .byte_responses
      .lock()
      .expect("byte responses")
      .pop()
      .ok_or_else(|| "unexpected byte GET request".to_owned())
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

fn client_with_artifact_root(
  http: FakeHttpClient,
  artifact_root: impl Into<std::path::PathBuf>,
) -> SlackWebApiClient<FakeHttpClient> {
  SlackWebApiClient::new_with_artifact_root(
    http,
    "connector-1",
    "xoxb-secret-token",
    SlackConfig::default(),
    1_000_000,
    artifact_root,
  )
}

#[tokio::test]
async fn resource_provider_get_message_fetches_exact_history_message_with_files() {
  let connector = client(FakeHttpClient::with_responses(vec![response(
    200,
    r#"{"ok":true,"messages":[{
      "ts":"100.0",
      "text":"Please inspect this",
      "files":[{
        "id":"F1",
        "name":"report.md",
        "title":"Report",
        "mimetype":"text/markdown",
        "filetype":"markdown",
        "size":42
      }]
    }]}"#,
  )]));
  let request =
    ChannelMessageFetchRequest::new("connector-1", "workspace-1", "C1", None::<String>, "100.0")
      .expect("request");

  let message = connector.fetch_message(request).await.expect("message");

  assert_eq!(
    message.text.as_deref(),
    Some(
      "Please inspect this\nfile: report.md\nmimetype=text/markdown\nfiletype=markdown\nid=F1\nsize=42"
    )
  );
  assert_eq!(message.resources.len(), 1);
  assert_eq!(message.resources[0].resource_id, "F1");
  assert_eq!(message.resources[0].name.as_deref(), Some("report.md"));
  assert_eq!(
    message.resources[0].media_type.as_deref(),
    Some("text/markdown")
  );
  assert_eq!(message.resources[0].size_bytes, Some(42));

  let requests = connector.http_client().requests.lock().expect("requests");
  assert_eq!(requests.len(), 1);
  assert_eq!(requests[0].path(), "conversations.history");
  assert_eq!(requests[0].query_value("channel"), Some("C1"));
  assert_eq!(requests[0].query_value("latest"), Some("100.0"));
  assert_eq!(requests[0].query_value("inclusive"), Some("true"));
  assert_eq!(requests[0].query_value("limit"), Some("1"));
}

#[tokio::test]
async fn resource_provider_get_threaded_message_fetches_replies_and_finds_exact_message() {
  let connector = client(FakeHttpClient::with_responses(vec![response(
    200,
    r#"{"ok":true,"messages":[
      {"ts":"100.0","text":"thread root"},
      {"ts":"101.0","text":"thread reply"}
    ]}"#,
  )]));
  let request =
    ChannelMessageFetchRequest::new("connector-1", "workspace-1", "C1", Some("100.0"), "101.0")
      .expect("request");

  let message = connector.fetch_message(request).await.expect("message");

  assert_eq!(message.thread_id.as_deref(), Some("100.0"));
  assert_eq!(message.message_ts, "101.0");
  assert_eq!(message.text.as_deref(), Some("thread reply"));
  let requests = connector.http_client().requests.lock().expect("requests");
  assert_eq!(requests[0].path(), "conversations.replies");
  assert_eq!(requests[0].query_value("channel"), Some("C1"));
  assert_eq!(requests[0].query_value("ts"), Some("100.0"));
  assert_eq!(requests[0].query_value("limit"), Some("50"));
}

#[tokio::test]
async fn resource_provider_get_threaded_message_paginates_until_exact_reply() {
  let connector = client(FakeHttpClient::with_responses(vec![
    response(
      200,
      r#"{"ok":true,"messages":[
        {"ts":"100.0","text":"thread root"},
        {"ts":"100.1","text":"older reply"}
      ],"response_metadata":{"next_cursor":"cursor-2"}}"#,
    ),
    response(
      200,
      r#"{"ok":true,"messages":[
        {"ts":"101.0","text":"target reply"}
      ],"response_metadata":{"next_cursor":""}}"#,
    ),
  ]));
  let request =
    ChannelMessageFetchRequest::new("connector-1", "workspace-1", "C1", Some("100.0"), "101.0")
      .expect("request");

  let message = connector.fetch_message(request).await.expect("message");

  assert_eq!(message.text.as_deref(), Some("target reply"));
  let requests = connector.http_client().requests.lock().expect("requests");
  assert_eq!(requests.len(), 2);
  assert_eq!(requests[1].query_value("cursor"), Some("cursor-2"));
}

#[tokio::test]
async fn resource_provider_file_info_returns_metadata_without_private_urls() {
  let connector = client(FakeHttpClient::with_responses(vec![response(
    200,
    r#"{"ok":true,"file":{
      "id":"F1",
      "title":"Private report",
      "mimetype":"application/json",
      "filetype":"json",
      "size":128,
      "url_private":"https://files.slack.com/private",
      "url_private_download":"https://files.slack.com/download"
    }}"#,
  )]));
  let request =
    ChannelResourceInfoRequest::new("connector-1", "workspace-1", "F1").expect("request");

  let info = connector.fetch_resource_info(request).await.expect("info");

  assert_eq!(info.resource_id, "F1");
  assert_eq!(info.name.as_deref(), Some("Private report"));
  assert_eq!(info.media_type.as_deref(), Some("application/json"));
  assert_eq!(info.size_bytes, Some(128));
  let output = serde_json::to_string(&info).expect("json");
  assert!(!output.contains("url_private"));
  assert!(!output.contains("files.slack.com"));
}

#[tokio::test]
async fn resource_provider_read_text_downloads_allowed_utf8_resource() {
  let connector = client(FakeHttpClient::with_responses_and_bytes(
    vec![response(
      200,
      r#"{"ok":true,"file":{
        "id":"F1",
        "name":"notes.txt",
        "mimetype":"text/plain",
        "filetype":"text",
        "size":11,
        "url_private":"https://files.slack.com/files-pri/T1-F1/notes.txt"
      }}"#,
    )],
    vec![b"hello world".to_vec()],
  ));
  let request =
    ChannelResourceTextRequest::new("connector-1", "workspace-1", "F1").expect("request");

  let text = connector.read_resource_text(request).await.expect("text");

  assert_eq!(text.text.as_deref(), Some("hello world"));
  let byte_requests = connector
    .http_client()
    .byte_requests
    .lock()
    .expect("byte requests");
  assert_eq!(
    byte_requests[0].url(),
    "https://files.slack.com/files-pri/T1-F1/notes.txt"
  );
  assert!(byte_requests[0].authorization_is_bearer_token("xoxb-secret-token"));
  assert_eq!(byte_requests[0].max_bytes(), 1_048_576);
}

#[tokio::test]
async fn resource_provider_read_text_rejects_binary_resource_before_download() {
  let connector = client(FakeHttpClient::with_responses(vec![response(
    200,
    r#"{"ok":true,"file":{
      "id":"F1",
      "name":"image.png",
      "mimetype":"image/png",
      "filetype":"png",
      "size":100,
      "url_private":"https://files.slack.com/files-pri/T1-F1/image.png"
    }}"#,
  )]));
  let request =
    ChannelResourceTextRequest::new("connector-1", "workspace-1", "F1").expect("request");

  let error = connector
    .read_resource_text(request)
    .await
    .expect_err("binary should be rejected");

  assert_eq!(error, ChannelResourceProviderError::UnsupportedResource);
  assert!(
    connector
      .http_client()
      .byte_requests
      .lock()
      .expect("byte requests")
      .is_empty()
  );
}

#[tokio::test]
async fn resource_provider_read_text_rejects_oversize_resource_before_download() {
  let connector = client(FakeHttpClient::with_responses(vec![response(
    200,
    r#"{"ok":true,"file":{
      "id":"F1",
      "name":"large.json",
      "mimetype":"application/json",
      "filetype":"json",
      "size":1048577,
      "url_private":"https://files.slack.com/files-pri/T1-F1/large.json"
    }}"#,
  )]));
  let request =
    ChannelResourceTextRequest::new("connector-1", "workspace-1", "F1").expect("request");

  let error = connector
    .read_resource_text(request)
    .await
    .expect_err("oversize should be rejected");

  assert_eq!(error, ChannelResourceProviderError::UnsupportedResource);
  assert!(
    connector
      .http_client()
      .byte_requests
      .lock()
      .expect("byte requests")
      .is_empty()
  );
}

#[tokio::test]
async fn resource_provider_read_text_rejects_non_slack_private_url_before_download() {
  let connector = client(FakeHttpClient::with_responses(vec![response(
    200,
    r#"{"ok":true,"file":{
      "id":"F1",
      "name":"notes.txt",
      "mimetype":"text/plain",
      "filetype":"text",
      "size":11,
      "url_private":"https://example.com/files-pri/T1-F1/notes.txt"
    }}"#,
  )]));
  let request =
    ChannelResourceTextRequest::new("connector-1", "workspace-1", "F1").expect("request");

  let error = connector
    .read_resource_text(request)
    .await
    .expect_err("non-slack url should be rejected");

  assert!(matches!(
    error,
    ChannelResourceProviderError::Request { .. }
  ));
  assert!(
    connector
      .http_client()
      .byte_requests
      .lock()
      .expect("byte requests")
      .is_empty()
  );
}

#[tokio::test]
async fn resource_provider_read_text_redacts_private_url_from_download_errors() {
  let connector = client(FakeHttpClient::with_responses_and_byte_error(
    vec![response(
      200,
      r#"{"ok":true,"file":{
        "id":"F1",
        "name":"notes.txt",
        "mimetype":"text/plain",
        "filetype":"text",
        "size":11,
        "url_private":"https://files.slack.com/files-pri/T1-F1/notes.txt"
      }}"#,
    )],
    "failed to fetch https://files.slack.com/files-pri/T1-F1/notes.txt with xoxb-secret-token",
  ));
  let request =
    ChannelResourceTextRequest::new("connector-1", "workspace-1", "F1").expect("request");

  let error = connector
    .read_resource_text(request)
    .await
    .expect_err("download should fail");
  let message = error.to_string();

  assert!(!message.contains("files.slack.com"), "{message}");
  assert!(!message.contains("xoxb-secret-token"), "{message}");
}

#[tokio::test]
async fn resource_provider_download_without_artifact_root_does_not_download_bytes() {
  let connector = client(FakeHttpClient::with_responses(vec![response(
    200,
    r#"{"ok":true,"file":{
      "id":"F1",
      "name":"notes.txt",
      "mimetype":"text/plain",
      "filetype":"text",
      "size":11,
      "url_private_download":"https://files.slack.com/files-pri/T1-F1/download/notes.txt"
    }}"#,
  )]));
  let request =
    ChannelResourceDownloadRequest::new("connector-1", "workspace-1", "F1").expect("request");

  let error = connector
    .download_resource(request)
    .await
    .expect_err("missing artifact root should fail");

  assert!(matches!(
    error,
    ChannelResourceProviderError::Provider { .. }
  ));
  assert!(
    connector
      .http_client()
      .byte_requests
      .lock()
      .expect("byte requests")
      .is_empty()
  );
}

#[tokio::test]
async fn resource_provider_download_writes_sanitized_artifact_path() {
  let tempdir = tempfile::tempdir().expect("tempdir");
  let connector = client_with_artifact_root(
    FakeHttpClient::with_responses_and_bytes(
      vec![response(
        200,
        r#"{"ok":true,"file":{
          "id":"F1",
          "name":"../secret report?.txt",
          "mimetype":"text/plain",
          "filetype":"text",
          "size":11,
          "url_private_download":"https://files.slack.com/files-pri/T1-F1/download/secret"
        }}"#,
      )],
      vec![b"hello world".to_vec()],
    ),
    tempdir.path(),
  );
  let request =
    ChannelResourceDownloadRequest::new("connector-1", "workspace-1", "F1").expect("request");

  let download = connector
    .download_resource(request)
    .await
    .expect("download");

  assert_eq!(
    download.artifact_uri,
    "artifact://slack/workspace-1/F1/secret_report_.txt"
  );
  let local_path = download.local_path.expect("local path");
  assert!(local_path.ends_with("/artifacts/slack/workspace-1/F1/secret_report_.txt"));
  assert_eq!(std::fs::read(local_path).expect("artifact"), b"hello world");
  assert_eq!(
    connector.http_client().byte_requests.lock().expect("bytes")[0].max_bytes(),
    25 * 1_024 * 1_024
  );
}
