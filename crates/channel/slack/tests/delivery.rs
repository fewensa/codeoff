use std::sync::Mutex;

use codeoff_channel_contract::{ChannelMessageRequest, ChannelReplyTarget};
use codeoff_channel_slack::{
  SlackDeliveryQueue, SlackHttpClient, SlackHttpRequest, SlackHttpResponse, SlackWebApiClient,
  SlackWebApiError,
};
use codeoff_config::{SlackConfig, SlackUserTokenConfig};
use codeoff_state::{
  SlackDeliveryRequest, SlackDeliverySender, SlackDeliveryStatusKind,
  SlackStopStreamDeliveryRequest, StateStore,
};
use std::collections::BTreeMap;
use std::env;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tempfile::tempdir;
use tokio::sync::Notify;

#[derive(Default)]
struct FakeHttpClient {
  responses: Mutex<Vec<SlackHttpResponse>>,
  requests: Arc<Mutex<Vec<SlackHttpRequest>>>,
  post_started: Option<Arc<Notify>>,
  post_release: Option<Arc<Notify>>,
  post_gate_used: AtomicBool,
}

impl FakeHttpClient {
  fn with_responses(responses: Vec<SlackHttpResponse>) -> Self {
    Self {
      responses: Mutex::new(responses.into_iter().rev().collect()),
      requests: Arc::default(),
      post_started: None,
      post_release: None,
      post_gate_used: AtomicBool::new(false),
    }
  }

  fn with_post_gate(responses: Vec<SlackHttpResponse>) -> (Self, Arc<Notify>, Arc<Notify>) {
    let post_started = Arc::new(Notify::new());
    let post_release = Arc::new(Notify::new());
    (
      Self {
        responses: Mutex::new(responses.into_iter().rev().collect()),
        requests: Arc::default(),
        post_started: Some(post_started.clone()),
        post_release: Some(post_release.clone()),
        post_gate_used: AtomicBool::new(false),
      },
      post_started,
      post_release,
    )
  }
}

#[async_trait::async_trait]
impl SlackHttpClient for FakeHttpClient {
  async fn get(&self, _request: SlackHttpRequest) -> Result<SlackHttpResponse, String> {
    Err("unexpected GET request".to_owned())
  }

  async fn post(&self, request: SlackHttpRequest) -> Result<SlackHttpResponse, String> {
    self.requests.lock().expect("requests").push(request);
    if !self.post_gate_used.swap(true, Ordering::Relaxed) {
      if let Some(post_started) = &self.post_started {
        post_started.notify_one();
      }
      if let Some(post_release) = &self.post_release {
        post_release.notified().await;
      }
    }
    self
      .responses
      .lock()
      .expect("responses")
      .pop()
      .ok_or_else(|| "unexpected POST request".to_owned())
  }
}

fn queue(http: FakeHttpClient, store: StateStore, now: u64) -> SlackDeliveryQueue<FakeHttpClient> {
  SlackDeliveryQueue::new(
    SlackWebApiClient::new(
      http,
      "connector-1",
      "xoxb-secret-token",
      SlackConfig::default(),
      now,
    ),
    store,
    now,
  )
}

fn ok_response(channel: &str, ts: &str, thread_ts: Option<&str>) -> SlackHttpResponse {
  let message = thread_ts.map_or_else(
    || format!(r#"{{"ts":"{ts}"}}"#),
    |thread_ts| format!(r#"{{"ts":"{ts}","thread_ts":"{thread_ts}"}}"#),
  );
  SlackHttpResponse::new(
    200,
    Vec::<(&str, &str)>::new(),
    format!(r#"{{"ok":true,"channel":"{channel}","ts":"{ts}","message":{message}}}"#),
  )
}

#[tokio::test]
async fn sends_thread_reply_and_persists_a_receipt() {
  let temp = tempdir().expect("tempdir");
  let store = StateStore::initialize(temp.path(), None)
    .await
    .expect("state store");
  let delivery = queue(
    FakeHttpClient::with_responses(vec![ok_response("C1", "200.0", Some("100.0"))]),
    store,
    100,
  );
  let request = ChannelMessageRequest::new(
    "connector-1",
    "workspace-1",
    "reply-1",
    ChannelReplyTarget::Thread {
      channel_id: "C1".to_owned(),
      thread_id: "100.0".to_owned(),
    },
    "Hello thread",
  )
  .expect("request");

  let receipt = delivery.deliver(&request).await.expect("deliver");

  assert_eq!(receipt.message_id, "200.0");
  let requests = delivery
    .http_client()
    .requests
    .lock()
    .expect("requests")
    .clone();
  assert_eq!(requests[0].path(), "chat.postMessage");
  assert!(requests[0].authorization_is_bearer_token("xoxb-secret-token"));
  assert_eq!(requests[0].json_value("channel").as_deref(), Some("C1"));
  assert_eq!(
    requests[0].json_value("thread_ts").as_deref(),
    Some("100.0")
  );
  assert_eq!(
    requests[0].json_value("text").as_deref(),
    Some("Hello thread")
  );
  let request_debug = format!("{:?}", requests[0]);
  assert!(request_debug.contains("authorization: \"<redacted>\""));
  assert!(!request_debug.contains("xoxb-secret-token"));
  assert!(!request_debug.contains("Hello thread"));
  assert_eq!(delivery.receipt_count().await.expect("receipt count"), 1);
}

#[tokio::test]
async fn sends_direct_message_and_deduplicates_a_repeated_request() {
  let temp = tempdir().expect("tempdir");
  let store = StateStore::initialize(temp.path(), None)
    .await
    .expect("state store");
  let delivery = queue(
    FakeHttpClient::with_responses(vec![ok_response("D1", "200.0", None)]),
    store,
    100,
  );
  let request = ChannelMessageRequest::new(
    "connector-1",
    "workspace-1",
    "dm-1",
    ChannelReplyTarget::DirectMessage {
      user_account_id: "U1".to_owned(),
    },
    "Hello DM",
  )
  .expect("request");

  let first = delivery.deliver(&request).await.expect("first delivery");
  let duplicate = delivery
    .deliver(&request)
    .await
    .expect("duplicate delivery");

  assert_eq!(first, duplicate);
  let requests = delivery.http_client().requests.lock().expect("requests");
  assert_eq!(requests.len(), 1);
  assert_eq!(requests[0].json_value("channel").as_deref(), Some("U1"));
  assert_eq!(requests[0].json_value("thread_ts").as_deref(), None);
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn defers_transient_completion_without_blocking_other_deliveries() {
  let temp = tempdir().expect("tempdir");
  let store = StateStore::initialize(temp.path(), None)
    .await
    .expect("state store");
  store
    .set_storage_contention_timeout_for_tests(0)
    .await
    .expect("set zero busy timeout");
  let (http, post_started, post_release) = FakeHttpClient::with_post_gate(vec![
    ok_response("C1", "200.0", Some("100.0")),
    ok_response("C2", "201.0", Some("101.0")),
    ok_response("C1", "202.0", Some("100.0")),
  ]);
  let delivery = queue(http, store.clone(), 100);
  let first_request = ChannelMessageRequest::new(
    "connector-1",
    "workspace-1",
    "storage-lock-first-1",
    ChannelReplyTarget::Thread {
      channel_id: "C1".to_owned(),
      thread_id: "100.0".to_owned(),
    },
    "defer persisted completion",
  )
  .expect("first request");
  let first_delivery = delivery.deliver(&first_request);
  tokio::pin!(first_delivery);
  tokio::select! {
    () = post_started.notified() => {}
    result = &mut first_delivery => panic!("delivery completed before post: {result:?}"),
  }
  let lock = store
    .acquire_exclusive_storage_lock_for_tests()
    .await
    .expect("acquire exclusive lock");
  post_release.notify_one();
  let first_receipt = first_delivery.await.expect("deferred delivery result");
  assert_eq!(first_receipt.message_id, "200.0");
  lock.release().await.expect("release exclusive lock");

  store
    .enqueue_slack_delivery(
      &SlackDeliveryRequest {
        connector_id: "connector-1".to_owned(),
        workspace_id: "workspace-1".to_owned(),
        request_dedupe_key: "storage-lock-same-channel-1".to_owned(),
        channel_id: "C1".to_owned(),
        thread_ts: Some("100.0".to_owned()),
        text: "wait for the in-memory throttle".to_owned(),
        sender: SlackDeliverySender::Bot,
      },
      100,
    )
    .await
    .expect("queue same-channel delivery");
  store
    .enqueue_slack_delivery(
      &SlackDeliveryRequest {
        connector_id: "connector-1".to_owned(),
        workspace_id: "workspace-1".to_owned(),
        request_dedupe_key: "storage-lock-other-channel-1".to_owned(),
        channel_id: "C2".to_owned(),
        thread_ts: Some("101.0".to_owned()),
        text: "deliver while same channel waits".to_owned(),
        sender: SlackDeliverySender::Bot,
      },
      100,
    )
    .await
    .expect("queue other-channel delivery");
  assert!(
    delivery
      .drain_due_once()
      .await
      .expect("defer same-channel delivery")
      .is_none()
  );
  assert_eq!(
    delivery
      .http_client()
      .requests
      .lock()
      .expect("requests")
      .len(),
    1
  );
  let other_channel_receipt = delivery
    .drain_due_once()
    .await
    .expect("drain other-channel delivery")
    .expect("other-channel receipt");
  assert_eq!(other_channel_receipt.message_id, "201.0");

  delivery.set_now_unix_seconds(101);
  let completed = delivery
    .drain_due_once()
    .await
    .expect("persist deferred completion")
    .expect("deferred completion receipt");
  assert_eq!(completed.message_id, "200.0");
  let same_channel_receipt = delivery
    .drain_due_once()
    .await
    .expect("drain same-channel delivery after throttle")
    .expect("same-channel receipt");
  assert_eq!(same_channel_receipt.message_id, "202.0");
  assert_eq!(
    delivery
      .http_client()
      .requests
      .lock()
      .expect("requests")
      .len(),
    3
  );
  assert_eq!(
    store
      .slack_delivery_receipt_count()
      .await
      .expect("receipt count"),
    3
  );
  assert_eq!(
    store
      .slack_delivery_status("workspace-1", "storage-lock-first-1", 101)
      .await
      .expect("status")
      .expect("delivery")
      .status,
    SlackDeliveryStatusKind::Delivered
  );
  assert_eq!(
    store
      .slack_delivery_status("workspace-1", "storage-lock-same-channel-1", 101)
      .await
      .expect("status")
      .expect("delivery")
      .status,
    SlackDeliveryStatusKind::Delivered
  );
  assert_eq!(
    store
      .slack_delivery_status("workspace-1", "storage-lock-other-channel-1", 101)
      .await
      .expect("status")
      .expect("delivery")
      .status,
    SlackDeliveryStatusKind::Delivered
  );
}

#[tokio::test]
async fn drains_one_due_queued_delivery_without_reenqueuing() {
  let temp = tempdir().expect("tempdir");
  let store = StateStore::initialize(temp.path(), None)
    .await
    .expect("state store");
  store
    .enqueue_slack_delivery(
      &SlackDeliveryRequest {
        connector_id: "connector-1".to_owned(),
        workspace_id: "workspace-1".to_owned(),
        request_dedupe_key: "queued-1".to_owned(),
        channel_id: "C1".to_owned(),
        thread_ts: Some("100.0".to_owned()),
        text: "Already queued".to_owned(),
        sender: SlackDeliverySender::Bot,
      },
      100,
    )
    .await
    .expect("enqueue delivery");
  let delivery = queue(
    FakeHttpClient::with_responses(vec![ok_response("C1", "200.0", Some("100.0"))]),
    store.clone(),
    100,
  );

  let receipt = delivery.drain_due_once().await.expect("drain delivery");

  assert_eq!(
    receipt.expect("receipt").request_dedupe_key,
    "queued-1".to_owned()
  );
  let requests = delivery
    .http_client()
    .requests
    .lock()
    .expect("requests")
    .clone();
  assert_eq!(requests.len(), 1);
  assert_eq!(requests[0].json_value("channel").as_deref(), Some("C1"));
  assert_eq!(
    requests[0].json_value("thread_ts").as_deref(),
    Some("100.0")
  );
  assert_eq!(
    store
      .slack_delivery_status("workspace-1", "queued-1", 100)
      .await
      .expect("status")
      .expect("delivery")
      .status,
    SlackDeliveryStatusKind::Delivered
  );
}

#[tokio::test]
async fn drains_one_due_stop_stream_delivery() {
  let temp = tempdir().expect("tempdir");
  let store = StateStore::initialize(temp.path(), None)
    .await
    .expect("state store");
  store
    .enqueue_slack_stop_stream_delivery(
      &SlackStopStreamDeliveryRequest {
        connector_id: "connector-1".to_owned(),
        workspace_id: "workspace-1".to_owned(),
        request_dedupe_key: "stream-stop-1".to_owned(),
        channel_id: "C1".to_owned(),
        thread_ts: Some("100.0".to_owned()),
        message_ts: "200.0".to_owned(),
        text: "Final stream answer".to_owned(),
        sender: SlackDeliverySender::Bot,
      },
      100,
    )
    .await
    .expect("enqueue delivery");
  let delivery = queue(
    FakeHttpClient::with_responses(vec![ok_response("C1", "200.0", Some("100.0"))]),
    store.clone(),
    100,
  );

  let receipt = delivery.drain_due_once().await.expect("drain delivery");

  assert_eq!(
    receipt.expect("receipt").request_dedupe_key,
    "stream-stop-1".to_owned()
  );
  let requests = delivery
    .http_client()
    .requests
    .lock()
    .expect("requests")
    .clone();
  assert_eq!(requests.len(), 1);
  assert_eq!(requests[0].path(), "chat.stopStream");
  assert_eq!(requests[0].json_value("channel").as_deref(), Some("C1"));
  assert_eq!(requests[0].json_value("ts").as_deref(), Some("200.0"));
  assert_eq!(
    requests[0].json_value("markdown_text").as_deref(),
    Some("Final stream answer")
  );
  assert_eq!(
    store
      .slack_delivery_status("workspace-1", "stream-stop-1", 100)
      .await
      .expect("status")
      .expect("delivery")
      .status,
    SlackDeliveryStatusKind::Delivered
  );
}

#[tokio::test]
async fn queued_user_sender_uses_configured_user_token_and_records_sender() {
  let temp = tempdir().expect("tempdir");
  let store = StateStore::initialize(temp.path(), None)
    .await
    .expect("state store");
  let mut user_tokens = BTreeMap::new();
  user_tokens.insert(
    "example".to_owned(),
    SlackUserTokenConfig {
      user_id: "U0EXAMPLE".to_owned(),
      token_env: "CODEOFF_TEST_SLACK_EXAMPLE_USER_TOKEN".to_owned(),
    },
  );
  let config = SlackConfig {
    user_tokens,
    ..SlackConfig::default()
  };
  store
    .enqueue_slack_delivery(
      &SlackDeliveryRequest {
        connector_id: "connector-1".to_owned(),
        workspace_id: "workspace-1".to_owned(),
        request_dedupe_key: "user-queued-1".to_owned(),
        channel_id: "C1".to_owned(),
        thread_ts: None,
        text: "User queued".to_owned(),
        sender: SlackDeliverySender::User {
          key: "example".to_owned(),
        },
      },
      100,
    )
    .await
    .expect("enqueue delivery");
  let delivery = SlackDeliveryQueue::new(
    SlackWebApiClient::new_with_user_token_resolver(
      FakeHttpClient::with_responses(vec![ok_response("C1", "200.0", None)]),
      "connector-1",
      "xoxb-secret-token",
      config,
      100,
      Arc::new(|name| {
        if name == "CODEOFF_TEST_SLACK_EXAMPLE_USER_TOKEN" {
          Ok("xoxp-user-secret-token".to_owned())
        } else {
          Err(env::VarError::NotPresent)
        }
      }),
    ),
    store.clone(),
    100,
  );

  let receipt = delivery.drain_due_once().await.expect("drain delivery");

  assert_eq!(
    receipt.expect("receipt").request_dedupe_key,
    "user-queued-1".to_owned()
  );
  let requests = delivery
    .http_client()
    .requests
    .lock()
    .expect("requests")
    .clone();
  assert!(requests[0].authorization_is_bearer_token("xoxp-user-secret-token"));
  let status = store
    .slack_delivery_status("workspace-1", "user-queued-1", 100)
    .await
    .expect("status")
    .expect("delivery");
  assert_eq!(status.sender_kind, "user");
  assert_eq!(status.sender_key.as_deref(), Some("example"));
}

#[tokio::test]
async fn missing_user_sender_token_env_returns_clear_error_without_leaking_token_values() {
  let temp = tempdir().expect("tempdir");
  let store = StateStore::initialize(temp.path(), None)
    .await
    .expect("state store");
  let mut user_tokens = BTreeMap::new();
  user_tokens.insert(
    "example".to_owned(),
    SlackUserTokenConfig {
      user_id: "U0EXAMPLE".to_owned(),
      token_env: "CODEOFF_TEST_SLACK_EXAMPLE_MISSING_TOKEN".to_owned(),
    },
  );
  let config = SlackConfig {
    user_tokens,
    ..SlackConfig::default()
  };
  store
    .enqueue_slack_delivery(
      &SlackDeliveryRequest {
        connector_id: "connector-1".to_owned(),
        workspace_id: "workspace-1".to_owned(),
        request_dedupe_key: "missing-token-1".to_owned(),
        channel_id: "C1".to_owned(),
        thread_ts: None,
        text: "User queued".to_owned(),
        sender: SlackDeliverySender::User {
          key: "example".to_owned(),
        },
      },
      100,
    )
    .await
    .expect("enqueue delivery");
  let delivery = SlackDeliveryQueue::new(
    SlackWebApiClient::new_with_user_token_resolver(
      FakeHttpClient::with_responses(vec![ok_response("C1", "200.0", None)]),
      "connector-1",
      "xoxb-secret-token",
      config,
      100,
      Arc::new(|_| Err(env::VarError::NotPresent)),
    ),
    store,
    100,
  );

  let error = delivery
    .drain_due_once()
    .await
    .expect_err("missing token fails");

  let message = error.to_string();
  assert!(message.contains("CODEOFF_TEST_SLACK_EXAMPLE_MISSING_TOKEN"));
  assert!(message.contains("user:example"));
  assert!(!message.contains("xoxb-secret-token"));
  assert!(
    delivery
      .http_client()
      .requests
      .lock()
      .expect("requests")
      .is_empty()
  );
}

#[tokio::test]
async fn rate_limit_reschedules_delivery_using_retry_after_without_exposing_the_token() {
  let temp = tempdir().expect("tempdir");
  let store = StateStore::initialize(temp.path(), None)
    .await
    .expect("state store");
  let delivery = queue(
    FakeHttpClient::with_responses(vec![
      SlackHttpResponse::new(
        429,
        [("Retry-After", "17")],
        "xoxb-secret-token rate limited",
      ),
      ok_response("C1", "200.0", Some("100.0")),
    ]),
    store,
    100,
  );
  let request = ChannelMessageRequest::new(
    "connector-1",
    "workspace-1",
    "retry-1",
    ChannelReplyTarget::Thread {
      channel_id: "C1".to_owned(),
      thread_id: "100.0".to_owned(),
    },
    "Retry me",
  )
  .expect("request");

  let error = delivery.deliver(&request).await.expect_err("rate limited");
  assert!(matches!(
    error,
    SlackWebApiError::RateLimited {
      retry_after_seconds: Some(17)
    }
  ));
  assert!(!error.to_string().contains("xoxb-secret-token"));
  assert!(matches!(
    delivery.deliver(&request).await,
    Err(SlackWebApiError::Deferred { available_at: 117 })
  ));
  delivery.set_now_unix_seconds(117);
  delivery.deliver(&request).await.expect("retry delivery");
  assert_eq!(
    delivery
      .http_client()
      .requests
      .lock()
      .expect("requests")
      .len(),
    2
  );
}

#[tokio::test]
async fn throttles_distinct_messages_for_the_same_channel_for_one_second() {
  let temp = tempdir().expect("tempdir");
  let store = StateStore::initialize(temp.path(), None)
    .await
    .expect("state store");
  let delivery = queue(
    FakeHttpClient::with_responses(vec![
      ok_response("C1", "200.0", Some("100.0")),
      ok_response("C1", "201.0", Some("100.0")),
    ]),
    store,
    100,
  );
  let first = ChannelMessageRequest::new(
    "connector-1",
    "workspace-1",
    "throttle-1",
    ChannelReplyTarget::Thread {
      channel_id: "C1".to_owned(),
      thread_id: "100.0".to_owned(),
    },
    "First",
  )
  .expect("first request");
  let second = ChannelMessageRequest::new(
    "connector-1",
    "workspace-1",
    "throttle-2",
    ChannelReplyTarget::Thread {
      channel_id: "C1".to_owned(),
      thread_id: "100.0".to_owned(),
    },
    "Second",
  )
  .expect("second request");

  delivery.deliver(&first).await.expect("first delivery");
  assert!(matches!(
    delivery.deliver(&second).await,
    Err(SlackWebApiError::Deferred { available_at: 101 })
  ));
  delivery.set_now_unix_seconds(101);
  delivery.deliver(&second).await.expect("second delivery");
  assert_eq!(
    delivery
      .http_client()
      .requests
      .lock()
      .expect("requests")
      .len(),
    2
  );
}

#[tokio::test]
async fn provider_errors_are_reported_without_exposing_the_token() {
  let temp = tempdir().expect("tempdir");
  let store = StateStore::initialize(temp.path(), None)
    .await
    .expect("state store");
  let delivery = queue(
    FakeHttpClient::with_responses(vec![SlackHttpResponse::new(
      200,
      Vec::<(&str, &str)>::new(),
      r#"{"ok":false,"error":"invalid_auth xoxb-secret-token"}"#,
    )]),
    store,
    100,
  );
  let request = ChannelMessageRequest::new(
    "connector-1",
    "workspace-1",
    "provider-error-1",
    ChannelReplyTarget::Thread {
      channel_id: "C1".to_owned(),
      thread_id: "100.0".to_owned(),
    },
    "Provider error",
  )
  .expect("request");

  let error = delivery
    .deliver(&request)
    .await
    .expect_err("provider error");

  assert_eq!(
    error,
    SlackWebApiError::Provider {
      message: "invalid_auth <redacted>".to_owned()
    }
  );
  assert!(!error.to_string().contains("xoxb-secret-token"));
}
