use std::sync::{Arc, Mutex};

use codeoff_channel_slack::{
  SlackHttpClient, SlackHttpRequest, SlackHttpResponse, SlackScheduleTargetVerifier,
  SlackWebApiClient,
};
use codeoff_config::SlackConfig;
use codeoff_runtime::schedule_service::{
  ChannelTargetVerifier, SlackTargetResolutionRequest, TargetVerificationError,
};
use serde_json::{Value, json};

#[derive(Clone, Default)]
struct FakeHttpClient {
  inner: Arc<FakeHttpInner>,
}

#[derive(Default)]
struct FakeHttpInner {
  responses: Mutex<Vec<SlackHttpResponse>>,
  requests: Mutex<Vec<SlackHttpRequest>>,
}

impl FakeHttpClient {
  fn with_responses(responses: Vec<SlackHttpResponse>) -> Self {
    Self {
      inner: Arc::new(FakeHttpInner {
        responses: Mutex::new(responses.into_iter().rev().collect()),
        requests: Mutex::default(),
      }),
    }
  }

  fn respond(&self, request: SlackHttpRequest) -> Result<SlackHttpResponse, String> {
    self.inner.requests.lock().expect("requests").push(request);
    self
      .inner
      .responses
      .lock()
      .expect("responses")
      .pop()
      .ok_or_else(|| "unexpected Slack request with xoxb-redacted".to_owned())
  }

  fn requests(&self) -> Vec<SlackHttpRequest> {
    self.inner.requests.lock().expect("requests").clone()
  }
}

#[async_trait::async_trait]
impl SlackHttpClient for FakeHttpClient {
  async fn get(&self, request: SlackHttpRequest) -> Result<SlackHttpResponse, String> {
    self.respond(request)
  }

  async fn post(&self, request: SlackHttpRequest) -> Result<SlackHttpResponse, String> {
    self.respond(request)
  }
}

fn response(body: impl Into<String>) -> SlackHttpResponse {
  SlackHttpResponse::new(200, Vec::<(&str, &str)>::new(), body)
}

fn rate_limited() -> SlackHttpResponse {
  SlackHttpResponse::new(
    429,
    [("retry-after", "30")],
    "rate limited body must not escape",
  )
}

fn verifier(
  responses: Vec<SlackHttpResponse>,
) -> (SlackScheduleTargetVerifier<FakeHttpClient>, FakeHttpClient) {
  verifier_with_config(responses, SlackConfig::default())
}

fn verifier_with_config(
  responses: Vec<SlackHttpResponse>,
  config: SlackConfig,
) -> (SlackScheduleTargetVerifier<FakeHttpClient>, FakeHttpClient) {
  let http = FakeHttpClient::with_responses(responses);
  let provider = Arc::new(SlackWebApiClient::new(
    http.clone(),
    "slack-default",
    "xoxb-test-secret",
    config,
    100,
  ));
  (SlackScheduleTargetVerifier::new(provider), http)
}

fn auth() -> SlackHttpResponse {
  response(
    r#"{"ok":true,"team_id":"T00000000","enterprise_id":"E00000000","user_id":"U0BOT","bot_id":"B0BOT"}"#,
  )
}

fn local_user(user_id: &str) -> SlackHttpResponse {
  response(
    json!({
      "ok": true,
      "user": {
        "id": user_id,
        "team_id": "T00000000",
        "deleted": false,
        "is_bot": false,
        "is_app_user": false,
        "is_restricted": false,
        "is_ultra_restricted": false,
        "profile": {},
      }
    })
    .to_string(),
  )
}

#[allow(clippy::needless_pass_by_value)]
fn user_with(user_id: &str, extra: Value) -> SlackHttpResponse {
  let mut user = json!({
    "id": user_id,
    "team_id": "T00000000",
    "deleted": false,
    "is_bot": false,
    "is_app_user": false,
    "is_restricted": false,
    "is_ultra_restricted": false,
    "profile": {},
  });
  user
    .as_object_mut()
    .expect("user")
    .extend(extra.as_object().expect("extra").clone());
  response(json!({"ok": true, "user": user}).to_string())
}

#[allow(clippy::needless_pass_by_value)]
fn channel_info(id: &str, extra: Value) -> SlackHttpResponse {
  let mut channel = json!({
    "id": id,
    "is_member": true,
    "context_team_id": "T00000000",
    "enterprise_id": "E00000000",
    "conversation_host_id": "T00000000",
    "shared_team_ids": ["T00000000"],
  });
  channel
    .as_object_mut()
    .expect("channel")
    .extend(extra.as_object().expect("extra").clone());
  response(json!({"ok": true, "channel": channel}).to_string())
}

fn dm_info(id: &str) -> SlackHttpResponse {
  channel_info(id, json!({"is_im": true, "is_private": true}))
}

fn members(ids: &[&str]) -> SlackHttpResponse {
  response(
    json!({
      "ok": true,
      "members": ids,
      "response_metadata": {"next_cursor": ""},
    })
    .to_string(),
  )
}

fn channel_target(id: &str) -> SlackTargetResolutionRequest {
  SlackTargetResolutionRequest::Channel {
    channel_id: id.to_owned(),
  }
}

fn dm_user_target(id: &str) -> SlackTargetResolutionRequest {
  SlackTargetResolutionRequest::DirectMessageUser {
    user_id: id.to_owned(),
  }
}

fn thread_target(channel_id: &str, thread_ts: &str) -> SlackTargetResolutionRequest {
  SlackTargetResolutionRequest::Thread {
    channel_id: channel_id.to_owned(),
    thread_ts: thread_ts.to_owned(),
  }
}

#[tokio::test]
async fn dm_open_accepts_enriched_and_official_id_only_responses_with_exact_request() {
  for opened in [
    r#"{"ok":true,"channel":{"id":"D2","is_im":true}}"#,
    r#"{"ok":true,"channel":{"id":"D2"}}"#,
  ] {
    let (verifier, http) = verifier(vec![
      auth(),
      local_user("U2"),
      response(opened),
      dm_info("D2"),
    ]);
    let resolved = verifier
      .resolve_target(None, None, &dm_user_target("U2"))
      .await
      .expect("canonical DM");
    assert_eq!(resolved.kind, "direct_message");
    assert_eq!(resolved.channel_id, "D2");
    assert_eq!(resolved.workspace_id, "T00000000");
    assert_eq!(resolved.enterprise_id.as_deref(), Some("E00000000"));
    let requests = http.requests();
    assert_eq!(
      requests
        .iter()
        .map(SlackHttpRequest::path)
        .collect::<Vec<_>>(),
      [
        "auth.test",
        "users.info",
        "conversations.open",
        "conversations.info"
      ]
    );
    assert_eq!(requests[2].json_value("users").as_deref(), Some("U2"));
    assert_eq!(requests[2].json_boolean_value("return_im"), Some(true));
    assert_eq!(
      requests[2].json_keys(),
      Some(vec!["return_im".to_owned(), "users".to_owned()])
    );
    assert!(
      requests
        .iter()
        .all(|request| request.authorization_is_bearer_token("xoxb-test-secret"))
    );
  }
}

#[tokio::test]
async fn repeated_dm_open_is_stable_and_reproves_the_same_canonical_conversation() {
  let (verifier, http) = verifier(vec![
    auth(),
    local_user("U2"),
    response(r#"{"ok":true,"channel":{"id":"D2"}}"#),
    dm_info("D2"),
    auth(),
    local_user("U2"),
    response(r#"{"ok":true,"already_open":true,"channel":{"id":"D2","is_im":true}}"#),
    dm_info("D2"),
  ]);
  let first = verifier
    .resolve_target(None, None, &dm_user_target("U2"))
    .await
    .expect("first");
  let second = verifier
    .resolve_target(None, None, &dm_user_target("U2"))
    .await
    .expect("second");
  assert_eq!(first, second);
  assert_eq!(
    http
      .requests()
      .iter()
      .filter(|request| request.path() == "conversations.info")
      .count(),
    2
  );
}

#[tokio::test]
async fn dm_rejects_wrong_kind_and_invalid_deleted_bot_app_slackbot_or_restricted_user() {
  let (wrong_kind, _) = verifier(vec![
    auth(),
    local_user("U2"),
    response(r#"{"ok":true,"channel":{"id":"C2"}}"#),
  ]);
  assert_eq!(
    wrong_kind
      .resolve_target(None, None, &dm_user_target("U2"))
      .await,
    Err(TargetVerificationError::Invalid)
  );

  for (user_id, extra) in [
    ("U2", json!({"deleted": true})),
    ("U2", json!({"is_bot": true})),
    ("U2", json!({"is_app_user": true})),
    ("USLACKBOT", json!({})),
    ("U2", json!({"is_restricted": true})),
    ("U2", json!({"is_ultra_restricted": true})),
  ] {
    let (verifier, http) = verifier(vec![auth(), user_with(user_id, extra)]);
    assert_eq!(
      verifier
        .resolve_target(None, None, &dm_user_target(user_id))
        .await,
      Err(TargetVerificationError::Invalid)
    );
    assert_eq!(
      http.requests().len(),
      2,
      "must fail before conversations.open"
    );
  }

  let (mismatched_user, _) = verifier(vec![auth(), local_user("U3")]);
  assert_eq!(
    mismatched_user
      .resolve_target(None, None, &dm_user_target("U2"))
      .await,
    Err(TargetVerificationError::Invalid)
  );
}

#[tokio::test]
async fn dm_classifies_open_and_info_failures_without_retrying_deterministic_errors() {
  for (responses, expected) in [
    (
      vec![
        auth(),
        local_user("U2"),
        response(r#"{"ok":false,"error":"missing_scope"}"#),
      ],
      TargetVerificationError::Unauthorized,
    ),
    (
      vec![
        auth(),
        local_user("U2"),
        response(r#"{"ok":true,"channel":{"id":"D2"}}"#),
        response(r#"{"ok":false,"error":"channel_not_found"}"#),
      ],
      TargetVerificationError::Invalid,
    ),
    (
      vec![auth(), local_user("U2"), rate_limited()],
      TargetVerificationError::Transient,
    ),
  ] {
    let (verifier, _) = verifier(responses);
    assert_eq!(
      verifier
        .resolve_target(None, None, &dm_user_target("U2"))
        .await,
      Err(expected)
    );
  }
}

#[tokio::test]
async fn thread_root_accepts_absent_or_self_thread_ts_and_rejects_reply_missing_or_wrong_channel() {
  for root in [
    r#"{"ok":true,"messages":[{"ts":"100.000000"}]}"#,
    r#"{"ok":true,"messages":[{"ts":"100.000000","thread_ts":"100.000000"}]}"#,
  ] {
    let (verifier, _) = verifier(vec![auth(), channel_info("C1", json!({})), response(root)]);
    let resolved = verifier
      .resolve_target(None, None, &thread_target("C1", "100.000000"))
      .await
      .expect("root");
    assert_eq!(resolved.kind, "thread");
    assert_eq!(resolved.thread_ts.as_deref(), Some("100.000000"));
  }

  for reply_response in [
    r#"{"ok":true,"messages":[{"ts":"100.000000","thread_ts":"100.000000"}]}"#,
    r#"{"ok":true,"messages":[]}"#,
  ] {
    let (verifier, _) = verifier(vec![
      auth(),
      channel_info("C1", json!({})),
      response(reply_response),
    ]);
    assert_eq!(
      verifier
        .resolve_target(None, None, &thread_target("C1", "101.000000"))
        .await,
      Err(TargetVerificationError::Invalid)
    );
  }

  let (not_found, _) = verifier(vec![
    auth(),
    channel_info("C1", json!({})),
    response(r#"{"ok":false,"error":"thread_not_found"}"#),
  ]);
  assert_eq!(
    not_found
      .resolve_target(None, None, &thread_target("C1", "100.000000"))
      .await,
    Err(TargetVerificationError::Invalid)
  );
}

#[tokio::test]
async fn auth_config_invocation_conversation_and_user_authority_fail_closed() {
  let wrong_config = SlackConfig {
    workspace_id: "TOTHER".to_owned(),
    ..SlackConfig::default()
  };
  let (config_mismatch, http) = verifier_with_config(vec![auth()], wrong_config);
  assert_eq!(
    config_mismatch
      .resolve_target(None, None, &channel_target("C1"))
      .await,
    Err(TargetVerificationError::Unauthorized)
  );
  assert_eq!(http.requests().len(), 1);

  let (invocation_mismatch, _) = verifier(vec![auth()]);
  assert_eq!(
    invocation_mismatch
      .resolve_target(Some("TOTHER"), Some("U1"), &channel_target("C1"))
      .await,
    Err(TargetVerificationError::Unauthorized)
  );

  let (revoked, _) = verifier(vec![response(r#"{"ok":false,"error":"token_revoked"}"#)]);
  assert_eq!(
    revoked
      .resolve_target(None, None, &channel_target("C1"))
      .await,
    Err(TargetVerificationError::Unauthorized)
  );

  let (wrong_context, _) = verifier(vec![
    auth(),
    channel_info("C1", json!({"context_team_id": "TOTHER"})),
  ]);
  assert_eq!(
    wrong_context
      .resolve_target(None, None, &channel_target("C1"))
      .await,
    Err(TargetVerificationError::Unauthorized)
  );

  let (foreign_user, _) = verifier(vec![auth(), user_with("U2", json!({"team_id": "TOTHER"}))]);
  assert_eq!(
    foreign_user
      .resolve_target(None, None, &dm_user_target("U2"))
      .await,
    Err(TargetVerificationError::Unauthorized)
  );
}

#[tokio::test]
async fn enterprise_user_and_shared_conversation_require_unambiguous_provider_authority() {
  let enterprise_user = user_with(
    "U2",
    json!({
      "team_id": "TOTHER",
      "enterprise_user": {"enterprise_id": "E00000000", "teams": ["T00000000", "TOTHER"]},
    }),
  );
  let (allowed, _) = verifier(vec![
    auth(),
    enterprise_user,
    response(r#"{"ok":true,"channel":{"id":"D2"}}"#),
    dm_info("D2"),
  ]);
  assert!(
    allowed
      .resolve_target(None, None, &dm_user_target("U2"))
      .await
      .is_ok()
  );

  let shared = json!({
    "is_shared": true,
    "is_ext_shared": true,
    "shared_team_ids": ["T00000000", "TEXTERNAL"],
    "connected_team_ids": ["TEXTERNAL"],
    "conversation_host_id": "TEXTERNAL",
  });
  let (allowed_shared, _) = verifier(vec![auth(), channel_info("C1", shared)]);
  let resolved = allowed_shared
    .resolve_target(None, None, &channel_target("C1"))
    .await
    .expect("shared channel");
  assert_eq!(resolved.conversation_host_id, "TEXTERNAL");

  for ambiguous in [
    json!({"is_shared": true, "is_ext_shared": true, "shared_team_ids": ["T00000000", "TEXTERNAL"], "conversation_host_id": null}),
    json!({"is_shared": true, "is_ext_shared": true, "shared_team_ids": ["TEXTERNAL"], "conversation_host_id": "TEXTERNAL"}),
    json!({"is_shared": true, "is_ext_shared": true, "shared_team_ids": ["T00000000"], "conversation_host_id": "EEXTERNAL"}),
  ] {
    let (verifier, _) = verifier(vec![auth(), channel_info("C1", ambiguous)]);
    assert_eq!(
      verifier
        .resolve_target(None, None, &channel_target("C1"))
        .await,
      Err(TargetVerificationError::Unauthorized)
    );
  }
}

#[tokio::test]
async fn channel_kind_archive_bot_and_caller_membership_matrix_is_enforced() {
  for (extra, expected) in [
    (json!({"is_private": false}), None),
    (json!({"is_private": true}), None),
    (
      json!({"is_im": true}),
      Some(TargetVerificationError::Invalid),
    ),
    (
      json!({"is_mpim": true}),
      Some(TargetVerificationError::Invalid),
    ),
    (
      json!({"is_archived": true}),
      Some(TargetVerificationError::Unavailable),
    ),
    (
      json!({"is_member": false}),
      Some(TargetVerificationError::Unauthorized),
    ),
  ] {
    let (verifier, _) = verifier(vec![auth(), channel_info("C1", extra)]);
    let result = verifier
      .resolve_target(None, None, &channel_target("C1"))
      .await;
    assert_eq!(result.err(), expected);
  }

  let (actor_allowed, _) = verifier(vec![
    auth(),
    local_user("U1"),
    channel_info("C1", json!({})),
    members(&["U1"]),
  ]);
  assert!(
    actor_allowed
      .resolve_target(Some("T00000000"), Some("U1"), &channel_target("C1"))
      .await
      .is_ok()
  );

  let (actor_denied, _) = verifier(vec![
    auth(),
    local_user("U1"),
    channel_info("C1", json!({})),
    members(&["U2"]),
  ]);
  assert_eq!(
    actor_denied
      .resolve_target(Some("T00000000"), Some("U1"), &channel_target("C1"))
      .await,
    Err(TargetVerificationError::Unauthorized)
  );
}

#[tokio::test]
async fn api_error_classification_is_exhaustive_redacted_and_retryable_only_when_transient() {
  for (code, expected) in [
    ("invalid_arguments", TargetVerificationError::Invalid),
    ("channel_not_found", TargetVerificationError::Invalid),
    ("missing_scope", TargetVerificationError::Unauthorized),
    ("invalid_auth", TargetVerificationError::Unauthorized),
    ("user_not_visible", TargetVerificationError::Unauthorized),
    ("is_archived", TargetVerificationError::Unavailable),
    ("org_login_required", TargetVerificationError::Unavailable),
    ("internal_error", TargetVerificationError::Transient),
    ("service_unavailable", TargetVerificationError::Transient),
    ("future_unknown_error", TargetVerificationError::Unavailable),
  ] {
    let (verifier, _) = verifier(vec![
      auth(),
      response(
        json!({"ok": false, "error": code, "token": "xoxb-secret", "body": "private"}).to_string(),
      ),
    ]);
    let result = verifier
      .resolve_target(None, None, &channel_target("C1"))
      .await;
    assert_eq!(result, Err(expected), "classification for {code}");
    let rendered = format!("{result:?}");
    assert!(!rendered.contains("xoxb-secret"));
    assert!(!rendered.contains("private"));
  }

  let (transport, _) = verifier(vec![auth()]);
  assert_eq!(
    transport
      .resolve_target(None, None, &channel_target("C1"))
      .await,
    Err(TargetVerificationError::Transient)
  );
}
