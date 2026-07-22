use std::sync::{Arc, Mutex};

use codeoff_channel_slack::{
  SlackHttpClient, SlackHttpRequest, SlackHttpResponse, SlackScheduleTargetVerifier,
  SlackWebApiClient,
};
use codeoff_config::SlackConfig;
use codeoff_runtime::schedule_service::{
  ChannelTargetVerifier, SlackTargetResolutionRequest, TargetVerificationError,
};

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

  fn respond(&self, request: SlackHttpRequest) -> Result<SlackHttpResponse, String> {
    self.requests.lock().expect("requests").push(request);
    self
      .responses
      .lock()
      .expect("responses")
      .pop()
      .ok_or_else(|| "unexpected Slack request with xoxb-redacted".to_owned())
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

fn response(body: &str) -> SlackHttpResponse {
  SlackHttpResponse::new(200, Vec::<(&str, &str)>::new(), body)
}

fn verifier(responses: Vec<SlackHttpResponse>) -> SlackScheduleTargetVerifier<FakeHttpClient> {
  SlackScheduleTargetVerifier::new(Arc::new(SlackWebApiClient::new(
    FakeHttpClient::with_responses(responses),
    "slack-default",
    "xoxb-test-secret",
    SlackConfig::default(),
    100,
  )))
}

fn channel_info(id: &str, extra: &str) -> SlackHttpResponse {
  response(&format!(
    r#"{{"ok":true,"channel":{{"id":"{id}","is_member":true{extra}}}}}"#
  ))
}

fn members(ids: &[&str]) -> SlackHttpResponse {
  response(&format!(
    r#"{{"ok":true,"members":{},"response_metadata":{{"next_cursor":""}}}}"#,
    serde_json::to_string(ids).expect("members")
  ))
}

#[tokio::test]
async fn resolves_channel_dm_and_root_thread_to_canonical_coordinates() {
  let channel = verifier(vec![channel_info("C1", ""), members(&["U1"])]);
  let resolved = channel
    .resolve_target(
      Some("T00000000"),
      Some("U1"),
      &SlackTargetResolutionRequest::Channel {
        channel_id: "C1".to_owned(),
      },
    )
    .await
    .expect("channel");
  assert_eq!(resolved.kind, "channel");
  assert_eq!(resolved.channel_id, "C1");
  assert_eq!(resolved.thread_ts, None);

  let dm = verifier(vec![
    response(r#"{"ok":true,"user":{"id":"U2","profile":{}}}"#),
    response(r#"{"ok":true,"channel":{"id":"D2","is_im":true}}"#),
  ]);
  let resolved = dm
    .resolve_target(
      None,
      None,
      &SlackTargetResolutionRequest::DirectMessageUser {
        user_id: "U2".to_owned(),
      },
    )
    .await
    .expect("dm");
  assert_eq!(resolved.kind, "direct_message");
  assert_eq!(resolved.channel_id, "D2");
  assert_eq!(resolved.thread_ts, None);

  let thread = verifier(vec![
    channel_info("C1", ""),
    members(&["U1"]),
    response(r#"{"ok":true,"messages":[{"ts":"100.000000"}]}"#),
  ]);
  let resolved = thread
    .resolve_target(
      Some("T00000000"),
      Some("U1"),
      &SlackTargetResolutionRequest::Thread {
        channel_id: "C1".to_owned(),
        thread_ts: "100.000000".to_owned(),
      },
    )
    .await
    .expect("thread");
  assert_eq!(resolved.kind, "thread");
  assert_eq!(resolved.thread_ts.as_deref(), Some("100.000000"));
  assert_eq!(resolved.authorization_evidence_digest.len(), 64);
}

#[tokio::test]
async fn fails_closed_for_workspace_actor_visibility_archive_kind_and_reply_parent() {
  let workspace = verifier(Vec::new());
  assert_eq!(
    workspace
      .resolve_target(
        Some("T-OTHER"),
        Some("U1"),
        &SlackTargetResolutionRequest::Channel {
          channel_id: "C1".to_owned(),
        },
      )
      .await,
    Err(TargetVerificationError::Unauthorized)
  );

  for (channel_response, expected) in [
    (
      channel_info("C1", ",\"is_archived\":true"),
      TargetVerificationError::Unavailable,
    ),
    (
      channel_info("D1", ",\"is_im\":true"),
      TargetVerificationError::Unavailable,
    ),
    (
      response(r#"{"ok":true,"channel":{"id":"C1","is_member":false}}"#),
      TargetVerificationError::Unavailable,
    ),
  ] {
    let verifier = verifier(vec![channel_response]);
    assert_eq!(
      verifier
        .resolve_target(
          Some("T00000000"),
          Some("U1"),
          &SlackTargetResolutionRequest::Channel {
            channel_id: "C1".to_owned(),
          },
        )
        .await,
      Err(expected)
    );
  }

  let unauthorized = verifier(vec![channel_info("C1", ""), members(&["U2"])]);
  assert_eq!(
    unauthorized
      .resolve_target(
        Some("T00000000"),
        Some("U1"),
        &SlackTargetResolutionRequest::Channel {
          channel_id: "C1".to_owned(),
        },
      )
      .await,
    Err(TargetVerificationError::Unauthorized)
  );

  let reply_parent = verifier(vec![
    channel_info("C1", ""),
    members(&["U1"]),
    response(r#"{"ok":true,"messages":[{"ts":"101.000000","thread_ts":"100.000000"}]}"#),
  ]);
  assert_eq!(
    reply_parent
      .resolve_target(
        Some("T00000000"),
        Some("U1"),
        &SlackTargetResolutionRequest::Thread {
          channel_id: "C1".to_owned(),
          thread_ts: "101.000000".to_owned(),
        },
      )
      .await,
    Err(TargetVerificationError::Invalid)
  );
}

#[tokio::test]
async fn classifies_dm_provider_and_transport_failures_without_secret_leakage() {
  let unavailable = verifier(vec![response(
    r#"{"ok":false,"error":"channel_not_found"}"#,
  )]);
  assert_eq!(
    unavailable
      .resolve_target(
        None,
        None,
        &SlackTargetResolutionRequest::DirectMessageConversation {
          channel_id: "D1".to_owned(),
        },
      )
      .await,
    Err(TargetVerificationError::Unavailable)
  );

  let transient = verifier(Vec::new());
  assert_eq!(
    transient
      .resolve_target(
        None,
        None,
        &SlackTargetResolutionRequest::DirectMessageUser {
          user_id: "U1".to_owned(),
        },
      )
      .await,
    Err(TargetVerificationError::Transient)
  );
}
