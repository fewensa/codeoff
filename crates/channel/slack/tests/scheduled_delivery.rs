use std::collections::VecDeque;
use std::fmt::Write as _;
use std::sync::Mutex;

use async_trait::async_trait;
use codeoff_channel_slack::{
  SlackHttpClient, SlackHttpRequest, SlackHttpResponse, SlackScheduledDeliveryProvider,
  SlackWebApiClient,
};
use codeoff_config::SlackConfig;
use codeoff_runtime::scheduled_delivery::{
  DeliveryProvider, DeliveryProviderOutcome, DeliveryProviderReadiness,
  DeliveryProviderReadinessRequest, DeliveryProviderRequest,
};
use codeoff_state::{
  AttestedExecutionProfileSnapshot, CapabilityProfileSnapshot, ClaimedScheduledDelivery,
  CreateScheduledJob, DeliveryTargetSnapshot, PreparedScheduledDelivery, PrincipalKey,
  ScheduleSpec, ScheduledJobDefinition, ScheduledRunResult, SkippedNoneBaselinePolicy, StateStore,
};
use serde_json::{Value, json};
use tempfile::{TempDir, tempdir};

enum HttpStep {
  Response(SlackHttpResponse),
  Error(String),
}

struct FakeHttp {
  steps: Mutex<VecDeque<HttpStep>>,
  requests: Mutex<Vec<SlackHttpRequest>>,
}

impl FakeHttp {
  fn new(steps: impl IntoIterator<Item = HttpStep>) -> Self {
    Self {
      steps: Mutex::new(steps.into_iter().collect()),
      requests: Mutex::new(Vec::new()),
    }
  }

  fn requests(&self) -> Vec<SlackHttpRequest> {
    self.requests.lock().expect("requests").clone()
  }
}

#[async_trait]
impl SlackHttpClient for FakeHttp {
  async fn get(&self, _request: SlackHttpRequest) -> Result<SlackHttpResponse, String> {
    Err("unexpected GET".to_owned())
  }

  async fn post(&self, request: SlackHttpRequest) -> Result<SlackHttpResponse, String> {
    self.requests.lock().expect("requests").push(request);
    match self.steps.lock().expect("steps").pop_front() {
      Some(HttpStep::Response(response)) => Ok(response),
      Some(HttpStep::Error(error)) => Err(error),
      None => Err("unexpected request".to_owned()),
    }
  }
}

fn response(status: u16, body: impl Into<String>) -> HttpStep {
  HttpStep::Response(SlackHttpResponse::new(
    status,
    Vec::<(&str, &str)>::new(),
    body,
  ))
}

fn owner() -> PrincipalKey {
  PrincipalKey::new("user", "slack", "T00000000", "U1").expect("owner")
}

fn target_identity(kind: &str) -> String {
  match kind {
    "channel" => "1".repeat(64),
    "direct_message" => "2".repeat(64),
    "thread" => "3".repeat(64),
    _ => "4".repeat(64),
  }
}

async fn claimed_delivery(
  kind: &str,
  channel_id: &str,
  thread_ts: Option<&str>,
) -> (TempDir, StateStore, ClaimedScheduledDelivery) {
  let temp = tempdir().expect("tempdir");
  let store = StateStore::initialize(&temp.path().join("state"), None)
    .await
    .expect("state");
  let job_id = format!("slack-{kind}-{channel_id}");
  let coordinates = thread_ts.map_or_else(
    || json!({"channel_id": channel_id}),
    |thread_ts| json!({"channel_id": channel_id, "thread_ts": thread_ts}),
  );
  let identity = target_identity(kind);
  let address = json!({
    "schema_version": 1,
    "workspace_id": "T00000000",
    "routing_authority": {
      "team_id": "T00000000",
      "enterprise_id": "E00000000",
      "context_team_id": "T00000000",
      "conversation_host_id": "T00000000",
    },
    "coordinates": coordinates,
    "authorization_evidence": {"version": 2, "digest": "a".repeat(64)},
    "requested_identity_digest": "b".repeat(64),
    "created_at": 100,
  });
  let target = DeliveryTargetSnapshot::new(
    format!("target-{kind}"),
    "slack",
    "slack-default",
    "T00000000",
    kind,
    address.to_string(),
    1,
    "slack-web-api-v2",
    &identity,
  )
  .expect("target");
  store
    .create_scheduled_job(&CreateScheduledJob {
      job_id: job_id.clone(),
      schedule_id: format!("schedule-{job_id}"),
      definition: ScheduledJobDefinition::new(1, "{}").expect("definition"),
      creator: owner(),
      owner: owner(),
      capability: CapabilityProfileSnapshot::new(1, "none", "{}").expect("capability"),
      targets: vec![target],
      schedule: ScheduleSpec::once(110),
      now: 100,
    })
    .await
    .expect("create");
  store
    .materialize_due_schedule(&job_id, 0, 110)
    .await
    .expect("materialize");
  let run = store
    .claim_next_scheduled_run("run-worker", 111, 200)
    .await
    .expect("claim run")
    .expect("run");
  let profile =
    AttestedExecutionProfileSnapshot::new(1, "{}", "sha256-v1", "profile").expect("profile");
  store
    .mark_scheduled_run_executing(&run.binding, &profile, 112)
    .await
    .expect("executing");
  store
    .complete_scheduled_run_success(
      &run.binding,
      &ScheduledRunResult::new("exact UTF-8: 測試  \n", "").expect("result"),
      120,
    )
    .await
    .expect("complete");
  let delivery_id = delivery_id(run.binding.run_id(), &identity);
  assert!(matches!(
    store
      .prepare_scheduled_delivery(
        &delivery_id,
        "text/markdown; charset=utf-8",
        "exact UTF-8: 測試  \n",
        1,
        121,
        SkippedNoneBaselinePolicy::DoNotAdvance,
      )
      .await
      .expect("prepare"),
    PreparedScheduledDelivery::Pending(_)
  ));
  let claim = store
    .claim_next_scheduled_delivery("delivery-worker", 122, 200)
    .await
    .expect("claim delivery")
    .expect("delivery");
  (temp, store, claim)
}

fn delivery_id(run_id: &str, identity: &str) -> String {
  let mut value = String::from("intent:v1:");
  for byte in run_id.as_bytes() {
    write!(&mut value, "{byte:02x}").expect("write id");
  }
  write!(&mut value, ":{identity}:1").expect("write identity");
  value
}

#[tokio::test]
async fn sends_exact_channel_thread_and_dm_routes_and_returns_provider_identity() {
  for (kind, channel_id, thread_ts) in [
    ("channel", "C123", None),
    ("direct_message", "D123", None),
    ("thread", "C123", Some("100.000001")),
  ] {
    let (_temp, _store, claim) = claimed_delivery(kind, channel_id, thread_ts).await;
    let http = FakeHttp::new([response(
      200,
      json!({
        "ok": true,
        "channel": channel_id,
        "ts": "200.000001",
        "team_id": "T00000000",
        "message": {"ts": "200.000001", "thread_ts": thread_ts},
      })
      .to_string(),
    )]);
    let provider = SlackScheduledDeliveryProvider::new(SlackWebApiClient::new(
      http,
      "slack-default",
      "xoxb-secret",
      SlackConfig::default(),
      100,
    ));
    let outcome = provider
      .send(DeliveryProviderRequest {
        payload: &claim.payload,
        target_json: &claim.target_json,
        idempotency_key: claim.binding.idempotency_key(),
      })
      .await;
    assert_eq!(
      outcome,
      DeliveryProviderOutcome::ConfirmedSuccess(
        codeoff_runtime::scheduled_delivery::ProviderMessageIdentity {
          provider: "slack".to_owned(),
          tenant: "T00000000".to_owned(),
          conversation_id: channel_id.to_owned(),
          thread_id: thread_ts.map(ToOwned::to_owned),
          message_id: "200.000001".to_owned(),
        }
      )
    );
    let requests = provider.http_client().requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].path(), "chat.postMessage");
    assert_eq!(
      requests[0].json_value("channel").as_deref(),
      Some(channel_id)
    );
    assert_eq!(requests[0].json_value("thread_ts").as_deref(), thread_ts);
    assert_eq!(
      requests[0].json_value("text").as_deref(),
      Some("exact UTF-8: 測試  \n")
    );
    let expected_keys = if thread_ts.is_some() {
      vec![
        "channel".to_owned(),
        "text".to_owned(),
        "thread_ts".to_owned(),
      ]
    } else {
      vec!["channel".to_owned(), "text".to_owned()]
    };
    assert_eq!(requests[0].json_keys(), Some(expected_keys));
  }
}

#[tokio::test]
async fn success_requires_exact_canonical_message_and_thread_identity() {
  for (kind, requested_thread, response_body) in [
    (
      "channel",
      None,
      json!({"ok":true,"channel":"C999","ts":"200.000001","message":{"ts":"200.000001"}}),
    ),
    (
      "channel",
      None,
      json!({"ok":true,"channel":"C123","ts":"malformed","message":{"ts":"malformed"}}),
    ),
    (
      "channel",
      None,
      json!({"ok":true,"channel":"C123","ts":"200.000001","message":{}}),
    ),
    (
      "channel",
      None,
      json!({"ok":true,"channel":"C123","ts":"200.000001","message":{"ts":"200.000001","thread_ts":"100.000001"}}),
    ),
    (
      "thread",
      Some("100.000001"),
      json!({"ok":true,"channel":"C123","ts":"200.000001","message":{"ts":"200.000001"}}),
    ),
    (
      "thread",
      Some("100.000001"),
      json!({"ok":true,"channel":"C123","ts":"200.000001","message":{"ts":"200.000001","thread_ts":"100.000002"}}),
    ),
    (
      "thread",
      Some("100.000001"),
      json!({"ok":true,"channel":"C123","ts":"200.000001","team_id":"T99999999","message":{"ts":"200.000001","thread_ts":"100.000001"}}),
    ),
  ] {
    let (_temp, _store, claim) = claimed_delivery(kind, "C123", requested_thread).await;
    let provider = SlackScheduledDeliveryProvider::new(SlackWebApiClient::new(
      FakeHttp::new([response(200, response_body.to_string())]),
      "slack-default",
      "xoxb-secret",
      SlackConfig::default(),
      100,
    ));
    assert_eq!(
      provider
        .send(DeliveryProviderRequest {
          payload: &claim.payload,
          target_json: &claim.target_json,
          idempotency_key: claim.binding.idempotency_key(),
        })
        .await,
      DeliveryProviderOutcome::AmbiguousPostWrite {
        error_kind: "slack_response_route_mismatch".to_owned(),
      }
    );
  }
}

#[tokio::test]
async fn classifies_explicit_rejection_rate_limit_and_maybe_written_failures() {
  let (_temp, _store, claim) = claimed_delivery("channel", "C123", None).await;
  for (step, expected) in [
    (
      response(
        200,
        r#"{"ok":false,"error":"missing_scope","token":"xoxb-secret"}"#,
      ),
      DeliveryProviderOutcome::ConfirmedNoWriteTerminal {
        error_kind: "slack_request_rejected".to_owned(),
      },
    ),
    (
      HttpStep::Response(SlackHttpResponse::new(
        429,
        [("Retry-After", "17")],
        r#"{"ok":false,"error":"ratelimited"}"#,
      )),
      DeliveryProviderOutcome::ConfirmedNoWriteRetryable {
        retry_after_seconds: Some(17),
        error_kind: "slack_rate_limited".to_owned(),
      },
    ),
    (
      response(503, "private response body"),
      DeliveryProviderOutcome::AmbiguousPostWrite {
        error_kind: "slack_write_outcome_unknown".to_owned(),
      },
    ),
    (
      response(200, "malformed private response"),
      DeliveryProviderOutcome::AmbiguousPostWrite {
        error_kind: "slack_write_outcome_unknown".to_owned(),
      },
    ),
    (
      HttpStep::Error("write then disconnect xoxb-secret private body".to_owned()),
      DeliveryProviderOutcome::AmbiguousPostWrite {
        error_kind: "slack_write_outcome_unknown".to_owned(),
      },
    ),
  ] {
    let provider = SlackScheduledDeliveryProvider::new(SlackWebApiClient::new(
      FakeHttp::new([step]),
      "slack-default",
      "xoxb-secret",
      SlackConfig::default(),
      100,
    ));
    let outcome = provider
      .send(DeliveryProviderRequest {
        payload: &claim.payload,
        target_json: &claim.target_json,
        idempotency_key: claim.binding.idempotency_key(),
      })
      .await;
    assert_eq!(outcome, expected);
    let rendered = format!("{outcome:?}");
    assert!(!rendered.contains("xoxb-secret"));
    assert!(!rendered.contains("private"));
  }
}

#[tokio::test]
async fn invalid_or_cross_workspace_target_fails_before_http_dispatch() {
  let (_temp, _store, claim) = claimed_delivery("channel", "C123", None).await;
  let mut target: Value = serde_json::from_str(&claim.target_json).expect("target");
  target["tenant"] = json!("T99999999");
  let target = target.to_string();
  let provider = SlackScheduledDeliveryProvider::new(SlackWebApiClient::new(
    FakeHttp::new([]),
    "slack-default",
    "xoxb-secret",
    SlackConfig::default(),
    100,
  ));
  assert_eq!(
    provider
      .send(DeliveryProviderRequest {
        payload: &claim.payload,
        target_json: &target,
        idempotency_key: claim.binding.idempotency_key(),
      })
      .await,
    DeliveryProviderOutcome::ConfirmedNoWriteTerminal {
      error_kind: "slack_target_authority_mismatch".to_owned(),
    }
  );
  assert!(provider.http_client().requests().is_empty());
}

#[tokio::test]
async fn authority_preflight_accepts_only_the_configured_workspace() {
  let matching = SlackScheduledDeliveryProvider::new(SlackWebApiClient::new(
    FakeHttp::new([response(
      200,
      r#"{"ok":true,"team_id":"T00000000","enterprise_id":"E00000000","user_id":"U123","bot_id":"B123"}"#,
    )]),
    "slack-default",
    "xoxb-secret",
    SlackConfig::default(),
    100,
  ));
  matching
    .verify_authority()
    .await
    .expect("matching authority");
  assert_eq!(matching.http_client().requests().len(), 1);
  assert_eq!(matching.http_client().requests()[0].path(), "auth.test");

  let mismatched = SlackScheduledDeliveryProvider::new(SlackWebApiClient::new(
    FakeHttp::new([response(
      200,
      r#"{"ok":true,"team_id":"T99999999","user_id":"U123","bot_id":"B123"}"#,
    )]),
    "slack-default",
    "xoxb-secret",
    SlackConfig::default(),
    100,
  ));
  assert!(mismatched.verify_authority().await.is_err());
  let requests = mismatched.http_client().requests();
  assert_eq!(requests.len(), 1);
  assert_eq!(requests[0].path(), "auth.test");
  assert!(
    !requests
      .iter()
      .any(|request| request.path() == "chat.postMessage")
  );
}

#[tokio::test]
async fn readiness_validates_target_before_auth_and_classifies_auth_availability() {
  let (_temp, _store, claim) = claimed_delivery("channel", "C123", None).await;
  let invalid = SlackScheduledDeliveryProvider::new(SlackWebApiClient::new(
    FakeHttp::new([]),
    "slack-default",
    "xoxb-secret",
    SlackConfig::default(),
    100,
  ));
  assert_eq!(
    invalid
      .readiness(DeliveryProviderReadinessRequest {
        target_json: r#"{"provider":"email"}"#,
      })
      .await,
    DeliveryProviderReadiness::Permanent {
      error_kind: "invalid_slack_target".to_owned(),
    }
  );
  assert!(invalid.http_client().requests().is_empty());

  let transient = SlackScheduledDeliveryProvider::new(SlackWebApiClient::new(
    FakeHttp::new([response(503, "private response")]),
    "slack-default",
    "xoxb-secret",
    SlackConfig::default(),
    100,
  ));
  assert_eq!(
    transient
      .readiness(DeliveryProviderReadinessRequest {
        target_json: &claim.target_json,
      })
      .await,
    DeliveryProviderReadiness::Retryable {
      retry_after_seconds: None,
      error_kind: "slack_authority_unavailable".to_owned(),
    }
  );
  assert_eq!(transient.http_client().requests()[0].path(), "auth.test");
}
