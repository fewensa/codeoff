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
  DeliveryProviderReadinessRequest, DeliveryProviderRequest, ScheduledDeliveryTickOutcome,
  run_scheduled_delivery_tick,
};
use codeoff_state::{
  AcceptedDeliveryBaselineIdentity, AttestedExecutionProfileSnapshot, CapabilityProfileSnapshot,
  ClaimedScheduledDelivery, CreateScheduledJob, DeliveryTargetSnapshot, PreparedScheduledDelivery,
  PrincipalKey, ScheduleSpec, ScheduledJobDefinition, ScheduledRunResult,
  SkippedNoneBaselinePolicy, StateStore,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
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
  async fn get(&self, request: SlackHttpRequest) -> Result<SlackHttpResponse, String> {
    self.requests.lock().expect("requests").push(request);
    match self.steps.lock().expect("steps").pop_front() {
      Some(HttpStep::Response(response)) => Ok(response),
      Some(HttpStep::Error(error)) => Err(error),
      None => Err("unexpected request".to_owned()),
    }
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

fn live_channel(channel_id: &str) -> HttpStep {
  response(
    200,
    json!({
      "ok": true,
      "channel": {
        "id": channel_id,
        "is_member": true,
        "context_team_id": "T00000000",
        "enterprise_id": "E00000000",
        "conversation_host_id": "T00000000",
        "shared_team_ids": ["T00000000"],
      }
    })
    .to_string(),
  )
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

fn sha256_hex(value: &str) -> String {
  let mut digest = Sha256::new();
  digest.update(value.as_bytes());
  let mut encoded = String::with_capacity(64);
  for byte in digest.finalize() {
    write!(&mut encoded, "{byte:02x}").expect("write digest");
  }
  encoded
}

async fn claimed_delivery(
  kind: &str,
  channel_id: &str,
  thread_ts: Option<&str>,
) -> (TempDir, StateStore, ClaimedScheduledDelivery) {
  claimed_delivery_with_body(kind, channel_id, thread_ts, "exact UTF-8: 測試  \n").await
}

async fn claimed_delivery_with_body(
  kind: &str,
  channel_id: &str,
  thread_ts: Option<&str>,
  body: &str,
) -> (TempDir, StateStore, ClaimedScheduledDelivery) {
  let (temp, store, delivery_id) = completed_delivery_intent(kind, channel_id, thread_ts).await;
  assert!(matches!(
    store
      .prepare_scheduled_delivery(
        &delivery_id,
        "text/markdown; charset=utf-8",
        body,
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

#[tokio::test]
async fn enforces_slack_message_limit_by_unicode_scalar_count_before_http() {
  let accepted_body = "a".repeat(40_000);
  let (_temp, _store, accepted) =
    claimed_delivery_with_body("channel", "C123", None, &accepted_body).await;
  let accepted_provider = SlackScheduledDeliveryProvider::new(SlackWebApiClient::new(
    FakeHttp::new([response(
      200,
      r#"{"ok":true,"channel":"C123","ts":"200.000001","team_id":"T00000000","message":{"ts":"200.000001"}}"#,
    )]),
    "slack-default",
    "xoxb-secret",
    SlackConfig::default(),
    100,
  ));
  assert!(matches!(
    accepted_provider
      .send(DeliveryProviderRequest {
        payload: &accepted.payload,
        target_json: &accepted.target_json,
        idempotency_key: accepted.binding.idempotency_key(),
      })
      .await,
    DeliveryProviderOutcome::ConfirmedSuccess(_)
  ));
  assert_eq!(accepted_provider.http_client().requests().len(), 1);

  for rejected_body in ["a".repeat(40_001), "測".repeat(40_001)] {
    let (_temp, _store, rejected) =
      claimed_delivery_with_body("channel", "C123", None, &rejected_body).await;
    let rejected_provider = SlackScheduledDeliveryProvider::new(SlackWebApiClient::new(
      FakeHttp::new([]),
      "slack-default",
      "xoxb-secret",
      SlackConfig::default(),
      100,
    ));
    assert_eq!(
      rejected_provider
        .send(DeliveryProviderRequest {
          payload: &rejected.payload,
          target_json: &rejected.target_json,
          idempotency_key: rejected.binding.idempotency_key(),
        })
        .await,
      DeliveryProviderOutcome::ConfirmedNoWriteTerminal {
        error_kind: "payload_too_long".to_owned(),
      }
    );
    assert!(rejected_provider.http_client().requests().is_empty());
  }
}

async fn completed_delivery_intent(
  kind: &str,
  channel_id: &str,
  thread_ts: Option<&str>,
) -> (TempDir, StateStore, String) {
  completed_delivery_intent_with_body(kind, channel_id, thread_ts, "exact UTF-8: 測試  \n").await
}

async fn completed_delivery_intent_with_body(
  kind: &str,
  channel_id: &str,
  thread_ts: Option<&str>,
  result_body: &str,
) -> (TempDir, StateStore, String) {
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
      schedule: ScheduleSpec::fixed_interval(110, 10).expect("interval"),
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
      &ScheduledRunResult::new(result_body, "").expect("result"),
      120,
    )
    .await
    .expect("complete");
  let delivery_id = delivery_id(run.binding.run_id(), &identity);
  (temp, store, delivery_id)
}

#[tokio::test]
async fn runtime_terminalizes_oversized_slack_payload_without_write_retry_or_baseline() {
  let body = "a".repeat(40_001);
  let (_temp, store, delivery_id) =
    completed_delivery_intent_with_body("channel", "C123", None, &body).await;
  let target_json = store
    .load_scheduled_delivery_intent_target_snapshot(&delivery_id)
    .await
    .expect("target snapshot");
  let provider = SlackScheduledDeliveryProvider::new(SlackWebApiClient::new(
    FakeHttp::new([
      response(
        200,
        r#"{"ok":true,"team_id":"T00000000","enterprise_id":"E00000000","user_id":"U123","bot_id":"B123"}"#,
      ),
      live_channel("C123"),
    ]),
    "slack-default",
    "xoxb-secret",
    SlackConfig::default(),
    100,
  ));
  assert_eq!(
    run_scheduled_delivery_tick(
      &store,
      &provider,
      "oversized-worker",
      tokio::sync::watch::channel(false).1,
    )
    .await
    .expect("oversized delivery"),
    ScheduledDeliveryTickOutcome::FailedTerminal
  );
  assert_eq!(
    store
      .scheduled_delivery_authority_for_tests(&delivery_id)
      .await
      .expect("delivery authority"),
    ("failed_terminal".to_owned(), 1, 1, 1)
  );
  assert_eq!(
    store
      .scheduled_delivery_run_state_for_tests(&delivery_id)
      .await
      .expect("run state"),
    "succeeded"
  );
  let identity = AcceptedDeliveryBaselineIdentity {
    job_id: "slack-channel-C123".to_owned(),
    target_identity_digest: target_identity("channel"),
    target_snapshot_digest_algorithm: "sha256-v1".to_owned(),
    target_snapshot_digest: sha256_hex(&target_json),
    delivery_policy_version: 1,
    render_version: 1,
    hash_algorithm: "sha256-utf8-exact-v1".to_owned(),
  };
  assert!(
    store
      .get_accepted_delivery_baseline(&identity)
      .await
      .expect("baseline")
      .is_none()
  );
  assert_eq!(
    run_scheduled_delivery_tick(
      &store,
      &provider,
      "oversized-worker",
      tokio::sync::watch::channel(false).1,
    )
    .await
    .expect("terminal delivery is not retried"),
    ScheduledDeliveryTickOutcome::Idle
  );
  let requests = provider.http_client().requests();
  assert_eq!(requests.len(), 2);
  assert!(
    requests
      .iter()
      .all(|request| request.path() != "chat.postMessage")
  );
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
#[allow(clippy::too_many_lines)]
async fn runtime_delivers_slack_result_skips_exact_repeat_and_sends_utf8_change() {
  let (_temp, store, first_delivery_id) = completed_delivery_intent("channel", "C123", None).await;
  let target_json = store
    .load_scheduled_delivery_intent_target_snapshot(&first_delivery_id)
    .await
    .expect("target snapshot");
  let provider = SlackScheduledDeliveryProvider::new(SlackWebApiClient::new(
    FakeHttp::new([
      response(
        200,
        r#"{"ok":true,"team_id":"T00000000","enterprise_id":"E00000000","user_id":"U123","bot_id":"B123"}"#,
      ),
      live_channel("C123"),
      response(
        200,
        r#"{"ok":true,"channel":"C123","ts":"200.000001","team_id":"T00000000","message":{"ts":"200.000001"}}"#,
      ),
      response(
        200,
        r#"{"ok":true,"team_id":"T00000000","enterprise_id":"E00000000","user_id":"U123","bot_id":"B123"}"#,
      ),
      live_channel("C123"),
      response(
        200,
        r#"{"ok":true,"channel":"C123","ts":"201.000001","team_id":"T00000000","message":{"ts":"201.000001"}}"#,
      ),
    ]),
    "slack-default",
    "xoxb-secret",
    SlackConfig::default(),
    100,
  ));
  assert_eq!(
    run_scheduled_delivery_tick(
      &store,
      &provider,
      "delivery-worker-a",
      tokio::sync::watch::channel(false).1,
    )
    .await
    .expect("first delivery"),
    ScheduledDeliveryTickOutcome::Delivered
  );
  assert_eq!(
    store
      .scheduled_delivery_authority_for_tests(&first_delivery_id)
      .await
      .expect("first authority"),
    ("delivered".to_owned(), 1, 1, 1)
  );
  let receipt: Value = serde_json::from_str(
    &store
      .scheduled_delivery_receipt_for_tests(&first_delivery_id)
      .await
      .expect("receipt")
      .expect("provider receipt"),
  )
  .expect("receipt json");
  assert_eq!(
    receipt,
    json!({
      "provider": "slack",
      "tenant": "T00000000",
      "conversation_id": "C123",
      "thread_id": null,
      "message_id": "200.000001",
    })
  );
  let baseline_identity = AcceptedDeliveryBaselineIdentity {
    job_id: "slack-channel-C123".to_owned(),
    target_identity_digest: target_identity("channel"),
    target_snapshot_digest_algorithm: "sha256-v1".to_owned(),
    target_snapshot_digest: sha256_hex(&target_json),
    delivery_policy_version: 1,
    render_version: 1,
    hash_algorithm: "sha256-utf8-exact-v1".to_owned(),
  };
  let first_baseline = store
    .get_accepted_delivery_baseline(&baseline_identity)
    .await
    .expect("baseline")
    .expect("accepted baseline");
  assert_eq!(first_baseline.source_delivery_id, first_delivery_id);

  store
    .materialize_due_schedule("slack-channel-C123", 0, 120)
    .await
    .expect("repeat occurrence");
  let repeat_run = store
    .claim_next_scheduled_run("repeat-run-worker", 121, 300)
    .await
    .expect("claim repeat")
    .expect("repeat run");
  let profile =
    AttestedExecutionProfileSnapshot::new(1, "{}", "sha256-v1", "profile").expect("profile");
  store
    .mark_scheduled_run_executing(&repeat_run.binding, &profile, 122)
    .await
    .expect("execute repeat");
  store
    .complete_scheduled_run_success(
      &repeat_run.binding,
      &ScheduledRunResult::new("exact UTF-8: 測試  \n", "").expect("repeat result"),
      123,
    )
    .await
    .expect("complete repeat");
  assert_eq!(
    run_scheduled_delivery_tick(
      &store,
      &provider,
      "delivery-worker-b",
      tokio::sync::watch::channel(false).1,
    )
    .await
    .expect("repeat delivery"),
    ScheduledDeliveryTickOutcome::SkippedUnchanged
  );
  assert_eq!(provider.http_client().requests().len(), 3);

  let changed_body = "exact UTF-8: 測試 e\u{0301}  \n";
  store
    .materialize_due_schedule("slack-channel-C123", 0, 130)
    .await
    .expect("changed occurrence");
  let changed_run = store
    .claim_next_scheduled_run("changed-run-worker", 131, 400)
    .await
    .expect("claim changed")
    .expect("changed run");
  store
    .mark_scheduled_run_executing(&changed_run.binding, &profile, 132)
    .await
    .expect("execute changed");
  store
    .complete_scheduled_run_success(
      &changed_run.binding,
      &ScheduledRunResult::new(changed_body, "").expect("changed result"),
      133,
    )
    .await
    .expect("complete changed");
  assert_eq!(
    run_scheduled_delivery_tick(
      &store,
      &provider,
      "delivery-worker-c",
      tokio::sync::watch::channel(false).1,
    )
    .await
    .expect("changed delivery"),
    ScheduledDeliveryTickOutcome::Delivered
  );
  let requests = provider.http_client().requests();
  assert_eq!(requests.len(), 6);
  assert_eq!(requests[5].path(), "chat.postMessage");
  assert_eq!(
    requests[5].json_value("text").as_deref(),
    Some(changed_body)
  );
  assert_eq!(
    store
      .get_accepted_delivery_baseline(&baseline_identity)
      .await
      .expect("changed baseline")
      .expect("updated baseline")
      .baseline_version,
    2
  );
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
      HttpStep::Response(SlackHttpResponse::new(
        429,
        [("Retry-After", "invalid")],
        r#"{"ok":false,"error":"ratelimited"}"#,
      )),
      DeliveryProviderOutcome::ConfirmedNoWriteRetryable {
        retry_after_seconds: None,
        error_kind: "slack_rate_limited".to_owned(),
      },
    ),
    (
      response(429, r#"{"ok":false,"error":"ratelimited"}"#),
      DeliveryProviderOutcome::ConfirmedNoWriteRetryable {
        retry_after_seconds: None,
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
#[allow(clippy::too_many_lines)]
async fn readiness_separates_exact_target_rejection_global_fatal_and_transient_deferral() {
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
        delivery_id: "delivery-1",
        target_json: r#"{"provider":"email"}"#,
        target_digest: "digest",
        payload_digest: "digest",
        binding_digest: "digest",
      })
      .await,
    DeliveryProviderReadiness::RejectDelivery {
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
        delivery_id: claim.binding.delivery_id(),
        target_json: &claim.target_json,
        target_digest: claim.payload.target_snapshot_digest(),
        payload_digest: claim.payload.digest(),
        binding_digest: "binding",
      })
      .await,
    DeliveryProviderReadiness::Deferred {
      retry_after_seconds: None,
      error_kind: "slack_authority_unavailable".to_owned(),
    }
  );
  assert_eq!(transient.http_client().requests()[0].path(), "auth.test");

  for target_response in [
    response(200, r#"{"ok":false,"error":"channel_not_found"}"#),
    response(200, r#"{"ok":false,"error":"no_permission"}"#),
    response(
      200,
      r#"{"ok":true,"channel":{"id":"C123","is_archived":true,"is_member":true,"context_team_id":"T00000000"}}"#,
    ),
  ] {
    let rejected = SlackScheduledDeliveryProvider::new(SlackWebApiClient::new(
      FakeHttp::new([
        response(
          200,
          r#"{"ok":true,"team_id":"T00000000","enterprise_id":"E00000000","user_id":"U123","bot_id":"B123"}"#,
        ),
        target_response,
      ]),
      "slack-default",
      "xoxb-secret",
      SlackConfig::default(),
      100,
    ));
    assert!(matches!(
      rejected
        .readiness(DeliveryProviderReadinessRequest {
          delivery_id: claim.binding.delivery_id(),
          target_json: &claim.target_json,
          target_digest: claim.payload.target_snapshot_digest(),
          payload_digest: claim.payload.digest(),
          binding_digest: "binding",
        })
        .await,
      DeliveryProviderReadiness::RejectDelivery { .. }
    ));
    assert_eq!(
      rejected
        .http_client()
        .requests()
        .iter()
        .map(SlackHttpRequest::path)
        .collect::<Vec<_>>(),
      ["auth.test", "conversations.info"]
    );
  }

  for steps in [
    vec![response(200, r#"{"ok":false,"error":"invalid_auth"}"#)],
    vec![
      response(
        200,
        r#"{"ok":true,"team_id":"T00000000","enterprise_id":"E00000000","user_id":"U123","bot_id":"B123"}"#,
      ),
      response(200, r#"{"ok":false,"error":"missing_scope"}"#),
    ],
  ] {
    let fatal = SlackScheduledDeliveryProvider::new(SlackWebApiClient::new(
      FakeHttp::new(steps),
      "slack-default",
      "xoxb-secret",
      SlackConfig::default(),
      100,
    ));
    assert!(matches!(
      fatal
        .readiness(DeliveryProviderReadinessRequest {
          delivery_id: claim.binding.delivery_id(),
          target_json: &claim.target_json,
          target_digest: claim.payload.target_snapshot_digest(),
          payload_digest: claim.payload.digest(),
          binding_digest: "binding",
        })
        .await,
      DeliveryProviderReadiness::FatalProvider { .. }
    ));
  }
}
