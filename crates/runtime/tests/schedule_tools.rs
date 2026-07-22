use async_trait::async_trait;
use codeoff_agent_contract::{
  ChannelReplyStrategy, ChannelTaskContext, ConversationKind, InvocationPrincipal, InvocationSource,
};
use codeoff_runtime::schedule_service::ScheduleInvocation;
use codeoff_runtime::schedule_service::{
  CapabilityRegistry, CapabilityRequest, ChannelTargetVerifier, ConfiguredOperatorIdentityPolicy,
  CreateScheduleRequest, DefaultCapabilityRegistry, DeliveryTargetRequest,
  OperatorAuthorizationPolicy, OwnerOnlyAuthorizationPolicy, PreviousSuccessPolicy,
  ScheduleService, ScheduleServiceError, SlackTargetResolutionRequest, TargetResolver,
  TargetResolverRegistration, TargetResolverRegistry, TargetVerificationError,
  UpdateScheduleRequest, VerifiedSlackTarget, VerifiedSlackTargetResolver,
};
use codeoff_runtime::schedule_tools::{SCHEDULE_DYNAMIC_TOOL_NAMES, ScheduleDynamicToolHandler};
use codeoff_state::{
  CapabilityProfileSnapshot, DeliveryTargetSnapshot, PrincipalKey, ScheduleSpec, StateStore,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tempfile::tempdir;

#[derive(Clone, Copy)]
enum VerifyMode {
  Allow,
  Unavailable,
  NotAllowed,
  Slow,
}

struct FakeVerifier(VerifyMode);

struct RotatingVerifier {
  calls: AtomicUsize,
  fail_on_call: Option<usize>,
}

#[async_trait]
impl ChannelTargetVerifier for RotatingVerifier {
  async fn resolve_target(
    &self,
    workspace_id: Option<&str>,
    _actor_id: Option<&str>,
    target: &SlackTargetResolutionRequest,
  ) -> Result<VerifiedSlackTarget, TargetVerificationError> {
    let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
    if self.fail_on_call == Some(call) {
      return Err(TargetVerificationError::Transient);
    }
    let (kind, channel_id, thread_ts) = match target {
      SlackTargetResolutionRequest::Channel { channel_id } => ("channel", channel_id.clone(), None),
      SlackTargetResolutionRequest::DirectMessageUser { .. }
      | SlackTargetResolutionRequest::DirectMessageConversation { .. } => {
        ("direct_message", "D1".to_owned(), None)
      }
      SlackTargetResolutionRequest::Thread {
        channel_id,
        thread_ts,
      } => ("thread", channel_id.clone(), Some(thread_ts.clone())),
    };
    let workspace_id = workspace_id.unwrap_or("T1").to_owned();
    Ok(VerifiedSlackTarget {
      workspace_id: workspace_id.clone(),
      team_id: workspace_id.clone(),
      enterprise_id: None,
      context_team_id: workspace_id.clone(),
      conversation_host_id: workspace_id,
      kind: kind.to_owned(),
      channel_id,
      thread_ts,
      authorization_evidence_version: u32::try_from(call).expect("test call count"),
      authorization_evidence_digest: format!("{call:064x}"),
    })
  }
}

struct InvocationCapabilityRegistry {
  malicious_digest: bool,
}

struct MaliciousTargetResolver {
  address: Value,
  connector: &'static str,
  resolver_version: u32,
  resolver_digest: &'static str,
  invalid_identity: bool,
}

#[async_trait]
impl TargetResolver for MaliciousTargetResolver {
  async fn resolve(
    &self,
    _invocation: &ScheduleInvocation,
    owner: &PrincipalKey,
    _target: &DeliveryTargetRequest,
    _now: i64,
  ) -> Result<Vec<DeliveryTargetSnapshot>, ScheduleServiceError> {
    let address_json = serde_json::to_string(&self.address)
      .map_err(|error| ScheduleServiceError::InvalidRequest(error.to_string()))?;
    let identity = json!({
      "provider": "slack",
      "connector": self.connector,
      "tenant": owner.tenant(),
      "kind": "channel",
      "address": self.address,
    });
    let mut digest = Sha256::new();
    digest.update(
      serde_json::to_string(&identity)
        .map_err(|error| ScheduleServiceError::InvalidRequest(error.to_string()))?
        .as_bytes(),
    );
    let identity_digest = if self.invalid_identity {
      "forged-identity".to_owned()
    } else {
      format!("{:x}", digest.finalize())
    };
    Ok(vec![
      DeliveryTargetSnapshot::new(
        "evil",
        "slack",
        self.connector,
        owner.tenant(),
        "channel",
        address_json,
        self.resolver_version,
        self.resolver_digest,
        identity_digest,
      )
      .map_err(|error| ScheduleServiceError::InvalidRequest(error.to_string()))?,
    ])
  }
}

impl CapabilityRegistry for InvocationCapabilityRegistry {
  fn describe_authorized(&self, invocation: &ScheduleInvocation) -> Vec<&'static str> {
    match invocation.principal.as_ref() {
      codeoff_agent_contract::InvocationPrincipalRef::ChannelActor { actor_id: "U1", .. } => {
        vec!["none"]
      }
      _ => Vec::new(),
    }
  }

  fn resolve(
    &self,
    _invocation: &ScheduleInvocation,
    _owner: &PrincipalKey,
    capability: &CapabilityRequest,
  ) -> Result<CapabilityProfileSnapshot, codeoff_runtime::schedule_service::ScheduleServiceError>
  {
    CapabilityProfileSnapshot::new(
      1,
      if self.malicious_digest {
        "forged"
      } else {
        "d73b7e"
      },
      json!({"name": capability.name, "tools": []}).to_string(),
    )
    .map_err(|error| {
      codeoff_runtime::schedule_service::ScheduleServiceError::InvalidRequest(error.to_string())
    })
  }
}

#[async_trait]
impl ChannelTargetVerifier for FakeVerifier {
  async fn resolve_target(
    &self,
    workspace_id: Option<&str>,
    _actor_id: Option<&str>,
    target: &SlackTargetResolutionRequest,
  ) -> Result<VerifiedSlackTarget, TargetVerificationError> {
    if matches!(self.0, VerifyMode::Slow) {
      tokio::time::sleep(Duration::from_millis(50)).await;
    }
    match self.0 {
      VerifyMode::Unavailable => return Err(TargetVerificationError::Transient),
      VerifyMode::NotAllowed => return Err(TargetVerificationError::Unauthorized),
      _ => {}
    }
    let (kind, channel_id, thread_ts) = match target {
      SlackTargetResolutionRequest::Channel { channel_id } => ("channel", channel_id.clone(), None),
      SlackTargetResolutionRequest::DirectMessageUser { .. }
      | SlackTargetResolutionRequest::DirectMessageConversation { .. } => {
        ("direct_message", "D1".to_owned(), None)
      }
      SlackTargetResolutionRequest::Thread {
        channel_id,
        thread_ts,
      } => ("thread", channel_id.clone(), Some(thread_ts.clone())),
    };
    let workspace_id = workspace_id.unwrap_or("T1").to_owned();
    Ok(VerifiedSlackTarget {
      team_id: workspace_id.clone(),
      enterprise_id: None,
      context_team_id: workspace_id.clone(),
      conversation_host_id: workspace_id.clone(),
      workspace_id,
      kind: kind.to_owned(),
      channel_id,
      thread_ts,
      authorization_evidence_version: 1,
      authorization_evidence_digest: "a".repeat(64),
    })
  }
}

fn verified_handler(
  store: StateStore,
  mode: VerifyMode,
  timeout: Duration,
) -> ScheduleDynamicToolHandler {
  let mut targets = TargetResolverRegistry::with_defaults();
  targets.register(VerifiedSlackTargetResolver::registration(
    Arc::new(FakeVerifier(mode)),
    timeout,
  ));
  ScheduleDynamicToolHandler::from_service(
    ScheduleService::with_components(
      store,
      Arc::new(targets),
      Arc::new(DefaultCapabilityRegistry),
      Arc::new(OwnerOnlyAuthorizationPolicy),
      timeout,
    ),
    Some(100),
  )
}

fn invocation_for(provider: &str, workspace_id: &str, actor: &str) -> ScheduleInvocation {
  ScheduleInvocation {
    source: InvocationSource::ChannelEvent {
      provider: provider.to_owned(),
      workspace_id: workspace_id.to_owned(),
      event_id: "E1".to_owned(),
      dedupe_key: "D1".to_owned(),
      source_reference: None,
    },
    principal: InvocationPrincipal::channel_actor(provider, workspace_id, actor),
    channel: Some(ChannelTaskContext {
      provider: provider.to_owned(),
      workspace_id: workspace_id.to_owned(),
      conversation_key: format!("{provider}:{workspace_id}:C1:T1"),
      conversation_kind: ConversationKind::Thread,
      reply_strategy: ChannelReplyStrategy::DynamicTool,
      message_text: None,
      channel_id: Some("C1".to_owned()),
      thread_id: Some("100.000000".to_owned()),
      message_ts: Some("100.000000".to_owned()),
      user_id: Some(actor.to_owned()),
      recent_context: None,
      conversation_summary: None,
    }),
  }
}

fn invocation(actor: &str) -> ScheduleInvocation {
  invocation_for("slack", "T1", actor)
}

fn create_arguments(request_id: &str) -> Value {
  json!({
    "request_id": request_id,
    "instruction": "Check the repository and report only meaningful changes.",
    "schedule": {"kind": "once", "at": 200},
    "target": {"kind": "none"},
    "capability": "none"
  })
}

fn output_content(output: &Value) -> Value {
  assert_eq!(output["success"], true, "unexpected tool failure: {output}");
  let envelope: Value = serde_json::from_str(
    output["contentItems"][0]["text"]
      .as_str()
      .expect("content text"),
  )
  .expect("JSON content");
  assert_eq!(envelope["schema_version"], 1);
  assert_eq!(envelope["ok"], true);
  envelope["data"].clone()
}

fn tool_envelope(output: &Value) -> Value {
  serde_json::from_str(
    output["contentItems"][0]["text"]
      .as_str()
      .expect("content text"),
  )
  .expect("versioned JSON envelope")
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn test_schedule_tools_owner_lifecycle_idempotency_and_restart() {
  let temp = tempdir().expect("tempdir");
  let state_dir = temp.path().join("state");
  let store = StateStore::initialize(&state_dir, None)
    .await
    .expect("state");
  let audit_store = store.clone();
  let handler = ScheduleDynamicToolHandler::new_with_now(store, 100);
  let owner = invocation("U1");

  let created_output = handler
    .handle_tool_call_async(&owner, "schedule_create", create_arguments("create-1"))
    .await;
  let created_envelope = tool_envelope(&created_output);
  let created = output_content(&created_output);
  let job_id = created["job_id"].as_str().expect("job id").to_owned();
  assert_eq!(created["generation"], 0);

  let replay_output = handler
    .handle_tool_call_async(&owner, "schedule_create", create_arguments("create-1"))
    .await;
  assert_eq!(tool_envelope(&replay_output), created_envelope);

  let mut conflict = create_arguments("create-1");
  conflict["instruction"] = json!("Different intent");
  let conflict = handler
    .handle_tool_call_async(&owner, "schedule_create", conflict)
    .await;
  assert_eq!(conflict["success"], false);
  assert!(conflict.to_string().contains("different semantics"));
  let audit = audit_store
    .list_schedule_audit_summaries("create-1")
    .await
    .expect("audit");
  assert!(audit.iter().any(|entry| entry.outcome == "applied"));
  assert!(audit.iter().any(|entry| entry.outcome == "replay"));
  assert!(audit.iter().any(|entry| entry.outcome == "conflict"));
  assert_eq!(audit.len(), 3, "one audit event is required per attempt");
  assert_eq!(
    audit
      .iter()
      .map(|entry| entry.audit_id.as_str())
      .collect::<std::collections::HashSet<_>>()
      .len(),
    3
  );

  let other_read = handler
    .handle_tool_call_async(&invocation("U2"), "schedule_get", json!({"job_id": job_id}))
    .await;
  assert_eq!(other_read["success"], false);
  assert!(other_read.to_string().contains("not_found_or_not_visible"));

  let paused = output_content(
    &handler
      .handle_tool_call_async(
        &owner,
        "schedule_pause",
        json!({"request_id": "pause-1", "job_id": job_id, "expected_generation": 0}),
      )
      .await,
  );
  assert_eq!(paused["status"], "paused");
  assert_eq!(paused["generation"], 1);

  let stale = handler
    .handle_tool_call_async(
      &owner,
      "schedule_pause",
      json!({"request_id": "pause-stale", "job_id": job_id, "expected_generation": 0}),
    )
    .await;
  assert_eq!(stale["success"], false);
  assert!(stale.to_string().contains("generation"));
  let stale_audit = audit_store
    .list_schedule_audit_summaries("pause-stale")
    .await
    .expect("stale audit");
  assert_eq!(stale_audit.len(), 1);
  assert_eq!(stale_audit[0].outcome, "stale_generation");
  assert_eq!(
    stale_audit[0].error_code.as_deref(),
    Some("stale_generation")
  );

  let updated = output_content(
    &handler
      .handle_tool_call_async(
        &owner,
        "schedule_update",
        json!({
          "request_id": "update-1",
          "job_id": job_id,
          "expected_generation": 1,
          "instruction": "Updated paused intent.",
          "schedule": {"kind": "once", "at": 300},
          "target": {"kind": "none"},
          "capability": "none"
        }),
      )
      .await,
  );
  assert_eq!(updated["status"], "paused");
  assert_eq!(updated["generation"], 2);

  let listed = output_content(
    &handler
      .handle_tool_call_async(&owner, "schedule_list", json!({"status": "paused"}))
      .await,
  );
  assert_eq!(listed["job_ids"], json!([job_id]));

  drop(handler);
  let reopened = StateStore::initialize(&state_dir, None)
    .await
    .expect("reopen state");
  let reopened_handler = ScheduleDynamicToolHandler::new_with_now(reopened, 101);
  let persisted = output_content(
    &reopened_handler
      .handle_tool_call_async(&owner, "schedule_get", json!({"job_id": job_id}))
      .await,
  );
  assert_eq!(persisted["status"], "paused");
  assert_eq!(
    persisted["definition"]["instruction"],
    "Updated paused intent."
  );
  assert_eq!(persisted["definition"]["schema_version"], 2);
  assert_eq!(persisted["definition"]["previous_success"]["kind"], "none");
}

#[tokio::test]
async fn test_schedule_get_hides_jobs_from_same_subject_in_other_provider_or_tenant() {
  let temp = tempdir().expect("tempdir");
  let store = StateStore::initialize(&temp.path().join("state"), None)
    .await
    .expect("state");
  let handler = ScheduleDynamicToolHandler::new_with_now(store, 100);
  let created = output_content(
    &handler
      .handle_tool_call_async(
        &invocation("U1"),
        "schedule_create",
        create_arguments("scope-create"),
      )
      .await,
  );
  let job_id = created["job_id"].as_str().expect("job id");

  for other_scope in [
    invocation_for("slack", "W2", "U1"),
    invocation_for("teams", "W1", "U1"),
  ] {
    let scoped_read = handler
      .handle_tool_call_async(&other_scope, "schedule_get", json!({"job_id": job_id}))
      .await;
    assert_eq!(scoped_read["success"], false);
    assert!(scoped_read.to_string().contains("not_found_or_not_visible"));
  }
}

#[tokio::test]
async fn test_schedule_tools_deny_untrusted_sources_and_unknown_fields() {
  let temp = tempdir().expect("tempdir");
  let store = StateStore::initialize(&temp.path().join("state"), None)
    .await
    .expect("state");
  let audit_store = store.clone();
  let handler = ScheduleDynamicToolHandler::new_with_now(store, 100);
  let mut scheduled = invocation("U1");
  scheduled.source = InvocationSource::ScheduledRun {
    job_id: "job-1".to_owned(),
    run_id: "run-1".to_owned(),
    scheduled_for: "200".to_owned(),
  };
  let denied = handler
    .handle_tool_call_async(&scheduled, "schedule_create", create_arguments("create-1"))
    .await;
  assert_eq!(denied["success"], false);
  let denied_again = handler
    .handle_tool_call_async(&scheduled, "schedule_create", create_arguments("create-1"))
    .await;
  assert_eq!(denied_again["success"], false);
  let audit = audit_store
    .list_schedule_audit_summaries("create-1")
    .await
    .expect("denied audit");
  assert!(audit.iter().any(|entry| {
    entry.outcome == "denied"
      && entry.decision == "deny"
      && entry.error_code.as_deref() == Some("unauthorized")
  }));
  assert_eq!(audit.len(), 2, "each denied attempt needs one unique event");
  assert_ne!(audit[0].audit_id, audit[1].audit_id);

  let mut mixed_actor = invocation("U1");
  mixed_actor.channel.as_mut().expect("context").user_id = Some("U2".to_owned());
  let denied = handler
    .handle_tool_call_async(
      &mixed_actor,
      "schedule_create",
      create_arguments("create-mixed"),
    )
    .await;
  assert!(denied.to_string().contains("unauthorized"));

  let mut cross_provider = invocation("U1");
  if let InvocationSource::ChannelEvent { provider, .. } = &mut cross_provider.source {
    *provider = "teams".to_owned();
  }
  let denied = handler
    .handle_tool_call_async(
      &cross_provider,
      "schedule_create",
      create_arguments("create-provider"),
    )
    .await;
  assert!(denied.to_string().contains("unauthorized"));
  assert!(denied.to_string().contains("authenticated actor"));

  let mut spoofed = create_arguments("create-2");
  spoofed["principal"] = json!({"actor_id": "admin"});
  let rejected = handler
    .handle_tool_call_async(&invocation("U1"), "schedule_create", spoofed)
    .await;
  assert_eq!(rejected["success"], false);
  assert!(rejected.to_string().contains("unknown field: principal"));

  let mut tenant_mismatch = invocation("U1");
  if let InvocationSource::ChannelEvent { workspace_id, .. } = &mut tenant_mismatch.source {
    *workspace_id = "W2".to_owned();
  }
  let denied = handler
    .handle_tool_call_async(
      &tenant_mismatch,
      "schedule_create",
      create_arguments("create-3"),
    )
    .await;
  assert_eq!(denied["success"], false);

  let mut unknown_capability = create_arguments("create-4");
  unknown_capability["capability"] = json!("github-read");
  let rejected = handler
    .handle_tool_call_async(&invocation("U1"), "schedule_create", unknown_capability)
    .await;
  assert_eq!(rejected["success"], false);
  assert!(rejected.to_string().contains("capability_unavailable"));
  let audit = audit_store
    .list_schedule_audit_summaries("create-4")
    .await
    .expect("audit");
  assert!(
    audit
      .iter()
      .any(|entry| entry.outcome == "capability_unavailable")
  );
}

#[tokio::test]
async fn test_direct_schedule_service_call_records_exactly_one_attempt_audit() {
  let temp = tempdir().expect("tempdir");
  let store = StateStore::initialize(&temp.path().join("state"), None)
    .await
    .expect("state");
  let audit_store = store.clone();
  let service = ScheduleService::new(store);
  let mut scheduled = invocation("U1");
  scheduled.source = InvocationSource::ScheduledRun {
    job_id: "job-1".to_owned(),
    run_id: "run-1".to_owned(),
    scheduled_for: "200".to_owned(),
  };

  let error = service
    .create(
      &scheduled,
      CreateScheduleRequest {
        request_id: "direct-service".to_owned(),
        instruction: "Direct service audit.".to_owned(),
        previous_success: PreviousSuccessPolicy::None,
        schedule: ScheduleSpec::once(200),
        target: DeliveryTargetRequest::None,
        capability: "none".to_owned(),
        now: 100,
      },
    )
    .await
    .expect_err("scheduled principal must be rejected");
  assert_eq!(error.code(), "unauthorized");
  let audit = audit_store
    .list_schedule_audit_summaries("direct-service")
    .await
    .expect("direct audit");
  assert_eq!(audit.len(), 1);
  assert_eq!(audit[0].outcome, "denied");
  assert_eq!(audit[0].decision, "deny");
}

#[tokio::test]
async fn test_operator_policy_requires_exact_trusted_mapping_and_persists_versioned_definition() {
  let temp = tempdir().expect("tempdir");
  let store = StateStore::initialize(&temp.path().join("state"), None)
    .await
    .expect("state");
  let policy =
    ConfiguredOperatorIdentityPolicy::new("ops-a", "realm-a", "alice").expect("operator policy");
  let service = ScheduleService::with_components(
    store.clone(),
    Arc::new(TargetResolverRegistry::with_defaults()),
    Arc::new(DefaultCapabilityRegistry),
    Arc::new(OperatorAuthorizationPolicy::new(Arc::new(policy))),
    Duration::from_millis(50),
  );
  let operator_invocation = ScheduleInvocation {
    source: InvocationSource::TrustedOperator {
      request_id: "operator-create".to_owned(),
    },
    principal: InvocationPrincipal::service("ops-a"),
    channel: None,
  };
  let created = service
    .create(
      &operator_invocation,
      CreateScheduleRequest {
        request_id: "operator-create".to_owned(),
        instruction: "Inspect durable work.".to_owned(),
        previous_success: PreviousSuccessPolicy::LatestSuccess,
        schedule: ScheduleSpec::once(200),
        target: DeliveryTargetRequest::None,
        capability: "none".to_owned(),
        now: 100,
      },
    )
    .await
    .expect("operator create");
  let job_id = created["data"]["job_id"].as_str().expect("job id");
  let owner = PrincipalKey::new("operator", "local", "realm-a", "alice").expect("owner");
  let job = store
    .get_scheduled_job_by_owner(&owner, job_id)
    .await
    .expect("owner query")
    .expect("job");
  assert_eq!(job.definition.version(), 2);
  let definition: Value =
    serde_json::from_str(job.definition.canonical_json()).expect("definition");
  assert_eq!(definition["schema_version"], 2);
  assert_eq!(definition["previous_success"]["kind"], "latest_success");
  let targets = store
    .get_scheduled_job_delivery_targets(job_id)
    .await
    .expect("targets");
  assert_eq!(targets.len(), 1);
  assert_eq!(targets[0].kind(), "none");

  for (index, rejected) in [
    ScheduleInvocation {
      source: InvocationSource::TrustedOperator {
        request_id: "wrong-service".to_owned(),
      },
      principal: InvocationPrincipal::service("ops-b"),
      channel: None,
    },
    ScheduleInvocation {
      source: InvocationSource::InternalService {
        service: "ops-a".to_owned(),
        request_id: "wrong-source".to_owned(),
      },
      principal: InvocationPrincipal::service("ops-a"),
      channel: None,
    },
    invocation("U1"),
  ]
  .into_iter()
  .enumerate()
  {
    let error = service
      .create(
        &rejected,
        CreateScheduleRequest {
          request_id: format!("operator-denied-{index}"),
          instruction: "Denied.".to_owned(),
          previous_success: PreviousSuccessPolicy::None,
          schedule: ScheduleSpec::once(300),
          target: DeliveryTargetRequest::None,
          capability: "none".to_owned(),
          now: 100,
        },
      )
      .await
      .expect_err("mapping must fail closed");
    assert_eq!(error.code(), "unauthorized");
  }
}

#[tokio::test]
async fn test_verified_resolver_fails_closed_for_unavailable_not_allowed_and_timeout() {
  for (index, (mode, code)) in [
    (VerifyMode::Unavailable, "resolver_unavailable"),
    (VerifyMode::NotAllowed, "resolver_not_allowed"),
    (VerifyMode::Slow, "resolver_timeout"),
  ]
  .into_iter()
  .enumerate()
  {
    let temp = tempdir().expect("tempdir");
    let store = StateStore::initialize(&temp.path().join("state"), None)
      .await
      .expect("state");
    let audit_store = store.clone();
    let handler = verified_handler(store, mode, Duration::from_millis(5));
    let mut arguments = create_arguments(&format!("resolver-{index}"));
    arguments["target"] = json!({"kind": "channel", "channel_id": "C2"});
    let output = handler
      .handle_tool_call_async(&invocation("U1"), "schedule_create", arguments)
      .await;
    assert_eq!(output["success"], false);
    assert!(output.to_string().contains(code), "{output}");
    let audit = audit_store
      .list_schedule_audit_summaries(&format!("resolver-{index}"))
      .await
      .expect("audit");
    assert!(audit.iter().any(|entry| entry.outcome == code));
  }
}

#[tokio::test]
async fn test_verified_slack_resolver_persists_direct_message_conversation_not_user() {
  let temp = tempdir().expect("tempdir");
  let store = StateStore::initialize(&temp.path().join("state"), None)
    .await
    .expect("state");
  let inspection = store.clone();
  let handler = verified_handler(store, VerifyMode::Allow, Duration::from_millis(50));
  let mut arguments = create_arguments("dm-other-user");
  arguments["target"] = json!({"kind": "direct_message", "user_id": "U2"});

  let output = handler
    .handle_tool_call_async(&invocation("U1"), "schedule_create", arguments)
    .await;

  assert_eq!(output["success"], true, "{output}");
  let job_id = output_content(&output)["job_id"]
    .as_str()
    .expect("job id")
    .to_owned();
  let targets = inspection
    .get_scheduled_job_delivery_targets(&job_id)
    .await
    .expect("targets");
  assert_eq!(targets[0].kind(), "direct_message");
  assert!(targets[0].address_json().contains("\"channel_id\":\"D1\""));
  assert!(!targets[0].address_json().contains("U2"));
}

#[tokio::test]
async fn test_capability_registry_is_invocation_scoped_and_revalidates_snapshots() {
  let temp = tempdir().expect("tempdir");
  let store = StateStore::initialize(&temp.path().join("state"), None)
    .await
    .expect("state");
  let audit_store = store.clone();
  let service = ScheduleService::with_components(
    store,
    Arc::new(TargetResolverRegistry::with_defaults()),
    Arc::new(InvocationCapabilityRegistry {
      malicious_digest: true,
    }),
    Arc::new(OwnerOnlyAuthorizationPolicy),
    Duration::from_millis(50),
  );
  let handler = ScheduleDynamicToolHandler::from_service(service, Some(100));
  let u1_specs = handler.tool_specs(&invocation("U1"));
  let u2_specs = handler.tool_specs(&invocation("U2"));
  let capability_enum = |specs: &[Value]| {
    specs
      .iter()
      .find(|spec| spec["name"] == "schedule_create")
      .expect("create")["inputSchema"]["properties"]["capability"]["enum"]
      .clone()
  };
  assert_eq!(capability_enum(&u1_specs), json!(["none"]));
  assert_eq!(capability_enum(&u2_specs), json!([]));
  let output = handler
    .handle_tool_call_async(
      &invocation("U1"),
      "schedule_create",
      create_arguments("malicious-capability"),
    )
    .await;
  assert!(output.to_string().contains("capability_invalid"));
  let audit = audit_store
    .list_schedule_audit_summaries("malicious-capability")
    .await
    .expect("capability audit");
  assert_eq!(audit.len(), 1);
  assert_eq!(audit[0].outcome, "capability_invalid");
  assert_eq!(audit[0].error_code.as_deref(), Some("capability_invalid"));
}

#[tokio::test]
async fn test_service_rejects_resolver_snapshots_not_bound_to_registration_and_request() {
  for (index, resolver) in [
    MaliciousTargetResolver {
      address: json!({"channel_id": "C3"}),
      connector: "trusted-connector",
      resolver_version: 7,
      resolver_digest: "trusted-digest",
      invalid_identity: false,
    },
    MaliciousTargetResolver {
      address: json!({"channel_id": "C2"}),
      connector: "wrong-connector",
      resolver_version: 7,
      resolver_digest: "trusted-digest",
      invalid_identity: false,
    },
    MaliciousTargetResolver {
      address: json!({"channel_id": "C2"}),
      connector: "trusted-connector",
      resolver_version: 8,
      resolver_digest: "trusted-digest",
      invalid_identity: false,
    },
    MaliciousTargetResolver {
      address: json!({"channel_id": "C2"}),
      connector: "trusted-connector",
      resolver_version: 7,
      resolver_digest: "wrong-digest",
      invalid_identity: false,
    },
    MaliciousTargetResolver {
      address: json!({"channel_id": "C2"}),
      connector: "trusted-connector",
      resolver_version: 7,
      resolver_digest: "trusted-digest",
      invalid_identity: true,
    },
  ]
  .into_iter()
  .enumerate()
  {
    let invalid_identity = resolver.invalid_identity;
    let temp = tempdir().expect("tempdir");
    let store = StateStore::initialize(&temp.path().join("state"), None)
      .await
      .expect("state");
    let inspection = store.clone();
    let mut targets = TargetResolverRegistry::with_defaults();
    targets.register(
      TargetResolverRegistration::new(
        "slack",
        "trusted-connector",
        7,
        "trusted-digest",
        vec!["channel"],
        Arc::new(resolver),
      )
      .expect("trusted registration"),
    );
    let service = ScheduleService::with_components(
      store,
      Arc::new(targets),
      Arc::new(DefaultCapabilityRegistry),
      Arc::new(OwnerOnlyAuthorizationPolicy),
      Duration::from_millis(50),
    );
    let handler = ScheduleDynamicToolHandler::from_service(service, Some(100));
    let job_id = format!("malicious-target-{index}");
    let mut arguments = create_arguments(&job_id);
    arguments["target"] = json!({"kind": "channel", "channel_id": "C2"});
    let output = handler
      .handle_tool_call_async(&invocation("U1"), "schedule_create", arguments)
      .await;
    let expected_error = if invalid_identity {
      "validation_failed"
    } else {
      "resolver_unavailable"
    };
    assert!(
      output.to_string().contains(expected_error),
      "case {index}: {output}"
    );
    assert_eq!(
      inspection
        .get_scheduled_job(&job_id)
        .await
        .expect("read rejected job"),
      None,
      "case {index} must fail before schedule commit"
    );
  }
}

#[tokio::test]
async fn test_service_concurrent_stores_converge_or_conflict_by_semantic_digest() {
  for different in [false, true] {
    let temp = tempdir().expect("tempdir");
    let state_dir = temp.path().join("state");
    let first = StateStore::initialize(&state_dir, None)
      .await
      .expect("first");
    let second = StateStore::initialize(&state_dir, None)
      .await
      .expect("second");
    let first_handler = ScheduleDynamicToolHandler::new_with_now(first, 100);
    let second_handler = ScheduleDynamicToolHandler::new_with_now(second, 100);
    let first_arguments = create_arguments("race-request");
    let mut second_arguments = create_arguments("race-request");
    if different {
      second_arguments["instruction"] = json!("different intent");
    }
    let actor = invocation("U1");
    let (left, right) = tokio::join!(
      first_handler.handle_tool_call_async(&actor, "schedule_create", first_arguments),
      second_handler.handle_tool_call_async(&actor, "schedule_create", second_arguments),
    );
    if different {
      assert_ne!(left["success"], right["success"], "{left} {right}");
      assert!(format!("{left}{right}").contains("idempotency_conflict"));
    } else {
      assert_eq!(left["success"], true, "{left}");
      assert_eq!(right["success"], true, "{right}");
      assert_eq!(output_content(&left), output_content(&right));
    }
  }
}

#[tokio::test]
async fn test_schedule_tools_resolve_supported_target_variants_to_durable_snapshots() {
  let temp = tempdir().expect("tempdir");
  let store = StateStore::initialize(&temp.path().join("state"), None)
    .await
    .expect("state");
  let handler = verified_handler(store, VerifyMode::Allow, Duration::from_millis(100));
  let owner = invocation("U1");
  let targets = [
    json!({"kind": "none"}),
    json!({"kind": "origin"}),
    json!({"kind": "channel", "channel_id": "C2"}),
    json!({"kind": "direct_message", "user_id": "U1"}),
    json!({"kind": "thread", "channel_id": "C2", "thread_id": "200.000000"}),
    json!({"kind": "channel", "channel_id": "C2"}),
  ];
  for (index, target) in targets.into_iter().enumerate() {
    let mut arguments = create_arguments(&format!("target-{index}"));
    arguments["target"] = target;
    let output = handler
      .handle_tool_call_async(&owner, "schedule_create", arguments)
      .await;
    assert_eq!(output["success"], true, "target {index} failed: {output}");
  }
}

#[tokio::test]
async fn test_slack_resolution_is_canonical_stable_and_precedes_schedule_mutation() {
  let temp = tempdir().expect("tempdir");
  let store = StateStore::initialize(&temp.path().join("state"), None)
    .await
    .expect("state");
  let inspection = store.clone();
  let handler = verified_handler(store, VerifyMode::Allow, Duration::from_millis(100));
  let actor = invocation("U1");

  let mut invalid = create_arguments("canonical-create");
  invalid["target"] = json!({"kind": "channel", "channel_id": "#general"});
  let rejected = handler
    .handle_tool_call_async(&actor, "schedule_create", invalid)
    .await;
  assert!(rejected.to_string().contains("canonical Slack"));
  let owner = PrincipalKey::new("user", "slack", "T1", "U1").expect("owner");
  assert!(
    inspection
      .list_scheduled_jobs_by_owner(&owner, codeoff_state::ScheduledJobStatus::Active, None, 10,)
      .await
      .expect("jobs")
      .job_ids
      .is_empty(),
    "resolution failure must not create a schedule"
  );

  let mut corrected = create_arguments("canonical-create");
  corrected["target"] = json!({"kind": "channel", "channel_id": "C2"});
  let created = handler
    .handle_tool_call_async(&actor, "schedule_create", corrected)
    .await;
  assert_eq!(created["success"], true, "{created}");
  let job_id = output_content(&created)["job_id"]
    .as_str()
    .expect("job id")
    .to_owned();
  let before = inspection
    .get_scheduled_job_delivery_targets(&job_id)
    .await
    .expect("targets")
    .remove(0);
  assert!(!before.address_json().contains("general"));
  assert!(before.address_json().contains("\"channel_id\":\"C2\""));

  let update = |request_id: &str, instruction: &str| {
    json!({
      "request_id": request_id,
      "job_id": job_id,
      "expected_generation": 0,
      "instruction": instruction,
      "schedule": {"kind": "once", "at": 300},
      "target": {"kind": "channel", "channel_id": "C2"},
      "capability": "none"
    })
  };
  let (left, right) = tokio::join!(
    handler.handle_tool_call_async(&actor, "schedule_update", update("update-left", "left")),
    handler.handle_tool_call_async(&actor, "schedule_update", update("update-right", "right")),
  );
  assert_ne!(left["success"], right["success"], "{left} {right}");
  assert!(format!("{left}{right}").contains("stale_generation"));
  let after = inspection
    .get_scheduled_job_delivery_targets(&job_id)
    .await
    .expect("targets")
    .remove(0);
  assert_eq!(before.identity_digest(), after.identity_digest());
  assert_eq!(before.address_json(), after.address_json());
}

fn service_with_verifier(
  store: StateStore,
  verifier: Arc<dyn ChannelTargetVerifier>,
) -> ScheduleService {
  let mut targets = TargetResolverRegistry::with_defaults();
  targets.register(VerifiedSlackTargetResolver::registration(
    verifier,
    Duration::from_millis(100),
  ));
  ScheduleService::with_components(
    store,
    Arc::new(targets),
    Arc::new(DefaultCapabilityRegistry),
    Arc::new(OwnerOnlyAuthorizationPolicy),
    Duration::from_millis(100),
  )
}

fn slack_create(
  request_id: &str,
  target: DeliveryTargetRequest,
  now: i64,
) -> CreateScheduleRequest {
  CreateScheduleRequest {
    request_id: request_id.to_owned(),
    instruction: "Check canonical target semantics.".to_owned(),
    previous_success: PreviousSuccessPolicy::None,
    schedule: ScheduleSpec::once(500),
    target,
    capability: "none".to_owned(),
    now,
  }
}

async fn resolve_snapshot(
  resolver: &VerifiedSlackTargetResolver,
  invocation: &ScheduleInvocation,
  owner: &PrincipalKey,
  target: DeliveryTargetRequest,
  now: i64,
) -> DeliveryTargetSnapshot {
  resolver
    .resolve(invocation, owner, &target, now)
    .await
    .expect("resolved")
    .remove(0)
}

#[tokio::test]
async fn test_delayed_create_and_update_replay_ignore_evidence_time_and_request_binding() {
  let temp = tempdir().expect("tempdir");
  let store = StateStore::initialize(&temp.path().join("state"), None)
    .await
    .expect("state");
  let inspection = store.clone();
  let verifier = Arc::new(RotatingVerifier {
    calls: AtomicUsize::new(0),
    fail_on_call: None,
  });
  let service = service_with_verifier(store, verifier.clone());
  let actor = invocation("U1");
  let target = DeliveryTargetRequest::DirectMessage {
    user_id: "U2".to_owned(),
  };
  let first = service
    .create(&actor, slack_create("delayed-create", target.clone(), 100))
    .await
    .expect("first create");
  let replay = service
    .create(&actor, slack_create("delayed-create", target.clone(), 150))
    .await
    .expect("delayed replay");
  assert_eq!(first, replay);
  let job_id = first["data"]["job_id"].as_str().expect("job id");
  let original_target = inspection
    .get_scheduled_job_delivery_targets(job_id)
    .await
    .expect("targets")
    .remove(0);
  let original_address: Value =
    serde_json::from_str(original_target.address_json()).expect("address");
  assert_eq!(original_address["created_at"], 100);
  assert_eq!(original_address["authorization_evidence"]["version"], 1);
  assert!(
    original_target
      .address_json()
      .contains("\"channel_id\":\"D1\"")
  );
  assert!(!original_target.address_json().contains("U2"));

  let update = |target: DeliveryTargetRequest, now| UpdateScheduleRequest {
    request_id: "delayed-update".to_owned(),
    job_id: job_id.to_owned(),
    expected_generation: 0,
    instruction: "Update canonical target semantics.".to_owned(),
    previous_success: PreviousSuccessPolicy::None,
    schedule: ScheduleSpec::once(600),
    target,
    capability: "none".to_owned(),
    now,
  };
  let updated = service
    .update(&actor, update(target.clone(), 200))
    .await
    .expect("update");
  let update_replay = service
    .update(
      &actor,
      update(
        DeliveryTargetRequest::DirectMessage {
          user_id: "U3".to_owned(),
        },
        250,
      ),
    )
    .await
    .expect("canonical DM indirection replay");
  assert_eq!(updated, update_replay);
  let persisted = inspection
    .get_scheduled_job(job_id)
    .await
    .expect("job")
    .expect("persisted job");
  assert_eq!(persisted.generation, 1);
  let updated_target = inspection
    .get_scheduled_job_delivery_targets(job_id)
    .await
    .expect("updated targets")
    .remove(0);
  let updated_address: Value =
    serde_json::from_str(updated_target.address_json()).expect("updated address");
  assert_eq!(updated_address["created_at"], 200);
  assert_eq!(updated_address["authorization_evidence"]["version"], 3);

  let conflict = service
    .update(
      &actor,
      update(
        DeliveryTargetRequest::Channel {
          channel_id: "C9".to_owned(),
        },
        300,
      ),
    )
    .await
    .expect_err("different routing target conflicts");
  assert!(matches!(
    conflict,
    ScheduleServiceError::IdempotencyConflict
  ));
  assert_eq!(verifier.calls.load(Ordering::SeqCst), 5);
}

#[tokio::test]
async fn test_failed_update_and_resolver_registration_cardinality_leave_job_unchanged() {
  let temp = tempdir().expect("tempdir");
  let store = StateStore::initialize(&temp.path().join("state"), None)
    .await
    .expect("state");
  let base = ScheduleService::new(store.clone());
  let actor = invocation("U1");
  let created = base
    .create(
      &actor,
      slack_create("registration-base", DeliveryTargetRequest::None, 100),
    )
    .await
    .expect("base create");
  let job_id = created["data"]["job_id"]
    .as_str()
    .expect("job id")
    .to_owned();

  let no_resolver = ScheduleService::new(store.clone());
  let update_request = |request_id: &str| UpdateScheduleRequest {
    request_id: request_id.to_owned(),
    job_id: job_id.clone(),
    expected_generation: 0,
    instruction: "Resolver cardinality must fail closed.".to_owned(),
    previous_success: PreviousSuccessPolicy::None,
    schedule: ScheduleSpec::once(600),
    target: DeliveryTargetRequest::Channel {
      channel_id: "C2".to_owned(),
    },
    capability: "none".to_owned(),
    now: 200,
  };
  assert!(matches!(
    no_resolver
      .update(&actor, update_request("zero-resolvers"))
      .await,
    Err(ScheduleServiceError::ResolverNotAllowed)
  ));

  let mut duplicate = TargetResolverRegistry::with_defaults();
  duplicate.register(VerifiedSlackTargetResolver::registration(
    Arc::new(FakeVerifier(VerifyMode::Allow)),
    Duration::from_millis(100),
  ));
  duplicate.register(VerifiedSlackTargetResolver::registration(
    Arc::new(FakeVerifier(VerifyMode::Allow)),
    Duration::from_millis(100),
  ));
  let duplicate_service = ScheduleService::with_components(
    store.clone(),
    Arc::new(duplicate),
    Arc::new(DefaultCapabilityRegistry),
    Arc::new(OwnerOnlyAuthorizationPolicy),
    Duration::from_millis(100),
  );
  assert!(matches!(
    duplicate_service
      .update(&actor, update_request("duplicate-resolvers"))
      .await,
    Err(ScheduleServiceError::ResolverNotAllowed)
  ));

  let failed = service_with_verifier(
    store.clone(),
    Arc::new(RotatingVerifier {
      calls: AtomicUsize::new(0),
      fail_on_call: Some(1),
    }),
  );
  assert!(matches!(
    failed
      .update(&actor, update_request("transient-update"))
      .await,
    Err(ScheduleServiceError::ResolverUnavailable)
  ));
  let job = store
    .get_scheduled_job(&job_id)
    .await
    .expect("job")
    .expect("persisted");
  assert_eq!(job.generation, 0);
  let targets = store
    .get_scheduled_job_delivery_targets(&job_id)
    .await
    .expect("targets");
  assert_eq!(targets.len(), 1);
  assert_eq!(targets[0].kind(), "none");

  let repaired = service_with_verifier(
    store.clone(),
    Arc::new(RotatingVerifier {
      calls: AtomicUsize::new(0),
      fail_on_call: None,
    }),
  );
  let applied = repaired
    .update(&actor, update_request("transient-update"))
    .await
    .expect("failed resolution did not claim idempotency");
  assert_eq!(applied["data"]["generation"], 1);
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn test_slack_identity_digest_is_parameterized_only_by_canonical_routing_identity() {
  let resolver = VerifiedSlackTargetResolver::new(
    Arc::new(RotatingVerifier {
      calls: AtomicUsize::new(0),
      fail_on_call: None,
    }),
    Duration::from_millis(100),
  );
  let actor_t1 = invocation_for("slack", "T1", "U1");
  let owner_t1 = PrincipalKey::new("user", "slack", "T1", "U1").expect("owner T1");
  let channel = resolve_snapshot(
    &resolver,
    &actor_t1,
    &owner_t1,
    DeliveryTargetRequest::Channel {
      channel_id: "C2".to_owned(),
    },
    100,
  )
  .await;
  let channel_later = resolve_snapshot(
    &resolver,
    &actor_t1,
    &owner_t1,
    DeliveryTargetRequest::Channel {
      channel_id: "C2".to_owned(),
    },
    200,
  )
  .await;
  assert_eq!(channel.identity_digest(), channel_later.identity_digest());
  assert_ne!(channel.address_json(), channel_later.address_json());

  let dm_u2 = resolve_snapshot(
    &resolver,
    &actor_t1,
    &owner_t1,
    DeliveryTargetRequest::DirectMessage {
      user_id: "U2".to_owned(),
    },
    300,
  )
  .await;
  let dm_u3 = resolve_snapshot(
    &resolver,
    &actor_t1,
    &owner_t1,
    DeliveryTargetRequest::DirectMessage {
      user_id: "U3".to_owned(),
    },
    400,
  )
  .await;
  assert_eq!(dm_u2.identity_digest(), dm_u3.identity_digest());
  assert_ne!(dm_u2.address_json(), dm_u3.address_json());

  let other_channel = resolve_snapshot(
    &resolver,
    &actor_t1,
    &owner_t1,
    DeliveryTargetRequest::Channel {
      channel_id: "C3".to_owned(),
    },
    500,
  )
  .await;
  let thread = resolve_snapshot(
    &resolver,
    &actor_t1,
    &owner_t1,
    DeliveryTargetRequest::Thread {
      channel_id: "C2".to_owned(),
      thread_id: "100.000000".to_owned(),
    },
    600,
  )
  .await;
  let other_thread = resolve_snapshot(
    &resolver,
    &actor_t1,
    &owner_t1,
    DeliveryTargetRequest::Thread {
      channel_id: "C2".to_owned(),
      thread_id: "101.000000".to_owned(),
    },
    700,
  )
  .await;
  let actor_t2 = invocation_for("slack", "T2", "U1");
  let owner_t2 = PrincipalKey::new("user", "slack", "T2", "U1").expect("owner T2");
  let other_workspace = resolve_snapshot(
    &resolver,
    &actor_t2,
    &owner_t2,
    DeliveryTargetRequest::Channel {
      channel_id: "C2".to_owned(),
    },
    800,
  )
  .await;
  for different in [&other_channel, &thread, &other_thread, &other_workspace] {
    assert_ne!(channel.identity_digest(), different.identity_digest());
  }
  assert_ne!(thread.identity_digest(), other_thread.identity_digest());

  for target in [channel, dm_u2, thread, other_workspace] {
    let address: Value = serde_json::from_str(target.address_json()).expect("address");
    assert!(address.get("event_id").is_none());
    assert!(address.get("source_reference").is_none());
    assert!(address.get("message_ts").is_none());
    assert!(address.get("routing_authority").is_some());
  }
}

#[test]
fn test_schedule_tool_schemas_are_bounded_and_deny_unknown_fields() {
  let temp = tempdir().expect("tempdir");
  let runtime = tokio::runtime::Runtime::new().expect("runtime");
  let store = runtime
    .block_on(StateStore::initialize(&temp.path().join("state"), None))
    .expect("state");
  let specs = ScheduleDynamicToolHandler::new(store).tool_specs(&invocation("U1"));
  assert_eq!(specs.len(), 7);
  for spec in &specs {
    assert_eq!(spec["inputSchema"]["type"], "object");
    assert_eq!(spec["inputSchema"]["additionalProperties"], false);
    assert!(
      spec["name"]
        .as_str()
        .is_some_and(|name| name.starts_with("schedule_"))
    );
  }
  let create = specs
    .iter()
    .find(|spec| spec["name"] == "schedule_create")
    .expect("create spec");
  assert_eq!(
    create["inputSchema"]["properties"]["target"]["oneOf"]
      .as_array()
      .map(Vec::len),
    Some(1)
  );
}

#[test]
fn test_schedule_tool_schema_without_trusted_context_fails_closed() {
  let temp = tempdir().expect("tempdir");
  let runtime = tokio::runtime::Runtime::new().expect("runtime");
  let store = runtime
    .block_on(StateStore::initialize(&temp.path().join("state"), None))
    .expect("state");
  let handler = ScheduleDynamicToolHandler::new_with_now(store, 100);
  let mut untrusted = invocation("U1");
  untrusted.channel = None;
  let specs = handler.tool_specs(&untrusted);
  let create = specs
    .iter()
    .find(|spec| spec["name"] == "schedule_create")
    .expect("create spec");
  assert_eq!(
    create["inputSchema"]["properties"]["target"]["oneOf"],
    json!([])
  );
  assert_eq!(
    create["inputSchema"]["properties"]["capability"]["enum"],
    json!([])
  );
  let output = runtime.block_on(handler.handle_tool_call_async(
    &untrusted,
    "schedule_create",
    create_arguments("no-context"),
  ));
  assert!(output.to_string().contains("unauthorized"));
}

#[tokio::test]
async fn test_all_schedule_tools_use_the_versioned_success_and_error_contract() {
  let temp = tempdir().expect("tempdir");
  let store = StateStore::initialize(&temp.path().join("state"), None)
    .await
    .expect("state");
  let handler = ScheduleDynamicToolHandler::new_with_now(store, 100);
  let owner = invocation("U1");
  let created_output = handler
    .handle_tool_call_async(
      &owner,
      "schedule_create",
      create_arguments("contract-create"),
    )
    .await;
  let created = output_content(&created_output);
  let job_id = created["job_id"].as_str().expect("job id");
  assert_eq!(created["next_run_at"], 200);
  assert_eq!(created["targets"]["count"], 1);

  let success_calls = [
    ("schedule_get", json!({"job_id": job_id})),
    ("schedule_list", json!({"status": "active"})),
    (
      "schedule_update",
      json!({
        "request_id": "contract-update", "job_id": job_id, "expected_generation": 0,
        "instruction": "Updated contract.", "schedule": {"kind": "once", "at": 300},
        "target": {"kind": "none"}, "capability": "none"
      }),
    ),
    (
      "schedule_pause",
      json!({"request_id": "contract-pause", "job_id": job_id, "expected_generation": 1}),
    ),
    (
      "schedule_resume",
      json!({"request_id": "contract-resume", "job_id": job_id, "expected_generation": 2}),
    ),
    (
      "schedule_delete",
      json!({"request_id": "contract-delete", "job_id": job_id, "expected_generation": 3}),
    ),
  ];
  for (tool, arguments) in success_calls {
    let output = handler
      .handle_tool_call_async(&owner, tool, arguments)
      .await;
    assert_eq!(output["success"], true, "{tool}: {output}");
    let envelope = tool_envelope(&output);
    assert_eq!(envelope["schema_version"], 1, "{tool}");
    assert_eq!(envelope["ok"], true, "{tool}");
    assert!(envelope.get("data").is_some(), "{tool}");
    if matches!(
      tool,
      "schedule_update" | "schedule_pause" | "schedule_resume" | "schedule_delete"
    ) {
      assert!(envelope["data"].get("next_run_at").is_some(), "{tool}");
      assert_eq!(envelope["data"]["targets"]["count"], 1, "{tool}");
    }
  }

  for tool in SCHEDULE_DYNAMIC_TOOL_NAMES {
    let output = handler
      .handle_tool_call_async(&owner, tool, json!({"unexpected": true}))
      .await;
    assert_eq!(output["success"], false, "{tool}: {output}");
    let envelope = tool_envelope(&output);
    assert_eq!(envelope["schema_version"], 1, "{tool}");
    assert_eq!(envelope["ok"], false, "{tool}");
    assert_eq!(envelope["error"]["schema_version"], 1, "{tool}");
    assert_eq!(envelope["error"]["code"], "validation_failed", "{tool}");
    assert!(envelope["error"]["retryable"].is_boolean(), "{tool}");
    assert!(envelope["error"]["message"].is_string(), "{tool}");
    assert!(envelope["error"]["details"].is_object(), "{tool}");
  }
}
