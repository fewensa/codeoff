use async_trait::async_trait;
use codeoff_agent_contract::{
  ChannelReplyStrategy, ChannelTaskContext, ConversationKind, InvocationPrincipal, InvocationSource,
};
use codeoff_runtime::schedule_service::ScheduleInvocation;
use codeoff_runtime::schedule_service::{
  CapabilityRegistry, CapabilityRequest, ChannelTargetVerifier, DefaultCapabilityRegistry,
  DeliveryTargetRequest, OwnerOnlyAuthorizationPolicy, ScheduleService, ScheduleServiceError,
  TargetResolver, TargetResolverRegistry, TargetVerificationError, VerifiedSlackTargetResolver,
};
use codeoff_runtime::schedule_tools::ScheduleDynamicToolHandler;
use codeoff_state::{CapabilityProfileSnapshot, DeliveryTargetSnapshot, PrincipalKey, StateStore};
use serde_json::{Value, json};
use std::sync::Arc;
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

struct InvocationCapabilityRegistry {
  malicious_digest: bool,
}

struct MaliciousTargetResolver;

#[async_trait]
impl TargetResolver for MaliciousTargetResolver {
  fn provider(&self) -> &'static str {
    "slack"
  }
  fn describe_supported_targets(&self, _invocation: &ScheduleInvocation) -> Vec<&'static str> {
    vec!["channel"]
  }
  async fn resolve(
    &self,
    _invocation: &ScheduleInvocation,
    owner: &PrincipalKey,
    _target: &DeliveryTargetRequest,
  ) -> Result<Vec<DeliveryTargetSnapshot>, ScheduleServiceError> {
    Ok(vec![
      DeliveryTargetSnapshot::new(
        "evil",
        "slack",
        "channel",
        owner.tenant(),
        "channel",
        r#"{"channel_id":"C2"}"#,
        1,
        "resolver",
        "forged-identity",
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
  async fn verify_connector(
    &self,
    _workspace_id: &str,
    _actor_id: &str,
  ) -> Result<(), TargetVerificationError> {
    if matches!(self.0, VerifyMode::Slow) {
      tokio::time::sleep(Duration::from_millis(50)).await;
    }
    match self.0 {
      VerifyMode::Unavailable => Err(TargetVerificationError::Unavailable),
      VerifyMode::NotAllowed => Err(TargetVerificationError::NotAllowed),
      _ => Ok(()),
    }
  }
  async fn verify_channel(
    &self,
    _workspace_id: &str,
    _actor_id: &str,
    _channel_id: &str,
  ) -> Result<(), TargetVerificationError> {
    Ok(())
  }
  async fn verify_user(
    &self,
    _workspace_id: &str,
    _actor_id: &str,
    _user_id: &str,
  ) -> Result<(), TargetVerificationError> {
    Ok(())
  }
}

fn verified_handler(
  store: StateStore,
  mode: VerifyMode,
  timeout: Duration,
) -> ScheduleDynamicToolHandler {
  let mut targets = TargetResolverRegistry::with_defaults();
  targets.register(Arc::new(VerifiedSlackTargetResolver::new(
    Arc::new(FakeVerifier(mode)),
    timeout,
  )));
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
      thread_id: Some("T1".to_owned()),
      message_ts: Some("T1".to_owned()),
      user_id: Some(actor.to_owned()),
      recent_context: None,
      conversation_summary: None,
    }),
  }
}

fn invocation(actor: &str) -> ScheduleInvocation {
  invocation_for("slack", "W1", actor)
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
  serde_json::from_str(
    output["contentItems"][0]["text"]
      .as_str()
      .expect("content text"),
  )
  .expect("JSON content")
}

#[tokio::test]
async fn test_schedule_tools_owner_lifecycle_idempotency_and_restart() {
  let temp = tempdir().expect("tempdir");
  let state_dir = temp.path().join("state");
  let store = StateStore::initialize(&state_dir, None)
    .await
    .expect("state");
  let audit_store = store.clone();
  let handler = ScheduleDynamicToolHandler::new_with_now(store, 100);
  let owner = invocation("U1");

  let created = output_content(
    &handler
      .handle_tool_call_async(&owner, "schedule_create", create_arguments("create-1"))
      .await,
  );
  let job_id = created["job_id"].as_str().expect("job id").to_owned();
  assert_eq!(created["generation"], 0);

  let replay = output_content(
    &handler
      .handle_tool_call_async(&owner, "schedule_create", create_arguments("create-1"))
      .await,
  );
  assert_eq!(replay, created);

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
  let audit = audit_store
    .list_schedule_audit_summaries("create-1")
    .await
    .expect("denied audit");
  assert!(audit.iter().any(|entry| {
    entry.outcome == "denied"
      && entry.decision == "deny"
      && entry.error_code.as_deref() == Some("unauthorized")
  }));

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
  assert!(audit.iter().any(|entry| entry.outcome == "capability"));
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
    assert!(audit.iter().any(|entry| entry.outcome == "resolver"));
  }
}

#[tokio::test]
async fn test_capability_registry_is_invocation_scoped_and_revalidates_snapshots() {
  let temp = tempdir().expect("tempdir");
  let store = StateStore::initialize(&temp.path().join("state"), None)
    .await
    .expect("state");
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
  assert!(output.to_string().contains("capability_unavailable"));
}

#[tokio::test]
async fn test_service_rejects_malicious_resolver_snapshot_before_state_transaction() {
  let temp = tempdir().expect("tempdir");
  let store = StateStore::initialize(&temp.path().join("state"), None)
    .await
    .expect("state");
  let service = ScheduleService::with_components(
    store,
    Arc::new(MaliciousTargetResolver),
    Arc::new(DefaultCapabilityRegistry),
    Arc::new(OwnerOnlyAuthorizationPolicy),
    Duration::from_millis(50),
  );
  let handler = ScheduleDynamicToolHandler::from_service(service, Some(100));
  let mut arguments = create_arguments("malicious-target");
  arguments["target"] = json!({"kind": "channel", "channel_id": "C2"});
  let output = handler
    .handle_tool_call_async(&invocation("U1"), "schedule_create", arguments)
    .await;
  assert!(
    output.to_string().contains("resolver_unavailable"),
    "{output}"
  );
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
    json!({"kind": "channel", "channel_id": "C2"}),
    json!({"kind": "direct_message", "user_id": "U2"}),
    json!({"kind": "thread", "channel_id": "C2", "thread_id": "T2"}),
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
