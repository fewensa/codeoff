use codeoff_agent_contract::{
  ChannelReplyStrategy, ChannelTaskContext, ConversationKind, InvocationPrincipal, InvocationSource,
};
use codeoff_runtime::schedule_service::ScheduleInvocation;
use codeoff_runtime::schedule_tools::ScheduleDynamicToolHandler;
use codeoff_state::StateStore;
use serde_json::{Value, json};
use tempfile::tempdir;

fn invocation(actor: &str) -> ScheduleInvocation {
  ScheduleInvocation {
    source: InvocationSource::ChannelEvent {
      provider: "slack".to_owned(),
      workspace_id: "W1".to_owned(),
      event_id: "E1".to_owned(),
      dedupe_key: "D1".to_owned(),
      source_reference: None,
    },
    principal: InvocationPrincipal::channel_actor("slack", "W1", actor),
    channel: Some(ChannelTaskContext {
      provider: "slack".to_owned(),
      workspace_id: "W1".to_owned(),
      conversation_key: "slack:W1:C1:T1".to_owned(),
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

fn create_arguments(request_id: &str) -> Value {
  json!({
    "request_id": request_id,
    "instruction": "Check the repository and report only meaningful changes.",
    "schedule": {"kind": "once", "at": 200},
    "target": {"kind": "origin"},
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

  let other_read = handler
    .handle_tool_call_async(&invocation("U2"), "schedule_get", json!({"job_id": job_id}))
    .await;
  assert_eq!(other_read["success"], false);
  assert!(other_read.to_string().contains("not owned"));

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
async fn test_schedule_tools_deny_untrusted_sources_and_unknown_fields() {
  let temp = tempdir().expect("tempdir");
  let store = StateStore::initialize(&temp.path().join("state"), None)
    .await
    .expect("state");
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
  assert!(
    rejected
      .to_string()
      .contains("unknown or unauthorized capability")
  );
}

#[tokio::test]
async fn test_schedule_tools_resolve_supported_target_variants_to_durable_snapshots() {
  let temp = tempdir().expect("tempdir");
  let store = StateStore::initialize(&temp.path().join("state"), None)
    .await
    .expect("state");
  let handler = ScheduleDynamicToolHandler::new_with_now(store, 100);
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
  let specs = ScheduleDynamicToolHandler::new(store).tool_specs();
  assert_eq!(specs.len(), 7);
  for spec in specs {
    assert_eq!(spec["inputSchema"]["type"], "object");
    assert_eq!(spec["inputSchema"]["additionalProperties"], false);
    assert!(
      spec["name"]
        .as_str()
        .is_some_and(|name| name.starts_with("schedule_"))
    );
  }
}
