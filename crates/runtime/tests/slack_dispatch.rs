use codeoff_agent_contract::{AgentBackend, AgentTask, AgentTaskResult};
use codeoff_channel_contract::{
  ChannelContextPage, ChannelContextRequest, ChannelEvent, ChannelEventKind, ChannelReplyTarget,
};
use codeoff_runtime::{
  ConversationDispatchLocks, DispatchOutcome, NoopProcessingStreamManager,
  ProcessingStreamFinishOutcome, ProcessingStreamFinishRequest, ProcessingStreamManager,
  ProcessingStreamStartRequest,
  channel_tools::{
    ChannelContextProvider, ChannelContextProviderError, ChannelDynamicToolHandler,
    GetDeliveryStatusRequest, get_delivery_status,
  },
  dispatch_next_channel_event, dispatch_next_channel_event_with_processing_streams,
  dispatch_next_channel_event_with_processing_streams_and_context,
  dispatch_next_channel_event_with_processing_streams_context_and_locks,
};
use codeoff_state::{
  ChannelConversationKey, ChannelEventStatusKind, SlackDeliveryStatusKind, SlackSourceEvent,
  StateError, StateStore,
};
use serde_json::Value;
use std::sync::Mutex;
use tempfile::tempdir;

#[derive(Debug)]
struct FakeBackend {
  result: Result<AgentTaskResult, String>,
  tasks: Mutex<Vec<AgentTask>>,
}

impl FakeBackend {
  fn new(result: Result<AgentTaskResult, String>) -> Self {
    Self {
      result,
      tasks: Mutex::new(Vec::new()),
    }
  }
}

impl AgentBackend for FakeBackend {
  fn provider_name(&self) -> &'static str {
    "fake-codex"
  }

  fn run(&self, task: AgentTask) -> Result<AgentTaskResult, String> {
    self.tasks.lock().expect("tasks").push(task);
    self.result.clone()
  }
}

#[derive(Default)]
struct FakeProcessingStreamManager {
  starts: Mutex<Vec<ProcessingStreamStartRequest>>,
  finishes: Mutex<Vec<ProcessingStreamFinishRequest>>,
  finish_existing_stream: Mutex<bool>,
}

struct FakeContextProvider {
  requests: Mutex<Vec<ChannelContextRequest>>,
  page: ChannelContextPage,
}

struct FailingContextProvider {
  error: ChannelContextProviderError,
  requests: Mutex<Vec<ChannelContextRequest>>,
}

impl FakeContextProvider {
  fn new(page: ChannelContextPage) -> Self {
    Self {
      requests: Mutex::new(Vec::new()),
      page,
    }
  }
}

impl FailingContextProvider {
  fn new(error: ChannelContextProviderError) -> Self {
    Self {
      error,
      requests: Mutex::new(Vec::new()),
    }
  }
}

#[async_trait::async_trait]
impl ChannelContextProvider for FakeContextProvider {
  async fn fetch_context(
    &self,
    request: ChannelContextRequest,
  ) -> Result<ChannelContextPage, ChannelContextProviderError> {
    self.requests.lock().expect("requests").push(request);
    Ok(self.page.clone())
  }
}

#[async_trait::async_trait]
impl ChannelContextProvider for FailingContextProvider {
  async fn fetch_context(
    &self,
    request: ChannelContextRequest,
  ) -> Result<ChannelContextPage, ChannelContextProviderError> {
    self.requests.lock().expect("requests").push(request);
    Err(self.error.clone())
  }
}

#[async_trait::async_trait]
impl ProcessingStreamManager for FakeProcessingStreamManager {
  async fn start_processing_stream(
    &self,
    request: ProcessingStreamStartRequest,
  ) -> Result<(), StateError> {
    self.starts.lock().expect("starts").push(request);
    Ok(())
  }

  async fn finish_processing_stream(
    &self,
    request: ProcessingStreamFinishRequest,
  ) -> Result<ProcessingStreamFinishOutcome, StateError> {
    self
      .finishes
      .lock()
      .expect("finishes")
      .push(request.clone());
    Ok(ProcessingStreamFinishOutcome {
      request_dedupe_key: request.request_dedupe_key,
      queued: true,
      completed_existing_stream: *self
        .finish_existing_stream
        .lock()
        .expect("finish existing stream"),
    })
  }
}

async fn queue_mention(store: &StateStore) {
  let event = ChannelEvent::new(
    "slack",
    "slack-default",
    "workspace-1",
    "event-1",
    "dedupe-1",
    ChannelEventKind::MentionReceived,
  )
  .expect("event")
  .with_text(Some("please restart the failed worker"))
  .with_source_details(
    ChannelReplyTarget::Thread {
      channel_id: "C1".to_owned(),
      thread_id: "100.0".to_owned(),
    },
    "slack://workspace-1/C1/100.0",
  )
  .expect("source details");
  store
    .persist_slack_source_event(
      &SlackSourceEvent {
        workspace_id: "workspace-1".to_owned(),
        event_kind: "app_mention".to_owned(),
        dedupe_key: "dedupe-1".to_owned(),
        envelope_id: Some("envelope-1".to_owned()),
        event_id: Some("event-1".to_owned()),
        channel_id: Some("C1".to_owned()),
        thread_ts: Some("99.0".to_owned()),
        message_ts: Some("100.0".to_owned()),
        user_id: Some("U1".to_owned()),
        raw_payload_json: "{}".to_owned(),
      },
      &event,
    )
    .await
    .expect("queue mention");
}

async fn queue_thread_followup_mention(store: &StateStore) {
  let event = ChannelEvent::new(
    "slack",
    "slack-default",
    "workspace-1",
    "event-2",
    "dedupe-2",
    ChannelEventKind::MentionReceived,
  )
  .expect("event")
  .with_source_details(
    ChannelReplyTarget::Thread {
      channel_id: "C1".to_owned(),
      thread_id: "99.0".to_owned(),
    },
    "slack://workspace-1/C1/99.0",
  )
  .expect("source details");
  store
    .persist_slack_source_event(
      &SlackSourceEvent {
        workspace_id: "workspace-1".to_owned(),
        event_kind: "app_mention".to_owned(),
        dedupe_key: "dedupe-2".to_owned(),
        envelope_id: Some("envelope-2".to_owned()),
        event_id: Some("event-2".to_owned()),
        channel_id: Some("C1".to_owned()),
        thread_ts: Some("99.0".to_owned()),
        message_ts: Some("101.0".to_owned()),
        user_id: Some("U1".to_owned()),
        raw_payload_json: "{}".to_owned(),
      },
      &event,
    )
    .await
    .expect("queue followup mention");
}

async fn queue_direct_message(store: &StateStore) {
  queue_direct_message_with(store, "dm-event-1", "dm-dedupe-1", "D1", "200.0").await;
}

async fn queue_direct_message_with(
  store: &StateStore,
  event_id: &str,
  dedupe_key: &str,
  channel_id: &str,
  message_ts: &str,
) {
  let event = ChannelEvent::new(
    "slack",
    "slack-default",
    "workspace-1",
    event_id,
    dedupe_key,
    ChannelEventKind::DirectMessageReceived,
  )
  .expect("event")
  .with_source_details(
    ChannelReplyTarget::Channel {
      channel_id: channel_id.to_owned(),
    },
    format!("slack://workspace-1/{channel_id}/{message_ts}"),
  )
  .expect("source details");
  store
    .persist_slack_source_event(
      &SlackSourceEvent {
        workspace_id: "workspace-1".to_owned(),
        event_kind: "message".to_owned(),
        dedupe_key: dedupe_key.to_owned(),
        envelope_id: Some("dm-envelope-1".to_owned()),
        event_id: Some(event_id.to_owned()),
        channel_id: Some(channel_id.to_owned()),
        thread_ts: Some(message_ts.to_owned()),
        message_ts: Some(message_ts.to_owned()),
        user_id: Some("U1".to_owned()),
        raw_payload_json: "{}".to_owned(),
      },
      &event,
    )
    .await
    .expect("queue direct message");
}

async fn queue_thread_message_with(
  store: &StateStore,
  event_id: &str,
  dedupe_key: &str,
  channel_id: &str,
  thread_ts: &str,
  message_ts: &str,
) {
  let event = ChannelEvent::new(
    "slack",
    "slack-default",
    "workspace-1",
    event_id,
    dedupe_key,
    ChannelEventKind::MentionReceived,
  )
  .expect("event")
  .with_source_details(
    ChannelReplyTarget::Thread {
      channel_id: channel_id.to_owned(),
      thread_id: thread_ts.to_owned(),
    },
    format!("slack://workspace-1/{channel_id}/{message_ts}"),
  )
  .expect("source details");
  store
    .persist_slack_source_event(
      &SlackSourceEvent {
        workspace_id: "workspace-1".to_owned(),
        event_kind: "app_mention".to_owned(),
        dedupe_key: dedupe_key.to_owned(),
        envelope_id: Some(format!("{event_id}-envelope")),
        event_id: Some(event_id.to_owned()),
        channel_id: Some(channel_id.to_owned()),
        thread_ts: Some(thread_ts.to_owned()),
        message_ts: Some(message_ts.to_owned()),
        user_id: Some("U1".to_owned()),
        raw_payload_json: "{}".to_owned(),
      },
      &event,
    )
    .await
    .expect("queue thread message");
}

async fn queue_ordinary_message(store: &StateStore) {
  let event = ChannelEvent::new(
    "slack",
    "slack-default",
    "workspace-1",
    "message-event-1",
    "message-dedupe-1",
    ChannelEventKind::MessageReceived,
  )
  .expect("event")
  .with_source_details(
    ChannelReplyTarget::Thread {
      channel_id: "C1".to_owned(),
      thread_id: "300.0".to_owned(),
    },
    "slack://workspace-1/C1/300.0",
  )
  .expect("source details");
  store
    .persist_slack_source_event(
      &SlackSourceEvent {
        workspace_id: "workspace-1".to_owned(),
        event_kind: "message".to_owned(),
        dedupe_key: "message-dedupe-1".to_owned(),
        envelope_id: Some("message-envelope-1".to_owned()),
        event_id: Some("message-event-1".to_owned()),
        channel_id: Some("C1".to_owned()),
        thread_ts: Some("300.0".to_owned()),
        message_ts: Some("300.0".to_owned()),
        user_id: Some("U1".to_owned()),
        raw_payload_json: "{}".to_owned(),
      },
      &event,
    )
    .await
    .expect("queue ordinary message");
}

async fn queue_channel_message(store: &StateStore) {
  let event = ChannelEvent::new(
    "slack",
    "slack-default",
    "workspace-1",
    "channel-event-1",
    "channel-dedupe-1",
    ChannelEventKind::MessageReceived,
  )
  .expect("event")
  .with_source_details(
    ChannelReplyTarget::Channel {
      channel_id: "C1".to_owned(),
    },
    "slack://workspace-1/C1/400.0",
  )
  .expect("source details");
  store
    .persist_slack_source_event(
      &SlackSourceEvent {
        workspace_id: "workspace-1".to_owned(),
        event_kind: "message".to_owned(),
        dedupe_key: "channel-dedupe-1".to_owned(),
        envelope_id: Some("channel-envelope-1".to_owned()),
        event_id: Some("channel-event-1".to_owned()),
        channel_id: Some("C1".to_owned()),
        thread_ts: None,
        message_ts: Some("400.0".to_owned()),
        user_id: Some("U1".to_owned()),
        raw_payload_json: "{}".to_owned(),
      },
      &event,
    )
    .await
    .expect("queue channel message");
}

#[tokio::test]
async fn dispatch_persists_private_draft_with_slack_source_references() {
  let temp = tempdir().expect("tempdir");
  let store = StateStore::initialize(temp.path(), None)
    .await
    .expect("store");
  queue_mention(&store).await;

  let outcome = dispatch_next_channel_event(
    &store,
    &FakeBackend::new(Ok(AgentTaskResult::draft(
      "Review the request and prepare a plan.",
    ))),
  )
  .await
  .expect("dispatch");

  assert_eq!(
    outcome,
    DispatchOutcome::Dispatched {
      event_id: "event-1".to_owned()
    }
  );
  let draft = store
    .latest_agent_draft()
    .await
    .expect("draft")
    .expect("stored draft");
  assert_eq!(draft.provider, "fake-codex");
  assert_eq!(draft.channel_id.as_deref(), Some("C1"));
  assert_eq!(draft.thread_id.as_deref(), Some("99.0"));
  assert_eq!(draft.message_ts.as_deref(), Some("100.0"));
  assert_eq!(draft.user_id.as_deref(), Some("U1"));
  assert_eq!(draft.event_id, "event-1");
  assert_eq!(draft.dedupe_key, "dedupe-1");
  assert_eq!(draft.content, "Review the request and prepare a plan.");
}

#[tokio::test]
async fn dispatch_does_not_start_processing_stream_for_slack_mention() {
  let temp = tempdir().expect("tempdir");
  let store = StateStore::initialize(temp.path(), None)
    .await
    .expect("store");
  queue_mention(&store).await;
  let streams = FakeProcessingStreamManager::default();
  let backend = FakeBackend::new(Ok(AgentTaskResult::accepted_dispatch()));

  dispatch_next_channel_event_with_processing_streams(&store, &backend, &streams)
    .await
    .expect("dispatch");

  assert!(streams.starts.lock().expect("starts").is_empty());
}

#[tokio::test]
async fn dispatch_does_not_start_processing_stream_for_slack_direct_message() {
  let temp = tempdir().expect("tempdir");
  let store = StateStore::initialize(temp.path(), None)
    .await
    .expect("store");
  queue_direct_message(&store).await;
  let streams = FakeProcessingStreamManager::default();
  let backend = FakeBackend::new(Ok(AgentTaskResult::accepted_dispatch()));

  dispatch_next_channel_event_with_processing_streams(&store, &backend, &streams)
    .await
    .expect("dispatch");

  assert!(streams.starts.lock().expect("starts").is_empty());
}

#[tokio::test]
async fn dispatch_persists_private_draft_for_slack_direct_messages() {
  let temp = tempdir().expect("tempdir");
  let store = StateStore::initialize(temp.path(), None)
    .await
    .expect("store");
  queue_direct_message(&store).await;

  let outcome = dispatch_next_channel_event(
    &store,
    &FakeBackend::new(Ok(AgentTaskResult::draft("Review the DM."))),
  )
  .await
  .expect("dispatch");

  assert_eq!(
    outcome,
    DispatchOutcome::Dispatched {
      event_id: "dm-event-1".to_owned()
    }
  );
  let draft = store
    .latest_agent_draft()
    .await
    .expect("draft")
    .expect("stored draft");
  assert_eq!(draft.channel_id.as_deref(), Some("D1"));
  assert_eq!(draft.thread_id.as_deref(), Some("200.0"));
  assert_eq!(draft.message_ts.as_deref(), Some("200.0"));
  assert_eq!(draft.user_id.as_deref(), Some("U1"));
  assert_eq!(draft.event_id, "dm-event-1");
  assert_eq!(draft.dedupe_key, "dm-dedupe-1");
  assert_eq!(draft.content, "Review the DM.");
}

#[tokio::test]
async fn conversation_locks_keep_same_direct_message_serial() {
  let temp = tempdir().expect("tempdir");
  let store = StateStore::initialize(temp.path(), None)
    .await
    .expect("store");
  queue_direct_message_with(&store, "dm-event-2", "dm-dedupe-2", "D1", "201.0").await;

  let locks = ConversationDispatchLocks::default();
  let _permit = locks
    .try_acquire("slack:workspace-1:dm:D1:U1")
    .expect("pre-acquire dm lock");

  let streams = NoopProcessingStreamManager;
  let backend = FakeBackend::new(Ok(AgentTaskResult::accepted_dispatch()));
  let second = dispatch_next_channel_event_with_processing_streams_context_and_locks(
    &store,
    &backend,
    &streams,
    None,
    None,
    Some(&locks),
  )
  .await
  .expect("second dispatch");

  assert_eq!(second, DispatchOutcome::Idle);
  assert_eq!(
    store
      .channel_event_status("slack", "workspace-1", "dm-dedupe-2")
      .await
      .expect("status")
      .expect("queued status")
      .status,
    ChannelEventStatusKind::Pending
  );
  assert!(backend.tasks.lock().expect("tasks").is_empty());
}

#[tokio::test]
async fn conversation_locks_allow_different_threads_to_dispatch_together() {
  let temp = tempdir().expect("tempdir");
  let store = StateStore::initialize(temp.path(), None)
    .await
    .expect("store");
  queue_thread_message_with(
    &store,
    "thread-event-2",
    "thread-dedupe-2",
    "C1",
    "200.0",
    "201.0",
  )
  .await;

  let locks = ConversationDispatchLocks::default();
  let _permit = locks
    .try_acquire("slack:workspace-1:thread:C1:100.0")
    .expect("pre-acquire unrelated thread lock");
  let backend = FakeBackend::new(Ok(AgentTaskResult::accepted_dispatch()));
  let streams = NoopProcessingStreamManager;

  let outcome = dispatch_next_channel_event_with_processing_streams_context_and_locks(
    &store,
    &backend,
    &streams,
    None,
    None,
    Some(&locks),
  )
  .await
  .expect("dispatch");

  assert_eq!(
    outcome,
    DispatchOutcome::Accepted {
      event_id: "thread-event-2".to_owned()
    }
  );
  assert_eq!(backend.tasks.lock().expect("tasks").len(), 1);
}

#[tokio::test]
async fn dispatch_bootstraps_recent_direct_message_context() {
  let temp = tempdir().expect("tempdir");
  let store = StateStore::initialize(temp.path(), None)
    .await
    .expect("store");
  queue_direct_message(&store).await;
  let history_event = ChannelEvent::new(
    "slack",
    "slack-default",
    "workspace-1",
    "history-event-1",
    "history-dedupe-1",
    ChannelEventKind::DirectMessageReceived,
  )
  .expect("history event")
  .with_text(Some("月球上都有什么"));
  let context_provider = FakeContextProvider::new(ChannelContextPage {
    events: vec![history_event],
    next_cursor: Some("older-dm-page".to_owned()),
  });
  let backend = FakeBackend::new(Ok(AgentTaskResult::accepted_dispatch()));
  let streams = FakeProcessingStreamManager::default();

  dispatch_next_channel_event_with_processing_streams_and_context(
    &store,
    &backend,
    &streams,
    Some(&context_provider),
    Some(4),
  )
  .await
  .expect("dispatch");

  let context = {
    let tasks = backend.tasks.lock().expect("tasks");
    tasks[0]
      .context
      .channel_context
      .clone()
      .expect("bootstrapped context")
  };
  assert!(context.contains("\"target_kind\": \"direct_message\""));
  assert!(context.contains("\"schema\": \"codeoff.channel_context.v1\""));
  assert!(context.contains("\"current_message\""));
  assert!(context.contains("月球上都有什么"));
  assert!(context.contains("older-dm-page"));
  let attempt = store
    .latest_context_fetch_attempt("workspace-1", "dm-dedupe-1")
    .await
    .expect("attempt")
    .expect("stored attempt");
  assert_eq!(attempt.status, "success");
  assert_eq!(attempt.error_kind, None);
  assert_eq!(
    *context_provider.requests.lock().expect("requests"),
    vec![ChannelContextRequest {
      connector_id: "slack-default".to_owned(),
      workspace_id: "workspace-1".to_owned(),
      target: ChannelReplyTarget::Channel {
        channel_id: "D1".to_owned(),
      },
      limit: 4,
      cursor: None,
    }]
  );
}

#[tokio::test]
async fn dispatch_records_context_fetch_failure_and_injects_warning() {
  let temp = tempdir().expect("tempdir");
  let store = StateStore::initialize(temp.path(), None)
    .await
    .expect("store");
  queue_mention(&store).await;
  let context_provider = FailingContextProvider::new(ChannelContextProviderError::RateLimited {
    retry_after_seconds: Some(30),
  });
  let backend = FakeBackend::new(Err("app server offline".to_owned()));
  let streams = FakeProcessingStreamManager::default();

  dispatch_next_channel_event_with_processing_streams_and_context(
    &store,
    &backend,
    &streams,
    Some(&context_provider),
    Some(4),
  )
  .await
  .expect("dispatch");

  let attempt = store
    .latest_context_fetch_attempt("workspace-1", "dedupe-1")
    .await
    .expect("attempt")
    .expect("stored attempt");
  assert_eq!(attempt.operation, "slack_bootstrap_context");
  assert_eq!(attempt.workspace_id, "workspace-1");
  assert_eq!(attempt.channel_id.as_deref(), Some("C1"));
  assert_eq!(attempt.thread_id.as_deref(), Some("99.0"));
  assert_eq!(attempt.message_ts.as_deref(), Some("100.0"));
  assert_eq!(attempt.dedupe_key, "dedupe-1");
  assert_eq!(attempt.status, "failed");
  assert_eq!(attempt.error_kind.as_deref(), Some("rate_limited"));
  assert!(
    attempt
      .error_message
      .as_deref()
      .expect("error message")
      .contains("retry after Some(30) seconds")
  );

  let tasks = backend.tasks.lock().expect("tasks");
  let context = tasks[0]
    .context
    .channel_context
    .as_deref()
    .expect("context warning");
  assert!(context.contains("\"warnings\""));
  assert!(context.contains("\"context_fetch_failed\""));
  assert!(context.contains("\"error_kind\": \"rate_limited\""));
  assert!(context.contains("retry after Some(30) seconds"));
}

#[tokio::test]
async fn dispatch_persists_private_draft_for_ordinary_slack_messages() {
  let temp = tempdir().expect("tempdir");
  let store = StateStore::initialize(temp.path(), None)
    .await
    .expect("store");
  queue_ordinary_message(&store).await;

  let outcome = dispatch_next_channel_event(
    &store,
    &FakeBackend::new(Ok(AgentTaskResult::draft("Review the ordinary message."))),
  )
  .await
  .expect("dispatch");

  assert_eq!(
    outcome,
    DispatchOutcome::Dispatched {
      event_id: "message-event-1".to_owned()
    }
  );
  assert_eq!(
    store
      .latest_agent_draft()
      .await
      .expect("draft")
      .expect("stored draft")
      .content,
    "Review the ordinary message."
  );
}

#[tokio::test]
async fn dispatch_marks_accepted_codex_turn_without_persisting_placeholder_draft() {
  let temp = tempdir().expect("tempdir");
  let store = StateStore::initialize(temp.path(), None)
    .await
    .expect("store");
  queue_mention(&store).await;

  let outcome = dispatch_next_channel_event(
    &store,
    &FakeBackend::new(Ok(AgentTaskResult::accepted_dispatch())),
  )
  .await
  .expect("dispatch");

  assert_eq!(
    outcome,
    DispatchOutcome::Accepted {
      event_id: "event-1".to_owned()
    }
  );
  assert_eq!(store.latest_agent_draft().await.expect("draft query"), None);
}

#[tokio::test]
async fn gateway_smoke_dispatches_fake_codex_tool_reply_and_resumes_slack_thread() {
  let temp = tempdir().expect("tempdir");
  let store = StateStore::initialize(temp.path(), None)
    .await
    .expect("store");
  queue_mention(&store).await;
  let first_backend = FakeBackend::new(Ok(AgentTaskResult::accepted_dispatch_with_thread(
    "codex-thread-smoke",
  )));

  let outcome = dispatch_next_channel_event(&store, &first_backend)
    .await
    .expect("dispatch");

  assert_eq!(
    outcome,
    DispatchOutcome::Accepted {
      event_id: "event-1".to_owned()
    }
  );
  let (first_conversation_key, first_resume_thread_id) = {
    let first_tasks = first_backend.tasks.lock().expect("first tasks");
    (
      first_tasks[0].context.conversation_key.clone(),
      first_tasks[0].context.resume_thread_id.clone(),
    )
  };
  assert_eq!(first_conversation_key, "slack:workspace-1:thread:C1:99.0");
  assert_eq!(first_resume_thread_id, None);

  let handler = ChannelDynamicToolHandler::new_with_now(store.clone(), 100);
  let queued = handler
    .handle_tool_call_async(
      "channel_reply_to_event",
      serde_json::json!({
        "connector_id": "slack-default",
        "workspace_id": "workspace-1",
        "event_dedupe_key": "dedupe-1",
        "request_dedupe_key": "reply-smoke-1",
        "text": "Queued through the channel gateway."
      }),
    )
    .await;

  assert_eq!(queued["success"], true, "{queued}");
  let delivery = get_delivery_status(
    &store,
    GetDeliveryStatusRequest {
      workspace_id: "workspace-1".to_owned(),
      request_dedupe_key: "reply-smoke-1".to_owned(),
      now_unix_seconds: 100,
    },
  )
  .await
  .expect("status")
  .expect("delivery status");
  assert_eq!(delivery.status, SlackDeliveryStatusKind::Pending);
  assert_eq!(delivery.channel_id, "C1");
  assert_eq!(delivery.thread_ts.as_deref(), Some("99.0"));

  queue_thread_followup_mention(&store).await;
  let second_backend = FakeBackend::new(Ok(AgentTaskResult::accepted_dispatch()));
  let outcome = dispatch_next_channel_event(&store, &second_backend)
    .await
    .expect("resume dispatch");

  assert_eq!(
    outcome,
    DispatchOutcome::Accepted {
      event_id: "event-2".to_owned()
    }
  );
  let second_tasks = second_backend.tasks.lock().expect("second tasks");
  assert_eq!(
    second_tasks[0].context.conversation_key,
    "slack:workspace-1:thread:C1:99.0"
  );
  assert_eq!(
    second_tasks[0].context.resume_thread_id.as_deref(),
    Some("codex-thread-smoke")
  );
}

#[tokio::test]
async fn channel_dynamic_tool_handler_queues_reply_and_reports_delivery_status() {
  let temp = tempdir().expect("tempdir");
  let store = StateStore::initialize(temp.path(), None)
    .await
    .expect("store");
  queue_mention(&store).await;
  let handler = ChannelDynamicToolHandler::new_with_now(store.clone(), 100);

  let reply = handler
    .handle_tool_call_async(
      "channel_reply_to_event",
      serde_json::json!({
        "connector_id": "slack-default",
        "workspace_id": "workspace-1",
        "event_dedupe_key": "dedupe-1",
        "request_dedupe_key": "reply-dynamic-1",
        "text": "Queued by dynamic tool."
      }),
    )
    .await;

  assert_eq!(reply["success"], true, "{reply}");
  assert_eq!(reply["contentItems"][0]["type"], "inputText");
  assert!(
    reply["contentItems"][0]["text"]
      .as_str()
      .expect("reply text")
      .contains("\"queued\":true")
  );

  let status = handler
    .handle_tool_call_async(
      "channel_get_delivery_status",
      serde_json::json!({
        "workspace_id": "workspace-1",
        "request_dedupe_key": "reply-dynamic-1"
      }),
    )
    .await;

  assert_eq!(status["success"], true);
  let text = status["contentItems"][0]["text"]
    .as_str()
    .expect("status text");
  assert!(text.contains("\"status\":\"pending\""));
  assert!(text.contains("\"channel_id\":\"C1\""));
  assert!(text.contains("\"thread_ts\":\"99.0\""));
}

#[tokio::test]
async fn dispatch_records_backend_failure_without_dropping_event() {
  let temp = tempdir().expect("tempdir");
  let store = StateStore::initialize(temp.path(), None)
    .await
    .expect("store");
  queue_mention(&store).await;

  let outcome = dispatch_next_channel_event(
    &store,
    &FakeBackend::new(Err("app server offline".to_owned())),
  )
  .await
  .expect("dispatch failure handling");

  assert_eq!(
    outcome,
    DispatchOutcome::Failed {
      event_id: "event-1".to_owned()
    }
  );
  assert_eq!(
    store
      .channel_event_status("slack", "workspace-1", "dedupe-1")
      .await
      .expect("queue state")
      .expect("failed queue event")
      .status,
    ChannelEventStatusKind::Failed
  );
}

#[tokio::test]
async fn dispatch_stops_processing_stream_after_backend_failure() {
  let temp = tempdir().expect("tempdir");
  let store = StateStore::initialize(temp.path(), None)
    .await
    .expect("store");
  queue_mention(&store).await;
  let streams = FakeProcessingStreamManager::default();

  let outcome = dispatch_next_channel_event_with_processing_streams(
    &store,
    &FakeBackend::new(Err("app server offline".to_owned())),
    &streams,
  )
  .await
  .expect("dispatch failure handling");

  assert_eq!(
    outcome,
    DispatchOutcome::Failed {
      event_id: "event-1".to_owned()
    }
  );
  let finishes = streams.finishes.lock().expect("finishes");
  assert_eq!(finishes.len(), 1);
  assert_eq!(finishes[0].connector_id, "slack-default");
  assert_eq!(finishes[0].workspace_id, "workspace-1");
  assert_eq!(finishes[0].event_dedupe_key, "dedupe-1");
  assert_eq!(finishes[0].request_dedupe_key, "dedupe-1:processing-error");
  assert_eq!(finishes[0].channel_id, "C1");
  assert_eq!(finishes[0].thread_ts, Some("99.0".to_owned()));
}

#[tokio::test]
async fn dispatch_records_codex_protocol_failure_without_dropping_event() {
  let temp = tempdir().expect("tempdir");
  let store = StateStore::initialize(temp.path(), None)
    .await
    .expect("store");
  queue_mention(&store).await;

  let outcome = dispatch_next_channel_event(
    &store,
    &FakeBackend::new(Err(
      "codex app server turn/start failed: codex unavailable".to_owned(),
    )),
  )
  .await
  .expect("dispatch failure handling");

  assert_eq!(
    outcome,
    DispatchOutcome::Failed {
      event_id: "event-1".to_owned()
    }
  );
  assert_eq!(
    store
      .channel_event_status("slack", "workspace-1", "dedupe-1")
      .await
      .expect("queue state")
      .expect("failed queue event")
      .status,
    ChannelEventStatusKind::Failed
  );
}

#[tokio::test]
async fn dispatch_uses_slack_thread_as_codex_conversation_key() {
  let temp = tempdir().expect("tempdir");
  let store = StateStore::initialize(temp.path(), None)
    .await
    .expect("store");
  queue_mention(&store).await;
  let backend = FakeBackend::new(Ok(AgentTaskResult::accepted_dispatch()));

  dispatch_next_channel_event(&store, &backend)
    .await
    .expect("dispatch");

  let tasks = backend.tasks.lock().expect("tasks");
  assert_eq!(tasks[0].task_id, "slack:workspace-1:dedupe-1");
  assert_eq!(
    tasks[0].context.conversation_key,
    "slack:workspace-1:thread:C1:99.0"
  );
  assert_eq!(tasks[0].context.resume_thread_id, None);
  assert_eq!(
    tasks[0].context.message_text.as_deref(),
    Some("please restart the failed worker")
  );
}

#[tokio::test]
async fn dispatch_includes_compact_slack_communication_context() {
  let temp = tempdir().expect("tempdir");
  let store = StateStore::initialize(temp.path(), None)
    .await
    .expect("store");
  queue_mention(&store).await;
  let backend = FakeBackend::new(Ok(AgentTaskResult::accepted_dispatch()));

  dispatch_next_channel_event(&store, &backend)
    .await
    .expect("dispatch");

  let tasks = backend.tasks.lock().expect("tasks");
  let context_text = tasks[0]
    .context
    .channel_context
    .as_deref()
    .expect("compact communication context");
  let context: Value = serde_json::from_str(context_text).expect("context json");
  let current_message = &context["current_message"];
  assert_eq!(context["schema"], "codeoff.channel_context.v1");
  assert_eq!(current_message["source_provider"], "slack");
  assert_eq!(current_message["connector_id"], "slack-default");
  assert_eq!(current_message["workspace_id"], "workspace-1");
  assert_eq!(current_message["event_dedupe_key"], "dedupe-1");
  assert_eq!(current_message["conversation_kind"], "thread");
  assert_eq!(current_message["channel_id"], "C1");
  assert_eq!(current_message["thread_ts"], "99.0");
  assert_eq!(current_message["message_ts"], "100.0");
  assert_eq!(current_message["sender"]["user_id"], "U1");
  assert_eq!(current_message["reply_target"]["kind"], "thread");
  assert_eq!(current_message["reply_target"]["channel_id"], "C1");
  assert_eq!(current_message["reply_target"]["thread_ts"], "99.0");
  assert_eq!(
    context["context_hint"],
    "Detailed communication context is available through channel.* tools."
  );
  assert!(context.get("recent_context").is_none());
  assert!(!context_text.contains("attachment"));
  assert!(!context_text.contains("project"));
}

#[tokio::test]
async fn dispatch_uses_existing_codex_thread_for_repeated_conversation() {
  let temp = tempdir().expect("tempdir");
  let store = StateStore::initialize(temp.path(), None)
    .await
    .expect("store");
  queue_mention(&store).await;
  store
    .upsert_channel_conversation_thread_id(
      &ChannelConversationKey {
        provider: "slack".to_owned(),
        workspace_id: "workspace-1".to_owned(),
        conversation_kind: "thread".to_owned(),
        channel_id: Some("C1".to_owned()),
        thread_id: Some("99.0".to_owned()),
        user_id: None,
      },
      "codex-thread-existing",
    )
    .await
    .expect("mapping");
  let backend = FakeBackend::new(Ok(AgentTaskResult::accepted_dispatch()));

  dispatch_next_channel_event(&store, &backend)
    .await
    .expect("dispatch");

  let tasks = backend.tasks.lock().expect("tasks");
  assert_eq!(
    tasks[0].context.resume_thread_id.as_deref(),
    Some("codex-thread-existing")
  );
}

#[tokio::test]
async fn dispatch_includes_conversation_summary_for_repeated_conversation() {
  let temp = tempdir().expect("tempdir");
  let store = StateStore::initialize(temp.path(), None)
    .await
    .expect("store");
  queue_mention(&store).await;
  let first_backend = FakeBackend::new(Ok(AgentTaskResult::draft(
    "Check the worker status and restart only if it is still failed.",
  )));

  dispatch_next_channel_event(&store, &first_backend)
    .await
    .expect("first dispatch");

  queue_thread_followup_mention(&store).await;
  let second_backend = FakeBackend::new(Ok(AgentTaskResult::accepted_dispatch()));

  dispatch_next_channel_event(&store, &second_backend)
    .await
    .expect("second dispatch");

  let tasks = second_backend.tasks.lock().expect("tasks");
  let summary = tasks[0]
    .context
    .conversation_summary
    .as_deref()
    .expect("conversation summary");
  assert!(summary.contains("Conversation State"));
  assert!(summary.contains("Latest user message:\nplease restart the failed worker"));
  assert!(summary.contains(
    "Latest assistant reply:\nCheck the worker status and restart only if it is still failed."
  ));
}

#[tokio::test]
async fn dispatch_persists_codex_thread_mapping_after_successful_new_conversation() {
  let temp = tempdir().expect("tempdir");
  let store = StateStore::initialize(temp.path(), None)
    .await
    .expect("store");
  queue_mention(&store).await;
  let key = ChannelConversationKey {
    provider: "slack".to_owned(),
    workspace_id: "workspace-1".to_owned(),
    conversation_kind: "thread".to_owned(),
    channel_id: Some("C1".to_owned()),
    thread_id: Some("99.0".to_owned()),
    user_id: None,
  };
  let backend = FakeBackend::new(Ok(AgentTaskResult::accepted_dispatch_with_thread(
    "codex-thread-new",
  )));

  dispatch_next_channel_event(&store, &backend)
    .await
    .expect("dispatch");

  assert_eq!(
    store
      .channel_conversation_thread_id(&key)
      .await
      .expect("mapping"),
    Some("codex-thread-new".to_owned())
  );
}

#[tokio::test]
async fn dispatch_does_not_persist_codex_thread_mapping_after_backend_failure() {
  let temp = tempdir().expect("tempdir");
  let store = StateStore::initialize(temp.path(), None)
    .await
    .expect("store");
  queue_mention(&store).await;
  let key = ChannelConversationKey {
    provider: "slack".to_owned(),
    workspace_id: "workspace-1".to_owned(),
    conversation_kind: "thread".to_owned(),
    channel_id: Some("C1".to_owned()),
    thread_id: Some("99.0".to_owned()),
    user_id: None,
  };
  let backend = FakeBackend::new(Err("app server offline".to_owned()));

  dispatch_next_channel_event(&store, &backend)
    .await
    .expect("dispatch");

  assert_eq!(
    store
      .channel_conversation_thread_id(&key)
      .await
      .expect("mapping"),
    None
  );
}

#[tokio::test]
async fn dispatch_replaces_stale_codex_thread_mapping_after_backend_recovery() {
  let temp = tempdir().expect("tempdir");
  let store = StateStore::initialize(temp.path(), None)
    .await
    .expect("store");
  queue_mention(&store).await;
  let key = ChannelConversationKey {
    provider: "slack".to_owned(),
    workspace_id: "workspace-1".to_owned(),
    conversation_kind: "thread".to_owned(),
    channel_id: Some("C1".to_owned()),
    thread_id: Some("99.0".to_owned()),
    user_id: None,
  };
  store
    .upsert_channel_conversation_thread_id(&key, "codex-thread-archived")
    .await
    .expect("old mapping");
  let backend = FakeBackend::new(Ok(AgentTaskResult::accepted_dispatch_with_thread(
    "codex-thread-replacement",
  )));

  dispatch_next_channel_event(&store, &backend)
    .await
    .expect("dispatch");

  let resume_thread_id = {
    let tasks = backend.tasks.lock().expect("tasks");
    tasks[0].context.resume_thread_id.clone()
  };
  assert_eq!(resume_thread_id.as_deref(), Some("codex-thread-archived"));
  assert_eq!(
    store
      .channel_conversation_thread_id(&key)
      .await
      .expect("mapping"),
    Some("codex-thread-replacement".to_owned())
  );
}

#[tokio::test]
async fn dispatch_uses_slack_dm_as_codex_conversation_key() {
  let temp = tempdir().expect("tempdir");
  let store = StateStore::initialize(temp.path(), None)
    .await
    .expect("store");
  queue_direct_message(&store).await;
  let backend = FakeBackend::new(Ok(AgentTaskResult::accepted_dispatch()));

  dispatch_next_channel_event(&store, &backend)
    .await
    .expect("dispatch");

  let tasks = backend.tasks.lock().expect("tasks");
  assert_eq!(tasks[0].task_id, "slack:workspace-1:dm-dedupe-1");
  assert_eq!(
    tasks[0].context.conversation_key,
    "slack:workspace-1:dm:D1:U1"
  );
  assert_eq!(tasks[0].context.resume_thread_id, None);
}

#[tokio::test]
async fn dispatch_uses_slack_channel_fallback_as_codex_conversation_key() {
  let temp = tempdir().expect("tempdir");
  let store = StateStore::initialize(temp.path(), None)
    .await
    .expect("store");
  queue_channel_message(&store).await;
  let backend = FakeBackend::new(Ok(AgentTaskResult::accepted_dispatch()));

  dispatch_next_channel_event(&store, &backend)
    .await
    .expect("dispatch");

  let tasks = backend.tasks.lock().expect("tasks");
  assert_eq!(
    tasks[0].context.conversation_key,
    "slack:workspace-1:channel:C1"
  );
  assert_eq!(tasks[0].context.resume_thread_id, None);
}
