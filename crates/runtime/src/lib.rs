//! Runtime wiring for Codeoff.
#![allow(
  clippy::missing_errors_doc,
  clippy::missing_panics_doc,
  clippy::map_unwrap_or,
  clippy::needless_pass_by_value,
  clippy::struct_field_names,
  clippy::too_many_lines,
  clippy::unused_self
)]

pub mod channel_tools;
mod schedule_audit;
mod schedule_authorization;
mod schedule_contract;
mod schedule_resolution;
pub mod schedule_service;
pub mod schedule_tools;
pub mod scheduled_delivery;
pub mod scheduled_execution;
pub mod scheduled_remote_protocol;
pub mod scheduled_remote_session;
pub mod scheduled_runner_broker;
pub mod scheduled_runner_control;
pub mod scheduled_runner_executor;
pub mod scheduled_runner_tls;
pub mod scheduler_observability;

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use codeoff_agent_contract::{
  AgentBackend, AgentTask, ChannelReplyStrategy, ChannelTaskContext, ConversationKind,
  FeedbackTarget, InvocationPrincipal, InvocationSource, SessionMode, ToolPolicy,
};
use codeoff_channel_contract::{ChannelEventKind, ChannelReplyTarget};
use codeoff_state::{
  AgentDraft, ChannelConversationKey, ContextFetchAttemptRecord, SlackDeliverySender,
  SlackProcessingIndicatorStatusKind, SlackSourceReferences, SlackStopStreamDeliveryRequest,
  StateError, StateStore,
};
use serde_json::{Value, json};

use crate::channel_tools::{
  CHANNEL_DYNAMIC_TOOL_NAMES, ChannelContextProvider, ChannelContextProviderError,
  ChannelToolError, SlackContextBootstrapRequest, bootstrap_slack_context,
};
use crate::schedule_tools::SCHEDULE_DYNAMIC_TOOL_NAMES;

const CHANNEL_CONVERSATION_SUMMARY_LIMIT: usize = 2_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchOutcome {
  Idle,
  Ignored { event_id: String },
  Dispatched { event_id: String },
  Accepted { event_id: String },
  Failed { event_id: String },
}

#[derive(Debug, Clone, Default)]
pub struct ConversationDispatchLocks {
  active: Arc<Mutex<HashSet<String>>>,
}

impl ConversationDispatchLocks {
  #[must_use]
  pub fn try_acquire(&self, key: &str) -> Option<ConversationDispatchPermit> {
    let mut active = self.active.lock().expect("conversation dispatch locks");
    if !active.insert(key.to_owned()) {
      return None;
    }
    Some(ConversationDispatchPermit {
      key: key.to_owned(),
      active: self.active.clone(),
    })
  }
}

pub struct ConversationDispatchPermit {
  key: String,
  active: Arc<Mutex<HashSet<String>>>,
}

impl Drop for ConversationDispatchPermit {
  fn drop(&mut self) {
    self
      .active
      .lock()
      .expect("conversation dispatch locks")
      .remove(&self.key);
  }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessingStreamStartRequest {
  pub connector_id: String,
  pub workspace_id: String,
  pub event_dedupe_key: String,
  pub channel_id: String,
  pub thread_ts: Option<String>,
  pub source_message_ts: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessingStreamFinishRequest {
  pub connector_id: String,
  pub workspace_id: String,
  pub event_dedupe_key: String,
  pub request_dedupe_key: String,
  pub channel_id: String,
  pub thread_ts: Option<String>,
  pub text: String,
  pub sender: SlackDeliverySender,
  pub now_unix_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessingStreamFinishOutcome {
  pub request_dedupe_key: String,
  pub queued: bool,
  pub completed_existing_stream: bool,
}

#[async_trait]
pub trait ProcessingStreamManager: Send + Sync {
  async fn start_processing_stream(
    &self,
    request: ProcessingStreamStartRequest,
  ) -> Result<(), StateError>;

  async fn finish_processing_stream(
    &self,
    request: ProcessingStreamFinishRequest,
  ) -> Result<ProcessingStreamFinishOutcome, StateError>;
}

pub struct NoopProcessingStreamManager;

#[async_trait]
impl ProcessingStreamManager for NoopProcessingStreamManager {
  async fn start_processing_stream(
    &self,
    _request: ProcessingStreamStartRequest,
  ) -> Result<(), StateError> {
    Ok(())
  }

  async fn finish_processing_stream(
    &self,
    request: ProcessingStreamFinishRequest,
  ) -> Result<ProcessingStreamFinishOutcome, StateError> {
    Ok(ProcessingStreamFinishOutcome {
      request_dedupe_key: request.request_dedupe_key,
      queued: false,
      completed_existing_stream: false,
    })
  }
}

#[derive(Clone)]
pub struct StateProcessingStreamManager {
  state: StateStore,
}

impl StateProcessingStreamManager {
  #[must_use]
  pub const fn new(state: StateStore) -> Self {
    Self { state }
  }
}

#[async_trait]
impl ProcessingStreamManager for StateProcessingStreamManager {
  async fn start_processing_stream(
    &self,
    _request: ProcessingStreamStartRequest,
  ) -> Result<(), StateError> {
    Ok(())
  }

  async fn finish_processing_stream(
    &self,
    request: ProcessingStreamFinishRequest,
  ) -> Result<ProcessingStreamFinishOutcome, StateError> {
    let Some(indicator) = self
      .state
      .slack_processing_indicator(&request.workspace_id, &request.event_dedupe_key)
      .await?
    else {
      return Ok(ProcessingStreamFinishOutcome {
        request_dedupe_key: request.request_dedupe_key,
        queued: false,
        completed_existing_stream: false,
      });
    };
    if indicator.status != SlackProcessingIndicatorStatusKind::Started {
      return Ok(ProcessingStreamFinishOutcome {
        request_dedupe_key: request.request_dedupe_key,
        queued: false,
        completed_existing_stream: false,
      });
    }

    let queued = self
      .state
      .enqueue_slack_stop_stream_delivery(
        &SlackStopStreamDeliveryRequest {
          connector_id: request.connector_id,
          workspace_id: request.workspace_id.clone(),
          request_dedupe_key: request.request_dedupe_key.clone(),
          channel_id: indicator.channel_id,
          thread_ts: indicator.thread_ts,
          message_ts: indicator.message_ts,
          text: request.text,
          sender: request.sender,
        },
        request.now_unix_seconds,
      )
      .await?;
    self
      .state
      .complete_slack_processing_indicator(&request.workspace_id, &request.event_dedupe_key)
      .await?;
    Ok(ProcessingStreamFinishOutcome {
      request_dedupe_key: request.request_dedupe_key,
      queued,
      completed_existing_stream: true,
    })
  }
}

/// Claims one queue event and turns supported Slack events into a private, bounded agent task.
///
/// The receiver loop never calls this function. Agent failures are stored on the queue row so a
/// later retry/recovery policy can act on the original event rather than losing it.
pub async fn dispatch_next_channel_event(
  state: &StateStore,
  backend: &impl AgentBackend,
) -> Result<DispatchOutcome, StateError> {
  dispatch_next_channel_event_with_processing_streams(state, backend, &NoopProcessingStreamManager)
    .await
}

pub async fn dispatch_next_channel_event_with_processing_streams(
  state: &StateStore,
  backend: &impl AgentBackend,
  processing_streams: &dyn ProcessingStreamManager,
) -> Result<DispatchOutcome, StateError> {
  dispatch_next_channel_event_with_processing_streams_and_context(
    state,
    backend,
    processing_streams,
    None,
    None,
  )
  .await
}

pub async fn dispatch_next_channel_event_with_processing_streams_and_context(
  state: &StateStore,
  backend: &impl AgentBackend,
  processing_streams: &dyn ProcessingStreamManager,
  context_provider: Option<&dyn ChannelContextProvider>,
  context_limit: Option<u16>,
) -> Result<DispatchOutcome, StateError> {
  dispatch_next_channel_event_with_processing_streams_context_and_locks(
    state,
    backend,
    processing_streams,
    context_provider,
    context_limit,
    None,
  )
  .await
}

pub async fn dispatch_next_channel_event_with_processing_streams_context_and_locks(
  state: &StateStore,
  backend: &impl AgentBackend,
  processing_streams: &dyn ProcessingStreamManager,
  context_provider: Option<&dyn ChannelContextProvider>,
  context_limit: Option<u16>,
  conversation_locks: Option<&ConversationDispatchLocks>,
) -> Result<DispatchOutcome, StateError> {
  let Some(claimed) = state.claim_next_channel_event().await? else {
    return Ok(DispatchOutcome::Idle);
  };
  let event = claimed.event;
  if event.provider != "slack" || !is_dispatchable_slack_event(event.kind) {
    state.complete_channel_event(claimed.id).await?;
    return Ok(DispatchOutcome::Ignored {
      event_id: event.event_id,
    });
  }

  let source = state
    .slack_source_references(&event.workspace_id, &event.dedupe_key)
    .await?;
  let (target_channel_id, target_thread_id) = match event.reply_target.as_ref() {
    Some(ChannelReplyTarget::Thread {
      channel_id,
      thread_id,
    }) => (Some(channel_id.clone()), Some(thread_id.clone())),
    Some(ChannelReplyTarget::Channel { channel_id }) => (Some(channel_id.clone()), None),
    _ => (None, None),
  };
  let (conversation_key, channel_conversation_key) = channel_conversation_key(&event, &source)
    .unwrap_or_else(|| {
      (
        format!(
          "{}:{}:{}",
          event.provider, event.workspace_id, event.dedupe_key
        ),
        ChannelConversationKey {
          provider: event.provider.clone(),
          workspace_id: event.workspace_id.clone(),
          conversation_kind: "channel".to_owned(),
          channel_id: target_channel_id.clone(),
          thread_id: None,
          user_id: None,
        },
      )
    });
  let _conversation_permit = if let Some(locks) = conversation_locks {
    let Some(permit) = locks.try_acquire(&conversation_key) else {
      state
        .release_channel_event(claimed.id, Duration::from_millis(250))
        .await?;
      return Ok(DispatchOutcome::Idle);
    };
    Some(permit)
  } else {
    None
  };
  let resume_thread_id = state
    .channel_conversation_thread_id(&channel_conversation_key)
    .await?;
  let conversation_summary = state
    .channel_conversation_summary(&channel_conversation_key)
    .await?
    .map(|summary| summary.summary);
  let context_channel_id = source
    .channel_id
    .clone()
    .or_else(|| target_channel_id.clone());
  let context_thread_id = source
    .thread_id
    .clone()
    .or_else(|| target_thread_id.clone());
  let channel_context = build_channel_context_envelope(
    state,
    context_provider,
    &event,
    &source,
    context_channel_id.clone(),
    context_thread_id.clone(),
    context_limit.unwrap_or(20),
    conversation_summary.as_deref(),
  )
  .await?;
  let task = build_slack_agent_task(
    &event,
    &source,
    conversation_key,
    &channel_conversation_key,
    resume_thread_id.clone(),
    channel_context,
    conversation_summary.clone(),
    source.channel_id.clone().or(target_channel_id),
    source.thread_id.clone().or(target_thread_id),
  );
  match backend.run(task) {
    Ok(result) => {
      let codex_thread_id = result.codex_thread_id().map(ToOwned::to_owned);
      let content = result.draft_content().map(ToOwned::to_owned);
      if let Some(content) = content.clone() {
        state
          .save_agent_draft(
            claimed.id,
            &AgentDraft {
              provider: backend.provider_name().to_owned(),
              channel_id: source.channel_id.or_else(|| source_channel_id(&event)),
              thread_id: source.thread_id.or_else(|| source_thread_id(&event)),
              message_ts: source.message_ts,
              user_id: source.user_id,
              event_id: event.event_id.clone(),
              dedupe_key: event.dedupe_key.clone(),
              content,
            },
          )
          .await?;
      }
      if let Some(codex_thread_id) = codex_thread_id
        && resume_thread_id.as_deref() != Some(codex_thread_id.as_str())
      {
        state
          .upsert_channel_conversation_thread_id(&channel_conversation_key, &codex_thread_id)
          .await?;
      }
      if let Some(summary) = updated_conversation_summary(
        conversation_summary.as_deref(),
        event.text.as_deref(),
        content.as_deref(),
      ) {
        state
          .upsert_channel_conversation_summary(&channel_conversation_key, &summary)
          .await?;
      }
      state.complete_channel_event(claimed.id).await?;
      let event_id = event.event_id;
      if result.draft_content().is_some() {
        Ok(DispatchOutcome::Dispatched { event_id })
      } else {
        Ok(DispatchOutcome::Accepted { event_id })
      }
    }
    Err(error) => {
      if let Some(channel_id) = source
        .channel_id
        .clone()
        .or_else(|| source_channel_id(&event))
        && let Err(stream_error) = processing_streams
          .finish_processing_stream(ProcessingStreamFinishRequest {
            connector_id: event.connector_id.clone(),
            workspace_id: event.workspace_id.clone(),
            event_dedupe_key: event.dedupe_key.clone(),
            request_dedupe_key: format!("{}:processing-error", event.dedupe_key),
            channel_id,
            thread_ts: source
              .thread_id
              .clone()
              .or_else(|| source_thread_id(&event)),
            text: "I hit an internal error while processing this message. Please try again."
              .to_owned(),
            sender: SlackDeliverySender::Bot,
            now_unix_seconds: now_unix_seconds(),
          })
          .await
      {
        eprintln!("failed to stop processing stream after backend error: {stream_error}");
      }
      state.fail_channel_event(claimed.id, &error).await?;
      Ok(DispatchOutcome::Failed {
        event_id: event.event_id,
      })
    }
  }
}

#[allow(clippy::too_many_arguments)]
fn build_slack_agent_task(
  event: &codeoff_channel_contract::ChannelEvent,
  source: &SlackSourceReferences,
  conversation_key: String,
  conversation: &ChannelConversationKey,
  resume_thread_id: Option<String>,
  recent_context: Option<String>,
  conversation_summary: Option<String>,
  channel_id: Option<String>,
  thread_id: Option<String>,
) -> AgentTask {
  let conversation_kind = match conversation.conversation_kind.as_str() {
    "dm" => ConversationKind::DirectMessage,
    "thread" => ConversationKind::Thread,
    _ => ConversationKind::Channel,
  };
  let reply_strategy = if conversation_kind == ConversationKind::DirectMessage {
    ChannelReplyStrategy::FinalAnswer
  } else {
    ChannelReplyStrategy::DynamicTool
  };
  let feedback_target = channel_id
    .clone()
    .map(|channel_id| FeedbackTarget::Channel {
      conversation_kind,
      channel_id,
      thread_id: thread_id.clone(),
      message_ts: source.message_ts.clone(),
    });
  let principal = source.user_id.as_ref().map_or_else(
    || InvocationPrincipal::service("codeoff:slack-ingress"),
    |user_id| InvocationPrincipal::channel_actor(&event.provider, &event.workspace_id, user_id),
  );
  AgentTask {
    task_id: format!("slack:{}:{}", event.workspace_id, event.dedupe_key),
    instruction: "Prepare a bounded private draft or action plan for the queued Slack event."
      .to_owned(),
    source: InvocationSource::ChannelEvent {
      provider: event.provider.clone(),
      workspace_id: event.workspace_id.clone(),
      event_id: event.event_id.clone(),
      dedupe_key: event.dedupe_key.clone(),
      source_reference: event.source_reference.clone(),
    },
    principal,
    session: resume_thread_id.map_or(SessionMode::Fresh, |thread_id| SessionMode::Resume {
      thread_id,
    }),
    channel: Some(ChannelTaskContext {
      provider: event.provider.clone(),
      workspace_id: event.workspace_id.clone(),
      conversation_key,
      conversation_kind,
      reply_strategy,
      message_text: event.text.clone(),
      channel_id,
      thread_id,
      message_ts: source.message_ts.clone(),
      user_id: source.user_id.clone(),
      recent_context,
      conversation_summary,
    }),
    previous_success: None,
    tool_policy: ToolPolicy::NamedSet(
      CHANNEL_DYNAMIC_TOOL_NAMES
        .iter()
        .chain(
          source
            .user_id
            .as_ref()
            .into_iter()
            .flat_map(|_| SCHEDULE_DYNAMIC_TOOL_NAMES.iter()),
        )
        .map(|name| (*name).to_owned())
        .collect(),
    ),
    feedback_target,
  }
}

fn updated_conversation_summary(
  previous_summary: Option<&str>,
  user_message: Option<&str>,
  assistant_reply: Option<&str>,
) -> Option<String> {
  let mut sections = Vec::new();
  if let Some(previous_summary) = non_empty_trimmed(previous_summary) {
    sections.push(format!("Previous context:\n{previous_summary}"));
  }
  if let Some(user_message) = non_empty_trimmed(user_message) {
    sections.push(format!("Latest user message:\n{user_message}"));
  }
  if let Some(assistant_reply) = non_empty_trimmed(assistant_reply) {
    sections.push(format!("Latest assistant reply:\n{assistant_reply}"));
  }
  if sections.is_empty() {
    return None;
  }
  Some(bound_summary(format!(
    "Conversation State\n{}",
    sections.join("\n\n")
  )))
}

fn non_empty_trimmed(value: Option<&str>) -> Option<&str> {
  let value = value?.trim();
  if value.is_empty() { None } else { Some(value) }
}

fn bound_summary(summary: String) -> String {
  if summary.len() <= CHANNEL_CONVERSATION_SUMMARY_LIMIT {
    return summary;
  }
  let mut start = summary.len() - CHANNEL_CONVERSATION_SUMMARY_LIMIT;
  while !summary.is_char_boundary(start) {
    start += 1;
  }
  summary[start..].trim_start().to_owned()
}

const fn is_dispatchable_slack_event(kind: ChannelEventKind) -> bool {
  matches!(
    kind,
    ChannelEventKind::MessageReceived
      | ChannelEventKind::MentionReceived
      | ChannelEventKind::DirectMessageReceived
  )
}

fn source_channel_id(event: &codeoff_channel_contract::ChannelEvent) -> Option<String> {
  match event.reply_target.as_ref() {
    Some(
      ChannelReplyTarget::Channel { channel_id } | ChannelReplyTarget::Thread { channel_id, .. },
    ) => Some(channel_id.clone()),
    _ => None,
  }
}

fn source_thread_id(event: &codeoff_channel_contract::ChannelEvent) -> Option<String> {
  match event.reply_target.as_ref() {
    Some(ChannelReplyTarget::Thread { thread_id, .. }) => Some(thread_id.clone()),
    _ => None,
  }
}

fn now_unix_seconds() -> u64 {
  SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap_or_default()
    .as_secs()
}

#[allow(clippy::too_many_arguments)]
async fn build_channel_context_envelope(
  state: &StateStore,
  context_provider: Option<&dyn ChannelContextProvider>,
  event: &codeoff_channel_contract::ChannelEvent,
  source: &SlackSourceReferences,
  channel_id: Option<String>,
  thread_id: Option<String>,
  limit: u16,
  conversation_summary: Option<&str>,
) -> Result<Option<String>, StateError> {
  let mut warnings = Vec::new();
  let mut recent_context = None;
  if let Some(provider) = context_provider {
    let context = bootstrap_slack_context(
      provider,
      SlackContextBootstrapRequest {
        event: event.clone(),
        channel_id: channel_id.clone(),
        thread_id: thread_id.clone(),
        limit,
      },
    )
    .await;
    match context {
      Ok(context) => {
        state
          .record_context_fetch_attempt(&ContextFetchAttemptRecord {
            operation: "slack_bootstrap_context".to_owned(),
            provider: event.provider.clone(),
            workspace_id: event.workspace_id.clone(),
            connector_id: event.connector_id.clone(),
            dedupe_key: event.dedupe_key.clone(),
            channel_id: channel_id.clone(),
            thread_id: thread_id.clone(),
            message_ts: source.message_ts.clone(),
            status: "success".to_owned(),
            error_kind: None,
            error_message: None,
          })
          .await?;
        recent_context = Some(dedup_context_events(context));
      }
      Err(error) => {
        let error_kind = context_fetch_error_kind(&error);
        let error_message = error.to_string();
        state
          .record_context_fetch_attempt(&ContextFetchAttemptRecord {
            operation: "slack_bootstrap_context".to_owned(),
            provider: event.provider.clone(),
            workspace_id: event.workspace_id.clone(),
            connector_id: event.connector_id.clone(),
            dedupe_key: event.dedupe_key.clone(),
            channel_id: channel_id.clone(),
            thread_id: thread_id.clone(),
            message_ts: source.message_ts.clone(),
            status: "failed".to_owned(),
            error_kind: Some(error_kind.to_owned()),
            error_message: Some(error_message.clone()),
          })
          .await?;
        warnings.push(json!({
          "kind": "context_fetch_failed",
          "operation": "slack_bootstrap_context",
          "error_kind": error_kind,
          "error_message": error_message,
          "dedupe_key": event.dedupe_key,
          "channel_id": channel_id,
          "thread_id": thread_id,
          "message_ts": source.message_ts,
        }));
      }
    }
  }

  let conversation_kind = channel_conversation_key(event, source)
    .map(|(_, key)| key.conversation_kind)
    .unwrap_or_else(|| "channel".to_owned());
  let mut envelope = json!({
    "schema": "codeoff.channel_context.v1",
    "context_hint": "Detailed communication context is available through channel.* tools.",
    "current_message": {
      "source_provider": event.provider,
      "workspace_id": event.workspace_id,
      "connector_id": event.connector_id,
      "event_id": event.event_id,
      "event_dedupe_key": event.dedupe_key,
      "conversation_kind": conversation_kind,
      "kind": format!("{:?}", event.kind),
      "text": event.text,
      "source_reference": event.source_reference,
      "channel_id": source.channel_id,
      "thread_id": source.thread_id,
      "thread_ts": source.thread_id,
      "message_ts": source.message_ts,
      "sender": {
        "user_id": source.user_id,
      },
      "reply_target": compact_source_reply_target_json(source, event.reply_target.as_ref()),
    },
  });
  if let Some(summary) = conversation_summary
    && let Some(object) = envelope.as_object_mut()
  {
    object.insert("conversation_summary".to_owned(), json!(summary));
  }
  if let Some(context) = recent_context
    && let Some(object) = envelope.as_object_mut()
  {
    object.insert("recent_context".to_owned(), context);
  }
  if !warnings.is_empty()
    && let Some(object) = envelope.as_object_mut()
  {
    object.insert("warnings".to_owned(), json!(warnings));
  }
  serde_json::to_string_pretty(&envelope)
    .map(Some)
    .map_err(|error| StateError::SerializeStatePayload {
      context: "channel context envelope",
      source: error,
    })
}

fn dedup_context_events(mut context: Value) -> Value {
  let Some(events) = context.get_mut("events").and_then(Value::as_array_mut) else {
    return context;
  };
  let mut seen = HashSet::new();
  events.retain(|event| {
    let key = event
      .get("text")
      .and_then(Value::as_str)
      .map(str::trim)
      .filter(|text| !text.is_empty())
      .map(ToOwned::to_owned)
      .unwrap_or_else(|| event.to_string());
    seen.insert(key)
  });
  context
}

fn compact_reply_target_json(target: Option<&ChannelReplyTarget>) -> Value {
  match target {
    Some(ChannelReplyTarget::Thread {
      channel_id,
      thread_id,
    }) => json!({
      "kind": "thread",
      "channel_id": channel_id,
      "thread_ts": thread_id,
    }),
    Some(ChannelReplyTarget::Channel { channel_id }) => json!({
      "kind": "channel",
      "channel_id": channel_id,
    }),
    Some(ChannelReplyTarget::DirectMessage { user_account_id }) => json!({
      "kind": "direct_message",
      "user_account_id": user_account_id,
    }),
    Some(ChannelReplyTarget::Ephemeral {
      channel_id,
      user_account_id,
    }) => json!({
      "kind": "ephemeral",
      "channel_id": channel_id,
      "user_account_id": user_account_id,
    }),
    None => Value::Null,
  }
}

fn compact_source_reply_target_json(
  source: &SlackSourceReferences,
  fallback: Option<&ChannelReplyTarget>,
) -> Value {
  if let (Some(channel_id), Some(thread_id)) =
    (source.channel_id.as_ref(), source.thread_id.as_ref())
  {
    return json!({
      "kind": "thread",
      "channel_id": channel_id,
      "thread_ts": thread_id,
    });
  }
  if let Some(channel_id) = source.channel_id.as_ref() {
    return json!({
      "kind": "channel",
      "channel_id": channel_id,
    });
  }
  compact_reply_target_json(fallback)
}

fn context_fetch_error_kind(error: &ChannelToolError) -> &'static str {
  match error {
    ChannelToolError::ContextProvider(error) => context_provider_error_kind(error),
    ChannelToolError::MissingReplyTarget => "missing_reply_target",
    ChannelToolError::InvalidRequest(_) => "invalid_request",
    ChannelToolError::State(_) => "state",
    ChannelToolError::MissingSourceEvent => "missing_source_event",
    ChannelToolError::UnsupportedTarget => "unsupported_target",
    ChannelToolError::InvalidSender { .. } => "invalid_sender",
    ChannelToolError::ResourceProvider(_) => "resource_provider",
  }
}

const fn context_provider_error_kind(error: &ChannelContextProviderError) -> &'static str {
  match error {
    ChannelContextProviderError::Request { .. } => "request",
    ChannelContextProviderError::RateLimited { .. } => "rate_limited",
    ChannelContextProviderError::Unavailable => "unavailable",
    ChannelContextProviderError::InvalidResponse { .. } => "invalid_response",
    ChannelContextProviderError::Provider { .. } => "provider",
    ChannelContextProviderError::UnsupportedTarget => "unsupported_target",
    ChannelContextProviderError::Deferred { .. } => "deferred",
  }
}

fn channel_conversation_key(
  event: &codeoff_channel_contract::ChannelEvent,
  source: &SlackSourceReferences,
) -> Option<(String, ChannelConversationKey)> {
  if event.provider != "slack" {
    return None;
  }
  let channel_id = source
    .channel_id
    .clone()
    .or_else(|| source_channel_id(event));
  if event.kind == ChannelEventKind::DirectMessageReceived
    && let (Some(channel_id), Some(user_id)) = (channel_id.clone(), source.user_id.clone())
  {
    let text = format!("slack:{}:dm:{channel_id}:{user_id}", event.workspace_id);
    return Some((
      text,
      ChannelConversationKey {
        provider: event.provider.clone(),
        workspace_id: event.workspace_id.clone(),
        conversation_kind: "dm".to_owned(),
        channel_id: Some(channel_id),
        thread_id: None,
        user_id: Some(user_id),
      },
    ));
  }
  let thread_id = source.thread_id.clone().or_else(|| source_thread_id(event));
  if let (Some(channel_id), Some(thread_id)) = (channel_id.clone(), thread_id) {
    let text = format!(
      "slack:{}:thread:{channel_id}:{thread_id}",
      event.workspace_id
    );
    return Some((
      text,
      ChannelConversationKey {
        provider: event.provider.clone(),
        workspace_id: event.workspace_id.clone(),
        conversation_kind: "thread".to_owned(),
        channel_id: Some(channel_id),
        thread_id: Some(thread_id),
        user_id: None,
      },
    ));
  }
  channel_id.map(|channel_id| {
    let text = format!("slack:{}:channel:{channel_id}", event.workspace_id);
    (
      text,
      ChannelConversationKey {
        provider: event.provider.clone(),
        workspace_id: event.workspace_id.clone(),
        conversation_kind: "channel".to_owned(),
        channel_id: Some(channel_id),
        thread_id: None,
        user_id: None,
      },
    )
  })
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn updated_conversation_summary_uses_structured_sections() {
    let summary = updated_conversation_summary(
      Some("Existing context"),
      Some("那火星呢？"),
      Some("火星直径约 6,779 公里。"),
    )
    .expect("summary");

    assert!(summary.contains("Conversation State"));
    assert!(summary.contains("Previous context:\nExisting context"));
    assert!(summary.contains("Latest user message:\n那火星呢？"));
    assert!(summary.contains("Latest assistant reply:\n火星直径约 6,779 公里。"));
  }
}
