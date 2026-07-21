//! Provider-neutral agent contracts for Codeoff.

/// A bounded, ephemeral unit of work passed from the runtime to an agent backend.
///
/// This execution request is deliberately separate from any persisted job definition. It contains
/// run-time provenance and policy and must not be serialized as scheduled user intent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentTask {
  pub task_id: String,
  pub instruction: String,
  pub source: InvocationSource,
  pub session: SessionMode,
  pub channel: Option<ChannelTaskContext>,
  pub previous_success: Option<PreviousSuccessContext>,
  pub tool_policy: ToolPolicy,
  pub feedback_target: Option<FeedbackTarget>,
}

/// Provenance for one invocation. This records origin and never grants authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvocationSource {
  ChannelEvent {
    provider: String,
    workspace_id: String,
    event_id: String,
    dedupe_key: String,
    source_reference: Option<String>,
  },
  ScheduledRun {
    job_id: String,
    run_id: String,
    scheduled_for: String,
  },
  TrustedOperator {
    request_id: String,
  },
  InternalService {
    service: String,
    request_id: String,
  },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionMode {
  Fresh,
  Resume { thread_id: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConversationKind {
  Channel,
  Thread,
  DirectMessage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelReplyStrategy {
  DynamicTool,
  FinalAnswer,
}

/// Optional communication context for interactive channel tasks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelTaskContext {
  pub provider: String,
  pub workspace_id: String,
  pub conversation_key: String,
  pub conversation_kind: ConversationKind,
  pub reply_strategy: ChannelReplyStrategy,
  pub message_text: Option<String>,
  pub channel_id: Option<String>,
  pub thread_id: Option<String>,
  pub message_ts: Option<String>,
  pub user_id: Option<String>,
  pub recent_context: Option<String>,
  pub conversation_summary: Option<String>,
}

/// Snapshot of a previous successful execution, bounded again by the backend before rendering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreviousSuccessContext {
  pub content: String,
  pub was_truncated: bool,
}

/// Per-task policy for Codeoff dynamic tools only.
///
/// This does not govern shell, filesystem, network, sandbox, approval, or configured MCP access.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ToolPolicy {
  #[default]
  None,
  NamedSet(Vec<String>),
}

/// Explicit opt-in for interactive feedback side effects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeedbackTarget {
  Channel {
    conversation_kind: ConversationKind,
    channel_id: String,
    thread_id: Option<String>,
    message_ts: Option<String>,
  },
}

/// Private agent output or dispatch state.
///
/// Runtime callers must explicitly decide whether private draft content may be published. An
/// accepted dispatch is not a draft and must not be persisted as one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentTaskResult {
  Draft {
    content: String,
    codex_thread_id: Option<String>,
  },
  AcceptedDispatch {
    codex_thread_id: Option<String>,
  },
}

impl AgentTaskResult {
  pub fn draft(content: impl Into<String>) -> Self {
    Self::Draft {
      content: content.into(),
      codex_thread_id: None,
    }
  }

  #[must_use]
  pub const fn accepted_dispatch() -> Self {
    Self::AcceptedDispatch {
      codex_thread_id: None,
    }
  }

  pub fn draft_with_thread(content: impl Into<String>, thread_id: impl Into<String>) -> Self {
    Self::Draft {
      content: content.into(),
      codex_thread_id: Some(thread_id.into()),
    }
  }

  pub fn accepted_dispatch_with_thread(thread_id: impl Into<String>) -> Self {
    Self::AcceptedDispatch {
      codex_thread_id: Some(thread_id.into()),
    }
  }

  #[must_use]
  pub fn draft_content(&self) -> Option<&str> {
    match self {
      Self::Draft { content, .. } => Some(content),
      Self::AcceptedDispatch { .. } => None,
    }
  }

  #[must_use]
  pub fn codex_thread_id(&self) -> Option<&str> {
    match self {
      Self::Draft {
        codex_thread_id, ..
      }
      | Self::AcceptedDispatch { codex_thread_id } => codex_thread_id.as_deref(),
    }
  }

  #[must_use]
  pub fn with_codex_thread_id(self, thread_id: impl Into<String>) -> Self {
    let codex_thread_id = Some(thread_id.into());
    match self {
      Self::Draft { content, .. } => Self::Draft {
        content,
        codex_thread_id,
      },
      Self::AcceptedDispatch { .. } => Self::AcceptedDispatch { codex_thread_id },
    }
  }

  /// Validates the final result seam required by a scheduled run.
  ///
  /// # Errors
  ///
  /// Returns stable `missing_result` or `result_too_large` errors when the output cannot become a
  /// durable scheduled result.
  pub fn scheduled_final_text(&self, max_bytes: usize) -> Result<&str, &'static str> {
    let Some(content) = self.draft_content() else {
      return Err("missing_result");
    };
    let content = content.trim();
    if content.is_empty() {
      return Err("missing_result");
    }
    if content.len() > max_bytes {
      return Err("result_too_large");
    }
    Ok(content)
  }
}

/// Replaceable boundary for agent implementations such as Codex, Hermes, or `OpenClaw`.
pub trait AgentBackend {
  fn provider_name(&self) -> &'static str;

  /// Runs one bounded agent task.
  ///
  /// # Errors
  ///
  /// Returns an error string when the backend cannot complete the task.
  fn run(&self, task: AgentTask) -> Result<AgentTaskResult, String>;
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn draft_with_thread_preserves_draft_content_and_thread_id() {
    let result = AgentTaskResult::draft_with_thread("Review this", "thread-1");

    assert_eq!(result.draft_content(), Some("Review this"));
    assert_eq!(result.codex_thread_id(), Some("thread-1"));
  }

  #[test]
  fn accepted_dispatch_with_thread_preserves_dispatch_semantics_and_thread_id() {
    let result = AgentTaskResult::accepted_dispatch_with_thread("thread-1");

    assert_eq!(result.draft_content(), None);
    assert_eq!(result.codex_thread_id(), Some("thread-1"));
  }

  #[test]
  fn scheduled_result_requires_bounded_non_empty_final_text() {
    assert_eq!(
      AgentTaskResult::accepted_dispatch().scheduled_final_text(100),
      Err("missing_result")
    );
    assert_eq!(
      AgentTaskResult::draft(" \n ").scheduled_final_text(100),
      Err("missing_result")
    );
    assert_eq!(
      AgentTaskResult::draft("result").scheduled_final_text(5),
      Err("result_too_large")
    );
    assert_eq!(
      AgentTaskResult::draft(" result ").scheduled_final_text(100),
      Ok("result")
    );
  }

  #[test]
  fn tool_policy_defaults_to_deny_all() {
    assert_eq!(ToolPolicy::default(), ToolPolicy::None);
  }
}
