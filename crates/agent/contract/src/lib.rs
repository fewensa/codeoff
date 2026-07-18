//! Provider-neutral agent contracts for Codeoff.

/// A bounded unit of work passed from the runtime to an agent backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentTask {
  pub task_id: String,
  pub objective: String,
  pub context: AgentTaskContext,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentTaskContext {
  pub provider: String,
  pub workspace_id: String,
  pub conversation_key: String,
  pub resume_thread_id: Option<String>,
  pub message_text: Option<String>,
  pub channel_id: Option<String>,
  pub thread_id: Option<String>,
  pub message_ts: Option<String>,
  pub user_id: Option<String>,
  pub channel_context: Option<String>,
  pub conversation_summary: Option<String>,
  pub event_id: String,
  pub dedupe_key: String,
  pub source_reference: Option<String>,
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
}
