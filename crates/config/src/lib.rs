//! Configuration wiring for Codeoff.

mod config;
mod error;

pub use codeoff_core::{CredentialRevision, RunnerWorkloadIdentity};
pub use config::{
  AgentConfig, CodeoffConfig, ConfigLoadOptions, DataRetentionConfig, DatabaseConfig,
  ScheduledCodexConfig, SchedulerRuntimeConfig, ServerConfig, SlackConfig,
  SlackDirectMessageFeedbackMode, SlackResponseFeedbackConfig, SlackResponseFeedbackMode,
  SlackUserTokenConfig, StateConfig,
};
pub use error::ConfigError;
