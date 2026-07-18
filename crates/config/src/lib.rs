//! Configuration wiring for Codeoff.

mod config;
mod error;

pub use config::{
  AgentConfig, CodeoffConfig, ConfigLoadOptions, DataRetentionConfig, DatabaseConfig, ServerConfig,
  SlackConfig, SlackDirectMessageFeedbackMode, SlackResponseFeedbackConfig,
  SlackResponseFeedbackMode, SlackUserTokenConfig, StateConfig,
};
pub use error::ConfigError;
