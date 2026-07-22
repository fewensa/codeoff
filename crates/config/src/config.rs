use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::ConfigError;

const DEFAULT_CONFIG_PATH: &str = "codeoff.toml";
const STATE_DIR_ENV: &str = "CODEOFF_STATE_DIR";
const STATE_DIR_PLACEHOLDER: &str = "${CODEOFF_STATE_DIR:-./.codeoff}";
const SQLITE_DATABASE_DRIVER: &str = "sqlite";

#[derive(Debug, Clone)]
pub struct ConfigLoadOptions {
  config_path: PathBuf,
  explicit_state_dir: Option<PathBuf>,
  state_dir_env: Option<PathBuf>,
}

impl ConfigLoadOptions {
  #[must_use]
  pub fn new() -> Self {
    Self::default()
  }

  #[must_use]
  pub fn config_path(mut self, config_path: PathBuf) -> Self {
    self.config_path = config_path;
    self
  }

  #[must_use]
  pub fn explicit_state_dir(mut self, state_dir: PathBuf) -> Self {
    self.explicit_state_dir = Some(state_dir);
    self
  }

  #[must_use]
  pub fn state_dir_env(mut self, state_dir: PathBuf) -> Self {
    self.state_dir_env = Some(state_dir);
    self
  }
}

impl Default for ConfigLoadOptions {
  fn default() -> Self {
    Self {
      config_path: PathBuf::from(DEFAULT_CONFIG_PATH),
      explicit_state_dir: None,
      state_dir_env: env::var_os(STATE_DIR_ENV).map(PathBuf::from),
    }
  }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct CodeoffConfig {
  pub server: ServerConfig,
  pub state: StateConfig,
  pub database: DatabaseConfig,
  pub data_retention: DataRetentionConfig,
  pub scheduler: SchedulerRuntimeConfig,
  pub slack: SlackConfig,
  pub agent: AgentConfig,
  pub mcp: McpConfig,
  #[serde(skip)]
  database_driver: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SchedulerRuntimeConfig {
  pub enabled: bool,
  pub run_claims_enabled: bool,
  pub delivery_claims_enabled: bool,
  pub recovery_batch_limit: u16,
  pub materialization_batch_limit: u16,
  pub tick_interval_ms: u64,
  pub error_backoff_ms: u64,
  pub lease_seconds: u16,
  pub heartbeat_interval_ms: u64,
  pub total_timeout_seconds: u32,
  pub prepare_grace_ms: u64,
  pub cancellation_grace_ms: u64,
  pub finalization_grace_ms: u64,
  pub retry_delay_seconds: u32,
  pub run_deadline_seconds: u32,
  pub max_attempts: u16,
}

impl Default for SchedulerRuntimeConfig {
  fn default() -> Self {
    Self {
      enabled: false,
      run_claims_enabled: false,
      delivery_claims_enabled: false,
      recovery_batch_limit: 32,
      materialization_batch_limit: 32,
      tick_interval_ms: 250,
      error_backoff_ms: 1_000,
      lease_seconds: 60,
      heartbeat_interval_ms: 15_000,
      total_timeout_seconds: 1_800,
      prepare_grace_ms: 5_000,
      cancellation_grace_ms: 5_000,
      finalization_grace_ms: 5_000,
      retry_delay_seconds: 30,
      run_deadline_seconds: 3_600,
      max_attempts: 3,
    }
  }
}

impl CodeoffConfig {
  /// Loads configuration from `codeoff.toml` when present, then applies state directory overrides.
  ///
  /// # Errors
  ///
  /// Returns an error when the config file exists but cannot be read or parsed.
  pub fn load(options: ConfigLoadOptions) -> Result<Self, ConfigError> {
    let mut config = if options.config_path.exists() {
      let content =
        fs::read_to_string(&options.config_path).map_err(|source| ConfigError::Read {
          path: options.config_path.clone(),
          source,
        })?;

      let mut config: Self = toml::from_str(&content).map_err(|source| ConfigError::Parse {
        path: options.config_path.clone(),
        source,
      })?;
      let database_driver: DatabaseDriverConfig =
        toml::from_str(&content).map_err(|source| ConfigError::Parse {
          path: options.config_path.clone(),
          source,
        })?;
      config.database_driver = Some(database_driver.database.driver);
      config
    } else {
      Self::default()
    };

    if config.state.dir == Path::new(STATE_DIR_PLACEHOLDER) {
      config.state.dir = options
        .state_dir_env
        .clone()
        .unwrap_or_else(|| PathBuf::from("./.codeoff"));
    }

    if let Some(state_dir) = options.state_dir_env {
      config.state.dir = state_dir;
    }

    if let Some(state_dir) = options.explicit_state_dir {
      config.state.dir = state_dir;
    }

    if let Some(database_url) = &mut config.database.url {
      *database_url =
        database_url.replace(STATE_DIR_PLACEHOLDER, &config.state.dir.to_string_lossy());
    }

    Ok(config)
  }

  #[must_use]
  pub fn state_dir(&self) -> &Path {
    &self.state.dir
  }

  #[must_use]
  pub fn database_url(&self) -> Option<&str> {
    self.database.url.as_deref()
  }

  #[must_use]
  pub fn database_driver(&self) -> &str {
    self
      .database_driver
      .as_deref()
      .unwrap_or(SQLITE_DATABASE_DRIVER)
  }

  /// Validates the loaded configuration values needed by the first runtime skeleton.
  ///
  /// # Errors
  ///
  /// Returns an error when required values are empty or the server bind address is invalid.
  pub fn validate(&self) -> Result<(), ConfigError> {
    self
      .server
      .bind
      .parse::<SocketAddr>()
      .map_err(|source| ConfigError::InvalidBind {
        value: self.server.bind.clone(),
        source,
      })?;

    if self.state.dir.as_os_str().is_empty() {
      return Err(ConfigError::EmptyStateDir);
    }

    if self
      .database
      .url
      .as_deref()
      .is_some_and(|database_url| database_url.trim().is_empty())
    {
      return Err(ConfigError::EmptyDatabaseUrl);
    }

    if self.database_driver() != SQLITE_DATABASE_DRIVER {
      return Err(ConfigError::UnsupportedDatabaseDriver);
    }

    self.scheduler.validate()?;

    if self.mcp.enabled {
      match self.mcp.transport.as_str() {
        "stdio" => {}
        "tcp" => {
          let bind =
            self
              .mcp
              .bind
              .parse::<SocketAddr>()
              .map_err(|source| ConfigError::InvalidBind {
                value: self.mcp.bind.clone(),
                source,
              })?;
          if !bind.ip().is_loopback() {
            return Err(ConfigError::NonLoopbackMcpBind {
              value: self.mcp.bind.clone(),
            });
          }
        }
        _ => {
          return Err(ConfigError::UnsupportedMcpTransport {
            value: self.mcp.transport.clone(),
          });
        }
      }
    }

    Ok(())
  }
}

impl SchedulerRuntimeConfig {
  fn validate(&self) -> Result<(), ConfigError> {
    let invalid = |field, reason| ConfigError::InvalidScheduler { field, reason };
    if !self.enabled && (self.run_claims_enabled || self.delivery_claims_enabled) {
      return Err(invalid(
        "enabled",
        "must be true when run or delivery claims are enabled",
      ));
    }
    if !(1..=1_024).contains(&self.recovery_batch_limit) {
      return Err(invalid(
        "recovery_batch_limit",
        "must be between 1 and 1024",
      ));
    }
    if !(1..=1_024).contains(&self.materialization_batch_limit) {
      return Err(invalid(
        "materialization_batch_limit",
        "must be between 1 and 1024",
      ));
    }
    if !(10..=60_000).contains(&self.tick_interval_ms) {
      return Err(invalid("tick_interval_ms", "must be between 10 and 60000"));
    }
    if !(10..=300_000).contains(&self.error_backoff_ms) {
      return Err(invalid("error_backoff_ms", "must be between 10 and 300000"));
    }
    if !(5..=3_600).contains(&self.lease_seconds) {
      return Err(invalid("lease_seconds", "must be between 5 and 3600"));
    }
    if self.heartbeat_interval_ms == 0
      || self.heartbeat_interval_ms >= u64::from(self.lease_seconds) * 1_000
    {
      return Err(invalid(
        "heartbeat_interval_ms",
        "must be positive and shorter than lease_seconds",
      ));
    }
    if !(1..=21_600).contains(&self.total_timeout_seconds) {
      return Err(invalid(
        "total_timeout_seconds",
        "must be between 1 and 21600",
      ));
    }
    for (field, value) in [
      ("prepare_grace_ms", self.prepare_grace_ms),
      ("cancellation_grace_ms", self.cancellation_grace_ms),
      ("finalization_grace_ms", self.finalization_grace_ms),
    ] {
      if !(1..=60_000).contains(&value) {
        return Err(invalid(field, "must be between 1 and 60000"));
      }
    }
    if !(1..=86_400).contains(&self.retry_delay_seconds) {
      return Err(invalid(
        "retry_delay_seconds",
        "must be between 1 and 86400",
      ));
    }
    if self.run_deadline_seconds < self.total_timeout_seconds || self.run_deadline_seconds > 604_800
    {
      return Err(invalid(
        "run_deadline_seconds",
        "must cover total_timeout_seconds and not exceed 604800",
      ));
    }
    if !(1..=20).contains(&self.max_attempts) {
      return Err(invalid("max_attempts", "must be between 1 and 20"));
    }
    Ok(())
  }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
  pub bind: String,
}

impl Default for ServerConfig {
  fn default() -> Self {
    Self {
      bind: "127.0.0.1:7788".to_owned(),
    }
  }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct StateConfig {
  pub dir: PathBuf,
}

impl Default for StateConfig {
  fn default() -> Self {
    Self {
      dir: PathBuf::from("./.codeoff"),
    }
  }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct DatabaseConfig {
  pub url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct DataRetentionConfig {
  pub enabled: bool,
  pub inbound_payload_days: u16,
  pub delivery_days: u16,
  pub context_attempt_days: u16,
  pub conversation_summary_days: u16,
  pub artifact_days: u16,
}

impl Default for DataRetentionConfig {
  fn default() -> Self {
    Self {
      enabled: true,
      inbound_payload_days: 30,
      delivery_days: 30,
      context_attempt_days: 14,
      conversation_summary_days: 90,
      artifact_days: 7,
    }
  }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct DatabaseDriverConfig {
  database: DatabaseDriverSelection,
}

#[derive(Debug, Deserialize)]
#[serde(default)]
struct DatabaseDriverSelection {
  driver: String,
}

impl Default for DatabaseDriverSelection {
  fn default() -> Self {
    Self {
      driver: SQLITE_DATABASE_DRIVER.to_owned(),
    }
  }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct SlackConfig {
  pub workspace_id: String,
  pub transport: String,
  pub bot_token_env: String,
  pub app_token_env: String,
  pub signing_secret_env: String,
  pub mention_user_ids: Vec<String>,
  pub allowed_dm_user_ids: Vec<String>,
  pub default_channel_ids: Vec<String>,
  pub recent_message_limit: u16,
  pub thread_message_limit: u16,
  pub history_lookback_hours: u16,
  pub response_feedback: SlackResponseFeedbackConfig,
  pub user_tokens: BTreeMap<String, SlackUserTokenConfig>,
}

impl Default for SlackConfig {
  fn default() -> Self {
    Self {
      workspace_id: "T00000000".to_owned(),
      transport: "socket_mode".to_owned(),
      bot_token_env: "SLACK_BOT_TOKEN".to_owned(),
      app_token_env: "SLACK_APP_TOKEN".to_owned(),
      signing_secret_env: "SLACK_SIGNING_SECRET".to_owned(),
      mention_user_ids: Vec::new(),
      allowed_dm_user_ids: Vec::new(),
      default_channel_ids: Vec::new(),
      recent_message_limit: 50,
      thread_message_limit: 100,
      history_lookback_hours: 168,
      response_feedback: SlackResponseFeedbackConfig::default(),
      user_tokens: BTreeMap::new(),
    }
  }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SlackResponseFeedbackMode {
  Off,
  #[default]
  Adaptive,
  AssistantStatus,
  StreamMessage,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SlackDirectMessageFeedbackMode {
  #[default]
  Message,
  AssistantStatus,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct SlackResponseFeedbackConfig {
  pub mode: SlackResponseFeedbackMode,
  pub direct_message_feedback: SlackDirectMessageFeedbackMode,
  pub status_delay_ms: u64,
  pub status_refresh_ms: u64,
  pub status_max_duration_ms: u64,
  pub stream_min_content_chars: usize,
  pub stream_requires_real_chunks: bool,
}

impl Default for SlackResponseFeedbackConfig {
  fn default() -> Self {
    Self {
      mode: SlackResponseFeedbackMode::Adaptive,
      direct_message_feedback: SlackDirectMessageFeedbackMode::Message,
      status_delay_ms: 1200,
      status_refresh_ms: 60_000,
      status_max_duration_ms: 120_000,
      stream_min_content_chars: 300,
      stream_requires_real_chunks: true,
    }
  }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct SlackUserTokenConfig {
  pub user_id: String,
  pub token_env: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct AgentConfig {
  pub codex_app_server: CodexAppServerConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct CodexAppServerConfig {
  pub command: String,
  pub transport: String,
  pub ephemeral_threads: bool,
  pub max_parallel_turns: usize,
  pub max_prompt_bytes: usize,
  pub previous_success_context_max_bytes: usize,
}

impl Default for CodexAppServerConfig {
  fn default() -> Self {
    Self {
      command: "codex app-server --listen stdio://".to_owned(),
      transport: "stdio".to_owned(),
      ephemeral_threads: true,
      max_parallel_turns: 2,
      max_prompt_bytes: 64 * 1024,
      previous_success_context_max_bytes: 8 * 1024,
    }
  }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct McpConfig {
  pub enabled: bool,
  pub transport: String,
  pub bind: String,
}

impl Default for McpConfig {
  fn default() -> Self {
    Self {
      enabled: false,
      transport: "stdio".to_owned(),
      bind: "127.0.0.1:7789".to_owned(),
    }
  }
}
