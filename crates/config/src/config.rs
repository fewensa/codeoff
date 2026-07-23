use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::net::SocketAddr;
use std::path::Component;
use std::path::{Path, PathBuf};

use codeoff_core::{
  CredentialRevision, RunnerWorkloadIdentity, SCHEDULER_OPERATIONAL_POLICY_VERSION,
  SchedulerOperationalPolicy,
};
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
  pub occurrence_search_limit: u32,
  pub tick_interval_ms: u64,
  pub error_backoff_ms: u64,
  pub minimum_schedule_cadence_seconds: u32,
  pub max_active_jobs: u32,
  pub max_active_jobs_per_owner: u32,
  pub max_prompt_bytes: u32,
  pub max_result_bytes: u32,
  pub max_summary_bytes: u32,
  pub run_lease_seconds: u16,
  pub run_heartbeat_interval_ms: u64,
  pub run_timeout_seconds: u32,
  pub run_prepare_grace_ms: u64,
  pub run_cancellation_grace_ms: u64,
  pub run_finalization_grace_ms: u64,
  pub run_retry_base_seconds: u32,
  pub run_retry_max_seconds: u32,
  pub run_deadline_seconds: u32,
  pub run_max_attempts: u16,
  pub delivery_tick_interval_ms: u64,
  pub delivery_batch_limit: u16,
  pub delivery_lease_seconds: u16,
  pub delivery_heartbeat_interval_ms: u64,
  pub delivery_readiness_timeout_seconds: u16,
  pub delivery_send_timeout_seconds: u16,
  pub delivery_finalization_timeout_seconds: u16,
  pub delivery_max_attempts: u16,
  pub delivery_retry_base_seconds: u32,
  pub delivery_retry_max_seconds: u32,
  pub delivery_retry_after_max_seconds: u32,
  pub delivery_deadline_seconds: u32,
  pub delivery_readiness_retry_base_seconds: u16,
  pub delivery_readiness_retry_max_seconds: u16,
}

impl Default for SchedulerRuntimeConfig {
  fn default() -> Self {
    Self {
      enabled: false,
      run_claims_enabled: false,
      delivery_claims_enabled: false,
      recovery_batch_limit: 32,
      materialization_batch_limit: 32,
      occurrence_search_limit: 100_000,
      tick_interval_ms: 250,
      error_backoff_ms: 1_000,
      minimum_schedule_cadence_seconds: 60,
      max_active_jobs: 1_000,
      max_active_jobs_per_owner: 100,
      max_prompt_bytes: 64 * 1024,
      max_result_bytes: 64 * 1024,
      max_summary_bytes: 32 * 1024,
      run_lease_seconds: 60,
      run_heartbeat_interval_ms: 15_000,
      run_timeout_seconds: 1_800,
      run_prepare_grace_ms: 5_000,
      run_cancellation_grace_ms: 5_000,
      run_finalization_grace_ms: 5_000,
      run_retry_base_seconds: 30,
      run_retry_max_seconds: 300,
      run_deadline_seconds: 3_600,
      run_max_attempts: 3,
      delivery_tick_interval_ms: 250,
      delivery_batch_limit: 32,
      delivery_lease_seconds: 60,
      delivery_heartbeat_interval_ms: 10_000,
      delivery_readiness_timeout_seconds: 10,
      delivery_send_timeout_seconds: 30,
      delivery_finalization_timeout_seconds: 5,
      delivery_max_attempts: 5,
      delivery_retry_base_seconds: 5,
      delivery_retry_max_seconds: 300,
      delivery_retry_after_max_seconds: 3_600,
      delivery_deadline_seconds: 3_600,
      delivery_readiness_retry_base_seconds: 1,
      delivery_readiness_retry_max_seconds: 60,
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
    let server_bind =
      self
        .server
        .bind
        .parse::<SocketAddr>()
        .map_err(|source| ConfigError::InvalidBind {
          value: self.server.bind.clone(),
          source,
        })?;
    if !server_bind.ip().is_loopback() && !self.server.allow_non_loopback {
      return Err(ConfigError::NonLoopbackServerBind {
        value: self.server.bind.clone(),
      });
    }

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
    if self.scheduler.run_claims_enabled {
      self.agent.scheduled_codex.validate()?;
    }
    self.data_retention.validate()?;

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
  /// Converts strict deserialized settings into the canonical scheduler policy.
  ///
  /// # Errors
  /// Returns the stable invalid field when the complete policy is incoherent.
  pub fn operational_policy(&self) -> Result<SchedulerOperationalPolicy, ConfigError> {
    let policy = SchedulerOperationalPolicy {
      schema_version: SCHEDULER_OPERATIONAL_POLICY_VERSION,
      recovery_batch_limit: self.recovery_batch_limit,
      materialization_batch_limit: self.materialization_batch_limit,
      occurrence_search_limit: self.occurrence_search_limit,
      tick_interval_ms: self.tick_interval_ms,
      error_backoff_ms: self.error_backoff_ms,
      minimum_schedule_cadence_seconds: self.minimum_schedule_cadence_seconds,
      max_active_jobs: self.max_active_jobs,
      max_active_jobs_per_owner: self.max_active_jobs_per_owner,
      max_prompt_bytes: self.max_prompt_bytes,
      max_result_bytes: self.max_result_bytes,
      max_summary_bytes: self.max_summary_bytes,
      run_lease_seconds: self.run_lease_seconds,
      run_heartbeat_interval_ms: self.run_heartbeat_interval_ms,
      run_timeout_seconds: self.run_timeout_seconds,
      run_prepare_grace_ms: self.run_prepare_grace_ms,
      run_cancellation_grace_ms: self.run_cancellation_grace_ms,
      run_finalization_grace_ms: self.run_finalization_grace_ms,
      run_retry_base_seconds: self.run_retry_base_seconds,
      run_retry_max_seconds: self.run_retry_max_seconds,
      run_deadline_seconds: self.run_deadline_seconds,
      run_max_attempts: self.run_max_attempts,
      delivery_tick_interval_ms: self.delivery_tick_interval_ms,
      delivery_batch_limit: self.delivery_batch_limit,
      delivery_lease_seconds: self.delivery_lease_seconds,
      delivery_heartbeat_interval_ms: self.delivery_heartbeat_interval_ms,
      delivery_readiness_timeout_seconds: self.delivery_readiness_timeout_seconds,
      delivery_send_timeout_seconds: self.delivery_send_timeout_seconds,
      delivery_finalization_timeout_seconds: self.delivery_finalization_timeout_seconds,
      delivery_max_attempts: self.delivery_max_attempts,
      delivery_retry_base_seconds: self.delivery_retry_base_seconds,
      delivery_retry_max_seconds: self.delivery_retry_max_seconds,
      delivery_retry_after_max_seconds: self.delivery_retry_after_max_seconds,
      delivery_deadline_seconds: self.delivery_deadline_seconds,
      delivery_readiness_retry_base_seconds: self.delivery_readiness_retry_base_seconds,
      delivery_readiness_retry_max_seconds: self.delivery_readiness_retry_max_seconds,
    };
    policy
      .validate()
      .map_err(|error| ConfigError::InvalidScheduler {
        field: error.field,
        reason: error.reason,
      })?;
    Ok(policy)
  }

  fn validate(&self) -> Result<(), ConfigError> {
    let invalid = |field, reason| ConfigError::InvalidScheduler { field, reason };
    if !self.enabled && (self.run_claims_enabled || self.delivery_claims_enabled) {
      return Err(invalid(
        "enabled",
        "must be true when run or delivery claims are enabled",
      ));
    }
    self.operational_policy().map(|_| ())
  }
}

impl ScheduledCodexConfig {
  fn validate(&self) -> Result<(), ConfigError> {
    let invalid = |field, reason| ConfigError::InvalidScheduler { field, reason };
    for (field, path) in [
      ("scheduled_codex.codex_program", &self.codex_program),
      ("scheduled_codex.codex_home", &self.codex_home),
      ("scheduled_codex.cwd", &self.cwd),
      (
        "scheduled_codex.github_mcp_artifact_path",
        &self.github_mcp_artifact_path,
      ),
      (
        "scheduled_codex.isolation_attestation_path",
        &self.isolation_attestation_path,
      ),
      (
        "scheduled_codex.isolation_trust_bundle_path",
        &self.isolation_trust_bundle_path,
      ),
    ] {
      if !path.is_absolute() {
        return Err(invalid(field, "must be an absolute path"));
      }
    }
    if self.codex_home == self.cwd
      || self.cwd.starts_with(&self.codex_home)
      || self.codex_home.starts_with(&self.cwd)
    {
      return Err(invalid(
        "scheduled_codex.cwd",
        "must not overlap the dedicated CODEX_HOME",
      ));
    }
    if self.trusted_owner_uid == self.runtime_uid || self.trusted_owner_gid == self.runtime_gid {
      return Err(invalid(
        "scheduled_codex.runtime_uid",
        "must identify an unprivileged runtime distinct from the trusted artifact owner",
      ));
    }
    for (field, value) in [
      (
        "scheduled_codex.github_mcp_endpoint_identity",
        self.github_mcp_endpoint_identity.as_str(),
      ),
      (
        "scheduled_codex.credential_reference",
        self.credential_reference.as_str(),
      ),
      (
        "scheduled_codex.permission_policy_revision",
        self.permission_policy_revision.as_str(),
      ),
      (
        "scheduled_codex.config_revision",
        self.config_revision.as_str(),
      ),
    ] {
      if value.is_empty() || value != value.trim() {
        return Err(invalid(field, "must be non-empty and trimmed"));
      }
    }
    RunnerWorkloadIdentity::parse(&self.runner_workload_identity).map_err(|_| {
      invalid(
        "scheduled_codex.runner_workload_identity",
        "must be a canonical SPIFFE workload identity",
      )
    })?;
    CredentialRevision::parse(&self.credential_revision).map_err(|_| {
      invalid(
        "scheduled_codex.credential_revision",
        "must be a bounded lowercase credential revision",
      )
    })?;
    for (field, value) in [
      (
        "scheduled_codex.codex_program_sha256",
        self.codex_program_sha256.as_str(),
      ),
      (
        "scheduled_codex.github_mcp_artifact_sha256",
        self.github_mcp_artifact_sha256.as_str(),
      ),
      ("scheduled_codex.config_sha256", self.config_sha256.as_str()),
    ] {
      if !is_lowercase_hex(value, 64) {
        return Err(invalid(field, "must be a lowercase SHA-256 digest"));
      }
    }
    self.validate_deployment_identity()?;
    if !is_loopback_mcp_url(&self.github_mcp_url) {
      return Err(invalid(
        "scheduled_codex.github_mcp_url",
        "must be a credential-free loopback HTTP MCP URL",
      ));
    }
    Ok(())
  }

  fn validate_deployment_identity(&self) -> Result<(), ConfigError> {
    let invalid = |field, reason| ConfigError::InvalidScheduler { field, reason };
    for (field, digest) in [
      (
        "scheduled_codex.gateway_image_digest",
        self.gateway_image_digest.as_str(),
      ),
      (
        "scheduled_codex.runner_image_digest",
        self.runner_image_digest.as_str(),
      ),
    ] {
      if !is_oci_sha256_digest(digest) {
        return Err(invalid(
          field,
          "must be an immutable sha256 OCI image digest",
        ));
      }
    }
    if !is_lowercase_hex(&self.runner_client_cert_public_key_fingerprint, 64) {
      return Err(invalid(
        "scheduled_codex.runner_client_cert_public_key_fingerprint",
        "must be a lowercase SHA-256 fingerprint",
      ));
    }
    Ok(())
  }

  /// Validates the strict configuration surface for one scheduled-runner process role.
  ///
  /// # Errors
  /// Returns an error when the execution backend, role table, or role-specific values do not
  /// match the selected process role.
  pub fn validate_remote_runner_role(&self, role: ScheduledRunnerRole) -> Result<(), ConfigError> {
    self.validate()?;
    if self.execution_backend != ScheduledExecutionBackend::RemoteRunner {
      return Err(invalid_scheduled_codex(
        "scheduled_codex.execution_backend",
        "must be remote-runner for a scheduled runner role",
      ));
    }
    let remote = &self.remote_runner;
    let selected = match role {
      ScheduledRunnerRole::Gateway => remote.gateway.is_some(),
      ScheduledRunnerRole::Control => remote.control.is_some(),
      ScheduledRunnerRole::Executor => remote.executor.is_some(),
    };
    if !selected {
      return Err(invalid_scheduled_codex(
        role.config_field(),
        "is required for the selected scheduled runner role",
      ));
    }
    if (role != ScheduledRunnerRole::Gateway && remote.gateway.is_some())
      || (role != ScheduledRunnerRole::Control && remote.control.is_some())
      || (role != ScheduledRunnerRole::Executor && remote.executor.is_some())
    {
      return Err(invalid_scheduled_codex(
        "scheduled_codex.remote_runner",
        "must contain only the selected scheduled runner role table",
      ));
    }
    match role {
      ScheduledRunnerRole::Gateway => remote.gateway.as_ref().map_or_else(
        || {
          Err(invalid_scheduled_codex(
            role.config_field(),
            "is required for the selected scheduled runner role",
          ))
        },
        ScheduledRunnerGatewayConfig::validate,
      ),
      ScheduledRunnerRole::Control => remote.control.as_ref().map_or_else(
        || {
          Err(invalid_scheduled_codex(
            role.config_field(),
            "is required for the selected scheduled runner role",
          ))
        },
        |config| config.validate(self),
      ),
      ScheduledRunnerRole::Executor => remote.executor.as_ref().map_or_else(
        || {
          Err(invalid_scheduled_codex(
            role.config_field(),
            "is required for the selected scheduled runner role",
          ))
        },
        |config| config.validate(self),
      ),
    }
  }
}

fn invalid_scheduled_codex(field: &'static str, reason: &'static str) -> ConfigError {
  ConfigError::InvalidScheduler { field, reason }
}

fn is_loopback_mcp_url(value: &str) -> bool {
  if value.contains('@') {
    return false;
  }
  ["http://127.0.0.1:", "http://[::1]:", "http://localhost:"]
    .iter()
    .find_map(|prefix| value.strip_prefix(prefix))
    .and_then(|suffix| suffix.strip_suffix("/mcp"))
    .and_then(|port| port.parse::<u16>().ok())
    .is_some_and(|port| port != 0)
}

fn is_lowercase_hex(value: &str, expected_len: usize) -> bool {
  value.len() == expected_len
    && value
      .bytes()
      .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_oci_sha256_digest(value: &str) -> bool {
  value
    .strip_prefix("sha256:")
    .is_some_and(|digest| is_lowercase_hex(digest, 64))
}

fn validate_absolute_paths<'a>(
  paths: impl IntoIterator<Item = (&'static str, &'a PathBuf)>,
) -> Result<(), ConfigError> {
  for (field, path) in paths {
    if !path.is_absolute()
      || path.file_name().is_none()
      || !path
        .components()
        .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
    {
      return Err(invalid_scheduled_codex(
        field,
        "must be a canonical absolute path",
      ));
    }
  }
  Ok(())
}

fn validate_milliseconds(field: &'static str, value: u64) -> Result<(), ConfigError> {
  if !(1..=300_000).contains(&value) {
    return Err(invalid_scheduled_codex(
      field,
      "must be between 1 and 300000 milliseconds",
    ));
  }
  Ok(())
}

fn validate_host_port(value: &str) -> Result<(), ConfigError> {
  let field = "scheduled_codex.remote_runner.control.gateway_address";
  if value.is_empty() || value != value.trim() || value.len() > 255 {
    return Err(invalid_scheduled_codex(
      field,
      "must be a bounded canonical host and nonzero port",
    ));
  }
  if let Ok(address) = value.parse::<SocketAddr>() {
    return if address.port() == 0 {
      Err(invalid_scheduled_codex(field, "must use a nonzero port"))
    } else {
      Ok(())
    };
  }
  let Some((host, port)) = value.rsplit_once(':') else {
    return Err(invalid_scheduled_codex(
      field,
      "must include a nonzero port",
    ));
  };
  if !is_canonical_dns_name(host) || port.parse::<u16>().ok().is_none_or(|port| port == 0) {
    return Err(invalid_scheduled_codex(
      field,
      "must be a canonical DNS name and nonzero port",
    ));
  }
  Ok(())
}

fn is_canonical_dns_name(value: &str) -> bool {
  !value.is_empty()
    && value.len() <= 253
    && value.as_bytes().first() != Some(&b'.')
    && value.as_bytes().last() != Some(&b'.')
    && value.split('.').all(|label| {
      !label.is_empty()
        && label.len() <= 63
        && label
          .as_bytes()
          .first()
          .is_some_and(u8::is_ascii_alphanumeric)
        && label
          .as_bytes()
          .last()
          .is_some_and(u8::is_ascii_alphanumeric)
        && label
          .bytes()
          .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    })
}

impl DataRetentionConfig {
  fn validate(&self) -> Result<(), ConfigError> {
    let invalid = |field, reason| ConfigError::InvalidDataRetention { field, reason };
    for (field, value) in [
      ("scheduled_run_days", self.scheduled_run_days),
      ("scheduled_delivery_days", self.scheduled_delivery_days),
    ] {
      if !(1..=3_650).contains(&value) {
        return Err(invalid(field, "must be between 1 and 3650"));
      }
    }
    if !(1..=1_024).contains(&self.scheduled_retention_batch_limit) {
      return Err(invalid(
        "scheduled_retention_batch_limit",
        "must be between 1 and 1024",
      ));
    }
    Ok(())
  }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
  pub bind: String,
  pub allow_non_loopback: bool,
}

impl Default for ServerConfig {
  fn default() -> Self {
    Self {
      bind: "127.0.0.1:7788".to_owned(),
      allow_non_loopback: false,
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
  pub scheduled_run_days: u16,
  pub scheduled_delivery_days: u16,
  pub scheduled_retention_batch_limit: u16,
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
      scheduled_run_days: 30,
      scheduled_delivery_days: 30,
      scheduled_retention_batch_limit: 100,
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
  pub scheduled_codex: ScheduledCodexConfig,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ScheduledExecutionBackend {
  #[default]
  Local,
  RemoteRunner,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScheduledRunnerRole {
  Gateway,
  Control,
  Executor,
}

impl ScheduledRunnerRole {
  const fn config_field(self) -> &'static str {
    match self {
      Self::Gateway => "scheduled_codex.remote_runner.gateway",
      Self::Control => "scheduled_codex.remote_runner.control",
      Self::Executor => "scheduled_codex.remote_runner.executor",
    }
  }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ScheduledRemoteRunnerConfig {
  pub gateway: Option<ScheduledRunnerGatewayConfig>,
  pub control: Option<ScheduledRunnerControlConfig>,
  pub executor: Option<ScheduledRunnerExecutorConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScheduledRunnerGatewayConfig {
  pub bind: String,
  pub server_certificate_path: PathBuf,
  pub server_private_key_path: PathBuf,
  pub client_ca_bundle_path: PathBuf,
  pub handshake_timeout_ms: u64,
  pub frame_timeout_ms: u64,
  pub readiness_ttl_ms: u64,
  pub max_connections: usize,
}

impl ScheduledRunnerGatewayConfig {
  fn validate(&self) -> Result<(), ConfigError> {
    let bind = self.bind.parse::<SocketAddr>().map_err(|_| {
      invalid_scheduled_codex(
        "scheduled_codex.remote_runner.gateway.bind",
        "must be a canonical IP socket address",
      )
    })?;
    if bind.port() == 0 {
      return Err(invalid_scheduled_codex(
        "scheduled_codex.remote_runner.gateway.bind",
        "must use a nonzero port",
      ));
    }
    validate_absolute_paths([
      (
        "scheduled_codex.remote_runner.gateway.server_certificate_path",
        &self.server_certificate_path,
      ),
      (
        "scheduled_codex.remote_runner.gateway.server_private_key_path",
        &self.server_private_key_path,
      ),
      (
        "scheduled_codex.remote_runner.gateway.client_ca_bundle_path",
        &self.client_ca_bundle_path,
      ),
    ])?;
    validate_milliseconds(
      "scheduled_codex.remote_runner.gateway.handshake_timeout_ms",
      self.handshake_timeout_ms,
    )?;
    validate_milliseconds(
      "scheduled_codex.remote_runner.gateway.frame_timeout_ms",
      self.frame_timeout_ms,
    )?;
    validate_milliseconds(
      "scheduled_codex.remote_runner.gateway.readiness_ttl_ms",
      self.readiness_ttl_ms,
    )?;
    if !(1..=64).contains(&self.max_connections) {
      return Err(invalid_scheduled_codex(
        "scheduled_codex.remote_runner.gateway.max_connections",
        "must be between 1 and 64",
      ));
    }
    Ok(())
  }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScheduledRunnerControlConfig {
  pub gateway_address: String,
  pub gateway_server_name: String,
  pub client_certificate_path: PathBuf,
  pub client_private_key_path: PathBuf,
  pub server_ca_bundle_path: PathBuf,
  pub local_socket_path: PathBuf,
  pub expected_executor_uid: u32,
  pub expected_executor_gid: u32,
  pub connect_timeout_ms: u64,
  pub frame_timeout_ms: u64,
}

impl ScheduledRunnerControlConfig {
  fn validate(&self, deployment: &ScheduledCodexConfig) -> Result<(), ConfigError> {
    validate_host_port(&self.gateway_address)?;
    if !is_canonical_dns_name(&self.gateway_server_name) {
      return Err(invalid_scheduled_codex(
        "scheduled_codex.remote_runner.control.gateway_server_name",
        "must be a canonical lowercase DNS name",
      ));
    }
    validate_absolute_paths([
      (
        "scheduled_codex.remote_runner.control.client_certificate_path",
        &self.client_certificate_path,
      ),
      (
        "scheduled_codex.remote_runner.control.client_private_key_path",
        &self.client_private_key_path,
      ),
      (
        "scheduled_codex.remote_runner.control.server_ca_bundle_path",
        &self.server_ca_bundle_path,
      ),
      (
        "scheduled_codex.remote_runner.control.local_socket_path",
        &self.local_socket_path,
      ),
    ])?;
    if self.expected_executor_uid == 0
      || self.expected_executor_gid == 0
      || self.expected_executor_uid != deployment.runtime_uid
      || self.expected_executor_gid != deployment.runtime_gid
    {
      return Err(invalid_scheduled_codex(
        "scheduled_codex.remote_runner.control.expected_executor_uid",
        "must match the nonroot scheduled_codex runtime identity",
      ));
    }
    validate_milliseconds(
      "scheduled_codex.remote_runner.control.connect_timeout_ms",
      self.connect_timeout_ms,
    )?;
    validate_milliseconds(
      "scheduled_codex.remote_runner.control.frame_timeout_ms",
      self.frame_timeout_ms,
    )
  }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScheduledRunnerExecutorConfig {
  pub local_socket_path: PathBuf,
  pub expected_control_uid: u32,
  pub expected_control_gid: u32,
  pub codex_child_uid: u32,
  pub codex_child_gid: u32,
  pub accept_timeout_ms: u64,
  pub frame_timeout_ms: u64,
}

impl ScheduledRunnerExecutorConfig {
  fn validate(&self, deployment: &ScheduledCodexConfig) -> Result<(), ConfigError> {
    validate_absolute_paths([(
      "scheduled_codex.remote_runner.executor.local_socket_path",
      &self.local_socket_path,
    )])?;
    if self.expected_control_uid != deployment.trusted_owner_uid
      || self.expected_control_gid != deployment.trusted_owner_gid
    {
      return Err(invalid_scheduled_codex(
        "scheduled_codex.remote_runner.executor.expected_control_uid",
        "must match the scheduled_codex trusted owner identity",
      ));
    }
    if self.codex_child_uid == 0
      || self.codex_child_gid == 0
      || self.codex_child_uid == deployment.runtime_uid
      || self.codex_child_gid == deployment.runtime_gid
      || self.codex_child_uid == self.expected_control_uid
      || self.codex_child_gid == self.expected_control_gid
    {
      return Err(invalid_scheduled_codex(
        "scheduled_codex.remote_runner.executor.codex_child_uid",
        "must identify a distinct nonroot Codex child identity",
      ));
    }
    validate_milliseconds(
      "scheduled_codex.remote_runner.executor.accept_timeout_ms",
      self.accept_timeout_ms,
    )?;
    validate_milliseconds(
      "scheduled_codex.remote_runner.executor.frame_timeout_ms",
      self.frame_timeout_ms,
    )
  }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ScheduledCodexConfig {
  pub execution_backend: ScheduledExecutionBackend,
  pub remote_runner: ScheduledRemoteRunnerConfig,
  pub codex_program: PathBuf,
  pub codex_program_sha256: String,
  pub codex_home: PathBuf,
  pub cwd: PathBuf,
  pub github_mcp_url: String,
  pub github_mcp_artifact_path: PathBuf,
  pub github_mcp_artifact_sha256: String,
  pub github_mcp_endpoint_identity: String,
  pub credential_reference: String,
  pub permission_policy_revision: String,
  pub config_revision: String,
  pub config_sha256: String,
  pub gateway_image_digest: String,
  pub runner_image_digest: String,
  pub runner_workload_identity: String,
  pub runner_client_cert_public_key_fingerprint: String,
  pub credential_revision: String,
  pub isolation_attestation_path: PathBuf,
  pub isolation_trust_bundle_path: PathBuf,
  pub trusted_owner_uid: u32,
  pub trusted_owner_gid: u32,
  pub runtime_uid: u32,
  pub runtime_gid: u32,
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
