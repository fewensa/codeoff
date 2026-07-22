use std::fs;
use std::path::{Path, PathBuf};

use codeoff_config::{
  CodeoffConfig, ConfigError, ConfigLoadOptions, DataRetentionConfig, DatabaseConfig,
  SchedulerRuntimeConfig, SlackDirectMessageFeedbackMode, SlackResponseFeedbackMode,
};
use tempfile::tempdir;

#[test]
fn test_state_dir_precedence_uses_explicit_override_before_env_and_config() {
  let dir = tempdir().expect("create tempdir");
  let config_path = dir.path().join("codeoff.toml");
  fs::write(
    &config_path,
    r#"
[state]
dir = "./from-config"
"#,
  )
  .expect("write config");

  let loaded = CodeoffConfig::load(
    ConfigLoadOptions::new()
      .config_path(config_path)
      .state_dir_env(PathBuf::from("/tmp/from-env"))
      .explicit_state_dir(PathBuf::from("/tmp/from-explicit")),
  )
  .expect("load config");

  assert_eq!(loaded.state_dir(), Path::new("/tmp/from-explicit"));
}

#[test]
fn test_state_dir_precedence_uses_env_before_config() {
  let dir = tempdir().expect("create tempdir");
  let config_path = dir.path().join("codeoff.toml");
  fs::write(
    &config_path,
    r#"
[state]
dir = "./from-config"
"#,
  )
  .expect("write config");

  let loaded = CodeoffConfig::load(
    ConfigLoadOptions::new()
      .config_path(config_path)
      .state_dir_env(PathBuf::from("/tmp/from-env")),
  )
  .expect("load config");

  assert_eq!(loaded.state_dir(), Path::new("/tmp/from-env"));
}

#[test]
fn test_config_check_accepts_minimal_valid_config() {
  let dir = tempdir().expect("create tempdir");
  let config_path = dir.path().join("codeoff.toml");
  fs::write(
    &config_path,
    r#"
[server]
bind = "127.0.0.1:7788"

[state]
dir = "./.codeoff"

[database]
url = "sqlite://./.codeoff/codeoff.db"
"#,
  )
  .expect("write config");

  let loaded =
    CodeoffConfig::load(ConfigLoadOptions::new().config_path(config_path)).expect("load config");

  loaded.validate().expect("minimal config should be valid");
  assert!(loaded.slack.mention_user_ids.is_empty());
}

#[test]
fn test_database_driver_defaults_to_sqlite_and_loads_from_toml() {
  let defaults_dir = tempdir().expect("create tempdir");
  let defaults = CodeoffConfig::load(
    ConfigLoadOptions::new().config_path(defaults_dir.path().join("missing-codeoff.toml")),
  )
  .expect("load defaults");
  assert_eq!(defaults.database_driver(), "sqlite");

  let dir = tempdir().expect("create tempdir");
  let config_path = dir.path().join("codeoff.toml");
  fs::write(
    &config_path,
    r#"
[database]
driver = "sqlite"
"#,
  )
  .expect("write config");

  let loaded =
    CodeoffConfig::load(ConfigLoadOptions::new().config_path(config_path)).expect("load config");

  assert_eq!(loaded.database_driver(), "sqlite");
}

#[test]
fn test_database_config_struct_literal_remains_compatible() {
  let database = DatabaseConfig {
    url: Some("sqlite://./custom.db".to_owned()),
  };

  assert_eq!(database.url.as_deref(), Some("sqlite://./custom.db"));
}

#[test]
fn test_data_retention_defaults_and_toml_overrides() {
  let defaults = CodeoffConfig::default();
  assert_eq!(
    defaults.data_retention,
    DataRetentionConfig {
      enabled: true,
      inbound_payload_days: 30,
      delivery_days: 30,
      context_attempt_days: 14,
      conversation_summary_days: 90,
      artifact_days: 7,
    }
  );

  let dir = tempdir().expect("create tempdir");
  let config_path = dir.path().join("codeoff.toml");
  fs::write(
    &config_path,
    r"
[data_retention]
enabled = false
inbound_payload_days = 45
delivery_days = 60
context_attempt_days = 21
conversation_summary_days = 120
artifact_days = 10
",
  )
  .expect("write config");

  let loaded =
    CodeoffConfig::load(ConfigLoadOptions::new().config_path(config_path)).expect("load config");

  assert_eq!(
    loaded.data_retention,
    DataRetentionConfig {
      enabled: false,
      inbound_payload_days: 45,
      delivery_days: 60,
      context_attempt_days: 21,
      conversation_summary_days: 120,
      artifact_days: 10,
    }
  );
}

#[test]
fn test_scheduler_run_claims_default_off_and_loads_explicit_opt_in() {
  assert_eq!(
    CodeoffConfig::default().scheduler,
    SchedulerRuntimeConfig {
      run_claims_enabled: false,
      delivery_enabled: false,
    }
  );

  let dir = tempdir().expect("create tempdir");
  let config_path = dir.path().join("codeoff.toml");
  fs::write(
    &config_path,
    r"
[scheduler]
run_claims_enabled = true
delivery_enabled = true
",
  )
  .expect("write config");

  let loaded =
    CodeoffConfig::load(ConfigLoadOptions::new().config_path(config_path)).expect("load config");

  assert!(loaded.scheduler.run_claims_enabled);
  assert!(loaded.scheduler.delivery_enabled);
}

#[test]
fn test_default_config_load_preserves_state_dir_without_database_url() {
  let dir = tempdir().expect("create tempdir");
  let loaded = CodeoffConfig::load(
    ConfigLoadOptions::new().config_path(dir.path().join("missing-codeoff.toml")),
  )
  .expect("load defaults");

  assert_eq!(loaded.state_dir(), Path::new("./.codeoff"));
  assert_eq!(loaded.database_url(), None);
}

#[test]
fn test_config_validate_rejects_explicit_blank_database_url() {
  let mut config = CodeoffConfig::default();
  config.database.url = Some("  ".to_owned());

  let error = config.validate().expect_err("blank database URL");

  assert!(matches!(error, ConfigError::EmptyDatabaseUrl));
}

#[test]
fn test_config_validate_rejects_unsupported_database_driver() {
  let dir = tempdir().expect("create tempdir");
  let config_path = dir.path().join("codeoff.toml");
  fs::write(
    &config_path,
    r#"
[database]
driver = "postgres"
"#,
  )
  .expect("write config");
  let config =
    CodeoffConfig::load(ConfigLoadOptions::new().config_path(config_path)).expect("load config");

  let error = config.validate().expect_err("unsupported database driver");

  assert!(matches!(error, ConfigError::UnsupportedDatabaseDriver));
  assert!(!error.to_string().contains("postgres"));
}

#[test]
fn test_slack_mention_user_ids_load_from_toml() {
  let dir = tempdir().expect("create tempdir");
  let config_path = dir.path().join("codeoff.toml");
  fs::write(
    &config_path,
    r#"
[slack]
mention_user_ids = ["U0EXAMPLE", "U0SECOND"]
"#,
  )
  .expect("write config");

  let loaded =
    CodeoffConfig::load(ConfigLoadOptions::new().config_path(config_path)).expect("load config");

  assert_eq!(loaded.slack.mention_user_ids, ["U0EXAMPLE", "U0SECOND"]);
}

#[test]
fn test_slack_allowed_dm_user_ids_load_from_toml() {
  let dir = tempdir().expect("create tempdir");
  let config_path = dir.path().join("codeoff.toml");
  fs::write(
    &config_path,
    r#"
[slack]
allowed_dm_user_ids = ["U0EXAMPLE"]
"#,
  )
  .expect("write config");

  let loaded =
    CodeoffConfig::load(ConfigLoadOptions::new().config_path(config_path)).expect("load config");

  assert_eq!(loaded.slack.allowed_dm_user_ids, ["U0EXAMPLE"]);
  assert!(
    CodeoffConfig::default()
      .slack
      .allowed_dm_user_ids
      .is_empty()
  );
}

#[test]
fn test_slack_user_tokens_load_from_toml() {
  let dir = tempdir().expect("create tempdir");
  let config_path = dir.path().join("codeoff.toml");
  fs::write(
    &config_path,
    r#"
[slack.user_tokens.example]
user_id = "U0EXAMPLE"
token_env = "SLACK_EXAMPLE_USER_TOKEN"
"#,
  )
  .expect("write config");

  let loaded =
    CodeoffConfig::load(ConfigLoadOptions::new().config_path(config_path)).expect("load config");

  let sender = loaded
    .slack
    .user_tokens
    .get("example")
    .expect("example sender config");
  assert_eq!(sender.user_id, "U0EXAMPLE");
  assert_eq!(sender.token_env, "SLACK_EXAMPLE_USER_TOKEN");
  assert!(CodeoffConfig::default().slack.user_tokens.is_empty());
}

#[test]
fn test_codex_app_server_parallel_turns_load_from_toml() {
  let dir = tempdir().expect("create tempdir");
  let config_path = dir.path().join("codeoff.toml");
  fs::write(
    &config_path,
    r"
[agent.codex_app_server]
max_parallel_turns = 4
",
  )
  .expect("write config");

  let loaded =
    CodeoffConfig::load(ConfigLoadOptions::new().config_path(config_path)).expect("load config");

  assert_eq!(loaded.agent.codex_app_server.max_parallel_turns, 4);
  assert_eq!(
    CodeoffConfig::default()
      .agent
      .codex_app_server
      .max_parallel_turns,
    2
  );
}

#[test]
fn test_slack_response_feedback_defaults_to_adaptive_without_immediate_stream() {
  let defaults_dir = tempdir().expect("create tempdir");
  let loaded = CodeoffConfig::load(
    ConfigLoadOptions::new().config_path(defaults_dir.path().join("missing-codeoff.toml")),
  )
  .expect("load defaults");

  assert_eq!(
    loaded.slack.response_feedback.mode,
    SlackResponseFeedbackMode::Adaptive
  );
  assert_eq!(
    loaded.slack.response_feedback.direct_message_feedback,
    SlackDirectMessageFeedbackMode::Message
  );
  assert_eq!(loaded.slack.response_feedback.status_delay_ms, 1200);
  assert_eq!(loaded.slack.response_feedback.status_refresh_ms, 60_000);
  assert_eq!(
    loaded.slack.response_feedback.status_max_duration_ms,
    120_000
  );
  assert_eq!(loaded.slack.response_feedback.stream_min_content_chars, 300);
  assert!(loaded.slack.response_feedback.stream_requires_real_chunks);
}

#[test]
fn test_slack_response_feedback_loads_overrides_from_toml() {
  let dir = tempdir().expect("create tempdir");
  let config_path = dir.path().join("codeoff.toml");
  fs::write(
    &config_path,
    r#"
[slack.response_feedback]
mode = "stream_message"
direct_message_feedback = "assistant_status"
status_delay_ms = 2500
status_refresh_ms = 30000
status_max_duration_ms = 90000
stream_min_content_chars = 500
stream_requires_real_chunks = false
"#,
  )
  .expect("write config");

  let loaded =
    CodeoffConfig::load(ConfigLoadOptions::new().config_path(config_path)).expect("load config");

  assert_eq!(
    loaded.slack.response_feedback.mode,
    SlackResponseFeedbackMode::StreamMessage
  );
  assert_eq!(
    loaded.slack.response_feedback.direct_message_feedback,
    SlackDirectMessageFeedbackMode::AssistantStatus
  );
  assert_eq!(loaded.slack.response_feedback.status_delay_ms, 2500);
  assert_eq!(loaded.slack.response_feedback.status_refresh_ms, 30_000);
  assert_eq!(
    loaded.slack.response_feedback.status_max_duration_ms,
    90_000
  );
  assert_eq!(loaded.slack.response_feedback.stream_min_content_chars, 500);
  assert!(!loaded.slack.response_feedback.stream_requires_real_chunks);
}

#[test]
fn test_codex_app_server_config_loads_from_toml() {
  let dir = tempdir().expect("create tempdir");
  let config_path = dir.path().join("codeoff.toml");
  fs::write(
    &config_path,
    r#"
[agent.codex_app_server]
command = "codex app-server --sandbox workspace-write"
transport = "stdio"
ephemeral_threads = false
max_prompt_bytes = 32768
previous_success_context_max_bytes = 4096
"#,
  )
  .expect("write config");

  let loaded =
    CodeoffConfig::load(ConfigLoadOptions::new().config_path(config_path)).expect("load config");

  assert_eq!(
    loaded.agent.codex_app_server.command,
    "codex app-server --sandbox workspace-write"
  );
  assert_eq!(loaded.agent.codex_app_server.transport, "stdio");
  assert!(!loaded.agent.codex_app_server.ephemeral_threads);
  assert_eq!(loaded.agent.codex_app_server.max_prompt_bytes, 32_768);
  assert_eq!(
    loaded
      .agent
      .codex_app_server
      .previous_success_context_max_bytes,
    4_096
  );
}

#[test]
fn test_mcp_config_loads_defaults_and_overrides_from_toml() {
  let defaults_dir = tempdir().expect("create tempdir");
  let defaults = CodeoffConfig::load(
    ConfigLoadOptions::new().config_path(defaults_dir.path().join("missing-codeoff.toml")),
  )
  .expect("load defaults");
  assert!(!defaults.mcp.enabled);
  assert_eq!(defaults.mcp.transport, "stdio");
  assert_eq!(defaults.mcp.bind, "127.0.0.1:7789");

  let dir = tempdir().expect("create tempdir");
  let config_path = dir.path().join("codeoff.toml");
  fs::write(
    &config_path,
    r#"
[mcp]
enabled = true
transport = "tcp"
bind = "127.0.0.1:7790"
"#,
  )
  .expect("write config");

  let loaded =
    CodeoffConfig::load(ConfigLoadOptions::new().config_path(config_path)).expect("load config");

  assert!(loaded.mcp.enabled);
  assert_eq!(loaded.mcp.transport, "tcp");
  assert_eq!(loaded.mcp.bind, "127.0.0.1:7790");
}

#[test]
fn test_mcp_validate_rejects_unknown_transport_only_when_enabled() {
  let mut disabled = CodeoffConfig::default();
  disabled.mcp.enabled = false;
  disabled.mcp.transport = "bogus".to_owned();
  disabled.mcp.bind = "not-a-socket".to_owned();
  disabled.validate().expect("disabled mcp ignored");

  let mut enabled = CodeoffConfig::default();
  enabled.mcp.enabled = true;
  enabled.mcp.transport = "bogus".to_owned();
  let error = enabled.validate().expect_err("unsupported transport");
  assert!(matches!(
    error,
    ConfigError::UnsupportedMcpTransport { value } if value == "bogus"
  ));
}

#[test]
fn test_mcp_validate_only_requires_bind_for_tcp_transport() {
  let mut stdio = CodeoffConfig::default();
  stdio.mcp.enabled = true;
  stdio.mcp.transport = "stdio".to_owned();
  stdio.mcp.bind = "not-a-socket".to_owned();
  stdio.validate().expect("stdio does not need bind");

  let mut tcp = CodeoffConfig::default();
  tcp.mcp.enabled = true;
  tcp.mcp.transport = "tcp".to_owned();
  tcp.mcp.bind = "not-a-socket".to_owned();
  let error = tcp.validate().expect_err("tcp needs valid bind");
  assert!(matches!(error, ConfigError::InvalidBind { .. }));
}

#[test]
fn test_mcp_tcp_bind_must_be_loopback() {
  let mut config = CodeoffConfig::default();
  config.mcp.enabled = true;
  config.mcp.transport = "tcp".to_owned();
  config.mcp.bind = "0.0.0.0:7789".to_owned();

  let error = config.validate().expect_err("non-loopback tcp mcp bind");

  assert!(matches!(
    error,
    ConfigError::NonLoopbackMcpBind { value } if value == "0.0.0.0:7789"
  ));
}

#[test]
fn test_documented_state_dir_placeholder_uses_default_when_env_is_absent() {
  let dir = tempdir().expect("create tempdir");
  let config_path = dir.path().join("codeoff.toml");
  fs::write(
    &config_path,
    r#"
[state]
dir = "${CODEOFF_STATE_DIR:-./.codeoff}"

[database]
url = "sqlite://${CODEOFF_STATE_DIR:-./.codeoff}/codeoff.db"
"#,
  )
  .expect("write config");

  let loaded =
    CodeoffConfig::load(ConfigLoadOptions::new().config_path(config_path)).expect("load config");

  assert_eq!(loaded.state_dir(), Path::new("./.codeoff"));
  assert_eq!(
    loaded.database_url(),
    Some("sqlite://./.codeoff/codeoff.db")
  );
}
