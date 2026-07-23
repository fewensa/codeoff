use std::fs;
use std::path::{Path, PathBuf};

use codeoff_config::{
  CodeoffConfig, ConfigError, ConfigLoadOptions, DataRetentionConfig, DatabaseConfig,
  ScheduledCodexConfig, SchedulerRuntimeConfig, SlackDirectMessageFeedbackMode,
  SlackResponseFeedbackMode,
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
fn test_server_bind_requires_explicit_non_loopback_exposure() {
  let mut config = CodeoffConfig::default();
  config.server.bind = "0.0.0.0:7788".to_owned();

  let error = config
    .validate()
    .expect_err("non-loopback server bind must fail closed");
  assert!(matches!(
    error,
    ConfigError::NonLoopbackServerBind { value } if value == "0.0.0.0:7788"
  ));

  config.server.allow_non_loopback = true;
  config
    .validate()
    .expect("explicit non-loopback exposure is valid");
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
      scheduled_run_days: 30,
      scheduled_delivery_days: 30,
      scheduled_retention_batch_limit: 100,
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
scheduled_run_days = 75
scheduled_delivery_days = 80
scheduled_retention_batch_limit = 125
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
      scheduled_run_days: 75,
      scheduled_delivery_days: 80,
      scheduled_retention_batch_limit: 125,
    }
  );
}

#[test]
fn test_data_retention_rejects_zero_and_unsafe_scheduler_limits() {
  let mut config = CodeoffConfig::default();
  config.data_retention.scheduled_run_days = 0;
  assert!(matches!(
    config.validate(),
    Err(ConfigError::InvalidDataRetention {
      field: "scheduled_run_days",
      ..
    })
  ));

  config.data_retention.scheduled_run_days = 30;
  config.data_retention.scheduled_delivery_days = 3_651;
  assert!(matches!(
    config.validate(),
    Err(ConfigError::InvalidDataRetention {
      field: "scheduled_delivery_days",
      ..
    })
  ));

  config.data_retention.scheduled_delivery_days = 30;
  config.data_retention.scheduled_retention_batch_limit = 0;
  assert!(matches!(
    config.validate(),
    Err(ConfigError::InvalidDataRetention {
      field: "scheduled_retention_batch_limit",
      ..
    })
  ));
}

#[test]
fn test_scheduler_run_claims_default_off_and_loads_explicit_opt_in() {
  let defaults = SchedulerRuntimeConfig::default();
  assert!(!defaults.enabled);
  assert!(!defaults.run_claims_enabled);
  assert!(!defaults.delivery_claims_enabled);

  let dir = tempdir().expect("create tempdir");
  let config_path = dir.path().join("codeoff.toml");
  fs::write(
    &config_path,
    r#"
[scheduler]
enabled = true
run_claims_enabled = true
delivery_claims_enabled = true
recovery_batch_limit = 64
run_retry_base_seconds = 60
run_max_attempts = 5

[agent.scheduled_codex]
codex_program = "/opt/codeoff/bin/codex"
codex_program_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
codex_home = "/var/lib/codeoff/scheduled-codex"
cwd = "/work/codeoff-scheduled"
github_mcp_url = "http://127.0.0.1:8090/mcp"
github_mcp_artifact_path = "/opt/codeoff/bin/github-mcp-server"
github_mcp_artifact_sha256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
github_mcp_endpoint_identity = "github-mcp-scheduled-v1"
credential_reference = "kubernetes:codeoff/github-mcp"
permission_policy_revision = "scheduled-read-only-v1"
config_revision = "scheduled-codex-v1"
config_sha256 = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
gateway_image_digest = "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
runner_image_digest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
runner_workload_identity = "spiffe://codeoff/runner/production"
runner_client_cert_public_key_fingerprint = "1111111111111111111111111111111111111111111111111111111111111111"
credential_revision = "github-readonly-2026-07"
isolation_attestation_path = "/var/run/codeoff/isolation-attestation.json"
isolation_trust_bundle_path = "/opt/codeoff/attestation/isolation-trust-bundle.json"
trusted_owner_uid = 0
trusted_owner_gid = 0
runtime_uid = 65534
runtime_gid = 65534
"#,
  )
  .expect("write config");

  let loaded =
    CodeoffConfig::load(ConfigLoadOptions::new().config_path(config_path)).expect("load config");

  assert!(loaded.scheduler.enabled);
  assert!(loaded.scheduler.run_claims_enabled);
  assert!(loaded.scheduler.delivery_claims_enabled);
  assert_eq!(loaded.scheduler.recovery_batch_limit, 64);
  assert_eq!(loaded.scheduler.run_retry_base_seconds, 60);
  assert_eq!(loaded.scheduler.run_max_attempts, 5);
  loaded.validate().expect("scheduler config");
}

#[test]
fn test_scheduler_config_rejects_claims_without_lifecycle_and_unsafe_limits() {
  let mut config = CodeoffConfig::default();
  config.scheduler.run_claims_enabled = true;
  assert!(matches!(
    config.validate(),
    Err(ConfigError::InvalidScheduler {
      field: "enabled",
      ..
    })
  ));

  config.scheduler.enabled = true;
  config.scheduler.run_claims_enabled = false;
  config.scheduler.run_heartbeat_interval_ms =
    u64::from(config.scheduler.run_lease_seconds) * 1_000;
  assert!(matches!(
    config.validate(),
    Err(ConfigError::InvalidScheduler {
      field: "run_heartbeat_interval_ms",
      ..
    })
  ));

  config.scheduler.run_heartbeat_interval_ms = 1_000;
  config.scheduler.run_max_attempts = 0;
  assert!(matches!(
    config.validate(),
    Err(ConfigError::InvalidScheduler {
      field: "run_max_attempts",
      ..
    })
  ));
}

#[test]
fn test_scheduler_policy_rejects_strict_heartbeat_and_incoherent_deadlines() {
  let mut config = CodeoffConfig::default();
  config.scheduler.run_heartbeat_interval_ms =
    u64::from(config.scheduler.run_lease_seconds) * 1_000 / 3;
  assert!(matches!(
    config.validate(),
    Err(ConfigError::InvalidScheduler {
      field: "run_heartbeat_interval_ms",
      ..
    })
  ));

  config.scheduler.run_heartbeat_interval_ms = u64::MAX;
  assert!(matches!(
    config.validate(),
    Err(ConfigError::InvalidScheduler {
      field: "run_heartbeat_interval_ms",
      ..
    })
  ));

  config.scheduler.run_heartbeat_interval_ms = 1_000;
  config.scheduler.run_deadline_seconds = config.scheduler.run_timeout_seconds;
  assert!(matches!(
    config.validate(),
    Err(ConfigError::InvalidScheduler {
      field: "run_deadline_seconds",
      ..
    })
  ));

  config.scheduler.run_deadline_seconds = SchedulerRuntimeConfig::default().run_deadline_seconds;
  config.scheduler.delivery_deadline_seconds = u32::from(
    config.scheduler.delivery_send_timeout_seconds
      + config.scheduler.delivery_finalization_timeout_seconds
      - 1,
  );
  assert!(matches!(
    config.validate(),
    Err(ConfigError::InvalidScheduler {
      field: "delivery_retry_after_max_seconds" | "delivery_deadline_seconds",
      ..
    })
  ));
}

fn valid_scheduled_codex_config() -> ScheduledCodexConfig {
  ScheduledCodexConfig {
    codex_program: "/opt/codeoff/bin/codex".into(),
    codex_program_sha256: "a".repeat(64),
    codex_home: "/var/lib/codeoff/scheduled-codex".into(),
    cwd: "/work/codeoff-scheduled".into(),
    github_mcp_url: "http://127.0.0.1:8090/mcp".to_owned(),
    github_mcp_artifact_path: "/opt/codeoff/bin/github-mcp-server".into(),
    github_mcp_artifact_sha256: "b".repeat(64),
    github_mcp_endpoint_identity: "github-mcp-scheduled-v1".to_owned(),
    credential_reference: "kubernetes:codeoff/github-mcp".to_owned(),
    permission_policy_revision: "scheduled-read-only-v1".to_owned(),
    config_revision: "scheduled-codex-v1".to_owned(),
    config_sha256: "c".repeat(64),
    gateway_image_digest: format!("sha256:{}", "e".repeat(64)),
    runner_image_digest: format!("sha256:{}", "f".repeat(64)),
    runner_workload_identity: "spiffe://codeoff/runner/production".to_owned(),
    runner_client_cert_public_key_fingerprint: "1".repeat(64),
    credential_revision: "github-readonly-2026-07".to_owned(),
    isolation_attestation_path: "/var/run/codeoff/isolation-attestation.json".into(),
    isolation_trust_bundle_path: "/opt/codeoff/attestation/isolation-trust-bundle.json".into(),
    trusted_owner_uid: 0,
    trusted_owner_gid: 0,
    runtime_uid: 65_534,
    runtime_gid: 65_534,
  }
}

fn scheduler_with_valid_scheduled_codex() -> CodeoffConfig {
  let mut config = CodeoffConfig::default();
  config.scheduler.enabled = true;
  config.scheduler.run_claims_enabled = true;
  config.agent.scheduled_codex = valid_scheduled_codex_config();
  config
}

#[test]
fn test_scheduled_codex_rejects_unsafe_paths_digests_keys_and_urls() {
  let mut config = scheduler_with_valid_scheduled_codex();
  config.agent.scheduled_codex.codex_program = "relative/codex".into();
  assert!(matches!(
    config.validate(),
    Err(ConfigError::InvalidScheduler {
      field: "scheduled_codex.codex_program",
      ..
    })
  ));

  let mut config = scheduler_with_valid_scheduled_codex();
  config.agent.scheduled_codex.isolation_trust_bundle_path = "relative/trust-bundle.json".into();
  assert!(matches!(
    config.validate(),
    Err(ConfigError::InvalidScheduler {
      field: "scheduled_codex.isolation_trust_bundle_path",
      ..
    })
  ));

  let mut config = scheduler_with_valid_scheduled_codex();
  config.agent.scheduled_codex.cwd = config.agent.scheduled_codex.codex_home.join("workspace");
  assert!(matches!(
    config.validate(),
    Err(ConfigError::InvalidScheduler {
      field: "scheduled_codex.cwd",
      ..
    })
  ));

  let mut config = scheduler_with_valid_scheduled_codex();
  config.agent.scheduled_codex.config_sha256 = "A".repeat(64);
  assert!(matches!(
    config.validate(),
    Err(ConfigError::InvalidScheduler {
      field: "scheduled_codex.config_sha256",
      ..
    })
  ));

  let mut config = scheduler_with_valid_scheduled_codex();
  config.agent.scheduled_codex.runner_image_digest = "sha-f375909".to_owned();
  assert!(matches!(
    config.validate(),
    Err(ConfigError::InvalidScheduler {
      field: "scheduled_codex.runner_image_digest",
      ..
    })
  ));

  let mut config = scheduler_with_valid_scheduled_codex();
  config.agent.scheduled_codex.runner_workload_identity =
    "spiffe://Codeoff/runner/production".to_owned();
  assert!(matches!(
    config.validate(),
    Err(ConfigError::InvalidScheduler {
      field: "scheduled_codex.runner_workload_identity",
      ..
    })
  ));

  let mut config = scheduler_with_valid_scheduled_codex();
  config.agent.scheduled_codex.credential_revision = "GitHub-Readonly".to_owned();
  assert!(matches!(
    config.validate(),
    Err(ConfigError::InvalidScheduler {
      field: "scheduled_codex.credential_revision",
      ..
    })
  ));

  let mut config = scheduler_with_valid_scheduled_codex();
  config.agent.scheduled_codex.github_mcp_url = "http://token@127.0.0.1:8090/mcp".to_owned();
  assert!(matches!(
    config.validate(),
    Err(ConfigError::InvalidScheduler {
      field: "scheduled_codex.github_mcp_url",
      ..
    })
  ));
}

#[test]
fn test_scheduler_config_rejects_retired_delivery_enabled_name() {
  let dir = tempdir().expect("create tempdir");
  let config_path = dir.path().join("codeoff.toml");
  fs::write(
    &config_path,
    r"
[scheduler]
enabled = true
delivery_enabled = true
",
  )
  .expect("write config");
  assert!(matches!(
    CodeoffConfig::load(ConfigLoadOptions::new().config_path(config_path)),
    Err(ConfigError::Parse { .. })
  ));
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
