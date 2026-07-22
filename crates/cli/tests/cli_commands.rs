use std::fs;

use assert_cmd::Command;
use clap::{CommandFactory, Parser};
use codeoff_channel_contract::{ChannelEvent, ChannelEventKind, ChannelReplyTarget};
use codeoff_cli::Cli;
use codeoff_config::{CodeoffConfig, ConfigLoadOptions};
use codeoff_state::{SlackSourceEvent, StateStore};
use tempfile::tempdir;

#[test]
fn test_cli_exposes_expected_subcommands() {
  let command = Cli::command();

  assert_eq!(
    command.get_about().expect("about").to_string(),
    "Codeoff channel gateway"
  );
  assert!(command.find_subcommand("serve").is_some());
  assert!(command.find_subcommand("migrate").is_some());
  assert!(command.find_subcommand("dev").is_some());

  let worker = command
    .find_subcommand("worker")
    .expect("worker subcommand");
  assert!(worker.find_subcommand("slack").is_some());
  assert!(worker.find_subcommand("channel-events").is_some());
  assert!(worker.find_subcommand("temporal").is_none());

  let mut scheduler = command
    .find_subcommand("scheduler")
    .expect("scheduler subcommand")
    .clone();
  for operation in [
    "status",
    "runs",
    "deliveries",
    "reconcile",
    "retry-run",
    "retry-delivery",
    "resolve-delivery-unknown",
    "create",
    "get",
    "list",
    "update",
    "pause",
    "resume",
    "delete",
  ] {
    assert!(
      scheduler.find_subcommand(operation).is_some(),
      "{operation}"
    );
  }
  assert!(
    !scheduler
      .render_long_help()
      .to_string()
      .contains("--as-user")
  );
  let status_help = scheduler
    .find_subcommand("status")
    .expect("scheduler status")
    .clone()
    .render_long_help()
    .to_string();
  for claim in [
    "enablement",
    "claim switches",
    "/healthz",
    "/readyz",
    "/metrics",
  ] {
    assert!(status_help.contains(claim), "missing status help {claim}");
  }

  let config = command
    .find_subcommand("config")
    .expect("config subcommand");
  assert!(config.find_subcommand("check").is_some());
}

#[test]
fn test_scheduler_diagnostics_and_dry_run_do_not_require_operator_identity() {
  let dir = tempdir().expect("create tempdir");
  let state_dir = dir.path().join("state");
  for arguments in [
    vec!["scheduler", "status", "--json"],
    vec!["scheduler", "runs", "list", "--limit", "10", "--json"],
    vec!["scheduler", "deliveries", "list", "--limit", "10", "--json"],
    vec![
      "scheduler",
      "reconcile",
      "--dry-run",
      "--limit",
      "10",
      "--json",
    ],
  ] {
    let output = Command::cargo_bin("codeoff")
      .expect("codeoff binary")
      .env_remove("CODEOFF_SCHEDULER_OPERATOR_ID")
      .env_remove("CODEOFF_SCHEDULER_OPERATOR_REALM")
      .arg("--state-dir")
      .arg(&state_dir)
      .args(arguments)
      .assert()
      .success()
      .get_output()
      .stdout
      .clone();
    let output: serde_json::Value = serde_json::from_slice(&output).expect("sanitized JSON");
    assert_eq!(output["schema_version"], 1);
    assert_eq!(output["ok"], true);
  }
}

#[test]
fn test_scheduler_diagnostics_default_to_sanitized_human_output() {
  let dir = tempdir().expect("create tempdir");
  let state_dir = dir.path().join("state");
  for arguments in [
    vec!["scheduler", "status"],
    vec!["scheduler", "runs", "list", "--limit", "10"],
    vec!["scheduler", "deliveries", "list", "--limit", "10"],
    vec!["scheduler", "reconcile", "--dry-run", "--limit", "10"],
  ] {
    let output = Command::cargo_bin("codeoff")
      .expect("codeoff binary")
      .env_remove("CODEOFF_SCHEDULER_OPERATOR_ID")
      .env_remove("CODEOFF_SCHEDULER_OPERATOR_REALM")
      .arg("--state-dir")
      .arg(&state_dir)
      .args(arguments)
      .assert()
      .success()
      .get_output()
      .stdout
      .clone();
    let output = String::from_utf8(output).expect("human output");
    assert!(output.starts_with("status: ok\n"));
    assert!(serde_json::from_str::<serde_json::Value>(&output).is_err());
    for forbidden in [
      "reason-sentinel",
      "evidence-sentinel",
      "receipt-sentinel",
      "authority-sentinel",
    ] {
      assert!(!output.contains(forbidden));
    }
  }
}

#[test]
fn test_scheduler_reconcile_requires_exactly_one_mode() {
  assert!(
    Cli::try_parse_from(["codeoff", "scheduler", "reconcile"])
      .expect_err("missing mode must fail")
      .to_string()
      .contains("--dry-run")
  );
  assert!(
    Cli::try_parse_from(["codeoff", "scheduler", "reconcile", "--dry-run", "--apply",]).is_err()
  );
  assert!(Cli::try_parse_from(["codeoff", "scheduler", "reconcile", "--dry-run"]).is_ok());
  assert!(Cli::try_parse_from(["codeoff", "scheduler", "reconcile", "--apply"]).is_ok());
}

#[test]
fn test_scheduler_force_resend_requires_reason_and_duplicate_risk_acknowledgement() {
  let prefix = [
    "codeoff",
    "scheduler",
    "resolve-delivery-unknown",
    "delivery",
    "--disposition",
    "force-resend",
    "--request-id",
    "request",
    "--expected-attempt",
    "1",
    "--expected-fence",
    "1",
    "--evidence-file",
    "evidence.json",
    "--authority-file",
    "authority.bin",
  ];
  assert!(Cli::try_parse_from(prefix).is_err());
  assert!(Cli::try_parse_from(prefix.into_iter().chain(["--reason-file", "reason.json"])).is_err());
  assert!(
    Cli::try_parse_from(prefix.into_iter().chain([
      "--reason-file",
      "reason.json",
      "--acknowledge-duplicate-risk",
    ]))
    .is_ok()
  );
}

#[test]
fn test_scheduler_mutation_fails_closed_when_authority_verifier_is_unavailable() {
  let dir = tempdir().expect("create tempdir");
  let state_dir = dir.path().join("state");
  let reason = dir.path().join("reason.json");
  let authority = dir.path().join("authority.bin");
  fs::write(
    &reason,
    r#"{"reason":"provider recovered","reason_code":"provider_recovered","schema_version":1}"#,
  )
  .expect("write reason");
  fs::write(&authority, b"opaque-authority").expect("write authority");
  let stderr = Command::cargo_bin("codeoff")
    .expect("codeoff binary")
    .env_remove("CODEOFF_SCHEDULER_OPERATOR_ID")
    .env_remove("CODEOFF_SCHEDULER_OPERATOR_REALM")
    .arg("--state-dir")
    .arg(&state_dir)
    .args([
      "scheduler",
      "retry-delivery",
      "delivery-id",
      "--request-id",
      "request-1",
      "--expected-attempt",
      "1",
      "--expected-fence",
      "1",
      "--reason-file",
      reason.to_str().expect("reason path"),
      "--authority-file",
      authority.to_str().expect("authority path"),
    ])
    .assert()
    .failure()
    .get_output()
    .stderr
    .clone();
  let error: serde_json::Value = serde_json::from_slice(&stderr).expect("structured error");
  assert_eq!(error["error"]["code"], "authority_verifier_unavailable");
  assert!(!String::from_utf8_lossy(&stderr).contains("opaque-authority"));
  assert!(!String::from_utf8_lossy(&stderr).contains("provider recovered"));
}

#[test]
fn test_scheduler_stdin_create_and_get_are_no_slack_sanitized_json() {
  let dir = tempdir().expect("create tempdir");
  let state_dir = dir.path().join("state");
  let prompt = "private prompt sentinel Authorization: Bearer hidden";
  let input = format!(
    r#"{{
      "schema_version": 1,
      "request_id": "stdin-create",
      "instruction": "{prompt}",
      "schedule": {{"kind": "once", "at": "2030-01-01T00:00:00Z"}},
      "capability": "none",
      "previous_success": {{"kind": "none"}},
      "delivery": {{"kind": "none"}}
    }}"#
  );
  let created = Command::cargo_bin("codeoff")
    .expect("codeoff binary")
    .env("CODEOFF_SCHEDULER_OPERATOR_ID", "ops-a")
    .env("CODEOFF_SCHEDULER_OPERATOR_REALM", "test-realm")
    .env_remove("SLACK_BOT_TOKEN")
    .env_remove("SLACK_APP_TOKEN")
    .env_remove("SLACK_SIGNING_SECRET")
    .args([
      "--state-dir",
      state_dir.to_str().expect("state path"),
      "scheduler",
      "create",
      "--file",
      "-",
      "--format",
      "json",
    ])
    .write_stdin(input)
    .assert()
    .success()
    .get_output()
    .stdout
    .clone();
  let created_text = String::from_utf8(created).expect("stdout");
  assert!(!created_text.contains(prompt));
  let created: serde_json::Value = serde_json::from_str(&created_text).expect("created JSON");
  assert_eq!(created["schema_version"], 1);
  assert_eq!(created["ok"], true);
  assert_eq!(created["data"]["targets"]["items"][0]["kind"], "none");
  let job_id = created["data"]["job_id"].as_str().expect("job id");

  let get = Command::cargo_bin("codeoff")
    .expect("codeoff binary")
    .env("CODEOFF_SCHEDULER_OPERATOR_ID", "ops-a")
    .env("CODEOFF_SCHEDULER_OPERATOR_REALM", "test-realm")
    .env_remove("SLACK_BOT_TOKEN")
    .env_remove("SLACK_APP_TOKEN")
    .env_remove("SLACK_SIGNING_SECRET")
    .args([
      "--state-dir",
      state_dir.to_str().expect("state path"),
      "scheduler",
      "get",
      job_id,
    ])
    .assert()
    .success()
    .get_output()
    .stdout
    .clone();
  let get_text = String::from_utf8(get).expect("get stdout");
  assert!(!get_text.contains(prompt));
  let get: serde_json::Value = serde_json::from_str(&get_text).expect("get JSON");
  assert_eq!(get["data"]["job_id"], job_id);
  assert!(get["data"]["definition"].get("instruction").is_none());
  assert!(state_dir.join("codeoff.db").is_file());
}

#[test]
fn test_scheduler_missing_identity_and_invalid_input_fail_closed_without_secret_echo() {
  let dir = tempdir().expect("create tempdir");
  let state_dir = dir.path().join("state");
  let missing = Command::cargo_bin("codeoff")
    .expect("codeoff binary")
    .env_remove("CODEOFF_SCHEDULER_OPERATOR_ID")
    .env_remove("CODEOFF_SCHEDULER_OPERATOR_REALM")
    .args([
      "--state-dir",
      state_dir.to_str().expect("state path"),
      "scheduler",
      "list",
    ])
    .assert()
    .failure()
    .get_output()
    .stderr
    .clone();
  let missing: serde_json::Value =
    serde_json::from_slice(&missing).expect("versioned identity error");
  assert_eq!(missing["error"]["code"], "unauthorized");
  assert!(!state_dir.exists());

  let secret = "Authorization: Bearer invalid-secret";
  let invalid = Command::cargo_bin("codeoff")
    .expect("codeoff binary")
    .env("CODEOFF_SCHEDULER_OPERATOR_ID", "ops-a")
    .env("CODEOFF_SCHEDULER_OPERATOR_REALM", "test-realm")
    .args([
      "--state-dir",
      state_dir.to_str().expect("state path"),
      "scheduler",
      "create",
      "--file",
      "-",
      "--format",
      "json",
    ])
    .write_stdin(format!(
      r#"{{"schema_version":1,"instruction":"{secret}","owner":"U1"}}"#
    ))
    .assert()
    .failure()
    .get_output()
    .stderr
    .clone();
  let invalid_text = String::from_utf8(invalid).expect("stderr");
  assert!(!invalid_text.contains(secret));
  let invalid: serde_json::Value = serde_json::from_str(&invalid_text).expect("versioned error");
  assert_eq!(invalid["error"]["code"], "validation_failed");
}

#[test]
fn test_serve_check_initializes_state_and_reports_sanitized_runtime_status() {
  let dir = tempdir().expect("create tempdir");
  let state_dir = dir.path().join("state");
  let config_path = dir.path().join("codeoff.toml");
  fs::write(
    &config_path,
    r#"
[server]
bind = "127.0.0.1:7788"

[state]
dir = "${CODEOFF_STATE_DIR:-./.codeoff}"

[database]
url = "sqlite://${CODEOFF_STATE_DIR:-./.codeoff}/private-codeoff.db"

[slack]
workspace_id = "T12345678"
transport = "socket_mode"

[agent.codex_app_server]
command = "codex app-server --listen stdio://"
transport = "stdio"

[mcp]
enabled = true
transport = "stdio"
"#,
  )
  .expect("write config");

  let assert = Command::cargo_bin("codeoff")
    .expect("codeoff binary")
    .env("SLACK_BOT_TOKEN", "xoxb-private-token")
    .env("SLACK_APP_TOKEN", "xapp-private-token")
    .env("SLACK_SIGNING_SECRET", "private-signing-secret")
    .args([
      "--config",
      config_path.to_str().expect("utf-8 path"),
      "--state-dir",
      state_dir.to_str().expect("utf-8 path"),
      "serve",
      "--check",
    ])
    .assert()
    .success();

  let output = assert.get_output();
  let stdout = String::from_utf8_lossy(&output.stdout);
  let stderr = String::from_utf8_lossy(&output.stderr);
  assert!(stdout.contains("serve check ok"));
  assert!(stdout.contains("state=initialized"));
  assert!(stdout.contains("slack_intake=ready transport=socket_mode workspace_id=T12345678"));
  assert!(stdout.contains("channel_dispatch=wired backend=codex_app_server"));
  assert!(stdout.contains("codex_backend=constructed transport=stdio"));
  assert!(stdout.contains("mcp=configured transport=stdio server_loop=not-started"));
  assert!(stdout.contains("slack_delivery=wired queue=next_due"));
  assert!(!stdout.contains("sqlite://"));
  assert!(!stdout.contains("private-codeoff.db"));
  assert!(!stdout.contains("xoxb-private-token"));
  assert!(!stdout.contains("xapp-private-token"));
  assert!(!stdout.contains("private-signing-secret"));
  assert!(!stderr.contains("sqlite://"));
  assert!(!stderr.contains("xoxb-private-token"));
  assert!(state_dir.join("private-codeoff.db").is_file());
}

#[test]
fn test_serve_check_reports_unavailable_processors_without_starting_live_processes() {
  let dir = tempdir().expect("create tempdir");
  let state_dir = dir.path().join("state");
  let config_path = dir.path().join("codeoff.toml");
  let sentinel = dir.path().join("codex-was-started");
  fs::write(
    &config_path,
    format!(
      r#"
[agent.codex_app_server]
command = "sh -c 'touch {}'"
transport = "stdio"
"#,
      sentinel.display()
    ),
  )
  .expect("write config");

  let assert = Command::cargo_bin("codeoff")
    .expect("codeoff binary")
    .env_remove("SLACK_BOT_TOKEN")
    .env_remove("SLACK_APP_TOKEN")
    .env_remove("SLACK_SIGNING_SECRET")
    .args([
      "--config",
      config_path.to_str().expect("utf-8 path"),
      "--state-dir",
      state_dir.to_str().expect("utf-8 path"),
      "serve",
      "--check",
    ])
    .assert()
    .success();

  let stdout = String::from_utf8_lossy(&assert.get_output().stdout);
  assert!(stdout.contains("serve check ok"));
  assert!(stdout.contains("state=initialized"));
  assert!(
    stdout.contains("slack_intake=unavailable transport=socket_mode missing_env=SLACK_BOT_TOKEN")
  );
  assert!(stdout.contains("channel_dispatch=wired backend=codex_app_server"));
  assert!(stdout.contains("codex_backend=constructed transport=stdio"));
  assert!(stdout.contains("mcp=disabled"));
  assert!(stdout.contains("slack_delivery=unavailable missing_env=SLACK_BOT_TOKEN"));
  assert!(!stdout.contains("sqlite://"));
  assert!(state_dir.join("codeoff.db").is_file());
  assert!(!sentinel.exists());
}

#[test]
fn test_serve_non_check_reports_wired_loops_without_skeleton_status() {
  let dir = tempdir().expect("create tempdir");
  let state_dir = dir.path().join("state");
  let config_path = dir.path().join("codeoff.toml");
  fs::write(
    &config_path,
    r#"
[mcp]
enabled = true
transport = "tcp"
bind = "127.0.0.1:0"

[scheduler]
enabled = true
run_claims_enabled = true
"#,
  )
  .expect("write config");

  let assert = Command::cargo_bin("codeoff")
    .expect("codeoff binary")
    .env_remove("SLACK_BOT_TOKEN")
    .env_remove("SLACK_APP_TOKEN")
    .env_remove("SLACK_SIGNING_SECRET")
    .env("CODEOFF_SERVE_TICK_LIMIT", "1")
    .args([
      "--config",
      config_path.to_str().expect("utf-8 path"),
      "--state-dir",
      state_dir.to_str().expect("utf-8 path"),
      "serve",
    ])
    .assert()
    .success();

  let stdout = String::from_utf8_lossy(&assert.get_output().stdout);
  assert!(stdout.contains("serve started"));
  assert!(stdout.contains("state=initialized"));
  assert!(
    stdout.contains("slack_intake=unavailable transport=socket_mode missing_env=SLACK_BOT_TOKEN")
  );
  assert!(stdout.contains("channel_dispatch=started backend=codex_app_server"));
  assert!(stdout.contains("slack_delivery=unavailable missing_env=SLACK_BOT_TOKEN"));
  assert!(stdout.contains("mcp=configured transport=tcp bind=127.0.0.1:0 server_loop=started"));
  assert!(!stdout.contains("serve skeleton tick ok"));
  assert!(!stdout.contains("live loops not started in this slice"));
  assert!(!stdout.contains("next-due-delivery-primitive-missing"));
}

#[test]
fn test_worker_channel_events_dry_run_reports_normalized_event_without_raw_payload() {
  let dir = tempdir().expect("create tempdir");
  let state_dir = dir.path().join("state");
  let config = CodeoffConfig::load(
    ConfigLoadOptions::new()
      .config_path(dir.path().join("missing-codeoff.toml"))
      .explicit_state_dir(state_dir.clone()),
  )
  .expect("load config");
  let event = ChannelEvent::new(
    "slack",
    "slack-default",
    "workspace-1",
    "event-1",
    "dedupe-1",
    ChannelEventKind::MentionReceived,
  )
  .expect("normalized event")
  .with_source_details(
    ChannelReplyTarget::Thread {
      channel_id: "C1".to_owned(),
      thread_id: "100.0".to_owned(),
    },
    "slack://workspace-1/C1/100.0",
  )
  .expect("source details");
  let source = SlackSourceEvent {
    workspace_id: "workspace-1".to_owned(),
    event_kind: "app_mention".to_owned(),
    dedupe_key: "dedupe-1".to_owned(),
    envelope_id: Some("envelope-1".to_owned()),
    event_id: Some("event-1".to_owned()),
    channel_id: Some("C1".to_owned()),
    thread_ts: Some("100.0".to_owned()),
    message_ts: Some("100.0".to_owned()),
    user_id: Some("U1".to_owned()),
    raw_payload_json: r#"{"secret":"do-not-print"}"#.to_owned(),
  };
  let runtime = tokio::runtime::Runtime::new().expect("create runtime");
  runtime.block_on(async {
    let store = StateStore::initialize(config.state_dir(), config.database_url())
      .await
      .expect("initialize state");
    store
      .persist_slack_source_event(&source, &event)
      .await
      .expect("persist event");
  });

  let assert = Command::cargo_bin("codeoff")
    .expect("codeoff binary")
    .args([
      "--state-dir",
      state_dir.to_str().expect("utf-8 path"),
      "worker",
      "channel-events",
      "--dry-run",
    ])
    .assert()
    .success();
  let stdout = String::from_utf8_lossy(&assert.get_output().stdout);
  assert!(stdout.contains("kind=MentionReceived"));
  assert!(stdout.contains("connector=slack-default"));
  assert!(stdout.contains("target=thread:C1:100.0"));
  assert!(stdout.contains("dedupe_key=dedupe-1"));
  assert!(stdout.contains("source_id=event-1"));
  assert!(!stdout.contains("do-not-print"));

  Command::cargo_bin("codeoff")
    .expect("codeoff binary")
    .args([
      "--state-dir",
      state_dir.to_str().expect("utf-8 path"),
      "worker",
      "channel-events",
      "--dry-run",
    ])
    .assert()
    .success()
    .stdout(predicates::str::contains("no pending channel events"));
}

#[test]
fn test_config_check_accepts_documented_minimal_config_without_printing_database_url() {
  let dir = tempdir().expect("create tempdir");
  let config_path = dir.path().join("codeoff.toml");
  fs::write(
    &config_path,
    r#"
[server]
bind = "127.0.0.1:7788"

[state]
dir = "${CODEOFF_STATE_DIR:-./.codeoff}"

[database]
url = "sqlite://${CODEOFF_STATE_DIR:-./.codeoff}/codeoff.db"
"#,
  )
  .expect("write config");

  let assert = Command::cargo_bin("codeoff")
    .expect("codeoff binary")
    .args([
      "--config",
      config_path.to_str().expect("utf-8 path"),
      "config",
      "check",
    ])
    .assert()
    .success();

  let stdout = String::from_utf8_lossy(&assert.get_output().stdout);
  assert!(stdout.contains("config ok"));
  assert!(stdout.contains("state_dir=./.codeoff"));
  assert!(stdout.contains("mcp=disabled"));
  assert!(stdout.contains("mcp_transport=stdio"));
  assert!(!stdout.contains("sqlite://"));
}

#[test]
fn test_migrate_initializes_state_database_without_printing_database_url() {
  let dir = tempdir().expect("create tempdir");
  let state_dir = dir.path().join("state");

  let assert = Command::cargo_bin("codeoff")
    .expect("codeoff binary")
    .args([
      "--state-dir",
      state_dir.to_str().expect("utf-8 path"),
      "migrate",
    ])
    .assert()
    .success();

  let stdout = String::from_utf8_lossy(&assert.get_output().stdout);
  assert!(stdout.contains("state migrated"));
  assert!(stdout.contains(&format!("state_dir={}", state_dir.display())));
  assert!(!stdout.contains("sqlite://"));
  assert!(state_dir.join("codeoff.db").is_file());
}

#[test]
fn test_worker_slack_check_validates_secrets_and_initializes_state_without_printing_values() {
  let dir = tempdir().expect("create tempdir");
  let state_dir = dir.path().join("state");

  let assert = Command::cargo_bin("codeoff")
    .expect("codeoff binary")
    .env("SLACK_BOT_TOKEN", "xoxb-private-token")
    .env("SLACK_APP_TOKEN", "xapp-private-token")
    .env("SLACK_SIGNING_SECRET", "private-signing-secret")
    .args([
      "--state-dir",
      state_dir.to_str().expect("utf-8 path"),
      "worker",
      "slack",
      "--check",
    ])
    .assert()
    .success();

  let output = assert.get_output();
  let stdout = String::from_utf8_lossy(&output.stdout);
  let stderr = String::from_utf8_lossy(&output.stderr);
  assert!(stdout.contains("slack config ok"));
  assert!(stdout.contains("SLACK_BOT_TOKEN"));
  assert!(!stdout.contains("xoxb-private-token"));
  assert!(!stdout.contains("xapp-private-token"));
  assert!(!stdout.contains("private-signing-secret"));
  assert!(!stderr.contains("xoxb-private-token"));
  assert!(state_dir.join("codeoff.db").is_file());
}

#[test]
fn test_worker_slack_check_fails_clearly_when_a_required_secret_is_missing() {
  Command::cargo_bin("codeoff")
    .expect("codeoff binary")
    .env_remove("SLACK_BOT_TOKEN")
    .env_remove("SLACK_APP_TOKEN")
    .env_remove("SLACK_SIGNING_SECRET")
    .args(["worker", "slack", "--check"])
    .assert()
    .failure()
    .stderr(predicates::str::contains("SLACK_BOT_TOKEN"));
}
