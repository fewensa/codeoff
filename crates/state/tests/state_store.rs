use std::error::Error;
use std::path::Path;
use std::str::FromStr;

use codeoff_channel_contract::{ChannelEvent, ChannelEventKind, ChannelReplyTarget};
use codeoff_state::{
  ChannelConversationKey, ChannelEventStatusKind, RetentionPolicy, SlackDeliveryClaim,
  SlackDeliveryOperationClaim, SlackDeliveryReceipt, SlackDeliveryRequest, SlackDeliverySender,
  SlackDeliveryStatusKind, SlackProcessingIndicatorStatusKind, SlackSourceEvent,
  SlackStopStreamDeliveryRequest, StateError, StateStore,
};
use sqlx::SqlitePool;
use sqlx::sqlite::SqliteConnectOptions;
use tempfile::tempdir;

fn default_database_url(state_dir: &Path) -> String {
  format!("sqlite://{}", state_dir.join("codeoff.db").display())
}

#[tokio::test]
async fn test_initialize_uses_default_database_when_url_is_omitted() {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state");

  let store = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize state store");

  assert!(state_dir.join("codeoff.db").is_file());
  assert!(
    store
      .claim_idempotency_key("tests", "default-database")
      .await
      .expect("claim idempotency key")
  );
}

#[tokio::test]
async fn test_initialize_creates_missing_state_dir_and_database() {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state");
  let _store = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize state store");

  assert!(state_dir.is_dir());
  assert!(state_dir.join("codeoff.db").is_file());
}

#[tokio::test]
async fn test_initialize_redacts_malformed_database_url() {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state");
  let sentinel = "sqlite-url-secret-4f9b";
  let database_url = format!(
    "sqlite://{}?{sentinel}=unexpected_parameter",
    temp.path().join("custom.db").display()
  );
  let parse_error = SqliteConnectOptions::from_str(&database_url).expect_err("parse database URL");
  assert!(parse_error.to_string().contains(sentinel));

  let error = StateStore::initialize(&state_dir, Some(&database_url))
    .await
    .expect_err("malformed database URL");
  let displayed = error.to_string();

  assert!(matches!(error, StateError::InvalidDatabaseUrl { .. }));
  assert!(!displayed.contains(sentinel));
  assert!(!displayed.contains(&database_url));
  assert!(!format!("{error:?}").contains(sentinel));
  assert!(!format!("{error:?}").contains(&database_url));
  assert!(error.source().is_none());
}

#[tokio::test]
async fn test_initialize_configures_wal_mode() {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state");
  StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize state store");

  let pool = SqlitePool::connect(&default_database_url(&state_dir))
    .await
    .expect("connect initialized database");
  let journal_mode: String = sqlx::query_scalar("pragma journal_mode")
    .fetch_one(&pool)
    .await
    .expect("read journal mode");

  assert_eq!(journal_mode, "wal");
}

#[tokio::test]
async fn test_initialize_runs_migrations_repeatably() {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state");
  StateStore::initialize(&state_dir, None)
    .await
    .expect("first initialize");
  StateStore::initialize(&state_dir, None)
    .await
    .expect("second initialize");

  let pool = SqlitePool::connect(&default_database_url(&state_dir))
    .await
    .expect("connect migrated database");
  let failed_migration_count: i64 =
    sqlx::query_scalar("select count(*) from _sqlx_migrations where success = false")
      .fetch_one(&pool)
      .await
      .expect("query migrations");

  assert_eq!(failed_migration_count, 0);
}

#[tokio::test]
async fn test_initialize_creates_foundation_tables() {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state");
  StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize state store");

  let pool = SqlitePool::connect(&default_database_url(&state_dir))
    .await
    .expect("connect migrated database");
  let tables: Vec<String> =
    sqlx::query_scalar("select name from sqlite_master where type = 'table' order by name")
      .fetch_all(&pool)
      .await
      .expect("query tables");

  for table in [
    "channel_conversation_summaries",
    "conversation_contexts",
    "channel_event_queue",
    "idempotency_keys",
    "slack_source_events",
    "slack_delivery_queue",
    "slack_delivery_receipts",
    "slack_processing_indicators",
    "work_items",
  ] {
    assert!(tables.iter().any(|name| name == table), "missing {table}");
  }
}

#[tokio::test]
async fn test_initialize_adds_slack_stream_delivery_and_indicator_schema() {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state");
  StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize state store");

  let pool = SqlitePool::connect(&default_database_url(&state_dir))
    .await
    .expect("connect migrated database");
  let delivery_columns: Vec<String> =
    sqlx::query_scalar("select name from pragma_table_info('slack_delivery_queue')")
      .fetch_all(&pool)
      .await
      .expect("query delivery columns");
  let indicator_columns: Vec<String> =
    sqlx::query_scalar("select name from pragma_table_info('slack_processing_indicators')")
      .fetch_all(&pool)
      .await
      .expect("query indicator columns");

  assert!(delivery_columns.iter().any(|name| name == "operation"));
  assert!(delivery_columns.iter().any(|name| name == "message_ts"));
  for column in [
    "workspace_id",
    "event_dedupe_key",
    "channel_id",
    "thread_ts",
    "message_ts",
    "status",
    "error",
    "created_at",
    "updated_at",
    "completed_at",
  ] {
    assert!(
      indicator_columns.iter().any(|name| name == column),
      "missing {column}"
    );
  }
}

#[tokio::test]
async fn test_initialize_handles_default_state_dir_with_url_special_characters() {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state?#special");
  let _store = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize state store");

  assert!(state_dir.join("codeoff.db").is_file());
}

#[tokio::test]
async fn test_initialize_creates_custom_database_parent_directory() {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state");
  let database_path = temp.path().join("custom").join("nested").join("codeoff.db");
  let database_url = format!("sqlite://{}", database_path.display());

  let _store = StateStore::initialize(&state_dir, Some(&database_url))
    .await
    .expect("initialize state store");

  assert!(state_dir.is_dir());
  assert!(database_path.is_file());
}

#[tokio::test]
async fn test_claim_idempotency_key_only_inserts_once() {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state");
  let store = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize state store");

  let first = store
    .claim_idempotency_key("tests", "same-key")
    .await
    .expect("claim first idempotency key");
  let second = store
    .claim_idempotency_key("tests", "same-key")
    .await
    .expect("claim duplicate idempotency key");

  assert!(first);
  assert!(!second);
}

#[tokio::test]
async fn test_channel_conversation_summary_upserts_and_reads_summary() {
  let temp = tempdir().expect("tempdir");
  let store = StateStore::initialize(temp.path(), None)
    .await
    .expect("store");
  let key = ChannelConversationKey {
    provider: "slack".to_owned(),
    workspace_id: "T1".to_owned(),
    conversation_kind: "thread".to_owned(),
    channel_id: Some("C1".to_owned()),
    thread_id: Some("100.0".to_owned()),
    user_id: None,
  };

  assert_eq!(
    store
      .channel_conversation_summary(&key)
      .await
      .expect("read"),
    None
  );
  store
    .upsert_channel_conversation_summary(&key, "User asked about worker restarts.")
    .await
    .expect("upsert");
  assert_eq!(
    store
      .channel_conversation_summary(&key)
      .await
      .expect("read")
      .expect("summary")
      .summary,
    "User asked about worker restarts."
  );
  store
    .upsert_channel_conversation_summary(
      &key,
      "User asked about worker restarts. Assistant replied.",
    )
    .await
    .expect("upsert replacement");
  assert_eq!(
    store
      .channel_conversation_summary(&key)
      .await
      .expect("read")
      .expect("summary")
      .summary,
    "User asked about worker restarts. Assistant replied."
  );
}

#[tokio::test]
async fn test_channel_conversation_mapping_upserts_and_reads_codex_thread() {
  let temp = tempdir().expect("tempdir");
  let store = StateStore::initialize(temp.path(), None)
    .await
    .expect("store");
  let key = ChannelConversationKey {
    provider: "slack".to_owned(),
    workspace_id: "T1".to_owned(),
    conversation_kind: "thread".to_owned(),
    channel_id: Some("C1".to_owned()),
    thread_id: Some("100.0".to_owned()),
    user_id: None,
  };

  assert_eq!(
    store
      .channel_conversation_thread_id(&key)
      .await
      .expect("read"),
    None
  );
  store
    .upsert_channel_conversation_thread_id(&key, "codex-thread-1")
    .await
    .expect("upsert");
  assert_eq!(
    store
      .channel_conversation_thread_id(&key)
      .await
      .expect("read"),
    Some("codex-thread-1".to_owned())
  );
  store
    .upsert_channel_conversation_thread_id(&key, "codex-thread-2")
    .await
    .expect("upsert replacement");
  assert_eq!(
    store
      .channel_conversation_thread_id(&key)
      .await
      .expect("read"),
    Some("codex-thread-2".to_owned())
  );
}

#[tokio::test]
async fn test_channel_conversation_mapping_scopes_by_provider_workspace_and_kind() {
  let temp = tempdir().expect("tempdir");
  let store = StateStore::initialize(temp.path(), None)
    .await
    .expect("store");
  let thread_key = ChannelConversationKey {
    provider: "slack".to_owned(),
    workspace_id: "T1".to_owned(),
    conversation_kind: "thread".to_owned(),
    channel_id: Some("C1".to_owned()),
    thread_id: Some("100.0".to_owned()),
    user_id: None,
  };
  let dm_key = ChannelConversationKey {
    provider: "slack".to_owned(),
    workspace_id: "T1".to_owned(),
    conversation_kind: "dm".to_owned(),
    channel_id: Some("D1".to_owned()),
    thread_id: None,
    user_id: Some("U1".to_owned()),
  };

  store
    .upsert_channel_conversation_thread_id(&thread_key, "thread-codex")
    .await
    .expect("thread upsert");
  store
    .upsert_channel_conversation_thread_id(&dm_key, "dm-codex")
    .await
    .expect("dm upsert");

  assert_eq!(
    store
      .channel_conversation_thread_id(&thread_key)
      .await
      .expect("thread read"),
    Some("thread-codex".to_owned())
  );
  assert_eq!(
    store
      .channel_conversation_thread_id(&dm_key)
      .await
      .expect("dm read"),
    Some("dm-codex".to_owned())
  );
}

#[tokio::test]
async fn test_channel_event_claiming_records_attempts_and_terminal_states() {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state");
  let store = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize state store");
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
    raw_payload_json: "{}".to_owned(),
  };
  store
    .persist_slack_source_event(&source, &event)
    .await
    .expect("persist normalized event");

  let claimed = store
    .claim_next_channel_event()
    .await
    .expect("claim pending event")
    .expect("one pending event");
  assert_eq!(claimed.event, event);
  assert_eq!(claimed.attempt_count, 1);
  assert!(
    store
      .claim_next_channel_event()
      .await
      .expect("claim while processing")
      .is_none()
  );

  store
    .fail_channel_event(claimed.id, "dry-run failure")
    .await
    .expect("record failed attempt");
  assert!(
    store
      .claim_next_channel_event()
      .await
      .expect("failed event is not claimed again")
      .is_none()
  );

  assert_eq!(
    store
      .channel_event_status("slack", "workspace-1", "dedupe-1")
      .await
      .expect("read failed queue event")
      .expect("failed queue event")
      .status,
    ChannelEventStatusKind::Failed
  );
}

#[tokio::test]
async fn test_channel_event_status_scopes_same_dedupe_key_by_provider() {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state");
  let store = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize state store");
  let workspace_id = "workspace-1";
  let dedupe_key = "shared-dedupe-key";
  let other_event = ChannelEvent::new(
    "teams",
    "teams-default",
    workspace_id,
    "teams-event-1",
    dedupe_key,
    ChannelEventKind::MentionReceived,
  )
  .expect("other provider event");
  let pool = SqlitePool::connect(&default_database_url(&state_dir))
    .await
    .expect("connect migrated database");
  sqlx::query(
    "insert into channel_event_queue (provider, workspace_id, dedupe_key, event_kind, payload_json, status) values (?1, ?2, ?3, ?4, ?5, 'processed')",
  )
  .bind(&other_event.provider)
  .bind(&other_event.workspace_id)
  .bind(&other_event.dedupe_key)
  .bind(format!("{:?}", other_event.kind))
  .bind(serde_json::to_string(&other_event).expect("serialize other event"))
  .execute(&pool)
  .await
  .expect("insert other provider event");

  let slack_event = ChannelEvent::new(
    "slack",
    "slack-default",
    workspace_id,
    "slack-event-1",
    dedupe_key,
    ChannelEventKind::MentionReceived,
  )
  .expect("slack event");
  store
    .persist_slack_source_event(
      &SlackSourceEvent {
        workspace_id: workspace_id.to_owned(),
        event_kind: "app_mention".to_owned(),
        dedupe_key: dedupe_key.to_owned(),
        envelope_id: Some("envelope-1".to_owned()),
        event_id: Some("slack-event-1".to_owned()),
        channel_id: Some("C1".to_owned()),
        thread_ts: None,
        message_ts: Some("100.0".to_owned()),
        user_id: Some("U1".to_owned()),
        raw_payload_json: "{}".to_owned(),
      },
      &slack_event,
    )
    .await
    .expect("persist slack event");
  let claimed = store
    .claim_next_channel_event()
    .await
    .expect("claim slack event")
    .expect("slack event");
  store
    .fail_channel_event(claimed.id, "slack failure")
    .await
    .expect("fail slack event");

  assert_eq!(
    store
      .channel_event_status("teams", workspace_id, dedupe_key)
      .await
      .expect("other provider status")
      .expect("other provider event")
      .status,
    ChannelEventStatusKind::Processed
  );
  assert_eq!(
    store
      .channel_event_status("slack", workspace_id, dedupe_key)
      .await
      .expect("slack status")
      .expect("slack event")
      .status,
    ChannelEventStatusKind::Failed
  );
}

#[tokio::test]
async fn test_slack_source_references_include_bounded_source_metadata() {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state");
  let store = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize state store");
  let event = ChannelEvent::new(
    "slack",
    "slack-default",
    "workspace-1",
    "event-1",
    "dedupe-1",
    ChannelEventKind::MentionReceived,
  )
  .expect("normalized event");
  let source = SlackSourceEvent {
    workspace_id: "workspace-1".to_owned(),
    event_kind: "app_mention".to_owned(),
    dedupe_key: "dedupe-1".to_owned(),
    envelope_id: Some("envelope-1".to_owned()),
    event_id: Some("event-1".to_owned()),
    channel_id: Some("C1".to_owned()),
    thread_ts: Some("100.0".to_owned()),
    message_ts: Some("101.0".to_owned()),
    user_id: Some("U1".to_owned()),
    raw_payload_json: r#"{
      "event": {
        "type": "app_mention",
        "text": "Please review https://example.com/report",
        "blocks": [{
          "type": "rich_text",
          "elements": [{
            "type": "rich_text_section",
            "elements": [
              {"type": "text", "text": "linked "},
              {"type": "link", "url": "https://example.com/block", "text": "block link"}
            ]
          }]
        }],
        "attachments": [{
          "id": 1,
          "title": "Quarterly report",
          "text": "attachment body",
          "title_link": "https://example.com/attachment"
        }],
        "files": [{
          "id": "F1",
          "name": "report.md",
          "title": "Report",
          "mimetype": "text/markdown",
          "filetype": "markdown",
          "size": 42,
          "url_private": "https://files.slack.com/private"
        }]
      }
    }"#
      .to_owned(),
  };
  store
    .persist_slack_source_event(&source, &event)
    .await
    .expect("persist slack event");

  let references = store
    .slack_source_references("workspace-1", "dedupe-1")
    .await
    .expect("source references");

  assert!(references.found);
  assert_eq!(references.event_kind.as_deref(), Some("app_mention"));
  assert_eq!(references.channel_id.as_deref(), Some("C1"));
  assert_eq!(references.thread_id.as_deref(), Some("100.0"));
  assert_eq!(references.message_ts.as_deref(), Some("101.0"));
  assert_eq!(references.user_id.as_deref(), Some("U1"));
  assert_eq!(
    references.text_preview.as_deref(),
    Some("Please review https://example.com/report")
  );
  assert_eq!(references.links.len(), 3);
  assert_eq!(references.links[0].url, "https://example.com/report");
  assert_eq!(references.links[1].url, "https://example.com/block");
  assert_eq!(references.links[1].text.as_deref(), Some("block link"));
  assert_eq!(references.links[2].url, "https://example.com/attachment");
  assert_eq!(references.attachments.len(), 1);
  assert_eq!(
    references.attachments[0].title.as_deref(),
    Some("Quarterly report")
  );
  assert_eq!(
    references.attachments[0].text.as_deref(),
    Some("attachment body")
  );
  assert_eq!(references.files.len(), 1);
  assert_eq!(references.files[0].resource_id.as_deref(), Some("F1"));
  assert_eq!(references.files[0].name.as_deref(), Some("report.md"));
  assert_eq!(
    references.files[0].media_type.as_deref(),
    Some("text/markdown")
  );
  assert_eq!(references.files[0].size_bytes, Some(42));
}

#[tokio::test]
async fn test_delivery_receipt_persists_slack_identifiers_and_dedupe_key() {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state");
  let store = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize state store");
  let request = SlackDeliveryRequest {
    connector_id: "connector-1".to_owned(),
    workspace_id: "workspace-1".to_owned(),
    request_dedupe_key: "message-1".to_owned(),
    channel_id: "C1".to_owned(),
    thread_ts: Some("100.0".to_owned()),
    text: "hello".to_owned(),
    sender: SlackDeliverySender::User {
      key: "example".to_owned(),
    },
  };
  store
    .enqueue_slack_delivery(&request, 100)
    .await
    .expect("enqueue delivery");
  let receipt = SlackDeliveryReceipt {
    connector_id: request.connector_id.clone(),
    workspace_id: request.workspace_id.clone(),
    channel_id: request.channel_id.clone(),
    thread_ts: request.thread_ts.clone(),
    message_ts: "200.0".to_owned(),
    request_dedupe_key: request.request_dedupe_key.clone(),
    sender: request.sender.clone(),
  };
  store
    .complete_slack_delivery(&receipt, r#"{"ok":true}"#, 101)
    .await
    .expect("persist receipt");

  let pool = SqlitePool::connect(&default_database_url(&state_dir))
    .await
    .expect("connect migrated database");
  let persisted: (String, Option<String>, String, String, String, Option<String>) = sqlx::query_as(
    "select channel_id, thread_ts, message_ts, request_dedupe_key, sender_kind, sender_key from slack_delivery_receipts",
  )
  .fetch_one(&pool)
  .await
  .expect("read receipt");

  assert_eq!(persisted.0, "C1");
  assert_eq!(persisted.1.as_deref(), Some("100.0"));
  assert_eq!(persisted.2, "200.0");
  assert_eq!(persisted.3, "message-1");
  assert_eq!(persisted.4, "user");
  assert_eq!(persisted.5.as_deref(), Some("example"));
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn test_cleanup_retained_data_removes_only_expired_terminal_rows_for_workspace() {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state");
  let store = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize state store");
  let pool = SqlitePool::connect(&default_database_url(&state_dir))
    .await
    .expect("connect migrated database");
  let old = "2026-05-01 00:00:00";
  let very_old = "2026-03-01 00:00:00";
  let recent = "2026-07-10 00:00:00";
  let now = 1_783_987_200;

  sqlx::query(
    r"
insert into slack_source_events (workspace_id, event_kind, dedupe_key, raw_payload_json, received_at, status)
values
  ('workspace-1', 'app_mention', 'old-terminal-source', '{}', ?1, 'queued'),
  ('workspace-1', 'app_mention', 'old-active-source', '{}', ?1, 'queued'),
  ('workspace-1', 'app_mention', 'recent-source', '{}', ?2, 'queued'),
  ('workspace-2', 'app_mention', 'other-workspace-source', '{}', ?1, 'queued')
",
  )
  .bind(old)
  .bind(recent)
  .execute(&pool)
  .await
  .expect("insert source events");
  sqlx::query(
    r"
insert into channel_event_queue (provider, workspace_id, dedupe_key, event_kind, payload_json, status, created_at, updated_at)
values
  ('slack', 'workspace-1', 'old-terminal-source', 'MentionReceived', '{}', 'processed', ?1, ?1),
  ('slack', 'workspace-1', 'old-active-source', 'MentionReceived', '{}', 'pending', ?1, ?1),
  ('slack', 'workspace-1', 'old-failed-event', 'MentionReceived', '{}', 'failed', ?1, ?1),
  ('slack', 'workspace-1', 'recent-processed-event', 'MentionReceived', '{}', 'processed', ?2, ?2),
  ('slack', 'workspace-2', 'other-workspace-event', 'MentionReceived', '{}', 'processed', ?1, ?1)
",
  )
  .bind(old)
  .bind(recent)
  .execute(&pool)
  .await
  .expect("insert queue events");
  sqlx::query(
    r"
insert into slack_delivery_queue (connector_id, workspace_id, request_dedupe_key, channel_id, text, status, available_at, created_at, updated_at)
values
  ('connector-1', 'workspace-1', 'old-delivered', 'C1', 'done', 'delivered', 100, ?1, ?1),
  ('connector-1', 'workspace-1', 'old-failed-delivery', 'C1', 'failed', 'failed', 100, ?1, ?1),
  ('connector-1', 'workspace-1', 'old-pending-delivery', 'C1', 'pending', 'pending', 100, ?1, ?1),
  ('connector-1', 'workspace-1', 'recent-delivered', 'C1', 'recent', 'delivered', 100, ?2, ?2),
  ('connector-1', 'workspace-2', 'other-workspace-delivery', 'C1', 'other', 'delivered', 100, ?1, ?1)
",
  )
  .bind(old)
  .bind(recent)
  .execute(&pool)
  .await
  .expect("insert delivery queue rows");
  sqlx::query(
    r#"
insert into slack_delivery_receipts (connector_id, workspace_id, channel_id, message_ts, request_dedupe_key, slack_response_json, created_at)
values
  ('connector-1', 'workspace-1', 'C1', '200.0', 'old-delivered', '{"ok":true}', ?1),
  ('connector-1', 'workspace-1', 'C1', '201.0', 'recent-delivered', '{"ok":true}', ?2),
  ('connector-1', 'workspace-2', 'C1', '202.0', 'other-workspace-delivery', '{"ok":true}', ?1)
"#,
  )
  .bind(old)
  .bind(recent)
  .execute(&pool)
  .await
  .expect("insert delivery receipts");
  sqlx::query(
    r"
insert into slack_processing_indicators (workspace_id, event_dedupe_key, channel_id, message_ts, status, created_at, updated_at, completed_at)
values
  ('workspace-1', 'old-completed-indicator', 'C1', '300.0', 'completed', ?1, ?1, ?1),
  ('workspace-1', 'old-started-indicator', 'C1', '301.0', 'started', ?1, ?1, null),
  ('workspace-1', 'recent-completed-indicator', 'C1', '302.0', 'completed', ?2, ?2, ?2),
  ('workspace-2', 'other-workspace-indicator', 'C1', '303.0', 'completed', ?1, ?1, ?1)
",
  )
  .bind(old)
  .bind(recent)
  .execute(&pool)
  .await
  .expect("insert processing indicators");
  sqlx::query(
    r"
insert into context_fetch_attempts (provider, workspace_id, connector_id, dedupe_key, operation, status, created_at)
values
  ('slack', 'workspace-1', 'connector-1', 'old-context-attempt', 'fetch_thread', 'failed', ?1),
  ('slack', 'workspace-1', 'connector-1', 'recent-context-attempt', 'fetch_thread', 'success', ?2),
  ('slack', 'workspace-2', 'connector-1', 'other-workspace-context-attempt', 'fetch_thread', 'failed', ?1)
",
  )
  .bind(old)
  .bind(recent)
  .execute(&pool)
  .await
  .expect("insert context fetch attempts");
  sqlx::query(
    r"
insert into channel_conversation_summaries (provider, workspace_id, conversation_kind, channel_id, thread_id, summary, created_at, updated_at)
values
  ('slack', 'workspace-1', 'thread', 'C1', '100.0', 'old summary', ?1, ?1),
  ('slack', 'workspace-1', 'thread', 'C1', '101.0', 'recent summary', ?2, ?2),
  ('slack', 'workspace-2', 'thread', 'C1', '102.0', 'other workspace summary', ?1, ?1)
",
  )
  .bind(very_old)
  .bind(recent)
  .execute(&pool)
  .await
  .expect("insert conversation summaries");

  let cleanup = store
    .cleanup_retained_data(
      Some("workspace-1"),
      now,
      &RetentionPolicy {
        enabled: true,
        inbound_payload_days: 30,
        delivery_days: 30,
        context_attempt_days: 14,
        conversation_summary_days: 90,
        artifact_days: 7,
      },
    )
    .await
    .expect("cleanup retained data");

  assert_eq!(cleanup.slack_source_events, 1);
  assert_eq!(cleanup.channel_event_queue, 2);
  assert_eq!(cleanup.slack_delivery_queue, 2);
  assert_eq!(cleanup.slack_delivery_receipts, 1);
  assert_eq!(cleanup.slack_processing_indicators, 1);
  assert_eq!(cleanup.context_fetch_attempts, 1);
  assert_eq!(cleanup.channel_conversation_summaries, 1);
  assert_eq!(cleanup.total_rows(), 9);

  for (table, key_column, removed_key) in [
    ("slack_source_events", "dedupe_key", "old-terminal-source"),
    ("channel_event_queue", "dedupe_key", "old-failed-event"),
    (
      "slack_delivery_queue",
      "request_dedupe_key",
      "old-delivered",
    ),
    (
      "slack_delivery_receipts",
      "request_dedupe_key",
      "old-delivered",
    ),
    (
      "slack_processing_indicators",
      "event_dedupe_key",
      "old-completed-indicator",
    ),
    (
      "context_fetch_attempts",
      "dedupe_key",
      "old-context-attempt",
    ),
    ("channel_conversation_summaries", "summary", "old summary"),
  ] {
    let count: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
      "select count(*) from {table} where workspace_id = ?1 and {key_column} = ?2"
    )))
    .bind("workspace-1")
    .bind(removed_key)
    .fetch_one(&pool)
    .await
    .expect("count removed row");
    assert_eq!(count, 0, "{table}.{removed_key} was retained");
  }

  for (table, key_column, retained_key) in [
    ("slack_source_events", "dedupe_key", "old-active-source"),
    ("slack_source_events", "dedupe_key", "recent-source"),
    (
      "slack_source_events",
      "dedupe_key",
      "other-workspace-source",
    ),
    ("channel_event_queue", "dedupe_key", "old-active-source"),
    (
      "channel_event_queue",
      "dedupe_key",
      "recent-processed-event",
    ),
    ("channel_event_queue", "dedupe_key", "other-workspace-event"),
    (
      "slack_delivery_queue",
      "request_dedupe_key",
      "old-pending-delivery",
    ),
    (
      "slack_delivery_queue",
      "request_dedupe_key",
      "recent-delivered",
    ),
    (
      "slack_delivery_queue",
      "request_dedupe_key",
      "other-workspace-delivery",
    ),
    (
      "slack_delivery_receipts",
      "request_dedupe_key",
      "recent-delivered",
    ),
    (
      "slack_delivery_receipts",
      "request_dedupe_key",
      "other-workspace-delivery",
    ),
    (
      "slack_processing_indicators",
      "event_dedupe_key",
      "old-started-indicator",
    ),
    (
      "slack_processing_indicators",
      "event_dedupe_key",
      "recent-completed-indicator",
    ),
    (
      "slack_processing_indicators",
      "event_dedupe_key",
      "other-workspace-indicator",
    ),
    (
      "context_fetch_attempts",
      "dedupe_key",
      "recent-context-attempt",
    ),
    (
      "context_fetch_attempts",
      "dedupe_key",
      "other-workspace-context-attempt",
    ),
    (
      "channel_conversation_summaries",
      "summary",
      "recent summary",
    ),
    (
      "channel_conversation_summaries",
      "summary",
      "other workspace summary",
    ),
  ] {
    let count: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
      "select count(*) from {table} where {key_column} = ?1"
    )))
    .bind(retained_key)
    .fetch_one(&pool)
    .await
    .expect("count retained row");
    assert_eq!(count, 1, "{table}.{retained_key} was removed");
  }
}

#[tokio::test]
async fn test_cleanup_retained_data_disabled_is_noop() {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state");
  let store = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize state store");
  let pool = SqlitePool::connect(&default_database_url(&state_dir))
    .await
    .expect("connect migrated database");
  sqlx::query(
    "insert into channel_event_queue (provider, workspace_id, dedupe_key, event_kind, payload_json, status, updated_at) values ('slack', 'workspace-1', 'old-processed-event', 'MentionReceived', '{}', 'processed', '2026-05-01 00:00:00')",
  )
  .execute(&pool)
  .await
  .expect("insert queue event");

  let cleanup = store
    .cleanup_retained_data(
      None,
      1_783_987_200,
      &RetentionPolicy {
        enabled: false,
        ..RetentionPolicy::default()
      },
    )
    .await
    .expect("cleanup retained data");

  assert_eq!(cleanup.total_rows(), 0);
  assert_eq!(
    store
      .channel_event_queue_count()
      .await
      .expect("channel event count"),
    1
  );
}

#[tokio::test]
async fn test_slack_processing_indicator_lifecycle() {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state");
  let store = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize state store");

  let created = store
    .create_slack_processing_indicator("workspace-1", "event-1", "C1", Some("100.0"), "200.0")
    .await
    .expect("create indicator");
  let repeated = store
    .create_slack_processing_indicator("workspace-1", "event-1", "C1", Some("100.0"), "200.0")
    .await
    .expect("repeat indicator");

  assert!(created);
  assert!(!repeated);

  let started = store
    .slack_processing_indicator("workspace-1", "event-1")
    .await
    .expect("find indicator")
    .expect("indicator exists");
  assert_eq!(started.workspace_id, "workspace-1");
  assert_eq!(started.event_dedupe_key, "event-1");
  assert_eq!(started.channel_id, "C1");
  assert_eq!(started.thread_ts.as_deref(), Some("100.0"));
  assert_eq!(started.message_ts, "200.0");
  assert_eq!(started.status, SlackProcessingIndicatorStatusKind::Started);
  assert_eq!(started.error, None);
  assert_eq!(started.completed_at, None);

  store
    .complete_slack_processing_indicator("workspace-1", "event-1")
    .await
    .expect("complete indicator");
  let completed = store
    .slack_processing_indicator("workspace-1", "event-1")
    .await
    .expect("find completed indicator")
    .expect("indicator exists");
  assert_eq!(
    completed.status,
    SlackProcessingIndicatorStatusKind::Completed
  );
  assert_eq!(completed.error, None);
  assert!(completed.completed_at.is_some());

  store
    .create_slack_processing_indicator("workspace-1", "event-2", "C1", None, "201.0")
    .await
    .expect("create second indicator");
  store
    .fail_slack_processing_indicator("workspace-1", "event-2", "agent failed")
    .await
    .expect("fail indicator");
  let failed = store
    .slack_processing_indicator("workspace-1", "event-2")
    .await
    .expect("find failed indicator")
    .expect("indicator exists");
  assert_eq!(failed.status, SlackProcessingIndicatorStatusKind::Failed);
  assert_eq!(failed.error.as_deref(), Some("agent failed"));
  assert!(failed.completed_at.is_some());
}

#[tokio::test]
async fn test_claim_stop_stream_slack_delivery_operation() {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state");
  let store = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize state store");
  let request = SlackStopStreamDeliveryRequest {
    connector_id: "connector-1".to_owned(),
    workspace_id: "workspace-1".to_owned(),
    request_dedupe_key: "stop-stream-1".to_owned(),
    channel_id: "C1".to_owned(),
    thread_ts: Some("100.0".to_owned()),
    message_ts: "200.0".to_owned(),
    text: "final answer".to_owned(),
    sender: SlackDeliverySender::Bot,
  };

  assert!(
    store
      .enqueue_slack_stop_stream_delivery(&request, 100)
      .await
      .expect("enqueue stop stream")
  );
  assert!(
    !store
      .enqueue_slack_stop_stream_delivery(&request, 100)
      .await
      .expect("enqueue duplicate stop stream")
  );

  let claimed = store
    .claim_slack_delivery_operation("workspace-1", "stop-stream-1", 100)
    .await
    .expect("claim stop stream");

  let SlackDeliveryOperationClaim::StopStream(claimed) = claimed else {
    panic!("expected stop_stream claim");
  };
  assert_eq!(claimed.connector_id, "connector-1");
  assert_eq!(claimed.workspace_id, "workspace-1");
  assert_eq!(claimed.request_dedupe_key, "stop-stream-1");
  assert_eq!(claimed.channel_id, "C1");
  assert_eq!(claimed.thread_ts.as_deref(), Some("100.0"));
  assert_eq!(claimed.message_ts, "200.0");
  assert_eq!(claimed.text, "final answer");
  assert_eq!(claimed.sender, SlackDeliverySender::Bot);

  let pool = SqlitePool::connect(&default_database_url(&state_dir))
    .await
    .expect("connect migrated database");
  let persisted: (String, String, String) = sqlx::query_as(
    "select operation, message_ts, status from slack_delivery_queue where workspace_id = ?1 and request_dedupe_key = ?2",
  )
  .bind("workspace-1")
  .bind("stop-stream-1")
  .fetch_one(&pool)
  .await
  .expect("read stop stream queue row");

  assert_eq!(persisted.0, "stop_stream");
  assert_eq!(persisted.1, "200.0");
  assert_eq!(persisted.2, "processing");
}

#[tokio::test]
async fn test_complete_slack_delivery_repeats_converge_without_rewinding_throttle() {
  let temp = tempdir().expect("tempdir");
  let state_dir = temp.path().join("state");
  let store = StateStore::initialize(&state_dir, None)
    .await
    .expect("state store");
  let request = SlackDeliveryRequest {
    connector_id: "connector-1".to_owned(),
    workspace_id: "workspace-1".to_owned(),
    request_dedupe_key: "completion-repeat-1".to_owned(),
    channel_id: "C1".to_owned(),
    thread_ts: Some("100.0".to_owned()),
    text: "hello".to_owned(),
    sender: SlackDeliverySender::Bot,
  };
  store
    .enqueue_slack_delivery(&request, 100)
    .await
    .expect("enqueue delivery");
  let receipt = SlackDeliveryReceipt {
    connector_id: request.connector_id.clone(),
    workspace_id: request.workspace_id.clone(),
    channel_id: request.channel_id.clone(),
    thread_ts: request.thread_ts.clone(),
    message_ts: "200.0".to_owned(),
    request_dedupe_key: request.request_dedupe_key.clone(),
    sender: request.sender.clone(),
  };

  store
    .complete_slack_delivery(&receipt, r#"{"ok":true}"#, 200)
    .await
    .expect("first completion");
  store
    .complete_slack_delivery(&receipt, r#"{"ok":true}"#, 150)
    .await
    .expect("repeated completion");

  assert_eq!(
    store
      .slack_delivery_status("workspace-1", "completion-repeat-1", 100)
      .await
      .expect("delivery status")
      .expect("delivery")
      .status,
    SlackDeliveryStatusKind::Delivered
  );
  let pool = SqlitePool::connect(&default_database_url(&state_dir))
    .await
    .expect("connect migrated database");
  let receipt_count: i64 = sqlx::query_scalar(
    "select count(*) from slack_delivery_receipts where workspace_id = ?1 and request_dedupe_key = ?2",
  )
  .bind("workspace-1")
  .bind("completion-repeat-1")
  .fetch_one(&pool)
  .await
  .expect("count receipts");
  let next_available_at: i64 = sqlx::query_scalar(
    "select next_available_at from slack_channel_throttles where workspace_id = ?1 and channel_id = ?2",
  )
  .bind("workspace-1")
  .bind("C1")
  .fetch_one(&pool)
  .await
  .expect("read channel throttle");

  assert_eq!(receipt_count, 1);
  assert_eq!(next_available_at, 200);
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn test_slack_delivery_status_distinguishes_pending_deferred_and_delivered() {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state");
  let store = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize state store");
  let request = SlackDeliveryRequest {
    connector_id: "connector-1".to_owned(),
    workspace_id: "workspace-1".to_owned(),
    request_dedupe_key: "message-1".to_owned(),
    channel_id: "C1".to_owned(),
    thread_ts: Some("100.0".to_owned()),
    text: "hello".to_owned(),
    sender: SlackDeliverySender::Bot,
  };
  store
    .enqueue_slack_delivery(&request, 100)
    .await
    .expect("enqueue delivery");

  let pending = store
    .slack_delivery_status("workspace-1", "message-1", 100)
    .await
    .expect("pending status");
  let pending = pending.expect("pending delivery exists");
  assert_eq!(pending.connector_id, "connector-1");
  assert_eq!(pending.workspace_id, "workspace-1");
  assert_eq!(pending.channel_id, "C1");
  assert_eq!(pending.thread_ts.as_deref(), Some("100.0"));
  assert_eq!(pending.message_ts, None);
  assert_eq!(pending.request_dedupe_key, "message-1");
  assert_eq!(pending.status, SlackDeliveryStatusKind::Pending);
  assert_eq!(pending.available_at, Some(100));
  assert_eq!(pending.attempt_count, Some(0));
  assert_eq!(pending.sender_kind, "bot");
  assert_eq!(pending.sender_key, None);

  store
    .retry_slack_delivery("workspace-1", "message-1", 200)
    .await
    .expect("defer delivery");
  let deferred = store
    .slack_delivery_status("workspace-1", "message-1", 150)
    .await
    .expect("deferred status");
  let deferred = deferred.expect("deferred delivery exists");
  assert_eq!(deferred.status, SlackDeliveryStatusKind::Deferred);
  assert_eq!(deferred.available_at, Some(200));
  assert_eq!(deferred.attempt_count, Some(0));

  let failed_request = SlackDeliveryRequest {
    request_dedupe_key: "message-failed".to_owned(),
    ..request.clone()
  };
  store
    .enqueue_slack_delivery(&failed_request, 100)
    .await
    .expect("enqueue failed delivery");
  let pool = SqlitePool::connect(&default_database_url(&state_dir))
    .await
    .expect("connect migrated database");
  sqlx::query(
    "update slack_delivery_queue set status = 'failed' where workspace_id = ?1 and request_dedupe_key = ?2",
  )
  .bind("workspace-1")
  .bind("message-failed")
  .execute(&pool)
  .await
  .expect("mark delivery failed");
  let failed = store
    .slack_delivery_status("workspace-1", "message-failed", 100)
    .await
    .expect("failed status")
    .expect("failed delivery exists");
  assert_eq!(failed.status, SlackDeliveryStatusKind::Failed);
  assert_eq!(failed.available_at, Some(100));
  assert_eq!(failed.attempt_count, Some(0));

  let claimed = store
    .claim_slack_delivery("workspace-1", "message-1", 200)
    .await
    .expect("claim delivery");
  assert!(matches!(
    claimed,
    codeoff_state::SlackDeliveryClaim::Ready(_)
  ));
  let processing = store
    .slack_delivery_status("workspace-1", "message-1", 200)
    .await
    .expect("processing status")
    .expect("processing delivery exists");
  assert_eq!(processing.status, SlackDeliveryStatusKind::Processing);
  assert_eq!(processing.available_at, Some(200));
  assert_eq!(processing.attempt_count, Some(1));

  store
    .complete_slack_delivery(
      &SlackDeliveryReceipt {
        connector_id: request.connector_id.clone(),
        workspace_id: request.workspace_id.clone(),
        channel_id: request.channel_id.clone(),
        thread_ts: request.thread_ts.clone(),
        message_ts: "200.0".to_owned(),
        request_dedupe_key: request.request_dedupe_key.clone(),
        sender: request.sender.clone(),
      },
      r#"{"ok":true}"#,
      201,
    )
    .await
    .expect("complete delivery");
  let delivered = store
    .slack_delivery_status("workspace-1", "message-1", 150)
    .await
    .expect("delivered status");
  let delivered = delivered.expect("delivered delivery exists");
  assert_eq!(delivered.connector_id, "connector-1");
  assert_eq!(delivered.workspace_id, "workspace-1");
  assert_eq!(delivered.channel_id, "C1");
  assert_eq!(delivered.thread_ts.as_deref(), Some("100.0"));
  assert_eq!(delivered.message_ts.as_deref(), Some("200.0"));
  assert_eq!(delivered.request_dedupe_key, "message-1");
  assert_eq!(delivered.status, SlackDeliveryStatusKind::Delivered);
  assert_eq!(delivered.available_at, None);
  assert_eq!(delivered.attempt_count, None);
  assert_eq!(delivered.sender_kind, "bot");
  assert_eq!(delivered.sender_key, None);

  let missing = store
    .slack_delivery_status("workspace-1", "missing", 150)
    .await
    .expect("missing status");
  assert_eq!(missing, None);
}

#[tokio::test]
async fn test_claim_next_due_slack_delivery_respects_available_at_and_channel_throttle() {
  let temp = tempdir().expect("create tempdir");
  let state_dir = temp.path().join("state");
  let store = StateStore::initialize(&state_dir, None)
    .await
    .expect("initialize state store");
  let deferred = SlackDeliveryRequest {
    connector_id: "connector-1".to_owned(),
    workspace_id: "workspace-1".to_owned(),
    request_dedupe_key: "message-deferred".to_owned(),
    channel_id: "C1".to_owned(),
    thread_ts: Some("100.0".to_owned()),
    text: "not yet".to_owned(),
    sender: SlackDeliverySender::Bot,
  };
  let throttled = SlackDeliveryRequest {
    request_dedupe_key: "message-throttled".to_owned(),
    channel_id: "C2".to_owned(),
    text: "channel waits".to_owned(),
    ..deferred.clone()
  };
  let ready = SlackDeliveryRequest {
    request_dedupe_key: "message-ready".to_owned(),
    channel_id: "C3".to_owned(),
    text: "send now".to_owned(),
    ..deferred.clone()
  };
  store
    .enqueue_slack_delivery(&deferred, 200)
    .await
    .expect("enqueue deferred delivery");
  store
    .enqueue_slack_delivery(&throttled, 100)
    .await
    .expect("enqueue throttled delivery");
  store
    .complete_slack_delivery(
      &SlackDeliveryReceipt {
        connector_id: "connector-1".to_owned(),
        workspace_id: "workspace-1".to_owned(),
        channel_id: "C2".to_owned(),
        thread_ts: None,
        message_ts: "199.0".to_owned(),
        request_dedupe_key: "already-delivered".to_owned(),
        sender: SlackDeliverySender::Bot,
      },
      r#"{"ok":true}"#,
      210,
    )
    .await
    .expect("set channel throttle");
  store
    .enqueue_slack_delivery(&ready, 100)
    .await
    .expect("enqueue ready delivery");

  let claimed = store
    .claim_next_due_slack_delivery(150)
    .await
    .expect("claim next due delivery");

  let SlackDeliveryClaim::Ready(claimed) = claimed.expect("due delivery") else {
    panic!("expected ready delivery");
  };
  assert_eq!(claimed.request_dedupe_key, "message-ready");
  assert_eq!(claimed.channel_id, "C3");
  assert_eq!(
    store
      .slack_delivery_status("workspace-1", "message-ready", 150)
      .await
      .expect("status")
      .expect("delivery")
      .status,
    SlackDeliveryStatusKind::Processing
  );
  assert_eq!(
    store
      .claim_next_due_slack_delivery(150)
      .await
      .expect("second claim"),
    None
  );
}

#[tokio::test]
async fn test_invalid_slack_delivery_sender_is_not_downgraded_to_bot() {
  let temp = tempdir().expect("tempdir");
  let state_dir = temp.path().join("state");
  let store = StateStore::initialize(&state_dir, None)
    .await
    .expect("state store");
  let request = SlackDeliveryRequest {
    connector_id: "slack-default".to_owned(),
    workspace_id: "workspace-1".to_owned(),
    request_dedupe_key: "invalid-sender-1".to_owned(),
    channel_id: "C1".to_owned(),
    thread_ts: None,
    text: "hello".to_owned(),
    sender: SlackDeliverySender::Bot,
  };
  store
    .enqueue_slack_delivery(&request, 100)
    .await
    .expect("enqueue delivery");
  let pool = SqlitePool::connect(&default_database_url(&state_dir))
    .await
    .expect("connect migrated database");
  let error = sqlx::query(
    "update slack_delivery_queue set sender_kind = 'user', sender_key = null where request_dedupe_key = ?1",
  )
  .bind(&request.request_dedupe_key)
  .execute(&pool)
  .await
  .expect_err("invalid sender should violate constraint");

  assert!(error.to_string().contains("CHECK constraint failed"));
  let claim = store
    .claim_slack_delivery("workspace-1", "invalid-sender-1", 100)
    .await
    .expect("valid original sender can still claim");

  assert!(
    matches!(claim, SlackDeliveryClaim::Ready(delivery) if delivery.sender == SlackDeliverySender::Bot)
  );
}
