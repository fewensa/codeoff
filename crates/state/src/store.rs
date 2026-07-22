use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;
#[cfg(feature = "test-support")]
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
#[cfg(feature = "test-support")]
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::time::Instant;

use codeoff_channel_contract::ChannelEvent;
use serde_json::Value;
use sqlx::migrate::Migrator;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
#[cfg(any(test, feature = "test-support"))]
use sqlx::{Connection, SqliteConnection};
use sqlx::{Sqlite, SqlitePool, Transaction};

use crate::StateError;

static MIGRATOR: Migrator = sqlx::migrate!("./migrations");
const DELETE_RETAINED_SLACK_SOURCE_EVENTS: &str = r"
delete from slack_source_events
where received_at < datetime(?1, 'unixepoch', ?2)
  and (?3 is null or workspace_id = ?3)
  and not exists (
    select 1
    from channel_event_queue queue
    where queue.workspace_id = slack_source_events.workspace_id
      and queue.dedupe_key = slack_source_events.dedupe_key
      and queue.status in ('pending', 'processing')
  )
";
const DELETE_RETAINED_CHANNEL_EVENT_QUEUE: &str = r"
delete from channel_event_queue
where updated_at < datetime(?1, 'unixepoch', ?2)
  and status in ('processed', 'failed')
  and (?3 is null or workspace_id = ?3)
";
const DELETE_RETAINED_SLACK_DELIVERY_RECEIPTS: &str = r"
delete from slack_delivery_receipts
where created_at < datetime(?1, 'unixepoch', ?2)
  and (?3 is null or workspace_id = ?3)
";
const DELETE_RETAINED_SLACK_DELIVERY_QUEUE: &str = r"
delete from slack_delivery_queue
where updated_at < datetime(?1, 'unixepoch', ?2)
  and status in ('delivered', 'failed')
  and (?3 is null or workspace_id = ?3)
";
const DELETE_RETAINED_SLACK_PROCESSING_INDICATORS: &str = r"
delete from slack_processing_indicators
where coalesce(completed_at, updated_at) < datetime(?1, 'unixepoch', ?2)
  and status in ('completed', 'failed')
  and (?3 is null or workspace_id = ?3)
";
const DELETE_RETAINED_CONTEXT_FETCH_ATTEMPTS: &str = r"
delete from context_fetch_attempts
where created_at < datetime(?1, 'unixepoch', ?2)
  and (?3 is null or workspace_id = ?3)
";
const DELETE_RETAINED_CHANNEL_CONVERSATION_SUMMARIES: &str = r"
delete from channel_conversation_summaries
where updated_at < datetime(?1, 'unixepoch', ?2)
  and (?3 is null or workspace_id = ?3)
";

#[derive(Debug, Clone)]
pub struct StateStore {
  pub(crate) pool: SqlitePool,
  #[cfg(any(test, feature = "test-support"))]
  test_connect_options: SqliteConnectOptions,
  #[cfg(feature = "test-support")]
  test_hooks: Arc<StateStoreTestHooks>,
}

#[cfg(feature = "test-support")]
#[derive(Default)]
struct StateStoreTestHooks {
  retention_after_scan: Mutex<Option<Box<dyn FnOnce() + Send>>>,
  executor_before_commit: Mutex<Option<Box<dyn FnOnce() + Send>>>,
  executor_after_commit: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

#[cfg(feature = "test-support")]
impl std::fmt::Debug for StateStoreTestHooks {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter.debug_struct("StateStoreTestHooks").finish()
  }
}

#[cfg(any(test, feature = "test-support"))]
pub struct StateStoreTestLock {
  connection: SqliteConnection,
}

#[cfg(feature = "test-support")]
#[derive(Debug)]
enum StateStoreTestFaultReset {
  QueryOnly,
  MaxPageCount(i64),
  Interrupt,
}

/// Restores a connection-local `SQLite` fault installed by scheduler tests.
#[cfg(feature = "test-support")]
#[derive(Debug)]
#[must_use = "the fault remains active until the guard is reset or the store is dropped"]
pub struct StateStoreTestFaultGuard {
  pool: SqlitePool,
  reset: Option<StateStoreTestFaultReset>,
  writes_observed: Option<Arc<AtomicUsize>>,
}

#[cfg(feature = "test-support")]
impl StateStoreTestFaultGuard {
  /// Returns the number of row-write callbacks observed by an interrupt fault.
  #[must_use]
  pub fn writes_observed(&self) -> usize {
    self
      .writes_observed
      .as_ref()
      .map_or(0, |writes| writes.load(Ordering::SeqCst))
  }

  /// Removes the installed fault before the connection is reused.
  ///
  /// # Errors
  ///
  /// Returns an error when the pooled connection cannot be restored.
  pub async fn reset(mut self) -> Result<(), StateError> {
    let reset = self.reset.take().expect("test fault reset is present");
    reset_test_fault(&self.pool, reset).await
  }
}

#[cfg(feature = "test-support")]
async fn reset_test_fault(
  pool: &SqlitePool,
  reset: StateStoreTestFaultReset,
) -> Result<(), StateError> {
  match reset {
    StateStoreTestFaultReset::QueryOnly => {
      sqlx::query("pragma query_only = off")
        .execute(pool)
        .await
        .map_err(|source| StateError::Scheduler { source })?;
    }
    StateStoreTestFaultReset::MaxPageCount(previous) => {
      sqlx::query(sqlx::AssertSqlSafe(format!(
        "pragma max_page_count = {previous}"
      )))
      .execute(pool)
      .await
      .map_err(|source| StateError::Scheduler { source })?;
    }
    StateStoreTestFaultReset::Interrupt => {
      let mut connection = pool
        .acquire()
        .await
        .map_err(|source| StateError::Scheduler { source })?;
      let mut handle = connection
        .lock_handle()
        .await
        .map_err(|source| StateError::Scheduler { source })?;
      handle.remove_progress_handler();
      handle.remove_update_hook();
    }
  }
  Ok(())
}

#[cfg(any(test, feature = "test-support"))]
impl StateStoreTestLock {
  /// Releases a test-only exclusive `SQLite` lock.
  ///
  /// # Errors
  ///
  /// Returns an error when `SQLite` cannot commit the transaction.
  pub async fn release(mut self) -> Result<(), StateError> {
    sqlx::query("commit")
      .execute(&mut self.connection)
      .await
      .map(|_| ())
      .map_err(|source| StateError::SlackDelivery { source })
  }
}

#[derive(Debug, Clone)]
pub struct SlackSourceEvent {
  pub workspace_id: String,
  pub event_kind: String,
  pub dedupe_key: String,
  pub envelope_id: Option<String>,
  pub event_id: Option<String>,
  pub channel_id: Option<String>,
  pub thread_ts: Option<String>,
  pub message_ts: Option<String>,
  pub user_id: Option<String>,
  pub raw_payload_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimedChannelEvent {
  pub id: i64,
  pub attempt_count: i64,
  pub event: ChannelEvent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelEventStatusKind {
  Pending,
  Processing,
  Processed,
  Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelEventStatus {
  pub status: ChannelEventStatusKind,
  pub attempt_count: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlackSourceReferences {
  pub found: bool,
  pub event_kind: Option<String>,
  pub channel_id: Option<String>,
  pub thread_id: Option<String>,
  pub message_ts: Option<String>,
  pub user_id: Option<String>,
  pub text_preview: Option<String>,
  pub links: Vec<SlackSourceLink>,
  pub attachments: Vec<SlackSourceAttachment>,
  pub files: Vec<SlackSourceFile>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlackSourceLink {
  pub url: String,
  pub text: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlackSourceAttachment {
  pub title: Option<String>,
  pub text: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlackSourceFile {
  pub resource_id: Option<String>,
  pub name: Option<String>,
  pub title: Option<String>,
  pub media_type: Option<String>,
  pub size_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelConversationKey {
  pub provider: String,
  pub workspace_id: String,
  pub conversation_kind: String,
  pub channel_id: Option<String>,
  pub thread_id: Option<String>,
  pub user_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelConversationSummary {
  pub summary: String,
  pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentDraft {
  pub provider: String,
  pub channel_id: Option<String>,
  pub thread_id: Option<String>,
  pub message_ts: Option<String>,
  pub user_id: Option<String>,
  pub event_id: String,
  pub dedupe_key: String,
  pub content: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextFetchAttempt {
  pub provider: String,
  pub workspace_id: String,
  pub connector_id: String,
  pub dedupe_key: String,
  pub operation: String,
  pub channel_id: Option<String>,
  pub thread_id: Option<String>,
  pub message_ts: Option<String>,
  pub status: String,
  pub error_kind: Option<String>,
  pub error_message: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetentionPolicy {
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

impl Default for RetentionPolicy {
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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RetentionCleanupReport {
  pub slack_source_events: u64,
  pub channel_event_queue: u64,
  pub slack_delivery_queue: u64,
  pub slack_delivery_receipts: u64,
  pub slack_processing_indicators: u64,
  pub context_fetch_attempts: u64,
  pub channel_conversation_summaries: u64,
  pub scheduled_runs_scanned: u64,
  pub scheduled_runs_deleted: u64,
  pub scheduled_runs_protected: u64,
  pub scheduled_permit_consumptions_deleted: u64,
  pub scheduled_rows_deleted: u64,
  pub scheduled_duration_milliseconds: u64,
}

impl RetentionCleanupReport {
  #[must_use]
  pub const fn total_rows(&self) -> u64 {
    self.slack_source_events
      + self.channel_event_queue
      + self.slack_delivery_queue
      + self.slack_delivery_receipts
      + self.slack_processing_indicators
      + self.context_fetch_attempts
      + self.channel_conversation_summaries
      + self.scheduled_rows_deleted
  }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextFetchAttemptRecord {
  pub operation: String,
  pub provider: String,
  pub workspace_id: String,
  pub connector_id: String,
  pub dedupe_key: String,
  pub channel_id: Option<String>,
  pub thread_id: Option<String>,
  pub message_ts: Option<String>,
  pub status: String,
  pub error_kind: Option<String>,
  pub error_message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlackDeliveryRequest {
  pub connector_id: String,
  pub workspace_id: String,
  pub request_dedupe_key: String,
  pub channel_id: String,
  pub thread_ts: Option<String>,
  pub text: String,
  pub sender: SlackDeliverySender,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlackStopStreamDeliveryRequest {
  pub connector_id: String,
  pub workspace_id: String,
  pub request_dedupe_key: String,
  pub channel_id: String,
  pub thread_ts: Option<String>,
  pub message_ts: String,
  pub text: String,
  pub sender: SlackDeliverySender,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlackDeliveryReceipt {
  pub connector_id: String,
  pub workspace_id: String,
  pub channel_id: String,
  pub thread_ts: Option<String>,
  pub message_ts: String,
  pub request_dedupe_key: String,
  pub sender: SlackDeliverySender,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum SlackDeliverySender {
  #[default]
  Bot,
  User {
    key: String,
  },
}

impl SlackDeliverySender {
  #[must_use]
  pub fn kind(&self) -> &'static str {
    match self {
      Self::Bot => "bot",
      Self::User { .. } => "user",
    }
  }

  #[must_use]
  pub fn key(&self) -> Option<&str> {
    match self {
      Self::Bot => None,
      Self::User { key } => Some(key),
    }
  }

  fn from_parts(kind: String, key: Option<String>) -> Result<Self, StateError> {
    match (kind.as_str(), key) {
      ("bot", _) => Ok(Self::Bot),
      ("user", Some(key)) => Ok(Self::User { key }),
      ("user", None) => Err(StateError::InvalidSlackDeliveryStatus {
        status: "missing user sender key".to_owned(),
      }),
      _ => Err(StateError::InvalidSlackDeliveryStatus { status: kind }),
    }
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlackDeliveryStatusKind {
  Pending,
  Deferred,
  Processing,
  Delivered,
  Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlackDeliveryStatus {
  pub connector_id: String,
  pub workspace_id: String,
  pub channel_id: String,
  pub thread_ts: Option<String>,
  pub message_ts: Option<String>,
  pub request_dedupe_key: String,
  pub status: SlackDeliveryStatusKind,
  pub available_at: Option<u64>,
  pub attempt_count: Option<i64>,
  pub sender_kind: String,
  pub sender_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlackDeliveryClaim {
  Ready(SlackDeliveryRequest),
  Delivered(SlackDeliveryReceipt),
  Deferred { available_at: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlackDeliveryOperationClaim {
  PostMessage(SlackDeliveryRequest),
  StopStream(SlackStopStreamDeliveryRequest),
  Delivered(SlackDeliveryReceipt),
  Deferred { available_at: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlackProcessingIndicatorStatusKind {
  Started,
  Completed,
  Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlackProcessingIndicator {
  pub workspace_id: String,
  pub event_dedupe_key: String,
  pub channel_id: String,
  pub thread_ts: Option<String>,
  pub message_ts: String,
  pub status: SlackProcessingIndicatorStatusKind,
  pub error: Option<String>,
  pub created_at: String,
  pub updated_at: String,
  pub completed_at: Option<String>,
}

impl StateStore {
  /// Initializes the state directory, opens `SQLite`, and applies embedded migrations.
  ///
  /// # Errors
  ///
  /// Returns an error when the state directory is not writable, the database cannot be opened,
  /// or migrations fail.
  pub async fn initialize(
    state_dir: &Path,
    database_url: Option<&str>,
  ) -> Result<Self, StateError> {
    prepare_state_dir(state_dir)?;

    let options = connect_options(state_dir, database_url)?;
    prepare_database_dir(&options)?;

    #[cfg(any(test, feature = "test-support"))]
    let test_connect_options = options.clone();
    let pool = SqlitePoolOptions::new()
      .max_connections(1)
      .connect_with(options)
      .await
      .map_err(|_| StateError::Connect)?;

    MIGRATOR
      .run(&pool)
      .await
      .map_err(|source| StateError::Migrate { source })?;

    Ok(Self {
      pool,
      #[cfg(any(test, feature = "test-support"))]
      test_connect_options,
      #[cfg(feature = "test-support")]
      test_hooks: Arc::new(StateStoreTestHooks::default()),
    })
  }

  /// Confirms that the current `SQLite` connection can execute a minimal read.
  ///
  /// # Errors
  ///
  /// Returns an error when `SQLite` cannot execute the readiness probe.
  pub async fn check_readable(&self) -> Result<(), StateError> {
    sqlx::query_scalar::<_, i64>("select 1")
      .fetch_one(&self.pool)
      .await
      .map(|_| ())
      .map_err(|source| StateError::Readiness { source })
  }

  /// Claims an idempotency key.
  ///
  /// Returns `true` when the key was inserted and `false` when it already existed.
  ///
  /// # Errors
  ///
  /// Returns an error when `SQLite` rejects the insert.
  pub async fn claim_idempotency_key(&self, scope: &str, key: &str) -> Result<bool, StateError> {
    let result = sqlx::query(
      r"
insert into idempotency_keys (scope, key, status, created_at, updated_at)
values (?1, ?2, 'claimed', datetime('now'), datetime('now'))
on conflict(scope, key) do nothing
",
    )
    .bind(scope)
    .bind(key)
    .execute(&self.pool)
    .await
    .map_err(|source| StateError::ClaimIdempotencyKey { source })?;

    Ok(result.rows_affected() == 1)
  }

  /// Persists a raw Slack source event and its normalized queue item atomically.
  ///
  /// Returns `true` only for the first delivery of the source event.
  ///
  /// # Errors
  ///
  /// Returns an error when the normalized event cannot be serialized or `SQLite` rejects the
  /// transaction.
  pub async fn persist_slack_source_event(
    &self,
    source: &SlackSourceEvent,
    event: &ChannelEvent,
  ) -> Result<bool, StateError> {
    let payload_json = serde_json::to_string(event)
      .map_err(|source| StateError::SerializeChannelEvent { source })?;
    let mut transaction = self
      .pool
      .begin()
      .await
      .map_err(|source| StateError::PersistSlackSourceEvent { source })?;
    let inserted = sqlx::query(
      r"insert into slack_source_events (workspace_id, event_kind, dedupe_key, envelope_id, event_id, channel_id, thread_ts, message_ts, user_id, raw_payload_json, status)
        values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 'queued')
        on conflict(workspace_id, dedupe_key) do nothing",
    )
    .bind(&source.workspace_id)
    .bind(&source.event_kind)
    .bind(&source.dedupe_key)
    .bind(&source.envelope_id)
    .bind(&source.event_id)
    .bind(&source.channel_id)
    .bind(&source.thread_ts)
    .bind(&source.message_ts)
    .bind(&source.user_id)
    .bind(&source.raw_payload_json)
    .execute(&mut *transaction)
    .await
    .map_err(|source| StateError::PersistSlackSourceEvent { source })?
    .rows_affected() == 1;

    if inserted {
      sqlx::query(
        r"insert into channel_event_queue (provider, workspace_id, dedupe_key, event_kind, payload_json)
          values (?1, ?2, ?3, ?4, ?5)
          on conflict(provider, workspace_id, dedupe_key) do nothing",
      )
      .bind(&event.provider)
      .bind(&event.workspace_id)
      .bind(&event.dedupe_key)
      .bind(format!("{:?}", event.kind))
      .bind(payload_json)
      .execute(&mut *transaction)
      .await
      .map_err(|source| StateError::PersistSlackSourceEvent { source })?;
    }
    transaction
      .commit()
      .await
      .map_err(|source| StateError::PersistSlackSourceEvent { source })?;
    Ok(inserted)
  }

  /// Counts pending and processed normalized channel event rows.
  ///
  /// # Errors
  ///
  /// Returns an error when `SQLite` cannot read the queue table.
  pub async fn channel_event_queue_count(&self) -> Result<i64, StateError> {
    sqlx::query_scalar("select count(*) from channel_event_queue")
      .fetch_one(&self.pool)
      .await
      .map_err(|source| StateError::QueryChannelEventState { source })
  }

  /// Atomically claims the next due normalized channel event for processing.
  ///
  /// A claimed event is moved from `pending` to `processing` and has its attempt count incremented.
  /// A second worker cannot claim the same row while it is processing.
  ///
  /// # Errors
  ///
  /// Returns an error when `SQLite` cannot claim the row or its normalized payload is invalid.
  pub async fn claim_next_channel_event(&self) -> Result<Option<ClaimedChannelEvent>, StateError> {
    let row = sqlx::query_as::<_, ChannelEventQueueRow>(
      r"
update channel_event_queue
set status = 'processing', attempt_count = attempt_count + 1, updated_at = datetime('now')
where id = (
  select id from channel_event_queue
  where status = 'pending' and available_at <= datetime('now')
  order by available_at, id
  limit 1
)
and status = 'pending'
returning id, attempt_count, payload_json
",
    )
    .fetch_optional(&self.pool)
    .await
    .map_err(|source| StateError::ChannelEventQueue { source })?;

    row.map(TryInto::try_into).transpose()
  }

  /// Marks a claimed channel event as processed.
  ///
  /// # Errors
  ///
  /// Returns an error when `SQLite` cannot update the claimed row.
  pub async fn complete_channel_event(&self, id: i64) -> Result<(), StateError> {
    sqlx::query(
      "update channel_event_queue set status = 'processed', updated_at = datetime('now') where id = ?1 and status = 'processing'",
    )
    .bind(id)
    .execute(&self.pool)
    .await
    .map_err(|source| StateError::ChannelEventQueue { source })?;
    Ok(())
  }

  /// Moves a claimed channel event back to pending without counting the lock deferral as an attempt.
  ///
  /// # Errors
  ///
  /// Returns an error when `SQLite` cannot update the claimed row.
  pub async fn release_channel_event(&self, id: i64, delay: Duration) -> Result<(), StateError> {
    let delay_seconds = format!("+{} seconds", delay.as_secs().max(1));
    sqlx::query(
      r"
update channel_event_queue
set status = 'pending',
    attempt_count = max(attempt_count - 1, 0),
    available_at = datetime('now', ?2),
    updated_at = datetime('now')
where id = ?1 and status = 'processing'
",
    )
    .bind(id)
    .bind(delay_seconds)
    .execute(&self.pool)
    .await
    .map_err(|source| StateError::ChannelEventQueue { source })?;
    Ok(())
  }

  /// Marks a claimed channel event as failed while retaining it for inspection or later recovery.
  ///
  /// # Errors
  ///
  /// Returns an error when `SQLite` cannot update the claimed row.
  pub async fn fail_channel_event(&self, id: i64, error: &str) -> Result<(), StateError> {
    sqlx::query(
      "update channel_event_queue set status = 'failed', last_error = ?2, updated_at = datetime('now') where id = ?1 and status = 'processing'",
    )
    .bind(id)
    .bind(error)
    .execute(&self.pool)
    .await
    .map_err(|source| StateError::ChannelEventQueue { source })?;
    Ok(())
  }

  /// Returns the durable status for a queued channel event, when present.
  ///
  /// # Errors
  ///
  /// Returns an error when `SQLite` cannot read the queue table.
  pub async fn channel_event_status(
    &self,
    provider: &str,
    workspace_id: &str,
    dedupe_key: &str,
  ) -> Result<Option<ChannelEventStatus>, StateError> {
    let row = sqlx::query_as::<_, ChannelEventStatusRow>(
      "select status, attempt_count from channel_event_queue where provider = ?1 and workspace_id = ?2 and dedupe_key = ?3",
    )
    .bind(provider)
    .bind(workspace_id)
    .bind(dedupe_key)
    .fetch_optional(&self.pool)
    .await
    .map_err(|source| StateError::QueryChannelEventState { source })?;
    row.map(TryInto::try_into).transpose()
  }

  /// Returns a queued normalized channel event by its stable provider/workspace/dedupe identity.
  ///
  /// # Errors
  ///
  /// Returns an error when `SQLite` cannot read the queue table or the payload cannot be decoded.
  pub async fn channel_event(
    &self,
    provider: &str,
    workspace_id: &str,
    dedupe_key: &str,
  ) -> Result<Option<ChannelEvent>, StateError> {
    let row = sqlx::query_as::<_, ChannelEventPayloadRow>(
      "select payload_json from channel_event_queue where provider = ?1 and workspace_id = ?2 and dedupe_key = ?3",
    )
    .bind(provider)
    .bind(workspace_id)
    .bind(dedupe_key)
    .fetch_optional(&self.pool)
    .await
    .map_err(|source| StateError::QueryChannelEventState { source })?;

    row.map(TryInto::try_into).transpose()
  }

  /// Loads Slack-specific source references for a normalized queue event.
  ///
  /// # Errors
  ///
  /// Returns an error when `SQLite` cannot read the source event table.
  pub async fn slack_source_references(
    &self,
    workspace_id: &str,
    dedupe_key: &str,
  ) -> Result<SlackSourceReferences, StateError> {
    let row = sqlx::query_as::<_, SlackSourceReferenceRow>(
      "select event_kind, channel_id, thread_ts, message_ts, user_id, raw_payload_json from slack_source_events where workspace_id = ?1 and dedupe_key = ?2",
    )
    .bind(workspace_id)
    .bind(dedupe_key)
    .fetch_optional(&self.pool)
    .await
    .map_err(|source| StateError::QueryChannelEventState { source })?;
    Ok(row.map_or(
      SlackSourceReferences {
        found: false,
        event_kind: None,
        channel_id: None,
        thread_id: None,
        message_ts: None,
        user_id: None,
        text_preview: None,
        links: Vec::new(),
        attachments: Vec::new(),
        files: Vec::new(),
      },
      Into::into,
    ))
  }

  /// Returns the durable Codex thread mapped to a channel conversation.
  ///
  /// # Errors
  ///
  /// Returns an error when `SQLite` cannot read the conversation mapping table.
  pub async fn channel_conversation_thread_id(
    &self,
    key: &ChannelConversationKey,
  ) -> Result<Option<String>, StateError> {
    sqlx::query_scalar::<_, String>(
      r"
select codex_thread_id
from channel_conversations
where provider = ?1
  and workspace_id = ?2
  and conversation_kind = ?3
  and channel_id = ?4
  and thread_id = ?5
  and user_id = ?6
",
    )
    .bind(&key.provider)
    .bind(&key.workspace_id)
    .bind(&key.conversation_kind)
    .bind(normalized_key_part(key.channel_id.as_ref()))
    .bind(normalized_key_part(key.thread_id.as_ref()))
    .bind(normalized_key_part(key.user_id.as_ref()))
    .fetch_optional(&self.pool)
    .await
    .map_err(|source| StateError::ChannelEventQueue { source })
  }

  /// Upserts the durable Codex thread mapped to a channel conversation.
  ///
  /// # Errors
  ///
  /// Returns an error when `SQLite` cannot write the conversation mapping table.
  pub async fn upsert_channel_conversation_thread_id(
    &self,
    key: &ChannelConversationKey,
    codex_thread_id: &str,
  ) -> Result<(), StateError> {
    sqlx::query(
      r"
insert into channel_conversations (
  provider,
  workspace_id,
  conversation_kind,
  channel_id,
  thread_id,
  user_id,
  codex_thread_id,
  created_at,
  updated_at
)
values (?1, ?2, ?3, ?4, ?5, ?6, ?7, datetime('now'), datetime('now'))
on conflict(provider, workspace_id, conversation_kind, channel_id, thread_id, user_id)
do update set codex_thread_id = excluded.codex_thread_id, updated_at = datetime('now')
",
    )
    .bind(&key.provider)
    .bind(&key.workspace_id)
    .bind(&key.conversation_kind)
    .bind(normalized_key_part(key.channel_id.as_ref()))
    .bind(normalized_key_part(key.thread_id.as_ref()))
    .bind(normalized_key_part(key.user_id.as_ref()))
    .bind(codex_thread_id)
    .execute(&self.pool)
    .await
    .map(|_| ())
    .map_err(|source| StateError::ChannelEventQueue { source })
  }

  /// Returns the local rolling summary for a channel conversation.
  ///
  /// # Errors
  ///
  /// Returns an error when `SQLite` cannot read the summary table.
  pub async fn channel_conversation_summary(
    &self,
    key: &ChannelConversationKey,
  ) -> Result<Option<ChannelConversationSummary>, StateError> {
    sqlx::query_as::<_, ChannelConversationSummaryRow>(
      r"
select summary, updated_at
from channel_conversation_summaries
where provider = ?1
  and workspace_id = ?2
  and conversation_kind = ?3
  and channel_id = ?4
  and thread_id = ?5
  and user_id = ?6
",
    )
    .bind(&key.provider)
    .bind(&key.workspace_id)
    .bind(&key.conversation_kind)
    .bind(normalized_key_part(key.channel_id.as_ref()))
    .bind(normalized_key_part(key.thread_id.as_ref()))
    .bind(normalized_key_part(key.user_id.as_ref()))
    .fetch_optional(&self.pool)
    .await
    .map(|row| row.map(Into::into))
    .map_err(|source| StateError::ChannelEventQueue { source })
  }

  /// Upserts the local rolling summary for a channel conversation.
  ///
  /// # Errors
  ///
  /// Returns an error when `SQLite` cannot write the summary table.
  pub async fn upsert_channel_conversation_summary(
    &self,
    key: &ChannelConversationKey,
    summary: &str,
  ) -> Result<(), StateError> {
    sqlx::query(
      r"
insert into channel_conversation_summaries (
  provider,
  workspace_id,
  conversation_kind,
  channel_id,
  thread_id,
  user_id,
  summary,
  created_at,
  updated_at
)
values (?1, ?2, ?3, ?4, ?5, ?6, ?7, datetime('now'), datetime('now'))
on conflict(provider, workspace_id, conversation_kind, channel_id, thread_id, user_id)
do update set summary = excluded.summary, updated_at = datetime('now')
",
    )
    .bind(&key.provider)
    .bind(&key.workspace_id)
    .bind(&key.conversation_kind)
    .bind(normalized_key_part(key.channel_id.as_ref()))
    .bind(normalized_key_part(key.thread_id.as_ref()))
    .bind(normalized_key_part(key.user_id.as_ref()))
    .bind(summary)
    .execute(&self.pool)
    .await
    .map(|_| ())
    .map_err(|source| StateError::ChannelEventQueue { source })
  }

  /// Persists a private agent draft for a claimed event. This never sends a channel message.
  ///
  /// # Errors
  ///
  /// Returns an error when `SQLite` cannot persist the draft.
  pub async fn save_agent_draft(
    &self,
    queue_event_id: i64,
    draft: &AgentDraft,
  ) -> Result<(), StateError> {
    sqlx::query(
      "insert into agent_drafts (channel_event_queue_id, provider, channel_id, thread_id, message_ts, user_id, event_id, dedupe_key, content) values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9) on conflict(channel_event_queue_id) do nothing",
    )
    .bind(queue_event_id).bind(&draft.provider).bind(&draft.channel_id).bind(&draft.thread_id)
    .bind(&draft.message_ts).bind(&draft.user_id).bind(&draft.event_id).bind(&draft.dedupe_key)
    .bind(&draft.content).execute(&self.pool).await
    .map_err(|source| StateError::ChannelEventQueue { source })?;
    Ok(())
  }

  /// Returns the most recently stored private draft for inspection by runtime callers.
  ///
  /// # Errors
  ///
  /// Returns an error when `SQLite` cannot read the draft table.
  pub async fn latest_agent_draft(&self) -> Result<Option<AgentDraft>, StateError> {
    sqlx::query_as::<_, AgentDraftRow>(
      "select provider, channel_id, thread_id, message_ts, user_id, event_id, dedupe_key, content from agent_drafts order by id desc limit 1",
    ).fetch_optional(&self.pool).await.map_err(|source| StateError::QueryChannelEventState { source })
      .map(|row| row.map(Into::into))
  }

  /// Records a failed context fetch attempt so prompt bootstrap failures stay durable.
  ///
  /// # Errors
  ///
  /// Returns an error when `SQLite` cannot persist the attempt.
  pub async fn record_context_fetch_attempt(
    &self,
    attempt: &ContextFetchAttemptRecord,
  ) -> Result<(), StateError> {
    sqlx::query(
      r"insert into context_fetch_attempts (operation, provider, workspace_id, connector_id, dedupe_key, channel_id, thread_id, message_ts, status, error_kind, error_message)
        values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
    )
    .bind(&attempt.operation)
    .bind(&attempt.provider)
    .bind(&attempt.workspace_id)
    .bind(&attempt.connector_id)
    .bind(&attempt.dedupe_key)
    .bind(&attempt.channel_id)
    .bind(&attempt.thread_id)
    .bind(&attempt.message_ts)
    .bind(&attempt.status)
    .bind(&attempt.error_kind)
    .bind(&attempt.error_message)
    .execute(&self.pool)
    .await
    .map_err(|source| StateError::ContextFetchAttempt { source })?;
    Ok(())
  }

  /// Returns the most recent context fetch attempt for a queued event.
  ///
  /// # Errors
  ///
  /// Returns an error when `SQLite` cannot read the attempt table.
  pub async fn latest_context_fetch_attempt(
    &self,
    workspace_id: &str,
    dedupe_key: &str,
  ) -> Result<Option<ContextFetchAttempt>, StateError> {
    sqlx::query_as::<_, ContextFetchAttemptRow>(
      r"select provider, workspace_id, connector_id, dedupe_key, operation, channel_id, thread_id, message_ts, status, error_kind, error_message
        from context_fetch_attempts
        where workspace_id = ?1 and dedupe_key = ?2
        order by id desc
        limit 1",
    )
    .bind(workspace_id)
    .bind(dedupe_key)
    .fetch_optional(&self.pool)
    .await
    .map_err(|source| StateError::ContextFetchAttempt { source })
    .map(|row| row.map(Into::into))
  }

  /// Counts persisted Slack source event rows.
  ///
  /// # Errors
  ///
  /// Returns an error when `SQLite` cannot read the Slack source event table.
  pub async fn slack_source_event_count(&self) -> Result<i64, StateError> {
    sqlx::query_scalar("select count(*) from slack_source_events")
      .fetch_one(&self.pool)
      .await
      .map_err(|source| StateError::QueryChannelEventState { source })
  }

  /// Adds an outbound Slack message to the durable queue.
  ///
  /// Returns `true` when the request was newly queued and `false` for an existing dedupe key.
  ///
  /// # Errors
  ///
  /// Returns an error when `SQLite` cannot persist the queue item.
  pub async fn enqueue_slack_delivery(
    &self,
    request: &SlackDeliveryRequest,
    now_unix_seconds: u64,
  ) -> Result<bool, StateError> {
    let result = sqlx::query(
      r"insert into slack_delivery_queue (connector_id, workspace_id, request_dedupe_key, channel_id, thread_ts, text, available_at, sender_kind, sender_key, operation)
        values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'post_message')
        on conflict(workspace_id, request_dedupe_key) do nothing",
    )
    .bind(&request.connector_id)
    .bind(&request.workspace_id)
    .bind(&request.request_dedupe_key)
    .bind(&request.channel_id)
    .bind(&request.thread_ts)
    .bind(&request.text)
    .bind(i64::try_from(now_unix_seconds).unwrap_or(i64::MAX))
    .bind(request.sender.kind())
    .bind(request.sender.key())
    .execute(&self.pool)
    .await
    .map_err(|source| StateError::SlackDelivery { source })?;
    Ok(result.rows_affected() == 1)
  }

  /// Adds an outbound Slack `chat.stopStream` request to the durable queue.
  ///
  /// Returns `true` when the request was newly queued and `false` for an existing dedupe key.
  ///
  /// # Errors
  ///
  /// Returns an error when `SQLite` cannot persist the queue item.
  pub async fn enqueue_slack_stop_stream_delivery(
    &self,
    request: &SlackStopStreamDeliveryRequest,
    now_unix_seconds: u64,
  ) -> Result<bool, StateError> {
    let result = sqlx::query(
      r"insert into slack_delivery_queue (connector_id, workspace_id, request_dedupe_key, channel_id, thread_ts, message_ts, text, available_at, sender_kind, sender_key, operation)
        values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 'stop_stream')
        on conflict(workspace_id, request_dedupe_key) do nothing",
    )
    .bind(&request.connector_id)
    .bind(&request.workspace_id)
    .bind(&request.request_dedupe_key)
    .bind(&request.channel_id)
    .bind(&request.thread_ts)
    .bind(&request.message_ts)
    .bind(&request.text)
    .bind(i64::try_from(now_unix_seconds).unwrap_or(i64::MAX))
    .bind(request.sender.kind())
    .bind(request.sender.key())
    .execute(&self.pool)
    .await
    .map_err(|source| StateError::SlackDelivery { source })?;
    Ok(result.rows_affected() == 1)
  }

  /// Creates the durable mapping from a Slack source event to its active stream message.
  ///
  /// Returns `true` when the indicator was newly created and `false` for an existing source event.
  ///
  /// # Errors
  ///
  /// Returns an error when `SQLite` cannot persist the indicator.
  pub async fn create_slack_processing_indicator(
    &self,
    workspace_id: &str,
    event_dedupe_key: &str,
    channel_id: &str,
    thread_ts: Option<&str>,
    message_ts: &str,
  ) -> Result<bool, StateError> {
    let result = sqlx::query(
      r"insert into slack_processing_indicators (workspace_id, event_dedupe_key, channel_id, thread_ts, message_ts)
        values (?1, ?2, ?3, ?4, ?5)
        on conflict(workspace_id, event_dedupe_key) do nothing",
    )
    .bind(workspace_id)
    .bind(event_dedupe_key)
    .bind(channel_id)
    .bind(thread_ts)
    .bind(message_ts)
    .execute(&self.pool)
    .await
    .map_err(|source| StateError::SlackDelivery { source })?;
    Ok(result.rows_affected() == 1)
  }

  /// Looks up a Slack processing indicator by source event dedupe key.
  ///
  /// # Errors
  ///
  /// Returns an error when `SQLite` cannot read the indicator.
  pub async fn slack_processing_indicator(
    &self,
    workspace_id: &str,
    event_dedupe_key: &str,
  ) -> Result<Option<SlackProcessingIndicator>, StateError> {
    let row = sqlx::query_as::<_, SlackProcessingIndicatorRow>(
      r"select workspace_id, event_dedupe_key, channel_id, thread_ts, message_ts, status, error, created_at, updated_at, completed_at
        from slack_processing_indicators
        where workspace_id = ?1 and event_dedupe_key = ?2",
    )
    .bind(workspace_id)
    .bind(event_dedupe_key)
    .fetch_optional(&self.pool)
    .await
    .map_err(|source| StateError::SlackDelivery { source })?;
    row.map(TryInto::try_into).transpose()
  }

  /// Marks a Slack processing indicator completed.
  ///
  /// # Errors
  ///
  /// Returns an error when `SQLite` cannot update the indicator.
  pub async fn complete_slack_processing_indicator(
    &self,
    workspace_id: &str,
    event_dedupe_key: &str,
  ) -> Result<(), StateError> {
    sqlx::query(
      r"update slack_processing_indicators
        set status = 'completed', error = null, completed_at = coalesce(completed_at, datetime('now')), updated_at = datetime('now')
        where workspace_id = ?1 and event_dedupe_key = ?2",
    )
    .bind(workspace_id)
    .bind(event_dedupe_key)
    .execute(&self.pool)
    .await
    .map_err(|source| StateError::SlackDelivery { source })?;
    Ok(())
  }

  /// Marks a Slack processing indicator failed with a durable error.
  ///
  /// # Errors
  ///
  /// Returns an error when `SQLite` cannot update the indicator.
  pub async fn fail_slack_processing_indicator(
    &self,
    workspace_id: &str,
    event_dedupe_key: &str,
    error: &str,
  ) -> Result<(), StateError> {
    sqlx::query(
      r"update slack_processing_indicators
        set status = 'failed', error = ?3, completed_at = coalesce(completed_at, datetime('now')), updated_at = datetime('now')
        where workspace_id = ?1 and event_dedupe_key = ?2",
    )
    .bind(workspace_id)
    .bind(event_dedupe_key)
    .bind(error)
    .execute(&self.pool)
    .await
    .map_err(|source| StateError::SlackDelivery { source })?;
    Ok(())
  }

  /// Looks up one outbound Slack delivery status by its stable dedupe key.
  ///
  /// # Errors
  ///
  /// Returns an error when `SQLite` cannot read delivery state.
  pub async fn slack_delivery_status(
    &self,
    workspace_id: &str,
    request_dedupe_key: &str,
    now_unix_seconds: u64,
  ) -> Result<Option<SlackDeliveryStatus>, StateError> {
    if let Some(receipt) = sqlx::query_as::<_, ReceiptRow>(
      "select connector_id, workspace_id, channel_id, thread_ts, message_ts, request_dedupe_key, sender_kind, sender_key from slack_delivery_receipts where workspace_id = ?1 and request_dedupe_key = ?2",
    )
    .bind(workspace_id)
    .bind(request_dedupe_key)
    .fetch_optional(&self.pool)
    .await
    .map_err(|source| StateError::SlackDelivery { source })? {
      let sender = SlackDeliverySender::from_parts(receipt.sender_kind, receipt.sender_key)?;
      return Ok(Some(SlackDeliveryStatus {
        connector_id: receipt.connector_id,
        workspace_id: receipt.workspace_id,
        channel_id: receipt.channel_id,
        thread_ts: receipt.thread_ts,
        message_ts: Some(receipt.message_ts),
        request_dedupe_key: receipt.request_dedupe_key,
        status: SlackDeliveryStatusKind::Delivered,
        available_at: None,
        attempt_count: None,
        sender_kind: sender.kind().to_owned(),
        sender_key: sender.key().map(ToOwned::to_owned),
      }));
    }

    let row = sqlx::query_as::<_, DeliveryStatusRow>(
      "select connector_id, workspace_id, request_dedupe_key, channel_id, thread_ts, message_ts, status, available_at, attempt_count, sender_kind, sender_key from slack_delivery_queue where workspace_id = ?1 and request_dedupe_key = ?2",
    )
    .bind(workspace_id)
    .bind(request_dedupe_key)
    .fetch_optional(&self.pool)
    .await
    .map_err(|source| StateError::SlackDelivery { source })?;
    let Some(row) = row else {
      return Ok(None);
    };

    let channel_available_at: Option<i64> = sqlx::query_scalar(
      "select next_available_at from slack_channel_throttles where workspace_id = ?1 and channel_id = ?2",
    )
    .bind(workspace_id)
    .bind(&row.channel_id)
    .fetch_optional(&self.pool)
    .await
    .map_err(|source| StateError::SlackDelivery { source })?;
    let available_at = row.available_at.max(channel_available_at.unwrap_or(0));
    let now = i64::try_from(now_unix_seconds).unwrap_or(i64::MAX);
    let status = match row.status.as_str() {
      "pending" if available_at > now => SlackDeliveryStatusKind::Deferred,
      "pending" => SlackDeliveryStatusKind::Pending,
      "processing" => SlackDeliveryStatusKind::Processing,
      "failed" => SlackDeliveryStatusKind::Failed,
      "delivered" => SlackDeliveryStatusKind::Delivered,
      _ => {
        return Err(StateError::InvalidSlackDeliveryStatus { status: row.status });
      }
    };

    let sender = SlackDeliverySender::from_parts(row.sender_kind, row.sender_key)?;
    Ok(Some(SlackDeliveryStatus {
      connector_id: row.connector_id,
      workspace_id: row.workspace_id,
      channel_id: row.channel_id,
      thread_ts: row.thread_ts,
      message_ts: row.message_ts,
      request_dedupe_key: row.request_dedupe_key,
      status,
      available_at: Some(u64::try_from(available_at).unwrap_or(0)),
      attempt_count: Some(row.attempt_count),
      sender_kind: sender.kind().to_owned(),
      sender_key: sender.key().map(ToOwned::to_owned),
    }))
  }

  /// Claims a due delivery, returns its receipt, or reports when it is next eligible.
  ///
  /// # Errors
  ///
  /// Returns an error when `SQLite` cannot read or update delivery state.
  pub async fn claim_slack_delivery(
    &self,
    workspace_id: &str,
    request_dedupe_key: &str,
    now_unix_seconds: u64,
  ) -> Result<SlackDeliveryClaim, StateError> {
    let now = i64::try_from(now_unix_seconds).unwrap_or(i64::MAX);
    let mut transaction = self
      .pool
      .begin()
      .await
      .map_err(|source| StateError::SlackDelivery { source })?;
    if let Some(receipt) = sqlx::query_as::<_, ReceiptRow>(
      "select connector_id, workspace_id, channel_id, thread_ts, message_ts, request_dedupe_key, sender_kind, sender_key from slack_delivery_receipts where workspace_id = ?1 and request_dedupe_key = ?2",
    )
    .bind(workspace_id)
    .bind(request_dedupe_key)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|source| StateError::SlackDelivery { source })? {
      transaction.commit().await.map_err(|source| StateError::SlackDelivery { source })?;
      return Ok(SlackDeliveryClaim::Delivered(receipt.try_into()?));
    }
    let row = sqlx::query_as::<_, DeliveryRow>(
      "select connector_id, workspace_id, request_dedupe_key, channel_id, thread_ts, message_ts, text, available_at, operation, status, sender_kind, sender_key from slack_delivery_queue where workspace_id = ?1 and request_dedupe_key = ?2 and operation = 'post_message'",
    )
    .bind(workspace_id)
    .bind(request_dedupe_key)
    .fetch_one(&mut *transaction)
    .await
    .map_err(|source| StateError::SlackDelivery { source })?;
    if row.status != "pending" {
      transaction
        .commit()
        .await
        .map_err(|source| StateError::SlackDelivery { source })?;
      return Ok(SlackDeliveryClaim::Deferred {
        available_at: now_unix_seconds.saturating_add(1),
      });
    }
    let channel_available_at: Option<i64> = sqlx::query_scalar(
      "select next_available_at from slack_channel_throttles where workspace_id = ?1 and channel_id = ?2",
    )
    .bind(workspace_id)
    .bind(&row.channel_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|source| StateError::SlackDelivery { source })?;
    let available_at = row.available_at.max(channel_available_at.unwrap_or(0));
    if available_at > now {
      transaction
        .commit()
        .await
        .map_err(|source| StateError::SlackDelivery { source })?;
      return Ok(SlackDeliveryClaim::Deferred {
        available_at: u64::try_from(available_at).unwrap_or(0),
      });
    }
    let delivery = SlackDeliveryRequest::try_from(row)?;
    let claimed = sqlx::query("update slack_delivery_queue set status = 'processing', attempt_count = attempt_count + 1, updated_at = datetime('now') where workspace_id = ?1 and request_dedupe_key = ?2 and status = 'pending'")
      .bind(workspace_id).bind(request_dedupe_key).execute(&mut *transaction).await
      .map_err(|source| StateError::SlackDelivery { source })?;
    if claimed.rows_affected() == 0 {
      transaction
        .commit()
        .await
        .map_err(|source| StateError::SlackDelivery { source })?;
      return Ok(SlackDeliveryClaim::Deferred {
        available_at: now_unix_seconds.saturating_add(1),
      });
    }
    transaction
      .commit()
      .await
      .map_err(|source| StateError::SlackDelivery { source })?;
    Ok(SlackDeliveryClaim::Ready(delivery))
  }

  /// Claims the next due pending Slack delivery across workspaces and channels.
  ///
  /// # Errors
  ///
  /// Returns an error when `SQLite` cannot read or update delivery state.
  pub async fn claim_next_due_slack_delivery(
    &self,
    now_unix_seconds: u64,
  ) -> Result<Option<SlackDeliveryClaim>, StateError> {
    let now = i64::try_from(now_unix_seconds).unwrap_or(i64::MAX);
    let mut transaction = self
      .pool
      .begin()
      .await
      .map_err(|source| StateError::SlackDelivery { source })?;
    let Some(row) = sqlx::query_as::<_, DeliveryRow>(
      r"select queue.connector_id, queue.workspace_id, queue.request_dedupe_key, queue.channel_id, queue.thread_ts, queue.message_ts, queue.text, queue.available_at, queue.operation, queue.status, queue.sender_kind, queue.sender_key
        from slack_delivery_queue queue
        left join slack_channel_throttles throttles
          on throttles.workspace_id = queue.workspace_id and throttles.channel_id = queue.channel_id
        where queue.status = 'pending'
          and queue.operation = 'post_message'
          and max(queue.available_at, coalesce(throttles.next_available_at, 0)) <= ?1
        order by max(queue.available_at, coalesce(throttles.next_available_at, 0)), queue.created_at, queue.id
        limit 1",
    )
    .bind(now)
    .fetch_optional(&mut *transaction)
    .await
      .map_err(|source| StateError::SlackDelivery { source })? else {
      transaction
        .commit()
        .await
        .map_err(|source| StateError::SlackDelivery { source })?;
      return Ok(None);
    };
    let delivery = SlackDeliveryRequest::try_from(row)?;
    let claimed = sqlx::query("update slack_delivery_queue set status = 'processing', attempt_count = attempt_count + 1, updated_at = datetime('now') where workspace_id = ?1 and request_dedupe_key = ?2 and status = 'pending'")
      .bind(&delivery.workspace_id).bind(&delivery.request_dedupe_key).execute(&mut *transaction).await
      .map_err(|source| StateError::SlackDelivery { source })?;
    transaction
      .commit()
      .await
      .map_err(|source| StateError::SlackDelivery { source })?;
    if claimed.rows_affected() == 0 {
      return Ok(None);
    }
    Ok(Some(SlackDeliveryClaim::Ready(delivery)))
  }

  /// Claims a due delivery operation, including stream operations.
  ///
  /// # Errors
  ///
  /// Returns an error when `SQLite` cannot read or update delivery state.
  pub async fn claim_slack_delivery_operation(
    &self,
    workspace_id: &str,
    request_dedupe_key: &str,
    now_unix_seconds: u64,
  ) -> Result<SlackDeliveryOperationClaim, StateError> {
    let now = i64::try_from(now_unix_seconds).unwrap_or(i64::MAX);
    let mut transaction = self
      .pool
      .begin()
      .await
      .map_err(|source| StateError::SlackDelivery { source })?;
    if let Some(receipt) = sqlx::query_as::<_, ReceiptRow>(
      "select connector_id, workspace_id, channel_id, thread_ts, message_ts, request_dedupe_key, sender_kind, sender_key from slack_delivery_receipts where workspace_id = ?1 and request_dedupe_key = ?2",
    )
    .bind(workspace_id)
    .bind(request_dedupe_key)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|source| StateError::SlackDelivery { source })? {
      transaction.commit().await.map_err(|source| StateError::SlackDelivery { source })?;
      return Ok(SlackDeliveryOperationClaim::Delivered(receipt.try_into()?));
    }
    let row = sqlx::query_as::<_, DeliveryRow>(
      "select connector_id, workspace_id, request_dedupe_key, channel_id, thread_ts, message_ts, text, available_at, operation, status, sender_kind, sender_key from slack_delivery_queue where workspace_id = ?1 and request_dedupe_key = ?2",
    )
    .bind(workspace_id)
    .bind(request_dedupe_key)
    .fetch_one(&mut *transaction)
    .await
    .map_err(|source| StateError::SlackDelivery { source })?;
    if row.status != "pending" {
      transaction
        .commit()
        .await
        .map_err(|source| StateError::SlackDelivery { source })?;
      return Ok(SlackDeliveryOperationClaim::Deferred {
        available_at: now_unix_seconds.saturating_add(1),
      });
    }
    let channel_available_at: Option<i64> = sqlx::query_scalar(
      "select next_available_at from slack_channel_throttles where workspace_id = ?1 and channel_id = ?2",
    )
    .bind(workspace_id)
    .bind(&row.channel_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|source| StateError::SlackDelivery { source })?;
    let available_at = row.available_at.max(channel_available_at.unwrap_or(0));
    if available_at > now {
      transaction
        .commit()
        .await
        .map_err(|source| StateError::SlackDelivery { source })?;
      return Ok(SlackDeliveryOperationClaim::Deferred {
        available_at: u64::try_from(available_at).unwrap_or(0),
      });
    }
    let claim = SlackDeliveryOperationClaim::try_from(row)?;
    let claimed = sqlx::query("update slack_delivery_queue set status = 'processing', attempt_count = attempt_count + 1, updated_at = datetime('now') where workspace_id = ?1 and request_dedupe_key = ?2 and status = 'pending'")
      .bind(workspace_id).bind(request_dedupe_key).execute(&mut *transaction).await
      .map_err(|source| StateError::SlackDelivery { source })?;
    if claimed.rows_affected() == 0 {
      transaction
        .commit()
        .await
        .map_err(|source| StateError::SlackDelivery { source })?;
      return Ok(SlackDeliveryOperationClaim::Deferred {
        available_at: now_unix_seconds.saturating_add(1),
      });
    }
    transaction
      .commit()
      .await
      .map_err(|source| StateError::SlackDelivery { source })?;
    Ok(claim)
  }

  /// Claims the next due pending Slack delivery operation.
  ///
  /// # Errors
  ///
  /// Returns an error when `SQLite` cannot read or update delivery state.
  pub async fn claim_next_due_slack_delivery_operation(
    &self,
    now_unix_seconds: u64,
  ) -> Result<Option<SlackDeliveryOperationClaim>, StateError> {
    let now = i64::try_from(now_unix_seconds).unwrap_or(i64::MAX);
    let mut transaction = self
      .pool
      .begin()
      .await
      .map_err(|source| StateError::SlackDelivery { source })?;
    let Some(row) = sqlx::query_as::<_, DeliveryRow>(
      r"select queue.connector_id, queue.workspace_id, queue.request_dedupe_key, queue.channel_id, queue.thread_ts, queue.message_ts, queue.text, queue.available_at, queue.operation, queue.status, queue.sender_kind, queue.sender_key
        from slack_delivery_queue queue
        left join slack_channel_throttles throttles
          on throttles.workspace_id = queue.workspace_id and throttles.channel_id = queue.channel_id
        where queue.status = 'pending'
          and max(queue.available_at, coalesce(throttles.next_available_at, 0)) <= ?1
        order by max(queue.available_at, coalesce(throttles.next_available_at, 0)), queue.created_at, queue.id
        limit 1",
    )
    .bind(now)
    .fetch_optional(&mut *transaction)
    .await
      .map_err(|source| StateError::SlackDelivery { source })? else {
      transaction
        .commit()
        .await
        .map_err(|source| StateError::SlackDelivery { source })?;
      return Ok(None);
    };
    let workspace_id = row.workspace_id.clone();
    let request_dedupe_key = row.request_dedupe_key.clone();
    let claim = SlackDeliveryOperationClaim::try_from(row)?;
    let claimed = sqlx::query("update slack_delivery_queue set status = 'processing', attempt_count = attempt_count + 1, updated_at = datetime('now') where workspace_id = ?1 and request_dedupe_key = ?2 and status = 'pending'")
      .bind(&workspace_id).bind(&request_dedupe_key).execute(&mut *transaction).await
      .map_err(|source| StateError::SlackDelivery { source })?;
    transaction
      .commit()
      .await
      .map_err(|source| StateError::SlackDelivery { source })?;
    if claimed.rows_affected() == 0 {
      return Ok(None);
    }
    Ok(Some(claim))
  }

  /// Returns an attempted delivery to the queue at the supplied retry time.
  ///
  /// # Errors
  ///
  /// Returns an error when `SQLite` cannot reschedule the queue item.
  pub async fn retry_slack_delivery(
    &self,
    workspace_id: &str,
    request_dedupe_key: &str,
    available_at: u64,
  ) -> Result<(), StateError> {
    sqlx::query("update slack_delivery_queue set status = 'pending', available_at = ?3, updated_at = datetime('now') where workspace_id = ?1 and request_dedupe_key = ?2")
      .bind(workspace_id).bind(request_dedupe_key).bind(i64::try_from(available_at).unwrap_or(i64::MAX))
      .execute(&self.pool).await.map_err(|source| StateError::SlackDelivery { source })?;
    Ok(())
  }

  /// Persists a successful Slack response, marks the queue row delivered, and advances the channel throttle.
  ///
  /// # Errors
  ///
  /// Returns an error when `SQLite` cannot persist the receipt and delivery state atomically.
  pub async fn complete_slack_delivery(
    &self,
    receipt: &SlackDeliveryReceipt,
    response_json: &str,
    next_available_at: u64,
  ) -> Result<(), StateError> {
    let mut transaction = self
      .pool
      .begin()
      .await
      .map_err(|source| StateError::SlackDelivery { source })?;
    sqlx::query("insert into slack_delivery_receipts (connector_id, workspace_id, channel_id, thread_ts, message_ts, request_dedupe_key, slack_response_json, sender_kind, sender_key) values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9) on conflict(workspace_id, request_dedupe_key) do nothing")
      .bind(&receipt.connector_id).bind(&receipt.workspace_id).bind(&receipt.channel_id).bind(&receipt.thread_ts).bind(&receipt.message_ts).bind(&receipt.request_dedupe_key).bind(response_json).bind(receipt.sender.kind()).bind(receipt.sender.key())
      .execute(&mut *transaction).await.map_err(|source| StateError::SlackDelivery { source })?;
    sqlx::query("update slack_delivery_queue set status = 'delivered', updated_at = datetime('now') where workspace_id = ?1 and request_dedupe_key = ?2")
      .bind(&receipt.workspace_id).bind(&receipt.request_dedupe_key).execute(&mut *transaction).await.map_err(|source| StateError::SlackDelivery { source })?;
    sqlx::query("insert into slack_channel_throttles (workspace_id, channel_id, next_available_at) values (?1, ?2, ?3) on conflict(workspace_id, channel_id) do update set next_available_at = max(slack_channel_throttles.next_available_at, excluded.next_available_at)")
      .bind(&receipt.workspace_id).bind(&receipt.channel_id).bind(i64::try_from(next_available_at).unwrap_or(i64::MAX))
      .execute(&mut *transaction).await.map_err(|source| StateError::SlackDelivery { source })?;
    transaction
      .commit()
      .await
      .map_err(|source| StateError::SlackDelivery { source })?;
    Ok(())
  }

  /// Counts durable Slack delivery receipts.
  ///
  /// # Errors
  ///
  /// Returns an error when `SQLite` cannot read the receipts table.
  pub async fn slack_delivery_receipt_count(&self) -> Result<i64, StateError> {
    sqlx::query_scalar("select count(*) from slack_delivery_receipts")
      .fetch_one(&self.pool)
      .await
      .map_err(|source| StateError::SlackDelivery { source })
  }

  /// Deletes retained terminal data older than the configured policy.
  ///
  /// Active queue rows are kept even when their timestamps are old. When `workspace_id` is present,
  /// cleanup is scoped to that workspace.
  ///
  /// # Errors
  ///
  /// Returns an error when `SQLite` rejects one of the cleanup statements.
  #[allow(
    clippy::too_many_lines,
    reason = "keeps one ordered retention cleanup transaction and report assembly visible"
  )]
  pub async fn cleanup_retained_data(
    &self,
    workspace_id: Option<&str>,
    now_unix_seconds: u64,
    policy: &RetentionPolicy,
  ) -> Result<RetentionCleanupReport, StateError> {
    if !policy.enabled {
      return Ok(RetentionCleanupReport::default());
    }

    let now = i64::try_from(now_unix_seconds).unwrap_or(i64::MAX);
    let inbound_payload_cutoff = retention_cutoff_modifier(policy.inbound_payload_days);
    let delivery_cutoff = retention_cutoff_modifier(policy.delivery_days);
    let context_attempt_cutoff = retention_cutoff_modifier(policy.context_attempt_days);
    let conversation_summary_cutoff = retention_cutoff_modifier(policy.conversation_summary_days);
    let mut transaction = self
      .pool
      .begin()
      .await
      .map_err(|source| StateError::CleanupRetainedData { source })?;

    let slack_source_events = delete_retained_rows(
      &mut transaction,
      DELETE_RETAINED_SLACK_SOURCE_EVENTS,
      now,
      &inbound_payload_cutoff,
      workspace_id,
    )
    .await
    .map_err(|source| StateError::CleanupRetainedData { source })?;

    let channel_event_queue = delete_retained_rows(
      &mut transaction,
      DELETE_RETAINED_CHANNEL_EVENT_QUEUE,
      now,
      &inbound_payload_cutoff,
      workspace_id,
    )
    .await
    .map_err(|source| StateError::CleanupRetainedData { source })?;

    let slack_delivery_receipts = delete_retained_rows(
      &mut transaction,
      DELETE_RETAINED_SLACK_DELIVERY_RECEIPTS,
      now,
      &delivery_cutoff,
      workspace_id,
    )
    .await
    .map_err(|source| StateError::CleanupRetainedData { source })?;

    let slack_delivery_queue = delete_retained_rows(
      &mut transaction,
      DELETE_RETAINED_SLACK_DELIVERY_QUEUE,
      now,
      &delivery_cutoff,
      workspace_id,
    )
    .await
    .map_err(|source| StateError::CleanupRetainedData { source })?;

    let slack_processing_indicators = delete_retained_rows(
      &mut transaction,
      DELETE_RETAINED_SLACK_PROCESSING_INDICATORS,
      now,
      &context_attempt_cutoff,
      workspace_id,
    )
    .await
    .map_err(|source| StateError::CleanupRetainedData { source })?;

    let context_fetch_attempts = delete_retained_rows(
      &mut transaction,
      DELETE_RETAINED_CONTEXT_FETCH_ATTEMPTS,
      now,
      &context_attempt_cutoff,
      workspace_id,
    )
    .await
    .map_err(|source| StateError::CleanupRetainedData { source })?;

    let channel_conversation_summaries = delete_retained_rows(
      &mut transaction,
      DELETE_RETAINED_CHANNEL_CONVERSATION_SUMMARIES,
      now,
      &conversation_summary_cutoff,
      workspace_id,
    )
    .await
    .map_err(|source| StateError::CleanupRetainedData { source })?;

    transaction
      .commit()
      .await
      .map_err(|source| StateError::CleanupRetainedData { source })?;

    let scheduler_started = Instant::now();
    let scheduled = self
      .cleanup_scheduled_history(
        now,
        retention_cutoff_unix_seconds(now, policy.scheduled_run_days),
        retention_cutoff_unix_seconds(now, policy.scheduled_delivery_days),
        u32::from(policy.scheduled_retention_batch_limit),
      )
      .await?;
    let scheduled_duration_milliseconds =
      u64::try_from(scheduler_started.elapsed().as_millis()).unwrap_or(u64::MAX);

    Ok(RetentionCleanupReport {
      slack_source_events,
      channel_event_queue,
      slack_delivery_queue,
      slack_delivery_receipts,
      slack_processing_indicators,
      context_fetch_attempts,
      channel_conversation_summaries,
      scheduled_runs_scanned: scheduled.scanned,
      scheduled_runs_deleted: scheduled.runs_deleted,
      scheduled_runs_protected: scheduled.protected,
      scheduled_permit_consumptions_deleted: scheduled.permit_consumptions_deleted,
      scheduled_rows_deleted: scheduled.rows_deleted,
      scheduled_duration_milliseconds,
    })
  }

  /// Installs a one-shot callback after scheduler retention candidate scanning.
  #[cfg(feature = "test-support")]
  pub fn set_scheduled_retention_after_scan_hook_for_tests(
    &self,
    hook: impl FnOnce() + Send + 'static,
  ) {
    *self
      .test_hooks
      .retention_after_scan
      .lock()
      .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Box::new(hook));
  }

  #[cfg(feature = "test-support")]
  pub(crate) fn run_scheduled_retention_after_scan_hook_for_tests(&self) {
    let hook = self
      .test_hooks
      .retention_after_scan
      .lock()
      .unwrap_or_else(std::sync::PoisonError::into_inner)
      .take();
    if let Some(hook) = hook {
      hook();
    }
  }

  /// Installs a one-shot callback immediately before admitted scheduler commit validation.
  #[cfg(feature = "test-support")]
  pub fn set_scheduled_executor_before_commit_hook_for_tests(
    &self,
    hook: impl FnOnce() + Send + 'static,
  ) {
    *self
      .test_hooks
      .executor_before_commit
      .lock()
      .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Box::new(hook));
  }

  #[cfg(feature = "test-support")]
  pub(crate) fn run_scheduled_executor_before_commit_hook_for_tests(&self) {
    let hook = self
      .test_hooks
      .executor_before_commit
      .lock()
      .unwrap_or_else(std::sync::PoisonError::into_inner)
      .take();
    if let Some(hook) = hook {
      hook();
    }
  }

  /// Installs a one-shot callback after commit completes but before its outcome is returned.
  #[cfg(feature = "test-support")]
  pub fn set_scheduled_executor_after_commit_hook_for_tests(
    &self,
    hook: impl FnOnce() + Send + 'static,
  ) {
    *self
      .test_hooks
      .executor_after_commit
      .lock()
      .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Box::new(hook));
  }

  #[cfg(feature = "test-support")]
  pub(crate) fn run_scheduled_executor_after_commit_hook_for_tests(&self) {
    let hook = self
      .test_hooks
      .executor_after_commit
      .lock()
      .unwrap_or_else(std::sync::PoisonError::into_inner)
      .take();
    if let Some(hook) = hook {
      hook();
    }
  }

  /// Sets the storage contention timeout for tests.
  ///
  /// # Errors
  ///
  /// Returns an error when the storage backend rejects the timeout.
  #[cfg(any(test, feature = "test-support"))]
  pub async fn set_storage_contention_timeout_for_tests(
    &self,
    timeout_milliseconds: u64,
  ) -> Result<(), StateError> {
    sqlx::query(sqlx::AssertSqlSafe(format!(
      "pragma busy_timeout = {timeout_milliseconds}"
    )))
    .execute(&self.pool)
    .await
    .map_err(|source| StateError::SlackDelivery { source })?;
    Ok(())
  }

  /// Makes the store's pooled connection reject mutations for a test.
  ///
  /// # Errors
  ///
  /// Returns an error when `SQLite` cannot enable query-only mode.
  #[cfg(feature = "test-support")]
  pub async fn install_query_only_fault_for_tests(
    &self,
  ) -> Result<StateStoreTestFaultGuard, StateError> {
    sqlx::query("pragma query_only = on")
      .execute(&self.pool)
      .await
      .map_err(|source| StateError::Scheduler { source })?;
    Ok(StateStoreTestFaultGuard {
      pool: self.pool.clone(),
      reset: Some(StateStoreTestFaultReset::QueryOnly),
      writes_observed: None,
    })
  }

  /// Caps the store's database at its current page count for a deterministic full-disk test.
  ///
  /// # Errors
  ///
  /// Returns an error when page accounting or the limit update fails.
  #[cfg(feature = "test-support")]
  pub async fn install_database_full_fault_for_tests(
    &self,
  ) -> Result<(StateStoreTestFaultGuard, i64, i64), StateError> {
    let page_count = sqlx::query_scalar::<_, i64>("pragma page_count")
      .fetch_one(&self.pool)
      .await
      .map_err(|source| StateError::Scheduler { source })?;
    let freelist_count = sqlx::query_scalar::<_, i64>("pragma freelist_count")
      .fetch_one(&self.pool)
      .await
      .map_err(|source| StateError::Scheduler { source })?;
    let previous = sqlx::query_scalar::<_, i64>("pragma max_page_count")
      .fetch_one(&self.pool)
      .await
      .map_err(|source| StateError::Scheduler { source })?;
    sqlx::query(sqlx::AssertSqlSafe(format!(
      "pragma max_page_count = {page_count}"
    )))
    .execute(&self.pool)
    .await
    .map_err(|source| StateError::Scheduler { source })?;
    Ok((
      StateStoreTestFaultGuard {
        pool: self.pool.clone(),
        reset: Some(StateStoreTestFaultReset::MaxPageCount(previous)),
        writes_observed: None,
      },
      page_count,
      freelist_count,
    ))
  }

  /// Interrupts a later statement only after the transaction has attempted a row write.
  ///
  /// # Errors
  ///
  /// Returns an error when the pooled `SQLite` handle cannot be configured.
  #[cfg(feature = "test-support")]
  pub async fn install_post_write_interrupt_fault_for_tests(
    &self,
  ) -> Result<StateStoreTestFaultGuard, StateError> {
    let writes = Arc::new(AtomicUsize::new(0));
    let mut connection = self
      .pool
      .acquire()
      .await
      .map_err(|source| StateError::Scheduler { source })?;
    let mut handle = connection
      .lock_handle()
      .await
      .map_err(|source| StateError::Scheduler { source })?;
    let update_writes = Arc::clone(&writes);
    handle.set_update_hook(move |_| {
      update_writes.fetch_add(1, Ordering::SeqCst);
    });
    let interrupt_writes = Arc::clone(&writes);
    let interrupted = AtomicBool::new(false);
    handle.set_progress_handler(1, move || {
      interrupt_writes.load(Ordering::SeqCst) == 0 || interrupted.swap(true, Ordering::SeqCst)
    });
    drop(handle);
    drop(connection);
    Ok(StateStoreTestFaultGuard {
      pool: self.pool.clone(),
      reset: Some(StateStoreTestFaultReset::Interrupt),
      writes_observed: Some(writes),
    })
  }

  /// Acquires this store's connection for an explicit cross-store test transaction.
  ///
  /// # Errors
  ///
  /// Returns an error when the test connection cannot be acquired.
  #[cfg(feature = "test-support")]
  pub async fn pool_for_tests(&self) -> Result<sqlx::pool::PoolConnection<Sqlite>, StateError> {
    self
      .pool
      .acquire()
      .await
      .map_err(|source| StateError::Scheduler { source })
  }

  /// Acquires a test-only exclusive storage lock against the state database.
  ///
  /// # Errors
  ///
  /// Returns an error when the storage backend cannot acquire the lock.
  #[cfg(any(test, feature = "test-support"))]
  pub async fn acquire_exclusive_storage_lock_for_tests(
    &self,
  ) -> Result<StateStoreTestLock, StateError> {
    let mut connection = SqliteConnection::connect_with(&self.test_connect_options)
      .await
      .map_err(|source| StateError::SlackDelivery { source })?;
    sqlx::query("begin exclusive")
      .execute(&mut connection)
      .await
      .map_err(|source| StateError::SlackDelivery { source })?;
    Ok(StateStoreTestLock { connection })
  }
}

#[derive(sqlx::FromRow)]
struct DeliveryRow {
  connector_id: String,
  workspace_id: String,
  request_dedupe_key: String,
  channel_id: String,
  thread_ts: Option<String>,
  message_ts: Option<String>,
  text: String,
  available_at: i64,
  operation: String,
  status: String,
  sender_kind: String,
  sender_key: Option<String>,
}

#[derive(sqlx::FromRow)]
struct DeliveryStatusRow {
  connector_id: String,
  workspace_id: String,
  request_dedupe_key: String,
  channel_id: String,
  thread_ts: Option<String>,
  message_ts: Option<String>,
  status: String,
  available_at: i64,
  attempt_count: i64,
  sender_kind: String,
  sender_key: Option<String>,
}

#[derive(sqlx::FromRow)]
struct SlackProcessingIndicatorRow {
  workspace_id: String,
  event_dedupe_key: String,
  channel_id: String,
  thread_ts: Option<String>,
  message_ts: String,
  status: String,
  error: Option<String>,
  created_at: String,
  updated_at: String,
  completed_at: Option<String>,
}

#[derive(sqlx::FromRow)]
struct ChannelEventQueueRow {
  id: i64,
  attempt_count: i64,
  payload_json: String,
}

#[derive(sqlx::FromRow)]
struct ChannelEventPayloadRow {
  payload_json: String,
}

#[derive(sqlx::FromRow)]
struct ChannelEventStatusRow {
  status: String,
  attempt_count: i64,
}

impl TryFrom<ChannelEventStatusRow> for ChannelEventStatus {
  type Error = StateError;

  fn try_from(row: ChannelEventStatusRow) -> Result<Self, Self::Error> {
    let status = match row.status.as_str() {
      "pending" => ChannelEventStatusKind::Pending,
      "processing" => ChannelEventStatusKind::Processing,
      "processed" => ChannelEventStatusKind::Processed,
      "failed" => ChannelEventStatusKind::Failed,
      status => {
        return Err(StateError::InvalidChannelEventStatus {
          status: status.to_owned(),
        });
      }
    };
    Ok(Self {
      status,
      attempt_count: row.attempt_count,
    })
  }
}

#[derive(sqlx::FromRow)]
struct SlackSourceReferenceRow {
  event_kind: String,
  channel_id: Option<String>,
  thread_ts: Option<String>,
  message_ts: Option<String>,
  user_id: Option<String>,
  raw_payload_json: String,
}

impl From<SlackSourceReferenceRow> for SlackSourceReferences {
  fn from(row: SlackSourceReferenceRow) -> Self {
    let metadata = slack_source_metadata(&row.raw_payload_json);
    Self {
      found: true,
      event_kind: Some(row.event_kind),
      channel_id: row.channel_id,
      thread_id: row.thread_ts,
      message_ts: row.message_ts,
      user_id: row.user_id,
      text_preview: metadata.text_preview,
      links: metadata.links,
      attachments: metadata.attachments,
      files: metadata.files,
    }
  }
}

struct SlackSourceMetadata {
  text_preview: Option<String>,
  links: Vec<SlackSourceLink>,
  attachments: Vec<SlackSourceAttachment>,
  files: Vec<SlackSourceFile>,
}

fn slack_source_metadata(raw_payload_json: &str) -> SlackSourceMetadata {
  let root = serde_json::from_str::<Value>(raw_payload_json).unwrap_or(Value::Null);
  let event = root.get("event").unwrap_or(&root);
  let mut links = Vec::new();
  collect_text_links(event.get("text").and_then(Value::as_str), &mut links);
  collect_block_links(event.get("blocks"), &mut links);
  let attachments = collect_attachments(event.get("attachments"), &mut links);
  let files = collect_files(event.get("files"));
  SlackSourceMetadata {
    text_preview: event
      .get("text")
      .and_then(Value::as_str)
      .map(ToOwned::to_owned),
    links,
    attachments,
    files,
  }
}

fn collect_text_links(text: Option<&str>, links: &mut Vec<SlackSourceLink>) {
  let Some(text) = text else {
    return;
  };
  for token in text.split_whitespace() {
    let url = token.trim_matches(|character: char| {
      matches!(
        character,
        '<' | '>' | '"' | '\'' | ')' | '(' | ',' | '.' | ';' | ':'
      )
    });
    if url.starts_with("http://") || url.starts_with("https://") {
      links.push(SlackSourceLink {
        url: url.to_owned(),
        text: None,
      });
    }
  }
}

fn collect_block_links(value: Option<&Value>, links: &mut Vec<SlackSourceLink>) {
  let Some(value) = value else {
    return;
  };
  match value {
    Value::Array(items) => {
      for item in items {
        collect_block_links(Some(item), links);
      }
    }
    Value::Object(object) => {
      if object.get("type").and_then(Value::as_str) == Some("link")
        && let Some(url) = object.get("url").and_then(Value::as_str)
      {
        links.push(SlackSourceLink {
          url: url.to_owned(),
          text: object
            .get("text")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        });
      }
      for value in object.values() {
        collect_block_links(Some(value), links);
      }
    }
    _ => {}
  }
}

fn collect_attachments(
  value: Option<&Value>,
  links: &mut Vec<SlackSourceLink>,
) -> Vec<SlackSourceAttachment> {
  value
    .and_then(Value::as_array)
    .map(|attachments| {
      attachments
        .iter()
        .filter_map(|attachment| {
          let title = attachment
            .get("title")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
          let text = attachment
            .get("text")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
          if let Some(url) = attachment.get("title_link").and_then(Value::as_str) {
            links.push(SlackSourceLink {
              url: url.to_owned(),
              text: title.clone(),
            });
          }
          if title.is_none() && text.is_none() {
            None
          } else {
            Some(SlackSourceAttachment { title, text })
          }
        })
        .collect()
    })
    .unwrap_or_default()
}

fn collect_files(value: Option<&Value>) -> Vec<SlackSourceFile> {
  value
    .and_then(Value::as_array)
    .map(|files| {
      files
        .iter()
        .map(|file| SlackSourceFile {
          resource_id: file
            .get("id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
          name: file
            .get("name")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
          title: file
            .get("title")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
          media_type: file
            .get("mimetype")
            .or_else(|| file.get("filetype"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
          size_bytes: file.get("size").and_then(Value::as_u64),
        })
        .collect()
    })
    .unwrap_or_default()
}

#[derive(sqlx::FromRow)]
struct AgentDraftRow {
  provider: String,
  channel_id: Option<String>,
  thread_id: Option<String>,
  message_ts: Option<String>,
  user_id: Option<String>,
  event_id: String,
  dedupe_key: String,
  content: String,
}

#[derive(sqlx::FromRow)]
struct ChannelConversationSummaryRow {
  summary: String,
  updated_at: String,
}

impl From<ChannelConversationSummaryRow> for ChannelConversationSummary {
  fn from(row: ChannelConversationSummaryRow) -> Self {
    Self {
      summary: row.summary,
      updated_at: row.updated_at,
    }
  }
}

#[derive(sqlx::FromRow)]
struct ContextFetchAttemptRow {
  provider: String,
  workspace_id: String,
  connector_id: String,
  dedupe_key: String,
  operation: String,
  channel_id: Option<String>,
  thread_id: Option<String>,
  message_ts: Option<String>,
  status: String,
  error_kind: Option<String>,
  error_message: Option<String>,
}

impl From<AgentDraftRow> for AgentDraft {
  fn from(row: AgentDraftRow) -> Self {
    Self {
      provider: row.provider,
      channel_id: row.channel_id,
      thread_id: row.thread_id,
      message_ts: row.message_ts,
      user_id: row.user_id,
      event_id: row.event_id,
      dedupe_key: row.dedupe_key,
      content: row.content,
    }
  }
}

impl From<ContextFetchAttemptRow> for ContextFetchAttempt {
  fn from(row: ContextFetchAttemptRow) -> Self {
    Self {
      provider: row.provider,
      workspace_id: row.workspace_id,
      connector_id: row.connector_id,
      dedupe_key: row.dedupe_key,
      operation: row.operation,
      channel_id: row.channel_id,
      thread_id: row.thread_id,
      message_ts: row.message_ts,
      status: row.status,
      error_kind: row.error_kind,
      error_message: row.error_message,
    }
  }
}

impl TryFrom<ChannelEventQueueRow> for ClaimedChannelEvent {
  type Error = StateError;

  fn try_from(row: ChannelEventQueueRow) -> Result<Self, Self::Error> {
    let event = serde_json::from_str(&row.payload_json)
      .map_err(|source| StateError::DeserializeChannelEvent { source })?;
    Ok(Self {
      id: row.id,
      attempt_count: row.attempt_count,
      event,
    })
  }
}

impl TryFrom<ChannelEventPayloadRow> for ChannelEvent {
  type Error = StateError;

  fn try_from(row: ChannelEventPayloadRow) -> Result<Self, Self::Error> {
    serde_json::from_str(&row.payload_json)
      .map_err(|source| StateError::DeserializeChannelEvent { source })
  }
}
impl TryFrom<DeliveryRow> for SlackDeliveryRequest {
  type Error = StateError;

  fn try_from(row: DeliveryRow) -> Result<Self, Self::Error> {
    let sender = SlackDeliverySender::from_parts(row.sender_kind, row.sender_key)?;
    Ok(Self {
      connector_id: row.connector_id,
      workspace_id: row.workspace_id,
      request_dedupe_key: row.request_dedupe_key,
      channel_id: row.channel_id,
      thread_ts: row.thread_ts,
      text: row.text,
      sender,
    })
  }
}

impl TryFrom<DeliveryRow> for SlackStopStreamDeliveryRequest {
  type Error = StateError;

  fn try_from(row: DeliveryRow) -> Result<Self, Self::Error> {
    let sender = SlackDeliverySender::from_parts(row.sender_kind, row.sender_key)?;
    let message_ts = row
      .message_ts
      .ok_or(StateError::InvalidSlackDeliveryOperation {
        operation: row.operation.clone(),
      })?;
    Ok(Self {
      connector_id: row.connector_id,
      workspace_id: row.workspace_id,
      request_dedupe_key: row.request_dedupe_key,
      channel_id: row.channel_id,
      thread_ts: row.thread_ts,
      message_ts,
      text: row.text,
      sender,
    })
  }
}

impl TryFrom<DeliveryRow> for SlackDeliveryOperationClaim {
  type Error = StateError;

  fn try_from(row: DeliveryRow) -> Result<Self, Self::Error> {
    match row.operation.as_str() {
      "post_message" => Ok(Self::PostMessage(row.try_into()?)),
      "stop_stream" => Ok(Self::StopStream(row.try_into()?)),
      operation => Err(StateError::InvalidSlackDeliveryOperation {
        operation: operation.to_owned(),
      }),
    }
  }
}

impl TryFrom<SlackProcessingIndicatorRow> for SlackProcessingIndicator {
  type Error = StateError;

  fn try_from(row: SlackProcessingIndicatorRow) -> Result<Self, Self::Error> {
    let status = match row.status.as_str() {
      "started" => SlackProcessingIndicatorStatusKind::Started,
      "completed" => SlackProcessingIndicatorStatusKind::Completed,
      "failed" => SlackProcessingIndicatorStatusKind::Failed,
      status => {
        return Err(StateError::InvalidSlackProcessingIndicatorStatus {
          status: status.to_owned(),
        });
      }
    };
    Ok(Self {
      workspace_id: row.workspace_id,
      event_dedupe_key: row.event_dedupe_key,
      channel_id: row.channel_id,
      thread_ts: row.thread_ts,
      message_ts: row.message_ts,
      status,
      error: row.error,
      created_at: row.created_at,
      updated_at: row.updated_at,
      completed_at: row.completed_at,
    })
  }
}
#[derive(sqlx::FromRow)]
struct ReceiptRow {
  connector_id: String,
  workspace_id: String,
  channel_id: String,
  thread_ts: Option<String>,
  message_ts: String,
  request_dedupe_key: String,
  sender_kind: String,
  sender_key: Option<String>,
}
impl TryFrom<ReceiptRow> for SlackDeliveryReceipt {
  type Error = StateError;

  fn try_from(row: ReceiptRow) -> Result<Self, Self::Error> {
    let sender = SlackDeliverySender::from_parts(row.sender_kind, row.sender_key)?;
    Ok(Self {
      connector_id: row.connector_id,
      workspace_id: row.workspace_id,
      channel_id: row.channel_id,
      thread_ts: row.thread_ts,
      message_ts: row.message_ts,
      request_dedupe_key: row.request_dedupe_key,
      sender,
    })
  }
}

fn connect_options(
  state_dir: &Path,
  database_url: Option<&str>,
) -> Result<SqliteConnectOptions, StateError> {
  let options = match database_url {
    Some(database_url) => {
      SqliteConnectOptions::from_str(database_url).map_err(|_| StateError::InvalidDatabaseUrl {
        reason: "SQLite URL could not be parsed",
      })?
    }
    None => SqliteConnectOptions::new().filename(state_dir.join("codeoff.db")),
  };

  Ok(
    options
      .create_if_missing(true)
      .foreign_keys(true)
      .journal_mode(SqliteJournalMode::Wal)
      .synchronous(SqliteSynchronous::Full)
      .busy_timeout(Duration::from_secs(5)),
  )
}

fn normalized_key_part(value: Option<&String>) -> &str {
  value.map_or("", String::as_str)
}

fn retention_cutoff_modifier(days: u16) -> String {
  format!("-{days} days")
}

fn retention_cutoff_unix_seconds(now: i64, days: u16) -> i64 {
  now.saturating_sub(i64::from(days) * 24 * 60 * 60)
}

async fn delete_retained_rows(
  transaction: &mut Transaction<'_, Sqlite>,
  sql: &'static str,
  now: i64,
  cutoff_modifier: &str,
  workspace_id: Option<&str>,
) -> Result<u64, sqlx::Error> {
  sqlx::query(sql)
    .bind(now)
    .bind(cutoff_modifier)
    .bind(workspace_id)
    .execute(&mut **transaction)
    .await
    .map(|result| result.rows_affected())
}

fn prepare_state_dir(state_dir: &Path) -> Result<(), StateError> {
  fs::create_dir_all(state_dir).map_err(|source| StateError::CreateStateDir {
    path: PathBuf::from(state_dir),
    source,
  })?;

  let probe_path = state_dir.join(".codeoff-write-probe");
  fs::write(&probe_path, b"ok").map_err(|source| StateError::WriteProbe {
    path: probe_path.clone(),
    source,
  })?;
  fs::remove_file(&probe_path).map_err(|source| StateError::RemoveProbe {
    path: probe_path,
    source,
  })?;

  Ok(())
}

fn prepare_database_dir(options: &SqliteConnectOptions) -> Result<(), StateError> {
  let Some(parent) = options.get_filename().parent() else {
    return Ok(());
  };

  if parent.as_os_str().is_empty() {
    return Ok(());
  }

  fs::create_dir_all(parent).map_err(|source| StateError::CreateDatabaseDir {
    path: PathBuf::from(parent),
    source,
  })
}

#[cfg(test)]
mod tests {
  use super::*;

  use sqlx::{Connection, SqliteConnection};
  use tempfile::tempdir;

  fn database_url(state_dir: &Path) -> String {
    format!("sqlite://{}", state_dir.join("codeoff.db").display())
  }

  #[tokio::test]
  async fn test_initialize_configures_sqlite_connection() {
    let temp = tempdir().expect("create tempdir");
    let state_dir = temp.path().join("state");
    let store = StateStore::initialize(&state_dir, None)
      .await
      .expect("initialize state store");

    let mut connection = store.pool.acquire().await.expect("acquire connection");
    let busy_timeout: i64 = sqlx::query_scalar("pragma busy_timeout")
      .fetch_one(&mut *connection)
      .await
      .expect("read busy timeout");
    let synchronous: i64 = sqlx::query_scalar("pragma synchronous")
      .fetch_one(&mut *connection)
      .await
      .expect("read synchronous mode");

    assert_eq!(busy_timeout, 5_000);
    assert_eq!(synchronous, 2);
    assert_eq!(store.pool.size(), 1);
    assert!(store.pool.try_acquire().is_none());
  }

  #[tokio::test]
  async fn test_sqlite_busy_completion_error_is_retryable() {
    let temp = tempdir().expect("tempdir");
    let state_dir = temp.path().join("state");
    let store = StateStore::initialize(&state_dir, None)
      .await
      .expect("state store");
    store
      .set_storage_contention_timeout_for_tests(0)
      .await
      .expect("set zero busy timeout");
    let mut lock = SqliteConnection::connect(&database_url(&state_dir))
      .await
      .expect("connect lock holder");
    sqlx::query("begin exclusive")
      .execute(&mut lock)
      .await
      .expect("acquire lock");
    let error = store
      .complete_slack_delivery(
        &SlackDeliveryReceipt {
          connector_id: "connector-1".to_owned(),
          workspace_id: "workspace-1".to_owned(),
          channel_id: "C1".to_owned(),
          thread_ts: None,
          message_ts: "200.0".to_owned(),
          request_dedupe_key: "busy-1".to_owned(),
          sender: SlackDeliverySender::Bot,
        },
        r#"{"ok":true}"#,
        101,
      )
      .await
      .expect_err("completion is busy");
    sqlx::query("commit")
      .execute(&mut lock)
      .await
      .expect("release lock");

    assert!(error.is_transient_storage_contention(), "{error:?}");
  }

  #[tokio::test]
  async fn test_exclusive_lock_uses_default_database_options_with_special_characters() {
    let temp = tempdir().expect("tempdir");
    let state_dir = temp.path().join("state?#special");
    let store = StateStore::initialize(&state_dir, None)
      .await
      .expect("state store");
    store
      .set_storage_contention_timeout_for_tests(0)
      .await
      .expect("set zero busy timeout");
    let lock = store
      .acquire_exclusive_storage_lock_for_tests()
      .await
      .expect("acquire exclusive lock");

    let error = store
      .claim_idempotency_key("tests", "contended")
      .await
      .expect_err("lock contends with initialized database");
    lock.release().await.expect("release lock");

    assert!(matches!(error, StateError::ClaimIdempotencyKey { .. }));
  }

  #[tokio::test]
  async fn test_exclusive_lock_uses_custom_database_options() {
    let temp = tempdir().expect("tempdir");
    let state_dir = temp.path().join("state");
    let database_path = temp.path().join("custom").join("codeoff.db");
    let database_url = format!("sqlite://{}?mode=rwc", database_path.display());
    let store = StateStore::initialize(&state_dir, Some(&database_url))
      .await
      .expect("state store");
    store
      .set_storage_contention_timeout_for_tests(0)
      .await
      .expect("set zero busy timeout");
    let lock = store
      .acquire_exclusive_storage_lock_for_tests()
      .await
      .expect("acquire exclusive lock");

    let error = store
      .claim_idempotency_key("tests", "custom-contended")
      .await
      .expect_err("lock contends with custom database");
    lock.release().await.expect("release lock");

    assert!(matches!(error, StateError::ClaimIdempotencyKey { .. }));
  }

  #[tokio::test]
  async fn test_exclusive_lock_uses_in_memory_database_options() {
    let temp = tempdir().expect("tempdir");
    let store = StateStore::initialize(temp.path(), Some("sqlite::memory:"))
      .await
      .expect("state store");
    store
      .set_storage_contention_timeout_for_tests(0)
      .await
      .expect("set zero busy timeout");
    let lock = store
      .acquire_exclusive_storage_lock_for_tests()
      .await
      .expect("acquire exclusive lock");

    let error = store
      .claim_idempotency_key("tests", "memory-contended")
      .await
      .expect_err("lock contends with in-memory database");
    lock.release().await.expect("release lock");

    assert!(matches!(error, StateError::ClaimIdempotencyKey { .. }));
  }
}
