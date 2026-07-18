use std::cell::Cell;
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use codeoff_channel_contract::{ChannelMessageReceipt, ChannelMessageRequest, ChannelReplyTarget};
use codeoff_state::{
  SlackDeliveryClaim, SlackDeliveryOperationClaim, SlackDeliveryReceipt, SlackDeliveryRequest,
  SlackDeliverySender, SlackStopStreamDeliveryRequest, StateStore,
};

use crate::{SlackHttpClient, SlackWebApiClient, SlackWebApiError};

struct PendingSlackCompletion {
  receipt: SlackDeliveryReceipt,
  response_json: String,
  next_attempt_at: u64,
  retry_delay_seconds: u64,
  next_available_at: u64,
}

/// Delivers Slack messages through a durable queue with receipt-based deduplication.
pub struct SlackDeliveryQueue<H> {
  api: SlackWebApiClient<H>,
  store: StateStore,
  now_unix_seconds: Cell<u64>,
  channel_interval_seconds: u64,
  // A process crash before this is flushed leaves the provider post unrecorded by design.
  pending_completions: Mutex<VecDeque<PendingSlackCompletion>>,
  in_memory_channel_throttles: Mutex<HashMap<(String, String), u64>>,
}

const INITIAL_COMPLETION_PERSISTENCE_RETRY_DELAY_SECONDS: u64 = 1;
const MAX_COMPLETION_PERSISTENCE_RETRY_DELAY_SECONDS: u64 = 60;

impl<H: SlackHttpClient + Sync> SlackDeliveryQueue<H> {
  #[must_use]
  pub fn new(api: SlackWebApiClient<H>, store: StateStore, now_unix_seconds: u64) -> Self {
    Self {
      api,
      store,
      now_unix_seconds: Cell::new(now_unix_seconds),
      channel_interval_seconds: 1,
      pending_completions: Mutex::new(VecDeque::new()),
      in_memory_channel_throttles: Mutex::new(HashMap::new()),
    }
  }

  #[must_use]
  pub const fn http_client(&self) -> &H {
    self.api.http_client()
  }

  pub fn set_now_unix_seconds(&self, now_unix_seconds: u64) {
    self.now_unix_seconds.set(now_unix_seconds);
  }

  /// Returns the number of successful durable Slack delivery receipts.
  ///
  /// # Errors
  ///
  /// Returns an error when the receipt store cannot be read.
  pub async fn receipt_count(&self) -> Result<i64, SlackWebApiError> {
    self
      .store
      .slack_delivery_receipt_count()
      .await
      .map_err(|error| state_error(&error))
  }

  /// Queues and delivers a supported outbound request when it is due.
  ///
  /// # Errors
  ///
  /// Returns an error for unsupported targets, deferred messages, Slack API failures, or state errors.
  pub async fn deliver(
    &self,
    request: &ChannelMessageRequest,
  ) -> Result<ChannelMessageReceipt, SlackWebApiError> {
    let queued = request_to_delivery(request)?;
    let now = self.now_unix_seconds.get();
    self
      .store
      .enqueue_slack_delivery(&queued, now)
      .await
      .map_err(|error| state_error(&error))?;
    if let Some(available_at) = self.in_memory_channel_available_at(&queued, now) {
      return Err(SlackWebApiError::Deferred { available_at });
    }
    match self
      .store
      .claim_slack_delivery(&queued.workspace_id, &queued.request_dedupe_key, now)
      .await
      .map_err(|error| state_error(&error))?
    {
      SlackDeliveryClaim::Delivered(receipt) => Ok(receipt_to_channel(receipt)),
      SlackDeliveryClaim::Deferred { available_at } => {
        Err(SlackWebApiError::Deferred { available_at })
      }
      SlackDeliveryClaim::Ready(delivery) => self.post_and_record(delivery, now).await,
    }
  }

  /// Drains one due delivery that was already queued by runtime or MCP channel tools.
  ///
  /// # Errors
  ///
  /// Returns an error for Slack API failures or state errors.
  pub async fn drain_due_once(&self) -> Result<Option<ChannelMessageReceipt>, SlackWebApiError> {
    let now = self.now_unix_seconds.get();
    if let Some(receipt) = self.complete_due_pending(now).await? {
      return Ok(Some(receipt_to_channel(receipt)));
    }
    match self
      .store
      .claim_next_due_slack_delivery_operation(now)
      .await
      .map_err(|error| state_error(&error))?
    {
      Some(SlackDeliveryOperationClaim::PostMessage(delivery)) => {
        if let Some(available_at) = self.in_memory_channel_available_at(&delivery, now) {
          self
            .store
            .retry_slack_delivery(
              &delivery.workspace_id,
              &delivery.request_dedupe_key,
              available_at,
            )
            .await
            .map_err(|error| state_error(&error))?;
          return Ok(None);
        }
        self.post_and_record(delivery, now).await.map(Some)
      }
      Some(SlackDeliveryOperationClaim::StopStream(delivery)) => {
        self.stop_stream_and_record(delivery, now).await.map(Some)
      }
      Some(SlackDeliveryOperationClaim::Delivered(receipt)) => {
        Ok(Some(receipt_to_channel(receipt)))
      }
      Some(SlackDeliveryOperationClaim::Deferred { available_at }) => {
        Err(SlackWebApiError::Deferred { available_at })
      }
      None => Ok(None),
    }
  }

  async fn post_and_record(
    &self,
    delivery: SlackDeliveryRequest,
    now: u64,
  ) -> Result<ChannelMessageReceipt, SlackWebApiError> {
    let posted = match self
      .api
      .post_message_as(
        &delivery.channel_id,
        delivery.thread_ts.as_deref(),
        &delivery.text,
        &delivery.sender,
      )
      .await
    {
      Ok(posted) => posted,
      Err(
        error @ SlackWebApiError::RateLimited {
          retry_after_seconds,
        },
      ) => {
        self
          .store
          .retry_slack_delivery(
            &delivery.workspace_id,
            &delivery.request_dedupe_key,
            now.saturating_add(retry_after_seconds.unwrap_or(1)),
          )
          .await
          .map_err(|error| state_error(&error))?;
        return Err(error);
      }
      Err(error) => {
        self
          .store
          .retry_slack_delivery(
            &delivery.workspace_id,
            &delivery.request_dedupe_key,
            now.saturating_add(1),
          )
          .await
          .map_err(|error| state_error(&error))?;
        return Err(error);
      }
    };
    let receipt = SlackDeliveryReceipt {
      connector_id: delivery.connector_id,
      workspace_id: delivery.workspace_id,
      channel_id: posted.channel_id,
      thread_ts: posted.thread_ts.or(delivery.thread_ts),
      message_ts: posted.message_ts,
      request_dedupe_key: delivery.request_dedupe_key,
      sender: delivery.sender,
    };
    let next_available_at = now.saturating_add(self.channel_interval_seconds);
    self.set_in_memory_channel_throttle(&receipt, next_available_at);
    let deferred = self
      .persist_or_defer_completion(&receipt, &posted.response_body, next_available_at, now)
      .await?;
    if !deferred {
      self.clear_in_memory_channel_throttle(&receipt, next_available_at);
    }
    Ok(receipt_to_channel(receipt))
  }

  async fn stop_stream_and_record(
    &self,
    delivery: SlackStopStreamDeliveryRequest,
    now: u64,
  ) -> Result<ChannelMessageReceipt, SlackWebApiError> {
    let posted = match self
      .api
      .stop_stream(&delivery.channel_id, &delivery.message_ts, &delivery.text)
      .await
    {
      Ok(posted) => posted,
      Err(
        error @ SlackWebApiError::RateLimited {
          retry_after_seconds,
        },
      ) => {
        self
          .store
          .retry_slack_delivery(
            &delivery.workspace_id,
            &delivery.request_dedupe_key,
            now.saturating_add(retry_after_seconds.unwrap_or(1)),
          )
          .await
          .map_err(|error| state_error(&error))?;
        return Err(error);
      }
      Err(error) => {
        self
          .store
          .retry_slack_delivery(
            &delivery.workspace_id,
            &delivery.request_dedupe_key,
            now.saturating_add(1),
          )
          .await
          .map_err(|error| state_error(&error))?;
        return Err(error);
      }
    };
    let receipt = SlackDeliveryReceipt {
      connector_id: delivery.connector_id,
      workspace_id: delivery.workspace_id,
      channel_id: posted.channel_id,
      thread_ts: posted.thread_ts.or(delivery.thread_ts),
      message_ts: posted.message_ts,
      request_dedupe_key: delivery.request_dedupe_key,
      sender: delivery.sender,
    };
    let next_available_at = now.saturating_add(self.channel_interval_seconds);
    self.set_in_memory_channel_throttle(&receipt, next_available_at);
    let deferred = self
      .persist_or_defer_completion(&receipt, &posted.response_body, next_available_at, now)
      .await?;
    if !deferred {
      self.clear_in_memory_channel_throttle(&receipt, next_available_at);
    }
    Ok(receipt_to_channel(receipt))
  }

  async fn persist_or_defer_completion(
    &self,
    receipt: &SlackDeliveryReceipt,
    response_json: &str,
    next_available_at: u64,
    now: u64,
  ) -> Result<bool, SlackWebApiError> {
    match self
      .store
      .complete_slack_delivery(receipt, response_json, next_available_at)
      .await
    {
      Ok(()) => Ok(false),
      Err(error) if error.is_transient_storage_contention() => {
        self
          .pending_completions
          .lock()
          .expect("pending completions")
          .push_back(PendingSlackCompletion {
            receipt: receipt.clone(),
            response_json: response_json.to_owned(),
            next_attempt_at: now.saturating_add(INITIAL_COMPLETION_PERSISTENCE_RETRY_DELAY_SECONDS),
            retry_delay_seconds: INITIAL_COMPLETION_PERSISTENCE_RETRY_DELAY_SECONDS,
            next_available_at,
          });
        Ok(true)
      }
      Err(error) => Err(state_error(&error)),
    }
  }

  async fn complete_due_pending(
    &self,
    now: u64,
  ) -> Result<Option<SlackDeliveryReceipt>, SlackWebApiError> {
    let Some(mut pending) = self.take_due_pending(now) else {
      return Ok(None);
    };
    match self
      .store
      .complete_slack_delivery(
        &pending.receipt,
        &pending.response_json,
        pending.next_available_at,
      )
      .await
    {
      Ok(()) => {
        self.clear_in_memory_channel_throttle(&pending.receipt, pending.next_available_at);
        Ok(Some(pending.receipt))
      }
      Err(error) if error.is_transient_storage_contention() => {
        pending.retry_delay_seconds = pending
          .retry_delay_seconds
          .saturating_mul(2)
          .min(MAX_COMPLETION_PERSISTENCE_RETRY_DELAY_SECONDS);
        pending.next_attempt_at = now.saturating_add(pending.retry_delay_seconds);
        self
          .pending_completions
          .lock()
          .expect("pending completions")
          .push_back(pending);
        Ok(None)
      }
      Err(error) => Err(state_error(&error)),
    }
  }

  fn take_due_pending(&self, now: u64) -> Option<PendingSlackCompletion> {
    let mut pending = self
      .pending_completions
      .lock()
      .expect("pending completions");
    let position = pending
      .iter()
      .position(|completion| completion.next_attempt_at <= now)?;
    pending.remove(position)
  }

  fn in_memory_channel_available_at(
    &self,
    delivery: &SlackDeliveryRequest,
    now: u64,
  ) -> Option<u64> {
    self
      .in_memory_channel_throttles
      .lock()
      .expect("in-memory channel throttles")
      .get(&(delivery.workspace_id.clone(), delivery.channel_id.clone()))
      .copied()
      .filter(|available_at| *available_at > now)
  }

  fn set_in_memory_channel_throttle(&self, receipt: &SlackDeliveryReceipt, next_available_at: u64) {
    let mut throttles = self
      .in_memory_channel_throttles
      .lock()
      .expect("in-memory channel throttles");
    let throttle = throttles
      .entry((receipt.workspace_id.clone(), receipt.channel_id.clone()))
      .or_insert(next_available_at);
    *throttle = (*throttle).max(next_available_at);
  }

  fn clear_in_memory_channel_throttle(
    &self,
    receipt: &SlackDeliveryReceipt,
    persisted_next_available_at: u64,
  ) {
    let mut throttles = self
      .in_memory_channel_throttles
      .lock()
      .expect("in-memory channel throttles");
    let key = (receipt.workspace_id.clone(), receipt.channel_id.clone());
    if throttles
      .get(&key)
      .is_some_and(|available_at| *available_at <= persisted_next_available_at)
    {
      throttles.remove(&key);
    }
  }
}

fn request_to_delivery(
  request: &ChannelMessageRequest,
) -> Result<SlackDeliveryRequest, SlackWebApiError> {
  let (channel_id, thread_ts) = match &request.target {
    ChannelReplyTarget::Thread {
      channel_id,
      thread_id,
    } => (channel_id.clone(), Some(thread_id.clone())),
    ChannelReplyTarget::DirectMessage { user_account_id } => (user_account_id.clone(), None),
    ChannelReplyTarget::Channel { .. } | ChannelReplyTarget::Ephemeral { .. } => {
      return Err(SlackWebApiError::UnsupportedTarget);
    }
  };
  Ok(SlackDeliveryRequest {
    connector_id: request.connector_id.clone(),
    workspace_id: request.workspace_id.clone(),
    request_dedupe_key: request.dedupe_key.clone(),
    channel_id,
    thread_ts,
    text: request.text.clone(),
    sender: SlackDeliverySender::Bot,
  })
}

fn receipt_to_channel(receipt: SlackDeliveryReceipt) -> ChannelMessageReceipt {
  ChannelMessageReceipt {
    connector_id: receipt.connector_id,
    workspace_id: receipt.workspace_id,
    request_dedupe_key: receipt.request_dedupe_key,
    message_id: receipt.message_ts,
  }
}

fn state_error(error: &codeoff_state::StateError) -> SlackWebApiError {
  SlackWebApiError::Request {
    message: format!("slack delivery state error: {error}"),
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  use std::sync::Mutex;
  use std::sync::atomic::{AtomicUsize, Ordering};

  use codeoff_channel_contract::{ChannelMessageRequest, ChannelReplyTarget};
  use codeoff_config::SlackConfig;
  use tempfile::tempdir;
  use tokio::sync::Notify;

  use crate::{SlackHttpRequest, SlackHttpResponse};

  struct GatedHttpClient {
    response: Mutex<Option<SlackHttpResponse>>,
    post_started: Notify,
    post_release: Notify,
    post_count: AtomicUsize,
  }

  impl GatedHttpClient {
    fn new(response: SlackHttpResponse) -> Self {
      Self {
        response: Mutex::new(Some(response)),
        post_started: Notify::new(),
        post_release: Notify::new(),
        post_count: AtomicUsize::new(0),
      }
    }
  }

  #[async_trait::async_trait]
  impl SlackHttpClient for GatedHttpClient {
    async fn get(&self, _request: SlackHttpRequest) -> Result<SlackHttpResponse, String> {
      Err("unexpected GET request".to_owned())
    }

    async fn post(&self, _request: SlackHttpRequest) -> Result<SlackHttpResponse, String> {
      self.post_count.fetch_add(1, Ordering::Relaxed);
      self.post_started.notify_one();
      self.post_release.notified().await;
      self
        .response
        .lock()
        .expect("response")
        .take()
        .ok_or_else(|| "unexpected POST request".to_owned())
    }
  }

  fn ok_response() -> SlackHttpResponse {
    SlackHttpResponse::new(
      200,
      Vec::<(&str, &str)>::new(),
      r#"{"ok":true,"channel":"C1","ts":"200.0","message":{"ts":"200.0","thread_ts":"100.0"}}"#,
    )
  }

  #[tokio::test]
  #[allow(clippy::too_many_lines)]
  async fn deferred_completion_backoff_doubles_to_sixty_second_cap_without_reposting() {
    let temp = tempdir().expect("tempdir");
    let store = StateStore::initialize(temp.path(), None)
      .await
      .expect("state store");
    store
      .set_storage_contention_timeout_for_tests(0)
      .await
      .expect("set zero busy timeout");
    let http = GatedHttpClient::new(ok_response());
    let delivery = SlackDeliveryQueue::new(
      SlackWebApiClient::new(
        http,
        "connector-1",
        "xoxb-secret-token",
        SlackConfig::default(),
        100,
      ),
      store.clone(),
      100,
    );
    let request = ChannelMessageRequest::new(
      "connector-1",
      "workspace-1",
      "storage-backoff-1",
      ChannelReplyTarget::Thread {
        channel_id: "C1".to_owned(),
        thread_id: "100.0".to_owned(),
      },
      "persist after contention",
    )
    .expect("request");
    let first_delivery = delivery.deliver(&request);
    tokio::pin!(first_delivery);
    tokio::select! {
      () = delivery.http_client().post_started.notified() => {}
      result = &mut first_delivery => panic!("delivery completed before post: {result:?}"),
    }
    let mut lock = Some(
      store
        .acquire_exclusive_storage_lock_for_tests()
        .await
        .expect("acquire exclusive lock"),
    );
    delivery.http_client().post_release.notify_one();
    first_delivery.await.expect("deferred delivery result");

    for (due_at, next_attempt_at) in [
      (101, 103),
      (103, 107),
      (107, 115),
      (115, 131),
      (131, 163),
      (163, 223),
      (223, 283),
      (283, 343),
    ] {
      delivery.set_now_unix_seconds(due_at);
      assert!(
        delivery
          .drain_due_once()
          .await
          .expect("defer contended completion")
          .is_none()
      );
      assert_eq!(
        delivery
          .pending_completions
          .lock()
          .expect("pending completions")
          .front()
          .map(|completion| completion.next_attempt_at),
        Some(next_attempt_at)
      );
    }

    lock
      .take()
      .expect("lock holder")
      .release()
      .await
      .expect("release lock");
    delivery.set_now_unix_seconds(343);
    let receipt = delivery
      .drain_due_once()
      .await
      .expect("persist deferred completion")
      .expect("deferred receipt");
    assert_eq!(receipt.message_id, "200.0");
    assert!(
      delivery
        .pending_completions
        .lock()
        .expect("pending completions")
        .is_empty()
    );
    assert_eq!(delivery.http_client().post_count.load(Ordering::Relaxed), 1);
    assert_eq!(
      store
        .slack_delivery_receipt_count()
        .await
        .expect("receipt count"),
      1
    );
  }
}
