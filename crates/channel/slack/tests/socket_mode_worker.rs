use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use codeoff_channel_slack::{
  SlackIntake, SlackIntakeResult, SlackSocketError, SlackSocketTransport, SocketWorkerAction,
  SocketWorkerOptions, TransportReceive, run_socket_worker,
};
use codeoff_state::StateStore;
use tempfile::tempdir;

#[derive(Debug, Default)]
struct FakeTransport {
  receives: VecDeque<Result<TransportReceive, SlackSocketError>>,
  calls: Arc<Mutex<Vec<String>>>,
}

#[async_trait]
impl SlackSocketTransport for FakeTransport {
  async fn open(&mut self, app_token: &str) -> Result<(), SlackSocketError> {
    self
      .calls
      .lock()
      .expect("calls lock")
      .push(format!("open:{app_token}"));
    Ok(())
  }

  async fn receive(&mut self) -> Result<TransportReceive, SlackSocketError> {
    self
      .receives
      .pop_front()
      .expect("fake transport has a queued receive result")
  }

  async fn acknowledge(&mut self, envelope_id: &str) -> Result<(), SlackSocketError> {
    self
      .calls
      .lock()
      .expect("calls lock")
      .push(format!("ack:{envelope_id}"));
    Ok(())
  }
}

#[tokio::test]
async fn acknowledges_an_envelope_before_slow_processing() {
  let mut transport = FakeTransport {
    receives: VecDeque::from([Ok(TransportReceive::Envelope(
      r#"{"envelope_id":"envelope-1","payload":{"event_id":"event-1"}}"#.to_owned(),
    ))]),
    calls: Arc::new(Mutex::new(Vec::new())),
  };
  let calls = Arc::clone(&transport.calls);

  let result = run_socket_worker(
    &mut transport,
    "xapp-test-token",
    SocketWorkerOptions::default(),
    |envelope| {
      transport_assert_acknowledged(&calls.lock().expect("calls lock"), &envelope);
      async { SocketWorkerAction::Shutdown }
    },
  )
  .await;

  assert_eq!(result.expect("worker completes"), 1);
  assert_eq!(
    *transport.calls.lock().expect("calls lock"),
    ["open:xapp-test-token", "ack:envelope-1"]
  );
}

#[tokio::test]
async fn skips_invalid_envelopes_without_calling_slow_processing() {
  let mut transport = FakeTransport {
    receives: VecDeque::from([
      Ok(TransportReceive::Envelope("not-json".to_owned())),
      Ok(TransportReceive::Envelope(
        r#"{"envelope_id":"envelope-2"}"#.to_owned(),
      )),
    ]),
    calls: Arc::new(Mutex::new(Vec::new())),
  };

  let result = run_socket_worker(
    &mut transport,
    "xapp-test-token",
    SocketWorkerOptions::default(),
    |_| async { SocketWorkerAction::Shutdown },
  )
  .await;

  assert_eq!(result.expect("worker completes"), 1);
  assert_eq!(
    *transport.calls.lock().expect("calls lock"),
    ["open:xapp-test-token", "ack:envelope-2"]
  );
}

#[tokio::test]
async fn reconnects_after_a_disconnect_and_processes_the_next_envelope() {
  let mut transport = FakeTransport {
    receives: VecDeque::from([
      Ok(TransportReceive::Disconnected),
      Ok(TransportReceive::Envelope(
        r#"{"envelope_id":"envelope-2"}"#.to_owned(),
      )),
    ]),
    calls: Arc::new(Mutex::new(Vec::new())),
  };

  let result = run_socket_worker(
    &mut transport,
    "xapp-test-token",
    SocketWorkerOptions { max_reconnects: 1 },
    |_| async { SocketWorkerAction::Shutdown },
  )
  .await;

  assert_eq!(result.expect("worker completes"), 1);
  assert_eq!(
    *transport.calls.lock().expect("calls lock"),
    [
      "open:xapp-test-token",
      "open:xapp-test-token",
      "ack:envelope-2"
    ]
  );
}

#[tokio::test]
async fn continues_after_an_ignored_envelope() {
  let temp = tempdir().expect("tempdir");
  let store = StateStore::initialize(temp.path(), None)
    .await
    .expect("store");
  let intake = SlackIntake::new(store, "slack-main");
  let mut transport = FakeTransport {
    receives: VecDeque::from([
      Ok(TransportReceive::Envelope(
        r#"{"envelope_id":"envelope-1","type":"hello","payload":{}}"#.to_owned(),
      )),
      Ok(TransportReceive::Envelope(
        include_str!("fixtures/app_mention.json").to_owned(),
      )),
    ]),
    calls: Arc::new(Mutex::new(Vec::new())),
  };
  let results = Arc::new(Mutex::new(Vec::new()));
  let callback_results = Arc::clone(&results);
  let worker_intake = intake.clone();

  let result = run_socket_worker(
    &mut transport,
    "xapp-test-token",
    SocketWorkerOptions::default(),
    move |envelope| {
      let intake = worker_intake.clone();
      let results = Arc::clone(&callback_results);
      async move {
        let intake_result = intake.accept(&envelope).await.expect("intake result");
        let result_count = {
          let mut results = results.lock().expect("results lock");
          results.push(intake_result);
          results.len()
        };
        if result_count == 2 {
          SocketWorkerAction::Shutdown
        } else {
          SocketWorkerAction::Continue
        }
      }
    },
  )
  .await;

  assert_eq!(result.expect("worker completes"), 2);
  assert_eq!(
    *results.lock().expect("results lock"),
    [SlackIntakeResult::Ignored, SlackIntakeResult::Queued]
  );
  assert_eq!(intake.queued_event_count().await.expect("queue count"), 1);
  assert_eq!(
    *transport.calls.lock().expect("calls lock"),
    [
      "open:xapp-test-token",
      "ack:envelope-1",
      "ack:env-app-mention-1"
    ]
  );
}

fn transport_assert_acknowledged(calls: &[String], envelope: &str) {
  assert_eq!(
    envelope,
    r#"{"envelope_id":"envelope-1","payload":{"event_id":"event-1"}}"#
  );
  assert_eq!(calls, ["open:xapp-test-token", "ack:envelope-1"]);
}
