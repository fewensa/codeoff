use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Scheduler worker emitting a telemetry event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulerWorker {
  Execution,
  DeliveryPreparation,
  Delivery,
}

/// Bounded scheduler operation represented by a telemetry event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulerOperation {
  Loop,
  Tick,
  Attempt,
}

/// Bounded outcome vocabulary shared by traces and metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulerOperationStatus {
  Started,
  Stopped,
  Idle,
  Completed,
  Failed,
  Cancelled,
  Unavailable,
  Deferred,
  Skipped,
  Unknown,
  LostAuthority,
  Aborted,
  Panicked,
}

/// Coarse failure category that cannot expose provider or persisted error text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulerTelemetryErrorKind {
  State,
  Worker,
}

/// Identifier-free scheduler telemetry emitted at authoritative worker boundaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchedulerTelemetryEvent {
  pub worker: SchedulerWorker,
  pub operation: SchedulerOperation,
  pub status: SchedulerOperationStatus,
  pub error_kind: Option<SchedulerTelemetryErrorKind>,
  pub duration: Duration,
  pub attempt: Option<u32>,
}

/// Receives scheduler telemetry without access to job, run, delivery, or channel identifiers.
pub trait SchedulerTelemetry: Send + Sync {
  fn record(&self, event: SchedulerTelemetryEvent);
}

#[derive(Debug, Default)]
pub struct NoopSchedulerTelemetry;

impl SchedulerTelemetry for NoopSchedulerTelemetry {
  fn record(&self, _event: SchedulerTelemetryEvent) {}
}

#[derive(Debug, Default)]
pub struct TracingSchedulerTelemetry;

impl SchedulerTelemetry for TracingSchedulerTelemetry {
  fn record(&self, event: SchedulerTelemetryEvent) {
    tracing::info!(
      target: "codeoff::scheduler",
      worker = worker_name(event.worker),
      operation = operation_name(event.operation),
      status = status_name(event.status),
      error_kind = event.error_kind.map(error_kind_name),
      duration_ms = u64::try_from(event.duration.as_millis()).unwrap_or(u64::MAX),
      attempt = event.attempt,
      "scheduler operation"
    );
  }
}

#[must_use]
pub const fn worker_name(worker: SchedulerWorker) -> &'static str {
  match worker {
    SchedulerWorker::Execution => "execution",
    SchedulerWorker::DeliveryPreparation => "delivery_preparation",
    SchedulerWorker::Delivery => "delivery",
  }
}

#[must_use]
pub const fn operation_name(operation: SchedulerOperation) -> &'static str {
  match operation {
    SchedulerOperation::Loop => "loop",
    SchedulerOperation::Tick => "tick",
    SchedulerOperation::Attempt => "attempt",
  }
}

#[must_use]
pub const fn status_name(status: SchedulerOperationStatus) -> &'static str {
  match status {
    SchedulerOperationStatus::Started => "started",
    SchedulerOperationStatus::Stopped => "stopped",
    SchedulerOperationStatus::Idle => "idle",
    SchedulerOperationStatus::Completed => "completed",
    SchedulerOperationStatus::Failed => "failed",
    SchedulerOperationStatus::Cancelled => "cancelled",
    SchedulerOperationStatus::Unavailable => "unavailable",
    SchedulerOperationStatus::Deferred => "deferred",
    SchedulerOperationStatus::Skipped => "skipped",
    SchedulerOperationStatus::Unknown => "unknown",
    SchedulerOperationStatus::LostAuthority => "lost_authority",
    SchedulerOperationStatus::Aborted => "aborted",
    SchedulerOperationStatus::Panicked => "panicked",
  }
}

pub(crate) fn record_scheduler_event(
  telemetry: &dyn SchedulerTelemetry,
  event: SchedulerTelemetryEvent,
) {
  let _ = catch_unwind(AssertUnwindSafe(|| telemetry.record(event)));
}

pub(crate) struct SchedulerLoopGuard {
  telemetry: Arc<dyn SchedulerTelemetry>,
  worker: SchedulerWorker,
  started_at: Instant,
  finished: bool,
}

impl SchedulerLoopGuard {
  pub(crate) fn start(telemetry: Arc<dyn SchedulerTelemetry>, worker: SchedulerWorker) -> Self {
    record_scheduler_event(
      telemetry.as_ref(),
      SchedulerTelemetryEvent {
        worker,
        operation: SchedulerOperation::Loop,
        status: SchedulerOperationStatus::Started,
        error_kind: None,
        duration: Duration::ZERO,
        attempt: None,
      },
    );
    Self {
      telemetry,
      worker,
      started_at: Instant::now(),
      finished: false,
    }
  }

  pub(crate) fn finish(
    mut self,
    status: SchedulerOperationStatus,
    error_kind: Option<SchedulerTelemetryErrorKind>,
  ) {
    self.record_terminal(status, error_kind);
  }

  fn record_terminal(
    &mut self,
    status: SchedulerOperationStatus,
    error_kind: Option<SchedulerTelemetryErrorKind>,
  ) {
    if self.finished {
      return;
    }
    self.finished = true;
    record_scheduler_event(
      self.telemetry.as_ref(),
      SchedulerTelemetryEvent {
        worker: self.worker,
        operation: SchedulerOperation::Loop,
        status,
        error_kind,
        duration: self.started_at.elapsed(),
        attempt: None,
      },
    );
  }
}

impl Drop for SchedulerLoopGuard {
  fn drop(&mut self) {
    if self.finished {
      return;
    }
    let status = if std::thread::panicking() {
      SchedulerOperationStatus::Panicked
    } else {
      SchedulerOperationStatus::Aborted
    };
    self.record_terminal(status, Some(SchedulerTelemetryErrorKind::Worker));
  }
}

#[must_use]
pub const fn error_kind_name(error_kind: SchedulerTelemetryErrorKind) -> &'static str {
  match error_kind {
    SchedulerTelemetryErrorKind::State => "state",
    SchedulerTelemetryErrorKind::Worker => "worker",
  }
}

#[cfg(test)]
mod tests {
  use std::sync::Mutex;

  use super::*;

  #[derive(Default)]
  struct RecordingTelemetry {
    events: Mutex<Vec<SchedulerTelemetryEvent>>,
  }

  impl SchedulerTelemetry for RecordingTelemetry {
    fn record(&self, event: SchedulerTelemetryEvent) {
      self.events.lock().expect("events").push(event);
    }
  }

  #[test]
  fn test_scheduler_telemetry_vocabulary_is_fixed_and_identifier_free() {
    assert_eq!(worker_name(SchedulerWorker::Execution), "execution");
    assert_eq!(operation_name(SchedulerOperation::Tick), "tick");
    assert_eq!(
      status_name(SchedulerOperationStatus::LostAuthority),
      "lost_authority"
    );
    assert_eq!(error_kind_name(SchedulerTelemetryErrorKind::State), "state");
  }

  #[test]
  fn test_loop_guard_emits_exactly_one_terminal_event() {
    let telemetry = Arc::new(RecordingTelemetry::default());
    let guard = SchedulerLoopGuard::start(telemetry.clone(), SchedulerWorker::Execution);
    guard.finish(SchedulerOperationStatus::Stopped, None);
    let events = telemetry.events.lock().expect("events");
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].status, SchedulerOperationStatus::Started);
    assert_eq!(events[1].status, SchedulerOperationStatus::Stopped);
  }

  #[test]
  fn test_loop_guard_reports_unwind_without_identifier_fields() {
    let telemetry = Arc::new(RecordingTelemetry::default());
    let unwind = catch_unwind(AssertUnwindSafe({
      let telemetry = telemetry.clone();
      move || {
        let _guard = SchedulerLoopGuard::start(telemetry, SchedulerWorker::Delivery);
        panic!("sentinel panic text");
      }
    }));
    assert!(unwind.is_err());
    let events = telemetry.events.lock().expect("events");
    assert_eq!(events.len(), 2);
    assert_eq!(events[1].status, SchedulerOperationStatus::Panicked);
    assert_eq!(
      events[1].error_kind,
      Some(SchedulerTelemetryErrorKind::Worker)
    );
  }

  #[test]
  fn test_panicking_telemetry_is_non_disruptive() {
    struct PanickingTelemetry;
    impl SchedulerTelemetry for PanickingTelemetry {
      fn record(&self, _event: SchedulerTelemetryEvent) {
        panic!("telemetry failed");
      }
    }

    record_scheduler_event(
      &PanickingTelemetry,
      SchedulerTelemetryEvent {
        worker: SchedulerWorker::Execution,
        operation: SchedulerOperation::Tick,
        status: SchedulerOperationStatus::Idle,
        error_kind: None,
        duration: Duration::ZERO,
        attempt: None,
      },
    );
  }
}
