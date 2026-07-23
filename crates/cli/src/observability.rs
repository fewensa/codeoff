use std::convert::Infallible;
use std::io;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use bytes::Bytes;
use codeoff_config::SchedulerRuntimeConfig;
use codeoff_runtime::scheduler_observability::{
  SchedulerOperation, SchedulerOperationStatus, SchedulerTelemetry, SchedulerTelemetryEvent,
  SchedulerWorker, TracingSchedulerTelemetry, error_kind_name, operation_name, status_name,
  worker_name,
};
use codeoff_state::{BoundedSchedulerAge, BoundedSchedulerGauge, SchedulerObservabilitySnapshot};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::header::{CACHE_CONTROL, CONTENT_TYPE};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::encoding::text::encode;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::Histogram;
use prometheus_client::registry::Registry;
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;

const METRICS_CONTENT_TYPE: &str = "application/openmetrics-text; version=1.0.0; charset=utf-8";
const JSON_CONTENT_TYPE: &str = "application/json; charset=utf-8";
const MAX_CONNECTIONS: usize = 64;
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);
pub(crate) const SNAPSHOT_INTERVAL: Duration = Duration::from_secs(5);
const SNAPSHOT_TIMEOUT: Duration = Duration::from_millis(500);
const SNAPSHOT_STALE_AFTER: Duration = Duration::from_secs(15);
const STATE_READ_TIMEOUT: Duration = Duration::from_millis(250);
const SNAPSHOT_COUNT_CAP: u64 = 100_000;
const SNAPSHOT_AGE_CAP_SECONDS: u64 = 30 * 24 * 60 * 60;

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct EventLabels {
  worker: &'static str,
  operation: &'static str,
  status: &'static str,
  error_kind: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct WorkerLabels {
  worker: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct TransitionLabels {
  kind: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LoopHealth {
  Disabled,
  Starting,
  Ready,
  Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ComponentState {
  Disabled,
  Available,
  Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SnapshotErrorKind {
  State,
  Timeout,
}

#[derive(Debug)]
struct ReadinessState {
  scheduler: ComponentState,
  run_claims: ComponentState,
  delivery_claims: ComponentState,
  delivery_provider: ComponentState,
  scheduled_executor: ComponentState,
  execution_loop: LoopHealth,
  delivery_loop: LoopHealth,
  snapshot_last_success: Option<Instant>,
  snapshot_error: Option<SnapshotErrorKind>,
}

#[derive(Clone, Default)]
struct StateMetrics {
  due_jobs: Gauge,
  pending_runs: Gauge,
  leased_runs: Gauge,
  executing_runs: Gauge,
  unknown_runs: Gauge,
  unprepared_delivery_intents: Gauge,
  pending_deliveries: Gauge,
  sending_deliveries: Gauge,
  retryable_deliveries: Gauge,
  unknown_deliveries: Gauge,
  oldest_pending_run_age: Gauge,
  oldest_unprepared_delivery_intent_age: Gauge,
  oldest_pending_delivery_age: Gauge,
  saturated_fields: Gauge,
  snapshot_refresh_success: Gauge,
  snapshot_age_seconds: Gauge,
  transitions: Family<TransitionLabels, Counter>,
  worker_capacity: Family<WorkerLabels, Gauge>,
  worker_available_slots: Family<WorkerLabels, Gauge>,
}

pub(crate) struct PrometheusSchedulerTelemetry {
  registry: Registry,
  events: Family<EventLabels, Counter>,
  durations: Family<EventLabels, Histogram>,
  last_attempt: Family<WorkerLabels, Gauge>,
  state_metrics: StateMetrics,
  readiness: RwLock<ReadinessState>,
  scheduled_executor_probe: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
  tracing: TracingSchedulerTelemetry,
}

impl PrometheusSchedulerTelemetry {
  #[cfg(test)]
  pub(crate) fn new(
    scheduler: &SchedulerRuntimeConfig,
    delivery_provider_available: bool,
    scheduled_executor_available: bool,
  ) -> Arc<Self> {
    Self::new_with_scheduled_executor_probe(
      scheduler,
      delivery_provider_available,
      scheduled_executor_available,
      None,
    )
  }

  pub(crate) fn new_with_scheduled_executor_probe(
    scheduler: &SchedulerRuntimeConfig,
    delivery_provider_available: bool,
    scheduled_executor_available: bool,
    scheduled_executor_probe: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
  ) -> Arc<Self> {
    let events = Family::default();
    let durations = Family::new_with_constructor(scheduler_duration_histogram as fn() -> Histogram);
    let last_attempt = Family::default();
    let state_metrics = StateMetrics::default();
    let mut registry = Registry::default();
    registry.register(
      "codeoff_scheduler_events",
      "Scheduler operations by fixed worker, operation, status, and error kind.",
      events.clone(),
    );
    registry.register(
      "codeoff_scheduler_operation_duration_seconds",
      "Scheduler operation duration measured with a monotonic clock.",
      durations.clone(),
    );
    registry.register(
      "codeoff_scheduler_last_attempt",
      "Last observed numeric scheduler attempt by worker.",
      last_attempt.clone(),
    );
    state_metrics.register(&mut registry);
    for worker in [
      SchedulerWorker::Execution,
      SchedulerWorker::DeliveryPreparation,
      SchedulerWorker::Delivery,
    ] {
      let labels = WorkerLabels {
        worker: worker_name(worker),
      };
      let capacity = i64::from(match worker {
        SchedulerWorker::Execution => scheduler.enabled && scheduler.run_claims_enabled,
        SchedulerWorker::DeliveryPreparation | SchedulerWorker::Delivery => {
          scheduler.enabled && scheduler.delivery_claims_enabled
        }
      });
      state_metrics
        .worker_capacity
        .get_or_create(&labels)
        .set(capacity);
      state_metrics
        .worker_available_slots
        .get_or_create(&labels)
        .set(capacity);
    }
    Arc::new(Self {
      registry,
      events,
      durations,
      last_attempt,
      state_metrics,
      readiness: RwLock::new(ReadinessState {
        scheduler: component_state(scheduler.enabled),
        run_claims: component_state(scheduler.run_claims_enabled),
        delivery_claims: component_state(scheduler.delivery_claims_enabled),
        delivery_provider: availability_state(delivery_provider_available),
        scheduled_executor: availability_state(scheduled_executor_available),
        execution_loop: if scheduler.enabled {
          LoopHealth::Starting
        } else {
          LoopHealth::Disabled
        },
        delivery_loop: if scheduler.enabled {
          LoopHealth::Starting
        } else {
          LoopHealth::Disabled
        },
        snapshot_last_success: None,
        snapshot_error: None,
      }),
      scheduled_executor_probe,
      tracing: TracingSchedulerTelemetry,
    })
  }

  pub(crate) fn encode_metrics(&self) -> Result<String, std::fmt::Error> {
    let mut body = String::new();
    let readiness = self.readiness.read().expect("scheduler readiness");
    let age = readiness
      .snapshot_last_success
      .map_or(0, |last_success| last_success.elapsed().as_secs());
    self
      .state_metrics
      .snapshot_age_seconds
      .set(i64::try_from(age).unwrap_or(i64::MAX));
    drop(readiness);
    encode(&mut body, &self.registry)?;
    Ok(body)
  }

  pub(crate) fn apply_snapshot(&self, snapshot: &SchedulerObservabilitySnapshot) {
    let metrics = &self.state_metrics;
    let gauges = [
      (&metrics.due_jobs, &snapshot.due_jobs),
      (&metrics.pending_runs, &snapshot.pending_runs),
      (&metrics.leased_runs, &snapshot.leased_runs),
      (&metrics.executing_runs, &snapshot.executing_runs),
      (&metrics.unknown_runs, &snapshot.unknown_runs),
      (
        &metrics.unprepared_delivery_intents,
        &snapshot.unprepared_delivery_intents,
      ),
      (&metrics.pending_deliveries, &snapshot.pending_deliveries),
      (&metrics.sending_deliveries, &snapshot.sending_deliveries),
      (
        &metrics.retryable_deliveries,
        &snapshot.retryable_deliveries,
      ),
      (&metrics.unknown_deliveries, &snapshot.unknown_deliveries),
    ];
    let mut saturated = 0_i64;
    for (metric, gauge) in gauges {
      metric.set(gauge_value(gauge));
      saturated += i64::from(gauge.saturated);
    }
    saturated += set_age(
      &metrics.oldest_pending_run_age,
      snapshot.oldest_pending_run_age.as_ref(),
    );
    saturated += set_age(
      &metrics.oldest_unprepared_delivery_intent_age,
      snapshot.oldest_unprepared_delivery_intent_age.as_ref(),
    );
    saturated += set_age(
      &metrics.oldest_pending_delivery_age,
      snapshot.oldest_pending_delivery_age.as_ref(),
    );
    metrics.saturated_fields.set(saturated);
    for total in &snapshot.transition_totals {
      let counter = metrics.transitions.get_or_create(&TransitionLabels {
        kind: total.kind.as_str(),
      });
      let current = counter.get();
      if total.value > current {
        counter.inc_by(total.value - current);
      }
    }
    metrics.snapshot_refresh_success.set(1);
    let mut readiness = self.readiness.write().expect("scheduler readiness");
    readiness.snapshot_last_success = Some(Instant::now());
    readiness.snapshot_error = None;
  }

  fn record_snapshot_error(&self, kind: SnapshotErrorKind) {
    self.state_metrics.snapshot_refresh_success.set(0);
    self
      .readiness
      .write()
      .expect("scheduler readiness")
      .snapshot_error = Some(kind);
  }

  fn readiness_reason(&self) -> (&'static str, bool) {
    self.readiness_reason_at(Instant::now())
  }

  fn readiness_reason_at(&self, now: Instant) -> (&'static str, bool) {
    let state = self.readiness.read().expect("scheduler readiness");
    if state.scheduler == ComponentState::Disabled {
      return ("scheduler_disabled", true);
    }
    if state.execution_loop != LoopHealth::Ready {
      return ("scheduler_loop_unavailable", false);
    }
    let scheduled_executor_available = self.scheduled_executor_probe.as_ref().map_or(
      state.scheduled_executor == ComponentState::Available,
      |probe| probe(),
    );
    if state.run_claims == ComponentState::Available && !scheduled_executor_available {
      return ("scheduler_executor_unavailable", false);
    }
    if state.delivery_claims == ComponentState::Available
      && state.delivery_provider != ComponentState::Available
    {
      return ("delivery_provider_unavailable", false);
    }
    if state.delivery_loop != LoopHealth::Ready {
      return ("delivery_loop_unavailable", false);
    }
    let Some(last_success) = state.snapshot_last_success else {
      return ("scheduler_snapshot_unavailable", false);
    };
    if now.saturating_duration_since(last_success) > SNAPSHOT_STALE_AFTER {
      return ("scheduler_snapshot_stale", false);
    }
    if state.snapshot_error.is_some() {
      return ("scheduler_snapshot_unavailable", false);
    }
    ("ready", true)
  }
}

fn scheduler_duration_histogram() -> Histogram {
  Histogram::new([0.001, 0.01, 0.1, 1.0, 5.0, 30.0, 300.0])
}

const fn component_state(enabled: bool) -> ComponentState {
  if enabled {
    ComponentState::Available
  } else {
    ComponentState::Disabled
  }
}

const fn availability_state(available: bool) -> ComponentState {
  if available {
    ComponentState::Available
  } else {
    ComponentState::Unavailable
  }
}

impl SchedulerTelemetry for PrometheusSchedulerTelemetry {
  fn record(&self, event: SchedulerTelemetryEvent) {
    let labels = EventLabels {
      worker: worker_name(event.worker),
      operation: operation_name(event.operation),
      status: status_name(event.status),
      error_kind: event.error_kind.map_or("none", error_kind_name),
    };
    self.events.get_or_create(&labels).inc();
    self
      .durations
      .get_or_create(&labels)
      .observe(event.duration.as_secs_f64());
    if let Some(attempt) = event.attempt {
      self
        .last_attempt
        .get_or_create(&WorkerLabels {
          worker: worker_name(event.worker),
        })
        .set(i64::from(attempt));
    }
    if event.operation == SchedulerOperation::Loop {
      let health = match event.status {
        SchedulerOperationStatus::Started => LoopHealth::Ready,
        SchedulerOperationStatus::Stopped
        | SchedulerOperationStatus::Failed
        | SchedulerOperationStatus::Aborted
        | SchedulerOperationStatus::Panicked => LoopHealth::Unavailable,
        _ => return self.tracing.record(event),
      };
      let mut readiness = self.readiness.write().expect("scheduler readiness");
      match event.worker {
        SchedulerWorker::Execution => readiness.execution_loop = health,
        SchedulerWorker::Delivery | SchedulerWorker::DeliveryPreparation => {
          readiness.delivery_loop = health;
        }
      }
    }
    if event.operation == SchedulerOperation::Attempt {
      let available = i64::from(event.status != SchedulerOperationStatus::Started);
      self
        .state_metrics
        .worker_available_slots
        .get_or_create(&WorkerLabels {
          worker: worker_name(event.worker),
        })
        .set(available);
    }
    self.tracing.record(event);
  }
}

impl StateMetrics {
  fn register(&self, registry: &mut Registry) {
    registry.register(
      "codeoff_scheduler_transitions",
      "Restart-safe accepted scheduler transitions by fixed kind.",
      self.transitions.clone(),
    );
    registry.register(
      "codeoff_scheduler_worker_capacity",
      "Configured scheduler worker capacity by fixed worker kind.",
      self.worker_capacity.clone(),
    );
    registry.register(
      "codeoff_scheduler_worker_available_slots",
      "Currently available scheduler worker slots by fixed worker kind.",
      self.worker_available_slots.clone(),
    );
    for (name, help, gauge) in [
      (
        "codeoff_scheduler_due_jobs",
        "Bounded due jobs.",
        &self.due_jobs,
      ),
      (
        "codeoff_scheduler_pending_runs",
        "Bounded pending runs.",
        &self.pending_runs,
      ),
      (
        "codeoff_scheduler_leased_runs",
        "Bounded leased runs.",
        &self.leased_runs,
      ),
      (
        "codeoff_scheduler_executing_runs",
        "Bounded executing runs.",
        &self.executing_runs,
      ),
      (
        "codeoff_scheduler_unknown_runs",
        "Bounded outcome-unknown runs.",
        &self.unknown_runs,
      ),
      (
        "codeoff_scheduler_unprepared_delivery_intents",
        "Bounded unprepared delivery intents.",
        &self.unprepared_delivery_intents,
      ),
      (
        "codeoff_scheduler_pending_deliveries",
        "Bounded prepared pending deliveries.",
        &self.pending_deliveries,
      ),
      (
        "codeoff_scheduler_sending_deliveries",
        "Bounded sending deliveries.",
        &self.sending_deliveries,
      ),
      (
        "codeoff_scheduler_retryable_deliveries",
        "Bounded retryable deliveries.",
        &self.retryable_deliveries,
      ),
      (
        "codeoff_scheduler_unknown_deliveries",
        "Bounded delivery-unknown deliveries.",
        &self.unknown_deliveries,
      ),
      (
        "codeoff_scheduler_oldest_pending_run_age_seconds",
        "Bounded oldest pending run age.",
        &self.oldest_pending_run_age,
      ),
      (
        "codeoff_scheduler_oldest_unprepared_delivery_intent_age_seconds",
        "Bounded oldest unprepared delivery intent age.",
        &self.oldest_unprepared_delivery_intent_age,
      ),
      (
        "codeoff_scheduler_oldest_pending_delivery_age_seconds",
        "Bounded oldest prepared pending delivery age.",
        &self.oldest_pending_delivery_age,
      ),
      (
        "codeoff_scheduler_saturated_fields",
        "Number of snapshot fields saturated at their cap.",
        &self.saturated_fields,
      ),
      (
        "codeoff_scheduler_snapshot_refresh_success",
        "Whether the most recent snapshot refresh succeeded.",
        &self.snapshot_refresh_success,
      ),
      (
        "codeoff_scheduler_snapshot_age_seconds",
        "Age of the last successful in-memory snapshot.",
        &self.snapshot_age_seconds,
      ),
    ] {
      registry.register(name, help, gauge.clone());
    }
  }
}

fn gauge_value(gauge: &BoundedSchedulerGauge) -> i64 {
  i64::try_from(gauge.value).unwrap_or(i64::MAX)
}

fn set_age(metric: &Gauge, age: Option<&BoundedSchedulerAge>) -> i64 {
  let Some(age) = age else {
    metric.set(-1);
    return 0;
  };
  metric.set(i64::try_from(age.value).unwrap_or(i64::MAX));
  i64::from(age.saturated)
}

#[derive(Debug)]
pub(crate) struct SnapshotReadError;

#[async_trait]
pub(crate) trait SchedulerSnapshotSource: Send + Sync {
  async fn scheduler_snapshot(
    &self,
    now: i64,
    count_cap: u64,
    age_cap_seconds: u64,
  ) -> Result<SchedulerObservabilitySnapshot, SnapshotReadError>;
}

#[async_trait]
impl SchedulerSnapshotSource for codeoff_state::StateStore {
  async fn scheduler_snapshot(
    &self,
    now: i64,
    count_cap: u64,
    age_cap_seconds: u64,
  ) -> Result<SchedulerObservabilitySnapshot, SnapshotReadError> {
    self
      .scheduler_observability_snapshot(now, count_cap, age_cap_seconds)
      .await
      .map_err(|_| SnapshotReadError)
  }
}

pub(crate) async fn refresh_scheduler_snapshot(
  source: &dyn SchedulerSnapshotSource,
  telemetry: &PrometheusSchedulerTelemetry,
) {
  let now = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .map_or(0, |duration| {
      i64::try_from(duration.as_secs()).unwrap_or(i64::MAX)
    });
  match tokio::time::timeout(
    SNAPSHOT_TIMEOUT,
    source.scheduler_snapshot(now, SNAPSHOT_COUNT_CAP, SNAPSHOT_AGE_CAP_SECONDS),
  )
  .await
  {
    Ok(Ok(snapshot)) => telemetry.apply_snapshot(&snapshot),
    Ok(Err(_)) => telemetry.record_snapshot_error(SnapshotErrorKind::State),
    Err(_) => telemetry.record_snapshot_error(SnapshotErrorKind::Timeout),
  }
}

pub(crate) struct OperationalHttpServer {
  listener: TcpListener,
  telemetry: Arc<PrometheusSchedulerTelemetry>,
  readiness_probe: Arc<dyn ReadinessProbe>,
  #[cfg(test)]
  panic_next_connection: Arc<std::sync::atomic::AtomicBool>,
}

#[async_trait]
trait ReadinessProbe: Send + Sync {
  async fn check_readable(&self) -> bool;
}

#[async_trait]
impl ReadinessProbe for codeoff_state::StateStore {
  async fn check_readable(&self) -> bool {
    codeoff_state::StateStore::check_readable(self)
      .await
      .is_ok()
  }
}

impl OperationalHttpServer {
  pub(crate) async fn bind(
    bind: &str,
    telemetry: Arc<PrometheusSchedulerTelemetry>,
    state: codeoff_state::StateStore,
  ) -> io::Result<Self> {
    Self::bind_with_probe(bind, telemetry, Arc::new(state)).await
  }

  async fn bind_with_probe(
    bind: &str,
    telemetry: Arc<PrometheusSchedulerTelemetry>,
    readiness_probe: Arc<dyn ReadinessProbe>,
  ) -> io::Result<Self> {
    let listener = TcpListener::bind(bind).await?;
    Ok(Self {
      listener,
      telemetry,
      readiness_probe,
      #[cfg(test)]
      panic_next_connection: Arc::new(std::sync::atomic::AtomicBool::new(false)),
    })
  }

  #[cfg(test)]
  pub(crate) fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
    self.listener.local_addr()
  }

  #[cfg(test)]
  pub(crate) fn panic_next_connection(&self) {
    self
      .panic_next_connection
      .store(true, std::sync::atomic::Ordering::SeqCst);
  }

  pub(crate) async fn run_until(self, mut shutdown: watch::Receiver<bool>) -> io::Result<()> {
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let mut connections = JoinSet::new();
    loop {
      tokio::select! {
        biased;
        changed = shutdown.changed() => {
          if changed.is_err() || *shutdown.borrow() {
            break;
          }
        }
        joined = connections.join_next(), if !connections.is_empty() => {
          let Some(joined) = joined else {
            continue;
          };
          joined.map_err(io::Error::other)?;
        }
        accepted = self.listener.accept() => {
          let (stream, _) = accepted?;
          let Ok(permit) = permits.clone().try_acquire_owned() else {
            drop(stream);
            continue;
          };
          let telemetry = self.telemetry.clone();
          let readiness_probe = self.readiness_probe.clone();
          #[cfg(test)]
          let panic_next_connection = self.panic_next_connection.clone();
          connections.spawn(async move {
            #[cfg(test)]
            assert!(
              !panic_next_connection.swap(false, std::sync::atomic::Ordering::SeqCst),
              "injected operational HTTP connection panic"
            );
            let service = service_fn(move |request| {
              route_request(request, telemetry.clone(), readiness_probe.clone())
            });
            let connection = http1::Builder::new()
              .keep_alive(false)
              .max_buf_size(8 * 1024)
              .serve_connection(TokioIo::new(stream), service);
            let _ = tokio::time::timeout(CONNECTION_TIMEOUT, connection).await;
            drop(permit);
          });
        }
      }
    }
    while let Some(joined) = connections.join_next().await {
      joined.map_err(io::Error::other)?;
    }
    Ok(())
  }
}

async fn route_request(
  request: Request<Incoming>,
  telemetry: Arc<PrometheusSchedulerTelemetry>,
  readiness_probe: Arc<dyn ReadinessProbe>,
) -> Result<Response<Full<Bytes>>, Infallible> {
  let response = if request.method() != Method::GET {
    fixed_response(
      StatusCode::METHOD_NOT_ALLOWED,
      JSON_CONTENT_TYPE,
      r#"{"error":"method_not_allowed"}"#,
    )
  } else if request.uri().query().is_some() {
    fixed_response(
      StatusCode::NOT_FOUND,
      JSON_CONTENT_TYPE,
      r#"{"error":"not_found"}"#,
    )
  } else {
    match request.uri().path() {
      "/healthz" => fixed_response(StatusCode::OK, JSON_CONTENT_TYPE, r#"{"status":"alive"}"#),
      "/metrics" => match telemetry.encode_metrics() {
        Ok(body) => owned_response(StatusCode::OK, METRICS_CONTENT_TYPE, body),
        Err(_) => fixed_response(
          StatusCode::INTERNAL_SERVER_ERROR,
          JSON_CONTENT_TYPE,
          r#"{"error":"metrics_encode_failed"}"#,
        ),
      },
      "/readyz" => readiness_response(readiness_probe.as_ref(), &telemetry).await,
      _ => fixed_response(
        StatusCode::NOT_FOUND,
        JSON_CONTENT_TYPE,
        r#"{"error":"not_found"}"#,
      ),
    }
  };
  Ok(response)
}

async fn readiness_response(
  readiness_probe: &dyn ReadinessProbe,
  telemetry: &PrometheusSchedulerTelemetry,
) -> Response<Full<Bytes>> {
  let readable = tokio::time::timeout(STATE_READ_TIMEOUT, readiness_probe.check_readable()).await;
  if !matches!(readable, Ok(true)) {
    return fixed_response(
      StatusCode::SERVICE_UNAVAILABLE,
      JSON_CONTENT_TYPE,
      r#"{"ready":false,"reason":"state_unavailable"}"#,
    );
  }
  let (reason, ready) = telemetry.readiness_reason();
  let status = if ready {
    StatusCode::OK
  } else {
    StatusCode::SERVICE_UNAVAILABLE
  };
  owned_response(
    status,
    JSON_CONTENT_TYPE,
    format!(r#"{{"ready":{ready},"reason":"{reason}"}}"#),
  )
}

fn fixed_response(
  status: StatusCode,
  content_type: &'static str,
  body: &'static str,
) -> Response<Full<Bytes>> {
  owned_response(status, content_type, body.to_owned())
}

fn owned_response(
  status: StatusCode,
  content_type: &'static str,
  body: String,
) -> Response<Full<Bytes>> {
  let mut response = Response::new(Full::new(Bytes::from(body)));
  *response.status_mut() = status;
  response.headers_mut().insert(
    CONTENT_TYPE,
    hyper::header::HeaderValue::from_static(content_type),
  );
  response.headers_mut().insert(
    CACHE_CONTROL,
    hyper::header::HeaderValue::from_static("no-store"),
  );
  response
}

pub(crate) fn init_scheduler_tracing() {
  let _ = tracing_subscriber::fmt()
    .json()
    .with_ansi(false)
    .with_target(true)
    .try_init();
}

#[cfg(test)]
mod tests {
  use std::net::SocketAddr;
  use std::sync::Mutex;
  use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

  use codeoff_runtime::scheduler_observability::SchedulerTelemetryErrorKind;
  use http_body_util::BodyExt as _;
  use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

  use super::*;

  struct CountingReadinessProbe {
    calls: AtomicUsize,
  }

  #[derive(Clone, Copy)]
  enum ProbeOutcome {
    False,
    Hang,
  }

  struct FaultReadinessProbe {
    calls: AtomicUsize,
    outcome: ProbeOutcome,
  }

  #[derive(Clone)]
  enum SnapshotOutcome {
    Success(Box<SchedulerObservabilitySnapshot>),
    Hang,
  }

  struct ControlledSnapshotSource {
    outcome: Mutex<SnapshotOutcome>,
  }

  #[async_trait]
  impl ReadinessProbe for CountingReadinessProbe {
    async fn check_readable(&self) -> bool {
      self.calls.fetch_add(1, Ordering::SeqCst);
      true
    }
  }

  #[async_trait]
  impl ReadinessProbe for FaultReadinessProbe {
    async fn check_readable(&self) -> bool {
      self.calls.fetch_add(1, Ordering::SeqCst);
      match self.outcome {
        ProbeOutcome::False => false,
        ProbeOutcome::Hang => std::future::pending().await,
      }
    }
  }

  #[async_trait]
  impl SchedulerSnapshotSource for ControlledSnapshotSource {
    async fn scheduler_snapshot(
      &self,
      _now: i64,
      _count_cap: u64,
      _age_cap_seconds: u64,
    ) -> Result<SchedulerObservabilitySnapshot, SnapshotReadError> {
      let outcome = self.outcome.lock().expect("snapshot outcome").clone();
      match outcome {
        SnapshotOutcome::Success(snapshot) => Ok(*snapshot),
        SnapshotOutcome::Hang => std::future::pending().await,
      }
    }
  }

  async fn test_state() -> (tempfile::TempDir, codeoff_state::StateStore) {
    let temp = tempfile::tempdir().expect("tempdir");
    let state = codeoff_state::StateStore::initialize(&temp.path().join("state"), None)
      .await
      .expect("state");
    (temp, state)
  }

  fn scheduler_config(
    enabled: bool,
    run_claims_enabled: bool,
    delivery_claims_enabled: bool,
  ) -> SchedulerRuntimeConfig {
    SchedulerRuntimeConfig {
      enabled,
      run_claims_enabled,
      delivery_claims_enabled,
      ..SchedulerRuntimeConfig::default()
    }
  }

  async fn response_body(response: Response<Full<Bytes>>) -> String {
    let body = response
      .into_body()
      .collect()
      .await
      .expect("response body")
      .to_bytes();
    String::from_utf8(body.to_vec()).expect("UTF-8 response")
  }

  fn record_loop_started(telemetry: &PrometheusSchedulerTelemetry, worker: SchedulerWorker) {
    telemetry.record(SchedulerTelemetryEvent {
      worker,
      operation: SchedulerOperation::Loop,
      status: SchedulerOperationStatus::Started,
      error_kind: None,
      duration: Duration::ZERO,
      attempt: None,
    });
  }

  fn empty_snapshot(value: u64) -> SchedulerObservabilitySnapshot {
    let gauge = BoundedSchedulerGauge {
      value,
      saturated: false,
    };
    SchedulerObservabilitySnapshot {
      due_jobs: gauge.clone(),
      pending_runs: gauge.clone(),
      leased_runs: gauge.clone(),
      executing_runs: gauge.clone(),
      unknown_runs: gauge.clone(),
      unprepared_delivery_intents: gauge.clone(),
      pending_deliveries: gauge.clone(),
      sending_deliveries: gauge.clone(),
      retryable_deliveries: gauge.clone(),
      unknown_deliveries: gauge,
      oldest_pending_run_age: None,
      oldest_unprepared_delivery_intent_age: None,
      oldest_pending_delivery_age: None,
      transition_totals: Vec::new(),
    }
  }

  async fn request(address: SocketAddr, request: &[u8]) -> String {
    let mut stream = tokio::net::TcpStream::connect(address)
      .await
      .expect("connect operational HTTP server");
    stream.write_all(request).await.expect("write request");
    let mut response = Vec::new();
    stream
      .read_to_end(&mut response)
      .await
      .expect("read response");
    String::from_utf8(response).expect("UTF-8 HTTP response")
  }

  fn assert_connection_closed(result: io::Result<usize>) {
    match result {
      Ok(0) => {}
      Err(error)
        if matches!(
          error.kind(),
          io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe
        ) => {}
      other => panic!("expected closed connection, got {other:?}"),
    }
  }

  async fn assert_faulty_readiness_probe(outcome: ProbeOutcome) {
    let telemetry =
      PrometheusSchedulerTelemetry::new(&scheduler_config(false, false, false), false, false);
    let readiness_probe = Arc::new(FaultReadinessProbe {
      calls: AtomicUsize::new(0),
      outcome,
    });
    let server =
      OperationalHttpServer::bind_with_probe("127.0.0.1:0", telemetry, readiness_probe.clone())
        .await
        .expect("bind server");
    let address = server.local_addr().expect("server address");
    let (shutdown, shutdown_rx) = watch::channel(false);
    let task = tokio::spawn(server.run_until(shutdown_rx));

    for path in ["/healthz", "/metrics"] {
      let response = request(
        address,
        format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").as_bytes(),
      )
      .await;
      assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    }
    assert_eq!(readiness_probe.calls.load(Ordering::SeqCst), 0);

    let readiness = request(
      address,
      b"GET /readyz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(readiness.starts_with("HTTP/1.1 503 Service Unavailable\r\n"));
    assert!(readiness.ends_with(r#"{"ready":false,"reason":"state_unavailable"}"#));
    assert_eq!(readiness_probe.calls.load(Ordering::SeqCst), 1);

    shutdown.send(true).expect("shutdown server");
    tokio::time::timeout(Duration::from_secs(1), task)
      .await
      .expect("server shutdown deadline")
      .expect("server task")
      .expect("server shutdown");
  }

  #[tokio::test]
  async fn test_readiness_reports_disabled_without_scheduler_dependencies() {
    let (_temp, state) = test_state().await;
    let telemetry =
      PrometheusSchedulerTelemetry::new(&scheduler_config(false, false, false), false, false);

    let response = readiness_response(&state, &telemetry).await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
      response_body(response).await,
      r#"{"ready":true,"reason":"scheduler_disabled"}"#
    );
  }

  #[tokio::test]
  async fn test_readiness_fails_closed_for_required_components() {
    let (_temp, state) = test_state().await;
    let starting =
      PrometheusSchedulerTelemetry::new(&scheduler_config(true, false, false), false, false);
    starting.apply_snapshot(&empty_snapshot(0));
    let response = readiness_response(&state, &starting).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(
      response_body(response)
        .await
        .contains("scheduler_loop_unavailable")
    );

    let executor_missing =
      PrometheusSchedulerTelemetry::new(&scheduler_config(true, true, false), false, false);
    executor_missing.apply_snapshot(&empty_snapshot(0));
    record_loop_started(&executor_missing, SchedulerWorker::Execution);
    record_loop_started(&executor_missing, SchedulerWorker::DeliveryPreparation);
    let response = readiness_response(&state, &executor_missing).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(
      response_body(response)
        .await
        .contains("scheduler_executor_unavailable")
    );

    let executor_ready =
      PrometheusSchedulerTelemetry::new(&scheduler_config(true, true, false), false, true);
    executor_ready.apply_snapshot(&empty_snapshot(0));
    record_loop_started(&executor_ready, SchedulerWorker::Execution);
    record_loop_started(&executor_ready, SchedulerWorker::DeliveryPreparation);
    let response = readiness_response(&state, &executor_ready).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
      response_body(response).await,
      r#"{"ready":true,"reason":"ready"}"#
    );

    let provider_missing =
      PrometheusSchedulerTelemetry::new(&scheduler_config(true, false, true), false, false);
    provider_missing.apply_snapshot(&empty_snapshot(0));
    record_loop_started(&provider_missing, SchedulerWorker::Execution);
    record_loop_started(&provider_missing, SchedulerWorker::DeliveryPreparation);
    let response = readiness_response(&state, &provider_missing).await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(
      response_body(response)
        .await
        .contains("delivery_provider_unavailable")
    );
  }

  #[test]
  fn test_readiness_tracks_live_scheduled_executor_rotation() {
    let available = Arc::new(AtomicBool::new(true));
    let probe_state = Arc::clone(&available);
    let probe: Arc<dyn Fn() -> bool + Send + Sync> =
      Arc::new(move || probe_state.load(Ordering::Acquire));
    let telemetry = PrometheusSchedulerTelemetry::new_with_scheduled_executor_probe(
      &scheduler_config(true, true, false),
      false,
      true,
      Some(probe),
    );
    telemetry.apply_snapshot(&empty_snapshot(0));
    record_loop_started(&telemetry, SchedulerWorker::Execution);
    record_loop_started(&telemetry, SchedulerWorker::DeliveryPreparation);

    assert_eq!(telemetry.readiness_reason(), ("ready", true));
    available.store(false, Ordering::Release);
    assert_eq!(
      telemetry.readiness_reason(),
      ("scheduler_executor_unavailable", false)
    );
    available.store(true, Ordering::Release);
    assert_eq!(telemetry.readiness_reason(), ("ready", true));
  }

  #[tokio::test]
  async fn test_snapshot_timeout_preserves_cache_becomes_stale_and_recovers() {
    let telemetry =
      PrometheusSchedulerTelemetry::new(&scheduler_config(true, false, false), false, false);
    let source = ControlledSnapshotSource {
      outcome: Mutex::new(SnapshotOutcome::Success(Box::new(empty_snapshot(7)))),
    };
    refresh_scheduler_snapshot(&source, &telemetry).await;
    record_loop_started(&telemetry, SchedulerWorker::Execution);
    record_loop_started(&telemetry, SchedulerWorker::DeliveryPreparation);
    assert_eq!(telemetry.readiness_reason(), ("ready", true));
    let first_success = telemetry
      .readiness
      .read()
      .expect("scheduler readiness")
      .snapshot_last_success
      .expect("snapshot success");

    *source.outcome.lock().expect("snapshot outcome") = SnapshotOutcome::Hang;
    let timeout_started = Instant::now();
    refresh_scheduler_snapshot(&source, &telemetry).await;

    assert!(timeout_started.elapsed() >= SNAPSHOT_TIMEOUT);
    assert_eq!(
      telemetry.readiness_reason(),
      ("scheduler_snapshot_unavailable", false)
    );
    let metrics = telemetry.encode_metrics().expect("metrics");
    assert!(metrics.contains("codeoff_scheduler_due_jobs 7"));
    assert!(metrics.contains("codeoff_scheduler_snapshot_refresh_success 0"));
    assert_eq!(
      telemetry.readiness_reason_at(first_success + SNAPSHOT_STALE_AFTER + Duration::from_secs(1)),
      ("scheduler_snapshot_stale", false)
    );

    *source.outcome.lock().expect("snapshot outcome") =
      SnapshotOutcome::Success(Box::new(empty_snapshot(9)));
    refresh_scheduler_snapshot(&source, &telemetry).await;

    assert_eq!(telemetry.readiness_reason(), ("ready", true));
    let metrics = telemetry.encode_metrics().expect("metrics");
    assert!(metrics.contains("codeoff_scheduler_due_jobs 9"));
    assert!(metrics.contains("codeoff_scheduler_snapshot_refresh_success 1"));
  }

  #[tokio::test]
  async fn test_readiness_false_probe_is_fixed_sanitized_and_route_isolated() {
    assert_faulty_readiness_probe(ProbeOutcome::False).await;
  }

  #[tokio::test]
  async fn test_readiness_timeout_is_fixed_sanitized_and_route_isolated() {
    let started = Instant::now();
    assert_faulty_readiness_probe(ProbeOutcome::Hang).await;
    assert!(started.elapsed() >= STATE_READ_TIMEOUT);
  }

  #[test]
  fn test_metrics_use_fixed_labels_and_numeric_attempt_gauge() {
    let telemetry =
      PrometheusSchedulerTelemetry::new(&scheduler_config(false, false, false), false, false);
    telemetry.record(SchedulerTelemetryEvent {
      worker: SchedulerWorker::Delivery,
      operation: SchedulerOperation::Attempt,
      status: SchedulerOperationStatus::Failed,
      error_kind: Some(SchedulerTelemetryErrorKind::State),
      duration: Duration::from_millis(12),
      attempt: Some(42),
    });

    let metrics = telemetry.encode_metrics().expect("metrics");

    assert!(metrics.contains("worker=\"delivery\""));
    assert!(metrics.contains("operation=\"attempt\""));
    assert!(metrics.contains("status=\"failed\""));
    assert!(metrics.contains("error_kind=\"state\""));
    assert!(metrics.contains("codeoff_scheduler_last_attempt{worker=\"delivery\"} 42"));
    assert!(!metrics.contains("attempt=\"42\""));
  }

  #[test]
  fn test_durable_transition_metrics_are_absolute_fixed_and_restart_seeded() {
    let telemetry =
      PrometheusSchedulerTelemetry::new(&scheduler_config(true, true, true), true, true);
    let mut snapshot = empty_snapshot(0);
    snapshot.transition_totals = codeoff_state::SchedulerTransitionKind::ALL
      .into_iter()
      .map(|kind| codeoff_state::SchedulerTransitionTotal { kind, value: 0 })
      .collect();
    snapshot.transition_totals[0].value = 7;
    telemetry.apply_snapshot(&snapshot);
    telemetry.apply_snapshot(&snapshot);

    let metrics = telemetry.encode_metrics().expect("metrics");
    assert!(
      metrics.contains("codeoff_scheduler_transitions_total{kind=\"occurrences_materialized\"} 7")
    );
    assert!(metrics.contains("codeoff_scheduler_worker_capacity{worker=\"execution\"} 1"));
    assert!(metrics.contains("codeoff_scheduler_worker_available_slots{worker=\"execution\"} 1"));
    for forbidden in [
      "job_id",
      "run_id",
      "delivery_id",
      "owner",
      "channel",
      "user",
      "thread",
      "prompt",
      "result",
      "token",
      "secret",
    ] {
      assert!(!metrics.contains(forbidden), "forbidden label: {forbidden}");
    }

    telemetry.record(SchedulerTelemetryEvent {
      worker: SchedulerWorker::Execution,
      operation: SchedulerOperation::Attempt,
      status: SchedulerOperationStatus::Started,
      error_kind: None,
      duration: Duration::ZERO,
      attempt: None,
    });
    let busy = telemetry.encode_metrics().expect("busy metrics");
    assert!(busy.contains("codeoff_scheduler_worker_available_slots{worker=\"execution\"} 0"));
  }

  #[tokio::test]
  async fn test_operational_http_server_exposes_only_exact_bounded_get_routes() {
    let (_temp, state) = test_state().await;
    let telemetry =
      PrometheusSchedulerTelemetry::new(&scheduler_config(false, false, false), false, false);
    refresh_scheduler_snapshot(&state, &telemetry).await;
    let readiness_probe = Arc::new(CountingReadinessProbe {
      calls: AtomicUsize::new(0),
    });
    let server =
      OperationalHttpServer::bind_with_probe("127.0.0.1:0", telemetry, readiness_probe.clone())
        .await
        .expect("bind server");
    let address = server.local_addr().expect("server address");
    let (shutdown, shutdown_rx) = watch::channel(false);
    let task = tokio::spawn(server.run_until(shutdown_rx));

    let health = request(
      address,
      b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(health.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(health.contains("content-type: application/json; charset=utf-8"));
    assert!(health.ends_with(r#"{"status":"alive"}"#));

    let metrics = request(
      address,
      b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(metrics.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(metrics.contains(METRICS_CONTENT_TYPE));
    assert!(metrics.contains("codeoff_scheduler_due_jobs"));
    assert_eq!(readiness_probe.calls.load(Ordering::SeqCst), 0);

    let readiness = request(
      address,
      b"GET /readyz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(readiness.starts_with("HTTP/1.1 200 OK\r\n"));
    assert_eq!(readiness_probe.calls.load(Ordering::SeqCst), 1);

    let method = request(
      address,
      b"POST /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: 999999\r\n\r\n",
    )
    .await;
    assert!(method.starts_with("HTTP/1.1 405 Method Not Allowed\r\n"));

    let secret = "identifier-must-not-be-reflected";
    let unknown = request(
      address,
      format!("GET /healthz?{secret} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .as_bytes(),
    )
    .await;
    assert!(unknown.starts_with("HTTP/1.1 404 Not Found\r\n"));
    assert!(!unknown.contains(secret));

    shutdown.send(true).expect("shutdown server");
    tokio::time::timeout(Duration::from_secs(1), task)
      .await
      .expect("server shutdown deadline")
      .expect("server task")
      .expect("server shutdown");
  }

  #[tokio::test]
  async fn test_operational_http_server_bind_collision_is_fatal() {
    let (_temp, state) = test_state().await;
    let telemetry =
      PrometheusSchedulerTelemetry::new(&scheduler_config(false, false, false), false, false);
    let first = OperationalHttpServer::bind("127.0.0.1:0", telemetry.clone(), state.clone())
      .await
      .expect("first bind");
    let address = first.local_addr().expect("first address");

    let error = OperationalHttpServer::bind(&address.to_string(), telemetry, state)
      .await
      .err()
      .expect("bind collision");

    assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
  }

  #[tokio::test]
  async fn test_operational_http_connection_panic_is_fatal_without_later_traffic() {
    let (_temp, state) = test_state().await;
    let telemetry =
      PrometheusSchedulerTelemetry::new(&scheduler_config(false, false, false), false, false);
    let server = OperationalHttpServer::bind("127.0.0.1:0", telemetry, state)
      .await
      .expect("bind server");
    let address = server.local_addr().expect("server address");
    server.panic_next_connection();
    let (_shutdown, shutdown_rx) = watch::channel(false);
    let task = tokio::spawn(server.run_until(shutdown_rx));

    let _connection = tokio::net::TcpStream::connect(address)
      .await
      .expect("connect fault-injected request");
    let error = tokio::time::timeout(Duration::from_secs(1), task)
      .await
      .expect("connection panic propagation deadline")
      .expect("server task")
      .expect_err("connection panic must be fatal");

    assert!(error.to_string().contains("panicked"));
  }

  #[tokio::test]
  async fn test_operational_http_connection_panic_is_not_starved_by_accept_pressure() {
    let (_temp, state) = test_state().await;
    let telemetry =
      PrometheusSchedulerTelemetry::new(&scheduler_config(false, false, false), false, false);
    let server = OperationalHttpServer::bind("127.0.0.1:0", telemetry, state)
      .await
      .expect("bind server");
    let address = server.local_addr().expect("server address");
    server.panic_next_connection();
    let mut preloaded = Vec::new();
    for _ in 0..16 {
      preloaded.push(
        tokio::net::TcpStream::connect(address)
          .await
          .expect("preload connection"),
      );
    }
    let attempts = Arc::new(AtomicUsize::new(0));
    let mut pressure = JoinSet::new();
    for _ in 0..8 {
      let attempts = attempts.clone();
      pressure.spawn(async move {
        while let Ok(stream) = tokio::net::TcpStream::connect(address).await {
          attempts.fetch_add(1, Ordering::SeqCst);
          drop(stream);
        }
      });
    }
    tokio::time::timeout(Duration::from_secs(1), async {
      while attempts.load(Ordering::SeqCst) == 0 {
        tokio::task::yield_now().await;
      }
    })
    .await
    .expect("accept pressure startup deadline");
    let (_shutdown, shutdown_rx) = watch::channel(false);
    let task = tokio::spawn(server.run_until(shutdown_rx));

    let error = tokio::time::timeout(Duration::from_secs(1), task)
      .await
      .expect("pressured panic propagation deadline")
      .expect("server task")
      .expect_err("connection panic must be fatal under accept pressure");

    assert!(error.to_string().contains("panicked"));
    assert!(attempts.load(Ordering::SeqCst) > 0);
    drop(preloaded);
    while let Some(joined) = pressure.join_next().await {
      joined.expect("pressure task");
    }
  }

  #[tokio::test]
  async fn test_operational_http_shutdown_surfaces_completed_connection_panic() {
    let (_temp, state) = test_state().await;
    let telemetry =
      PrometheusSchedulerTelemetry::new(&scheduler_config(false, false, false), false, false);
    let server = OperationalHttpServer::bind("127.0.0.1:0", telemetry, state)
      .await
      .expect("bind server");
    let address = server.local_addr().expect("server address");
    server.panic_next_connection();
    let (shutdown, shutdown_rx) = watch::channel(false);
    let task = tokio::spawn(server.run_until(shutdown_rx));
    let _connection = tokio::net::TcpStream::connect(address)
      .await
      .expect("connect fault-injected request");
    tokio::task::yield_now().await;
    let _ = shutdown.send(true);

    let error = tokio::time::timeout(Duration::from_secs(1), task)
      .await
      .expect("shutdown panic propagation deadline")
      .expect("server task")
      .expect_err("shutdown must not hide connection panic");

    assert!(error.to_string().contains("panicked"));
  }

  #[tokio::test]
  async fn test_operational_http_server_bounds_headers_connections_and_idle_time() {
    let (_temp, state) = test_state().await;
    let telemetry =
      PrometheusSchedulerTelemetry::new(&scheduler_config(false, false, false), false, false);
    let server = OperationalHttpServer::bind("127.0.0.1:0", telemetry, state)
      .await
      .expect("bind server");
    let address = server.local_addr().expect("server address");
    let (shutdown, shutdown_rx) = watch::channel(false);
    let task = tokio::spawn(server.run_until(shutdown_rx));

    let mut oversized = tokio::net::TcpStream::connect(address)
      .await
      .expect("connect oversized request");
    let oversized_request = format!(
      "GET /healthz HTTP/1.1\r\nHost: localhost\r\nX-Large: {}\r\n\r\n",
      "a".repeat(9 * 1024)
    );
    oversized
      .write_all(oversized_request.as_bytes())
      .await
      .expect("write oversized request");
    let mut response = Vec::new();
    oversized
      .read_to_end(&mut response)
      .await
      .expect("read oversized response");
    let response = String::from_utf8(response).expect("UTF-8 oversized response");
    assert!(!response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(!response.contains(r#"{"status":"alive"}"#));

    let mut idle = tokio::net::TcpStream::connect(address)
      .await
      .expect("connect idle request");
    idle
      .write_all(b"GET /healthz HTTP/1.1\r\n")
      .await
      .expect("write partial request");
    let mut byte = [0_u8; 1];
    let idle_started = Instant::now();
    let idle_result = tokio::time::timeout(
      CONNECTION_TIMEOUT + Duration::from_secs(1),
      idle.read(&mut byte),
    )
    .await
    .expect("idle connection close deadline");
    assert_connection_closed(idle_result);
    assert!(idle_started.elapsed() >= CONNECTION_TIMEOUT);

    let health = request(
      address,
      b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(health.starts_with("HTTP/1.1 200 OK\r\n"));

    let mut held = Vec::with_capacity(MAX_CONNECTIONS);
    for _ in 0..MAX_CONNECTIONS {
      held.push(
        tokio::net::TcpStream::connect(address)
          .await
          .expect("connect held request"),
      );
    }
    let mut excess = tokio::net::TcpStream::connect(address)
      .await
      .expect("connect excess request");
    let excess_result = tokio::time::timeout(Duration::from_secs(1), excess.read(&mut byte))
      .await
      .expect("excess connection close deadline");
    assert_connection_closed(excess_result);
    drop(held);

    shutdown.send(true).expect("shutdown server");
    tokio::time::timeout(Duration::from_secs(1), task)
      .await
      .expect("server shutdown deadline")
      .expect("server task")
      .expect("server shutdown");
  }
}
