use std::any::Any;
use std::fmt::Write as _;
use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use codeoff_agent_contract::{
  AgentTask, InvocationPrincipal, InvocationSource, PreviousSuccessContext, SessionMode, ToolPolicy,
};
use codeoff_core::SchedulerOperationalPolicy;
use codeoff_state::{
  AttestedExecutionProfileSnapshot, ClaimedScheduledRun, ExpiredRunReclaimOutcome, RunLeaseBinding,
  ScheduledExecutionDisposition, ScheduledExecutionTerminal, ScheduledExecutorAdmission,
  ScheduledPrepareAuthority, ScheduledRunLateEvidenceKind, ScheduledRunResult, StateError,
  StateStore, TransportConvergence,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::sync::{Semaphore, oneshot, watch};
use tokio::task::JoinHandle;

use crate::channel_tools::CHANNEL_DYNAMIC_TOOL_NAMES;
use crate::schedule_tools::SCHEDULE_DYNAMIC_TOOL_NAMES;
use crate::scheduler_observability::{
  NoopSchedulerTelemetry, SchedulerLoopGuard, SchedulerOperation, SchedulerOperationStatus,
  SchedulerTelemetry, SchedulerTelemetryErrorKind, SchedulerTelemetryEvent, SchedulerWorker,
  record_scheduler_event,
};

static PREPARE_NONCE_SEQUENCE: AtomicU64 = AtomicU64::new(1);
const SCHEDULER_DRAIN_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_LOG_ERROR_BYTES: usize = 512;

#[derive(Clone)]
pub struct GlobalTurnBudget {
  semaphore: Arc<Semaphore>,
}

impl GlobalTurnBudget {
  #[must_use]
  pub fn new(max_parallel_turns: usize) -> Self {
    Self {
      semaphore: Arc::new(Semaphore::new(max_parallel_turns.max(1))),
    }
  }

  /// Acquires one global agent-turn slot.
  ///
  /// # Errors
  /// Returns an error when the budget has been closed.
  pub async fn acquire(&self) -> Result<tokio::sync::OwnedSemaphorePermit, StateError> {
    Arc::clone(&self.semaphore)
      .acquire_owned()
      .await
      .map_err(|_| StateError::InvalidSchedulerState {
        reason: "global turn budget is closed".to_owned(),
      })
  }

  #[cfg(test)]
  fn available_permits(&self) -> usize {
    self.semaphore.available_permits()
  }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScheduledWorkerConfig {
  pub enabled: bool,
  pub run_claims_enabled: bool,
  pub operational_policy: SchedulerOperationalPolicy,
}

pub struct ScheduledWorkerHandle {
  shutdown: watch::Sender<bool>,
  join: Option<JoinHandle<()>>,
  guardians: Arc<BlockingGuardianRegistry>,
  worker_failed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScheduledWorkerShutdown {
  Clean,
  NonClean,
}

#[derive(Clone)]
pub struct ScheduledExecutor {
  backend: Arc<dyn ScheduledExecutionBackend>,
}

impl ScheduledExecutor {
  #[must_use]
  pub fn new(backend: Arc<dyn ScheduledExecutionBackend>) -> Self {
    Self { backend }
  }

  #[must_use]
  pub fn is_ready(&self) -> bool {
    self.backend.readiness() == ExecutorReadiness::Ready
  }
}

impl ScheduledWorkerHandle {
  /// Stops materialization and prevents new scheduled-run claims.
  pub fn request_shutdown(&self) {
    let _ = self.shutdown.send(true);
  }

  /// Stops materialization and new claims, then drains all owned scheduled work.
  pub async fn shutdown(&mut self) -> ScheduledWorkerShutdown {
    self.shutdown_with_timeout(SCHEDULER_DRAIN_TIMEOUT).await
  }

  async fn shutdown_with_timeout(&mut self, timeout: Duration) -> ScheduledWorkerShutdown {
    self.request_shutdown();
    let deadline = tokio::time::Instant::now() + timeout;
    if let Some(mut join) = self.join.take() {
      match tokio::time::timeout_at(deadline, &mut join).await {
        Ok(Ok(())) => {}
        Ok(Err(_)) => self.worker_failed = true,
        Err(_) => {
          self.join = Some(join);
          return ScheduledWorkerShutdown::NonClean;
        }
      }
    }
    if self.guardians.drain_until(deadline).await && !self.worker_failed {
      ScheduledWorkerShutdown::Clean
    } else {
      ScheduledWorkerShutdown::NonClean
    }
  }
}

impl Drop for ScheduledWorkerHandle {
  fn drop(&mut self) {
    let _ = self.shutdown.send(true);
  }
}

pub fn spawn_scheduled_worker(
  state: StateStore,
  budget: GlobalTurnBudget,
  config: ScheduledWorkerConfig,
  executor: Option<ScheduledExecutor>,
  telemetry: Arc<dyn SchedulerTelemetry>,
) -> Result<Option<ScheduledWorkerHandle>, StateError> {
  if !config.enabled {
    return Ok(None);
  }
  if config.run_claims_enabled
    && executor
      .as_ref()
      .is_none_or(|executor| !executor.is_ready())
  {
    return Err(StateError::InvalidSchedulerState {
      reason: "scheduled run claims require a validated executor".to_owned(),
    });
  }
  let (shutdown, shutdown_rx) = watch::channel(false);
  let guardians = Arc::new(BlockingGuardianRegistry::default());
  let mut orchestrator = ScheduledRunOrchestrator::new(
    state.clone(),
    executor.map_or_else(
      || Arc::new(UnavailableScheduledExecutionBackend) as Arc<dyn ScheduledExecutionBackend>,
      |executor| executor.backend,
    ),
    budget,
    Arc::clone(&guardians),
    format!("codeoff-scheduler-{}", std::process::id()),
  );
  orchestrator.run_claims_enabled = config.run_claims_enabled;
  orchestrator.policy = ExecutionPolicy::from_policy(&config.operational_policy);
  orchestrator.telemetry = telemetry.clone();
  let join = tokio::spawn(run_scheduled_worker(
    state,
    orchestrator,
    shutdown_rx,
    telemetry,
  ));
  Ok(Some(ScheduledWorkerHandle {
    shutdown,
    join: Some(join),
    guardians,
    worker_failed: false,
  }))
}

#[derive(Default)]
struct BlockingGuardianRegistry {
  tasks: Mutex<Vec<JoinHandle<()>>>,
}

impl BlockingGuardianRegistry {
  fn retain<T: Send + 'static>(
    &self,
    task: JoinHandle<T>,
    permit: tokio::sync::OwnedSemaphorePermit,
  ) {
    let guardian = tokio::spawn(async move {
      let _ = task.await;
      drop(permit);
    });
    self.tasks.lock().expect("guardian registry").push(guardian);
  }

  async fn drain_until(&self, deadline: tokio::time::Instant) -> bool {
    let tasks = std::mem::take(&mut *self.tasks.lock().expect("guardian registry"));
    let mut remaining = Vec::new();
    let mut clean = true;
    let mut tasks = tasks.into_iter();
    while let Some(mut task) = tasks.next() {
      match tokio::time::timeout_at(deadline, &mut task).await {
        Ok(Ok(())) => {}
        Ok(Err(_)) => clean = false,
        Err(_) => {
          remaining.push(task);
          remaining.extend(tasks);
          clean = false;
          break;
        }
      }
    }
    self
      .tasks
      .lock()
      .expect("guardian registry")
      .extend(remaining);
    clean
  }
}

#[cfg(test)]
struct ScheduledRunHandle {
  _shutdown: watch::Sender<bool>,
  join: JoinHandle<Result<TickOutcome, StateError>>,
}

#[cfg(test)]
impl ScheduledRunHandle {
  #[cfg(test)]
  async fn join(self) -> Result<TickOutcome, StateError> {
    self.join.await.map_err(join_error)?
  }
}

async fn run_scheduled_worker(
  state: StateStore,
  orchestrator: ScheduledRunOrchestrator,
  shutdown: watch::Receiver<bool>,
  telemetry: Arc<dyn SchedulerTelemetry>,
) {
  let loop_guard = SchedulerLoopGuard::start(telemetry.clone(), SchedulerWorker::Execution);
  loop {
    if *shutdown.borrow() {
      break;
    }
    let started_at = Instant::now();
    record_execution_event(
      telemetry.as_ref(),
      SchedulerOperation::Tick,
      SchedulerOperationStatus::Started,
      None,
      Duration::ZERO,
      None,
    );
    let tick = Box::pin(run_scheduled_worker_tick(
      &state,
      &orchestrator,
      shutdown.clone(),
    ))
    .await;
    let (status, error_kind) = match &tick {
      Ok(outcome) => (execution_tick_status(*outcome), None),
      Err(_) => (
        SchedulerOperationStatus::Failed,
        Some(SchedulerTelemetryErrorKind::State),
      ),
    };
    record_execution_event(
      telemetry.as_ref(),
      SchedulerOperation::Tick,
      status,
      error_kind,
      started_at.elapsed(),
      None,
    );
    let delay = if let Err(error) = &tick {
      eprintln!("scheduled worker tick failed: {}", bounded_log_error(error));
      orchestrator.policy.error_backoff
    } else {
      orchestrator.policy.tick_interval
    };
    tokio::select! {
      () = cancellation_requested(shutdown.clone()) => break,
      () = tokio::time::sleep(delay) => {}
    }
  }
  loop_guard.finish(SchedulerOperationStatus::Stopped, None);
}

fn record_execution_event(
  telemetry: &dyn SchedulerTelemetry,
  operation: SchedulerOperation,
  status: SchedulerOperationStatus,
  error_kind: Option<SchedulerTelemetryErrorKind>,
  duration: Duration,
  attempt: Option<u32>,
) {
  record_scheduler_event(
    telemetry,
    SchedulerTelemetryEvent {
      worker: SchedulerWorker::Execution,
      operation,
      status,
      error_kind,
      duration,
      attempt,
    },
  );
}

async fn run_scheduled_worker_tick(
  state: &StateStore,
  orchestrator: &ScheduledRunOrchestrator,
  shutdown: watch::Receiver<bool>,
) -> Result<TickOutcome, StateError> {
  if *shutdown.borrow() {
    return Ok(TickOutcome::Cancelled);
  }
  let now = orchestrator.clock.now();
  for _ in 0..orchestrator.policy.recovery_batch_limit {
    let outcome = tokio::select! {
      result = state.reclaim_next_expired_scheduled_run_from_snapshot(now) => result?,
      () = cancellation_requested(shutdown.clone()) => return Ok(TickOutcome::Cancelled),
    };
    if outcome == ExpiredRunReclaimOutcome::Idle {
      break;
    }
  }
  if !orchestrator.run_claims_enabled {
    return Ok(TickOutcome::Unavailable);
  }
  if orchestrator.backend.refresh_admission().await == RefreshedExecutorAdmission::Unavailable {
    return Ok(TickOutcome::Unavailable);
  }
  let due_jobs = tokio::select! {
    result = state.list_due_scheduled_jobs(now, orchestrator.policy.materialization_batch_limit) => result?,
    () = cancellation_requested(shutdown.clone()) => return Ok(TickOutcome::Cancelled),
  };
  for job_id in due_jobs {
    if *shutdown.borrow() {
      return Ok(TickOutcome::Cancelled);
    }
    let job = tokio::select! {
      result = state.get_scheduled_job(&job_id) => result?,
      () = cancellation_requested(shutdown.clone()) => return Ok(TickOutcome::Cancelled),
    };
    let Some(job) = job else {
      continue;
    };
    let admission = orchestrator.backend.refresh_admission().await;
    if admission == RefreshedExecutorAdmission::Unavailable {
      return Ok(TickOutcome::Unavailable);
    }
    let clock = Arc::clone(&orchestrator.clock);
    let materialization = match &admission {
      RefreshedExecutorAdmission::Unavailable => unreachable!(),
      RefreshedExecutorAdmission::Ready => tokio::select! {
        result = state.materialize_due_schedule(&job_id, job.generation, now) => result,
        () = cancellation_requested(shutdown.clone()) => return Ok(TickOutcome::Cancelled),
      },
      RefreshedExecutorAdmission::Authority(authority) => {
        let state = state.clone();
        let job_id = job_id.clone();
        let authority = authority.clone();
        let cancellation = Arc::new(AtomicBool::new(false));
        let task_cancellation = Arc::clone(&cancellation);
        let joined = join_admitted_state_mutation(
          async move {
            let clock_read = || clock.now();
            state
              .materialize_due_schedule_with_admission(
                &job_id,
                job.generation,
                now,
                &authority,
                &clock_read,
                task_cancellation.as_ref(),
              )
              .await
          },
          cancellation,
          shutdown.clone(),
        )
        .await?;
        if joined.cancellation_requested {
          match joined.result {
            Ok(_) | Err(StateError::ScheduledExecutorAdmissionUnavailable) => {
              return Ok(TickOutcome::Cancelled);
            }
            Err(error) => return Err(error),
          }
        }
        joined.result
      }
    };
    match materialization {
      Ok(_) => {}
      Err(StateError::ScheduledExecutorAdmissionUnavailable) => {
        return Ok(TickOutcome::Unavailable);
      }
      Err(error) => return Err(error),
    }
  }
  if *shutdown.borrow() {
    return Ok(TickOutcome::Cancelled);
  }

  let supervisor = orchestrator.clone();
  let (run_shutdown, run_shutdown_rx) = watch::channel(false);
  let run = supervisor.run_supervised(run_shutdown_rx);
  tokio::pin!(run);
  tokio::select! {
    result = &mut run => result,
    () = cancellation_requested(shutdown) => {
      let _ = run_shutdown.send(true);
      run.await
    }
  }
}

async fn cancellation_requested(mut shutdown: watch::Receiver<bool>) {
  while !*shutdown.borrow() {
    if shutdown.changed().await.is_err() {
      return;
    }
  }
}

struct JoinedAdmissionMutation<T> {
  result: Result<T, StateError>,
  cancellation_requested: bool,
}

async fn join_admitted_state_mutation<T>(
  mutation: impl Future<Output = Result<T, StateError>> + Send + 'static,
  cancellation: Arc<AtomicBool>,
  shutdown: watch::Receiver<bool>,
) -> Result<JoinedAdmissionMutation<T>, StateError>
where
  T: Send + 'static,
{
  let mut task = tokio::spawn(mutation);
  tokio::select! {
    result = &mut task => Ok(JoinedAdmissionMutation {
      result: result.map_err(admitted_mutation_join_error)?,
      cancellation_requested: false,
    }),
    () = cancellation_requested(shutdown) => {
      cancellation.store(true, Ordering::Release);
      Ok(JoinedAdmissionMutation {
        result: task.await.map_err(admitted_mutation_join_error)?,
        cancellation_requested: true,
      })
    }
  }
}

fn admitted_mutation_join_error(error: tokio::task::JoinError) -> StateError {
  StateError::InvalidSchedulerState {
    reason: format!("scheduled admitted state mutation task failed: {error}"),
  }
}

fn bounded_log_error(error: &StateError) -> String {
  let message = error.to_string();
  if message.len() <= MAX_LOG_ERROR_BYTES {
    return message;
  }
  let mut end = MAX_LOG_ERROR_BYTES;
  while !message.is_char_boundary(end) {
    end -= 1;
  }
  format!("{}…", &message[..end])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutorReadiness {
  Ready,
  Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TickOutcome {
  Cancelled,
  Unavailable,
  Idle,
  Completed,
  Failed,
  LostLease,
}

const fn execution_tick_status(outcome: TickOutcome) -> SchedulerOperationStatus {
  match outcome {
    TickOutcome::Cancelled => SchedulerOperationStatus::Cancelled,
    TickOutcome::Unavailable => SchedulerOperationStatus::Unavailable,
    TickOutcome::Idle => SchedulerOperationStatus::Idle,
    TickOutcome::Completed => SchedulerOperationStatus::Completed,
    TickOutcome::Failed => SchedulerOperationStatus::Failed,
    TickOutcome::LostLease => SchedulerOperationStatus::LostAuthority,
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HeartbeatStop {
  LostLease,
  HardDeadline,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExecutionPolicy {
  recovery_batch_limit: u16,
  materialization_batch_limit: u32,
  tick_interval: Duration,
  error_backoff: Duration,
  lease_seconds: i64,
  heartbeat_interval: Duration,
  total_timeout: Duration,
  prepare_grace: Duration,
  cancellation_grace: Duration,
  finalization_grace: Duration,
}

impl Default for ExecutionPolicy {
  fn default() -> Self {
    Self::from_policy(&SchedulerOperationalPolicy::default())
  }
}

impl ExecutionPolicy {
  fn from_policy(policy: &SchedulerOperationalPolicy) -> Self {
    Self {
      recovery_batch_limit: policy.recovery_batch_limit,
      materialization_batch_limit: u32::from(policy.materialization_batch_limit),
      tick_interval: Duration::from_millis(policy.tick_interval_ms),
      error_backoff: Duration::from_millis(policy.error_backoff_ms),
      lease_seconds: i64::from(policy.run_lease_seconds),
      heartbeat_interval: Duration::from_millis(policy.run_heartbeat_interval_ms),
      total_timeout: Duration::from_secs(u64::from(policy.run_timeout_seconds)),
      prepare_grace: Duration::from_millis(policy.run_prepare_grace_ms),
      cancellation_grace: Duration::from_millis(policy.run_cancellation_grace_ms),
      finalization_grace: Duration::from_millis(policy.run_finalization_grace_ms),
    }
  }
}

#[async_trait]
trait SchedulerClock: Send + Sync {
  fn now(&self) -> i64;
  async fn sleep(&self, duration: Duration);
}

struct SystemClock;

#[async_trait]
impl SchedulerClock for SystemClock {
  fn now(&self) -> i64 {
    SystemTime::now()
      .duration_since(UNIX_EPOCH)
      .map_or(0, |duration| {
        i64::try_from(duration.as_secs()).unwrap_or(i64::MAX)
      })
  }

  async fn sleep(&self, duration: Duration) {
    tokio::time::sleep(duration).await;
  }
}

#[allow(
  dead_code,
  reason = "the production scheduled executor remains unavailable until the trusted issuer checkpoint"
)]
pub struct PrepareInput {
  pub task: AgentTask,
  pub binding: RunLeaseBinding,
  pub authority: ScheduledPrepareAuthority,
  pub definition_json: String,
  pub capability_json: String,
  pub capability_digest: String,
  pub targets_json: String,
  pub cancellation: Arc<AtomicBool>,
}

pub struct BackendPrepared {
  authority: ScheduledPrepareAuthority,
  authority_digest: String,
  attested_profile_json: String,
  attested_profile_digest: String,
  pub execution: Box<dyn PreparedExecution>,
}

impl BackendPrepared {
  #[must_use]
  pub fn new(
    authority: ScheduledPrepareAuthority,
    attested_profile_json: String,
    attested_profile_digest: String,
    execution: Box<dyn PreparedExecution>,
  ) -> Self {
    Self {
      authority_digest: authority.digest().to_owned(),
      authority,
      attested_profile_json,
      attested_profile_digest,
      execution,
    }
  }
}

pub trait PreparedExecution: Send {
  fn execute(self: Box<Self>, cancellation: Arc<AtomicBool>) -> ExecutionResult;
}

pub struct BackendAuthorization(Box<dyn Any + Send>);

impl BackendAuthorization {
  #[must_use]
  pub fn new<T: Send + 'static>(value: T) -> Self {
    Self(Box::new(value))
  }

  /// Recovers the concrete integration-owned authorization.
  ///
  /// # Errors
  /// Returns an error when the backend receives an authorization issued for another integration.
  pub fn downcast<T: Send + 'static>(self) -> Result<T, PrepareFailure> {
    self
      .0
      .downcast::<T>()
      .map(|value| *value)
      .map_err(|_| PrepareFailure::artifact("scheduled_backend_authorization_type_mismatch"))
  }
}

#[async_trait]
pub trait ScheduledExecutionBackend: Send + Sync {
  fn readiness(&self) -> ExecutorReadiness;
  async fn refresh_readiness(&self) -> ExecutorReadiness {
    self.readiness()
  }
  async fn refresh_admission(&self) -> RefreshedExecutorAdmission {
    match self.refresh_readiness().await {
      ExecutorReadiness::Ready => RefreshedExecutorAdmission::Ready,
      ExecutorReadiness::Unavailable => RefreshedExecutorAdmission::Unavailable,
    }
  }
  async fn authorize(&self, _input: &PrepareInput) -> Result<BackendAuthorization, PrepareFailure> {
    Ok(BackendAuthorization::new(()))
  }
  fn prepare(
    &self,
    input: PrepareInput,
    authorization: BackendAuthorization,
  ) -> Result<BackendPrepared, PrepareFailure>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefreshedExecutorAdmission {
  Unavailable,
  Ready,
  Authority(ScheduledExecutorAdmission),
}

struct UnavailableScheduledExecutionBackend;

#[async_trait]
impl ScheduledExecutionBackend for UnavailableScheduledExecutionBackend {
  fn readiness(&self) -> ExecutorReadiness {
    ExecutorReadiness::Unavailable
  }

  async fn authorize(&self, _input: &PrepareInput) -> Result<BackendAuthorization, PrepareFailure> {
    Err(PrepareFailure::fatal("scheduled_executor_unavailable"))
  }
  fn prepare(
    &self,
    _input: PrepareInput,
    _authorization: BackendAuthorization,
  ) -> Result<BackendPrepared, PrepareFailure> {
    Err(PrepareFailure::fatal("scheduled_executor_unavailable"))
  }
}

struct PreparedRun {
  authority: ScheduledPrepareAuthority,
  attested_profile: AttestedExecutionProfileSnapshot,
  execution: Box<dyn PreparedExecution>,
}

impl PreparedRun {
  fn from_backend(
    expected_authority: &ScheduledPrepareAuthority,
    prepared: BackendPrepared,
  ) -> Result<Self, PrepareFailure> {
    let profile: Value = serde_json::from_str(&prepared.attested_profile_json)
      .map_err(|_| PrepareFailure::profile("scheduled_attested_profile_json_invalid"))?;
    let canonical_profile = serde_json::to_string(&profile)
      .map_err(|_| PrepareFailure::profile("scheduled_attested_profile_canonicalization_failed"))?;
    let schema_version = profile
      .get("schema_version")
      .and_then(Value::as_u64)
      .and_then(|value| u32::try_from(value).ok())
      .ok_or_else(|| PrepareFailure::profile("scheduled_attested_profile_schema_missing"))?;
    let authority_matches = match schema_version {
      1 => expected_authority.attestation_matches(
        &canonical_profile,
        &prepared.attested_profile_digest,
        false,
      ),
      2 => expected_authority
        .recovery_attestation_matches(&canonical_profile, &prepared.attested_profile_digest),
      _ => false,
    };
    if prepared.authority != *expected_authority
      || prepared.authority_digest != expected_authority.digest()
      || !authority_matches
    {
      return Err(PrepareFailure::profile(
        "scheduled_attested_profile_authority_mismatch",
      ));
    }
    let attested_profile = AttestedExecutionProfileSnapshot::new(
      schema_version,
      canonical_profile,
      "sha256-v1",
      prepared.attested_profile_digest,
    )
    .map_err(|_| PrepareFailure::profile("scheduled_attested_profile_snapshot_invalid"))?;
    Ok(Self {
      authority: prepared.authority,
      attested_profile,
      execution: prepared.execution,
    })
  }

  fn matches(&self, authority: &ScheduledPrepareAuthority) -> bool {
    self.authority == *authority
  }

  fn execute(self, cancellation: Arc<AtomicBool>) -> ExecutionResult {
    self.execution.execute(cancellation)
  }
}

#[derive(Debug)]
pub struct PrepareFailure {
  pub retryable: bool,
  pub kind: String,
  pub message: String,
}

impl PrepareFailure {
  #[must_use]
  pub fn fatal(message: impl Into<String>) -> Self {
    Self::classified("preflight_rejected", message)
  }

  fn profile(message: impl Into<String>) -> Self {
    Self::classified("profile_validation_failed", message)
  }

  fn artifact(message: impl Into<String>) -> Self {
    Self::classified("artifact_validation_failed", message)
  }

  fn tool_list(message: impl Into<String>) -> Self {
    Self::classified("tool_list_validation_failed", message)
  }

  fn classified(kind: &str, message: impl Into<String>) -> Self {
    Self {
      retryable: false,
      kind: kind.to_owned(),
      message: message.into(),
    }
  }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(
  dead_code,
  reason = "production execution results become reachable with the trusted scheduled executor"
)]
pub enum ExecutionResult {
  Completed { summary: String },
  Interrupted { transport_converged: bool },
  TimedOut { transport_converged: bool },
  Failed { kind: String, message: String },
  TransportLost { message: String },
  AcceptedDispatch,
  Empty,
}

#[derive(Clone)]
struct ScheduledRunOrchestrator {
  state: StateStore,
  backend: Arc<dyn ScheduledExecutionBackend>,
  clock: Arc<dyn SchedulerClock>,
  budget: GlobalTurnBudget,
  guardians: Arc<BlockingGuardianRegistry>,
  lease_owner: String,
  run_claims_enabled: bool,
  policy: ExecutionPolicy,
  telemetry: Arc<dyn SchedulerTelemetry>,
}

impl ScheduledRunOrchestrator {
  fn new(
    state: StateStore,
    backend: Arc<dyn ScheduledExecutionBackend>,
    budget: GlobalTurnBudget,
    guardians: Arc<BlockingGuardianRegistry>,
    lease_owner: impl Into<String>,
  ) -> Self {
    Self {
      state,
      backend,
      clock: Arc::new(SystemClock),
      budget,
      guardians,
      lease_owner: lease_owner.into(),
      run_claims_enabled: true,
      policy: ExecutionPolicy::default(),
      telemetry: Arc::new(NoopSchedulerTelemetry),
    }
  }

  #[cfg(test)]
  fn unavailable(
    state: StateStore,
    budget: GlobalTurnBudget,
    guardians: Arc<BlockingGuardianRegistry>,
    lease_owner: impl Into<String>,
  ) -> Self {
    Self::new(
      state,
      Arc::new(UnavailableScheduledExecutionBackend),
      budget,
      guardians,
      lease_owner,
    )
  }

  #[cfg(test)]
  async fn run_once(&self) -> Result<TickOutcome, StateError> {
    self.spawn_once().join().await
  }

  #[cfg(test)]
  fn spawn_once(&self) -> ScheduledRunHandle {
    let supervisor = self.clone();
    let (shutdown, shutdown_rx) = watch::channel(false);
    let join = tokio::spawn(async move { supervisor.run_supervised(shutdown_rx).await });
    ScheduledRunHandle {
      _shutdown: shutdown,
      join,
    }
  }

  async fn run_supervised(
    self,
    shutdown: watch::Receiver<bool>,
  ) -> Result<TickOutcome, StateError> {
    let telemetry = self.telemetry.clone();
    let attempt = AtomicU64::new(0);
    let started_at = Instant::now();
    record_execution_event(
      telemetry.as_ref(),
      SchedulerOperation::Attempt,
      SchedulerOperationStatus::Started,
      None,
      Duration::ZERO,
      None,
    );
    let result = self.run_supervised_inner(shutdown, &attempt).await;
    let attempt = attempt.load(Ordering::Acquire);
    let attempt = (attempt > 0).then(|| u32::try_from(attempt).unwrap_or(u32::MAX));
    record_execution_event(
      telemetry.as_ref(),
      SchedulerOperation::Attempt,
      match &result {
        Ok(outcome) => execution_tick_status(*outcome),
        Err(_) => SchedulerOperationStatus::Failed,
      },
      result
        .as_ref()
        .err()
        .map(|_| SchedulerTelemetryErrorKind::State),
      started_at.elapsed(),
      attempt,
    );
    result
  }

  async fn run_supervised_inner(
    mut self,
    shutdown: watch::Receiver<bool>,
    observed_attempt: &AtomicU64,
  ) -> Result<TickOutcome, StateError> {
    let mut permit = Some(tokio::select! {
      result = self.budget.acquire() => result?,
      () = cancellation_requested(shutdown.clone()) => return Ok(TickOutcome::Cancelled),
    });
    if !self.run_claims_enabled {
      return Ok(TickOutcome::Unavailable);
    }
    let admission = self.backend.refresh_admission().await;
    if admission == RefreshedExecutorAdmission::Unavailable {
      return Ok(TickOutcome::Unavailable);
    }
    if *shutdown.borrow() {
      return Ok(TickOutcome::Cancelled);
    }
    let now = self.clock.now();
    let claim_result = match &admission {
      RefreshedExecutorAdmission::Unavailable => Ok(None),
      RefreshedExecutorAdmission::Ready => {
        let clock_read = || self.clock.now();
        tokio::select! {
          result = self
            .state
            .claim_next_scheduled_run_from_snapshot_with_clock(
              &self.lease_owner,
              now,
              &clock_read,
            ) => result,
          () = cancellation_requested(shutdown.clone()) => return Ok(TickOutcome::Cancelled),
        }
      }
      RefreshedExecutorAdmission::Authority(authority) => {
        let state = self.state.clone();
        let lease_owner = self.lease_owner.clone();
        let authority = authority.clone();
        let clock = Arc::clone(&self.clock);
        let cancellation = Arc::new(AtomicBool::new(false));
        let task_cancellation = Arc::clone(&cancellation);
        let joined = join_admitted_state_mutation(
          async move {
            let clock_read = || clock.now();
            state
              .claim_next_scheduled_run_from_snapshot_with_admission(
                &lease_owner,
                now,
                &authority,
                &clock_read,
                task_cancellation.as_ref(),
              )
              .await
          },
          cancellation,
          shutdown.clone(),
        )
        .await?;
        if joined.cancellation_requested {
          match joined.result {
            Ok(Some(claim)) => Ok(Some(claim)),
            Ok(None) | Err(StateError::ScheduledExecutorAdmissionUnavailable) => {
              return Ok(TickOutcome::Cancelled);
            }
            Err(error) => return Err(error),
          }
        } else {
          joined.result
        }
      }
    };
    let claim = match claim_result {
      Ok(claim) => claim,
      Err(StateError::ScheduledExecutorAdmissionUnavailable) => {
        return Ok(TickOutcome::Unavailable);
      }
      Err(error) => return Err(error),
    };
    let Some(claim) = claim else {
      return Ok(TickOutcome::Idle);
    };
    let snapshot_policy = ExecutionPolicy::from_policy(&claim.scheduler_policy);
    #[cfg(test)]
    {
      self.policy.lease_seconds = snapshot_policy.lease_seconds;
    }
    #[cfg(not(test))]
    {
      self.policy = snapshot_policy;
    }
    #[cfg(test)]
    if self.policy == ExecutionPolicy::default() {
      self.policy = snapshot_policy;
    }
    let Some(absolute_deadline) = claim.scheduler_policy.run_deadline_at(claim.scheduled_for)
    else {
      self
        .record_preflight_failure(&claim, PrepareFailure::fatal("run_deadline_overflow"))
        .await?;
      return Ok(TickOutcome::Failed);
    };
    let deadline_now = self.clock.now();
    if deadline_now >= absolute_deadline {
      self
        .record_preflight_failure(&claim, PrepareFailure::fatal("run_deadline_exceeded"))
        .await?;
      return Ok(TickOutcome::Failed);
    }
    self.policy.total_timeout = self.policy.total_timeout.min(Duration::from_secs(
      u64::try_from(absolute_deadline - deadline_now).unwrap_or(0),
    ));
    let total_deadline = tokio::time::Instant::now()
      .checked_add(self.policy.total_timeout)
      .ok_or_else(|| StateError::InvalidSchedulerState {
        reason: "scheduled total deadline overflow".to_owned(),
      })?;
    let terminal_commit_deadline = total_deadline
      .checked_add(self.policy.prepare_grace)
      .and_then(|deadline| deadline.checked_add(self.policy.cancellation_grace))
      .ok_or_else(|| StateError::InvalidSchedulerState {
        reason: "scheduled terminal commit deadline overflow".to_owned(),
      })?;
    let heartbeat_stop_deadline = terminal_commit_deadline
      .checked_add(self.policy.finalization_grace)
      .ok_or_else(|| StateError::InvalidSchedulerState {
        reason: "scheduled heartbeat stop deadline overflow".to_owned(),
      })?;
    observed_attempt.store(
      u64::try_from(claim.binding.attempt()).unwrap_or(u64::MAX),
      Ordering::Release,
    );

    let cancellation = Arc::new(AtomicBool::new(false));
    let (mut heartbeat, mut heartbeat_stop) =
      self.start_heartbeat(&claim, Arc::clone(&cancellation), heartbeat_stop_deadline);
    let authority =
      match ScheduledPrepareAuthority::for_claim(&claim, prepare_nonce(&claim.binding)) {
        Ok(authority) => authority,
        Err(error) => {
          let outcome = self
            .record_preflight_failure(&claim, PrepareFailure::artifact(error.to_string()))
            .await;
          stop_heartbeat(&mut heartbeat).await;
          return outcome;
        }
      };
    let task = match task_from_claim(&claim, &authority) {
      Ok(task) => task,
      Err(failure) => {
        let outcome = self.record_preflight_failure(&claim, failure).await;
        stop_heartbeat(&mut heartbeat).await;
        return outcome;
      }
    };
    let input = PrepareInput {
      task,
      binding: claim.binding.clone(),
      authority: authority.clone(),
      definition_json: claim.definition_json.clone(),
      capability_json: claim.capability_json.clone(),
      capability_digest: claim.capability_digest.clone(),
      targets_json: claim.targets_json.clone(),
      cancellation: Arc::clone(&cancellation),
    };
    let backend = Arc::clone(&self.backend);
    if self.clock.now() >= absolute_deadline {
      let outcome = self
        .record_preflight_failure(&claim, PrepareFailure::fatal("run_deadline_exceeded"))
        .await;
      stop_heartbeat(&mut heartbeat).await;
      return outcome;
    }
    let authorization = tokio::select! {
      biased;
      () = cancellation_requested(shutdown.clone()) => {
        cancellation.store(true, Ordering::Release);
        let outcome = self
          .record_shutdown_preflight(&claim, "scheduler_shutdown_during_authorization")
          .await;
        stop_heartbeat(&mut heartbeat).await;
        return outcome;
      },
      stop = &mut heartbeat_stop => {
        cancellation.store(true, Ordering::Release);
        let outcome = if matches!(stop, Ok(HeartbeatStop::LostLease)) {
          self.append_late_preflight(&claim).await?;
          Ok(TickOutcome::LostLease)
        } else {
          self.record_preflight_failure(
            &claim,
            PrepareFailure::fatal("authorization_hard_deadline"),
          ).await
        };
        stop_heartbeat(&mut heartbeat).await;
        return outcome;
      },
      () = tokio::time::sleep_until(total_deadline) => {
        cancellation.store(true, Ordering::Release);
        let outcome = self.record_preflight_failure(
          &claim,
          PrepareFailure::fatal("authorization_total_deadline"),
        ).await;
        stop_heartbeat(&mut heartbeat).await;
        return outcome;
      },
      result = backend.authorize(&input) => result,
    };
    let authorization = match authorization {
      Ok(authorization) => authorization,
      Err(failure) => {
        let outcome = self.record_preflight_failure(&claim, failure).await;
        stop_heartbeat(&mut heartbeat).await;
        return outcome;
      }
    };
    if self.clock.now() >= absolute_deadline {
      let outcome = self
        .record_preflight_failure(&claim, PrepareFailure::fatal("run_deadline_exceeded"))
        .await;
      stop_heartbeat(&mut heartbeat).await;
      return outcome;
    }
    let mut prepare = tokio::task::spawn_blocking(move || backend.prepare(input, authorization));
    let prepared = tokio::select! {
      biased;
      () = cancellation_requested(shutdown.clone()) => {
        cancellation.store(true, Ordering::Release);
        if tokio::time::timeout(self.policy.prepare_grace, &mut prepare).await.is_err() {
          let retained_permit = permit.take().expect("scheduled execution permit is held");
          self.guardians.retain(prepare, retained_permit);
        }
        let outcome = self
          .record_shutdown_preflight(&claim, "scheduler_shutdown_during_prepare")
          .await;
        stop_heartbeat(&mut heartbeat).await;
        return outcome;
      },
      stop = &mut heartbeat_stop => {
        cancellation.store(true, Ordering::Release);
        if tokio::time::timeout(self.policy.prepare_grace, &mut prepare).await.is_err() {
          let retained_permit = permit.take().expect("scheduled execution permit is held");
          self.guardians.retain(prepare, retained_permit);
        }
        let outcome = if matches!(stop, Ok(HeartbeatStop::LostLease)) {
          self.append_late_preflight(&claim).await?;
          Ok(TickOutcome::LostLease)
        } else {
          self.record_preflight_failure(&claim, PrepareFailure::fatal("prepare_hard_deadline")).await
        };
        stop_heartbeat(&mut heartbeat).await;
        return outcome;
      },
      () = tokio::time::sleep_until(total_deadline) => {
        cancellation.store(true, Ordering::Release);
        if tokio::time::timeout(self.policy.prepare_grace, &mut prepare).await.is_err() {
          let retained_permit = permit.take().expect("scheduled execution permit is held");
          self.guardians.retain(prepare, retained_permit);
        }
        let outcome = self.record_preflight_failure(
          &claim,
          PrepareFailure::fatal("prepare_total_deadline"),
        ).await;
        stop_heartbeat(&mut heartbeat).await;
        return outcome;
      },
      result = &mut prepare => result.map_err(join_error)?,
    };
    let prepared =
      match prepared.and_then(|prepared| PreparedRun::from_backend(&authority, prepared)) {
        Ok(prepared) if prepared.matches(&authority) => prepared,
        Ok(_) => {
          let outcome = self
            .record_preflight_failure(
              &claim,
              PrepareFailure::artifact("prepared_authority_mismatch"),
            )
            .await;
          stop_heartbeat(&mut heartbeat).await;
          return outcome;
        }
        Err(failure) => {
          let outcome = self.record_preflight_failure(&claim, failure).await;
          stop_heartbeat(&mut heartbeat).await;
          return outcome;
        }
      };

    if *shutdown.borrow() {
      cancellation.store(true, Ordering::Release);
      let outcome = self
        .record_shutdown_preflight(&claim, "scheduler_shutdown_before_execution")
        .await;
      stop_heartbeat(&mut heartbeat).await;
      return outcome;
    }
    if self.clock.now() >= absolute_deadline {
      let outcome = self
        .record_preflight_failure(&claim, PrepareFailure::fatal("run_deadline_exceeded"))
        .await;
      stop_heartbeat(&mut heartbeat).await;
      return outcome;
    }

    let mark_executing = tokio::select! {
      result = tokio::time::timeout_at(
        total_deadline,
        self.state.mark_scheduled_run_executing(
          &claim.binding,
          &prepared.attested_profile,
          self.clock.now(),
        ),
      ) => result,
      () = cancellation_requested(shutdown.clone()) => {
        cancellation.store(true, Ordering::Release);
        let outcome = self
          .record_shutdown_preflight(&claim, "scheduler_shutdown_before_execution_commit")
          .await;
        stop_heartbeat(&mut heartbeat).await;
        return outcome;
      },
    };
    let Ok(mark_executing) = mark_executing else {
      cancellation.store(true, Ordering::Release);
      let outcome = self
        .record_preflight_failure(&claim, PrepareFailure::fatal("preflight_commit_deadline"))
        .await;
      stop_heartbeat(&mut heartbeat).await;
      return outcome;
    };
    if let Err(error) = mark_executing {
      cancellation.store(true, Ordering::Release);
      if matches!(error, StateError::ScheduledRunLostLease) {
        self.append_late_preflight(&claim).await?;
        stop_heartbeat(&mut heartbeat).await;
        return Ok(TickOutcome::LostLease);
      }
      stop_heartbeat(&mut heartbeat).await;
      return Err(error);
    }

    let execution_cancellation = Arc::clone(&cancellation);
    let mut execution =
      tokio::task::spawn_blocking(move || prepared.execute(execution_cancellation));
    let result = tokio::select! {
      biased;
      () = cancellation_requested(shutdown.clone()) => {
        cancellation.store(true, Ordering::Release);
        let result = if let Ok(result) = tokio::time::timeout(
          self.policy.cancellation_grace,
          &mut execution,
        ).await {
          result.map_err(join_error)?
        } else {
          let retained_permit = permit.take().expect("scheduled execution permit is held");
          self.guardians.retain(execution, retained_permit);
          ExecutionResult::Interrupted {
            transport_converged: false,
          }
        };
        let shutdown_terminal_deadline = tokio::time::Instant::now()
          .checked_add(self.policy.finalization_grace)
          .ok_or_else(|| StateError::InvalidSchedulerState {
            reason: "scheduled shutdown terminal deadline overflow".to_owned(),
          })?;
        let shutdown_hard_stop_deadline = shutdown_terminal_deadline
          .checked_add(self.policy.finalization_grace)
          .ok_or_else(|| StateError::InvalidSchedulerState {
            reason: "scheduled shutdown hard-stop deadline overflow".to_owned(),
          })?;
        let outcome = self
          .commit_execution_result_bounded(
            &claim,
            result,
            shutdown_terminal_deadline,
            shutdown_hard_stop_deadline,
            None,
          )
          .await;
        stop_heartbeat(&mut heartbeat).await;
        return outcome;
      },
      stop = &mut heartbeat_stop => {
        cancellation.store(true, Ordering::Release);
        if tokio::time::timeout(self.policy.cancellation_grace, &mut execution).await.is_err() {
          let retained_permit = permit.take().expect("scheduled execution permit is held");
          self.guardians.retain(execution, retained_permit);
        }
        let outcome = if matches!(stop, Ok(HeartbeatStop::LostLease)) {
          self.append_late_execution(&claim).await?;
          Ok(TickOutcome::LostLease)
        } else {
          self.commit_execution_result_bounded(
            &claim,
            ExecutionResult::TransportLost {
              message: "heartbeat hard deadline".to_owned(),
            },
            terminal_commit_deadline,
            heartbeat_stop_deadline,
            Some(shutdown.clone()),
          ).await
        };
        stop_heartbeat(&mut heartbeat).await;
        return outcome;
      },
      () = tokio::time::sleep_until(total_deadline) => {
        cancellation.store(true, Ordering::Release);
        let result = if let Ok(result) = tokio::time::timeout(
          self.policy.cancellation_grace,
          &mut execution,
        ).await {
          result.map_err(join_error)?
        } else {
          let retained_permit = permit.take().expect("scheduled execution permit is held");
          self.guardians.retain(execution, retained_permit);
          ExecutionResult::TransportLost {
            message: "execution cancellation did not converge".to_owned(),
          }
        };
        let outcome = self
          .commit_execution_result_bounded(
            &claim,
            result,
            terminal_commit_deadline,
            heartbeat_stop_deadline,
            Some(shutdown.clone()),
          )
          .await;
        stop_heartbeat(&mut heartbeat).await;
        return outcome;
      },
      result = &mut execution => result.map_err(join_error)?,
    };
    let outcome = self
      .commit_execution_result_bounded(
        &claim,
        result,
        terminal_commit_deadline,
        heartbeat_stop_deadline,
        Some(shutdown),
      )
      .await;
    stop_heartbeat(&mut heartbeat).await;
    outcome
  }

  fn start_heartbeat(
    &self,
    claim: &ClaimedScheduledRun,
    cancellation: Arc<AtomicBool>,
    hard_stop_deadline: tokio::time::Instant,
  ) -> (JoinHandle<()>, oneshot::Receiver<HeartbeatStop>) {
    let state = self.state.clone();
    let binding = claim.binding.clone();
    let clock = Arc::clone(&self.clock);
    let interval = self.policy.heartbeat_interval;
    let lease_seconds = self.policy.lease_seconds;
    let (lost_tx, lost_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
      loop {
        tokio::select! {
          biased;
          () = tokio::time::sleep_until(hard_stop_deadline) => {
            cancellation.store(true, Ordering::Release);
            let _ = lost_tx.send(HeartbeatStop::HardDeadline);
            return;
          }
          () = clock.sleep(interval) => {}
        }
        let now = clock.now();
        let Some(expires_at) = now.checked_add(lease_seconds) else {
          cancellation.store(true, Ordering::Release);
          let _ = lost_tx.send(HeartbeatStop::LostLease);
          return;
        };
        if state
          .heartbeat_scheduled_run(&binding, now, expires_at)
          .await
          .is_err()
        {
          cancellation.store(true, Ordering::Release);
          let _ = lost_tx.send(HeartbeatStop::LostLease);
          return;
        }
      }
    });
    (task, lost_rx)
  }

  async fn record_preflight_failure(
    &self,
    claim: &ClaimedScheduledRun,
    failure: PrepareFailure,
  ) -> Result<TickOutcome, StateError> {
    let now = self.clock.now();
    match self
      .state
      .record_scheduled_run_preflight_failure_from_snapshot(
        &claim.binding,
        failure.retryable,
        &failure.kind,
        &failure.message,
        now,
      )
      .await
    {
      Ok(()) => Ok(TickOutcome::Failed),
      Err(StateError::ScheduledRunLostLease) => {
        self.append_late_preflight(claim).await?;
        Ok(TickOutcome::LostLease)
      }
      Err(error) => Err(error),
    }
  }

  async fn record_shutdown_preflight(
    &self,
    claim: &ClaimedScheduledRun,
    message: &'static str,
  ) -> Result<TickOutcome, StateError> {
    match tokio::time::timeout(
      self.policy.finalization_grace,
      self.record_preflight_failure(claim, PrepareFailure::fatal(message)),
    )
    .await
    {
      Ok(outcome) => outcome,
      Err(_) => Ok(TickOutcome::Cancelled),
    }
  }

  async fn append_late_preflight(&self, claim: &ClaimedScheduledRun) -> Result<(), StateError> {
    self
      .state
      .append_scheduled_run_late_evidence(
        &claim.binding,
        ScheduledRunLateEvidenceKind::PreflightAfterLeaseLoss,
        &sha256_hex(b"scheduled-preflight-after-lease-loss-v1"),
        self.clock.now(),
      )
      .await?;
    Ok(())
  }

  async fn append_late_execution(&self, claim: &ClaimedScheduledRun) -> Result<(), StateError> {
    self
      .state
      .append_scheduled_run_late_evidence(
        &claim.binding,
        ScheduledRunLateEvidenceKind::CompletionAfterLeaseLoss,
        &sha256_hex(b"scheduled-execution-after-lease-loss-v1"),
        self.clock.now(),
      )
      .await?;
    Ok(())
  }

  async fn commit_execution_result(
    &self,
    claim: &ClaimedScheduledRun,
    result: ExecutionResult,
  ) -> Result<TickOutcome, StateError> {
    let now = self.clock.now();
    let result = match result {
      ExecutionResult::Completed { summary } if summary.trim().is_empty() => ExecutionResult::Empty,
      ExecutionResult::Completed { summary } => {
        match ScheduledRunResult::new(summary.clone(), summary) {
          Ok(result) => {
            return self
              .state
              .complete_scheduled_run_success(&claim.binding, &result, now)
              .await
              .map(|outcome| match outcome {
                codeoff_state::ScheduledRunSuccessOutcome::Committed => TickOutcome::Completed,
                codeoff_state::ScheduledRunSuccessOutcome::LateEvidence(_) => {
                  TickOutcome::LostLease
                }
              });
          }
          Err(error) => ExecutionResult::Failed {
            kind: "output_schema_violation".to_owned(),
            message: error.to_string(),
          },
        }
      }
      result => result,
    };
    let (disposition, kind, message) = execution_failure_disposition(claim, result, now);
    self
      .state
      .record_scheduled_run_execution_outcome(&claim.binding, disposition, kind, message, now)
      .await
      .map(|outcome| match outcome {
        codeoff_state::ScheduledRunExecutionOutcome::LateEvidence(_) => TickOutcome::LostLease,
        _ => TickOutcome::Failed,
      })
  }

  async fn commit_execution_result_bounded(
    &self,
    claim: &ClaimedScheduledRun,
    result: ExecutionResult,
    mut terminal_deadline: tokio::time::Instant,
    mut hard_stop_deadline: tokio::time::Instant,
    mut shutdown: Option<watch::Receiver<bool>>,
  ) -> Result<TickOutcome, StateError> {
    loop {
      let commit = tokio::time::timeout_at(
        terminal_deadline,
        self.commit_execution_result(claim, result.clone()),
      );
      tokio::pin!(commit);
      let commit = match shutdown.as_ref() {
        Some(shutdown_rx) => tokio::select! {
          result = &mut commit => result,
          () = cancellation_requested(shutdown_rx.clone()) => {
            shutdown = None;
            terminal_deadline = tokio::time::Instant::now()
              .checked_add(self.policy.finalization_grace)
              .ok_or_else(|| StateError::InvalidSchedulerState {
                reason: "scheduled shutdown terminal deadline overflow".to_owned(),
              })?;
            hard_stop_deadline = terminal_deadline
              .checked_add(self.policy.finalization_grace)
              .ok_or_else(|| StateError::InvalidSchedulerState {
                reason: "scheduled shutdown hard-stop deadline overflow".to_owned(),
              })?;
            continue;
          },
        },
        None => commit.await,
      };
      match commit {
        Ok(Err(error)) if error.is_transient_storage_contention() => {
          if tokio::time::Instant::now() >= terminal_deadline {
            break;
          }
          tokio::time::sleep(Duration::from_millis(2)).await;
        }
        Ok(outcome) => return outcome,
        Err(_) => break,
      }
    }
    let fallback = self.state.record_scheduled_run_execution_outcome(
      &claim.binding,
      ScheduledExecutionDisposition::Terminal(ScheduledExecutionTerminal::OutcomeUnknown),
      "terminal_commit_deadline",
      "scheduled terminal commit exceeded its bounded database window",
      self.clock.now(),
    );
    match tokio::time::timeout_at(hard_stop_deadline, fallback).await {
      Ok(Ok(codeoff_state::ScheduledRunExecutionOutcome::LateEvidence(_))) => {
        Ok(TickOutcome::LostLease)
      }
      Ok(Ok(_)) => Ok(TickOutcome::Failed),
      Ok(Err(StateError::ScheduledRunLostLease)) | Err(_) => Ok(TickOutcome::LostLease),
      Ok(Err(error)) if error.is_transient_storage_contention() => Ok(TickOutcome::LostLease),
      Ok(Err(error)) => Err(error),
    }
  }
}

fn task_from_claim(
  claim: &ClaimedScheduledRun,
  authority: &ScheduledPrepareAuthority,
) -> Result<AgentTask, PrepareFailure> {
  reject_dynamic_tool_exposure(&claim.capability_json)?;
  if authority.instruction().len()
    > usize::try_from(claim.scheduler_policy.max_prompt_bytes).unwrap_or(usize::MAX)
  {
    return Err(PrepareFailure::fatal(
      "scheduled_instruction_exceeds_max_prompt_bytes",
    ));
  }
  let previous_success = authority
    .previous_success()
    .map(|content| PreviousSuccessContext {
      content: content.to_owned(),
      was_truncated: authority.previous_success_was_truncated(),
    });
  let task = AgentTask {
    task_id: format!(
      "scheduled:{}:{}:{}",
      claim.binding.run_id(),
      claim.binding.attempt(),
      claim.binding.fence()
    ),
    instruction: authority.instruction().to_owned(),
    source: InvocationSource::ScheduledRun {
      job_id: claim.binding.job_id().to_owned(),
      run_id: claim.binding.run_id().to_owned(),
      scheduled_for: claim.scheduled_for.to_string(),
    },
    principal: InvocationPrincipal::service("codeoff-scheduler"),
    session: SessionMode::Fresh,
    channel: None,
    previous_success,
    tool_policy: ToolPolicy::None,
    feedback_target: None,
  };
  task.validate().map_err(PrepareFailure::artifact)?;
  Ok(task)
}

fn reject_dynamic_tool_exposure(capability_json: &str) -> Result<(), PrepareFailure> {
  let capability: Value = serde_json::from_str(capability_json)
    .map_err(|_| PrepareFailure::tool_list("scheduled_capability_tool_list_invalid"))?;
  let prohibited = CHANNEL_DYNAMIC_TOOL_NAMES
    .iter()
    .chain(SCHEDULE_DYNAMIC_TOOL_NAMES)
    .copied()
    .collect::<Vec<_>>();
  if contains_prohibited_tool(&capability, &prohibited) {
    return Err(PrepareFailure::tool_list(
      "scheduled_capability_exposes_dynamic_tools",
    ));
  }
  Ok(())
}

fn contains_prohibited_tool(value: &Value, prohibited: &[&str]) -> bool {
  match value {
    Value::String(value) => prohibited.contains(&value.as_str()),
    Value::Array(values) => values
      .iter()
      .any(|value| contains_prohibited_tool(value, prohibited)),
    Value::Object(values) => values
      .values()
      .any(|value| contains_prohibited_tool(value, prohibited)),
    _ => false,
  }
}

fn execution_failure_disposition(
  claim: &ClaimedScheduledRun,
  result: ExecutionResult,
  now: i64,
) -> (ScheduledExecutionDisposition, &'static str, &'static str) {
  let retry = |exhausted| match (
    claim.scheduler_policy.run_retry_at(
      claim.binding.run_id(),
      claim.binding.attempt(),
      claim.scheduled_for,
      now,
    ),
    claim.scheduler_policy.run_deadline_at(claim.scheduled_for),
  ) {
    (Some(retry_at), Some(deadline_at)) => ScheduledExecutionDisposition::RetryAt {
      retry_at,
      deadline_at,
      max_attempts: i64::from(claim.scheduler_policy.run_max_attempts),
      transport: TransportConvergence::Converged,
      exhausted,
    },
    _ => ScheduledExecutionDisposition::Terminal(exhausted),
  };
  match result {
    ExecutionResult::Interrupted {
      transport_converged: true,
    } => (
      retry(ScheduledExecutionTerminal::Failed),
      "interrupted",
      "scheduled execution interrupted",
    ),
    ExecutionResult::TimedOut {
      transport_converged: true,
    } => (
      retry(ScheduledExecutionTerminal::TimedOut),
      "timed_out",
      "scheduled execution timed out",
    ),
    ExecutionResult::Interrupted { .. }
    | ExecutionResult::TimedOut { .. }
    | ExecutionResult::TransportLost { .. } => (
      ScheduledExecutionDisposition::Terminal(ScheduledExecutionTerminal::OutcomeUnknown),
      "transport_not_converged",
      "scheduled execution transport did not converge",
    ),
    ExecutionResult::Failed { .. } => (
      ScheduledExecutionDisposition::Terminal(ScheduledExecutionTerminal::Failed),
      "turn_failed",
      "scheduled execution failed",
    ),
    ExecutionResult::AcceptedDispatch => (
      ScheduledExecutionDisposition::Terminal(ScheduledExecutionTerminal::OutcomeUnknown),
      "accepted_dispatch_without_result",
      "scheduled execution returned no final result",
    ),
    ExecutionResult::Empty => (
      ScheduledExecutionDisposition::Terminal(ScheduledExecutionTerminal::Failed),
      "empty_result",
      "scheduled execution returned an empty result",
    ),
    ExecutionResult::Completed { .. } => unreachable!("completed results commit separately"),
  }
}

fn prepare_nonce(binding: &RunLeaseBinding) -> String {
  let sequence = PREPARE_NONCE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
  let timestamp = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .map_or(0, |duration| duration.as_nanos());
  sha256_hex(
    format!(
      "scheduled-prepare-nonce-v1\n{}\n{}\n{}\n{}\n{}\n{timestamp}\n{sequence}",
      std::process::id(),
      binding.run_id(),
      binding.job_id(),
      binding.attempt(),
      binding.fence(),
    )
    .as_bytes(),
  )
}

fn join_error(error: tokio::task::JoinError) -> StateError {
  StateError::InvalidSchedulerState {
    reason: format!("scheduled blocking task failed: {error}"),
  }
}

async fn stop_heartbeat(heartbeat: &mut JoinHandle<()>) {
  heartbeat.abort();
  let _ = heartbeat.await;
}

fn sha256_hex(value: &[u8]) -> String {
  let mut digest = Sha256::new();
  digest.update(value);
  digest
    .finalize()
    .iter()
    .fold(String::with_capacity(64), |mut encoded, byte| {
      write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
      encoded
    })
}

#[cfg(test)]
mod tests {
  use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize};
  use std::sync::{Barrier, Mutex, mpsc};

  use codeoff_agent_contract::{InvocationPrincipalRef, InvocationSource};
  use codeoff_state::{
    CapabilityProfileSnapshot, CreateScheduledJob, DeliveryTargetSnapshot,
    ExpiredRunReclaimOutcome, MaterializationOutcome, PrincipalKey, ScheduleSpec,
    ScheduledExecutorEpochAuthority, ScheduledJobDefinition,
  };
  use tempfile::{TempDir, tempdir};

  use super::*;

  #[derive(Default)]
  struct RecordingTelemetry {
    events: Mutex<Vec<SchedulerTelemetryEvent>>,
  }

  impl SchedulerTelemetry for RecordingTelemetry {
    fn record(&self, event: SchedulerTelemetryEvent) {
      self.events.lock().expect("telemetry events").push(event);
    }
  }

  #[test]
  fn test_execution_tick_telemetry_uses_fixed_outcomes() {
    for (outcome, expected) in [
      (TickOutcome::Cancelled, SchedulerOperationStatus::Cancelled),
      (
        TickOutcome::Unavailable,
        SchedulerOperationStatus::Unavailable,
      ),
      (TickOutcome::Idle, SchedulerOperationStatus::Idle),
      (TickOutcome::Completed, SchedulerOperationStatus::Completed),
      (TickOutcome::Failed, SchedulerOperationStatus::Failed),
      (
        TickOutcome::LostLease,
        SchedulerOperationStatus::LostAuthority,
      ),
    ] {
      assert_eq!(execution_tick_status(outcome), expected);
    }
  }

  const TARGET_IDENTITY: &str = "0000000000000000000000000000000000000000000000000000000000000001";

  struct TestClock(AtomicI64, i64);

  #[async_trait]
  impl SchedulerClock for TestClock {
    fn now(&self) -> i64 {
      self.0.load(Ordering::Acquire)
    }

    async fn sleep(&self, duration: Duration) {
      tokio::time::sleep(duration).await;
      self.0.fetch_add(self.1, Ordering::AcqRel);
    }
  }

  #[derive(Clone)]
  struct FakeBackend {
    seen: Arc<Mutex<Vec<AgentTask>>>,
    result: ExecutionResult,
    prepare_delay: Duration,
    execution_delay: Duration,
    honor_execution_cancellation: bool,
    completion_barrier: Option<Arc<Barrier>>,
    active: Arc<AtomicUsize>,
    max_active: Arc<AtomicUsize>,
  }

  impl FakeBackend {
    fn new(result: ExecutionResult) -> Self {
      Self {
        seen: Arc::new(Mutex::new(Vec::new())),
        result,
        prepare_delay: Duration::ZERO,
        execution_delay: Duration::ZERO,
        honor_execution_cancellation: true,
        completion_barrier: None,
        active: Arc::new(AtomicUsize::new(0)),
        max_active: Arc::new(AtomicUsize::new(0)),
      }
    }
  }

  impl ScheduledExecutionBackend for FakeBackend {
    fn readiness(&self) -> ExecutorReadiness {
      ExecutorReadiness::Ready
    }

    fn prepare(
      &self,
      input: PrepareInput,
      _authorization: BackendAuthorization,
    ) -> Result<BackendPrepared, PrepareFailure> {
      if !self.prepare_delay.is_zero() {
        std::thread::sleep(self.prepare_delay);
      }
      assert!(!input.definition_json.is_empty());
      assert_eq!(input.capability_json, "{}");
      assert_eq!(input.capability_digest, "profile");
      assert!(input.targets_json.contains(TARGET_IDENTITY));
      self.seen.lock().expect("seen tasks").push(input.task);
      let profile = input.authority.attestation_json(true);
      Ok(BackendPrepared {
        authority_digest: input.authority.digest().to_owned(),
        authority: input.authority,
        attested_profile_json: profile.clone(),
        attested_profile_digest: sha256_hex(profile.as_bytes()),
        execution: Box::new(FakePrepared {
          result: self.result.clone(),
          execution_delay: self.execution_delay,
          honor_cancellation: self.honor_execution_cancellation,
          completion_barrier: self.completion_barrier.clone(),
          active: Arc::clone(&self.active),
          max_active: Arc::clone(&self.max_active),
        }),
      })
    }
  }

  struct SwitchableBackend {
    available: Arc<AtomicBool>,
    inner: FakeBackend,
  }

  struct AdmissionBackend {
    admission: Arc<Mutex<RefreshedExecutorAdmission>>,
    inner: FakeBackend,
  }

  #[async_trait]
  impl ScheduledExecutionBackend for AdmissionBackend {
    fn readiness(&self) -> ExecutorReadiness {
      ExecutorReadiness::Ready
    }

    async fn refresh_admission(&self) -> RefreshedExecutorAdmission {
      self.admission.lock().expect("executor admission").clone()
    }

    fn prepare(
      &self,
      input: PrepareInput,
      authorization: BackendAuthorization,
    ) -> Result<BackendPrepared, PrepareFailure> {
      self.inner.prepare(input, authorization)
    }
  }

  fn test_executor_authority(epoch: i64, marker: char) -> ScheduledExecutorEpochAuthority {
    ScheduledExecutorEpochAuthority {
      schema_version: 1,
      deployment_epoch: epoch,
      attestation_id: marker.to_string().repeat(64),
      attestation_digest: "b".repeat(64),
      profile_digest: "c".repeat(64),
      issued_at: 100,
      expires_at: 200,
    }
  }

  fn test_executor_admission(
    authority: &ScheduledExecutorEpochAuthority,
    deadline: i64,
  ) -> ScheduledExecutorAdmission {
    ScheduledExecutorAdmission {
      schema_version: authority.schema_version,
      deployment_epoch: authority.deployment_epoch,
      attestation_id: authority.attestation_id.clone(),
      profile_digest: authority.profile_digest.clone(),
      signed_not_after: authority.expires_at,
      operation_deadline: deadline,
    }
  }

  #[async_trait]
  impl ScheduledExecutionBackend for SwitchableBackend {
    fn readiness(&self) -> ExecutorReadiness {
      if self.available.load(Ordering::Acquire) {
        ExecutorReadiness::Ready
      } else {
        ExecutorReadiness::Unavailable
      }
    }

    async fn refresh_readiness(&self) -> ExecutorReadiness {
      self.readiness()
    }

    fn prepare(
      &self,
      input: PrepareInput,
      authorization: BackendAuthorization,
    ) -> Result<BackendPrepared, PrepareFailure> {
      self.inner.prepare(input, authorization)
    }
  }

  struct FakePrepared {
    result: ExecutionResult,
    execution_delay: Duration,
    honor_cancellation: bool,
    completion_barrier: Option<Arc<Barrier>>,
    active: Arc<AtomicUsize>,
    max_active: Arc<AtomicUsize>,
  }

  struct SwappingBackend {
    barrier: Arc<Barrier>,
    authorities: Arc<Mutex<Vec<ScheduledPrepareAuthority>>>,
    executions: Arc<AtomicUsize>,
  }

  impl ScheduledExecutionBackend for SwappingBackend {
    fn readiness(&self) -> ExecutorReadiness {
      ExecutorReadiness::Ready
    }

    fn prepare(
      &self,
      input: PrepareInput,
      _authorization: BackendAuthorization,
    ) -> Result<BackendPrepared, PrepareFailure> {
      self
        .authorities
        .lock()
        .expect("swap authorities")
        .push(input.authority.clone());
      self.barrier.wait();
      let swapped = self
        .authorities
        .lock()
        .expect("swap authorities")
        .iter()
        .find(|authority| authority.digest() != input.authority.digest())
        .expect("other authority")
        .clone();
      let profile = swapped.attestation_json(true);
      Ok(BackendPrepared {
        authority_digest: swapped.digest().to_owned(),
        authority: swapped,
        attested_profile_json: profile.clone(),
        attested_profile_digest: sha256_hex(profile.as_bytes()),
        execution: Box::new(CountingPrepared(Arc::clone(&self.executions))),
      })
    }
  }

  struct CountingPrepared(Arc<AtomicUsize>);

  impl PreparedExecution for CountingPrepared {
    fn execute(self: Box<Self>, _cancellation: Arc<AtomicBool>) -> ExecutionResult {
      self.0.fetch_add(1, Ordering::AcqRel);
      ExecutionResult::Completed {
        summary: "must not execute".to_owned(),
      }
    }
  }

  impl PreparedExecution for FakePrepared {
    fn execute(self: Box<Self>, cancellation: Arc<AtomicBool>) -> ExecutionResult {
      let active = self.active.fetch_add(1, Ordering::AcqRel) + 1;
      self.max_active.fetch_max(active, Ordering::AcqRel);
      let started = std::time::Instant::now();
      while started.elapsed() < self.execution_delay
        && (!self.honor_cancellation || !cancellation.load(Ordering::Acquire))
      {
        std::thread::sleep(Duration::from_millis(1));
      }
      if let Some(barrier) = self.completion_barrier {
        barrier.wait();
      }
      self.active.fetch_sub(1, Ordering::AcqRel);
      self.result
    }
  }

  async fn fixture(job_ids: &[(&str, i64)]) -> (TempDir, StateStore) {
    let temp = tempdir().expect("tempdir");
    let store = StateStore::initialize(&temp.path().join("state"), None)
      .await
      .expect("state");
    for (job_id, scheduled_for) in job_ids {
      create_job(&store, job_id, *scheduled_for).await;
      assert!(matches!(
        store
          .materialize_due_schedule(job_id, 0, *scheduled_for)
          .await
          .expect("materialize"),
        MaterializationOutcome::Created(_)
      ));
    }
    (temp, store)
  }

  async fn create_job(store: &StateStore, job_id: &str, scheduled_for: i64) {
    let principal = PrincipalKey::new("user", "test", "tenant", "owner").expect("principal");
    store
      .create_scheduled_job(&CreateScheduledJob {
        job_id: job_id.to_owned(),
        schedule_id: format!("schedule-{job_id}"),
        definition: ScheduledJobDefinition::new(
          1,
          format!(
            r#"{{"instruction":"execute {job_id}","previous_success":{{"kind":"none"}},"schema_version":1}}"#
          ),
        )
        .expect("definition"),
        creator: principal.clone(),
        owner: principal,
        capability: CapabilityProfileSnapshot::new(1, "profile", "{}").expect("capability"),
        targets: vec![DeliveryTargetSnapshot::new(
          format!("target-{job_id}"),
          "none",
          "none",
          "tenant",
          "none",
          "{}",
          1,
          "resolver-v1",
          TARGET_IDENTITY,
        )
        .expect("target")],
        schedule: ScheduleSpec::once(scheduled_for),
        now: 100,
      })
      .await
      .expect("create job");
  }

  fn install_executor_commit_gate(
    store: &StateStore,
    before_commit: bool,
  ) -> (mpsc::Receiver<()>, mpsc::SyncSender<()>) {
    let (reached_tx, reached_rx) = mpsc::sync_channel(0);
    let (resume_tx, resume_rx) = mpsc::sync_channel(0);
    let hook = move || {
      reached_tx.send(()).expect("report commit gate");
      resume_rx.recv().expect("resume commit gate");
    };
    if before_commit {
      store.set_scheduled_executor_before_commit_hook_for_tests(hook);
    } else {
      store.set_scheduled_executor_after_commit_hook_for_tests(hook);
    }
    (reached_rx, resume_tx)
  }

  async fn wait_for_admitted_mutation_cancellation(cancellation: &AtomicBool) {
    tokio::time::timeout(Duration::from_secs(1), async {
      while !cancellation.load(Ordering::Acquire) {
        tokio::task::yield_now().await;
      }
    })
    .await
    .expect("admitted mutation cancellation");
  }

  fn orchestrator(
    state: StateStore,
    backend: Arc<dyn ScheduledExecutionBackend>,
    clock: Arc<dyn SchedulerClock>,
    parallelism: usize,
  ) -> ScheduledRunOrchestrator {
    ScheduledRunOrchestrator {
      state,
      backend,
      clock,
      budget: GlobalTurnBudget::new(parallelism),
      guardians: Arc::new(BlockingGuardianRegistry::default()),
      lease_owner: "runtime-test".to_owned(),
      run_claims_enabled: true,
      policy: ExecutionPolicy {
        lease_seconds: 20,
        heartbeat_interval: Duration::from_mins(1),
        total_timeout: Duration::from_secs(10),
        prepare_grace: Duration::from_millis(20),
        cancellation_grace: Duration::from_millis(20),
        finalization_grace: Duration::from_millis(20),
        ..ExecutionPolicy::default()
      },
      telemetry: Arc::new(NoopSchedulerTelemetry),
    }
  }

  #[tokio::test]
  async fn test_completed_execution_emits_numeric_authoritative_attempt() {
    let (_temp, state) = fixture(&[("telemetry-attempt", 110)]).await;
    let backend = Arc::new(FakeBackend::new(ExecutionResult::Completed {
      summary: "done".to_owned(),
    }));
    let telemetry = Arc::new(RecordingTelemetry::default());
    let mut runtime = orchestrator(state, backend, Arc::new(TestClock(111.into(), 1)), 1);
    runtime.telemetry = telemetry.clone();

    assert_eq!(
      runtime.run_once().await.expect("execution tick"),
      TickOutcome::Completed
    );
    let events = telemetry.events.lock().expect("telemetry events");
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].status, SchedulerOperationStatus::Started);
    assert_eq!(events[0].attempt, None);
    assert_eq!(events[1].worker, SchedulerWorker::Execution);
    assert_eq!(events[1].operation, SchedulerOperation::Attempt);
    assert_eq!(events[1].status, SchedulerOperationStatus::Completed);
    assert_eq!(events[1].attempt, Some(1));
    assert_eq!(events[1].error_kind, None);
  }

  #[tokio::test]
  async fn test_unavailable_readiness_produces_zero_claims() {
    let (_temp, state) = fixture(&[("unavailable", 110)]).await;
    let runtime = ScheduledRunOrchestrator::unavailable(
      state.clone(),
      GlobalTurnBudget::new(1),
      Arc::new(BlockingGuardianRegistry::default()),
      "runtime-test",
    );
    assert_eq!(
      runtime.run_once().await.expect("tick"),
      TickOutcome::Unavailable
    );
    let claim = state
      .claim_next_scheduled_run("proof", 111, 130)
      .await
      .expect("claim proof")
      .expect("run remained pending");
    assert_eq!(claim.binding.attempt(), 1);
  }

  #[tokio::test]
  async fn test_live_readiness_gap_has_zero_materialization_or_claim_delta_and_recovers() {
    let temp = tempdir().expect("tempdir");
    let state = StateStore::initialize(&temp.path().join("state"), None)
      .await
      .expect("state");
    create_job(&state, "authority-gap", 110).await;
    let available = Arc::new(AtomicBool::new(false));
    let backend = Arc::new(SwitchableBackend {
      available: Arc::clone(&available),
      inner: FakeBackend::new(ExecutionResult::Completed {
        summary: "rotated".to_owned(),
      }),
    });
    let runtime = orchestrator(
      state.clone(),
      backend,
      Arc::new(TestClock(AtomicI64::new(111), 1)),
      1,
    );
    let before = state
      .scheduler_observability_snapshot(111, 100, 1_000)
      .await
      .expect("snapshot before gap");
    let (_shutdown, shutdown_rx) = watch::channel(false);

    assert_eq!(
      Box::pin(run_scheduled_worker_tick(
        &state,
        &runtime,
        shutdown_rx.clone()
      ))
      .await
      .expect("gap tick"),
      TickOutcome::Unavailable
    );
    assert_eq!(
      state
        .scheduler_observability_snapshot(111, 100, 1_000)
        .await
        .expect("snapshot during gap"),
      before
    );

    available.store(true, Ordering::Release);
    assert_eq!(
      Box::pin(run_scheduled_worker_tick(&state, &runtime, shutdown_rx))
        .await
        .expect("recovery tick"),
      TickOutcome::Completed
    );
  }

  #[tokio::test]
  async fn test_executor_admission_deadline_bounds_claim_lock_wait_without_counter_delta() {
    let (_temp, state) = fixture(&[("admission-lock", 110)]).await;
    let authority = test_executor_authority(1, 'a');
    state
      .register_scheduled_executor_epoch(&authority, 110)
      .await
      .expect("register authority");
    let admission = Arc::new(Mutex::new(RefreshedExecutorAdmission::Authority(
      test_executor_admission(&authority, 116),
    )));
    let runtime = orchestrator(
      state.clone(),
      Arc::new(AdmissionBackend {
        admission,
        inner: FakeBackend::new(ExecutionResult::Completed {
          summary: "must not execute under contention".to_owned(),
        }),
      }),
      Arc::new(TestClock(AtomicI64::new(111), 1)),
      1,
    );
    let lock = state
      .acquire_exclusive_storage_lock_for_tests()
      .await
      .expect("exclusive lock");
    tokio::time::pause();

    assert_eq!(
      runtime.run_once().await.expect("bounded claim"),
      TickOutcome::Unavailable
    );
    drop(lock);
    tokio::time::resume();
    tokio::time::sleep(Duration::from_millis(50)).await;
    let claim = state
      .claim_next_scheduled_run("proof", 112, 140)
      .await
      .expect("claim proof")
      .expect("run remains pending");
    assert_eq!(claim.binding.attempt(), 1);
    assert_eq!(claim.binding.fence(), 1);
  }

  #[tokio::test]
  async fn test_rotated_admission_cannot_materialize_and_per_item_refresh_recovers() {
    let temp = tempdir().expect("tempdir");
    let state = StateStore::initialize(&temp.path().join("state"), None)
      .await
      .expect("state");
    create_job(&state, "admission-rotation", 110).await;
    let epoch_one = test_executor_authority(1, 'a');
    let epoch_two = test_executor_authority(2, 'd');
    state
      .register_scheduled_executor_epoch(&epoch_one, 105)
      .await
      .expect("epoch one");
    state
      .register_scheduled_executor_epoch(&epoch_two, 106)
      .await
      .expect("epoch two");
    let admission = Arc::new(Mutex::new(RefreshedExecutorAdmission::Authority(
      test_executor_admission(&epoch_one, 150),
    )));
    let runtime = orchestrator(
      state.clone(),
      Arc::new(AdmissionBackend {
        admission: Arc::clone(&admission),
        inner: FakeBackend::new(ExecutionResult::Completed {
          summary: "recovered".to_owned(),
        }),
      }),
      Arc::new(TestClock(AtomicI64::new(111), 1)),
      1,
    );
    let before = state
      .scheduler_observability_snapshot(111, 10, 100)
      .await
      .expect("before rotation");
    let (_shutdown, shutdown_rx) = watch::channel(false);

    assert_eq!(
      Box::pin(run_scheduled_worker_tick(
        &state,
        &runtime,
        shutdown_rx.clone()
      ))
      .await
      .expect("stale admission tick"),
      TickOutcome::Unavailable
    );
    assert_eq!(
      state
        .scheduler_observability_snapshot(111, 10, 100)
        .await
        .expect("after rejected rotation"),
      before
    );

    *admission.lock().expect("executor admission") =
      RefreshedExecutorAdmission::Authority(test_executor_admission(&epoch_two, 150));
    assert_eq!(
      Box::pin(run_scheduled_worker_tick(&state, &runtime, shutdown_rx))
        .await
        .expect("rotated admission tick"),
      TickOutcome::Completed
    );
  }

  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn test_materialization_cancellation_before_commit_rolls_back_and_recovers() {
    let temp = tempdir().expect("tempdir");
    let state = StateStore::initialize(&temp.path().join("state"), None)
      .await
      .expect("state");
    create_job(&state, "materialize-pre-commit-cancel", 110).await;
    let authority = test_executor_authority(1, 'a');
    state
      .register_scheduled_executor_epoch(&authority, 105)
      .await
      .expect("register authority");
    let admission = test_executor_admission(&authority, 150);
    let (reached, resume) = install_executor_commit_gate(&state, true);
    let cancellation = Arc::new(AtomicBool::new(false));
    let task_cancellation = Arc::clone(&cancellation);
    let helper_cancellation = Arc::clone(&cancellation);
    let task_state = state.clone();
    let task_admission = admission.clone();
    let (shutdown, shutdown_rx) = watch::channel(false);
    let caller = tokio::spawn(join_admitted_state_mutation(
      async move {
        task_state
          .materialize_due_schedule_with_admission(
            "materialize-pre-commit-cancel",
            0,
            111,
            &task_admission,
            &|| 111,
            task_cancellation.as_ref(),
          )
          .await
      },
      helper_cancellation,
      shutdown_rx,
    ));

    reached
      .recv_timeout(Duration::from_secs(1))
      .expect("pre-commit gate");
    shutdown.send(true).expect("cancel materialization");
    wait_for_admitted_mutation_cancellation(cancellation.as_ref()).await;
    assert!(!caller.is_finished());
    resume.send(()).expect("resume materialization");
    let joined = caller
      .await
      .expect("caller join")
      .expect("mutation task join");
    assert!(joined.cancellation_requested);
    assert!(matches!(
      joined.result,
      Err(StateError::ScheduledExecutorAdmissionUnavailable)
    ));
    let snapshot = state
      .scheduler_observability_snapshot(111, 10, 100)
      .await
      .expect("rolled-back snapshot");
    assert_eq!(snapshot.due_jobs.value, 1);
    assert_eq!(snapshot.pending_runs.value, 0);

    assert!(matches!(
      state
        .materialize_due_schedule_with_admission(
          "materialize-pre-commit-cancel",
          0,
          111,
          &admission,
          &|| 111,
          &AtomicBool::new(false),
        )
        .await
        .expect("recovered materialization"),
      MaterializationOutcome::Created(_)
    ));
  }

  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn test_materialization_cancellation_after_commit_returns_committed_outcome() {
    let temp = tempdir().expect("tempdir");
    let state = StateStore::initialize(&temp.path().join("state"), None)
      .await
      .expect("state");
    create_job(&state, "materialize-post-commit-cancel", 110).await;
    let authority = test_executor_authority(1, 'b');
    state
      .register_scheduled_executor_epoch(&authority, 105)
      .await
      .expect("register authority");
    let admission = test_executor_admission(&authority, 150);
    let (reached, resume) = install_executor_commit_gate(&state, false);
    let cancellation = Arc::new(AtomicBool::new(false));
    let task_cancellation = Arc::clone(&cancellation);
    let helper_cancellation = Arc::clone(&cancellation);
    let task_state = state.clone();
    let task_admission = admission;
    let (shutdown, shutdown_rx) = watch::channel(false);
    let caller = tokio::spawn(join_admitted_state_mutation(
      async move {
        task_state
          .materialize_due_schedule_with_admission(
            "materialize-post-commit-cancel",
            0,
            111,
            &task_admission,
            &|| 111,
            task_cancellation.as_ref(),
          )
          .await
      },
      helper_cancellation,
      shutdown_rx,
    ));

    reached
      .recv_timeout(Duration::from_secs(1))
      .expect("post-commit gate");
    shutdown.send(true).expect("cancel materialization");
    wait_for_admitted_mutation_cancellation(cancellation.as_ref()).await;
    assert!(!caller.is_finished());
    resume.send(()).expect("return committed outcome");
    let joined = caller
      .await
      .expect("caller join")
      .expect("mutation task join");
    assert!(joined.cancellation_requested);
    assert!(matches!(
      joined.result,
      Ok(MaterializationOutcome::Created(_))
    ));
    let snapshot = state
      .scheduler_observability_snapshot(111, 10, 100)
      .await
      .expect("committed snapshot");
    assert_eq!(snapshot.due_jobs.value, 0);
    assert_eq!(snapshot.pending_runs.value, 1);
  }

  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn test_claim_cancellation_before_commit_rolls_back_counters_and_recovers() {
    let (_temp, state) = fixture(&[("claim-pre-commit-cancel", 110)]).await;
    let authority = test_executor_authority(1, 'c');
    state
      .register_scheduled_executor_epoch(&authority, 105)
      .await
      .expect("register authority");
    let admission = test_executor_admission(&authority, 150);
    let (reached, resume) = install_executor_commit_gate(&state, true);
    let cancellation = Arc::new(AtomicBool::new(false));
    let task_cancellation = Arc::clone(&cancellation);
    let helper_cancellation = Arc::clone(&cancellation);
    let task_state = state.clone();
    let task_admission = admission.clone();
    let (shutdown, shutdown_rx) = watch::channel(false);
    let caller = tokio::spawn(join_admitted_state_mutation(
      async move {
        task_state
          .claim_next_scheduled_run_with_admission(
            "claim-pre-commit",
            111,
            130,
            &task_admission,
            &|| 111,
            task_cancellation.as_ref(),
          )
          .await
      },
      helper_cancellation,
      shutdown_rx,
    ));

    reached
      .recv_timeout(Duration::from_secs(1))
      .expect("pre-commit gate");
    shutdown.send(true).expect("cancel claim");
    wait_for_admitted_mutation_cancellation(cancellation.as_ref()).await;
    assert!(!caller.is_finished());
    resume.send(()).expect("resume claim");
    let joined = caller
      .await
      .expect("caller join")
      .expect("mutation task join");
    assert!(joined.cancellation_requested);
    assert!(matches!(
      joined.result,
      Err(StateError::ScheduledExecutorAdmissionUnavailable)
    ));

    let claim = state
      .claim_next_scheduled_run_with_admission(
        "claim-recovery",
        112,
        131,
        &admission,
        &|| 112,
        &AtomicBool::new(false),
      )
      .await
      .expect("recovered claim")
      .expect("pending run");
    assert_eq!(claim.binding.attempt(), 1);
    assert_eq!(claim.binding.fence(), 1);
  }

  #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
  async fn test_claim_cancellation_after_commit_returns_committed_counters() {
    let (_temp, state) = fixture(&[("claim-post-commit-cancel", 110)]).await;
    let authority = test_executor_authority(1, 'd');
    state
      .register_scheduled_executor_epoch(&authority, 105)
      .await
      .expect("register authority");
    let admission = test_executor_admission(&authority, 150);
    let (reached, resume) = install_executor_commit_gate(&state, false);
    let cancellation = Arc::new(AtomicBool::new(false));
    let task_cancellation = Arc::clone(&cancellation);
    let helper_cancellation = Arc::clone(&cancellation);
    let task_state = state.clone();
    let task_admission = admission;
    let (shutdown, shutdown_rx) = watch::channel(false);
    let caller = tokio::spawn(join_admitted_state_mutation(
      async move {
        task_state
          .claim_next_scheduled_run_with_admission(
            "claim-post-commit",
            111,
            130,
            &task_admission,
            &|| 111,
            task_cancellation.as_ref(),
          )
          .await
      },
      helper_cancellation,
      shutdown_rx,
    ));

    reached
      .recv_timeout(Duration::from_secs(1))
      .expect("post-commit gate");
    shutdown.send(true).expect("cancel claim");
    wait_for_admitted_mutation_cancellation(cancellation.as_ref()).await;
    assert!(!caller.is_finished());
    resume.send(()).expect("return committed claim");
    let joined = caller
      .await
      .expect("caller join")
      .expect("mutation task join");
    assert!(joined.cancellation_requested);
    let claim = joined
      .result
      .expect("committed claim outcome")
      .expect("committed claim");
    assert_eq!(claim.binding.attempt(), 1);
    assert_eq!(claim.binding.fence(), 1);
  }

  #[tokio::test]
  async fn test_run_claim_kill_switch_reconciles_without_materializing_or_claiming() {
    let (_temp, state) = fixture(&[("unavailable-recovery", 110)]).await;
    create_job(&state, "kill-switch-due", 111).await;
    let expired_claim = state
      .claim_next_scheduled_run("stale-worker", 111, 120)
      .await
      .expect("claim stale run")
      .expect("stale run");
    let mut runtime = orchestrator(
      state.clone(),
      Arc::new(FakeBackend::new(ExecutionResult::Completed {
        summary: "must not execute".to_owned(),
      })),
      Arc::new(TestClock(AtomicI64::new(121), 1)),
      1,
    );
    runtime.run_claims_enabled = false;
    let (_shutdown, shutdown_rx) = watch::channel(false);

    assert_eq!(
      Box::pin(run_scheduled_worker_tick(&state, &runtime, shutdown_rx))
        .await
        .expect("tick"),
      TickOutcome::Unavailable
    );
    assert!(matches!(
      state
        .materialize_due_schedule("kill-switch-due", 0, 121)
        .await
        .expect("materialize proof"),
      MaterializationOutcome::Created(_)
    ));
    let current = state
      .claim_next_scheduled_run("current-worker", 151, 180)
      .await
      .expect("claim recovered run")
      .expect("recovered run");
    assert_eq!(current.binding.run_id(), expired_claim.binding.run_id());
    assert_eq!(
      current.binding.attempt(),
      expired_claim.binding.attempt() + 1
    );
    assert!(current.binding.fence() > expired_claim.binding.fence());
  }

  #[tokio::test]
  async fn test_worker_disabled_and_unavailable_are_fail_closed_before_materialization() {
    let temp = tempdir().expect("tempdir");
    let state = StateStore::initialize(&temp.path().join("state"), None)
      .await
      .expect("state");
    create_job(&state, "fail-closed-worker", 110).await;

    assert!(
      spawn_scheduled_worker(
        state.clone(),
        GlobalTurnBudget::new(1),
        ScheduledWorkerConfig::default(),
        None,
        Arc::new(NoopSchedulerTelemetry),
      )
      .expect("disabled worker")
      .is_none()
    );
    let worker = spawn_scheduled_worker(
      state.clone(),
      GlobalTurnBudget::new(1),
      ScheduledWorkerConfig {
        enabled: true,
        run_claims_enabled: true,
        ..ScheduledWorkerConfig::default()
      },
      None,
      Arc::new(NoopSchedulerTelemetry),
    );
    assert!(matches!(
      worker,
      Err(StateError::InvalidSchedulerState { .. })
    ));

    assert_eq!(
      state
        .list_due_scheduled_jobs(111, 10)
        .await
        .expect("due jobs"),
      ["fail-closed-worker"]
    );
    assert!(matches!(
      state
        .materialize_due_schedule("fail-closed-worker", 0, 111)
        .await
        .expect("materialize proof"),
      MaterializationOutcome::Created(_)
    ));
    let claim = state
      .claim_next_scheduled_run("proof", 111, 130)
      .await
      .expect("claim proof")
      .expect("unavailable worker left run unclaimed");
    assert_eq!(claim.binding.attempt(), 1);
  }

  #[tokio::test]
  async fn test_worker_materializes_executes_and_drains_without_channel_context() {
    let temp = tempdir().expect("tempdir");
    let state = StateStore::initialize(&temp.path().join("state"), None)
      .await
      .expect("state");
    create_job(&state, "no-slack-worker", 110).await;
    let backend = Arc::new(FakeBackend::new(ExecutionResult::Completed {
      summary: "scheduled result".to_owned(),
    }));
    let runtime = orchestrator(
      state.clone(),
      backend.clone(),
      Arc::new(TestClock(AtomicI64::new(111), 1)),
      1,
    );
    let (shutdown, shutdown_rx) = watch::channel(false);
    let worker = tokio::spawn(run_scheduled_worker(
      state,
      runtime,
      shutdown_rx,
      Arc::new(NoopSchedulerTelemetry),
    ));

    tokio::time::timeout(Duration::from_secs(1), async {
      while backend.seen.lock().expect("seen tasks").is_empty() {
        tokio::task::yield_now().await;
      }
    })
    .await
    .expect("scheduled execution");
    shutdown.send(true).expect("stop worker");
    tokio::time::timeout(Duration::from_secs(1), worker)
      .await
      .expect("bounded drain")
      .expect("worker join");

    let tasks = backend.seen.lock().expect("seen tasks");
    assert_eq!(tasks.len(), 1);
    assert!(tasks[0].channel.is_none());
    assert!(tasks[0].feedback_target.is_none());
  }

  #[tokio::test]
  async fn test_worker_shutdown_cancels_active_run_before_any_new_materialization() {
    let temp = tempdir().expect("tempdir");
    let state = StateStore::initialize(&temp.path().join("state"), None)
      .await
      .expect("state");
    create_job(&state, "active-at-shutdown", 110).await;
    let mut backend = FakeBackend::new(ExecutionResult::Interrupted {
      transport_converged: false,
    });
    backend.execution_delay = Duration::from_secs(1);
    let backend = Arc::new(backend);
    let runtime = orchestrator(
      state.clone(),
      backend.clone(),
      Arc::new(TestClock(AtomicI64::new(111), 1)),
      1,
    );
    let (shutdown, shutdown_rx) = watch::channel(false);
    let worker = tokio::spawn(run_scheduled_worker(
      state.clone(),
      runtime,
      shutdown_rx,
      Arc::new(NoopSchedulerTelemetry),
    ));
    tokio::time::timeout(Duration::from_secs(1), async {
      while backend.active.load(Ordering::Acquire) == 0 {
        tokio::task::yield_now().await;
      }
    })
    .await
    .expect("active execution");

    shutdown.send(true).expect("stop worker");
    create_job(&state, "created-after-shutdown", 110).await;
    tokio::time::timeout(Duration::from_secs(1), worker)
      .await
      .expect("bounded drain")
      .expect("worker join");

    assert_eq!(backend.active.load(Ordering::Acquire), 0);
    assert_eq!(
      state
        .list_due_scheduled_jobs(111, 10)
        .await
        .expect("due jobs after shutdown"),
      ["created-after-shutdown"]
    );
  }

  #[tokio::test]
  async fn test_worker_shutdown_reports_non_clean_until_non_cooperative_execution_finishes() {
    let (_temp, state) = fixture(&[("non-cooperative-shutdown", 110)]).await;
    let mut backend = FakeBackend::new(ExecutionResult::Completed {
      summary: "late completion".to_owned(),
    });
    backend.execution_delay = Duration::from_millis(500);
    backend.honor_execution_cancellation = false;
    let backend = Arc::new(backend);
    let budget = GlobalTurnBudget::new(1);
    let guardians = Arc::new(BlockingGuardianRegistry::default());
    let clock = Arc::new(TestClock(AtomicI64::new(111), 1));
    let mut runtime = orchestrator(state.clone(), backend.clone(), clock.clone(), 1);
    runtime.budget = budget.clone();
    runtime.guardians = Arc::clone(&guardians);
    runtime.policy.heartbeat_interval = Duration::from_millis(1);
    runtime.policy.cancellation_grace = Duration::from_millis(5);
    let (shutdown, shutdown_rx) = watch::channel(false);
    let join = tokio::spawn(run_scheduled_worker(
      state,
      runtime,
      shutdown_rx,
      Arc::new(NoopSchedulerTelemetry),
    ));
    let mut worker = ScheduledWorkerHandle {
      shutdown,
      join: Some(join),
      guardians,
      worker_failed: false,
    };
    tokio::time::timeout(Duration::from_secs(1), async {
      while backend.active.load(Ordering::Acquire) == 0 {
        tokio::task::yield_now().await;
      }
    })
    .await
    .expect("active execution");

    assert_eq!(
      worker
        .shutdown_with_timeout(Duration::from_millis(100))
        .await,
      ScheduledWorkerShutdown::NonClean
    );
    assert_eq!(budget.available_permits(), 0);
    assert_eq!(worker.guardians.tasks.lock().expect("guardians").len(), 1);
    let heartbeat_stopped_at = clock.now();
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert_eq!(clock.now(), heartbeat_stopped_at);

    tokio::time::timeout(Duration::from_secs(1), async {
      while backend.active.load(Ordering::Acquire) != 0 {
        tokio::task::yield_now().await;
      }
    })
    .await
    .expect("non-cooperative execution completed");
    assert_eq!(
      worker.shutdown_with_timeout(Duration::from_secs(1)).await,
      ScheduledWorkerShutdown::Clean
    );
    assert_eq!(budget.available_permits(), 1);
  }

  #[tokio::test]
  async fn test_worker_failure_never_reports_clean_shutdown() {
    let (shutdown, _) = watch::channel(false);
    let join = tokio::spawn(std::future::pending());
    join.abort();
    let mut worker = ScheduledWorkerHandle {
      shutdown,
      join: Some(join),
      guardians: Arc::new(BlockingGuardianRegistry::default()),
      worker_failed: false,
    };

    assert_eq!(
      worker.shutdown_with_timeout(Duration::from_secs(1)).await,
      ScheduledWorkerShutdown::NonClean
    );
    assert_eq!(
      worker.shutdown_with_timeout(Duration::from_secs(1)).await,
      ScheduledWorkerShutdown::NonClean
    );
  }

  #[tokio::test]
  async fn test_shared_global_budget_blocks_scheduled_execution_behind_channel_turn() {
    let (_temp, state) = fixture(&[("shared-budget", 110)]).await;
    let backend = Arc::new(FakeBackend::new(ExecutionResult::Completed {
      summary: "done".to_owned(),
    }));
    let budget = GlobalTurnBudget::new(1);
    let channel_permit = budget.acquire().await.expect("channel permit");
    let runtime = Arc::new(ScheduledRunOrchestrator {
      state,
      backend: backend.clone(),
      clock: Arc::new(TestClock(AtomicI64::new(111), 1)),
      budget: budget.clone(),
      guardians: Arc::new(BlockingGuardianRegistry::default()),
      lease_owner: "runtime-test".to_owned(),
      run_claims_enabled: true,
      policy: ExecutionPolicy::default(),
      telemetry: Arc::new(NoopSchedulerTelemetry),
    });
    let scheduled = {
      let runtime = runtime.clone();
      tokio::spawn(async move { runtime.run_once().await })
    };
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(backend.seen.lock().expect("seen tasks").is_empty());
    assert_eq!(budget.available_permits(), 0);

    drop(channel_permit);
    assert_eq!(
      scheduled
        .await
        .expect("scheduled join")
        .expect("scheduled tick"),
      TickOutcome::Completed
    );
    assert_eq!(backend.max_active.load(Ordering::Acquire), 1);
    assert_eq!(budget.available_permits(), 1);
  }

  #[tokio::test]
  async fn test_success_uses_fresh_channel_free_task_and_commits_only_after_attestation() {
    let (_temp, state) = fixture(&[("success", 110)]).await;
    let backend = Arc::new(FakeBackend::new(ExecutionResult::Completed {
      summary: "completed result".to_owned(),
    }));
    let runtime = orchestrator(
      state.clone(),
      backend.clone(),
      Arc::new(TestClock(AtomicI64::new(111), 1)),
      1,
    );
    assert_eq!(
      runtime.run_once().await.expect("tick"),
      TickOutcome::Completed
    );
    assert!(
      state
        .claim_next_scheduled_run("proof", 112, 130)
        .await
        .expect("claim proof")
        .is_none()
    );
    let seen = backend.seen.lock().expect("seen tasks");
    let task = seen.first().expect("one task");
    assert!(matches!(task.source, InvocationSource::ScheduledRun { .. }));
    assert!(matches!(
      task.principal.as_ref(),
      InvocationPrincipalRef::Service {
        service: "codeoff-scheduler"
      }
    ));
    assert_eq!(task.session, SessionMode::Fresh);
    assert!(task.channel.is_none());
    assert!(task.previous_success.is_none());
    assert!(task.feedback_target.is_none());
    assert_eq!(task.tool_policy, ToolPolicy::None);
  }

  #[tokio::test]
  async fn test_shared_semaphore_bounds_parallel_scheduled_execution() {
    let (_temp, state) = fixture(&[("first", 110), ("second", 111)]).await;
    let mut backend = FakeBackend::new(ExecutionResult::Completed {
      summary: "done".to_owned(),
    });
    backend.execution_delay = Duration::from_millis(20);
    let backend = Arc::new(backend);
    let runtime = Arc::new(orchestrator(
      state,
      backend.clone(),
      Arc::new(TestClock(AtomicI64::new(112), 1)),
      1,
    ));
    let first = {
      let runtime = Arc::clone(&runtime);
      tokio::spawn(async move { runtime.run_once().await })
    };
    let second = {
      let runtime = Arc::clone(&runtime);
      tokio::spawn(async move { runtime.run_once().await })
    };
    assert_eq!(
      first.await.expect("first task").expect("first tick"),
      TickOutcome::Completed
    );
    assert_eq!(
      second.await.expect("second task").expect("second tick"),
      TickOutcome::Completed
    );
    assert_eq!(backend.max_active.load(Ordering::Acquire), 1);
  }

  #[tokio::test]
  async fn test_interrupted_converged_execution_retries_same_logical_run() {
    let (_temp, state) = fixture(&[("retry", 110)]).await;
    let backend = Arc::new(FakeBackend::new(ExecutionResult::Interrupted {
      transport_converged: true,
    }));
    let runtime = orchestrator(
      state.clone(),
      backend,
      Arc::new(TestClock(AtomicI64::new(111), 1)),
      1,
    );
    assert_eq!(runtime.run_once().await.expect("tick"), TickOutcome::Failed);
    assert!(
      state
        .claim_next_scheduled_run("too-early", 140, 150)
        .await
        .expect("early claim")
        .is_none()
    );
    let retry = state
      .claim_next_scheduled_run("retry-proof", 141, 170)
      .await
      .expect("retry claim")
      .expect("same run retried");
    assert_eq!(retry.binding.attempt(), 2);
    assert_eq!(retry.binding.job_id(), "retry");
  }

  #[tokio::test]
  async fn test_lost_lease_cancels_execution_and_only_appends_late_evidence() {
    let (_temp, state) = fixture(&[("lost", 110)]).await;
    let mut backend = FakeBackend::new(ExecutionResult::Interrupted {
      transport_converged: true,
    });
    backend.execution_delay = Duration::from_millis(100);
    let backend = Arc::new(backend);
    let mut runtime = orchestrator(
      state.clone(),
      backend,
      Arc::new(TestClock(AtomicI64::new(111), 61)),
      1,
    );
    runtime.policy.heartbeat_interval = Duration::from_millis(1);
    assert_eq!(
      runtime.run_once().await.expect("tick"),
      TickOutcome::LostLease
    );
    assert!(
      state
        .claim_next_scheduled_run("proof", 114, 130)
        .await
        .expect("terminal authority proof")
        .is_none(),
      "the stale executor must not return the logical run to pending"
    );
  }

  #[test]
  fn test_capability_snapshot_cannot_reenable_channel_or_schedule_tools() {
    assert!(reject_dynamic_tool_exposure(r#"{"tools":["schedule_create"]}"#).is_err());
    assert!(
      reject_dynamic_tool_exposure(r#"{"nested":{"tool":"channel_reply_to_event"}}"#).is_err()
    );
    assert!(reject_dynamic_tool_exposure(r#"{"tools":["github.get_issue"]}"#).is_ok());
  }

  #[test]
  fn test_prepare_validation_failure_kinds_are_fixed_and_sanitized() {
    for (failure, expected) in [
      (
        PrepareFailure::profile("malformed profile JSON"),
        "profile_validation_failed",
      ),
      (
        PrepareFailure::artifact("prepared authority mismatch"),
        "artifact_validation_failed",
      ),
      (
        PrepareFailure::tool_list("unexpected tool inventory"),
        "tool_list_validation_failed",
      ),
      (
        PrepareFailure::fatal("provider-specific text"),
        "preflight_rejected",
      ),
    ] {
      assert_eq!(failure.kind, expected);
    }
  }

  #[tokio::test]
  async fn test_malformed_persisted_snapshots_are_artifact_failures_before_agent_start() {
    for (case, column, snapshot_index) in [
      ("definition", "definition_json", 0),
      ("targets", "targets_json", 1),
      ("baseline", "execution_baseline_json", 2),
    ] {
      let (temp, state) = fixture(&[(case, 110)]).await;
      let snapshots = state
        .scheduled_run_snapshots_for_tests(case)
        .await
        .expect("read persisted snapshots");
      let canonical = match snapshot_index {
        0 => snapshots.0,
        1 => snapshots.1,
        2 => snapshots.2,
        _ => unreachable!("fixed snapshot matrix"),
      };
      let malformed = serde_json::to_string_pretty(
        &serde_json::from_str::<serde_json::Value>(&canonical).expect("canonical snapshot JSON"),
      )
      .expect("format noncanonical snapshot");
      assert_ne!(canonical, malformed);
      state
        .replace_scheduled_run_snapshot_for_tests(case, column, &malformed)
        .await
        .expect("tamper persisted snapshot");
      let backend = Arc::new(FakeBackend::new(ExecutionResult::Completed {
        summary: "must not execute".to_owned(),
      }));
      let runtime = orchestrator(
        state.clone(),
        backend.clone(),
        Arc::new(TestClock(AtomicI64::new(111), 1)),
        1,
      );
      assert_eq!(
        runtime.run_once().await.expect("execution tick"),
        TickOutcome::Failed
      );
      assert!(backend.seen.lock().expect("seen tasks").is_empty());
      let first = state
        .scheduler_observability_snapshot(112, 100, 1_000)
        .await
        .expect("first artifact metric");
      let second = state
        .scheduler_observability_snapshot(112, 100, 1_000)
        .await
        .expect("second artifact metric");
      assert_eq!(first.transition_totals, second.transition_totals);
      assert_eq!(
        first
          .transition_totals
          .iter()
          .find(
            |total| total.kind == codeoff_state::SchedulerTransitionKind::ArtifactValidationFailed
          )
          .expect("artifact metric")
          .value,
        1,
        "case={case}"
      );
      for kind in [
        codeoff_state::SchedulerTransitionKind::ProfileValidationFailed,
        codeoff_state::SchedulerTransitionKind::ToolListValidationFailed,
      ] {
        assert_eq!(
          first
            .transition_totals
            .iter()
            .find(|total| total.kind == kind)
            .expect("validation metric")
            .value,
          0,
          "case={case} kind={kind:?}"
        );
      }
      drop(runtime);
      drop(state);
      let restarted = StateStore::initialize(&temp.path().join("state"), None)
        .await
        .expect("restart state");
      let after_restart = restarted
        .scheduler_observability_snapshot(113, 100, 1_000)
        .await
        .expect("restart artifact metric");
      assert_eq!(first.transition_totals, after_restart.transition_totals);
    }
  }

  #[tokio::test]
  async fn test_empty_and_accepted_dispatch_outputs_never_commit_success() {
    for (job_id, result) in [
      (
        "empty",
        ExecutionResult::Completed {
          summary: " \n ".to_owned(),
        },
      ),
      ("accepted", ExecutionResult::AcceptedDispatch),
    ] {
      let (_temp, state) = fixture(&[(job_id, 110)]).await;
      let runtime = orchestrator(
        state,
        Arc::new(FakeBackend::new(result)),
        Arc::new(TestClock(AtomicI64::new(111), 1)),
        1,
      );
      assert_eq!(runtime.run_once().await.expect("tick"), TickOutcome::Failed);
    }
  }

  #[tokio::test]
  async fn test_latest_success_policy_injects_only_the_prior_accepted_summary() {
    let temp = tempdir().expect("tempdir");
    let state = StateStore::initialize(&temp.path().join("state"), None)
      .await
      .expect("state");
    let principal = PrincipalKey::new("user", "test", "tenant", "owner").expect("principal");
    state
      .create_scheduled_job(&CreateScheduledJob {
        job_id: "latest".to_owned(),
        schedule_id: "schedule-latest".to_owned(),
        definition: ScheduledJobDefinition::new(
          1,
          r#"{"instruction":"execute latest","previous_success":{"kind":"latest_success"},"schema_version":1}"#,
        )
        .expect("definition"),
        creator: principal.clone(),
        owner: principal,
        capability: CapabilityProfileSnapshot::new(1, "profile", "{}").expect("capability"),
        targets: vec![DeliveryTargetSnapshot::new(
          "target-latest",
          "none",
          "none",
          "tenant",
          "none",
          "{}",
          1,
          "resolver-v1",
          TARGET_IDENTITY,
        )
        .expect("target")],
        schedule: ScheduleSpec::fixed_interval(110, 10).expect("interval"),
        now: 100,
      })
      .await
      .expect("create job");
    assert!(matches!(
      state
        .materialize_due_schedule("latest", 0, 110)
        .await
        .expect("first materialization"),
      MaterializationOutcome::Created(_)
    ));
    let backend = Arc::new(FakeBackend::new(ExecutionResult::Completed {
      summary: "first accepted summary".to_owned(),
    }));
    let first = orchestrator(
      state.clone(),
      backend.clone(),
      Arc::new(TestClock(AtomicI64::new(111), 1)),
      1,
    );
    assert_eq!(
      first.run_once().await.expect("first tick"),
      TickOutcome::Completed
    );
    assert!(matches!(
      state
        .materialize_due_schedule("latest", 0, 120)
        .await
        .expect("second materialization"),
      MaterializationOutcome::Created(_)
    ));
    let second = orchestrator(
      state,
      backend.clone(),
      Arc::new(TestClock(AtomicI64::new(121), 1)),
      1,
    );
    assert_eq!(
      second.run_once().await.expect("second tick"),
      TickOutcome::Completed
    );
    let seen = backend.seen.lock().expect("seen tasks");
    assert!(seen[0].previous_success.is_none());
    assert_eq!(
      seen[1].previous_success,
      Some(PreviousSuccessContext {
        content: "first accepted summary".to_owned(),
        was_truncated: false,
      })
    );
  }

  #[tokio::test]
  async fn test_concurrent_runs_cannot_swap_prepared_authority_or_attestation() {
    let (_temp, state) = fixture(&[("swap-first", 110), ("swap-second", 111)]).await;
    let executions = Arc::new(AtomicUsize::new(0));
    let backend = Arc::new(SwappingBackend {
      barrier: Arc::new(Barrier::new(2)),
      authorities: Arc::new(Mutex::new(Vec::new())),
      executions: Arc::clone(&executions),
    });
    let runtime = Arc::new(orchestrator(
      state,
      backend,
      Arc::new(TestClock(AtomicI64::new(112), 1)),
      2,
    ));
    let first = {
      let runtime = Arc::clone(&runtime);
      tokio::spawn(async move { runtime.run_once().await })
    };
    let second = {
      let runtime = Arc::clone(&runtime);
      tokio::spawn(async move { runtime.run_once().await })
    };
    assert_eq!(
      first.await.expect("first task").expect("first tick"),
      TickOutcome::Failed
    );
    assert_eq!(
      second.await.expect("second task").expect("second tick"),
      TickOutcome::Failed
    );
    assert_eq!(executions.load(Ordering::Acquire), 0);
  }

  #[tokio::test]
  async fn test_aborting_run_once_caller_does_not_abort_owned_supervisor() {
    let (_temp, state) = fixture(&[("caller-abort", 110)]).await;
    let mut backend = FakeBackend::new(ExecutionResult::Completed {
      summary: "survived caller abort".to_owned(),
    });
    backend.execution_delay = Duration::from_millis(40);
    let backend = Arc::new(backend);
    let runtime = Arc::new(orchestrator(
      state.clone(),
      backend.clone(),
      Arc::new(TestClock(AtomicI64::new(111), 1)),
      1,
    ));
    let caller = {
      let runtime = Arc::clone(&runtime);
      tokio::spawn(async move { runtime.run_once().await })
    };
    tokio::time::timeout(Duration::from_secs(1), async {
      while backend.active.load(Ordering::Acquire) == 0 {
        tokio::task::yield_now().await;
      }
    })
    .await
    .expect("execution started");
    caller.abort();
    tokio::time::sleep(Duration::from_millis(70)).await;
    assert_eq!(backend.active.load(Ordering::Acquire), 0);
    assert!(
      state
        .claim_next_scheduled_run("proof", 112, 140)
        .await
        .expect("claim proof")
        .is_none(),
      "the detached caller receiver must not abandon claimed authority"
    );
  }

  #[tokio::test]
  async fn test_hung_prepare_fails_preflight_but_guardian_retains_permit_until_exit() {
    let (_temp, state) = fixture(&[("hung-prepare", 110)]).await;
    let mut backend = FakeBackend::new(ExecutionResult::Completed {
      summary: "must not execute".to_owned(),
    });
    backend.prepare_delay = Duration::from_millis(150);
    let mut runtime = orchestrator(
      state,
      Arc::new(backend),
      Arc::new(TestClock(AtomicI64::new(111), 1)),
      1,
    );
    runtime.policy.total_timeout = Duration::from_millis(50);
    runtime.policy.prepare_grace = Duration::from_millis(5);
    assert_eq!(runtime.run_once().await.expect("tick"), TickOutcome::Failed);
    assert_eq!(runtime.budget.available_permits(), 0);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(runtime.budget.available_permits(), 1);
  }

  #[tokio::test]
  async fn test_hung_execute_becomes_outcome_unknown_and_guardian_retains_permit() {
    let (_temp, state) = fixture(&[("hung-execute", 110)]).await;
    let mut backend = FakeBackend::new(ExecutionResult::Completed {
      summary: "late completion must not win".to_owned(),
    });
    let completion_barrier = Arc::new(Barrier::new(2));
    backend.completion_barrier = Some(Arc::clone(&completion_barrier));
    backend.honor_execution_cancellation = false;
    let mut configured = orchestrator(
      state.clone(),
      Arc::new(backend.clone()),
      Arc::new(TestClock(AtomicI64::new(111), 1)),
      1,
    );
    configured.policy.total_timeout = Duration::from_millis(50);
    configured.policy.cancellation_grace = Duration::from_millis(5);
    let runtime = Arc::new(configured);
    let caller = {
      let runtime = Arc::clone(&runtime);
      tokio::spawn(async move { runtime.run_once().await })
    };
    tokio::time::timeout(Duration::from_secs(1), async {
      while backend.active.load(Ordering::Acquire) == 0 {
        tokio::task::yield_now().await;
      }
    })
    .await
    .expect("execution start");
    assert_eq!(
      caller.await.expect("caller").expect("tick"),
      TickOutcome::Failed
    );
    assert_eq!(runtime.budget.available_permits(), 0);
    assert!(
      state
        .claim_next_scheduled_run("proof", 112, 140)
        .await
        .expect("claim proof")
        .is_none(),
      "unknown execution must not be retried"
    );
    completion_barrier.wait();
    tokio::time::timeout(Duration::from_secs(1), async {
      while runtime.budget.available_permits() == 0 {
        tokio::task::yield_now().await;
      }
    })
    .await
    .expect("guardian permit release");
    assert_eq!(runtime.budget.available_permits(), 1);
  }

  #[tokio::test]
  async fn test_heartbeat_stops_and_joins_after_terminal_commit() {
    let (_temp, state) = fixture(&[("heartbeat-stop", 110)]).await;
    let mut backend = FakeBackend::new(ExecutionResult::Completed {
      summary: "done".to_owned(),
    });
    backend.execution_delay = Duration::from_millis(10);
    let clock = Arc::new(TestClock(AtomicI64::new(111), 1));
    let mut runtime = orchestrator(state, Arc::new(backend), clock.clone(), 1);
    runtime.policy.heartbeat_interval = Duration::from_millis(1);
    assert_eq!(
      runtime.run_once().await.expect("tick"),
      TickOutcome::Completed
    );
    let stopped_at = clock.now();
    tokio::time::sleep(Duration::from_millis(5)).await;
    assert_eq!(clock.now(), stopped_at);
  }

  #[tokio::test]
  async fn test_terminal_commit_waits_for_cross_pool_lock_released_within_reserve() {
    let (_temp, state) = fixture(&[("commit-unlocked", 110)]).await;
    let mut backend = FakeBackend::new(ExecutionResult::Completed {
      summary: "committed after contention".to_owned(),
    });
    backend.execution_delay = Duration::from_millis(30);
    let backend = Arc::new(backend);
    let runtime = Arc::new(orchestrator(
      state.clone(),
      backend.clone(),
      Arc::new(TestClock(AtomicI64::new(111), 1)),
      1,
    ));
    let caller = {
      let runtime = Arc::clone(&runtime);
      tokio::spawn(async move { runtime.run_once().await })
    };
    while backend.active.load(Ordering::Acquire) == 0 {
      tokio::task::yield_now().await;
    }
    let lock = state
      .acquire_exclusive_storage_lock_for_tests()
      .await
      .expect("exclusive lock");
    while backend.active.load(Ordering::Acquire) != 0 {
      tokio::task::yield_now().await;
    }
    tokio::time::sleep(Duration::from_millis(10)).await;
    lock.release().await.expect("release lock");
    assert_eq!(
      caller.await.expect("caller task").expect("tick"),
      TickOutcome::Completed
    );
    let (run_id, job_id) = {
      let seen = backend.seen.lock().expect("seen tasks");
      let InvocationSource::ScheduledRun { run_id, job_id, .. } = &seen[0].source else {
        panic!("scheduled source");
      };
      (run_id.clone(), job_id.clone())
    };
    assert_eq!(
      state
        .scheduled_execution_authority_counts_for_tests(&run_id, &job_id)
        .await
        .expect("authority counts"),
      (1, 1, 1, 0)
    );
  }

  #[tokio::test]
  async fn test_terminal_commit_contention_past_reserve_stops_heartbeat_and_reclaims_unknown() {
    let (_temp, state) = fixture(&[("commit-blocked", 110)]).await;
    let mut backend = FakeBackend::new(ExecutionResult::Completed {
      summary: "must roll back".to_owned(),
    });
    let completion_barrier = Arc::new(Barrier::new(2));
    backend.completion_barrier = Some(Arc::clone(&completion_barrier));
    let backend = Arc::new(backend);
    let clock = Arc::new(TestClock(AtomicI64::new(111), 1));
    let mut configured = orchestrator(state.clone(), backend.clone(), clock.clone(), 1);
    configured.policy.total_timeout = Duration::from_millis(50);
    configured.policy.prepare_grace = Duration::from_millis(5);
    configured.policy.cancellation_grace = Duration::from_millis(5);
    configured.policy.finalization_grace = Duration::from_millis(20);
    configured.policy.heartbeat_interval = Duration::from_millis(5);
    let runtime = Arc::new(configured);
    let caller = {
      let runtime = Arc::clone(&runtime);
      tokio::spawn(async move { runtime.run_once().await })
    };
    while backend.active.load(Ordering::Acquire) == 0 {
      tokio::task::yield_now().await;
    }
    let lock = state
      .acquire_exclusive_storage_lock_for_tests()
      .await
      .expect("exclusive lock");
    completion_barrier.wait();
    let outcome = tokio::time::timeout(Duration::from_millis(150), caller)
      .await
      .expect("supervisor hard stop")
      .expect("caller task")
      .expect("tick");
    assert_eq!(outcome, TickOutcome::LostLease);
    let heartbeat_stopped_at = clock.now();
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert_eq!(clock.now(), heartbeat_stopped_at);
    lock.release().await.expect("release lock");
    assert!(matches!(
      state
        .reclaim_next_expired_scheduled_run(200, 3, 210)
        .await
        .expect("reclaim"),
      ExpiredRunReclaimOutcome::OutcomeUnknown { .. }
    ));
    let (run_id, job_id) = {
      let seen = backend.seen.lock().expect("seen tasks");
      let InvocationSource::ScheduledRun { run_id, job_id, .. } = &seen[0].source else {
        panic!("scheduled source");
      };
      (run_id.clone(), job_id.clone())
    };
    assert_eq!(
      state
        .scheduled_execution_authority_counts_for_tests(&run_id, &job_id)
        .await
        .expect("authority counts"),
      (0, 0, 0, 0)
    );
  }

  #[tokio::test]
  async fn test_shutdown_bounds_terminal_commit_contention_and_stops_heartbeat() {
    let (_temp, state) = fixture(&[("commit-shutdown", 110)]).await;
    let mut backend = FakeBackend::new(ExecutionResult::Completed {
      summary: "must not block shutdown".to_owned(),
    });
    backend.execution_delay = Duration::from_millis(200);
    let backend = Arc::new(backend);
    let clock = Arc::new(TestClock(AtomicI64::new(111), 1));
    let mut runtime = orchestrator(state.clone(), backend.clone(), clock.clone(), 1);
    runtime.policy.total_timeout = Duration::from_secs(2);
    runtime.policy.finalization_grace = Duration::from_millis(20);
    runtime.policy.heartbeat_interval = Duration::from_millis(5);
    let (shutdown, shutdown_rx) = watch::channel(false);
    let caller = tokio::spawn(runtime.run_supervised(shutdown_rx));
    while backend.active.load(Ordering::Acquire) == 0 {
      tokio::task::yield_now().await;
    }
    let lock = state
      .acquire_exclusive_storage_lock_for_tests()
      .await
      .expect("exclusive lock");
    while backend.active.load(Ordering::Acquire) != 0 {
      tokio::task::yield_now().await;
    }

    shutdown.send(true).expect("request shutdown");
    let outcome = tokio::time::timeout(Duration::from_millis(250), caller)
      .await
      .expect("shutdown terminal deadline")
      .expect("caller task")
      .expect("tick");
    assert_eq!(outcome, TickOutcome::LostLease);
    let heartbeat_stopped_at = clock.now();
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert_eq!(clock.now(), heartbeat_stopped_at);
    lock.release().await.expect("release lock");
  }
}
