use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use codeoff_agent_contract::{
  AgentTask, InvocationPrincipal, InvocationSource, PreviousSuccessContext, SessionMode, ToolPolicy,
};
use codeoff_state::{
  AttestedExecutionProfileSnapshot, ClaimedScheduledRun, PreflightFailureDisposition,
  RunLeaseBinding, ScheduledExecutionDisposition, ScheduledExecutionTerminal,
  ScheduledRunLateEvidenceKind, ScheduledRunResult, StateError, StateStore, TransportConvergence,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::sync::{Semaphore, oneshot};
use tokio::task::JoinHandle;

use crate::channel_tools::CHANNEL_DYNAMIC_TOOL_NAMES;
use crate::schedule_tools::SCHEDULE_DYNAMIC_TOOL_NAMES;

const MAX_PREVIOUS_SUCCESS_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExecutorReadiness {
  Ready,
  Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TickOutcome {
  Unavailable,
  Idle,
  Completed,
  Failed,
  LostLease,
}

#[derive(Debug, Clone)]
struct ExecutionPolicy {
  lease_seconds: i64,
  heartbeat_interval: Duration,
  cancellation_grace: Duration,
  retry_delay_seconds: i64,
  run_deadline_seconds: i64,
  max_attempts: i64,
}

impl Default for ExecutionPolicy {
  fn default() -> Self {
    Self {
      lease_seconds: 60,
      heartbeat_interval: Duration::from_secs(15),
      cancellation_grace: Duration::from_secs(5),
      retry_delay_seconds: 30,
      run_deadline_seconds: 3_600,
      max_attempts: 3,
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

struct PrepareInput {
  task: AgentTask,
  definition_json: String,
  capability_json: String,
  capability_digest: String,
  targets_json: String,
  cancellation: Arc<AtomicBool>,
}

struct BackendPrepared {
  attested_profile_json: String,
  attested_profile_digest: String,
  execution: Box<dyn PreparedExecution>,
}

trait PreparedExecution: Send {
  fn execute(self: Box<Self>, cancellation: Arc<AtomicBool>) -> ExecutionResult;
}

trait ScheduledExecutionBackend: Send + Sync {
  fn readiness(&self) -> ExecutorReadiness;
  fn prepare(&self, input: PrepareInput) -> Result<BackendPrepared, PrepareFailure>;
}

struct UnavailableScheduledExecutionBackend;

impl ScheduledExecutionBackend for UnavailableScheduledExecutionBackend {
  fn readiness(&self) -> ExecutorReadiness {
    ExecutorReadiness::Unavailable
  }

  fn prepare(&self, _input: PrepareInput) -> Result<BackendPrepared, PrepareFailure> {
    Err(PrepareFailure::fatal("scheduled_executor_unavailable"))
  }
}

struct PreparedRun {
  run_id: String,
  job_id: String,
  attempt: i64,
  fence: i64,
  lease_owner: String,
  attested_profile: AttestedExecutionProfileSnapshot,
  execution: Box<dyn PreparedExecution>,
}

impl PreparedRun {
  fn from_backend(
    binding: &RunLeaseBinding,
    prepared: BackendPrepared,
  ) -> Result<Self, PrepareFailure> {
    let profile: Value = serde_json::from_str(&prepared.attested_profile_json)
      .map_err(|error| PrepareFailure::fatal(error.to_string()))?;
    let canonical_profile =
      serde_json::to_string(&profile).map_err(|error| PrepareFailure::fatal(error.to_string()))?;
    if canonical_profile != prepared.attested_profile_json
      || sha256_hex(canonical_profile.as_bytes()) != prepared.attested_profile_digest
      || profile.get("schema_version").and_then(Value::as_u64) != Some(1)
    {
      return Err(PrepareFailure::fatal(
        "scheduled_attested_profile_authority_mismatch",
      ));
    }
    let attested_profile = AttestedExecutionProfileSnapshot::new(
      1,
      canonical_profile,
      "sha256-v1",
      prepared.attested_profile_digest,
    )
    .map_err(|error| PrepareFailure::fatal(error.to_string()))?;
    Ok(Self {
      run_id: binding.run_id().to_owned(),
      job_id: binding.job_id().to_owned(),
      attempt: binding.attempt(),
      fence: binding.fence(),
      lease_owner: binding.lease_owner().to_owned(),
      attested_profile,
      execution: prepared.execution,
    })
  }

  fn matches(&self, binding: &RunLeaseBinding) -> bool {
    self.run_id == binding.run_id()
      && self.job_id == binding.job_id()
      && self.attempt == binding.attempt()
      && self.fence == binding.fence()
      && self.lease_owner == binding.lease_owner()
  }

  fn execute(self, cancellation: Arc<AtomicBool>) -> ExecutionResult {
    self.execution.execute(cancellation)
  }
}

#[derive(Debug)]
struct PrepareFailure {
  retryable: bool,
  kind: String,
  message: String,
}

impl PrepareFailure {
  fn fatal(message: impl Into<String>) -> Self {
    Self {
      retryable: false,
      kind: "preflight_rejected".to_owned(),
      message: message.into(),
    }
  }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ExecutionResult {
  Completed { summary: String },
  Interrupted { transport_converged: bool },
  TimedOut { transport_converged: bool },
  Failed { kind: String, message: String },
  TransportLost { message: String },
  AcceptedDispatch,
  Empty,
}

struct ScheduledRunOrchestrator {
  state: StateStore,
  backend: Arc<dyn ScheduledExecutionBackend>,
  clock: Arc<dyn SchedulerClock>,
  semaphore: Arc<Semaphore>,
  lease_owner: String,
  policy: ExecutionPolicy,
}

impl ScheduledRunOrchestrator {
  fn unavailable(state: StateStore, parallelism: usize, lease_owner: impl Into<String>) -> Self {
    Self {
      state,
      backend: Arc::new(UnavailableScheduledExecutionBackend),
      clock: Arc::new(SystemClock),
      semaphore: Arc::new(Semaphore::new(parallelism.max(1))),
      lease_owner: lease_owner.into(),
      policy: ExecutionPolicy::default(),
    }
  }

  async fn run_once(&self) -> Result<TickOutcome, StateError> {
    let mut permit = Some(
      Arc::clone(&self.semaphore)
        .acquire_owned()
        .await
        .map_err(|_| StateError::InvalidSchedulerState {
          reason: "scheduled execution semaphore is closed".to_owned(),
        })?,
    );
    if self.backend.readiness() != ExecutorReadiness::Ready {
      return Ok(TickOutcome::Unavailable);
    }
    let now = self.clock.now();
    let lease_expires_at = checked_add(now, self.policy.lease_seconds, "lease expiry")?;
    let Some(claim) = self
      .state
      .claim_next_scheduled_run(&self.lease_owner, now, lease_expires_at)
      .await?
    else {
      return Ok(TickOutcome::Idle);
    };

    let cancellation = Arc::new(AtomicBool::new(false));
    let (heartbeat, mut lost_lease) = self.start_heartbeat(&claim, Arc::clone(&cancellation));
    let task = match task_from_claim(&claim) {
      Ok(task) => task,
      Err(failure) => {
        let outcome = self.record_preflight_failure(&claim, failure).await;
        heartbeat.abort();
        return outcome;
      }
    };
    let input = PrepareInput {
      task,
      definition_json: claim.definition_json.clone(),
      capability_json: claim.capability_json.clone(),
      capability_digest: claim.capability_digest.clone(),
      targets_json: claim.targets_json.clone(),
      cancellation: Arc::clone(&cancellation),
    };
    let backend = Arc::clone(&self.backend);
    let mut prepare = tokio::task::spawn_blocking(move || backend.prepare(input));
    let prepared = tokio::select! {
      biased;
      _ = &mut lost_lease => {
        cancellation.store(true, Ordering::Release);
        if tokio::time::timeout(self.policy.cancellation_grace, &mut prepare).await.is_err() {
          let retained_permit = permit.take().expect("scheduled execution permit is held");
          tokio::spawn(async move {
            let _ = prepare.await;
            drop(retained_permit);
          });
        }
        heartbeat.abort();
        self.append_late_preflight(&claim).await?;
        return Ok(TickOutcome::LostLease);
      },
      result = &mut prepare => result.map_err(join_error)?,
    };
    let prepared =
      match prepared.and_then(|prepared| PreparedRun::from_backend(&claim.binding, prepared)) {
        Ok(prepared) if prepared.matches(&claim.binding) => prepared,
        Ok(_) => {
          heartbeat.abort();
          return self
            .record_preflight_failure(&claim, PrepareFailure::fatal("prepared_authority_mismatch"))
            .await;
        }
        Err(failure) => {
          let outcome = self.record_preflight_failure(&claim, failure).await;
          heartbeat.abort();
          return outcome;
        }
      };

    if let Err(error) = self
      .state
      .mark_scheduled_run_executing(&claim.binding, &prepared.attested_profile, self.clock.now())
      .await
    {
      cancellation.store(true, Ordering::Release);
      heartbeat.abort();
      if matches!(error, StateError::ScheduledRunLostLease) {
        self.append_late_preflight(&claim).await?;
        return Ok(TickOutcome::LostLease);
      }
      return Err(error);
    }

    let execution_cancellation = Arc::clone(&cancellation);
    let mut execution =
      tokio::task::spawn_blocking(move || prepared.execute(execution_cancellation));
    let result = tokio::select! {
      biased;
      _ = &mut lost_lease => {
        cancellation.store(true, Ordering::Release);
        if tokio::time::timeout(self.policy.cancellation_grace, &mut execution).await.is_err() {
          let retained_permit = permit.take().expect("scheduled execution permit is held");
          tokio::spawn(async move {
            let _ = execution.await;
            drop(retained_permit);
          });
        }
        heartbeat.abort();
        self.append_late_execution(&claim).await?;
        return Ok(TickOutcome::LostLease);
      },
      result = &mut execution => result.map_err(join_error)?,
    };
    let outcome = self.commit_execution_result(&claim, result).await;
    heartbeat.abort();
    outcome
  }

  fn start_heartbeat(
    &self,
    claim: &ClaimedScheduledRun,
    cancellation: Arc<AtomicBool>,
  ) -> (JoinHandle<()>, oneshot::Receiver<()>) {
    let state = self.state.clone();
    let binding = claim.binding.clone();
    let clock = Arc::clone(&self.clock);
    let interval = self.policy.heartbeat_interval;
    let lease_seconds = self.policy.lease_seconds;
    let (lost_tx, lost_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
      loop {
        clock.sleep(interval).await;
        let now = clock.now();
        let Some(expires_at) = now.checked_add(lease_seconds) else {
          cancellation.store(true, Ordering::Release);
          let _ = lost_tx.send(());
          return;
        };
        if state
          .heartbeat_scheduled_run(&binding, now, expires_at)
          .await
          .is_err()
        {
          cancellation.store(true, Ordering::Release);
          let _ = lost_tx.send(());
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
    let disposition = if failure.retryable {
      PreflightFailureDisposition::RetryAt(checked_add(
        now,
        self.policy.retry_delay_seconds,
        "preflight retry",
      )?)
    } else {
      PreflightFailureDisposition::Fail
    };
    match self
      .state
      .record_scheduled_run_preflight_failure(
        &claim.binding,
        disposition,
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
    let (disposition, kind, message) =
      execution_failure_disposition(claim, result, &self.policy, now)?;
    self
      .state
      .record_scheduled_run_execution_outcome(&claim.binding, disposition, kind, message, now)
      .await
      .map(|outcome| match outcome {
        codeoff_state::ScheduledRunExecutionOutcome::LateEvidence(_) => TickOutcome::LostLease,
        _ => TickOutcome::Failed,
      })
  }
}

fn task_from_claim(claim: &ClaimedScheduledRun) -> Result<AgentTask, PrepareFailure> {
  reject_dynamic_tool_exposure(&claim.capability_json)?;
  let definition: Value = serde_json::from_str(&claim.definition_json)
    .map_err(|error| PrepareFailure::fatal(error.to_string()))?;
  let instruction = definition
    .get("instruction")
    .and_then(Value::as_str)
    .filter(|value| !value.trim().is_empty())
    .ok_or_else(|| PrepareFailure::fatal("scheduled_definition_missing_instruction"))?
    .to_owned();
  let include_previous_success = definition
    .pointer("/previous_success/kind")
    .and_then(Value::as_str)
    == Some("latest_success");
  let previous_success = previous_success_from_claim(claim, include_previous_success)?;
  let task = AgentTask {
    task_id: format!(
      "scheduled:{}:{}:{}",
      claim.binding.run_id(),
      claim.binding.attempt(),
      claim.binding.fence()
    ),
    instruction,
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
  task.validate().map_err(PrepareFailure::fatal)?;
  Ok(task)
}

fn previous_success_from_claim(
  claim: &ClaimedScheduledRun,
  enabled: bool,
) -> Result<Option<PreviousSuccessContext>, PrepareFailure> {
  if !enabled {
    return Ok(None);
  }
  let baseline: Value = serde_json::from_str(&claim.execution_baseline_json)
    .map_err(|error| PrepareFailure::fatal(error.to_string()))?;
  let Some(content) = baseline
    .get("previous_success_context")
    .and_then(Value::as_str)
  else {
    return Ok(None);
  };
  let boundary = content
    .char_indices()
    .map(|(index, _)| index)
    .take_while(|index| *index <= MAX_PREVIOUS_SUCCESS_BYTES)
    .last()
    .unwrap_or(0);
  let was_truncated = content.len() > MAX_PREVIOUS_SUCCESS_BYTES;
  Ok(Some(PreviousSuccessContext {
    content: if was_truncated {
      content[..boundary].to_owned()
    } else {
      content.to_owned()
    },
    was_truncated,
  }))
}

fn reject_dynamic_tool_exposure(capability_json: &str) -> Result<(), PrepareFailure> {
  let capability: Value = serde_json::from_str(capability_json)
    .map_err(|error| PrepareFailure::fatal(error.to_string()))?;
  let prohibited = CHANNEL_DYNAMIC_TOOL_NAMES
    .iter()
    .chain(SCHEDULE_DYNAMIC_TOOL_NAMES)
    .copied()
    .collect::<Vec<_>>();
  if contains_prohibited_tool(&capability, &prohibited) {
    return Err(PrepareFailure::fatal(
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
  policy: &ExecutionPolicy,
  now: i64,
) -> Result<(ScheduledExecutionDisposition, &'static str, &'static str), StateError> {
  let retry_at = checked_add(now, policy.retry_delay_seconds, "execution retry")?;
  let deadline_at = checked_add(
    claim.scheduled_for,
    policy.run_deadline_seconds,
    "execution deadline",
  )?;
  let retry = |exhausted| ScheduledExecutionDisposition::RetryAt {
    retry_at,
    deadline_at,
    max_attempts: policy.max_attempts,
    transport: TransportConvergence::Converged,
    exhausted,
  };
  Ok(match result {
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
  })
}

fn checked_add(value: i64, delta: i64, field: &str) -> Result<i64, StateError> {
  value
    .checked_add(delta)
    .ok_or_else(|| StateError::InvalidSchedulerState {
      reason: format!("scheduled {field} overflow"),
    })
}

fn join_error(error: tokio::task::JoinError) -> StateError {
  StateError::InvalidSchedulerState {
    reason: format!("scheduled blocking task failed: {error}"),
  }
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
  use std::sync::Mutex;
  use std::sync::atomic::{AtomicI64, AtomicUsize};

  use codeoff_agent_contract::{InvocationPrincipalRef, InvocationSource};
  use codeoff_state::{
    CapabilityProfileSnapshot, CreateScheduledJob, DeliveryTargetSnapshot, MaterializationOutcome,
    PrincipalKey, ScheduleSpec, ScheduledJobDefinition,
  };
  use tempfile::{TempDir, tempdir};

  use super::*;

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
    execution_delay: Duration,
    active: Arc<AtomicUsize>,
    max_active: Arc<AtomicUsize>,
  }

  impl FakeBackend {
    fn new(result: ExecutionResult) -> Self {
      Self {
        seen: Arc::new(Mutex::new(Vec::new())),
        result,
        execution_delay: Duration::ZERO,
        active: Arc::new(AtomicUsize::new(0)),
        max_active: Arc::new(AtomicUsize::new(0)),
      }
    }
  }

  impl ScheduledExecutionBackend for FakeBackend {
    fn readiness(&self) -> ExecutorReadiness {
      ExecutorReadiness::Ready
    }

    fn prepare(&self, input: PrepareInput) -> Result<BackendPrepared, PrepareFailure> {
      assert!(!input.cancellation.load(Ordering::Acquire));
      assert!(!input.definition_json.is_empty());
      assert_eq!(input.capability_json, "{}");
      assert_eq!(input.capability_digest, "profile");
      assert!(input.targets_json.contains(TARGET_IDENTITY));
      self.seen.lock().expect("seen tasks").push(input.task);
      let profile = r#"{"schema_version":1,"side_effect_free":true}"#;
      Ok(BackendPrepared {
        attested_profile_json: profile.to_owned(),
        attested_profile_digest: sha256_hex(profile.as_bytes()),
        execution: Box::new(FakePrepared {
          result: self.result.clone(),
          execution_delay: self.execution_delay,
          active: Arc::clone(&self.active),
          max_active: Arc::clone(&self.max_active),
        }),
      })
    }
  }

  struct FakePrepared {
    result: ExecutionResult,
    execution_delay: Duration,
    active: Arc<AtomicUsize>,
    max_active: Arc<AtomicUsize>,
  }

  impl PreparedExecution for FakePrepared {
    fn execute(self: Box<Self>, cancellation: Arc<AtomicBool>) -> ExecutionResult {
      let active = self.active.fetch_add(1, Ordering::AcqRel) + 1;
      self.max_active.fetch_max(active, Ordering::AcqRel);
      let started = std::time::Instant::now();
      while started.elapsed() < self.execution_delay && !cancellation.load(Ordering::Acquire) {
        std::thread::sleep(Duration::from_millis(1));
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
      let principal = PrincipalKey::new("user", "test", "tenant", "owner").expect("principal");
      store
        .create_scheduled_job(&CreateScheduledJob {
          job_id: (*job_id).to_owned(),
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
          schedule: ScheduleSpec::once(*scheduled_for),
          now: 100,
        })
        .await
        .expect("create job");
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
      semaphore: Arc::new(Semaphore::new(parallelism)),
      lease_owner: "runtime-test".to_owned(),
      policy: ExecutionPolicy {
        lease_seconds: 20,
        heartbeat_interval: Duration::from_mins(1),
        cancellation_grace: Duration::from_millis(20),
        retry_delay_seconds: 5,
        run_deadline_seconds: 100,
        max_attempts: 3,
      },
    }
  }

  #[tokio::test]
  async fn test_unavailable_readiness_produces_zero_claims() {
    let (_temp, state) = fixture(&[("unavailable", 110)]).await;
    let runtime = ScheduledRunOrchestrator::unavailable(state.clone(), 1, "runtime-test");
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
        .claim_next_scheduled_run("too-early", 115, 130)
        .await
        .expect("early claim")
        .is_none()
    );
    let retry = state
      .claim_next_scheduled_run("retry-proof", 116, 140)
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
      Arc::new(TestClock(AtomicI64::new(111), 2)),
      1,
    );
    runtime.policy.lease_seconds = 1;
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
}
