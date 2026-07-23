use std::sync::Arc;
use std::sync::RwLock;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use codeoff_agent_codex::{
  BuiltScheduledCodexExecutor, PreparedScheduledCodexExecution, RequestedCapabilityProfile,
  ScheduledCodexExecution, ScheduledCodexRequest, ScheduledDeploymentAuthority,
  ScheduledExecutionIdentity, ScheduledExecutionResult, ScheduledFailure, ScheduledFailureKind,
  ScheduledIsolationPermit, load_current_scheduled_deployment_authority,
};
use codeoff_config::ScheduledCodexConfig;
use codeoff_runtime::scheduled_execution::{
  BackendAuthorization, BackendPrepared, ExecutionResult, ExecutorReadiness, PrepareFailure,
  PrepareInput, PreparedExecution, RefreshedExecutorAdmission, ScheduledExecutionBackend,
  ScheduledWorkerConfig,
};
use codeoff_runtime::scheduled_runner_broker::RemoteIsolationPermitIssuer;
use codeoff_state::{
  ConsumeScheduledExecutionPermit, ScheduledExecutorAdmission, ScheduledExecutorEpochAuthority,
  StateError, StateStore,
};
use serde_json::json;
use sha2::{Digest, Sha256};

const CLAIM_MIN_REMAINING_SECONDS: i64 = 30;
const ADMISSION_OPERATION_SECONDS: i64 = 5;

type AuthoritySource =
  dyn Fn() -> Result<ScheduledDeploymentAuthority, ScheduledFailure> + Send + Sync;
type AuthorityClock = dyn Fn() -> Option<i64> + Send + Sync;

struct ScheduledAuthorityManager {
  state: StateStore,
  cached: RwLock<ScheduledDeploymentAuthority>,
  source: Arc<AuthoritySource>,
  clock: Arc<AuthorityClock>,
}

impl ScheduledAuthorityManager {
  fn production(
    state: StateStore,
    initial: ScheduledDeploymentAuthority,
    deployment: ScheduledCodexConfig,
    profile: RequestedCapabilityProfile,
  ) -> Self {
    let source =
      Arc::new(move || load_current_scheduled_deployment_authority(&deployment, &profile));
    Self {
      state,
      cached: RwLock::new(initial),
      source,
      clock: Arc::new(|| now_unix_seconds().ok()),
    }
  }

  #[cfg(test)]
  fn with_source_and_clock(
    state: StateStore,
    initial: ScheduledDeploymentAuthority,
    source: Arc<AuthoritySource>,
    clock: Arc<AuthorityClock>,
  ) -> Self {
    Self {
      state,
      cached: RwLock::new(initial),
      source,
      clock,
    }
  }

  fn readiness(&self) -> ExecutorReadiness {
    if self.current().is_some() {
      ExecutorReadiness::Ready
    } else {
      ExecutorReadiness::Unavailable
    }
  }

  fn current(&self) -> Option<ScheduledDeploymentAuthority> {
    let now = (self.clock)()?;
    self
      .cached
      .read()
      .ok()
      .filter(|authority| authority_is_claimable(authority, now))
      .map(|authority| authority.clone())
  }

  fn admission(&self) -> Option<ScheduledExecutorAdmission> {
    let now = (self.clock)()?;
    let authority = self
      .cached
      .read()
      .ok()
      .filter(|authority| authority_is_claimable(authority, now))?
      .clone();
    let signed_not_after = i64::try_from(authority.expires_at_unix_seconds).ok()?;
    let operation_deadline = now
      .checked_add(ADMISSION_OPERATION_SECONDS)?
      .min(signed_not_after.saturating_sub(1));
    if operation_deadline <= now {
      return None;
    }
    Some(ScheduledExecutorAdmission {
      schema_version: authority.schema_version,
      deployment_epoch: authority.deployment_epoch,
      attestation_id: authority.attestation_id,
      profile_digest: authority.profile_digest,
      signed_not_after,
      operation_deadline,
    })
  }

  async fn refresh(&self) -> ExecutorReadiness {
    let Some(now) = (self.clock)() else {
      return ExecutorReadiness::Unavailable;
    };
    let Ok(candidate) = (self.source)() else {
      return self.readiness();
    };
    if !authority_is_claimable(&candidate, now) {
      return self.readiness();
    }
    let Some(cached) = self.cached.read().ok().map(|authority| authority.clone()) else {
      return ExecutorReadiness::Unavailable;
    };
    if candidate == cached {
      return ExecutorReadiness::Ready;
    }
    if candidate.deployment_epoch <= cached.deployment_epoch {
      return self.readiness();
    }
    if self
      .state
      .register_scheduled_executor_epoch(&epoch_authority(&candidate), now)
      .await
      .is_err()
    {
      return self.readiness();
    }
    let Ok(mut current) = self.cached.write() else {
      return ExecutorReadiness::Unavailable;
    };
    if candidate.deployment_epoch > current.deployment_epoch {
      *current = candidate;
    }
    drop(current);
    self.readiness()
  }
}

fn authority_is_claimable(authority: &ScheduledDeploymentAuthority, now: i64) -> bool {
  let Ok(expires_at) = i64::try_from(authority.expires_at_unix_seconds) else {
    return false;
  };
  now > 0 && expires_at.saturating_sub(now) > CLAIM_MIN_REMAINING_SECONDS
}

fn epoch_authority(authority: &ScheduledDeploymentAuthority) -> ScheduledExecutorEpochAuthority {
  ScheduledExecutorEpochAuthority {
    schema_version: authority.schema_version,
    deployment_epoch: authority.deployment_epoch,
    attestation_id: authority.attestation_id.clone(),
    attestation_digest: authority.attestation_digest.clone(),
    profile_digest: authority.profile_digest.clone(),
    issued_at: i64::try_from(authority.issued_at_unix_seconds).unwrap_or(i64::MAX),
    expires_at: i64::try_from(authority.expires_at_unix_seconds).unwrap_or(i64::MAX),
  }
}

pub(crate) struct CodexScheduledExecutionBackend {
  state: StateStore,
  executor: Arc<dyn ScheduledCodexExecution>,
  profile: RequestedCapabilityProfile,
  authority: ScheduledAuthorityManager,
  timeout: Duration,
  interrupt_grace: Duration,
  terminate_grace: Duration,
  kill_grace: Duration,
}

pub(crate) struct RemoteCodexPermitIssuer {
  state: StateStore,
  authority: ScheduledDeploymentAuthority,
  credential_revision: String,
}

impl RemoteCodexPermitIssuer {
  pub(crate) fn new(
    state: StateStore,
    authority: ScheduledDeploymentAuthority,
    credential_revision: String,
  ) -> Self {
    Self {
      state,
      authority,
      credential_revision,
    }
  }
}

#[async_trait]
impl RemoteIsolationPermitIssuer for RemoteCodexPermitIssuer {
  async fn issue(
    &self,
    input: &PrepareInput,
    session_nonce: &str,
  ) -> Result<String, PrepareFailure> {
    let identity = scheduled_identity(input);
    let permit = consume_authorization(
      &self.state,
      &self.authority,
      &identity,
      input.authority.digest(),
      now_unix_seconds()?,
    )
    .await?;
    permit
      .into_remote_envelope(
        input.authority.digest(),
        &self.credential_revision,
        session_nonce,
      )
      .map(|envelope| envelope.as_json().to_owned())
      .map_err(scheduled_failure)
  }
}

impl CodexScheduledExecutionBackend {
  pub(crate) fn new(
    state: StateStore,
    built: BuiltScheduledCodexExecutor,
    deployment: ScheduledCodexConfig,
    config: ScheduledWorkerConfig,
  ) -> Self {
    let cancellation_grace =
      Duration::from_millis(config.operational_policy.run_cancellation_grace_ms);
    let third = cancellation_grace / 3;
    Self {
      state: state.clone(),
      executor: built.executor,
      profile: built.profile.clone(),
      authority: ScheduledAuthorityManager::production(
        state,
        built.authority,
        deployment,
        built.profile,
      ),
      timeout: Duration::from_secs(u64::from(config.operational_policy.run_timeout_seconds)),
      interrupt_grace: third,
      terminate_grace: third,
      kill_grace: cancellation_grace
        .saturating_sub(third)
        .saturating_sub(third),
    }
  }
}

#[derive(Debug)]
struct ConsumedCodexAuthorization(ScheduledIsolationPermit);

#[async_trait]
impl ScheduledExecutionBackend for CodexScheduledExecutionBackend {
  fn readiness(&self) -> ExecutorReadiness {
    self.authority.readiness()
  }

  async fn refresh_readiness(&self) -> ExecutorReadiness {
    self.authority.refresh().await
  }

  async fn refresh_admission(&self) -> RefreshedExecutorAdmission {
    if self.authority.refresh().await != ExecutorReadiness::Ready {
      return RefreshedExecutorAdmission::Unavailable;
    }
    self.authority.admission().map_or(
      RefreshedExecutorAdmission::Unavailable,
      RefreshedExecutorAdmission::Authority,
    )
  }

  async fn authorize(&self, input: &PrepareInput) -> Result<BackendAuthorization, PrepareFailure> {
    let identity = scheduled_identity(input);
    let consumed_at = now_unix_seconds()?;
    let authority = self.authority.current().ok_or_else(authority_unavailable)?;
    let permit = consume_authorization(
      &self.state,
      &authority,
      &identity,
      input.authority.digest(),
      consumed_at,
    )
    .await?;
    Ok(BackendAuthorization::new(ConsumedCodexAuthorization(
      permit,
    )))
  }

  fn prepare(
    &self,
    input: PrepareInput,
    authorization: BackendAuthorization,
  ) -> Result<BackendPrepared, PrepareFailure> {
    let permit = authorization.downcast::<ConsumedCodexAuthorization>()?.0;
    let identity = scheduled_identity(&input);
    let request = ScheduledCodexRequest {
      task: input.task,
      identity,
      profile: self.profile.clone(),
      cancellation: input.cancellation,
      timeout: self.timeout,
      interrupt_grace: self.interrupt_grace,
      terminate_grace: self.terminate_grace,
      kill_grace: self.kill_grace,
    };
    let prepared = self
      .executor
      .prepare(request, permit)
      .map_err(prepare_failure)?;
    let capability_profile = prepared.attested_profile().canonical_json();
    let attested_profile_json = input
      .authority
      .recovery_attestation_json(&capability_profile)
      .map_err(|error| PrepareFailure::fatal(error.to_string()))?;
    let attested_profile_digest = sha256_hex(attested_profile_json.as_bytes());
    Ok(BackendPrepared::new(
      input.authority,
      attested_profile_json,
      attested_profile_digest,
      Box::new(CodexPreparedExecution(prepared)),
    ))
  }
}

fn scheduled_identity(input: &PrepareInput) -> ScheduledExecutionIdentity {
  ScheduledExecutionIdentity {
    run_id: input.binding.run_id().to_owned(),
    job_id: input.binding.job_id().to_owned(),
    attempt: input.binding.attempt(),
    fence: input.binding.fence(),
  }
}

fn permit_digest(
  domain: &str,
  identity: &ScheduledExecutionIdentity,
  prepare_authority_digest: &str,
  authority: &ScheduledDeploymentAuthority,
) -> String {
  sha256_hex(
    json!({
      "attestation_id": authority.attestation_id,
      "authority_digest": prepare_authority_digest,
      "deployment_epoch": authority.deployment_epoch,
      "domain": domain,
      "identity": {
        "attempt": identity.attempt,
        "fence": identity.fence,
        "job_id": identity.job_id,
        "run_id": identity.run_id,
      },
      "profile_digest": authority.profile_digest,
    })
    .to_string()
    .as_bytes(),
  )
}

async fn consume_authorization(
  state: &StateStore,
  authority: &ScheduledDeploymentAuthority,
  identity: &ScheduledExecutionIdentity,
  prepare_authority_digest: &str,
  consumed_at: i64,
) -> Result<ScheduledIsolationPermit, PrepareFailure> {
  let nonce = permit_digest(
    "scheduled-codex-permit-nonce-v1",
    identity,
    prepare_authority_digest,
    authority,
  );
  let permit_id = permit_digest(
    "scheduled-codex-permit-id-v1",
    identity,
    prepare_authority_digest,
    authority,
  );
  state
    .consume_scheduled_execution_permit(&ConsumeScheduledExecutionPermit {
      deployment_epoch: authority.deployment_epoch,
      attestation_id: authority.attestation_id.clone(),
      profile_digest: authority.profile_digest.clone(),
      run_id: identity.run_id.clone(),
      job_id: identity.job_id.clone(),
      attempt: identity.attempt,
      fence: identity.fence,
      authority_digest: prepare_authority_digest.to_owned(),
      nonce: nonce.clone(),
      permit_id: permit_id.clone(),
      consumed_at,
    })
    .await
    .map_err(permit_consumption_failure)?;
  ScheduledIsolationPermit::from_consumed(
    authority,
    identity.clone(),
    &authority.profile_digest,
    nonce,
    permit_id,
  )
  .map_err(scheduled_failure)
}

fn permit_consumption_failure(error: StateError) -> PrepareFailure {
  if matches!(
    &error,
    StateError::InvalidSchedulerState { reason }
      if reason == "scheduled execution permit deployment epoch is not current"
  ) {
    return authority_unavailable();
  }
  PrepareFailure::fatal(error.to_string())
}

struct CodexPreparedExecution(Box<dyn PreparedScheduledCodexExecution>);

impl PreparedExecution for CodexPreparedExecution {
  fn execute(self: Box<Self>, _cancellation: Arc<AtomicBool>) -> ExecutionResult {
    match self.0.execute() {
      ScheduledExecutionResult::Completed { output, .. } => ExecutionResult::Completed {
        summary: output.summary,
      },
      ScheduledExecutionResult::Interrupted { .. } => ExecutionResult::Interrupted {
        transport_converged: true,
      },
      ScheduledExecutionResult::TransportLost(failure) => ExecutionResult::TransportLost {
        message: failure.message,
      },
      ScheduledExecutionResult::Failed(failure)
      | ScheduledExecutionResult::PreflightRejected(failure) => execution_failure(failure),
    }
  }
}

fn prepare_failure(result: ScheduledExecutionResult) -> PrepareFailure {
  let failure = match result {
    ScheduledExecutionResult::Failed(failure)
    | ScheduledExecutionResult::TransportLost(failure)
    | ScheduledExecutionResult::PreflightRejected(failure) => failure,
    ScheduledExecutionResult::Interrupted { .. } => {
      return PrepareFailure::fatal("scheduled_prepare_interrupted");
    }
    ScheduledExecutionResult::Completed { .. } => {
      return PrepareFailure::fatal("scheduled_prepare_completed_without_execution");
    }
  };
  PrepareFailure {
    retryable: failure.kind == ScheduledFailureKind::Transport,
    kind: scheduled_failure_kind(failure.kind).to_owned(),
    message: failure.message,
  }
}

fn scheduled_failure(failure: ScheduledFailure) -> PrepareFailure {
  PrepareFailure {
    retryable: false,
    kind: scheduled_failure_kind(failure.kind).to_owned(),
    message: failure.message,
  }
}

fn authority_unavailable() -> PrepareFailure {
  PrepareFailure {
    retryable: true,
    kind: "scheduled_executor_unavailable".to_owned(),
    message: "scheduled_executor_authority_unavailable".to_owned(),
  }
}

fn execution_failure(failure: ScheduledFailure) -> ExecutionResult {
  match failure.kind {
    ScheduledFailureKind::TimedOut => ExecutionResult::TimedOut {
      transport_converged: true,
    },
    ScheduledFailureKind::Interrupted => ExecutionResult::Interrupted {
      transport_converged: true,
    },
    ScheduledFailureKind::Transport => ExecutionResult::TransportLost {
      message: failure.message,
    },
    kind => ExecutionResult::Failed {
      kind: scheduled_failure_kind(kind).to_owned(),
      message: failure.message,
    },
  }
}

const fn scheduled_failure_kind(kind: ScheduledFailureKind) -> &'static str {
  match kind {
    ScheduledFailureKind::InvalidRequest => "invalid_request",
    ScheduledFailureKind::ProtocolIncompatible => "protocol_incompatible",
    ScheduledFailureKind::CapabilityMismatch => "capability_mismatch",
    ScheduledFailureKind::CredentialIsolationUnproven => "credential_isolation_unproven",
    ScheduledFailureKind::OutputSchemaViolation => "output_schema_violation",
    ScheduledFailureKind::TurnFailed => "turn_failed",
    ScheduledFailureKind::TimedOut => "timed_out",
    ScheduledFailureKind::Interrupted => "interrupted",
    ScheduledFailureKind::Transport => "transport",
  }
}

fn now_unix_seconds() -> Result<i64, PrepareFailure> {
  SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .ok()
    .and_then(|duration| i64::try_from(duration.as_secs()).ok())
    .filter(|value| *value > 0)
    .ok_or_else(|| PrepareFailure::fatal("scheduled_executor_clock_invalid"))
}

fn sha256_hex(bytes: &[u8]) -> String {
  format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
  use std::sync::atomic::{AtomicI64, Ordering};

  use codeoff_state::ScheduledExecutorEpochAuthority;
  use tempfile::TempDir;

  use super::*;

  fn authority(
    deployment_epoch: i64,
    issued_at: i64,
    expires_at: i64,
    attestation_digit: char,
  ) -> ScheduledDeploymentAuthority {
    ScheduledDeploymentAuthority {
      schema_version: 1,
      deployment_epoch,
      attestation_id: attestation_digit.to_string().repeat(64),
      attestation_digest: "b".repeat(64),
      trust_key_id: "d".repeat(64),
      profile_digest: "c".repeat(64),
      github_mcp_access_auth_mode: "supervisor-dynamic-tools-v1".to_owned(),
      github_mcp_access_token_revision: "mcp-channel-v1".to_owned(),
      isolation_revision: "deployment-isolation-v1".to_owned(),
      issued_at_unix_seconds: u64::try_from(issued_at).expect("issued at"),
      expires_at_unix_seconds: u64::try_from(expires_at).expect("expires at"),
    }
  }

  async fn register_authority(
    state: &StateStore,
    authority: &ScheduledDeploymentAuthority,
    now: i64,
  ) {
    state
      .register_scheduled_executor_epoch(&epoch_authority(authority), now)
      .await
      .expect("register authority");
  }

  #[tokio::test]
  async fn live_authority_expires_fail_closed_and_recovers_on_higher_epoch() {
    let temp = TempDir::new().expect("tempdir");
    let state = StateStore::initialize(&temp.path().join("state"), None)
      .await
      .expect("initialize state");
    let initial = authority(7, 900, 1_040, 'a');
    register_authority(&state, &initial, 1_000).await;
    let loaded = Arc::new(RwLock::new(Ok(initial.clone())));
    let source_state = Arc::clone(&loaded);
    let source: Arc<AuthoritySource> =
      Arc::new(move || source_state.read().expect("authority source").clone());
    let now = Arc::new(AtomicI64::new(1_009));
    let clock_state = Arc::clone(&now);
    let clock: Arc<AuthorityClock> = Arc::new(move || Some(clock_state.load(Ordering::Acquire)));
    let manager = ScheduledAuthorityManager::with_source_and_clock(state, initial, source, clock);

    assert_eq!(manager.readiness(), ExecutorReadiness::Ready);
    now.store(1_010, Ordering::Release);
    assert_eq!(manager.readiness(), ExecutorReadiness::Unavailable);
    assert_eq!(manager.refresh().await, ExecutorReadiness::Unavailable);

    let rotated = authority(8, 1_005, 1_300, 'd');
    *loaded.write().expect("authority source") = Ok(rotated.clone());
    assert_eq!(manager.refresh().await, ExecutorReadiness::Ready);
    assert_eq!(manager.current(), Some(rotated));
  }

  #[tokio::test]
  async fn invalid_reload_preserves_only_a_still_claimable_cached_authority() {
    let temp = TempDir::new().expect("tempdir");
    let state_dir = temp.path().join("state");
    let state = StateStore::initialize(&state_dir, None)
      .await
      .expect("initialize state");
    let current = authority(8, 1_000, 1_300, 'd');
    register_authority(&state, &current, 1_010).await;
    let loaded = Arc::new(RwLock::new(Ok(current.clone())));
    let source_state = Arc::clone(&loaded);
    let source: Arc<AuthoritySource> =
      Arc::new(move || source_state.read().expect("authority source").clone());
    let now = Arc::new(AtomicI64::new(1_020));
    let clock_state = Arc::clone(&now);
    let clock: Arc<AuthorityClock> = Arc::new(move || Some(clock_state.load(Ordering::Acquire)));
    let manager = ScheduledAuthorityManager::with_source_and_clock(
      state.clone(),
      current.clone(),
      Arc::clone(&source),
      Arc::clone(&clock),
    );

    *loaded.write().expect("authority source") = Ok(authority(7, 1_000, 1_300, 'a'));
    assert_eq!(manager.refresh().await, ExecutorReadiness::Ready);
    *loaded.write().expect("authority source") = Ok(authority(8, 1_000, 1_300, 'e'));
    assert_eq!(manager.refresh().await, ExecutorReadiness::Ready);
    *loaded.write().expect("authority source") = Err(ScheduledFailure {
      kind: ScheduledFailureKind::CredentialIsolationUnproven,
      message: "malformed rotation".to_owned(),
    });
    assert_eq!(manager.refresh().await, ExecutorReadiness::Ready);
    assert_eq!(manager.current(), Some(current.clone()));

    now.store(1_270, Ordering::Release);
    assert_eq!(manager.refresh().await, ExecutorReadiness::Unavailable);
    drop(manager);
    drop(state);

    let reopened = StateStore::initialize(&state_dir, None)
      .await
      .expect("reopen state");
    register_authority(&reopened, &current, 1_020).await;
    *loaded.write().expect("authority source") = Ok(current.clone());
    now.store(1_020, Ordering::Release);
    let restarted =
      ScheduledAuthorityManager::with_source_and_clock(reopened, current, source, clock);
    assert_eq!(restarted.refresh().await, ExecutorReadiness::Ready);
  }

  #[tokio::test]
  async fn consumed_permit_cannot_be_replayed_after_restart() {
    let temp = TempDir::new().expect("tempdir");
    let state_dir = temp.path().join("state");
    let state = StateStore::initialize(&state_dir, None)
      .await
      .expect("initialize state");
    let now = now_unix_seconds().expect("clock");
    let authority = ScheduledDeploymentAuthority {
      schema_version: 1,
      deployment_epoch: 7,
      attestation_id: "a".repeat(64),
      attestation_digest: "b".repeat(64),
      trust_key_id: "d".repeat(64),
      profile_digest: "c".repeat(64),
      github_mcp_access_auth_mode: "supervisor-dynamic-tools-v1".to_owned(),
      github_mcp_access_token_revision: "mcp-channel-v1".to_owned(),
      isolation_revision: "deployment-isolation-v1".to_owned(),
      issued_at_unix_seconds: u64::try_from(now - 1).expect("issued at"),
      expires_at_unix_seconds: u64::try_from(now + 300).expect("expires at"),
    };
    state
      .register_scheduled_executor_epoch(
        &ScheduledExecutorEpochAuthority {
          schema_version: authority.schema_version,
          deployment_epoch: authority.deployment_epoch,
          attestation_id: authority.attestation_id.clone(),
          attestation_digest: authority.attestation_digest.clone(),
          profile_digest: authority.profile_digest.clone(),
          issued_at: now - 1,
          expires_at: now + 300,
        },
        now,
      )
      .await
      .expect("register epoch");
    let identity = ScheduledExecutionIdentity {
      run_id: "run-1".to_owned(),
      job_id: "job-1".to_owned(),
      attempt: 1,
      fence: 1,
    };
    consume_authorization(&state, &authority, &identity, &"d".repeat(64), now)
      .await
      .expect("first consumption");
    drop(state);

    let reopened = StateStore::initialize(&state_dir, None)
      .await
      .expect("reopen state");
    assert!(
      consume_authorization(&reopened, &authority, &identity, &"d".repeat(64), now + 1)
        .await
        .is_err()
    );
  }

  #[test]
  fn epoch_rotation_race_is_retryable_but_permit_replay_is_fatal() {
    let rotated = permit_consumption_failure(StateError::InvalidSchedulerState {
      reason: "scheduled execution permit deployment epoch is not current".to_owned(),
    });
    assert!(rotated.retryable);
    assert_eq!(rotated.kind, "scheduled_executor_unavailable");

    let replay = permit_consumption_failure(StateError::InvalidSchedulerState {
      reason: "scheduled execution permit was already consumed or replayed".to_owned(),
    });
    assert!(!replay.retryable);
    assert_eq!(replay.kind, "preflight_rejected");
  }
}
