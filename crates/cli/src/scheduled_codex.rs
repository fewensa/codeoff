use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use codeoff_agent_codex::{
  BuiltScheduledCodexExecutor, PreparedScheduledCodexExecution, RequestedCapabilityProfile,
  ScheduledCodexExecution, ScheduledCodexRequest, ScheduledDeploymentAuthority,
  ScheduledExecutionIdentity, ScheduledExecutionResult, ScheduledFailure, ScheduledFailureKind,
  ScheduledIsolationPermit,
};
use codeoff_runtime::scheduled_execution::{
  BackendAuthorization, BackendPrepared, ExecutionResult, ExecutorReadiness, PrepareFailure,
  PrepareInput, PreparedExecution, ScheduledExecutionBackend, ScheduledWorkerConfig,
};
use codeoff_state::{ConsumeScheduledExecutionPermit, StateStore};
use serde_json::json;
use sha2::{Digest, Sha256};

pub(crate) struct CodexScheduledExecutionBackend {
  state: StateStore,
  executor: Arc<dyn ScheduledCodexExecution>,
  profile: RequestedCapabilityProfile,
  authority: ScheduledDeploymentAuthority,
  timeout: Duration,
  interrupt_grace: Duration,
  terminate_grace: Duration,
  kill_grace: Duration,
}

impl CodexScheduledExecutionBackend {
  pub(crate) fn new(
    state: StateStore,
    built: BuiltScheduledCodexExecutor,
    config: ScheduledWorkerConfig,
  ) -> Self {
    let cancellation_grace = Duration::from_millis(config.cancellation_grace_ms);
    let third = cancellation_grace / 3;
    Self {
      state,
      executor: built.executor,
      profile: built.profile,
      authority: built.authority,
      timeout: Duration::from_secs(u64::from(config.total_timeout_seconds)),
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
    ExecutorReadiness::Ready
  }

  async fn authorize(&self, input: &PrepareInput) -> Result<BackendAuthorization, PrepareFailure> {
    let identity = scheduled_identity(input);
    let consumed_at = now_unix_seconds()?;
    let permit = consume_authorization(
      &self.state,
      &self.authority,
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
    .map_err(|error| PrepareFailure::fatal(error.to_string()))?;
  ScheduledIsolationPermit::from_consumed(
    authority,
    identity.clone(),
    &authority.profile_digest,
    nonce,
    permit_id,
  )
  .map_err(scheduled_failure)
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
  use codeoff_state::ScheduledExecutorEpochAuthority;
  use tempfile::TempDir;

  use super::*;

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
      profile_digest: "c".repeat(64),
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
}
