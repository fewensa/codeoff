use std::fmt::{self, Write as _};
use std::sync::Arc;
use std::time::Duration;

use codeoff_state::{
  CapabilityProfileSnapshot, CreateScheduledJob, DeliveryTargetSnapshot, PrincipalKey,
  ScheduleMutationAudit, ScheduleMutationIdempotency, ScheduleSpec, ScheduledJob,
  ScheduledJobDefinition, ScheduledJobMutation, ScheduledJobStatus, StateError, StateStore,
  TransactionalMutationOutcome, UpdateScheduledJob,
};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::schedule_audit::ScheduleAuditAttempt;
use crate::schedule_contract::{error_envelope, success_envelope};

const DIGEST_ALGORITHM: &str = "sha256-canonical-json-v1";
pub(crate) const SNAPSHOT_VERSION: u32 = 1;
const DEFINITION_VERSION: u32 = 2;

pub use crate::schedule_authorization::{
  AuthorizationPolicy, ConfiguredOperatorIdentityPolicy, DisabledOperatorIdentityPolicy,
  OperatorAuthorizationPolicy, OperatorIdentityPolicy, OwnerOnlyAuthorizationPolicy,
  ScheduleInvocation,
};
pub use crate::schedule_resolution::{
  CapabilityRegistry, CapabilityRequest, ChannelTargetVerifier, DefaultCapabilityRegistry,
  DefaultTargetResolver, DeliveryTargetRequest, SlackTargetResolutionRequest, TargetResolver,
  TargetResolverRegistration, TargetResolverRegistry, TargetVerificationError, VerifiedSlackTarget,
  VerifiedSlackTargetResolver,
};
use crate::schedule_resolution::{
  ResolvedTargetSet, scope_targets, validate_capability_snapshot, validate_resolved_targets,
};

#[derive(Debug)]
pub enum ScheduleServiceError {
  Unauthorized,
  NotVisible,
  InvalidRequest(String),
  ResolverUnavailable,
  TargetUnavailable,
  ResolverNotAllowed,
  ResolverTimeout,
  CapabilityUnavailable,
  CapabilityInvalid,
  IdempotencyInProgress,
  IdempotencyConflict,
  State(StateError),
}

impl fmt::Display for ScheduleServiceError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::Unauthorized => write!(
        formatter,
        "schedule operation requires an authenticated actor"
      ),
      Self::NotVisible => write!(formatter, "schedule was not found or is not visible"),
      Self::InvalidRequest(reason) => write!(formatter, "invalid schedule request: {reason}"),
      Self::ResolverUnavailable => write!(formatter, "target resolver is unavailable"),
      Self::TargetUnavailable => write!(formatter, "target is unavailable"),
      Self::ResolverNotAllowed => write!(formatter, "target is not allowed"),
      Self::ResolverTimeout => write!(formatter, "target resolver timed out"),
      Self::CapabilityUnavailable => write!(formatter, "capability is unavailable"),
      Self::CapabilityInvalid => write!(formatter, "capability snapshot is invalid"),
      Self::IdempotencyInProgress => write!(formatter, "schedule request is already in progress"),
      Self::IdempotencyConflict => {
        write!(formatter, "request id was reused with different semantics")
      }
      Self::State(_) => write!(formatter, "schedule storage operation failed"),
    }
  }
}

impl std::error::Error for ScheduleServiceError {}

impl From<StateError> for ScheduleServiceError {
  fn from(error: StateError) -> Self {
    Self::State(error)
  }
}

impl From<String> for ScheduleServiceError {
  fn from(reason: String) -> Self {
    Self::InvalidRequest(reason)
  }
}

impl From<&str> for ScheduleServiceError {
  fn from(reason: &str) -> Self {
    Self::InvalidRequest(reason.to_owned())
  }
}

impl ScheduleServiceError {
  #[must_use]
  pub fn code(&self) -> &'static str {
    match self {
      Self::Unauthorized => "unauthorized",
      Self::NotVisible => "not_found_or_not_visible",
      Self::InvalidRequest(_) => "validation_failed",
      Self::ResolverUnavailable => "resolver_unavailable",
      Self::TargetUnavailable => "target_unavailable",
      Self::ResolverNotAllowed => "resolver_not_allowed",
      Self::ResolverTimeout => "resolver_timeout",
      Self::CapabilityUnavailable => "capability_unavailable",
      Self::CapabilityInvalid => "capability_invalid",
      Self::IdempotencyInProgress => "idempotency_in_progress",
      Self::IdempotencyConflict => "idempotency_conflict",
      Self::State(StateError::SchedulerGenerationConflict) => "stale_generation",
      Self::State(StateError::ScheduledOnceExpired) => "expired_not_resumable",
      Self::State(error) if error.is_transient_storage_contention() => "storage_busy",
      Self::State(_) => "storage_error",
    }
  }

  #[must_use]
  pub fn retryable(&self) -> bool {
    match self {
      Self::ResolverUnavailable | Self::ResolverTimeout | Self::IdempotencyInProgress => true,
      Self::State(error) => error.is_transient_storage_contention(),
      _ => false,
    }
  }

  #[must_use]
  pub fn structured_json(&self) -> Value {
    error_envelope(self.code(), self.retryable(), &self.to_string(), json!({}))
  }
}

#[derive(Debug, Clone)]
pub struct CreateScheduleRequest {
  pub request_id: String,
  pub instruction: String,
  pub previous_success: PreviousSuccessPolicy,
  pub schedule: ScheduleSpec,
  pub target: DeliveryTargetRequest,
  pub capability: String,
  pub now: i64,
}

#[derive(Debug, Clone)]
pub struct UpdateScheduleRequest {
  pub request_id: String,
  pub job_id: String,
  pub expected_generation: i64,
  pub instruction: String,
  pub previous_success: PreviousSuccessPolicy,
  pub schedule: ScheduleSpec,
  pub target: DeliveryTargetRequest,
  pub capability: String,
  pub now: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreviousSuccessPolicy {
  None,
  LatestSuccess,
}

impl PreviousSuccessPolicy {
  #[must_use]
  pub const fn as_str(self) -> &'static str {
    match self {
      Self::None => "none",
      Self::LatestSuccess => "latest_success",
    }
  }
}

#[derive(Debug, Clone)]
pub struct LifecycleScheduleRequest {
  pub request_id: String,
  pub job_id: String,
  pub expected_generation: i64,
  pub now: i64,
}

struct PreparedMutation {
  mutation: ScheduledJobMutation,
  owner: PrincipalKey,
  request_id: String,
  request_digest: String,
  response: Value,
}

#[derive(Clone)]
pub struct ScheduleService {
  state: StateStore,
  target_resolver: Arc<TargetResolverRegistry>,
  capability_registry: Arc<dyn CapabilityRegistry>,
  authorization: Arc<dyn AuthorizationPolicy>,
  resolver_timeout: Duration,
}

impl ScheduleService {
  #[must_use]
  pub fn new(state: StateStore) -> Self {
    Self {
      state,
      target_resolver: Arc::new(TargetResolverRegistry::with_defaults()),
      capability_registry: Arc::new(DefaultCapabilityRegistry),
      authorization: Arc::new(OwnerOnlyAuthorizationPolicy),
      resolver_timeout: Duration::from_secs(5),
    }
  }
}

impl ScheduleService {
  #[must_use]
  pub fn with_components(
    state: StateStore,
    target_resolver: Arc<TargetResolverRegistry>,
    capability_registry: Arc<dyn CapabilityRegistry>,
    authorization: Arc<dyn AuthorizationPolicy>,
    resolver_timeout: Duration,
  ) -> Self {
    Self {
      state,
      target_resolver,
      capability_registry,
      authorization,
      resolver_timeout,
    }
  }

  pub fn describe_supported_targets(
    &self,
    invocation: &ScheduleInvocation,
  ) -> Result<Vec<&'static str>, ScheduleServiceError> {
    self.authorize_create_principal(invocation)?;
    Ok(self.target_resolver.describe_supported_targets(invocation))
  }

  pub fn describe_authorized_capabilities(
    &self,
    invocation: &ScheduleInvocation,
  ) -> Result<Vec<&'static str>, ScheduleServiceError> {
    self.authorize_create_principal(invocation)?;
    Ok(self.capability_registry.describe_authorized(invocation))
  }

  pub async fn reject_invalid_attempt(
    &self,
    invocation: &ScheduleInvocation,
    operation: &'static str,
    request_id: Option<&str>,
    job_id: Option<&str>,
    error: ScheduleServiceError,
    now: i64,
  ) -> ScheduleServiceError {
    let attempt = self.audit_attempt(invocation, operation, request_id, job_id, now);
    match self
      .state
      .append_schedule_audit(&attempt.error_record(&error))
      .await
    {
      Ok(()) => error,
      Err(state_error) => ScheduleServiceError::State(state_error),
    }
  }

  pub async fn create(
    &self,
    invocation: &ScheduleInvocation,
    request: CreateScheduleRequest,
  ) -> Result<Value, ScheduleServiceError> {
    let attempt = self.audit_attempt(
      invocation,
      "create",
      Some(&request.request_id),
      None,
      request.now,
    );
    match self.prepare_create(invocation, request).await {
      Ok(prepared) => self.apply_mutation(prepared, &attempt).await,
      Err(error) => self.finish_error_attempt(&attempt, error).await,
    }
  }

  async fn prepare_create(
    &self,
    invocation: &ScheduleInvocation,
    request: CreateScheduleRequest,
  ) -> Result<PreparedMutation, ScheduleServiceError> {
    validate_request_id(&request.request_id)?;
    validate_instruction(&request.instruction)?;
    let owner = self.authorize_create_principal(invocation)?;
    let job_id = format!(
      "job_{}",
      &digest_json(&json!({
        "owner": principal_json(&owner),
        "request_id": request.request_id,
      }))?[..32]
    );
    let capability = self.resolve_capability(invocation, &owner, &request.capability)?;
    let targets = scope_targets(
      &job_id,
      validate_resolved_targets(
        invocation,
        &owner,
        &request.target,
        self
          .resolve_targets(invocation, &owner, &request.target, request.now)
          .await?,
      )?,
    )?;
    let semantic = mutation_semantics(
      "create",
      &owner,
      &request.instruction,
      request.previous_success,
      &request.schedule,
      &capability,
      &targets,
      None,
      None,
    )?;
    let next_run_at = request
      .schedule
      .first_after_create(request.now)
      .map_err(|error| ScheduleServiceError::InvalidRequest(error.to_string()))?;
    let response = success_envelope(json!({
      "job_id": job_id,
      "status": "active",
      "generation": 0,
      "next_run_at": next_run_at,
      "targets": target_summary(&targets),
    }));
    let mutation = ScheduledJobMutation::Create(Box::new(CreateScheduledJob {
      job_id: job_id.clone(),
      schedule_id: format!("schedule_{job_id}"),
      definition: definition(&request.instruction, request.previous_success)?,
      creator: owner.clone(),
      owner: owner.clone(),
      capability,
      targets,
      schedule: request.schedule,
      now: request.now,
    }));
    Ok(PreparedMutation {
      mutation,
      owner,
      request_id: request.request_id,
      request_digest: digest_json(&semantic)?,
      response,
    })
  }
  pub async fn update(
    &self,
    invocation: &ScheduleInvocation,
    request: UpdateScheduleRequest,
  ) -> Result<Value, ScheduleServiceError> {
    let attempt = self.audit_attempt(
      invocation,
      "update",
      Some(&request.request_id),
      Some(&request.job_id),
      request.now,
    );
    match self.prepare_update(invocation, request).await {
      Ok(prepared) => self.apply_mutation(prepared, &attempt).await,
      Err(error) => self.finish_error_attempt(&attempt, error).await,
    }
  }

  async fn prepare_update(
    &self,
    invocation: &ScheduleInvocation,
    request: UpdateScheduleRequest,
  ) -> Result<PreparedMutation, ScheduleServiceError> {
    validate_request_id(&request.request_id)?;
    validate_instruction(&request.instruction)?;
    let (owner, current) = self.authorize_job(invocation, &request.job_id).await?;
    let capability = self.resolve_capability(invocation, &owner, &request.capability)?;
    let targets = scope_targets(
      &request.job_id,
      validate_resolved_targets(
        invocation,
        &owner,
        &request.target,
        self
          .resolve_targets(invocation, &owner, &request.target, request.now)
          .await?,
      )?,
    )?;
    let semantic = mutation_semantics(
      "update",
      &owner,
      &request.instruction,
      request.previous_success,
      &request.schedule,
      &capability,
      &targets,
      Some(&request.job_id),
      Some(request.expected_generation),
    )?;
    let next_run_at = if current.status == ScheduledJobStatus::Active {
      Some(
        request
          .schedule
          .first_after_create(request.now)
          .map_err(|error| ScheduleServiceError::InvalidRequest(error.to_string()))?,
      )
    } else {
      None
    };
    let response = success_envelope(json!({
      "job_id": request.job_id,
      "status": current.status.as_str(),
      "generation": next_generation(request.expected_generation)?,
      "next_run_at": next_run_at,
      "targets": target_summary(&targets),
    }));
    let mutation = ScheduledJobMutation::Update(Box::new(UpdateScheduledJob {
      job_id: request.job_id,
      expected_generation: request.expected_generation,
      definition: definition(&request.instruction, request.previous_success)?,
      capability,
      targets,
      schedule: request.schedule,
      now: request.now,
    }));
    Ok(PreparedMutation {
      mutation,
      owner,
      request_id: request.request_id,
      request_digest: digest_json(&semantic)?,
      response,
    })
  }
  pub async fn pause(
    &self,
    invocation: &ScheduleInvocation,
    request: LifecycleScheduleRequest,
  ) -> Result<Value, ScheduleServiceError> {
    self.lifecycle(invocation, request, "pause").await
  }

  pub async fn resume(
    &self,
    invocation: &ScheduleInvocation,
    request: LifecycleScheduleRequest,
  ) -> Result<Value, ScheduleServiceError> {
    self.lifecycle(invocation, request, "resume").await
  }

  pub async fn delete(
    &self,
    invocation: &ScheduleInvocation,
    request: LifecycleScheduleRequest,
  ) -> Result<Value, ScheduleServiceError> {
    self.lifecycle(invocation, request, "delete").await
  }

  pub async fn get(
    &self,
    invocation: &ScheduleInvocation,
    job_id: &str,
    now: i64,
  ) -> Result<Value, ScheduleServiceError> {
    let attempt = self.audit_attempt(invocation, "get", Some(job_id), Some(job_id), now);
    let result = async {
      let (owner, job) = self.authorize_job(invocation, job_id).await?;
      let targets = self
        .state
        .get_scheduled_job_delivery_targets(job_id)
        .await?;
      Ok((success_envelope(job_json(&job, &targets)?), owner))
    }
    .await;
    self.finish_authorized_read_attempt(&attempt, result).await
  }

  pub async fn list(
    &self,
    invocation: &ScheduleInvocation,
    status: ScheduledJobStatus,
    cursor: Option<&str>,
    limit: u32,
    now: i64,
  ) -> Result<Value, ScheduleServiceError> {
    let attempt = self.audit_attempt(invocation, "list", Some("list"), None, now);
    let result = async {
      let owner = self.authorization.authenticate(invocation)?;
      self.authorization.authorize_list(&owner)?;
      let page = self
        .state
        .list_scheduled_jobs_by_owner(&owner, status, cursor, limit)
        .await?;
      Ok((
        success_envelope(json!({
          "job_ids": page.job_ids,
          "next_cursor": page.next_cursor,
        })),
        owner,
      ))
    }
    .await;
    self.finish_authorized_read_attempt(&attempt, result).await
  }

  async fn lifecycle(
    &self,
    invocation: &ScheduleInvocation,
    request: LifecycleScheduleRequest,
    operation: &'static str,
  ) -> Result<Value, ScheduleServiceError> {
    let attempt = self.audit_attempt(
      invocation,
      operation,
      Some(&request.request_id),
      Some(&request.job_id),
      request.now,
    );
    match self.prepare_lifecycle(invocation, request, operation).await {
      Ok(prepared) => self.apply_mutation(prepared, &attempt).await,
      Err(error) => self.finish_error_attempt(&attempt, error).await,
    }
  }

  async fn prepare_lifecycle(
    &self,
    invocation: &ScheduleInvocation,
    request: LifecycleScheduleRequest,
    operation: &'static str,
  ) -> Result<PreparedMutation, ScheduleServiceError> {
    validate_request_id(&request.request_id)?;
    let (owner, current) = self.authorize_job(invocation, &request.job_id).await?;
    let targets = self
      .state
      .get_scheduled_job_delivery_targets(&request.job_id)
      .await?;
    let semantic = json!({
      "operation": operation,
      "owner": principal_json(&owner),
      "job_id": request.job_id,
      "expected_generation": request.expected_generation,
    });
    let (status, next_run_at) = match operation {
      "pause" => ("paused", None),
      "resume" => (
        "active",
        Some(current.schedule.next_after(request.now).map_err(|error| {
          if matches!(current.schedule, ScheduleSpec::Once { .. }) {
            ScheduleServiceError::State(StateError::ScheduledOnceExpired)
          } else {
            ScheduleServiceError::InvalidRequest(error.to_string())
          }
        })?),
      ),
      "delete" => ("deleted", None),
      _ => unreachable!("bounded lifecycle operation"),
    };
    let response = success_envelope(json!({
      "job_id": request.job_id,
      "status": status,
      "generation": next_generation(request.expected_generation)?,
      "next_run_at": next_run_at,
      "targets": target_summary(&targets),
    }));
    let mutation = match operation {
      "pause" => ScheduledJobMutation::Pause {
        job_id: request.job_id,
        expected_generation: request.expected_generation,
        now: request.now,
      },
      "resume" => ScheduledJobMutation::Resume {
        job_id: request.job_id,
        expected_generation: request.expected_generation,
        now: request.now,
      },
      "delete" => ScheduledJobMutation::Delete {
        job_id: request.job_id,
        expected_generation: request.expected_generation,
        now: request.now,
      },
      _ => unreachable!("bounded lifecycle operation"),
    };
    Ok(PreparedMutation {
      mutation,
      owner,
      request_id: request.request_id,
      request_digest: digest_json(&semantic)?,
      response,
    })
  }

  async fn authorize_job(
    &self,
    invocation: &ScheduleInvocation,
    job_id: &str,
  ) -> Result<(PrincipalKey, ScheduledJob), ScheduleServiceError> {
    let owner = self.authorization.authenticate(invocation)?;
    bounded("job_id", job_id)?;
    let job = self
      .state
      .get_scheduled_job_by_owner(&owner, job_id)
      .await?;
    let job = self.authorization.authorize_existing(&owner, job)?;
    Ok((owner, job))
  }

  fn authorize_create_principal(
    &self,
    invocation: &ScheduleInvocation,
  ) -> Result<PrincipalKey, ScheduleServiceError> {
    let principal = self.authorization.authenticate(invocation)?;
    self.authorization.authorize_create(&principal)?;
    Ok(principal)
  }

  fn audit_attempt(
    &self,
    invocation: &ScheduleInvocation,
    operation: &'static str,
    request_id: Option<&str>,
    job_id: Option<&str>,
    now: i64,
  ) -> ScheduleAuditAttempt {
    let mut attempt = ScheduleAuditAttempt::new(invocation, operation, request_id, job_id, now);
    if let Ok(principal) = self.authorization.authenticate(invocation) {
      attempt.principal = Some(principal);
    }
    attempt
  }

  fn resolve_capability(
    &self,
    invocation: &ScheduleInvocation,
    owner: &PrincipalKey,
    name: &str,
  ) -> Result<CapabilityProfileSnapshot, ScheduleServiceError> {
    if !self
      .capability_registry
      .describe_authorized(invocation)
      .contains(&name)
    {
      return Err(ScheduleServiceError::CapabilityUnavailable);
    }
    let snapshot = self
      .capability_registry
      .resolve(
        invocation,
        owner,
        &CapabilityRequest {
          name: name.to_owned(),
        },
      )
      .map_err(|error| match error {
        ScheduleServiceError::CapabilityUnavailable => error,
        _ => ScheduleServiceError::CapabilityInvalid,
      })?;
    validate_capability_snapshot(name, snapshot)
  }

  async fn resolve_targets(
    &self,
    invocation: &ScheduleInvocation,
    owner: &PrincipalKey,
    target: &DeliveryTargetRequest,
    now: i64,
  ) -> Result<ResolvedTargetSet, ScheduleServiceError> {
    tokio::time::timeout(
      self.resolver_timeout,
      self.target_resolver.resolve(invocation, owner, target, now),
    )
    .await
    .map_err(|_| ScheduleServiceError::ResolverTimeout)?
  }

  async fn apply_mutation(
    &self,
    prepared: PreparedMutation,
    attempt: &ScheduleAuditAttempt,
  ) -> Result<Value, ScheduleServiceError> {
    let PreparedMutation {
      mutation,
      owner,
      request_id,
      request_digest,
      response,
    } = prepared;
    let response_json = match canonical_json(&response) {
      Ok(response) => response,
      Err(error) => return self.finish_error_attempt(attempt, error).await,
    };
    let operation = mutation_operation(&mutation);
    let job_id = mutation_job_id(&mutation).to_owned();
    let (old_generation, new_generation) = mutation_generations(&mutation);
    let (
      resolver_provider,
      target_kind,
      resolver_version,
      resolver_digest,
      capability_version,
      capability_digest,
    ) = mutation_audit_snapshots(&mutation);
    let mut audit = attempt.record("applied", "allow", None);
    audit.principal = Some(owner.clone());
    audit.operation = operation.to_owned();
    audit.job_id = Some(job_id);
    audit.request_id.clone_from(&request_id);
    audit.correlation_id.clone_from(&request_id);
    audit.old_generation = old_generation;
    audit.new_generation = new_generation;
    audit.resolver_provider = resolver_provider;
    audit.target_kind = target_kind;
    audit.resolver_version = resolver_version;
    audit.resolver_digest = resolver_digest;
    audit.capability_version = capability_version;
    audit.capability_digest = capability_digest;
    audit.idempotency_outcome = Some("applied".to_owned());
    let idempotency = ScheduleMutationIdempotency {
      principal: owner,
      request_id,
      digest_algorithm: DIGEST_ALGORITHM.to_owned(),
      request_digest,
      response_json,
    };
    let outcome = self
      .state
      .apply_idempotent_schedule_mutation_with_audit(&mutation, &idempotency, Some(&audit))
      .await;
    match outcome {
      Err(error) => {
        self
          .finish_error_attempt(attempt, ScheduleServiceError::State(error))
          .await
      }
      Ok(TransactionalMutationOutcome::Applied(response)) => serde_json::from_str(&response)
        .map_err(|error| {
          ScheduleServiceError::State(StateError::InvalidSchedulerState {
            reason: format!("invalid persisted schedule response: {error}"),
          })
        }),
      Ok(TransactionalMutationOutcome::Replay(response)) => {
        let response = match serde_json::from_str(&response) {
          Ok(response) => response,
          Err(error) => {
            return self
              .finish_error_attempt(
                attempt,
                ScheduleServiceError::State(StateError::InvalidSchedulerState {
                  reason: format!("invalid persisted schedule response: {error}"),
                }),
              )
              .await;
          }
        };
        let mut replay = attempt.record("replay", "allow", None);
        replay.idempotency_outcome = Some("replay".to_owned());
        self.append_attempt(replay).await?;
        Ok(response)
      }
      Ok(TransactionalMutationOutcome::InProgress) => {
        self
          .finish_error_attempt(attempt, ScheduleServiceError::IdempotencyInProgress)
          .await
      }
      Ok(TransactionalMutationOutcome::Conflict) => {
        self
          .finish_error_attempt(attempt, ScheduleServiceError::IdempotencyConflict)
          .await
      }
    }
  }

  async fn finish_authorized_read_attempt(
    &self,
    attempt: &ScheduleAuditAttempt,
    result: Result<(Value, PrincipalKey), ScheduleServiceError>,
  ) -> Result<Value, ScheduleServiceError> {
    match result {
      Ok((value, owner)) => {
        let mut audit = attempt.record("applied", "allow", None);
        audit.principal = Some(owner);
        self.append_attempt(audit).await?;
        Ok(value)
      }
      Err(error) => self.finish_error_attempt(attempt, error).await,
    }
  }

  async fn finish_error_attempt(
    &self,
    attempt: &ScheduleAuditAttempt,
    error: ScheduleServiceError,
  ) -> Result<Value, ScheduleServiceError> {
    self.append_attempt(attempt.error_record(&error)).await?;
    Err(error)
  }

  async fn append_attempt(&self, audit: ScheduleMutationAudit) -> Result<(), ScheduleServiceError> {
    self
      .state
      .append_schedule_audit(&audit)
      .await
      .map_err(Into::into)
  }
}

pub(crate) fn bounded<'a>(field: &str, value: &'a str) -> Result<&'a str, ScheduleServiceError> {
  if value.trim().is_empty() || value.len() > 255 || value != value.trim() {
    return Err(ScheduleServiceError::InvalidRequest(format!(
      "{field} must be a bounded non-empty string"
    )));
  }
  Ok(value)
}

fn validate_request_id(value: &str) -> Result<(), ScheduleServiceError> {
  bounded("request_id", value).map(|_| ())
}

fn validate_instruction(value: &str) -> Result<(), ScheduleServiceError> {
  if value.trim().is_empty() || value.len() > 64 * 1024 {
    return Err(ScheduleServiceError::InvalidRequest(
      "instruction must contain 1..=65536 bytes".to_owned(),
    ));
  }
  Ok(())
}

fn definition(
  instruction: &str,
  previous_success: PreviousSuccessPolicy,
) -> Result<ScheduledJobDefinition, ScheduleServiceError> {
  ScheduledJobDefinition::new(
    DEFINITION_VERSION,
    canonical_json(&json!({
      "schema_version": DEFINITION_VERSION,
      "instruction": instruction,
      "previous_success": {"kind": previous_success.as_str()},
    }))?,
  )
  .map_err(|error| ScheduleServiceError::InvalidRequest(error.to_string()))
}

#[allow(clippy::too_many_arguments)]
fn mutation_semantics(
  operation: &str,
  owner: &PrincipalKey,
  instruction: &str,
  previous_success: PreviousSuccessPolicy,
  schedule: &ScheduleSpec,
  capability: &CapabilityProfileSnapshot,
  targets: &[DeliveryTargetSnapshot],
  job_id: Option<&str>,
  expected_generation: Option<i64>,
) -> Result<Value, ScheduleServiceError> {
  let definition = match previous_success {
    PreviousSuccessPolicy::None => {
      json!({"version": SNAPSHOT_VERSION, "instruction": instruction})
    }
    PreviousSuccessPolicy::LatestSuccess => json!({
      "version": DEFINITION_VERSION,
      "instruction": instruction,
      "previous_success": {"kind": previous_success.as_str()},
    }),
  };
  Ok(json!({
    "operation": operation,
    "owner": principal_json(owner),
    "job_id": job_id,
    "expected_generation": expected_generation,
    "definition": definition,
    "schedule": schedule_json(schedule),
    "capability": {
      "version": capability.schema_version(),
      "digest": capability.digest(),
      "snapshot": serde_json::from_str::<Value>(capability.canonical_json()).map_err(|error| ScheduleServiceError::InvalidRequest(error.to_string()))?,
    },
    "targets": targets.iter().map(target_json).collect::<Result<Vec<_>, _>>()?,
  }))
}

fn target_json(target: &DeliveryTargetSnapshot) -> Result<Value, ScheduleServiceError> {
  Ok(json!({
    "provider": target.provider(),
    "connector": target.connector(),
    "tenant": target.tenant(),
    "kind": target.kind(),
    "address": serde_json::from_str::<Value>(target.address_json()).map_err(|error| ScheduleServiceError::InvalidRequest(error.to_string()))?,
    "resolver_version": target.resolver_version(),
    "resolver_digest": target.resolver_digest(),
    "identity_digest": target.identity_digest(),
  }))
}

fn next_generation(generation: i64) -> Result<i64, ScheduleServiceError> {
  generation.checked_add(1).ok_or_else(|| {
    ScheduleServiceError::InvalidRequest("expected_generation is too large".to_owned())
  })
}

fn schedule_json(schedule: &ScheduleSpec) -> Value {
  match schedule {
    ScheduleSpec::Once { at } => json!({"kind": "once", "at": at}),
    ScheduleSpec::FixedInterval {
      anchor,
      every_seconds,
    } => json!({"kind": "fixed_interval", "anchor": anchor, "every_seconds": every_seconds}),
    ScheduleSpec::Cron {
      expression,
      timezone,
    } => json!({"kind": "cron", "expression": expression, "timezone": timezone}),
  }
}

fn principal_json(principal: &PrincipalKey) -> Value {
  json!({
    "kind": principal.kind(),
    "provider": principal.provider(),
    "tenant": principal.tenant(),
    "subject": principal.subject(),
  })
}

fn mutation_operation(mutation: &ScheduledJobMutation) -> &'static str {
  match mutation {
    ScheduledJobMutation::Create(_) => "create",
    ScheduledJobMutation::Update(_) => "update",
    ScheduledJobMutation::Pause { .. } => "pause",
    ScheduledJobMutation::Resume { .. } => "resume",
    ScheduledJobMutation::Delete { .. } => "delete",
  }
}

fn mutation_job_id(mutation: &ScheduledJobMutation) -> &str {
  match mutation {
    ScheduledJobMutation::Create(request) => &request.job_id,
    ScheduledJobMutation::Update(request) => &request.job_id,
    ScheduledJobMutation::Pause { job_id, .. }
    | ScheduledJobMutation::Resume { job_id, .. }
    | ScheduledJobMutation::Delete { job_id, .. } => job_id,
  }
}

fn mutation_generations(mutation: &ScheduledJobMutation) -> (Option<i64>, Option<i64>) {
  match mutation {
    ScheduledJobMutation::Create(_) => (None, Some(0)),
    ScheduledJobMutation::Update(request) => (
      Some(request.expected_generation),
      request.expected_generation.checked_add(1),
    ),
    ScheduledJobMutation::Pause {
      expected_generation,
      ..
    }
    | ScheduledJobMutation::Resume {
      expected_generation,
      ..
    }
    | ScheduledJobMutation::Delete {
      expected_generation,
      ..
    } => (
      Some(*expected_generation),
      expected_generation.checked_add(1),
    ),
  }
}

type MutationAuditSnapshots = (
  Option<String>,
  Option<String>,
  Option<i64>,
  Option<String>,
  Option<i64>,
  Option<String>,
);

fn mutation_audit_snapshots(mutation: &ScheduledJobMutation) -> MutationAuditSnapshots {
  let (targets, capability) = match mutation {
    ScheduledJobMutation::Create(request) => {
      (Some(request.targets.as_slice()), Some(&request.capability))
    }
    ScheduledJobMutation::Update(request) => {
      (Some(request.targets.as_slice()), Some(&request.capability))
    }
    _ => (None, None),
  };
  let target = targets.and_then(|targets| targets.first());
  (
    target.map(|target| target.provider().to_owned()),
    target.map(|target| target.kind().to_owned()),
    target.map(|target| i64::from(target.resolver_version())),
    target.map(|target| target.resolver_digest().to_owned()),
    capability.map(|capability| i64::from(capability.schema_version())),
    capability.map(|capability| capability.digest().to_owned()),
  )
}

fn target_summary(targets: &[DeliveryTargetSnapshot]) -> Value {
  json!({
    "count": targets.len(),
    "items": targets.iter().map(|target| json!({
      "provider": target.provider(),
      "kind": target.kind(),
      "resolver_version": target.resolver_version(),
      "resolver_digest": target.resolver_digest(),
      "identity_digest": target.identity_digest(),
    })).collect::<Vec<_>>(),
  })
}

fn job_json(
  job: &ScheduledJob,
  targets: &[DeliveryTargetSnapshot],
) -> Result<Value, ScheduleServiceError> {
  Ok(json!({
    "job_id": job.job_id,
    "status": job.status.as_str(),
    "generation": job.generation,
    "definition": serde_json::from_str::<Value>(job.definition.canonical_json()).map_err(|error| ScheduleServiceError::InvalidRequest(error.to_string()))?,
    "schedule": schedule_json(&job.schedule),
    "next_run_at": job.next_run_at,
    "targets": target_summary(targets),
    "capability": serde_json::from_str::<Value>(job.capability.canonical_json()).map_err(|error| ScheduleServiceError::InvalidRequest(error.to_string()))?,
  }))
}

pub(crate) fn canonical_json(value: &Value) -> Result<String, ScheduleServiceError> {
  serde_json::to_string(&canonicalize(value))
    .map_err(|error| ScheduleServiceError::InvalidRequest(error.to_string()))
}

pub(crate) fn digest_json(value: &Value) -> Result<String, ScheduleServiceError> {
  let mut digest = Sha256::new();
  digest.update(canonical_json(value)?.as_bytes());
  let mut encoded = String::with_capacity(64);
  for byte in digest.finalize() {
    write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
  }
  Ok(encoded)
}

fn canonicalize(value: &Value) -> Value {
  match value {
    Value::Object(object) => {
      let mut keys = object.keys().collect::<Vec<_>>();
      keys.sort_unstable();
      let mut canonical = Map::new();
      for key in keys {
        canonical.insert(key.clone(), canonicalize(&object[key]));
      }
      Value::Object(canonical)
    }
    Value::Array(values) => Value::Array(values.iter().map(canonicalize).collect()),
    _ => value.clone(),
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn mutation_semantics_preserves_legacy_digest_for_no_previous_success() {
    let owner = PrincipalKey::new("operator", "local", "realm-a", "ops-a").expect("owner");
    let capability = CapabilityProfileSnapshot::new(
      SNAPSHOT_VERSION,
      "capability-digest",
      json!({"name": "none", "tools": []}).to_string(),
    )
    .expect("capability");
    let target = DeliveryTargetSnapshot::new(
      "target-none",
      "none",
      "none",
      owner.tenant(),
      "none",
      "{}",
      SNAPSHOT_VERSION,
      "default-none-v1",
      "0000000000000000000000000000000000000000000000000000000000000001",
    )
    .expect("target");
    let schedule = ScheduleSpec::once(2_000_000_000);

    let legacy = mutation_semantics(
      "create",
      &owner,
      "Inspect durable work.",
      PreviousSuccessPolicy::None,
      &schedule,
      &capability,
      std::slice::from_ref(&target),
      Some("job-1"),
      Some(0),
    )
    .expect("legacy semantics");
    let latest_success = mutation_semantics(
      "create",
      &owner,
      "Inspect durable work.",
      PreviousSuccessPolicy::LatestSuccess,
      &schedule,
      &capability,
      &[target],
      Some("job-1"),
      Some(0),
    )
    .expect("latest-success semantics");

    assert_eq!(
      legacy["definition"],
      json!({"version": 1, "instruction": "Inspect durable work."})
    );
    assert_eq!(latest_success["definition"]["version"], 2);
    assert_eq!(
      latest_success["definition"]["previous_success"]["kind"],
      "latest_success"
    );
    assert_ne!(legacy, latest_success);
  }
}
