use std::fmt::{self, Write as _};
use std::sync::Arc;
use std::time::Duration;

use codeoff_state::{
  CapabilityProfileSnapshot, CreateScheduledJob, DeliveryTargetSnapshot, PrincipalKey,
  ScheduleMutationAudit, ScheduleMutationIdempotency, ScheduleSpec, ScheduledJob,
  ScheduledJobDefinition, ScheduledJobListPage, ScheduledJobMutation, ScheduledJobStatus,
  StateError, StateStore, TransactionalMutationOutcome, UpdateScheduledJob,
};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

const DIGEST_ALGORITHM: &str = "sha256-canonical-json-v1";
pub(crate) const SNAPSHOT_VERSION: u32 = 1;

pub use crate::schedule_authorization::{
  AuthorizationPolicy, OwnerOnlyAuthorizationPolicy, ScheduleInvocation,
};
pub use crate::schedule_resolution::{
  CapabilityRegistry, CapabilityRequest, ChannelTargetVerifier, DefaultCapabilityRegistry,
  DefaultTargetResolver, DeliveryTargetRequest, TargetResolver, TargetResolverRegistry,
  TargetVerificationError, VerifiedSlackTargetResolver,
};
use crate::schedule_resolution::{
  scope_targets, validate_capability_snapshot, validate_resolved_targets,
};

#[derive(Debug)]
pub enum ScheduleServiceError {
  Unauthorized,
  NotVisible,
  InvalidRequest(String),
  ResolverUnavailable,
  ResolverNotAllowed,
  ResolverTimeout,
  CapabilityUnavailable,
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
      Self::ResolverNotAllowed => write!(formatter, "target is not allowed"),
      Self::ResolverTimeout => write!(formatter, "target resolver timed out"),
      Self::CapabilityUnavailable => write!(formatter, "capability is unavailable"),
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
      Self::ResolverNotAllowed => "resolver_not_allowed",
      Self::ResolverTimeout => "resolver_timeout",
      Self::CapabilityUnavailable => "capability_unavailable",
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
    json!({
      "code": self.code(),
      "retryable": self.retryable(),
      "message": self.to_string(),
      "details": {},
    })
  }
}

#[derive(Debug, Clone)]
pub struct CreateScheduleRequest {
  pub request_id: String,
  pub instruction: String,
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
  pub schedule: ScheduleSpec,
  pub target: DeliveryTargetRequest,
  pub capability: String,
  pub now: i64,
}

#[derive(Debug, Clone)]
pub struct LifecycleScheduleRequest {
  pub request_id: String,
  pub job_id: String,
  pub expected_generation: i64,
  pub now: i64,
}

#[derive(Clone)]
pub struct ScheduleService {
  state: StateStore,
  target_resolver: Arc<dyn TargetResolver>,
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
    target_resolver: Arc<dyn TargetResolver>,
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
    self.authorization.authorize_create(invocation)?;
    Ok(self.target_resolver.describe_supported_targets(invocation))
  }

  pub fn describe_authorized_capabilities(
    &self,
    invocation: &ScheduleInvocation,
  ) -> Result<Vec<&'static str>, ScheduleServiceError> {
    self.authorization.authorize_create(invocation)?;
    Ok(self.capability_registry.describe_authorized(invocation))
  }

  pub async fn record_error_audit(
    &self,
    invocation: &ScheduleInvocation,
    operation: &str,
    request_id: Option<&str>,
    job_id: Option<&str>,
    error: &ScheduleServiceError,
    now: i64,
  ) {
    let outcome = match error.code() {
      "unauthorized" | "not_found_or_not_visible" => "denied",
      "validation_failed" => "validation",
      "resolver_unavailable" | "resolver_not_allowed" | "resolver_timeout" => "resolver",
      "capability_unavailable" => "capability",
      _ => "storage",
    };
    let correlation_id = request_id
      .filter(|value| !value.is_empty() && value.len() <= 255)
      .unwrap_or("uncorrelated");
    let principal = invocation.canonical_actor().ok();
    let audit = ScheduleMutationAudit {
      audit_id: format!(
        "audit_error_{}",
        &digest_json(&json!({
          "principal": principal.as_ref().map(principal_json), "operation": operation,
          "correlation_id": correlation_id, "job_id": job_id, "code": error.code(),
        }))
        .unwrap_or_else(|_| "invalid".to_owned())[..32]
      ),
      principal,
      operation: operation.to_owned(),
      job_id: job_id.map(ToOwned::to_owned),
      request_id: correlation_id.to_owned(),
      outcome: outcome.to_owned(),
      decision: if outcome == "denied" { "deny" } else { "error" }.to_owned(),
      reason: Some(error.code().to_owned()),
      error_code: Some(error.code().to_owned()),
      old_generation: None,
      new_generation: None,
      resolver_provider: None,
      target_kind: None,
      resolver_version: None,
      resolver_digest: None,
      capability_version: None,
      capability_digest: None,
      idempotency_outcome: None,
      latency_ms: 0,
      correlation_id: correlation_id.to_owned(),
      occurred_at: now,
    };
    let _ = self.state.append_schedule_audit(&audit).await;
  }

  pub async fn create(
    &self,
    invocation: &ScheduleInvocation,
    request: CreateScheduleRequest,
  ) -> Result<Value, ScheduleServiceError> {
    validate_request_id(&request.request_id)?;
    validate_instruction(&request.instruction)?;
    let owner = self.authorization.authorize_create(invocation)?;
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
        &owner,
        &request.target,
        self
          .resolve_targets(invocation, &owner, &request.target)
          .await?,
      )?,
    )?;
    let semantic = mutation_semantics(
      "create",
      &owner,
      &request.instruction,
      &request.schedule,
      &capability,
      &targets,
      None,
      None,
    )?;
    let request_digest = digest_json(&semantic)?;
    let response = json!({"job_id": job_id, "status": "active", "generation": 0});
    let mutation = ScheduledJobMutation::Create(Box::new(CreateScheduledJob {
      job_id: job_id.clone(),
      schedule_id: format!("schedule_{job_id}"),
      definition: definition(&request.instruction)?,
      creator: owner.clone(),
      owner: owner.clone(),
      capability,
      targets,
      schedule: request.schedule,
      now: request.now,
    }));
    self
      .apply_mutation(
        mutation,
        owner,
        request.request_id,
        request_digest,
        response,
        request.now,
      )
      .await
  }

  pub async fn update(
    &self,
    invocation: &ScheduleInvocation,
    request: UpdateScheduleRequest,
  ) -> Result<Value, ScheduleServiceError> {
    validate_request_id(&request.request_id)?;
    validate_instruction(&request.instruction)?;
    let (owner, current) = self.authorize_job(invocation, &request.job_id).await?;
    let capability = self.resolve_capability(invocation, &owner, &request.capability)?;
    let targets = scope_targets(
      &request.job_id,
      validate_resolved_targets(
        &owner,
        &request.target,
        self
          .resolve_targets(invocation, &owner, &request.target)
          .await?,
      )?,
    )?;
    let semantic = mutation_semantics(
      "update",
      &owner,
      &request.instruction,
      &request.schedule,
      &capability,
      &targets,
      Some(&request.job_id),
      Some(request.expected_generation),
    )?;
    let response = json!({
      "job_id": request.job_id,
      "status": current.status.as_str(),
      "generation": next_generation(request.expected_generation)?,
    });
    let mutation = ScheduledJobMutation::Update(Box::new(UpdateScheduledJob {
      job_id: request.job_id,
      expected_generation: request.expected_generation,
      definition: definition(&request.instruction)?,
      capability,
      targets,
      schedule: request.schedule,
      now: request.now,
    }));
    self
      .apply_mutation(
        mutation,
        owner,
        request.request_id,
        digest_json(&semantic)?,
        response,
        request.now,
      )
      .await
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
  ) -> Result<Value, ScheduleServiceError> {
    let (_, job) = self.authorize_job(invocation, job_id).await?;
    job_json(&job)
  }

  pub async fn list(
    &self,
    invocation: &ScheduleInvocation,
    status: ScheduledJobStatus,
    cursor: Option<&str>,
    limit: u32,
  ) -> Result<ScheduledJobListPage, ScheduleServiceError> {
    let owner = self.authorization.authorize_create(invocation)?;
    self
      .state
      .list_scheduled_jobs_by_owner(&owner, status, cursor, limit)
      .await
      .map_err(Into::into)
  }

  async fn lifecycle(
    &self,
    invocation: &ScheduleInvocation,
    request: LifecycleScheduleRequest,
    operation: &'static str,
  ) -> Result<Value, ScheduleServiceError> {
    validate_request_id(&request.request_id)?;
    let (owner, _) = self.authorize_job(invocation, &request.job_id).await?;
    let semantic = json!({
      "operation": operation,
      "owner": principal_json(&owner),
      "job_id": request.job_id,
      "expected_generation": request.expected_generation,
    });
    let status = match operation {
      "pause" => "paused",
      "resume" => "active",
      "delete" => "deleted",
      _ => unreachable!("bounded lifecycle operation"),
    };
    let response = json!({
      "job_id": request.job_id,
      "status": status,
      "generation": next_generation(request.expected_generation)?,
    });
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
    self
      .apply_mutation(
        mutation,
        owner,
        request.request_id,
        digest_json(&semantic)?,
        response,
        request.now,
      )
      .await
  }

  async fn authorize_job(
    &self,
    invocation: &ScheduleInvocation,
    job_id: &str,
  ) -> Result<(PrincipalKey, ScheduledJob), ScheduleServiceError> {
    let job = self.state.get_scheduled_job(job_id).await?;
    self.authorization.authorize_existing(invocation, job)
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
    let snapshot = self.capability_registry.resolve(
      invocation,
      owner,
      &CapabilityRequest {
        name: name.to_owned(),
      },
    )?;
    validate_capability_snapshot(name, snapshot)
  }

  async fn resolve_targets(
    &self,
    invocation: &ScheduleInvocation,
    owner: &PrincipalKey,
    target: &DeliveryTargetRequest,
  ) -> Result<Vec<DeliveryTargetSnapshot>, ScheduleServiceError> {
    tokio::time::timeout(
      self.resolver_timeout,
      self.target_resolver.resolve(invocation, owner, target),
    )
    .await
    .map_err(|_| ScheduleServiceError::ResolverTimeout)?
  }

  async fn apply_mutation(
    &self,
    mutation: ScheduledJobMutation,
    owner: PrincipalKey,
    request_id: String,
    request_digest: String,
    response: Value,
    now: i64,
  ) -> Result<Value, ScheduleServiceError> {
    let response_json = canonical_json(&response)?;
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
    let audit = ScheduleMutationAudit {
      audit_id: format!(
        "audit_{}",
        &digest_json(&json!({
          "principal": principal_json(&owner),
          "operation": operation,
          "request_id": request_id,
        }))?[..32]
      ),
      principal: Some(owner.clone()),
      operation: operation.to_owned(),
      job_id: Some(job_id),
      request_id: request_id.clone(),
      outcome: "applied".to_owned(),
      decision: "allow".to_owned(),
      reason: None,
      error_code: None,
      old_generation,
      new_generation,
      resolver_provider,
      target_kind,
      resolver_version,
      resolver_digest,
      capability_version,
      capability_digest,
      idempotency_outcome: Some("applied".to_owned()),
      latency_ms: 0,
      correlation_id: request_id.clone(),
      occurred_at: now,
    };
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
        let service_error = ScheduleServiceError::State(error);
        let mut failed = audit_for_outcome(&audit, "storage", "error", Some(service_error.code()));
        failed.idempotency_outcome = None;
        let _ = self.state.append_schedule_audit(&failed).await;
        Err(service_error)
      }
      Ok(TransactionalMutationOutcome::Applied(response)) => serde_json::from_str(&response)
        .map_err(|error| {
          ScheduleServiceError::State(StateError::InvalidSchedulerState {
            reason: format!("invalid persisted schedule response: {error}"),
          })
        }),
      Ok(TransactionalMutationOutcome::Replay(response)) => {
        let replay = audit_for_outcome(&audit, "replay", "allow", None);
        let _ = self.state.append_schedule_audit(&replay).await;
        serde_json::from_str(&response).map_err(|_| {
          ScheduleServiceError::InvalidRequest("invalid persisted response".to_owned())
        })
      }
      Ok(TransactionalMutationOutcome::InProgress) => {
        let pending = audit_for_outcome(
          &audit,
          "in_progress",
          "error",
          Some("idempotency_in_progress"),
        );
        let _ = self.state.append_schedule_audit(&pending).await;
        Err(ScheduleServiceError::IdempotencyInProgress)
      }
      Ok(TransactionalMutationOutcome::Conflict) => {
        let conflict = audit_for_outcome(&audit, "conflict", "deny", Some("idempotency_conflict"));
        let _ = self.state.append_schedule_audit(&conflict).await;
        Err(ScheduleServiceError::IdempotencyConflict)
      }
    }
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

fn definition(instruction: &str) -> Result<ScheduledJobDefinition, ScheduleServiceError> {
  ScheduledJobDefinition::new(
    SNAPSHOT_VERSION,
    canonical_json(&json!({"instruction": instruction}))?,
  )
  .map_err(|error| ScheduleServiceError::InvalidRequest(error.to_string()))
}

#[allow(clippy::too_many_arguments)]
fn mutation_semantics(
  operation: &str,
  owner: &PrincipalKey,
  instruction: &str,
  schedule: &ScheduleSpec,
  capability: &CapabilityProfileSnapshot,
  targets: &[DeliveryTargetSnapshot],
  job_id: Option<&str>,
  expected_generation: Option<i64>,
) -> Result<Value, ScheduleServiceError> {
  Ok(json!({
    "operation": operation,
    "owner": principal_json(owner),
    "job_id": job_id,
    "expected_generation": expected_generation,
    "definition": {"version": SNAPSHOT_VERSION, "instruction": instruction},
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

fn audit_for_outcome(
  audit: &ScheduleMutationAudit,
  outcome: &str,
  decision: &str,
  error_code: Option<&str>,
) -> ScheduleMutationAudit {
  let mut derived = audit.clone();
  derived.audit_id = format!("{}-{outcome}", audit.audit_id);
  outcome.clone_into(&mut derived.outcome);
  decision.clone_into(&mut derived.decision);
  derived.error_code = error_code.map(ToOwned::to_owned);
  derived.idempotency_outcome = Some(outcome.to_owned());
  derived
}

fn job_json(job: &ScheduledJob) -> Result<Value, ScheduleServiceError> {
  Ok(json!({
    "job_id": job.job_id,
    "status": job.status.as_str(),
    "generation": job.generation,
    "definition": serde_json::from_str::<Value>(job.definition.canonical_json()).map_err(|error| ScheduleServiceError::InvalidRequest(error.to_string()))?,
    "schedule": schedule_json(&job.schedule),
    "next_run_at": job.next_run_at,
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
  use super::{ScheduleMutationAudit, audit_for_outcome};

  #[test]
  fn test_in_progress_audit_uses_stable_sanitized_outcome() {
    let base = ScheduleMutationAudit {
      audit_id: "audit".to_owned(),
      principal: None,
      operation: "create".to_owned(),
      job_id: Some("job".to_owned()),
      request_id: "request".to_owned(),
      outcome: "applied".to_owned(),
      decision: "allow".to_owned(),
      reason: None,
      error_code: None,
      old_generation: None,
      new_generation: Some(0),
      resolver_provider: None,
      target_kind: None,
      resolver_version: None,
      resolver_digest: None,
      capability_version: None,
      capability_digest: None,
      idempotency_outcome: Some("applied".to_owned()),
      latency_ms: 0,
      correlation_id: "request".to_owned(),
      occurred_at: 1,
    };

    let audit = audit_for_outcome(
      &base,
      "in_progress",
      "error",
      Some("idempotency_in_progress"),
    );

    assert_eq!(audit.outcome, "in_progress");
    assert_eq!(audit.decision, "error");
    assert_eq!(audit.error_code.as_deref(), Some("idempotency_in_progress"));
    assert_eq!(audit.idempotency_outcome.as_deref(), Some("in_progress"));
  }
}
