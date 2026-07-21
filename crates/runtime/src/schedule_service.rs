use std::fmt::{self, Write as _};

use async_trait::async_trait;
use codeoff_agent_contract::{
  ChannelTaskContext, ConversationKind, InvocationPrincipal, InvocationPrincipalRef,
  InvocationSource,
};
use codeoff_state::{
  CapabilityProfileSnapshot, CreateScheduledJob, DeliveryTargetSnapshot, PrincipalKey,
  ScheduleMutationAudit, ScheduleMutationIdempotency, ScheduleSpec, ScheduledJob,
  ScheduledJobDefinition, ScheduledJobListPage, ScheduledJobMutation, ScheduledJobStatus,
  StateError, StateStore, TransactionalMutationOutcome, UpdateScheduledJob,
};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

const DIGEST_ALGORITHM: &str = "sha256-canonical-json-v1";
const SNAPSHOT_VERSION: u32 = 1;

#[derive(Debug)]
pub enum ScheduleServiceError {
  Unauthorized,
  Forbidden,
  NotFound,
  InvalidRequest(String),
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
      Self::Forbidden => write!(
        formatter,
        "schedule is not owned by the authenticated actor"
      ),
      Self::NotFound => write!(formatter, "schedule was not found"),
      Self::InvalidRequest(reason) => write!(formatter, "invalid schedule request: {reason}"),
      Self::IdempotencyInProgress => write!(formatter, "schedule request is already in progress"),
      Self::IdempotencyConflict => {
        write!(formatter, "request id was reused with different semantics")
      }
      Self::State(error) => write!(formatter, "schedule state operation failed: {error}"),
    }
  }
}

impl std::error::Error for ScheduleServiceError {}

impl From<StateError> for ScheduleServiceError {
  fn from(error: StateError) -> Self {
    Self::State(error)
  }
}

#[derive(Debug, Clone)]
pub struct ScheduleInvocation {
  pub source: InvocationSource,
  pub principal: InvocationPrincipal,
  pub channel: Option<ChannelTaskContext>,
}

impl ScheduleInvocation {
  fn authorized_owner(&self) -> Result<PrincipalKey, ScheduleServiceError> {
    let InvocationPrincipalRef::ChannelActor {
      provider,
      workspace_id,
      actor_id,
    } = self.principal.as_ref()
    else {
      return Err(ScheduleServiceError::Unauthorized);
    };
    let InvocationSource::ChannelEvent {
      provider: source_provider,
      workspace_id: source_workspace,
      ..
    } = &self.source
    else {
      return Err(ScheduleServiceError::Unauthorized);
    };
    if source_provider != provider || source_workspace != workspace_id {
      return Err(ScheduleServiceError::Unauthorized);
    }
    PrincipalKey::new("channel_actor", provider, workspace_id, actor_id)
      .map_err(|error| ScheduleServiceError::InvalidRequest(error.to_string()))
  }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryTargetRequest {
  None,
  Origin,
  Channel {
    channel_id: String,
  },
  DirectMessage {
    user_id: String,
  },
  Thread {
    channel_id: String,
    thread_id: String,
  },
}

#[async_trait]
pub trait TargetResolver: Send + Sync {
  async fn resolve(
    &self,
    invocation: &ScheduleInvocation,
    owner: &PrincipalKey,
    target: &DeliveryTargetRequest,
  ) -> Result<Vec<DeliveryTargetSnapshot>, ScheduleServiceError>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultTargetResolver;

#[async_trait]
impl TargetResolver for DefaultTargetResolver {
  async fn resolve(
    &self,
    invocation: &ScheduleInvocation,
    owner: &PrincipalKey,
    target: &DeliveryTargetRequest,
  ) -> Result<Vec<DeliveryTargetSnapshot>, ScheduleServiceError> {
    let (provider, connector, tenant, kind, address) = match target {
      DeliveryTargetRequest::None => (
        "none".to_owned(),
        "none".to_owned(),
        owner.tenant().to_owned(),
        "none".to_owned(),
        json!({}),
      ),
      DeliveryTargetRequest::Origin => {
        let context = invocation.channel.as_ref().ok_or_else(|| {
          ScheduleServiceError::InvalidRequest("origin target requires channel context".to_owned())
        })?;
        ensure_context_matches_owner(context, owner)?;
        let (kind, address) = origin_address(context)?;
        (
          context.provider.clone(),
          "channel".to_owned(),
          context.workspace_id.clone(),
          kind,
          address,
        )
      }
      DeliveryTargetRequest::Channel { channel_id } => (
        owner.provider().to_owned(),
        "channel".to_owned(),
        owner.tenant().to_owned(),
        "channel".to_owned(),
        json!({"channel_id": bounded("channel_id", channel_id)?}),
      ),
      DeliveryTargetRequest::DirectMessage { user_id } => (
        owner.provider().to_owned(),
        "channel".to_owned(),
        owner.tenant().to_owned(),
        "direct_message".to_owned(),
        json!({"user_id": bounded("user_id", user_id)?}),
      ),
      DeliveryTargetRequest::Thread {
        channel_id,
        thread_id,
      } => (
        owner.provider().to_owned(),
        "channel".to_owned(),
        owner.tenant().to_owned(),
        "thread".to_owned(),
        json!({
          "channel_id": bounded("channel_id", channel_id)?,
          "thread_id": bounded("thread_id", thread_id)?,
        }),
      ),
    };
    let address_json = canonical_json(&address)?;
    let identity_digest = digest_json(&json!({
      "provider": provider,
      "connector": connector,
      "tenant": tenant,
      "kind": kind,
      "address": address,
    }))?;
    let target_id = format!("target_{}", &identity_digest[..32]);
    let resolver_digest = digest_json(&json!({"resolver": "default", "version": 1}))?;
    let snapshot = DeliveryTargetSnapshot::new(
      target_id,
      provider,
      connector,
      tenant,
      kind,
      address_json,
      SNAPSHOT_VERSION,
      resolver_digest,
      identity_digest,
    )
    .map_err(|error| ScheduleServiceError::InvalidRequest(error.to_string()))?;
    Ok(vec![snapshot])
  }
}

pub trait CapabilityRegistry: Send + Sync {
  fn resolve(
    &self,
    owner: &PrincipalKey,
    capability: &str,
  ) -> Result<CapabilityProfileSnapshot, ScheduleServiceError>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DefaultCapabilityRegistry;

impl CapabilityRegistry for DefaultCapabilityRegistry {
  fn resolve(
    &self,
    _owner: &PrincipalKey,
    capability: &str,
  ) -> Result<CapabilityProfileSnapshot, ScheduleServiceError> {
    if capability != "none" {
      return Err(ScheduleServiceError::InvalidRequest(format!(
        "unknown or unauthorized capability profile: {capability}"
      )));
    }
    let profile = json!({"name": "none", "tools": []});
    let canonical = canonical_json(&profile)?;
    CapabilityProfileSnapshot::new(SNAPSHOT_VERSION, digest_json(&profile)?, canonical)
      .map_err(|error| ScheduleServiceError::InvalidRequest(error.to_string()))
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
pub struct ScheduleService<R = DefaultTargetResolver, C = DefaultCapabilityRegistry> {
  state: StateStore,
  target_resolver: R,
  capability_registry: C,
}

impl ScheduleService {
  #[must_use]
  pub fn new(state: StateStore) -> Self {
    Self {
      state,
      target_resolver: DefaultTargetResolver,
      capability_registry: DefaultCapabilityRegistry,
    }
  }
}

impl<R, C> ScheduleService<R, C>
where
  R: TargetResolver,
  C: CapabilityRegistry,
{
  #[must_use]
  pub const fn with_components(
    state: StateStore,
    target_resolver: R,
    capability_registry: C,
  ) -> Self {
    Self {
      state,
      target_resolver,
      capability_registry,
    }
  }

  pub async fn create(
    &self,
    invocation: &ScheduleInvocation,
    request: CreateScheduleRequest,
  ) -> Result<Value, ScheduleServiceError> {
    validate_request_id(&request.request_id)?;
    validate_instruction(&request.instruction)?;
    let owner = invocation.authorized_owner()?;
    let job_id = format!(
      "job_{}",
      &digest_json(&json!({
        "owner": principal_json(&owner),
        "request_id": request.request_id,
      }))?[..32]
    );
    let capability = self
      .capability_registry
      .resolve(&owner, &request.capability)?;
    let targets = scope_targets(
      &job_id,
      self
        .target_resolver
        .resolve(invocation, &owner, &request.target)
        .await?,
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
    let owner = invocation.authorized_owner()?;
    let current = self.require_owned_job(&owner, &request.job_id).await?;
    let capability = self
      .capability_registry
      .resolve(&owner, &request.capability)?;
    let targets = scope_targets(
      &request.job_id,
      self
        .target_resolver
        .resolve(invocation, &owner, &request.target)
        .await?,
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
    let owner = invocation.authorized_owner()?;
    let job = self.require_owned_job(&owner, job_id).await?;
    job_json(&job)
  }

  pub async fn list(
    &self,
    invocation: &ScheduleInvocation,
    status: ScheduledJobStatus,
    cursor: Option<&str>,
    limit: u32,
  ) -> Result<ScheduledJobListPage, ScheduleServiceError> {
    let owner = invocation.authorized_owner()?;
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
    let owner = invocation.authorized_owner()?;
    self.require_owned_job(&owner, &request.job_id).await?;
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

  async fn require_owned_job(
    &self,
    owner: &PrincipalKey,
    job_id: &str,
  ) -> Result<ScheduledJob, ScheduleServiceError> {
    let job = self
      .state
      .get_scheduled_job(job_id)
      .await?
      .ok_or(ScheduleServiceError::NotFound)?;
    if &job.owner != owner {
      return Err(ScheduleServiceError::Forbidden);
    }
    Ok(job)
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
    let audit = ScheduleMutationAudit {
      audit_id: format!(
        "audit_{}",
        &digest_json(&json!({
          "principal": principal_json(&owner),
          "operation": operation,
          "request_id": request_id,
        }))?[..32]
      ),
      principal: owner.clone(),
      operation: operation.to_owned(),
      job_id,
      request_id: request_id.clone(),
      outcome: "applied".to_owned(),
      occurred_at: now,
    };
    let idempotency = ScheduleMutationIdempotency {
      principal: owner,
      request_id,
      digest_algorithm: DIGEST_ALGORITHM.to_owned(),
      request_digest,
      response_json,
    };
    match self
      .state
      .apply_idempotent_schedule_mutation_with_audit(&mutation, &idempotency, Some(&audit))
      .await?
    {
      TransactionalMutationOutcome::Applied(response)
      | TransactionalMutationOutcome::Replay(response) => {
        serde_json::from_str(&response).map_err(|error| {
          ScheduleServiceError::State(StateError::InvalidSchedulerState {
            reason: format!("invalid persisted schedule response: {error}"),
          })
        })
      }
      TransactionalMutationOutcome::InProgress => Err(ScheduleServiceError::IdempotencyInProgress),
      TransactionalMutationOutcome::Conflict => Err(ScheduleServiceError::IdempotencyConflict),
    }
  }
}

fn ensure_context_matches_owner(
  context: &ChannelTaskContext,
  owner: &PrincipalKey,
) -> Result<(), ScheduleServiceError> {
  if context.provider != owner.provider() || context.workspace_id != owner.tenant() {
    return Err(ScheduleServiceError::Unauthorized);
  }
  Ok(())
}

fn origin_address(context: &ChannelTaskContext) -> Result<(String, Value), ScheduleServiceError> {
  match context.conversation_kind {
    ConversationKind::Channel => Ok((
      "channel".to_owned(),
      json!({"channel_id": required("channel_id", context.channel_id.as_deref())?}),
    )),
    ConversationKind::DirectMessage => Ok((
      "direct_message".to_owned(),
      json!({"user_id": required("user_id", context.user_id.as_deref())?}),
    )),
    ConversationKind::Thread => Ok((
      "thread".to_owned(),
      json!({
        "channel_id": required("channel_id", context.channel_id.as_deref())?,
        "thread_id": required("thread_id", context.thread_id.as_deref())?,
      }),
    )),
  }
}

fn required<'a>(field: &str, value: Option<&'a str>) -> Result<&'a str, ScheduleServiceError> {
  bounded(field, value.unwrap_or_default())
}

fn bounded<'a>(field: &str, value: &'a str) -> Result<&'a str, ScheduleServiceError> {
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

fn scope_targets(
  job_id: &str,
  targets: Vec<DeliveryTargetSnapshot>,
) -> Result<Vec<DeliveryTargetSnapshot>, ScheduleServiceError> {
  targets
    .into_iter()
    .enumerate()
    .map(|(ordinal, target)| {
      let target_id = format!(
        "target_{}",
        &digest_json(&json!({
          "job_id": job_id,
          "ordinal": ordinal,
          "identity_digest": target.identity_digest(),
        }))?[..32]
      );
      target
        .with_target_id(target_id)
        .map_err(|error| ScheduleServiceError::InvalidRequest(error.to_string()))
    })
    .collect()
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

fn canonical_json(value: &Value) -> Result<String, ScheduleServiceError> {
  serde_json::to_string(&canonicalize(value))
    .map_err(|error| ScheduleServiceError::InvalidRequest(error.to_string()))
}

fn digest_json(value: &Value) -> Result<String, ScheduleServiceError> {
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
