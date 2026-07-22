use std::env;
use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use chrono::DateTime;
use codeoff_agent_contract::{InvocationPrincipal, InvocationSource};
use codeoff_config::SchedulerRuntimeConfig;
use codeoff_runtime::schedule_service::{
  ConfiguredOperatorIdentityPolicy, CreateScheduleRequest, DefaultCapabilityRegistry,
  DeliveryTargetRequest, LifecycleScheduleRequest, OperatorAuthorizationPolicy,
  PreviousSuccessPolicy, ScheduleInvocation, ScheduleService, ScheduleServiceError,
  TargetResolverRegistry, UpdateScheduleRequest,
};
use codeoff_state::{
  PrincipalKey, ScheduleSpec, ScheduledDeliveryState, ScheduledDeliveryUnknownAction,
  ScheduledJobStatus, ScheduledRunState, SchedulerOperatorRequest, StateStore,
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::command::{
  SchedulerCommand, SchedulerDeliveriesCommand, SchedulerDeliveryDisposition,
  SchedulerDeliveryStatus, SchedulerFileFormat, SchedulerRetryRunState, SchedulerRunStatus,
  SchedulerRunsCommand,
};

const SCHEDULER_REQUEST_SCHEMA_VERSION: u32 = 1;
const MAX_SCHEDULER_REQUEST_BYTES: u64 = 128 * 1024;
const OPERATOR_ID_ENV: &str = "CODEOFF_SCHEDULER_OPERATOR_ID";
const OPERATOR_REALM_ENV: &str = "CODEOFF_SCHEDULER_OPERATOR_REALM";
const MAX_OPERATOR_FILE_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SchedulerMutationInput {
  schema_version: u32,
  request_id: String,
  instruction: String,
  schedule: SchedulerScheduleInput,
  capability: String,
  previous_success: PreviousSuccessPolicyInput,
  delivery: DeliveryInput,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum SchedulerScheduleInput {
  Once {
    at: String,
  },
  Interval {
    anchor: String,
    every_seconds: i64,
  },
  Cron {
    expression: String,
    timezone: String,
  },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum PreviousSuccessPolicyInput {
  None,
  LatestSuccess,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum DeliveryInput {
  None,
  SlackChannel {
    channel_id: String,
  },
  SlackDirectMessage {
    user_id: String,
  },
  SlackThread {
    channel_id: String,
    thread_ts: String,
  },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ValidatedSchedulerMutation {
  pub(crate) request_id: String,
  pub(crate) instruction: String,
  pub(crate) schedule: ScheduleSpec,
  pub(crate) capability: String,
  pub(crate) previous_success: PreviousSuccessPolicy,
  pub(crate) target: DeliveryTargetRequest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SchedulerInputError {
  MissingStdinFormat,
  UnsupportedFileFormat,
  ReadFailed,
  RequestTooLarge,
  InvalidDocument,
  UnsupportedSchemaVersion,
  InvalidRequest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SchedulerOperatorConfig {
  service_identity: String,
  realm: String,
  subject: String,
}

impl SchedulerOperatorConfig {
  pub(crate) fn from_environment() -> Result<Self, ScheduleServiceError> {
    let service_identity =
      env::var(OPERATOR_ID_ENV).map_err(|_| ScheduleServiceError::Unauthorized)?;
    let realm = env::var(OPERATOR_REALM_ENV).map_err(|_| ScheduleServiceError::Unauthorized)?;
    Self::new(service_identity, realm)
  }

  fn new(service_identity: String, realm: String) -> Result<Self, ScheduleServiceError> {
    let policy =
      ConfiguredOperatorIdentityPolicy::new(&service_identity, &realm, &service_identity)?;
    drop(policy);
    Ok(Self {
      subject: service_identity.clone(),
      service_identity,
      realm,
    })
  }

  pub(crate) fn diagnostic() -> Self {
    Self {
      service_identity: "scheduler-diagnostic".to_owned(),
      realm: "local".to_owned(),
      subject: "scheduler-diagnostic".to_owned(),
    }
  }
}

#[derive(Debug)]
pub(crate) struct SchedulerCommandError(Value);

impl SchedulerCommandError {
  pub(crate) fn service(error: &ScheduleServiceError) -> Self {
    Self(error.structured_json())
  }
}

impl fmt::Display for SchedulerCommandError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(formatter, "{}", self.0)
  }
}

impl std::error::Error for SchedulerCommandError {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SchedulerReasonFile {
  schema_version: u32,
  reason_code: String,
  reason: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SchedulerEvidenceFile {
  schema_version: u32,
  evidence: Value,
  #[serde(default)]
  provider_receipt: Option<Value>,
}

pub(crate) trait SchedulerAuthorityVerifier: Send + Sync {
  fn verify(
    &self,
    authority: &[u8],
    action_digest: &str,
  ) -> Result<PrincipalKey, SchedulerCommandError>;
}

#[derive(Debug, Default)]
pub(crate) struct UnavailableSchedulerAuthorityVerifier;

impl SchedulerAuthorityVerifier for UnavailableSchedulerAuthorityVerifier {
  fn verify(
    &self,
    _authority: &[u8],
    _action_digest: &str,
  ) -> Result<PrincipalKey, SchedulerCommandError> {
    Err(command_error(
      "authority_verifier_unavailable",
      "scheduler mutation authority verifier is not available",
    ))
  }
}

#[cfg(test)]
pub(crate) async fn execute_scheduler_command(
  command: SchedulerCommand,
  state: StateStore,
  operator: SchedulerOperatorConfig,
  now: i64,
) -> Result<Value, SchedulerCommandError> {
  execute_scheduler_command_with_resolvers(
    command,
    state,
    operator,
    std::sync::Arc::new(TargetResolverRegistry::with_defaults()),
    now,
  )
  .await
}

#[allow(clippy::too_many_lines)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) async fn execute_scheduler_command_with_resolvers(
  command: SchedulerCommand,
  state: StateStore,
  operator: SchedulerOperatorConfig,
  target_resolvers: std::sync::Arc<TargetResolverRegistry>,
  now: i64,
) -> Result<Value, SchedulerCommandError> {
  execute_scheduler_command_with_policy_and_verifier(
    command,
    state,
    operator,
    target_resolvers,
    &SchedulerRuntimeConfig::default(),
    &UnavailableSchedulerAuthorityVerifier,
    now,
  )
  .await
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(crate) async fn execute_scheduler_command_with_policy_and_verifier(
  command: SchedulerCommand,
  state: StateStore,
  operator: SchedulerOperatorConfig,
  target_resolvers: std::sync::Arc<TargetResolverRegistry>,
  policy: &SchedulerRuntimeConfig,
  authority_verifier: &dyn SchedulerAuthorityVerifier,
  now: i64,
) -> Result<Value, SchedulerCommandError> {
  if !command.uses_legacy_service() {
    return execute_scheduler_operator_command(command, &state, policy, authority_verifier, now)
      .await;
  }
  let service = build_scheduler_service(state, &operator, target_resolvers)
    .map_err(|error| SchedulerCommandError::service(&error))?;
  let result = match command {
    SchedulerCommand::Create { file, format } => {
      let request = read_or_audit_input(&service, "create", &operator, &file, format, now).await?;
      let invocation = trusted_operator_invocation(&operator, &request.request_id);
      service
        .create(
          &invocation,
          CreateScheduleRequest {
            request_id: request.request_id,
            instruction: request.instruction,
            previous_success: request.previous_success,
            schedule: request.schedule,
            target: request.target,
            capability: request.capability,
            now,
          },
        )
        .await
    }
    SchedulerCommand::Get { job_id } => {
      let invocation = trusted_operator_invocation(&operator, &job_id);
      service.get(&invocation, &job_id, now).await
    }
    SchedulerCommand::List {
      status,
      cursor,
      limit,
    } => {
      let invocation = trusted_operator_invocation(&operator, "list");
      match validate_list_request(
        &service,
        &invocation,
        &status,
        cursor.as_deref(),
        limit,
        now,
      )
      .await
      {
        Ok(status) => {
          service
            .list(&invocation, status, cursor.as_deref(), limit, now)
            .await
        }
        Err(error) => Err(error),
      }
    }
    SchedulerCommand::Update {
      job_id,
      file,
      format,
      generation,
    } => {
      let request = read_or_audit_input(&service, "update", &operator, &file, format, now).await?;
      let invocation = trusted_operator_invocation(&operator, &request.request_id);
      service
        .update(
          &invocation,
          UpdateScheduleRequest {
            request_id: request.request_id,
            job_id,
            expected_generation: generation,
            instruction: request.instruction,
            previous_success: request.previous_success,
            schedule: request.schedule,
            target: request.target,
            capability: request.capability,
            now,
          },
        )
        .await
    }
    SchedulerCommand::Pause {
      job_id,
      generation,
      request_id,
    } => {
      lifecycle(
        &service, &operator, "pause", request_id, job_id, generation, now,
      )
      .await
    }
    SchedulerCommand::Resume {
      job_id,
      generation,
      request_id,
    } => {
      lifecycle(
        &service, &operator, "resume", request_id, job_id, generation, now,
      )
      .await
    }
    SchedulerCommand::Delete {
      job_id,
      generation,
      request_id,
    } => {
      lifecycle(
        &service, &operator, "delete", request_id, job_id, generation, now,
      )
      .await
    }
    SchedulerCommand::Status { .. }
    | SchedulerCommand::Runs { .. }
    | SchedulerCommand::Deliveries { .. }
    | SchedulerCommand::Reconcile { .. }
    | SchedulerCommand::RetryRun { .. }
    | SchedulerCommand::RetryDelivery { .. }
    | SchedulerCommand::ResolveDeliveryUnknown { .. } => {
      unreachable!("operator command handled before schedule service construction")
    }
  }
  .map_err(|error| SchedulerCommandError::service(&error))?;
  Ok(sanitize_output(result))
}

#[allow(clippy::too_many_lines)]
async fn execute_scheduler_operator_command(
  command: SchedulerCommand,
  state: &StateStore,
  policy: &SchedulerRuntimeConfig,
  authority_verifier: &dyn SchedulerAuthorityVerifier,
  now: i64,
) -> Result<Value, SchedulerCommandError> {
  match command {
    SchedulerCommand::Status { .. } => Ok(success(json!({
      "scheduler": "reachable",
      "enabled": policy.enabled,
      "run_claims_enabled": policy.run_claims_enabled,
      "delivery_claims_enabled": policy.delivery_claims_enabled,
      "recovery_batch_limit": policy.recovery_batch_limit,
      "materialization_batch_limit": policy.materialization_batch_limit,
    }))),
    SchedulerCommand::Runs { command } => match command {
      SchedulerRunsCommand::List { status, limit, .. } => {
        validate_operator_limit(limit)?;
        let runs = state
          .list_scheduled_run_operator_projections_by_state(
            None,
            status.map(run_status_state),
            limit,
          )
          .await
          .map_err(state_command_error)?;
        let items = runs
          .into_iter()
          .map(run_projection_json)
          .collect::<Vec<_>>();
        Ok(success(json!({"items": items, "limit": limit})))
      }
      SchedulerRunsCommand::Show { run_id, .. } => {
        let run = state
          .get_scheduled_run_operator_projection(&run_id)
          .await
          .map_err(state_command_error)?
          .ok_or_else(|| command_error("not_found", "scheduled run was not found"))?;
        Ok(success(run_projection_json(run)))
      }
    },
    SchedulerCommand::Deliveries { command } => match command {
      SchedulerDeliveriesCommand::List { status, limit, .. } => {
        validate_operator_limit(limit)?;
        let deliveries = state
          .list_scheduled_delivery_operator_projections_by_state(
            None,
            status.map(delivery_status_state),
            limit,
          )
          .await
          .map_err(state_command_error)?;
        let items = deliveries
          .into_iter()
          .map(delivery_projection_json)
          .collect::<Vec<_>>();
        Ok(success(json!({"items": items, "limit": limit})))
      }
      SchedulerDeliveriesCommand::Show { delivery_id, .. } => {
        let delivery = state
          .get_scheduled_delivery_operator_projection(&delivery_id)
          .await
          .map_err(state_command_error)?
          .ok_or_else(|| command_error("not_found", "scheduled delivery was not found"))?;
        Ok(success(delivery_projection_json(delivery)))
      }
    },
    SchedulerCommand::Reconcile {
      dry_run,
      apply,
      limit,
      authority_file,
      ..
    } => {
      if dry_run == apply {
        return Err(command_error(
          "invalid_request",
          "exactly one of --dry-run or --apply is required",
        ));
      }
      validate_operator_limit(limit)?;
      let limit = limit.min(policy.recovery_batch_limit).min(100);
      let run_candidates = state
        .list_scheduled_run_reconcile_candidates(now, limit)
        .await
        .map_err(state_command_error)?;
      let deliveries = state
        .list_scheduled_delivery_reconcile_candidates(now, limit)
        .await
        .map_err(state_command_error)?;
      let next_attempt_at = now
        .checked_add(i64::from(policy.retry_delay_seconds))
        .ok_or_else(|| command_error("invalid_policy", "scheduler retry timing overflowed"))?;
      let run_plan = run_candidates
        .iter()
        .map(|candidate| {
          serde_json::from_str::<Value>(&candidate.canonical_plan_snapshot())
            .expect("state returns canonical reconcile snapshots")
        })
        .collect::<Vec<_>>();
      let delivery_plan = deliveries
        .iter()
        .map(|delivery| {
          json!({
            "attempt": delivery.attempt,
            "delivery_id": delivery.delivery_id,
            "fence": delivery.fence,
            "lease_expires_at": delivery.lease_expires_at,
            "state": delivery.state.as_str(),
          })
        })
        .collect::<Vec<_>>();
      let plan = json!({
        "delivery_candidates": delivery_plan,
        "limit": limit,
        "max_attempts": policy.max_attempts,
        "next_attempt_at": next_attempt_at,
        "now": now,
        "run_candidates": run_plan,
        "schema_version": 1,
      });
      let plan_digest = sha256_hex(plan.to_string().as_bytes());
      if !apply {
        return Ok(success(json!({"plan": plan, "plan_digest": plan_digest})));
      }
      let authority_file = authority_file.ok_or_else(|| {
        command_error(
          "invalid_request",
          "--authority-file is required with --apply",
        )
      })?;
      let authority = read_bounded_file(&authority_file)?;
      let _principal = authority_verifier.verify(&authority, &plan_digest)?;
      let mut run_results = Vec::with_capacity(run_candidates.len());
      for candidate in &run_candidates {
        let outcome = state
          .reconcile_scheduled_run_candidate(
            candidate,
            i64::from(policy.max_attempts),
            next_attempt_at,
            now,
          )
          .await;
        run_results.push(json!({
          "run_id": candidate.run_id(),
          "outcome": reconcile_run_outcome(outcome),
        }));
      }
      let mut delivery_results = Vec::with_capacity(deliveries.len());
      for delivery in &deliveries {
        let outcome = state
          .reconcile_expired_scheduled_delivery(
            &delivery.delivery_id,
            delivery.state,
            delivery.attempt,
            delivery.fence,
            delivery.lease_expires_at.expect("filtered expiry"),
            now,
          )
          .await;
        delivery_results.push(json!({
          "delivery_id": delivery.delivery_id,
          "outcome": reconcile_delivery_outcome(outcome),
        }));
      }
      Ok(success(json!({
        "delivery_results": delivery_results,
        "plan_digest": plan_digest,
        "run_results": run_results,
      })))
    }
    SchedulerCommand::RetryRun {
      run_id,
      expected_state,
      request_id,
      expected_attempt,
      expected_fence,
      reason_file,
      authority_file,
    } => {
      reject_ambiguous_stdin(&[&reason_file, &authority_file])?;
      let reason = read_reason_file(&reason_file)?;
      let authority = read_bounded_file(&authority_file)?;
      let expected_state = retry_run_state(expected_state);
      let next_attempt_at = now
        .checked_add(i64::from(policy.retry_delay_seconds))
        .ok_or_else(|| command_error("invalid_policy", "scheduler retry timing overflowed"))?;
      let provisional = SchedulerOperatorRequest::for_run_retry(
        provisional_principal(),
        &request_id,
        &run_id,
        expected_attempt,
        expected_fence,
        expected_state,
        &reason.canonical_json,
        &reason.digest,
        next_attempt_at,
        now,
      )
      .map_err(value_command_error)?;
      let principal = authority_verifier.verify(&authority, &provisional.request_digest)?;
      let request = SchedulerOperatorRequest::for_run_retry(
        principal,
        request_id,
        &run_id,
        expected_attempt,
        expected_fence,
        expected_state,
        &reason.canonical_json,
        &reason.digest,
        next_attempt_at,
        now,
      )
      .map_err(value_command_error)?;
      let outcome = state
        .operator_retry_scheduled_run(
          &request,
          &run_id,
          expected_attempt,
          expected_fence,
          &reason.canonical_json,
          &reason.digest,
          next_attempt_at,
        )
        .await
        .map_err(state_command_error)?;
      Ok(success(json!({
        "outcome": format!("{outcome:?}").to_lowercase(),
        "reason_code": reason.reason_code,
        "reason_digest": reason.digest,
        "request_digest": request.request_digest,
        "run_id": run_id,
      })))
    }
    SchedulerCommand::RetryDelivery {
      delivery_id,
      request_id,
      expected_attempt,
      expected_fence,
      reason_file,
      authority_file,
    } => {
      reject_ambiguous_stdin(&[&reason_file, &authority_file])?;
      let reason = read_reason_file(&reason_file)?;
      let authority = read_bounded_file(&authority_file)?;
      let provisional = SchedulerOperatorRequest::for_delivery_retry(
        provisional_principal(),
        &request_id,
        &delivery_id,
        expected_attempt,
        expected_fence,
        &reason.canonical_json,
        &reason.digest,
        now,
      )
      .map_err(value_command_error)?;
      let principal = authority_verifier.verify(&authority, &provisional.request_digest)?;
      let request = SchedulerOperatorRequest::for_delivery_retry(
        principal,
        request_id,
        &delivery_id,
        expected_attempt,
        expected_fence,
        &reason.canonical_json,
        &reason.digest,
        now,
      )
      .map_err(value_command_error)?;
      let outcome = state
        .operator_retry_scheduled_delivery(
          &request,
          &delivery_id,
          expected_attempt,
          expected_fence,
          &reason.canonical_json,
          &reason.digest,
        )
        .await
        .map_err(state_command_error)?;
      Ok(success(json!({
        "delivery_id": delivery_id,
        "outcome": format!("{outcome:?}").to_lowercase(),
        "reason_code": reason.reason_code,
        "reason_digest": reason.digest,
        "request_digest": request.request_digest,
      })))
    }
    SchedulerCommand::ResolveDeliveryUnknown {
      delivery_id,
      disposition,
      request_id,
      expected_attempt,
      expected_fence,
      evidence_file,
      reason_file,
      acknowledge_duplicate_risk,
      authority_file,
    } => {
      let mut input_paths: Vec<&Path> = vec![&evidence_file, &authority_file];
      if let Some(reason_file) = &reason_file {
        input_paths.push(reason_file);
      }
      reject_ambiguous_stdin(&input_paths)?;
      let reason = reason_file.as_deref().map(read_reason_file).transpose()?;
      let evidence = read_evidence_file(
        &evidence_file,
        disposition,
        reason.as_ref(),
        acknowledge_duplicate_risk,
      )?;
      let authority = read_bounded_file(&authority_file)?;
      let provisional = SchedulerOperatorRequest::for_delivery_action(
        provisional_principal(),
        &request_id,
        &delivery_id,
        expected_attempt,
        expected_fence,
        &evidence.action,
        now,
      )
      .map_err(value_command_error)?;
      let principal = authority_verifier.verify(&authority, &provisional.request_digest)?;
      let request = SchedulerOperatorRequest::for_delivery_action(
        principal,
        request_id,
        &delivery_id,
        expected_attempt,
        expected_fence,
        &evidence.action,
        now,
      )
      .map_err(value_command_error)?;
      let outcome = state
        .operator_act_on_unknown_delivery(
          &request,
          &delivery_id,
          expected_attempt,
          expected_fence,
          &evidence.action,
        )
        .await
        .map_err(state_command_error)?;
      Ok(success(json!({
        "delivery_id": delivery_id,
        "evidence_digest": evidence.digest,
        "outcome": format!("{outcome:?}").to_lowercase(),
        "request_digest": request.request_digest,
      })))
    }
    SchedulerCommand::Create { .. }
    | SchedulerCommand::Get { .. }
    | SchedulerCommand::List { .. }
    | SchedulerCommand::Update { .. }
    | SchedulerCommand::Pause { .. }
    | SchedulerCommand::Resume { .. }
    | SchedulerCommand::Delete { .. } => unreachable!("legacy command routed separately"),
  }
}

struct ValidatedReason {
  canonical_json: String,
  digest: String,
  reason_code: String,
}

struct ValidatedEvidence {
  action: ScheduledDeliveryUnknownAction,
  digest: String,
}

fn success(data: Value) -> Value {
  json!({"data": data, "ok": true, "schema_version": 1})
}

pub(crate) fn render_scheduler_human(output: &Value) -> String {
  let mut lines = vec!["status: ok".to_owned()];
  append_human_value(&mut lines, "", &output["data"]);
  lines.join("\n")
}

fn append_human_value(lines: &mut Vec<String>, prefix: &str, value: &Value) {
  match value {
    Value::Object(object) if object.is_empty() => lines.push(format!("{prefix}: none")),
    Value::Object(object) => {
      for (key, value) in object {
        let name = if prefix.is_empty() {
          key.clone()
        } else {
          format!("{prefix}.{key}")
        };
        append_human_value(lines, &name, value);
      }
    }
    Value::Array(array) if array.is_empty() => lines.push(format!("{prefix}: none")),
    Value::Array(array) => {
      for (index, value) in array.iter().enumerate() {
        append_human_value(lines, &format!("{prefix}[{index}]"), value);
      }
    }
    Value::String(value) => lines.push(format!(
      "{prefix}: {}",
      serde_json::to_string(value).expect("JSON strings are serializable")
    )),
    Value::Null => lines.push(format!("{prefix}: none")),
    Value::Bool(_) | Value::Number(_) => lines.push(format!("{prefix}: {value}")),
  }
}

fn command_error(code: &str, message: &str) -> SchedulerCommandError {
  SchedulerCommandError(json!({
    "error": {"code": code, "message": message},
    "ok": false,
    "schema_version": 1,
  }))
}

fn state_command_error(_error: codeoff_state::StateError) -> SchedulerCommandError {
  command_error("state_error", "scheduler state operation failed")
}

fn value_command_error(_error: codeoff_state::StateValueError) -> SchedulerCommandError {
  command_error("invalid_request", "scheduler operator request is invalid")
}

fn validate_operator_limit(limit: u16) -> Result<(), SchedulerCommandError> {
  if limit == 0 || limit > 100 {
    return Err(command_error(
      "invalid_request",
      "operator limit must be between 1 and 100",
    ));
  }
  Ok(())
}

const fn run_status_state(status: SchedulerRunStatus) -> ScheduledRunState {
  match status {
    SchedulerRunStatus::Pending => ScheduledRunState::Pending,
    SchedulerRunStatus::Leased => ScheduledRunState::Leased,
    SchedulerRunStatus::Executing => ScheduledRunState::Executing,
    SchedulerRunStatus::Succeeded => ScheduledRunState::Succeeded,
    SchedulerRunStatus::Failed => ScheduledRunState::Failed,
    SchedulerRunStatus::TimedOut => ScheduledRunState::TimedOut,
    SchedulerRunStatus::Cancelled => ScheduledRunState::Cancelled,
    SchedulerRunStatus::OutcomeUnknown => ScheduledRunState::OutcomeUnknown,
  }
}

const fn retry_run_state(status: SchedulerRetryRunState) -> ScheduledRunState {
  match status {
    SchedulerRetryRunState::Failed => ScheduledRunState::Failed,
    SchedulerRetryRunState::TimedOut => ScheduledRunState::TimedOut,
    SchedulerRetryRunState::Cancelled => ScheduledRunState::Cancelled,
  }
}

const fn delivery_status_state(status: SchedulerDeliveryStatus) -> ScheduledDeliveryState {
  match status {
    SchedulerDeliveryStatus::Pending => ScheduledDeliveryState::Pending,
    SchedulerDeliveryStatus::Sending => ScheduledDeliveryState::Sending,
    SchedulerDeliveryStatus::Delivered => ScheduledDeliveryState::Delivered,
    SchedulerDeliveryStatus::FailedRetryable => ScheduledDeliveryState::FailedRetryable,
    SchedulerDeliveryStatus::FailedTerminal => ScheduledDeliveryState::FailedTerminal,
    SchedulerDeliveryStatus::DeliveryUnknown => ScheduledDeliveryState::DeliveryUnknown,
    SchedulerDeliveryStatus::SkippedNone => ScheduledDeliveryState::SkippedNone,
    SchedulerDeliveryStatus::SkippedUnchanged => ScheduledDeliveryState::SkippedUnchanged,
  }
}

fn provisional_principal() -> PrincipalKey {
  PrincipalKey::new("service", "codeoff", "local", "authority-verifier")
    .expect("static provisional principal")
}

fn sha256_hex(bytes: &[u8]) -> String {
  let mut hasher = Sha256::new();
  hasher.update(bytes);
  format!("{:x}", hasher.finalize())
}

fn read_bounded_file(path: &Path) -> Result<Vec<u8>, SchedulerCommandError> {
  let mut bytes = Vec::new();
  if path == Path::new("-") {
    io::stdin()
      .lock()
      .take(MAX_OPERATOR_FILE_BYTES + 1)
      .read_to_end(&mut bytes)
      .map_err(|_| command_error("read_failed", "failed to read operator input"))?;
  } else {
    File::open(path)
      .map_err(|_| command_error("read_failed", "failed to read operator input"))?
      .take(MAX_OPERATOR_FILE_BYTES + 1)
      .read_to_end(&mut bytes)
      .map_err(|_| command_error("read_failed", "failed to read operator input"))?;
  }
  if bytes.is_empty() || bytes.len() as u64 > MAX_OPERATOR_FILE_BYTES {
    return Err(command_error(
      "invalid_request",
      "operator input is empty or exceeds its byte limit",
    ));
  }
  Ok(bytes)
}

fn reject_ambiguous_stdin(paths: &[&Path]) -> Result<(), SchedulerCommandError> {
  if paths.iter().filter(|path| **path == Path::new("-")).count() > 1 {
    return Err(command_error(
      "invalid_request",
      "a command cannot read more than one input from stdin",
    ));
  }
  Ok(())
}

fn read_reason_file(path: &Path) -> Result<ValidatedReason, SchedulerCommandError> {
  let bytes = read_bounded_file(path)?;
  validate_canonical_operator_json(&bytes, "reason file is invalid")?;
  let input: SchedulerReasonFile = serde_json::from_slice(&bytes)
    .map_err(|_| command_error("invalid_request", "reason file is invalid"))?;
  if input.schema_version != 1
    || input.reason_code.is_empty()
    || input.reason_code.len() > 64
    || !input
      .reason_code
      .bytes()
      .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    || input.reason.trim() != input.reason
    || input.reason.is_empty()
    || input.reason.len() > 4 * 1024
  {
    return Err(command_error("invalid_request", "reason file is invalid"));
  }
  let canonical_json = json!({
    "reason": input.reason,
    "reason_code": input.reason_code.clone(),
    "schema_version": 1,
  })
  .to_string();
  Ok(ValidatedReason {
    digest: sha256_hex(canonical_json.as_bytes()),
    reason_code: input.reason_code,
    canonical_json,
  })
}

fn read_evidence_file(
  path: &Path,
  disposition: SchedulerDeliveryDisposition,
  reason: Option<&ValidatedReason>,
  duplicate_risk_acknowledged: bool,
) -> Result<ValidatedEvidence, SchedulerCommandError> {
  let bytes = read_bounded_file(path)?;
  validate_canonical_operator_json(&bytes, "evidence file is invalid")?;
  let input: SchedulerEvidenceFile = serde_json::from_slice(&bytes)
    .map_err(|_| command_error("invalid_request", "evidence file is invalid"))?;
  if input.schema_version != 1 {
    return Err(command_error("invalid_request", "evidence file is invalid"));
  }
  let evidence_json = serde_json::to_string(&input.evidence)
    .map_err(|_| command_error("invalid_request", "evidence file is invalid"))?;
  let evidence_digest = sha256_hex(evidence_json.as_bytes());
  let action = match disposition {
    SchedulerDeliveryDisposition::ConfirmDelivered
      if reason.is_none() && !duplicate_risk_acknowledged =>
    {
      let receipt = input.provider_receipt.ok_or_else(|| {
        command_error(
          "invalid_request",
          "confirm-delivered requires provider_receipt",
        )
      })?;
      ScheduledDeliveryUnknownAction::ConfirmDelivered {
        provider_receipt: receipt.to_string(),
        evidence_json,
        evidence_digest: evidence_digest.clone(),
      }
    }
    SchedulerDeliveryDisposition::ConfirmNoWriteTerminal
      if input.provider_receipt.is_none() && reason.is_none() && !duplicate_risk_acknowledged =>
    {
      ScheduledDeliveryUnknownAction::ConfirmNoWriteTerminal {
        evidence_json,
        evidence_digest: evidence_digest.clone(),
      }
    }
    SchedulerDeliveryDisposition::ForceResend
      if input.provider_receipt.is_none() && reason.is_some() && duplicate_risk_acknowledged =>
    {
      let reason = reason.expect("guarded reason");
      ScheduledDeliveryUnknownAction::ForceResend {
        evidence_json,
        evidence_digest: evidence_digest.clone(),
        reason_json: reason.canonical_json.clone(),
        reason_digest: reason.digest.clone(),
        duplicate_risk_acknowledged,
      }
    }
    SchedulerDeliveryDisposition::AcknowledgeUnknown
      if input.provider_receipt.is_none() && reason.is_none() && !duplicate_risk_acknowledged =>
    {
      ScheduledDeliveryUnknownAction::AcknowledgeUnknown {
        evidence_json,
        evidence_digest: evidence_digest.clone(),
      }
    }
    _ => return Err(command_error("invalid_request", "evidence file is invalid")),
  };
  Ok(ValidatedEvidence {
    action,
    digest: evidence_digest,
  })
}

fn validate_canonical_operator_json(
  bytes: &[u8],
  message: &str,
) -> Result<(), SchedulerCommandError> {
  let value: Value =
    serde_json::from_slice(bytes).map_err(|_| command_error("invalid_request", message))?;
  if serde_json::to_vec(&value).ok().as_deref() != Some(bytes) {
    return Err(command_error("invalid_request", message));
  }
  Ok(())
}

fn run_projection_json(run: codeoff_state::ScheduledRunOperatorProjection) -> Value {
  json!({
    "attempt": run.attempt,
    "error_kind": run.error_kind,
    "fence": run.fence,
    "job_id": run.job_id,
    "lease_expires_at": run.lease_expires_at,
    "next_attempt_at": run.next_attempt_at,
    "run_id": run.run_id,
    "state": run.state.as_str(),
    "updated_at": run.updated_at,
  })
}

fn delivery_projection_json(delivery: codeoff_state::ScheduledDeliveryOperatorProjection) -> Value {
  json!({
    "attempt": delivery.attempt,
    "delivery_id": delivery.delivery_id,
    "error_kind": delivery.error_kind,
    "fence": delivery.fence,
    "job_id": delivery.job_id,
    "lease_expires_at": delivery.lease_expires_at,
    "next_attempt_at": delivery.next_attempt_at,
    "provider_outcome": delivery.provider_outcome,
    "run_id": delivery.run_id,
    "state": delivery.state.as_str(),
    "updated_at": delivery.updated_at,
  })
}

fn reconcile_run_outcome(
  outcome: Result<codeoff_state::ScheduledRunReconcileOutcome, codeoff_state::StateError>,
) -> &'static str {
  match outcome {
    Ok(codeoff_state::ScheduledRunReconcileOutcome::Applied(_)) => "applied",
    Ok(codeoff_state::ScheduledRunReconcileOutcome::Stale) => "stale",
    Ok(codeoff_state::ScheduledRunReconcileOutcome::NotEligible) => "not_eligible",
    Err(_) => "error",
  }
}

fn reconcile_delivery_outcome(
  outcome: Result<codeoff_state::ScheduledDeliveryReconcileOutcome, codeoff_state::StateError>,
) -> &'static str {
  match outcome {
    Ok(codeoff_state::ScheduledDeliveryReconcileOutcome::Applied { .. }) => "applied",
    Ok(codeoff_state::ScheduledDeliveryReconcileOutcome::Stale) => "stale",
    Ok(codeoff_state::ScheduledDeliveryReconcileOutcome::NotEligible) => "not_eligible",
    Err(_) => "error",
  }
}

fn build_scheduler_service(
  state: StateStore,
  operator: &SchedulerOperatorConfig,
  target_resolvers: std::sync::Arc<TargetResolverRegistry>,
) -> Result<ScheduleService, ScheduleServiceError> {
  let policy = ConfiguredOperatorIdentityPolicy::new(
    &operator.service_identity,
    &operator.realm,
    &operator.subject,
  )?;
  Ok(ScheduleService::with_components(
    state,
    target_resolvers,
    std::sync::Arc::new(DefaultCapabilityRegistry),
    std::sync::Arc::new(OperatorAuthorizationPolicy::new(std::sync::Arc::new(
      policy,
    ))),
    std::time::Duration::from_secs(5),
  ))
}

async fn validate_list_request(
  service: &ScheduleService,
  invocation: &ScheduleInvocation,
  status: &str,
  cursor: Option<&str>,
  limit: u32,
  now: i64,
) -> Result<ScheduledJobStatus, ScheduleServiceError> {
  let result = parse_status(status).and_then(|status| {
    validate_list(cursor, limit)?;
    Ok(status)
  });
  match result {
    Ok(status) => Ok(status),
    Err(error) => Err(
      service
        .reject_invalid_attempt(invocation, "list", Some("list"), None, error, now)
        .await,
    ),
  }
}

async fn read_or_audit_input(
  service: &ScheduleService,
  operation: &'static str,
  operator: &SchedulerOperatorConfig,
  path: &Path,
  format: Option<SchedulerFileFormat>,
  now: i64,
) -> Result<ValidatedSchedulerMutation, SchedulerCommandError> {
  match read_scheduler_mutation(path, format) {
    Ok(request) => Ok(request),
    Err(input_error) => {
      let invocation = trusted_operator_invocation(operator, "invalid-request");
      let error = service
        .reject_invalid_attempt(
          &invocation,
          operation,
          None,
          None,
          ScheduleServiceError::InvalidRequest(input_error.to_string()),
          now,
        )
        .await;
      Err(SchedulerCommandError::service(&error))
    }
  }
}

#[allow(clippy::too_many_arguments)]
async fn lifecycle(
  service: &ScheduleService,
  operator: &SchedulerOperatorConfig,
  operation: &'static str,
  request_id: String,
  job_id: String,
  expected_generation: i64,
  now: i64,
) -> Result<Value, ScheduleServiceError> {
  let invocation = trusted_operator_invocation(operator, &request_id);
  let request = LifecycleScheduleRequest {
    request_id,
    job_id,
    expected_generation,
    now,
  };
  match operation {
    "pause" => service.pause(&invocation, request).await,
    "resume" => service.resume(&invocation, request).await,
    "delete" => service.delete(&invocation, request).await,
    _ => unreachable!("bounded lifecycle operation"),
  }
}

fn trusted_operator_invocation(
  operator: &SchedulerOperatorConfig,
  request_id: &str,
) -> ScheduleInvocation {
  ScheduleInvocation {
    source: InvocationSource::TrustedOperator {
      request_id: request_id.to_owned(),
    },
    principal: InvocationPrincipal::service(&operator.service_identity),
    channel: None,
  }
}

fn parse_status(value: &str) -> Result<ScheduledJobStatus, ScheduleServiceError> {
  match value {
    "active" => Ok(ScheduledJobStatus::Active),
    "paused" => Ok(ScheduledJobStatus::Paused),
    "completed" => Ok(ScheduledJobStatus::Completed),
    "deleted" => Ok(ScheduledJobStatus::Deleted),
    _ => Err(ScheduleServiceError::InvalidRequest(
      "status must be active, paused, completed, or deleted".to_owned(),
    )),
  }
}

fn validate_list(cursor: Option<&str>, limit: u32) -> Result<(), ScheduleServiceError> {
  if !(1..=100).contains(&limit)
    || cursor.is_some_and(|value| value.trim() != value || value.is_empty() || value.len() > 255)
  {
    return Err(ScheduleServiceError::InvalidRequest(
      "list cursor or limit is invalid".to_owned(),
    ));
  }
  Ok(())
}

fn sanitize_output(mut value: Value) -> Value {
  if let Some(data) = value.get_mut("data").and_then(Value::as_object_mut)
    && let Some(definition) = data.remove("definition")
  {
    let summary = definition.as_object().map_or_else(
      || json!({}),
      |object| {
        json!({
          "schema_version": object.get("schema_version"),
          "previous_success": object.get("previous_success"),
        })
      },
    );
    data.insert("definition".to_owned(), summary);
  }
  value
}

impl fmt::Display for SchedulerInputError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    let message = match self {
      Self::MissingStdinFormat => "--format is required when --file is -",
      Self::UnsupportedFileFormat => "scheduler request file must use .json or .toml",
      Self::ReadFailed => "failed to read scheduler request file",
      Self::RequestTooLarge => "scheduler request file exceeds the byte limit",
      Self::InvalidDocument => "scheduler request file is malformed or violates its strict schema",
      Self::UnsupportedSchemaVersion => "scheduler request schema_version is unsupported",
      Self::InvalidRequest => "scheduler request contains an invalid value",
    };
    formatter.write_str(message)
  }
}

impl std::error::Error for SchedulerInputError {}

pub(crate) fn read_scheduler_mutation(
  path: &Path,
  explicit_format: Option<SchedulerFileFormat>,
) -> Result<ValidatedSchedulerMutation, SchedulerInputError> {
  let format = resolve_format(path, explicit_format)?;
  if path == Path::new("-") {
    let stdin = io::stdin();
    return decode_scheduler_mutation(stdin.lock(), format);
  }
  let file = File::open(path).map_err(|_| SchedulerInputError::ReadFailed)?;
  decode_scheduler_mutation(file, format)
}

fn resolve_format(
  path: &Path,
  explicit_format: Option<SchedulerFileFormat>,
) -> Result<SchedulerFileFormat, SchedulerInputError> {
  if path == Path::new("-") {
    return explicit_format.ok_or(SchedulerInputError::MissingStdinFormat);
  }
  let inferred = match path.extension().and_then(|value| value.to_str()) {
    Some("json") => Some(SchedulerFileFormat::Json),
    Some("toml") => Some(SchedulerFileFormat::Toml),
    _ => None,
  };
  explicit_format
    .or(inferred)
    .ok_or(SchedulerInputError::UnsupportedFileFormat)
}

fn decode_scheduler_mutation(
  reader: impl Read,
  format: SchedulerFileFormat,
) -> Result<ValidatedSchedulerMutation, SchedulerInputError> {
  let mut bytes = Vec::new();
  reader
    .take(MAX_SCHEDULER_REQUEST_BYTES + 1)
    .read_to_end(&mut bytes)
    .map_err(|_| SchedulerInputError::ReadFailed)?;
  if bytes.len() as u64 > MAX_SCHEDULER_REQUEST_BYTES {
    return Err(SchedulerInputError::RequestTooLarge);
  }
  let input: SchedulerMutationInput = match format {
    SchedulerFileFormat::Json => {
      serde_json::from_slice(&bytes).map_err(|_| SchedulerInputError::InvalidDocument)?
    }
    SchedulerFileFormat::Toml => {
      let source = std::str::from_utf8(&bytes).map_err(|_| SchedulerInputError::InvalidDocument)?;
      toml::from_str(source).map_err(|_| SchedulerInputError::InvalidDocument)?
    }
  };
  validate_scheduler_mutation(input)
}

fn validate_scheduler_mutation(
  input: SchedulerMutationInput,
) -> Result<ValidatedSchedulerMutation, SchedulerInputError> {
  if input.schema_version != SCHEDULER_REQUEST_SCHEMA_VERSION {
    return Err(SchedulerInputError::UnsupportedSchemaVersion);
  }
  if input.request_id.trim() != input.request_id
    || input.request_id.is_empty()
    || input.request_id.len() > 255
    || input.capability.trim() != input.capability
    || input.capability.is_empty()
    || input.capability.len() > 255
  {
    return Err(SchedulerInputError::InvalidRequest);
  }
  let instruction = input.instruction.trim().to_owned();
  if instruction.is_empty() || instruction.len() > 64 * 1024 {
    return Err(SchedulerInputError::InvalidRequest);
  }
  let schedule = match input.schedule {
    SchedulerScheduleInput::Once { at } => ScheduleSpec::once(parse_rfc3339(&at)?),
    SchedulerScheduleInput::Interval {
      anchor,
      every_seconds,
    } => ScheduleSpec::fixed_interval(parse_rfc3339(&anchor)?, every_seconds)
      .map_err(|_| SchedulerInputError::InvalidRequest)?,
    SchedulerScheduleInput::Cron {
      expression,
      timezone,
    } => {
      ScheduleSpec::cron(&expression, &timezone).map_err(|_| SchedulerInputError::InvalidRequest)?
    }
  };
  let previous_success = match input.previous_success {
    PreviousSuccessPolicyInput::None => PreviousSuccessPolicy::None,
    PreviousSuccessPolicyInput::LatestSuccess => PreviousSuccessPolicy::LatestSuccess,
  };
  let target = match input.delivery {
    DeliveryInput::None => DeliveryTargetRequest::None,
    DeliveryInput::SlackChannel { channel_id } => DeliveryTargetRequest::Channel { channel_id },
    DeliveryInput::SlackDirectMessage { user_id } => {
      DeliveryTargetRequest::DirectMessage { user_id }
    }
    DeliveryInput::SlackThread {
      channel_id,
      thread_ts,
    } => DeliveryTargetRequest::Thread {
      channel_id,
      thread_id: thread_ts,
    },
  };
  Ok(ValidatedSchedulerMutation {
    request_id: input.request_id,
    instruction,
    schedule,
    capability: input.capability,
    previous_success,
    target,
  })
}

fn parse_rfc3339(value: &str) -> Result<i64, SchedulerInputError> {
  DateTime::parse_from_rfc3339(value)
    .map(|date_time| date_time.timestamp())
    .map_err(|_| SchedulerInputError::InvalidRequest)
}

#[cfg(test)]
mod tests {
  use super::*;
  use async_trait::async_trait;
  use codeoff_agent_contract::{
    ChannelReplyStrategy, ChannelTaskContext, ConversationKind, InvocationPrincipal,
    InvocationSource,
  };
  use codeoff_channel_slack::{
    SlackHttpClient, SlackHttpRequest, SlackHttpResponse, SlackScheduleTargetVerifier,
    SlackWebApiClient,
  };
  use codeoff_config::SlackConfig;
  use codeoff_runtime::schedule_service::{
    ChannelTargetVerifier, DefaultCapabilityRegistry, OwnerOnlyAuthorizationPolicy,
    SlackTargetResolutionRequest, TargetVerificationError, VerifiedSlackTarget,
    VerifiedSlackTargetResolver,
  };
  use codeoff_runtime::schedule_tools::ScheduleDynamicToolHandler;
  use codeoff_state::{
    AttestedExecutionProfileSnapshot, ClaimedScheduledRun, PreflightFailureDisposition,
    PreparedScheduledDelivery, PrincipalKey, ScheduledDeliveryFailure,
    ScheduledDeliveryOperatorProjection, ScheduledDeliveryState, ScheduledDeliveryUnknownAction,
    ScheduledRunResult, SchedulerOperatorMutationOutcome, SchedulerOperatorRequest,
    SkippedNoneBaselinePolicy,
  };
  use std::io::Cursor;
  use std::sync::atomic::{AtomicUsize, Ordering};
  use std::sync::{Arc, Mutex};
  use std::time::Duration;

  struct CountingSlackVerifier(Arc<AtomicUsize>);

  #[derive(Default)]
  struct AcceptingAuthorityVerifier(Mutex<Vec<String>>);

  impl SchedulerAuthorityVerifier for AcceptingAuthorityVerifier {
    fn verify(
      &self,
      authority: &[u8],
      action_digest: &str,
    ) -> Result<PrincipalKey, SchedulerCommandError> {
      assert_eq!(authority, b"authority-sentinel");
      assert_eq!(action_digest.len(), 64);
      self
        .0
        .lock()
        .expect("verifier records")
        .push(action_digest.to_owned());
      PrincipalKey::new("service", "codeoff", "ops", "verified-operator")
        .map_err(value_command_error)
    }
  }

  #[tokio::test]
  async fn scheduler_status_reports_sanitized_runtime_switches_and_batch_limits() {
    let temp = tempfile::tempdir().expect("tempdir");
    let state = StateStore::initialize(&temp.path().join("state"), None)
      .await
      .expect("initialize state");
    let policy = SchedulerRuntimeConfig {
      enabled: true,
      run_claims_enabled: true,
      delivery_claims_enabled: false,
      recovery_batch_limit: 37,
      materialization_batch_limit: 41,
      ..SchedulerRuntimeConfig::default()
    };
    let output = execute_scheduler_command_with_policy_and_verifier(
      SchedulerCommand::Status { json: true },
      state,
      SchedulerOperatorConfig::diagnostic(),
      Arc::new(TargetResolverRegistry::with_defaults()),
      &policy,
      &AcceptingAuthorityVerifier::default(),
      100,
    )
    .await
    .expect("scheduler status");
    assert_eq!(
      output,
      json!({
        "data": {
          "scheduler": "reachable",
          "enabled": true,
          "run_claims_enabled": true,
          "delivery_claims_enabled": false,
          "recovery_batch_limit": 37,
          "materialization_batch_limit": 41,
        },
        "ok": true,
        "schema_version": 1,
      })
    );
    let human = render_scheduler_human(&output);
    for claim in [
      "enabled: true",
      "run_claims_enabled: true",
      "delivery_claims_enabled: false",
      "recovery_batch_limit: 37",
      "materialization_batch_limit: 41",
    ] {
      assert!(human.contains(claim), "missing status claim {claim}");
    }
  }

  #[derive(Clone, Default)]
  struct FakeSlackHttp {
    responses: Arc<Mutex<Vec<SlackHttpResponse>>>,
    requests: Arc<Mutex<Vec<SlackHttpRequest>>>,
  }

  impl FakeSlackHttp {
    fn new(responses: Vec<SlackHttpResponse>) -> Self {
      Self {
        responses: Arc::new(Mutex::new(responses.into_iter().rev().collect())),
        requests: Arc::new(Mutex::default()),
      }
    }

    fn respond(&self, request: SlackHttpRequest) -> Result<SlackHttpResponse, String> {
      self.requests.lock().expect("requests").push(request);
      self
        .responses
        .lock()
        .expect("responses")
        .pop()
        .ok_or_else(|| "unexpected Slack request".to_owned())
    }
  }

  #[async_trait]
  impl SlackHttpClient for FakeSlackHttp {
    async fn get(&self, request: SlackHttpRequest) -> Result<SlackHttpResponse, String> {
      self.respond(request)
    }

    async fn post(&self, request: SlackHttpRequest) -> Result<SlackHttpResponse, String> {
      self.respond(request)
    }
  }

  fn slack_response(body: impl Into<String>) -> SlackHttpResponse {
    SlackHttpResponse::new(200, Vec::<(&str, &str)>::new(), body)
  }

  fn slack_auth() -> SlackHttpResponse {
    slack_response(
      r#"{"ok":true,"team_id":"T00000000","enterprise_id":"E00000000","user_id":"U0BOT","bot_id":"B0BOT"}"#,
    )
  }

  fn slack_user(user_id: &str) -> SlackHttpResponse {
    slack_response(
      json!({
        "ok": true,
        "user": {
          "id": user_id,
          "team_id": "T00000000",
          "profile": {},
        }
      })
      .to_string(),
    )
  }

  fn slack_channel(channel_id: &str, is_im: bool) -> SlackHttpResponse {
    slack_response(
      json!({
        "ok": true,
        "channel": {
          "id": channel_id,
          "is_im": is_im,
          "is_private": is_im,
          "is_member": true,
          "context_team_id": "T00000000",
          "enterprise_id": "E00000000",
          "conversation_host_id": "T00000000",
          "shared_team_ids": ["T00000000"],
        }
      })
      .to_string(),
    )
  }

  fn slack_members() -> SlackHttpResponse {
    slack_response(r#"{"ok":true,"members":["U1"],"response_metadata":{"next_cursor":""}}"#)
  }

  fn real_slack_resolvers(responses: Vec<SlackHttpResponse>) -> Arc<TargetResolverRegistry> {
    let provider = Arc::new(SlackWebApiClient::new(
      FakeSlackHttp::new(responses),
      "slack-default",
      "xoxb-test-secret",
      SlackConfig::default(),
      100,
    ));
    let mut resolvers = TargetResolverRegistry::with_defaults();
    resolvers.register(VerifiedSlackTargetResolver::registration(
      Arc::new(SlackScheduleTargetVerifier::new(provider)),
      Duration::from_millis(100),
    ));
    Arc::new(resolvers)
  }

  async fn prepare_cli_delivery(
    state: &StateStore,
    job_id: &str,
    scheduled_for: i64,
    failure: Option<ScheduledDeliveryFailure>,
  ) -> ScheduledDeliveryOperatorProjection {
    let operator =
      SchedulerOperatorConfig::new("ops-a".to_owned(), "realm-a".to_owned()).expect("operator");
    let service = build_scheduler_service(
      state.clone(),
      &operator,
      real_slack_resolvers(vec![slack_auth(), slack_channel("C1", false)]),
    )
    .expect("service");
    let created = service
      .create(
        &trusted_operator_invocation(&operator, job_id),
        CreateScheduleRequest {
          request_id: job_id.to_owned(),
          instruction: format!("execute {job_id}"),
          previous_success: PreviousSuccessPolicy::None,
          schedule: ScheduleSpec::once(scheduled_for),
          target: DeliveryTargetRequest::Channel {
            channel_id: "C1".to_owned(),
          },
          capability: "none".to_owned(),
          now: 100,
        },
      )
      .await
      .expect("create delivery job");
    let actual_job_id = created["data"]["job_id"]
      .as_str()
      .expect("created job id")
      .to_owned();
    state
      .materialize_due_schedule(&actual_job_id, 0, scheduled_for)
      .await
      .expect("materialize");
    let run = state
      .claim_next_scheduled_run("run-worker", scheduled_for + 1, scheduled_for + 50)
      .await
      .expect("claim run")
      .expect("run");
    let profile =
      AttestedExecutionProfileSnapshot::new(1, "{}", "sha256-v1", "profile").expect("profile");
    state
      .mark_scheduled_run_executing(&run.binding, &profile, scheduled_for + 2)
      .await
      .expect("execute");
    state
      .complete_scheduled_run_success(
        &run.binding,
        &ScheduledRunResult::new(format!("payload-{job_id}"), "").expect("result"),
        scheduled_for + 3,
      )
      .await
      .expect("complete");
    let delivery_id = state
      .list_scheduled_delivery_operator_projections(None, 100)
      .await
      .expect("list deliveries")
      .into_iter()
      .find(|delivery| delivery.job_id == actual_job_id)
      .expect("delivery")
      .delivery_id;
    assert!(matches!(
      state
        .prepare_scheduled_delivery(
          &delivery_id,
          "text/plain; charset=utf-8",
          &format!("payload-{job_id}"),
          1,
          scheduled_for + 4,
          SkippedNoneBaselinePolicy::DoNotAdvance,
        )
        .await
        .expect("prepare"),
      PreparedScheduledDelivery::Pending(_)
    ));
    let delivery = state
      .claim_next_scheduled_delivery("delivery-worker", scheduled_for + 5, scheduled_for + 50)
      .await
      .expect("claim delivery")
      .expect("delivery");
    if let Some(failure) = failure {
      state
        .complete_scheduled_delivery_failure(&delivery.binding, &failure, scheduled_for + 6)
        .await
        .expect("delivery failure");
    }
    state
      .get_scheduled_delivery_operator_projection(&delivery_id)
      .await
      .expect("projection")
      .expect("delivery projection")
  }

  async fn prepare_cli_leased_run(
    state: &StateStore,
    request_id: &str,
    scheduled_for: i64,
  ) -> ClaimedScheduledRun {
    let operator =
      SchedulerOperatorConfig::new("ops-a".to_owned(), "realm-a".to_owned()).expect("operator");
    let service = build_scheduler_service(
      state.clone(),
      &operator,
      Arc::new(TargetResolverRegistry::with_defaults()),
    )
    .expect("service");
    let created = service
      .create(
        &trusted_operator_invocation(&operator, request_id),
        CreateScheduleRequest {
          request_id: request_id.to_owned(),
          instruction: format!("execute {request_id}"),
          previous_success: PreviousSuccessPolicy::None,
          schedule: ScheduleSpec::once(scheduled_for),
          target: DeliveryTargetRequest::None,
          capability: "none".to_owned(),
          now: 100,
        },
      )
      .await
      .expect("create run job");
    let job_id = created["data"]["job_id"].as_str().expect("job id");
    state
      .materialize_due_schedule(job_id, 0, scheduled_for)
      .await
      .expect("materialize run");
    state
      .claim_next_scheduled_run("run-worker", scheduled_for + 1, scheduled_for + 50)
      .await
      .expect("claim run")
      .expect("run")
  }

  #[async_trait]
  impl ChannelTargetVerifier for CountingSlackVerifier {
    async fn resolve_target(
      &self,
      workspace_id: Option<&str>,
      actor_id: Option<&str>,
      target: &SlackTargetResolutionRequest,
    ) -> Result<VerifiedSlackTarget, TargetVerificationError> {
      assert_eq!(workspace_id, None, "trusted CLI has no channel workspace");
      assert_eq!(actor_id, None, "trusted CLI has no channel actor");
      self.0.fetch_add(1, Ordering::SeqCst);
      let SlackTargetResolutionRequest::Channel { channel_id } = target else {
        return Err(TargetVerificationError::Invalid);
      };
      Ok(VerifiedSlackTarget {
        workspace_id: "T00000000".to_owned(),
        team_id: "T00000000".to_owned(),
        enterprise_id: None,
        context_team_id: "T00000000".to_owned(),
        conversation_host_id: "T00000000".to_owned(),
        kind: "channel".to_owned(),
        channel_id: channel_id.clone(),
        thread_ts: None,
        authorization_evidence_version: 1,
        authorization_evidence_digest: "b".repeat(64),
      })
    }
  }

  const DEFINITION_VERSION_FOR_TESTS: u32 = 2;
  const VALID_JSON: &str = r#"{
    "schema_version": 1,
    "request_id": "request-1",
    "instruction": "  inspect durable issues  ",
    "schedule": {"kind": "once", "at": "2030-01-01T12:00:00+08:00"},
    "capability": "none",
    "previous_success": {"kind": "latest_success"},
    "delivery": {"kind": "none"}
  }"#;

  #[test]
  fn strict_json_decoder_normalizes_bounded_scheduler_request() {
    let request = decode_scheduler_mutation(
      Cursor::new(VALID_JSON.as_bytes()),
      SchedulerFileFormat::Json,
    )
    .expect("request");
    assert_eq!(request.request_id, "request-1");
    assert_eq!(request.instruction, "inspect durable issues");
    assert_eq!(request.schedule, ScheduleSpec::once(1_893_470_400));
    assert_eq!(request.capability, "none");
    assert_eq!(
      request.previous_success,
      PreviousSuccessPolicy::LatestSuccess
    );
  }

  #[test]
  fn strict_toml_decoder_accepts_explicit_versioned_contract() {
    let request = decode_scheduler_mutation(
      Cursor::new(
        br#"
schema_version = 1
request_id = "request-1"
instruction = "inspect durable issues"
capability = "none"

[schedule]
kind = "interval"
anchor = "2030-01-01T00:00:00Z"
every_seconds = 300

[previous_success]
kind = "none"

[delivery]
kind = "none"
"#,
      ),
      SchedulerFileFormat::Toml,
    )
    .expect("request");
    assert_eq!(
      request.schedule,
      ScheduleSpec::fixed_interval(1_893_456_000, 300).expect("interval")
    );
    assert_eq!(request.previous_success, PreviousSuccessPolicy::None);
  }

  #[test]
  fn strict_decoder_rejects_unknown_fields_versions_and_enums_without_echoing_input() {
    for source in [
      VALID_JSON.replace("\"schema_version\": 1", "\"schema_version\": 2"),
      VALID_JSON.replace("\"delivery\":", "\"owner\": \"U1\", \"delivery\":"),
      VALID_JSON.replace("\"kind\": \"none\"}", "\"kind\": \"slack\"}"),
    ] {
      let secret = "Authorization: Bearer secret-sentinel";
      let source = source.replace("inspect durable issues", secret);
      let error =
        decode_scheduler_mutation(Cursor::new(source.as_bytes()), SchedulerFileFormat::Json)
          .expect_err("invalid request");
      assert!(!error.to_string().contains(secret));
    }
  }

  #[test]
  fn strict_decoder_rejects_malformed_oversized_and_invalid_schedule_inputs() {
    assert_eq!(
      decode_scheduler_mutation(Cursor::new(b"{"), SchedulerFileFormat::Json),
      Err(SchedulerInputError::InvalidDocument)
    );
    assert_eq!(
      decode_scheduler_mutation(
        Cursor::new(vec![
          b'x';
          usize::try_from(MAX_SCHEDULER_REQUEST_BYTES + 1)
            .expect("request bound fits usize")
        ]),
        SchedulerFileFormat::Json
      ),
      Err(SchedulerInputError::RequestTooLarge)
    );
    for source in [
      VALID_JSON.replace("2030-01-01T12:00:00+08:00", "2030-01-01T12:00:00"),
      VALID_JSON.replace("inspect durable issues", "   "),
    ] {
      assert_eq!(
        decode_scheduler_mutation(Cursor::new(source.as_bytes()), SchedulerFileFormat::Json),
        Err(SchedulerInputError::InvalidRequest)
      );
    }
  }

  #[test]
  fn stdin_requires_explicit_format_and_path_format_is_bounded() {
    assert_eq!(
      resolve_format(Path::new("-"), None),
      Err(SchedulerInputError::MissingStdinFormat)
    );
    assert_eq!(
      resolve_format(Path::new("request.yaml"), None),
      Err(SchedulerInputError::UnsupportedFileFormat)
    );
    assert_eq!(
      resolve_format(Path::new("request.json"), None),
      Ok(SchedulerFileFormat::Json)
    );
  }

  #[test]
  fn operator_reason_is_strict_canonical_and_stdin_inputs_are_unambiguous() {
    let temp = tempfile::tempdir().expect("tempdir");
    let reason_path = temp.path().join("reason.json");
    std::fs::write(
      &reason_path,
      r#"{"reason":"provider recovered","reason_code":"provider_recovered","schema_version":1}"#,
    )
    .expect("write reason");
    let reason = read_reason_file(&reason_path).expect("valid reason");
    assert_eq!(reason.reason_code, "provider_recovered");
    assert!(!reason.canonical_json.contains("Authorization"));
    assert_eq!(reason.digest.len(), 64);
    assert!(reject_ambiguous_stdin(&[Path::new("-"), Path::new("-")]).is_err());
    assert!(reject_ambiguous_stdin(&[Path::new("-"), Path::new("-"), Path::new("-")]).is_err());
    assert!(reject_ambiguous_stdin(&[Path::new("-"), &reason_path]).is_ok());

    std::fs::write(
      &reason_path,
      r#"{"schema_version":1,"reason_code":"bad-code","reason":"secret","extra":true}"#,
    )
    .expect("write invalid reason");
    let Err(error) = read_reason_file(&reason_path) else {
      panic!("invalid reason must fail");
    };
    for rendered in [error.to_string(), format!("{error:?}")] {
      assert!(!rendered.contains("secret"));
      assert!(!rendered.contains("bad-code"));
    }
  }

  #[test]
  fn reconcile_outcome_labels_cover_applied_stale_not_eligible_and_error() {
    assert_eq!(
      reconcile_run_outcome(Ok(codeoff_state::ScheduledRunReconcileOutcome::Applied(
        codeoff_state::ExpiredRunReclaimOutcome::Idle,
      ))),
      "applied"
    );
    assert_eq!(
      reconcile_run_outcome(Ok(codeoff_state::ScheduledRunReconcileOutcome::Stale)),
      "stale"
    );
    assert_eq!(
      reconcile_run_outcome(Ok(codeoff_state::ScheduledRunReconcileOutcome::NotEligible)),
      "not_eligible"
    );
    assert_eq!(
      reconcile_run_outcome(Err(codeoff_state::StateError::InvalidSchedulerState {
        reason: "redacted".to_owned(),
      })),
      "error"
    );
    assert_eq!(
      reconcile_delivery_outcome(Ok(
        codeoff_state::ScheduledDeliveryReconcileOutcome::Applied {
          delivery_id: "delivery".to_owned(),
          attempt: 1,
          fence: 1,
        },
      )),
      "applied"
    );
    assert_eq!(
      reconcile_delivery_outcome(Ok(codeoff_state::ScheduledDeliveryReconcileOutcome::Stale,)),
      "stale"
    );
    assert_eq!(
      reconcile_delivery_outcome(Ok(
        codeoff_state::ScheduledDeliveryReconcileOutcome::NotEligible,
      )),
      "not_eligible"
    );
    assert_eq!(
      reconcile_delivery_outcome(Err(codeoff_state::StateError::InvalidSchedulerState {
        reason: "redacted".to_owned(),
      })),
      "error"
    );
  }

  async fn execute_test_operator_command(
    command: SchedulerCommand,
    state: StateStore,
    verifier: &AcceptingAuthorityVerifier,
    now: i64,
  ) -> Result<Value, SchedulerCommandError> {
    execute_scheduler_command_with_policy_and_verifier(
      command,
      state,
      SchedulerOperatorConfig::diagnostic(),
      Arc::new(TargetResolverRegistry::with_defaults()),
      &SchedulerRuntimeConfig::default(),
      verifier,
      now,
    )
    .await
  }

  fn write_operator_evidence(path: &Path, kind: &str, evidence_id: &str, receipt: Option<Value>) {
    let mut evidence = json!({
      "evidence_id": evidence_id,
      "evidence_version": 1,
      "kind": kind,
      "provider": "slack",
      "target_kind": "channel",
      "tenant": "T00000000",
    });
    if let Some(receipt) = &receipt {
      evidence["receipt_digest"] = json!(sha256_hex(receipt.to_string().as_bytes()));
    }
    if kind != "operator_acknowledged_unknown" {
      evidence["provider_query_started_at"] = json!(900);
      evidence["provider_query_completed_at"] = json!(910);
      evidence["provider_query_window_start"] = json!(800);
      evidence["provider_query_window_end"] = json!(900);
      evidence["provider_query_scope"] = json!("canonical_delivery_target");
      evidence["provider_query_result"] = json!(match kind {
        "provider_confirmed_delivered" => "write_confirmed",
        "provider_confirmed_no_write" => "no_write_confirmed",
        "operator_force_resend" => "no_matching_write_found",
        _ => panic!("unsupported resolution evidence kind"),
      });
      evidence["provider_query_summary_digest"] =
        json!(sha256_hex(b"redacted-provider-query-summary"));
    }
    let envelope = json!({
      "evidence": evidence,
      "provider_receipt": receipt,
      "schema_version": 1,
    });
    std::fs::write(path, envelope.to_string()).expect("write evidence");
  }

  #[tokio::test]
  #[allow(clippy::too_many_lines)]
  async fn operator_cli_adapter_binds_retry_and_unknown_delivery_actions() {
    let temp = tempfile::tempdir().expect("tempdir");
    let state = StateStore::initialize(&temp.path().join("state"), None)
      .await
      .expect("state");
    let verifier = AcceptingAuthorityVerifier::default();
    let authority = temp.path().join("authority.bin");
    std::fs::write(&authority, b"authority-sentinel").expect("authority");
    let reason = temp.path().join("reason.json");
    std::fs::write(
      &reason,
      r#"{"reason":"provider recovered","reason_code":"provider_recovered","schema_version":1}"#,
    )
    .expect("reason");

    let retryable = prepare_cli_delivery(
      &state,
      "cli-retry-delivery",
      200,
      Some(ScheduledDeliveryFailure::ConfirmedNoWriteRetryable {
        error_kind: "rate_limited".to_owned(),
        redacted_message: None,
        next_attempt_at: 2_000,
      }),
    )
    .await;
    let retry_command = SchedulerCommand::RetryDelivery {
      delivery_id: retryable.delivery_id.clone(),
      request_id: "retry-delivery-request".to_owned(),
      expected_attempt: retryable.attempt,
      expected_fence: retryable.fence,
      reason_file: reason.clone(),
      authority_file: authority.clone(),
    };
    let applied =
      execute_test_operator_command(retry_command.clone(), state.clone(), &verifier, 1000)
        .await
        .expect("apply retry");
    assert_eq!(applied["data"]["outcome"], "applied");
    let replay = execute_test_operator_command(retry_command, state.clone(), &verifier, 1000)
      .await
      .expect("replay retry");
    assert_eq!(replay["data"]["outcome"], "replay");

    for (index, disposition, kind) in [
      (
        0_i64,
        SchedulerDeliveryDisposition::ConfirmDelivered,
        "provider_confirmed_delivered",
      ),
      (
        1,
        SchedulerDeliveryDisposition::ConfirmNoWriteTerminal,
        "provider_confirmed_no_write",
      ),
      (
        2,
        SchedulerDeliveryDisposition::ForceResend,
        "operator_force_resend",
      ),
      (
        3,
        SchedulerDeliveryDisposition::AcknowledgeUnknown,
        "operator_acknowledged_unknown",
      ),
    ] {
      let unknown = prepare_cli_delivery(
        &state,
        &format!("cli-unknown-{index}"),
        300 + index * 100,
        Some(ScheduledDeliveryFailure::AmbiguousPostWrite {
          error_kind: "ambiguous".to_owned(),
          redacted_message: None,
        }),
      )
      .await;
      let receipt = (disposition == SchedulerDeliveryDisposition::ConfirmDelivered).then(|| {
        json!({
          "conversation_id": "C1",
          "message_id": format!("message-{index}"),
          "provider": "slack",
          "receipt_version": 1,
          "target_kind": "channel",
          "tenant": "T00000000",
          "thread_id": null,
        })
      });
      let evidence = temp.path().join(format!("evidence-{index}.json"));
      write_operator_evidence(
        &evidence,
        kind,
        &format!("evidence-{index}"),
        receipt.clone(),
      );
      let request_id = format!("unknown-request-{index}");
      let command = SchedulerCommand::ResolveDeliveryUnknown {
        delivery_id: unknown.delivery_id.clone(),
        disposition,
        request_id: request_id.clone(),
        expected_attempt: unknown.attempt,
        expected_fence: unknown.fence,
        evidence_file: evidence.clone(),
        reason_file: (disposition == SchedulerDeliveryDisposition::ForceResend)
          .then(|| reason.clone()),
        acknowledge_duplicate_risk: disposition == SchedulerDeliveryDisposition::ForceResend,
        authority_file: authority.clone(),
      };
      let output = execute_test_operator_command(command.clone(), state.clone(), &verifier, 1000)
        .await
        .expect("resolve unknown");
      assert_eq!(output["data"]["outcome"], "applied");
      let replay = execute_test_operator_command(command, state.clone(), &verifier, 1000)
        .await
        .expect("replay unknown");
      assert_eq!(replay["data"]["outcome"], "replay");
      let changed_evidence = temp.path().join(format!("changed-evidence-{index}.json"));
      write_operator_evidence(
        &changed_evidence,
        kind,
        &format!("changed-evidence-{index}"),
        receipt.clone(),
      );
      let changed_evidence_conflict = execute_test_operator_command(
        SchedulerCommand::ResolveDeliveryUnknown {
          delivery_id: unknown.delivery_id.clone(),
          disposition,
          request_id: request_id.clone(),
          expected_attempt: unknown.attempt,
          expected_fence: unknown.fence,
          evidence_file: changed_evidence,
          reason_file: (disposition == SchedulerDeliveryDisposition::ForceResend)
            .then(|| reason.clone()),
          acknowledge_duplicate_risk: disposition == SchedulerDeliveryDisposition::ForceResend,
          authority_file: authority.clone(),
        },
        state.clone(),
        &verifier,
        1000,
      )
      .await
      .expect("changed evidence conflict");
      assert_eq!(changed_evidence_conflict["data"]["outcome"], "conflict");
      if disposition == SchedulerDeliveryDisposition::ConfirmDelivered {
        let changed_receipt_evidence = temp.path().join("changed-receipt-evidence.json");
        write_operator_evidence(
          &changed_receipt_evidence,
          kind,
          "changed-receipt-evidence",
          Some(json!({
            "conversation_id": "C1",
            "message_id": "changed-message",
            "provider": "slack",
            "receipt_version": 1,
            "target_kind": "channel",
            "tenant": "T00000000",
            "thread_id": null,
          })),
        );
        let conflict = execute_test_operator_command(
          SchedulerCommand::ResolveDeliveryUnknown {
            delivery_id: unknown.delivery_id.clone(),
            disposition,
            request_id: request_id.clone(),
            expected_attempt: unknown.attempt,
            expected_fence: unknown.fence,
            evidence_file: changed_receipt_evidence,
            reason_file: None,
            acknowledge_duplicate_risk: false,
            authority_file: authority.clone(),
          },
          state.clone(),
          &verifier,
          1000,
        )
        .await
        .expect("changed receipt conflict");
        assert_eq!(conflict["data"]["outcome"], "conflict");
      }
      if disposition == SchedulerDeliveryDisposition::ForceResend {
        let changed_reason = temp.path().join("changed-force-reason.json");
        std::fs::write(
          &changed_reason,
          r#"{"reason":"changed duplicate decision","reason_code":"changed_duplicate_decision","schema_version":1}"#,
        )
        .expect("changed force reason");
        let conflict = execute_test_operator_command(
          SchedulerCommand::ResolveDeliveryUnknown {
            delivery_id: unknown.delivery_id.clone(),
            disposition,
            request_id: request_id.clone(),
            expected_attempt: unknown.attempt,
            expected_fence: unknown.fence,
            evidence_file: evidence.clone(),
            reason_file: Some(changed_reason),
            acknowledge_duplicate_risk: true,
            authority_file: authority.clone(),
          },
          state.clone(),
          &verifier,
          1000,
        )
        .await
        .expect("changed reason conflict");
        assert_eq!(conflict["data"]["outcome"], "conflict");
      }
      if index == 0 {
        for (delivery_id, expected_fence) in [
          (unknown.delivery_id.clone(), unknown.fence + 1),
          ("changed-delivery-id".to_owned(), unknown.fence),
        ] {
          let conflict = execute_test_operator_command(
            SchedulerCommand::ResolveDeliveryUnknown {
              delivery_id,
              disposition,
              request_id: request_id.clone(),
              expected_attempt: unknown.attempt,
              expected_fence,
              evidence_file: evidence.clone(),
              reason_file: None,
              acknowledge_duplicate_risk: false,
              authority_file: authority.clone(),
            },
            state.clone(),
            &verifier,
            1000,
          )
          .await
          .expect("changed target or CAS conflict");
          assert_eq!(conflict["data"]["outcome"], "conflict");
        }
        let changed_disposition_evidence = temp.path().join("changed-disposition-evidence.json");
        write_operator_evidence(
          &changed_disposition_evidence,
          "provider_confirmed_no_write",
          "changed-disposition",
          None,
        );
        let conflict = execute_test_operator_command(
          SchedulerCommand::ResolveDeliveryUnknown {
            delivery_id: unknown.delivery_id.clone(),
            disposition: SchedulerDeliveryDisposition::ConfirmNoWriteTerminal,
            request_id: request_id.clone(),
            expected_attempt: unknown.attempt,
            expected_fence: unknown.fence,
            evidence_file: changed_disposition_evidence,
            reason_file: None,
            acknowledge_duplicate_risk: false,
            authority_file: authority.clone(),
          },
          state.clone(),
          &verifier,
          1000,
        )
        .await
        .expect("changed disposition conflict");
        assert_eq!(conflict["data"]["outcome"], "conflict");
      }
      for text in [
        output.to_string(),
        format!("{output:?}"),
        render_scheduler_human(&output),
      ] {
        for forbidden in [
          "authority-sentinel",
          "provider recovered",
          "verified-operator",
          "message-",
          "evidence-",
          "payload-",
        ] {
          assert!(!text.contains(forbidden), "leaked {forbidden}");
        }
      }
    }
    assert!(verifier.0.lock().expect("digests").len() >= 10);
  }

  #[tokio::test]
  #[allow(clippy::too_many_lines)]
  async fn operator_cli_adapter_applies_run_retry_and_exact_reconcile_plan() {
    let temp = tempfile::tempdir().expect("tempdir");
    let state = StateStore::initialize(&temp.path().join("state"), None)
      .await
      .expect("state");
    let verifier = AcceptingAuthorityVerifier::default();
    let authority = temp.path().join("authority.bin");
    std::fs::write(&authority, b"authority-sentinel").expect("authority");
    let reason = temp.path().join("reason.json");
    std::fs::write(
      &reason,
      r#"{"reason":"operator approved retry","reason_code":"manual_retry","schema_version":1}"#,
    )
    .expect("reason");

    let terminal = prepare_cli_leased_run(&state, "cli-retry-run", 800).await;
    state
      .record_scheduled_run_preflight_failure(
        &terminal.binding,
        PreflightFailureDisposition::Fail,
        "preflight_failed",
        "redacted failure",
        802,
      )
      .await
      .expect("terminalize run");
    let retry = SchedulerCommand::RetryRun {
      run_id: terminal.binding.run_id().to_owned(),
      expected_state: SchedulerRetryRunState::Failed,
      request_id: "retry-run-request".to_owned(),
      expected_attempt: terminal.binding.attempt(),
      expected_fence: terminal.binding.fence(),
      reason_file: reason,
      authority_file: authority.clone(),
    };
    let applied = execute_test_operator_command(retry.clone(), state.clone(), &verifier, 900)
      .await
      .expect("apply run retry");
    assert_eq!(applied["data"]["outcome"], "applied");
    let replay = execute_test_operator_command(retry.clone(), state.clone(), &verifier, 900)
      .await
      .expect("replay run retry");
    assert_eq!(replay["data"]["outcome"], "replay");
    let SchedulerCommand::RetryRun {
      run_id,
      request_id,
      expected_attempt,
      expected_fence,
      reason_file,
      authority_file,
      ..
    } = retry
    else {
      unreachable!("run retry command")
    };
    let conflict = execute_test_operator_command(
      SchedulerCommand::RetryRun {
        run_id,
        expected_state: SchedulerRetryRunState::Cancelled,
        request_id,
        expected_attempt,
        expected_fence,
        reason_file,
        authority_file,
      },
      state.clone(),
      &verifier,
      900,
    )
    .await
    .expect("conflicting run retry");
    assert_eq!(conflict["data"]["outcome"], "conflict");

    let reconcile_state = StateStore::initialize(&temp.path().join("reconcile-state"), None)
      .await
      .expect("reconcile state");
    let sending =
      prepare_cli_delivery(&reconcile_state, "cli-reconcile-delivery", 1_200, None).await;
    let leased = prepare_cli_leased_run(&reconcile_state, "cli-reconcile-run", 1_300).await;
    for command in [
      SchedulerCommand::Runs {
        command: SchedulerRunsCommand::List {
          status: Some(SchedulerRunStatus::Leased),
          limit: 10,
          json: true,
        },
      },
      SchedulerCommand::Runs {
        command: SchedulerRunsCommand::Show {
          run_id: leased.binding.run_id().to_owned(),
          json: false,
        },
      },
      SchedulerCommand::Deliveries {
        command: SchedulerDeliveriesCommand::List {
          status: Some(SchedulerDeliveryStatus::Sending),
          limit: 10,
          json: true,
        },
      },
      SchedulerCommand::Deliveries {
        command: SchedulerDeliveriesCommand::Show {
          delivery_id: sending.delivery_id.clone(),
          json: false,
        },
      },
    ] {
      let diagnostic =
        execute_test_operator_command(command, reconcile_state.clone(), &verifier, 1_400)
          .await
          .expect("populated diagnostic");
      for rendered in [
        diagnostic.to_string(),
        format!("{diagnostic:?}"),
        render_scheduler_human(&diagnostic),
      ] {
        for forbidden in [
          "run-worker",
          "delivery-worker",
          "payload-",
          "C1",
          "authority-sentinel",
        ] {
          assert!(
            !rendered.contains(forbidden),
            "diagnostic leaked {forbidden}"
          );
        }
      }
    }
    let verifier_calls_before_dry_run = verifier.0.lock().expect("digests").len();
    let dry_run = execute_test_operator_command(
      SchedulerCommand::Reconcile {
        dry_run: true,
        apply: false,
        limit: 10,
        authority_file: None,
        json: true,
      },
      reconcile_state.clone(),
      &verifier,
      1_400,
    )
    .await
    .expect("plan exact reconcile");
    assert_eq!(
      dry_run["data"]["plan_digest"],
      sha256_hex(dry_run["data"]["plan"].to_string().as_bytes())
    );
    assert_eq!(
      verifier.0.lock().expect("digests").len(),
      verifier_calls_before_dry_run,
      "dry-run must not invoke mutation authority"
    );
    assert_eq!(
      reconcile_state
        .get_scheduled_run_operator_projection(leased.binding.run_id())
        .await
        .expect("read run after dry-run")
        .expect("run after dry-run")
        .state,
      ScheduledRunState::Leased
    );
    assert_eq!(
      reconcile_state
        .get_scheduled_delivery_operator_projection(&sending.delivery_id)
        .await
        .expect("read delivery after dry-run")
        .expect("delivery after dry-run")
        .state,
      ScheduledDeliveryState::Sending
    );
    let reconcile = SchedulerCommand::Reconcile {
      dry_run: false,
      apply: true,
      limit: 10,
      authority_file: Some(authority),
      json: true,
    };
    let output = execute_test_operator_command(reconcile, reconcile_state, &verifier, 1_400)
      .await
      .expect("apply exact reconcile");
    assert_eq!(
      output["data"]["plan_digest"],
      dry_run["data"]["plan_digest"]
    );
    assert_eq!(
      verifier
        .0
        .lock()
        .expect("digests")
        .last()
        .map(String::as_str),
      output["data"]["plan_digest"].as_str()
    );
    assert_eq!(
      output["data"]["run_results"][0]["run_id"],
      leased.binding.run_id()
    );
    assert_eq!(output["data"]["run_results"][0]["outcome"], "applied");
    assert_eq!(
      output["data"]["delivery_results"][0]["delivery_id"],
      sending.delivery_id
    );
    assert_eq!(output["data"]["delivery_results"][0]["outcome"], "applied");
    let text = output.to_string();
    for forbidden in [
      "authority-sentinel",
      "operator approved retry",
      "run-worker",
      "delivery-worker",
      "payload-",
    ] {
      assert!(!text.contains(forbidden), "leaked {forbidden}");
    }
  }

  #[tokio::test]
  #[allow(clippy::too_many_lines)]
  async fn trusted_local_control_plane_is_restart_safe_sanitized_and_owner_scoped() {
    let temp = tempfile::tempdir().expect("tempdir");
    let state_dir = temp.path().join("state");
    let create_file = temp.path().join("create.json");
    let update_file = temp.path().join("update.toml");
    let secret = "prompt-secret-sentinel Authorization: Bearer hidden";
    std::fs::write(
      &create_file,
      VALID_JSON.replace("inspect durable issues", secret),
    )
    .expect("create fixture");
    std::fs::write(
      &update_file,
      r#"
schema_version = 1
request_id = "request-update"
instruction = "updated private instruction"
capability = "none"

[schedule]
kind = "cron"
expression = "0 9 * * 1-5"
timezone = "Asia/Singapore"

[previous_success]
kind = "none"

[delivery]
kind = "none"
"#,
    )
    .expect("update fixture");
    let operator =
      SchedulerOperatorConfig::new("ops-a".to_owned(), "realm-a".to_owned()).expect("operator");
    let state = StateStore::initialize(&state_dir, None)
      .await
      .expect("state");

    let create_command = SchedulerCommand::Create {
      file: create_file.clone(),
      format: None,
    };
    assert!(!format!("{create_command:?}").contains(secret));
    let created =
      execute_scheduler_command(create_command.clone(), state.clone(), operator.clone(), 100)
        .await
        .expect("create");
    let job_id = created["data"]["job_id"]
      .as_str()
      .expect("job id")
      .to_owned();
    assert!(!created.to_string().contains(secret));
    assert_eq!(created["data"]["targets"]["items"][0]["kind"], "none");

    drop(state);
    let reopened = StateStore::initialize(&state_dir, None)
      .await
      .expect("reopened");
    let replay = execute_scheduler_command(create_command, reopened.clone(), operator.clone(), 100)
      .await
      .expect("exact replay");
    assert_eq!(replay, created);

    let conflicting_file = temp.path().join("conflicting.json");
    std::fs::write(
      &conflicting_file,
      VALID_JSON
        .replace("inspect durable issues", secret)
        .replace("latest_success", "none"),
    )
    .expect("conflicting fixture");
    let conflict = execute_scheduler_command(
      SchedulerCommand::Create {
        file: conflicting_file,
        format: None,
      },
      reopened.clone(),
      operator.clone(),
      100,
    )
    .await
    .expect_err("policy digest conflict");
    assert_eq!(conflict.0["error"]["code"], "idempotency_conflict");

    let unsupported_file = temp.path().join("unsupported.json");
    std::fs::write(
      &unsupported_file,
      VALID_JSON
        .replace("request-1", "unsupported-capability")
        .replace("\"capability\": \"none\"", "\"capability\": \"github\""),
    )
    .expect("unsupported fixture");
    let unsupported = execute_scheduler_command(
      SchedulerCommand::Create {
        file: unsupported_file,
        format: None,
      },
      reopened.clone(),
      operator.clone(),
      100,
    )
    .await
    .expect_err("unsupported capability");
    assert_eq!(unsupported.0["error"]["code"], "capability_unavailable");
    let unsupported_audit = reopened
      .list_schedule_audit_summaries("unsupported-capability")
      .await
      .expect("unsupported audit");
    assert_eq!(unsupported_audit.len(), 1);
    assert_eq!(unsupported_audit[0].outcome, "capability_unavailable");

    let got = execute_scheduler_command(
      SchedulerCommand::Get {
        job_id: job_id.clone(),
      },
      reopened.clone(),
      operator.clone(),
      100,
    )
    .await
    .expect("get");
    assert!(!got.to_string().contains(secret));
    assert!(got["data"]["definition"].get("instruction").is_none());
    assert_eq!(
      got["data"]["definition"]["previous_success"]["kind"],
      "latest_success"
    );

    let owner = PrincipalKey::new("operator", "local", "realm-a", "ops-a").expect("owner");
    let durable = reopened
      .get_scheduled_job_by_owner(&owner, &job_id)
      .await
      .expect("durable")
      .expect("job");
    let definition: Value =
      serde_json::from_str(durable.definition.canonical_json()).expect("definition");
    assert_eq!(durable.definition.version(), DEFINITION_VERSION_FOR_TESTS);
    assert_eq!(definition["schema_version"], DEFINITION_VERSION_FOR_TESTS);
    assert_eq!(definition["instruction"], secret);
    assert_eq!(definition["previous_success"]["kind"], "latest_success");
    let targets = reopened
      .get_scheduled_job_delivery_targets(&job_id)
      .await
      .expect("targets");
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].kind(), "none");
    assert_eq!(targets[0].address_json(), "{}");

    let other = SchedulerOperatorConfig::new("ops-b".to_owned(), "realm-a".to_owned())
      .expect("other operator");
    let hidden = execute_scheduler_command(
      SchedulerCommand::Get {
        job_id: job_id.clone(),
      },
      reopened.clone(),
      other,
      100,
    )
    .await
    .expect_err("cross-owner read must be hidden");
    assert_eq!(hidden.0["error"]["code"], "not_found_or_not_visible");

    let updated = execute_scheduler_command(
      SchedulerCommand::Update {
        job_id: job_id.clone(),
        file: update_file,
        format: None,
        generation: 0,
      },
      reopened.clone(),
      operator.clone(),
      100,
    )
    .await
    .expect("update");
    assert_eq!(updated["data"]["generation"], 1);

    let stale_error = execute_scheduler_command(
      SchedulerCommand::Pause {
        job_id: job_id.clone(),
        generation: 0,
        request_id: "pause-stale".to_owned(),
      },
      reopened.clone(),
      operator.clone(),
      100,
    )
    .await
    .expect_err("stale generation");
    assert_eq!(stale_error.0["error"]["code"], "stale_generation");

    for (command, expected_status, expected_generation) in [
      (
        SchedulerCommand::Pause {
          job_id: job_id.clone(),
          generation: 1,
          request_id: "pause-1".to_owned(),
        },
        "paused",
        2,
      ),
      (
        SchedulerCommand::Resume {
          job_id: job_id.clone(),
          generation: 2,
          request_id: "resume-1".to_owned(),
        },
        "active",
        3,
      ),
      (
        SchedulerCommand::Delete {
          job_id: job_id.clone(),
          generation: 3,
          request_id: "delete-1".to_owned(),
        },
        "deleted",
        4,
      ),
    ] {
      let output = execute_scheduler_command(command, reopened.clone(), operator.clone(), 100)
        .await
        .expect(expected_status);
      assert_eq!(output["data"]["status"], expected_status);
      assert_eq!(output["data"]["generation"], expected_generation);
    }
  }

  #[tokio::test]
  async fn cli_adapter_matches_direct_schedule_service_for_canonical_create() {
    let temp = tempfile::tempdir().expect("tempdir");
    let file = temp.path().join("request.json");
    std::fs::write(&file, VALID_JSON).expect("fixture");
    let operator =
      SchedulerOperatorConfig::new("ops-a".to_owned(), "realm-a".to_owned()).expect("operator");
    let cli_state = StateStore::initialize(&temp.path().join("cli-state"), None)
      .await
      .expect("cli state");
    let direct_state = StateStore::initialize(&temp.path().join("direct-state"), None)
      .await
      .expect("direct state");
    let cli = execute_scheduler_command(
      SchedulerCommand::Create { file, format: None },
      cli_state,
      operator.clone(),
      100,
    )
    .await
    .expect("CLI create");

    let request = decode_scheduler_mutation(
      Cursor::new(VALID_JSON.as_bytes()),
      SchedulerFileFormat::Json,
    )
    .expect("request");
    let service = build_scheduler_service(
      direct_state,
      &operator,
      std::sync::Arc::new(TargetResolverRegistry::with_defaults()),
    )
    .expect("service");
    let invocation = trusted_operator_invocation(&operator, &request.request_id);
    let direct = service
      .create(
        &invocation,
        CreateScheduleRequest {
          request_id: request.request_id,
          instruction: request.instruction,
          previous_success: request.previous_success,
          schedule: request.schedule,
          target: request.target,
          capability: request.capability,
          now: 100,
        },
      )
      .await
      .expect("direct create");
    assert_eq!(cli, direct);
  }

  #[tokio::test]
  async fn trusted_cli_uses_shared_slack_resolver_before_persisting_target() {
    let temp = tempfile::tempdir().expect("tempdir");
    let file = temp.path().join("slack-request.json");
    let source = VALID_JSON.replace(
      r#""delivery": {"kind": "none"}"#,
      r#""delivery": {"kind": "slack_channel", "channel_id": "C2"}"#,
    );
    std::fs::write(&file, source).expect("fixture");
    let operator =
      SchedulerOperatorConfig::new("ops-a".to_owned(), "realm-a".to_owned()).expect("operator");
    let state = StateStore::initialize(&temp.path().join("state"), None)
      .await
      .expect("state");
    let inspection = state.clone();
    let calls = Arc::new(AtomicUsize::new(0));
    let mut resolvers = TargetResolverRegistry::with_defaults();
    resolvers.register(VerifiedSlackTargetResolver::registration(
      Arc::new(CountingSlackVerifier(calls.clone())),
      Duration::from_millis(50),
    ));

    let output = execute_scheduler_command_with_resolvers(
      SchedulerCommand::Create { file, format: None },
      state,
      operator,
      Arc::new(resolvers),
      100,
    )
    .await
    .expect("CLI create");

    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let job_id = output["data"]["job_id"].as_str().expect("job id");
    let targets = inspection
      .get_scheduled_job_delivery_targets(job_id)
      .await
      .expect("targets");
    assert_eq!(targets[0].provider(), "slack");
    assert_eq!(targets[0].tenant(), "T00000000");
    assert!(targets[0].address_json().contains("\"channel_id\":\"C2\""));
  }

  fn slack_channel_invocation(kind: ConversationKind, channel_id: &str) -> ScheduleInvocation {
    let is_thread = kind == ConversationKind::Thread;
    ScheduleInvocation {
      source: InvocationSource::ChannelEvent {
        provider: "slack".to_owned(),
        workspace_id: "T00000000".to_owned(),
        event_id: "Ev-must-not-persist".to_owned(),
        dedupe_key: "dedupe-must-not-persist".to_owned(),
        source_reference: Some("slack://must-not-persist".to_owned()),
      },
      principal: InvocationPrincipal::channel_actor("slack", "T00000000", "U1"),
      channel: Some(ChannelTaskContext {
        provider: "slack".to_owned(),
        workspace_id: "T00000000".to_owned(),
        conversation_key: "event-pointer-must-not-persist".to_owned(),
        conversation_kind: kind,
        reply_strategy: ChannelReplyStrategy::DynamicTool,
        message_text: None,
        channel_id: Some(channel_id.to_owned()),
        thread_id: is_thread.then(|| "100.000000".to_owned()),
        message_ts: Some("999.000000".to_owned()),
        user_id: Some("U1".to_owned()),
        recent_context: None,
        conversation_summary: None,
      }),
    }
  }

  #[tokio::test]
  #[allow(clippy::too_many_lines)]
  async fn real_slack_adapter_origins_persist_exact_canonical_target_json_without_event_pointer() {
    for (kind, channel_id, responses, expected_kind, thread_ts, evidence_digest, request_digest) in [
      (
        ConversationKind::Channel,
        "C1",
        vec![
          slack_auth(),
          slack_user("U1"),
          slack_channel("C1", false),
          slack_members(),
        ],
        "channel",
        None,
        "a01e5610e60cec8e844b2bd06615abab3ef240a2ae09ada6a15e712ed697215e",
        "80688bb01e165963cc3560507fcc3680ee5bd1312d9ac4aee722895186b50074",
      ),
      (
        ConversationKind::DirectMessage,
        "D1",
        vec![slack_auth(), slack_user("U1"), slack_channel("D1", true)],
        "direct_message",
        None,
        "ce3da6525a8390ff7c25872b37c08e700d773ba0e6d8dd55e926cabc8d5762cd",
        "1ace3e7c55c7b1f14d4e8cb7340c4931bf37c58930d4d89a953dc7361821a29a",
      ),
      (
        ConversationKind::Thread,
        "C1",
        vec![
          slack_auth(),
          slack_user("U1"),
          slack_channel("C1", false),
          slack_members(),
          slack_response(
            r#"{"ok":true,"messages":[{"ts":"100.000000","thread_ts":"100.000000"}]}"#,
          ),
        ],
        "thread",
        Some("100.000000"),
        "ae95fe1a437f6a5195961596598fa41246dce29e1b4637d29a063f18d54d6677",
        "4c609f534a9d55e4efcbe7aea85e3f54e8a8d92a7da10c4547d080368b6dc137",
      ),
    ] {
      let temp = tempfile::tempdir().expect("tempdir");
      let state = StateStore::initialize(&temp.path().join("state"), None)
        .await
        .expect("state");
      let inspection = state.clone();
      let service = ScheduleService::with_components(
        state,
        real_slack_resolvers(responses),
        Arc::new(DefaultCapabilityRegistry),
        Arc::new(OwnerOnlyAuthorizationPolicy),
        Duration::from_millis(100),
      );
      let output = service
        .create(
          &slack_channel_invocation(kind, channel_id),
          CreateScheduleRequest {
            request_id: format!("origin-{expected_kind}"),
            instruction: "Resolve real Slack origin.".to_owned(),
            previous_success: PreviousSuccessPolicy::None,
            schedule: ScheduleSpec::once(500),
            target: DeliveryTargetRequest::Origin,
            capability: "none".to_owned(),
            now: 100,
          },
        )
        .await
        .expect("create");
      let job_id = output["data"]["job_id"].as_str().expect("job id");
      let target = inspection
        .get_scheduled_job_delivery_targets(job_id)
        .await
        .expect("target")
        .remove(0);
      let coordinates = thread_ts.map_or_else(
        || json!({"channel_id": channel_id}),
        |thread_ts| json!({"channel_id": channel_id, "thread_ts": thread_ts}),
      );
      assert_eq!(
        serde_json::from_str::<Value>(target.address_json()).expect("address"),
        json!({
          "schema_version": 1,
          "workspace_id": "T00000000",
          "routing_authority": {
            "team_id": "T00000000",
            "enterprise_id": "E00000000",
            "context_team_id": "T00000000",
            "conversation_host_id": "T00000000",
          },
          "coordinates": coordinates,
          "authorization_evidence": {"version": 2, "digest": evidence_digest},
          "requested_identity_digest": request_digest,
          "created_at": 100,
        })
      );
      assert_eq!(target.kind(), expected_kind);
      let route = target.delivery_route().expect("provider-neutral route");
      assert_eq!(route.provider(), "slack");
      assert_eq!(route.tenant(), "T00000000");
      assert_eq!(route.kind(), expected_kind);
      assert_eq!(route.conversation_id(), channel_id);
      assert_eq!(route.thread_id(), thread_ts);
      inspection
        .materialize_due_schedule(job_id, 0, 500)
        .await
        .expect("materialize real resolver schedule");
      let run = inspection
        .claim_next_scheduled_run("real-resolver-run", 501, 600)
        .await
        .expect("claim real resolver run")
        .expect("real resolver run");
      let profile = AttestedExecutionProfileSnapshot::new(1, "{}", "sha256-v1", "profile")
        .expect("execution profile");
      inspection
        .mark_scheduled_run_executing(&run.binding, &profile, 502)
        .await
        .expect("execute real resolver run");
      inspection
        .complete_scheduled_run_success(
          &run.binding,
          &ScheduledRunResult::new("resolved result", "").expect("result"),
          503,
        )
        .await
        .expect("complete real resolver run");
      let delivery_id = inspection
        .list_scheduled_delivery_operator_projections(None, 10)
        .await
        .expect("list real resolver delivery")
        .remove(0)
        .delivery_id;
      assert!(matches!(
        inspection
          .prepare_scheduled_delivery(
            &delivery_id,
            "text/plain; charset=utf-8",
            "resolved payload",
            1,
            504,
            SkippedNoneBaselinePolicy::DoNotAdvance,
          )
          .await
          .expect("prepare real resolver delivery"),
        PreparedScheduledDelivery::Pending(_)
      ));
      let delivery = inspection
        .claim_next_scheduled_delivery("real-resolver-delivery", 505, 600)
        .await
        .expect("claim real resolver delivery")
        .expect("real resolver delivery");
      inspection
        .complete_scheduled_delivery_failure(
          &delivery.binding,
          &ScheduledDeliveryFailure::AmbiguousPostWrite {
            error_kind: "provider_response_lost".to_owned(),
            redacted_message: None,
          },
          506,
        )
        .await
        .expect("record real resolver ambiguity");
      let receipt = json!({
        "conversation_id": channel_id,
        "message_id": format!("operator-{expected_kind}-message"),
        "provider": "slack",
        "receipt_version": 1,
        "target_kind": expected_kind,
        "tenant": "T00000000",
        "thread_id": thread_ts,
      })
      .to_string();
      let receipt_digest = sha256_hex(receipt.as_bytes());
      let operator_evidence = json!({
        "evidence_id": format!("real-resolver-{expected_kind}"),
        "evidence_version": 1,
        "kind": "provider_confirmed_delivered",
        "provider": "slack",
        "receipt_digest": receipt_digest,
        "provider_query_completed_at": 506,
        "provider_query_result": "write_confirmed",
        "provider_query_scope": "canonical_delivery_target",
        "provider_query_started_at": 505,
        "provider_query_summary_digest": sha256_hex(b"redacted-provider-query-summary"),
        "provider_query_window_end": 505,
        "provider_query_window_start": 500,
        "target_kind": expected_kind,
        "tenant": "T00000000",
      })
      .to_string();
      let operator_evidence_digest = sha256_hex(operator_evidence.as_bytes());
      let action = ScheduledDeliveryUnknownAction::ConfirmDelivered {
        provider_receipt: receipt,
        evidence_json: operator_evidence,
        evidence_digest: operator_evidence_digest,
      };
      let operator_request = SchedulerOperatorRequest::for_delivery_action(
        PrincipalKey::new("operator", "local", "ops", "reviewer").expect("operator"),
        format!("real-resolver-{expected_kind}"),
        delivery.binding.delivery_id(),
        delivery.binding.attempt(),
        delivery.binding.fence(),
        &action,
        507,
      )
      .expect("real resolver operator request");
      assert_eq!(
        inspection
          .operator_act_on_unknown_delivery(
            &operator_request,
            delivery.binding.delivery_id(),
            delivery.binding.attempt(),
            delivery.binding.fence(),
            &action,
          )
          .await
          .expect("confirm real resolver delivery"),
        SchedulerOperatorMutationOutcome::Applied
      );
      assert_eq!(
        inspection
          .list_scheduled_delivery_operator_projections(None, 10)
          .await
          .expect("read confirmed delivery")
          .remove(0)
          .state,
        ScheduledDeliveryState::Delivered
      );
      for forbidden in [
        "Ev-must-not-persist",
        "dedupe-must-not-persist",
        "slack://must-not-persist",
        "event-pointer-must-not-persist",
        "999.000000",
      ] {
        assert!(!target.address_json().contains(forbidden));
      }
    }
  }

  #[tokio::test]
  async fn slack_dynamic_tool_and_cli_share_real_provider_canonical_identity() {
    let temp = tempfile::tempdir().expect("tempdir");
    let cli_file = temp.path().join("slack-cli.json");
    std::fs::write(
      &cli_file,
      VALID_JSON.replace(
        r#""delivery": {"kind": "none"}"#,
        r#""delivery": {"kind": "slack_channel", "channel_id": "C2"}"#,
      ),
    )
    .expect("fixture");
    let cli_state = StateStore::initialize(&temp.path().join("cli"), None)
      .await
      .expect("CLI state");
    let cli_inspection = cli_state.clone();
    let cli_output = execute_scheduler_command_with_resolvers(
      SchedulerCommand::Create {
        file: cli_file,
        format: None,
      },
      cli_state,
      SchedulerOperatorConfig::new("ops-a".to_owned(), "realm-a".to_owned()).expect("operator"),
      real_slack_resolvers(vec![slack_auth(), slack_channel("C2", false)]),
      100,
    )
    .await
    .expect("CLI");
    let cli_target = cli_inspection
      .get_scheduled_job_delivery_targets(cli_output["data"]["job_id"].as_str().expect("job"))
      .await
      .expect("CLI target")
      .remove(0);

    let tool_state = StateStore::initialize(&temp.path().join("tool"), None)
      .await
      .expect("tool state");
    let tool_inspection = tool_state.clone();
    let tool_service = ScheduleService::with_components(
      tool_state,
      real_slack_resolvers(vec![
        slack_auth(),
        slack_user("U1"),
        slack_channel("C2", false),
        slack_members(),
      ]),
      Arc::new(DefaultCapabilityRegistry),
      Arc::new(OwnerOnlyAuthorizationPolicy),
      Duration::from_millis(100),
    );
    let handler = ScheduleDynamicToolHandler::from_service(tool_service, Some(100));
    let output = handler
      .handle_tool_call_async(
        &slack_channel_invocation(ConversationKind::Channel, "C1"),
        "schedule_create",
        json!({
          "request_id": "tool-create",
          "instruction": "Compare canonical providers.",
          "schedule": {"kind": "once", "at": 500},
          "target": {"kind": "channel", "channel_id": "C2"},
          "capability": "none",
        }),
      )
      .await;
    assert_eq!(output["success"], true, "{output}");
    let envelope: Value =
      serde_json::from_str(output["contentItems"][0]["text"].as_str().expect("content"))
        .expect("envelope");
    let tool_target = tool_inspection
      .get_scheduled_job_delivery_targets(envelope["data"]["job_id"].as_str().expect("tool job"))
      .await
      .expect("tool target")
      .remove(0);
    assert_eq!(cli_target.identity_digest(), tool_target.identity_digest());
    assert_eq!(cli_target.provider(), tool_target.provider());
    assert_eq!(cli_target.connector(), tool_target.connector());
    assert_eq!(cli_target.tenant(), tool_target.tenant());
    assert_eq!(cli_target.kind(), tool_target.kind());
    let stable_projection = |target: &codeoff_state::DeliveryTargetSnapshot| {
      let address: Value = serde_json::from_str(target.address_json()).expect("address");
      json!({
        "workspace_id": address["workspace_id"],
        "routing_authority": address["routing_authority"],
        "coordinates": address["coordinates"],
      })
    };
    assert_eq!(
      stable_projection(&cli_target),
      stable_projection(&tool_target)
    );
  }
}
