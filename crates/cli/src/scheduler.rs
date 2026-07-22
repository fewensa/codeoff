use std::env;
use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use chrono::DateTime;
use codeoff_agent_contract::{InvocationPrincipal, InvocationSource};
use codeoff_runtime::schedule_service::{
  ConfiguredOperatorIdentityPolicy, CreateScheduleRequest, DefaultCapabilityRegistry,
  DeliveryTargetRequest, LifecycleScheduleRequest, OperatorAuthorizationPolicy,
  PreviousSuccessPolicy, ScheduleInvocation, ScheduleService, ScheduleServiceError,
  TargetResolverRegistry, UpdateScheduleRequest,
};
use codeoff_state::{ScheduleSpec, ScheduledJobStatus, StateStore};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::command::{SchedulerCommand, SchedulerFileFormat};

const SCHEDULER_REQUEST_SCHEMA_VERSION: u32 = 1;
const MAX_SCHEDULER_REQUEST_BYTES: u64 = 128 * 1024;
const OPERATOR_ID_ENV: &str = "CODEOFF_SCHEDULER_OPERATOR_ID";
const OPERATOR_REALM_ENV: &str = "CODEOFF_SCHEDULER_OPERATOR_REALM";

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
pub(crate) async fn execute_scheduler_command_with_resolvers(
  command: SchedulerCommand,
  state: StateStore,
  operator: SchedulerOperatorConfig,
  target_resolvers: std::sync::Arc<TargetResolverRegistry>,
  now: i64,
) -> Result<Value, SchedulerCommandError> {
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
  }
  .map_err(|error| SchedulerCommandError::service(&error))?;
  Ok(sanitize_output(result))
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
    AttestedExecutionProfileSnapshot, PreparedScheduledDelivery, PrincipalKey,
    ScheduledDeliveryFailure, ScheduledDeliveryState, ScheduledDeliveryUnknownAction,
    ScheduledRunResult, SchedulerOperatorMutationOutcome, SchedulerOperatorRequest,
    SkippedNoneBaselinePolicy,
  };
  use std::io::Cursor;
  use std::sync::atomic::{AtomicUsize, Ordering};
  use std::sync::{Arc, Mutex};
  use std::time::Duration;

  struct CountingSlackVerifier(Arc<AtomicUsize>);

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
      let (receipt_digest, operator_evidence_digest) = match expected_kind {
        "channel" => (
          "e56ebe0615616be029fe6affbf10eae04563718f089002c65794756a4762f535",
          "bac34051ce5ed63dcc66dc15c17ea73c3050b5a05b3f3e04deeb75c1466d1112",
        ),
        "direct_message" => (
          "55258902520189aede7485035ced4b0e63a48a144479006cc457b1f80d87424c",
          "522b9e4fc386aec5958c5d5a91bbe77aba68e6dc9bb8d157897d3a10b09c2eff",
        ),
        "thread" => (
          "f62298ae6787508f5e0ae7e9908d4a2e7c1344572100a22db98831e93b03a46f",
          "1380f082082a6101d1a2a7e6b3a6ca0a229a747dc23b9aea00975c8a8a0a2c1c",
        ),
        _ => unreachable!(),
      };
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
      let operator_evidence = json!({
        "evidence_id": format!("real-resolver-{expected_kind}"),
        "evidence_version": 1,
        "kind": "provider_confirmed_delivered",
        "provider": "slack",
        "receipt_digest": receipt_digest,
        "target_kind": expected_kind,
        "tenant": "T00000000",
      })
      .to_string();
      let action = ScheduledDeliveryUnknownAction::ConfirmDelivered {
        provider_receipt: receipt,
        evidence_json: operator_evidence,
        evidence_digest: operator_evidence_digest.to_owned(),
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
