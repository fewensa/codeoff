use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use codeoff_state::{ScheduleSpec, ScheduledJobStatus, StateStore};
use serde_json::{Map, Value, json};

use crate::schedule_service::{
  CreateScheduleRequest, DeliveryTargetRequest, LifecycleScheduleRequest, ScheduleInvocation,
  ScheduleService, UpdateScheduleRequest,
};

pub const SCHEDULE_DYNAMIC_TOOL_NAMES: &[&str] = &[
  "schedule_create",
  "schedule_get",
  "schedule_list",
  "schedule_update",
  "schedule_pause",
  "schedule_resume",
  "schedule_delete",
];

#[derive(Clone)]
pub struct ScheduleDynamicToolHandler {
  service: ScheduleService,
  now: Option<i64>,
}

impl ScheduleDynamicToolHandler {
  #[must_use]
  pub fn new(state: StateStore) -> Self {
    Self {
      service: ScheduleService::new(state),
      now: None,
    }
  }

  #[must_use]
  pub fn new_with_now(state: StateStore, now: i64) -> Self {
    Self {
      service: ScheduleService::new(state),
      now: Some(now),
    }
  }

  #[must_use]
  pub fn tool_specs(&self) -> Vec<Value> {
    vec![
      tool_spec(
        "schedule_create",
        "Create an owner-scoped durable schedule.",
        create_schema(),
      ),
      tool_spec(
        "schedule_get",
        "Read one owner-scoped schedule.",
        job_schema(),
      ),
      tool_spec(
        "schedule_list",
        "List owner-scoped schedules by status.",
        list_schema(),
      ),
      tool_spec(
        "schedule_update",
        "Replace one owner-scoped schedule using generation CAS.",
        update_schema(),
      ),
      tool_spec(
        "schedule_pause",
        "Pause one owner-scoped schedule using generation CAS.",
        lifecycle_schema(),
      ),
      tool_spec(
        "schedule_resume",
        "Resume one owner-scoped schedule using generation CAS.",
        lifecycle_schema(),
      ),
      tool_spec(
        "schedule_delete",
        "Soft-delete one owner-scoped schedule using generation CAS.",
        lifecycle_schema(),
      ),
    ]
  }

  pub async fn handle_tool_call_async(
    &self,
    invocation: &ScheduleInvocation,
    tool: &str,
    arguments: Value,
  ) -> Value {
    let result = match tool {
      "schedule_create" => self.create(invocation, arguments).await,
      "schedule_get" => self.get(invocation, arguments).await,
      "schedule_list" => self.list(invocation, arguments).await,
      "schedule_update" => self.update(invocation, arguments).await,
      "schedule_pause" => self.lifecycle(invocation, arguments, "pause").await,
      "schedule_resume" => self.lifecycle(invocation, arguments, "resume").await,
      "schedule_delete" => self.lifecycle(invocation, arguments, "delete").await,
      _ => Err(format!("unsupported dynamic tool: {tool}")),
    };
    match result {
      Ok(content) => success(content),
      Err(error) => failure(error),
    }
  }

  async fn create(
    &self,
    invocation: &ScheduleInvocation,
    arguments: Value,
  ) -> Result<Value, String> {
    let object = object(arguments)?;
    reject_unknown(
      &object,
      &[
        "request_id",
        "instruction",
        "schedule",
        "target",
        "capability",
      ],
    )?;
    self
      .service
      .create(
        invocation,
        CreateScheduleRequest {
          request_id: string(&object, "request_id")?,
          instruction: string(&object, "instruction")?,
          schedule: schedule(object.get("schedule").ok_or("missing schedule")?)?,
          target: target(object.get("target").ok_or("missing target")?)?,
          capability: optional_string(&object, "capability")?.unwrap_or_else(|| "none".to_owned()),
          now: self.now(),
        },
      )
      .await
      .map_err(|error| error.to_string())
  }

  async fn update(
    &self,
    invocation: &ScheduleInvocation,
    arguments: Value,
  ) -> Result<Value, String> {
    let object = object(arguments)?;
    reject_unknown(
      &object,
      &[
        "request_id",
        "job_id",
        "expected_generation",
        "instruction",
        "schedule",
        "target",
        "capability",
      ],
    )?;
    self
      .service
      .update(
        invocation,
        UpdateScheduleRequest {
          request_id: string(&object, "request_id")?,
          job_id: string(&object, "job_id")?,
          expected_generation: integer(&object, "expected_generation")?,
          instruction: string(&object, "instruction")?,
          schedule: schedule(object.get("schedule").ok_or("missing schedule")?)?,
          target: target(object.get("target").ok_or("missing target")?)?,
          capability: optional_string(&object, "capability")?.unwrap_or_else(|| "none".to_owned()),
          now: self.now(),
        },
      )
      .await
      .map_err(|error| error.to_string())
  }

  async fn get(&self, invocation: &ScheduleInvocation, arguments: Value) -> Result<Value, String> {
    let object = object(arguments)?;
    reject_unknown(&object, &["job_id"])?;
    self
      .service
      .get(invocation, &string(&object, "job_id")?)
      .await
      .map_err(|error| error.to_string())
  }

  async fn list(&self, invocation: &ScheduleInvocation, arguments: Value) -> Result<Value, String> {
    let object = object(arguments)?;
    reject_unknown(&object, &["status", "cursor", "limit"])?;
    let status = match optional_string(&object, "status")?
      .as_deref()
      .unwrap_or("active")
    {
      "active" => ScheduledJobStatus::Active,
      "paused" => ScheduledJobStatus::Paused,
      "completed" => ScheduledJobStatus::Completed,
      "deleted" => ScheduledJobStatus::Deleted,
      value => return Err(format!("invalid status: {value}")),
    };
    let cursor = optional_string(&object, "cursor")?;
    let limit = object.get("limit").map_or(Ok(50), |value| {
      value
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| "limit must be an unsigned integer".to_owned())
    })?;
    let page = self
      .service
      .list(invocation, status, cursor.as_deref(), limit)
      .await
      .map_err(|error| error.to_string())?;
    Ok(json!({"job_ids": page.job_ids, "next_cursor": page.next_cursor}))
  }

  async fn lifecycle(
    &self,
    invocation: &ScheduleInvocation,
    arguments: Value,
    operation: &str,
  ) -> Result<Value, String> {
    let object = object(arguments)?;
    reject_unknown(&object, &["request_id", "job_id", "expected_generation"])?;
    let request = LifecycleScheduleRequest {
      request_id: string(&object, "request_id")?,
      job_id: string(&object, "job_id")?,
      expected_generation: integer(&object, "expected_generation")?,
      now: self.now(),
    };
    match operation {
      "pause" => self.service.pause(invocation, request).await,
      "resume" => self.service.resume(invocation, request).await,
      "delete" => self.service.delete(invocation, request).await,
      _ => unreachable!("bounded lifecycle operation"),
    }
    .map_err(|error| error.to_string())
  }

  fn now(&self) -> i64 {
    self.now.unwrap_or_else(|| {
      i64::try_from(
        SystemTime::now()
          .duration_since(UNIX_EPOCH)
          .unwrap_or_default()
          .as_secs(),
      )
      .unwrap_or(i64::MAX)
    })
  }
}

fn tool_spec(name: &str, description: &str, input_schema: Value) -> Value {
  json!({"name": name, "description": description, "inputSchema": input_schema})
}

fn create_schema() -> Value {
  json!({
    "type": "object",
    "additionalProperties": false,
    "required": ["request_id", "instruction", "schedule", "target"],
    "properties": {
      "request_id": bounded_string_schema(),
      "instruction": {"type": "string", "minLength": 1, "maxLength": 65536},
      "schedule": schedule_schema(),
      "target": target_schema(),
      "capability": {"type": "string", "enum": ["none"]}
    }
  })
}

fn update_schema() -> Value {
  let mut schema = create_schema();
  schema["required"] = json!([
    "request_id",
    "job_id",
    "expected_generation",
    "instruction",
    "schedule",
    "target"
  ]);
  schema["properties"]["job_id"] = bounded_string_schema();
  schema["properties"]["expected_generation"] = json!({"type": "integer", "minimum": 0});
  schema
}

fn lifecycle_schema() -> Value {
  json!({
    "type": "object",
    "additionalProperties": false,
    "required": ["request_id", "job_id", "expected_generation"],
    "properties": {
      "request_id": bounded_string_schema(),
      "job_id": bounded_string_schema(),
      "expected_generation": {"type": "integer", "minimum": 0}
    }
  })
}

fn job_schema() -> Value {
  json!({"type": "object", "additionalProperties": false, "required": ["job_id"], "properties": {"job_id": bounded_string_schema()}})
}

fn list_schema() -> Value {
  json!({
    "type": "object",
    "additionalProperties": false,
    "properties": {
      "status": {"type": "string", "enum": ["active", "paused", "completed", "deleted"]},
      "cursor": bounded_string_schema(),
      "limit": {"type": "integer", "minimum": 1, "maximum": 100}
    }
  })
}

fn schedule_schema() -> Value {
  json!({
    "oneOf": [
      {"type": "object", "additionalProperties": false, "required": ["kind", "at"], "properties": {"kind": {"const": "once"}, "at": {"type": "integer"}}},
      {"type": "object", "additionalProperties": false, "required": ["kind", "anchor", "every_seconds"], "properties": {"kind": {"const": "fixed_interval"}, "anchor": {"type": "integer"}, "every_seconds": {"type": "integer", "minimum": 1}}},
      {"type": "object", "additionalProperties": false, "required": ["kind", "expression", "timezone"], "properties": {"kind": {"const": "cron"}, "expression": bounded_string_schema(), "timezone": bounded_string_schema()}}
    ]
  })
}

fn target_schema() -> Value {
  json!({
    "oneOf": [
      {"type": "object", "additionalProperties": false, "required": ["kind"], "properties": {"kind": {"const": "none"}}},
      {"type": "object", "additionalProperties": false, "required": ["kind"], "properties": {"kind": {"const": "origin"}}},
      {"type": "object", "additionalProperties": false, "required": ["kind", "channel_id"], "properties": {"kind": {"const": "channel"}, "channel_id": bounded_string_schema()}},
      {"type": "object", "additionalProperties": false, "required": ["kind", "user_id"], "properties": {"kind": {"const": "direct_message"}, "user_id": bounded_string_schema()}},
      {"type": "object", "additionalProperties": false, "required": ["kind", "channel_id", "thread_id"], "properties": {"kind": {"const": "thread"}, "channel_id": bounded_string_schema(), "thread_id": bounded_string_schema()}}
    ]
  })
}

fn bounded_string_schema() -> Value {
  json!({"type": "string", "minLength": 1, "maxLength": 255})
}

fn schedule(value: &Value) -> Result<ScheduleSpec, String> {
  let object = value.as_object().ok_or("schedule must be an object")?;
  match string(object, "kind")?.as_str() {
    "once" => {
      reject_unknown(object, &["kind", "at"])?;
      Ok(ScheduleSpec::once(integer(object, "at")?))
    }
    "fixed_interval" => {
      reject_unknown(object, &["kind", "anchor", "every_seconds"])?;
      ScheduleSpec::fixed_interval(
        integer(object, "anchor")?,
        integer(object, "every_seconds")?,
      )
      .map_err(|error| error.to_string())
    }
    "cron" => {
      reject_unknown(object, &["kind", "expression", "timezone"])?;
      ScheduleSpec::cron(&string(object, "expression")?, &string(object, "timezone")?)
        .map_err(|error| error.to_string())
    }
    kind => Err(format!("invalid schedule kind: {kind}")),
  }
}

fn target(value: &Value) -> Result<DeliveryTargetRequest, String> {
  let object = value.as_object().ok_or("target must be an object")?;
  match string(object, "kind")?.as_str() {
    "none" => {
      reject_unknown(object, &["kind"])?;
      Ok(DeliveryTargetRequest::None)
    }
    "origin" => {
      reject_unknown(object, &["kind"])?;
      Ok(DeliveryTargetRequest::Origin)
    }
    "channel" => {
      reject_unknown(object, &["kind", "channel_id"])?;
      Ok(DeliveryTargetRequest::Channel {
        channel_id: string(object, "channel_id")?,
      })
    }
    "direct_message" => {
      reject_unknown(object, &["kind", "user_id"])?;
      Ok(DeliveryTargetRequest::DirectMessage {
        user_id: string(object, "user_id")?,
      })
    }
    "thread" => {
      reject_unknown(object, &["kind", "channel_id", "thread_id"])?;
      Ok(DeliveryTargetRequest::Thread {
        channel_id: string(object, "channel_id")?,
        thread_id: string(object, "thread_id")?,
      })
    }
    kind => Err(format!("invalid target kind: {kind}")),
  }
}

fn object(value: Value) -> Result<Map<String, Value>, String> {
  value
    .as_object()
    .cloned()
    .ok_or_else(|| "tool arguments must be an object".to_owned())
}

fn reject_unknown(object: &Map<String, Value>, allowed: &[&str]) -> Result<(), String> {
  let allowed = allowed.iter().copied().collect::<HashSet<_>>();
  if let Some(key) = object.keys().find(|key| !allowed.contains(key.as_str())) {
    return Err(format!("unknown field: {key}"));
  }
  Ok(())
}

fn string(object: &Map<String, Value>, field: &str) -> Result<String, String> {
  object
    .get(field)
    .and_then(Value::as_str)
    .map(ToOwned::to_owned)
    .ok_or_else(|| format!("{field} must be a string"))
}

fn optional_string(object: &Map<String, Value>, field: &str) -> Result<Option<String>, String> {
  object.get(field).map(|_| string(object, field)).transpose()
}

fn integer(object: &Map<String, Value>, field: &str) -> Result<i64, String> {
  object
    .get(field)
    .and_then(Value::as_i64)
    .ok_or_else(|| format!("{field} must be an integer"))
}

fn success(content: Value) -> Value {
  json!({"success": true, "contentItems": [{"type": "inputText", "text": content.to_string()}]})
}

fn failure(message: impl Into<String>) -> Value {
  json!({"success": false, "contentItems": [{"type": "inputText", "text": message.into()}]})
}
