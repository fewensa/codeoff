use serde_json::{Value, json};

pub const SCHEDULE_CONTRACT_VERSION: u32 = 1;

pub(crate) fn success_envelope(data: Value) -> Value {
  json!({
    "schema_version": SCHEDULE_CONTRACT_VERSION,
    "ok": true,
    "data": data,
  })
}

pub(crate) fn error_envelope(code: &str, retryable: bool, message: &str, details: Value) -> Value {
  json!({
    "schema_version": SCHEDULE_CONTRACT_VERSION,
    "ok": false,
    "error": {
      "schema_version": SCHEDULE_CONTRACT_VERSION,
      "code": code,
      "retryable": retryable,
      "message": message,
      "details": details,
    },
  })
}
