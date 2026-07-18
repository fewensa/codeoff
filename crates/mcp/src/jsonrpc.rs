use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::tools::{ChannelToolDispatcher, ToolCallError};

const JSONRPC_VERSION: &str = "2.0";
const PROTOCOL_VERSION: &str = "2024-11-05";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonRpcRequest {
  pub jsonrpc: String,
  pub id: Option<Value>,
  pub method: String,
  pub params: Option<Value>,
}

pub struct JsonRpcDispatcher<'a> {
  tools: &'a ChannelToolDispatcher<'a>,
}

impl<'a> JsonRpcDispatcher<'a> {
  #[must_use]
  pub const fn new(tools: &'a ChannelToolDispatcher<'a>) -> Self {
    Self { tools }
  }

  pub async fn handle(&self, request: JsonRpcRequest) -> Option<Value> {
    let Some(id) = request.id else {
      return None;
    };

    Some(match request.method.as_str() {
      "initialize" => response(
        id,
        json!({
          "protocolVersion": PROTOCOL_VERSION,
          "serverInfo": {
            "name": "codeoff-mcp",
            "version": env!("CARGO_PKG_VERSION"),
          },
          "capabilities": {
            "tools": {}
          }
        }),
      ),
      "tools/list" => response(
        id,
        json!({
          "tools": self.tools.list_tools()
        }),
      ),
      "tools/call" => match self.tools.call(request.params).await {
        Ok(result) => response(id, result),
        Err(error) => error_response(id, error),
      },
      _ => error_response(
        id,
        ToolCallError::MethodNotFound {
          method: request.method,
        },
      ),
    })
  }
}

fn response(id: Value, result: Value) -> Value {
  json!({
    "jsonrpc": JSONRPC_VERSION,
    "id": id,
    "result": result,
  })
}

fn error_response(id: Value, error: ToolCallError) -> Value {
  let (code, message, data) = error.into_json_rpc_parts();
  json!({
    "jsonrpc": JSONRPC_VERSION,
    "id": id,
    "error": {
      "code": code,
      "message": message,
      "data": data,
    },
  })
}
