//! MCP JSON-RPC boundary for Codeoff.
#![allow(
  clippy::missing_errors_doc,
  clippy::needless_pass_by_value,
  clippy::question_mark,
  clippy::struct_field_names,
  clippy::too_many_lines
)]

mod jsonrpc;
mod server;
mod tools;

pub use jsonrpc::{JsonRpcDispatcher, JsonRpcRequest};
pub use server::McpTcpServer;
pub use tools::ChannelToolDispatcher;
