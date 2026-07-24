//! Codex App Server backend wiring for Codeoff.

mod scheduled;
#[cfg(unix)]
mod scheduled_artifacts;
mod scheduled_mcp;

pub use codeoff_core::AttestedCapabilityProfile;
#[cfg(unix)]
pub use scheduled::enable_scheduled_executor_subreaper;
pub use scheduled::{
  BuiltScheduledCodexExecutor, CODEX_APP_SERVER_SCHEMA_SHA256, CODEX_CLI_VERSION,
  GITHUB_MCP_ACCESS_TOKEN_ENV, GITHUB_MCP_ARTIFACT_SHA256_ARM64, GITHUB_MCP_ARTIFACT_SHA256_X86_64,
  GITHUB_MCP_SERVER_VERSION, PreparedScheduledCodexExecution, ProcessExit,
  RemoteIsolationPermitEnvelope, RequestedCapabilityProfile, ScheduledCodexExecution,
  ScheduledCodexExecutor, ScheduledCodexRequest, ScheduledDeploymentAuthority,
  ScheduledExecutionIdentity, ScheduledExecutionResult, ScheduledFailure, ScheduledFailureKind,
  ScheduledFinalOutput, ScheduledIsolationPermit, ScheduledJsonlTransport,
  ScheduledRuntimeEvidence, ScheduledUsage, TimedRead, build_production_scheduled_codex_executor,
  build_supervised_scheduled_codex_executor, load_current_scheduled_deployment_authority,
  load_trusted_owner_scheduled_deployment_authority, prepare_scheduled_codex_home,
};

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use codeoff_agent_contract::{
  AgentBackend, AgentTask, AgentTaskResult, ChannelReplyStrategy, ChannelTaskContext,
  InvocationPrincipal, InvocationSource, SessionMode, ToolPolicy,
};
use codeoff_config::CodeoffConfig;
use serde_json::{Value, json};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodexAppServerRequest {
  pub conversation_id: String,
  pub resume_thread_id: Option<String>,
  pub prompt: String,
  pub tool_policy: ToolPolicy,
  pub dynamic_tool_context: CodexDynamicToolContext,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodexDynamicToolContext {
  pub source: InvocationSource,
  pub principal: InvocationPrincipal,
  pub channel: Option<ChannelTaskContext>,
}

const DEFAULT_MAX_PROMPT_BYTES: usize = 64 * 1024;
const DEFAULT_PREVIOUS_SUCCESS_CONTEXT_MAX_BYTES: usize = 8 * 1024;
const TRUNCATION_MARKER: &str = "\n[truncated]";

/// Transport seam for the Codex App Server JSON-RPC client.
///
/// The process protocol deliberately remains behind this trait so the runtime does not depend on
/// Codex-specific transport details and tests need no credentials or running server.
pub trait CodexAppServerClient {
  /// Starts or resumes one Codex App Server turn.
  ///
  /// # Errors
  ///
  /// Returns an error when the Codex App Server transport fails or reports a terminal turn error.
  fn start_turn(&self, request: &CodexAppServerRequest) -> Result<AgentTaskResult, String>;
}

/// Builds a stdio Codex App Server backend from configuration.
///
/// # Errors
///
/// Returns an error when the configured transport or command is unsupported.
pub fn build_codex_app_server_backend(
  config: &CodeoffConfig,
) -> Result<CodexAppServerBackend<StdioCodexAppServerClient>, String> {
  build_codex_app_server_backend_with_dynamic_tool_handler(config, NoopCodexDynamicToolHandler)
}

/// Builds a stdio Codex App Server backend with a dynamic tool handler.
///
/// # Errors
///
/// Returns an error when the configured transport or command is unsupported.
pub fn build_codex_app_server_backend_with_dynamic_tool_handler<H>(
  config: &CodeoffConfig,
  dynamic_tool_handler: H,
) -> Result<CodexAppServerBackend<StdioCodexAppServerClient<H>>, String>
where
  H: CodexDynamicToolHandler,
{
  let codex = &config.agent.codex_app_server;
  if codex.transport != "stdio" {
    return Err(format!(
      "unsupported codex app server transport: {} (only stdio is supported)",
      codex.transport
    ));
  }
  if codex.command.trim().is_empty() {
    return Err("codex app server command must not be empty".to_owned());
  }

  Ok(
    CodexAppServerBackend::new(StdioCodexAppServerClient::with_dynamic_tool_handler(
      codex.command.clone(),
      codex.ephemeral_threads,
      dynamic_tool_handler,
    ))
    .with_prompt_limits(
      codex.max_prompt_bytes,
      codex.previous_success_context_max_bytes,
    ),
  )
}

pub trait JsonlTransport {
  /// Writes one JSON-RPC message.
  ///
  /// # Errors
  ///
  /// Returns an error when the transport cannot serialize or write the message.
  fn write_json(&mut self, value: Value) -> Result<(), String>;

  /// Reads one JSON-RPC message.
  ///
  /// # Errors
  ///
  /// Returns an error when the transport cannot read or parse the next message.
  fn read_json(&mut self) -> Result<Value, String>;
}

pub trait CodexDynamicToolHandler {
  fn tool_specs(&self, context: &CodexDynamicToolContext) -> Vec<Value>;

  fn handle_tool_call(
    &self,
    context: &CodexDynamicToolContext,
    tool: &str,
    arguments: Value,
  ) -> Value;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodexTurnEvent {
  AgentMessageStarted(CodexAgentMessageStartedEvent),
  AgentMessageDelta(CodexAgentMessageDeltaEvent),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodexAgentMessageStartedEvent {
  pub thread_id: String,
  pub turn_id: String,
  pub item_id: String,
  pub phase: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodexAgentMessageDeltaEvent {
  pub thread_id: String,
  pub turn_id: String,
  pub item_id: String,
  pub phase: Option<String>,
  pub delta: String,
}

pub trait CodexTurnEventObserver {
  fn observe_codex_turn_event(&self, event: CodexTurnEvent);
}

#[derive(Debug, Clone, Copy, Default)]
pub struct NoopCodexTurnEventObserver;

impl CodexTurnEventObserver for NoopCodexTurnEventObserver {
  fn observe_codex_turn_event(&self, _event: CodexTurnEvent) {}
}

#[derive(Debug, Clone, Copy, Default)]
pub struct NoopCodexDynamicToolHandler;

impl CodexDynamicToolHandler for NoopCodexDynamicToolHandler {
  fn tool_specs(&self, _context: &CodexDynamicToolContext) -> Vec<Value> {
    Vec::new()
  }

  fn handle_tool_call(
    &self,
    _context: &CodexDynamicToolContext,
    tool: &str,
    _arguments: Value,
  ) -> Value {
    dynamic_tool_failure(format!("unsupported dynamic tool: {tool}"))
  }
}

pub struct StdioJsonlTransport {
  child: Child,
  stdin: ChildStdin,
  stdout: BufReader<ChildStdout>,
}

impl StdioJsonlTransport {
  /// Spawns a stdio JSONL transport using the configured Codex App Server command.
  ///
  /// # Errors
  ///
  /// Returns an error when the process cannot be started or stdio cannot be captured.
  pub fn spawn(command: &str) -> Result<Self, String> {
    let mut child = Command::new("sh")
      .arg("-c")
      .arg(command)
      .stdin(Stdio::piped())
      .stdout(Stdio::piped())
      .stderr(Stdio::null())
      .spawn()
      .map_err(|error| format!("failed to start codex app server: {error}"))?;
    let stdin = child
      .stdin
      .take()
      .ok_or_else(|| "codex app server stdin unavailable".to_owned())?;
    let stdout = child
      .stdout
      .take()
      .ok_or_else(|| "codex app server stdout unavailable".to_owned())?;
    Ok(Self {
      child,
      stdin,
      stdout: BufReader::new(stdout),
    })
  }
}

impl Drop for StdioJsonlTransport {
  fn drop(&mut self) {
    let _ = self.child.kill();
    let _ = self.child.wait();
  }
}

impl JsonlTransport for StdioJsonlTransport {
  fn write_json(&mut self, value: Value) -> Result<(), String> {
    let mut line = serde_json::to_vec(&value)
      .map_err(|error| format!("failed to encode codex app server request: {error}"))?;
    line.push(b'\n');
    self
      .stdin
      .write_all(&line)
      .map_err(|error| format!("failed to write codex app server request: {error}"))?;
    self
      .stdin
      .flush()
      .map_err(|error| format!("failed to flush codex app server request: {error}"))
  }

  fn read_json(&mut self) -> Result<Value, String> {
    let mut line = String::new();
    let bytes = self
      .stdout
      .read_line(&mut line)
      .map_err(|error| format!("failed to read codex app server response: {error}"))?;
    if bytes == 0 {
      return Err("codex app server closed stdout".to_owned());
    }
    serde_json::from_str(&line)
      .map_err(|error| format!("failed to decode codex app server response: {error}"))
  }
}

pub struct CodexAppServerJsonlClient<F, O = NoopCodexTurnEventObserver> {
  transport_factory: F,
  ephemeral_threads: bool,
  dynamic_tool_handler: NoopCodexDynamicToolHandler,
  event_observer: O,
}

impl<F> CodexAppServerJsonlClient<F> {
  #[must_use]
  pub fn new(transport_factory: F, ephemeral_threads: bool) -> Self {
    Self {
      transport_factory,
      ephemeral_threads,
      dynamic_tool_handler: NoopCodexDynamicToolHandler,
      event_observer: NoopCodexTurnEventObserver,
    }
  }
}

impl<F, O> CodexAppServerJsonlClient<F, O> {
  #[must_use]
  pub fn with_dynamic_tool_handler<H>(
    self,
    dynamic_tool_handler: H,
  ) -> CodexAppServerJsonlClientWithTools<F, H, O> {
    CodexAppServerJsonlClientWithTools {
      transport_factory: self.transport_factory,
      ephemeral_threads: self.ephemeral_threads,
      dynamic_tool_handler,
      event_observer: self.event_observer,
    }
  }

  #[must_use]
  pub fn with_event_observer<NO>(self, event_observer: NO) -> CodexAppServerJsonlClient<F, NO> {
    CodexAppServerJsonlClient {
      transport_factory: self.transport_factory,
      ephemeral_threads: self.ephemeral_threads,
      dynamic_tool_handler: self.dynamic_tool_handler,
      event_observer,
    }
  }
}

pub struct CodexAppServerJsonlClientWithTools<F, H, O = NoopCodexTurnEventObserver> {
  transport_factory: F,
  ephemeral_threads: bool,
  dynamic_tool_handler: H,
  event_observer: O,
}

impl<F, H, O> CodexAppServerJsonlClientWithTools<F, H, O> {
  #[must_use]
  pub fn with_event_observer<NO>(
    self,
    event_observer: NO,
  ) -> CodexAppServerJsonlClientWithTools<F, H, NO> {
    CodexAppServerJsonlClientWithTools {
      transport_factory: self.transport_factory,
      ephemeral_threads: self.ephemeral_threads,
      dynamic_tool_handler: self.dynamic_tool_handler,
      event_observer,
    }
  }
}

#[derive(Debug, Clone)]
pub struct StdioCodexAppServerClient<
  H = NoopCodexDynamicToolHandler,
  O = NoopCodexTurnEventObserver,
> {
  command: String,
  ephemeral_threads: bool,
  dynamic_tool_handler: H,
  event_observer: O,
}

impl StdioCodexAppServerClient {
  #[must_use]
  pub fn new(command: String, ephemeral_threads: bool) -> Self {
    Self {
      command,
      ephemeral_threads,
      dynamic_tool_handler: NoopCodexDynamicToolHandler,
      event_observer: NoopCodexTurnEventObserver,
    }
  }
}

impl<H> StdioCodexAppServerClient<H> {
  #[must_use]
  pub fn with_dynamic_tool_handler(
    command: String,
    ephemeral_threads: bool,
    dynamic_tool_handler: H,
  ) -> Self {
    Self {
      command,
      ephemeral_threads,
      dynamic_tool_handler,
      event_observer: NoopCodexTurnEventObserver,
    }
  }
}

impl<H, O> StdioCodexAppServerClient<H, O> {
  #[must_use]
  pub fn with_event_observer<NO>(self, event_observer: NO) -> StdioCodexAppServerClient<H, NO> {
    StdioCodexAppServerClient {
      command: self.command,
      ephemeral_threads: self.ephemeral_threads,
      dynamic_tool_handler: self.dynamic_tool_handler,
      event_observer,
    }
  }
}

impl<H, O> CodexAppServerClient for StdioCodexAppServerClient<H, O>
where
  H: CodexDynamicToolHandler,
  O: CodexTurnEventObserver,
{
  fn start_turn(&self, request: &CodexAppServerRequest) -> Result<AgentTaskResult, String> {
    start_jsonl_turn(
      &|| StdioJsonlTransport::spawn(&self.command),
      self.ephemeral_threads,
      &self.dynamic_tool_handler,
      &self.event_observer,
      request,
    )
  }
}

impl<F, T, O> CodexAppServerClient for CodexAppServerJsonlClient<F, O>
where
  F: Fn() -> Result<T, String>,
  T: JsonlTransport,
  O: CodexTurnEventObserver,
{
  fn start_turn(&self, request: &CodexAppServerRequest) -> Result<AgentTaskResult, String> {
    start_jsonl_turn(
      &self.transport_factory,
      self.ephemeral_threads,
      &self.dynamic_tool_handler,
      &self.event_observer,
      request,
    )
  }
}

impl<F, T, H, O> CodexAppServerClient for CodexAppServerJsonlClientWithTools<F, H, O>
where
  F: Fn() -> Result<T, String>,
  T: JsonlTransport,
  H: CodexDynamicToolHandler,
  O: CodexTurnEventObserver,
{
  fn start_turn(&self, request: &CodexAppServerRequest) -> Result<AgentTaskResult, String> {
    start_jsonl_turn(
      &self.transport_factory,
      self.ephemeral_threads,
      &self.dynamic_tool_handler,
      &self.event_observer,
      request,
    )
  }
}

fn start_jsonl_turn<F, T, H, O>(
  transport_factory: &F,
  ephemeral_threads: bool,
  dynamic_tool_handler: &H,
  event_observer: &O,
  request: &CodexAppServerRequest,
) -> Result<AgentTaskResult, String>
where
  F: Fn() -> Result<T, String>,
  T: JsonlTransport,
  H: CodexDynamicToolHandler,
  O: CodexTurnEventObserver,
{
  let (dynamic_tools, allowed_dynamic_tools) = resolve_dynamic_tools(
    dynamic_tool_handler.tool_specs(&request.dynamic_tool_context),
    &request.tool_policy,
  )?;
  let mut transport = (transport_factory)()?;
  let mut initialize_params = json!({
    "clientInfo": {
      "name": "codeoff",
      "version": env!("CARGO_PKG_VERSION"),
    },
  });
  if !dynamic_tools.is_empty() {
    initialize_params["capabilities"] = json!({
      "experimentalApi": true,
    });
  }
  send_request(&mut transport, 1, "initialize", &initialize_params)?;
  read_response(&mut transport, 1, "initialize")?;
  send_notification(&mut transport, "initialized")?;
  let (thread, thread_method, turn_request_id) =
    if let Some(thread_id) = request.resume_thread_id.as_deref() {
      send_request(
        &mut transport,
        2,
        "thread/resume",
        &json!({
          "threadId": thread_id,
        }),
      )?;
      match read_response(&mut transport, 2, "thread/resume") {
        Ok(thread) => (thread, "thread/resume", 3),
        Err(error) if is_stale_resume_thread_error(&error) => {
          send_request(
            &mut transport,
            3,
            "thread/start",
            &thread_start_params(ephemeral_threads, dynamic_tools),
          )?;
          (
            read_response(&mut transport, 3, "thread/start")?,
            "thread/start",
            4,
          )
        }
        Err(error) => return Err(error),
      }
    } else {
      send_request(
        &mut transport,
        2,
        "thread/start",
        &thread_start_params(ephemeral_threads, dynamic_tools),
      )?;
      (
        read_response(&mut transport, 2, "thread/start")?,
        "thread/start",
        3,
      )
    };
  let thread_id = thread["thread"]["id"]
    .as_str()
    .ok_or_else(|| format!("codex app server {thread_method} response missing thread.id"))?
    .to_owned();
  let turn_params = json!({
    "threadId": thread_id,
    "clientUserMessageId": request.conversation_id,
    "input": [
      {
        "type": "text",
        "text": request.prompt,
      }
    ],
  });
  send_request(&mut transport, turn_request_id, "turn/start", &turn_params)?;
  let turn_start = read_response(&mut transport, turn_request_id, "turn/start")?;
  let turn_id = turn_start["turn"]["id"]
    .as_str()
    .or_else(|| turn_start["turn_id"].as_str())
    .ok_or_else(|| "codex app server turn/start response missing turn.id".to_owned())?;
  wait_for_terminal_turn(
    &mut transport,
    &thread_id,
    turn_id,
    dynamic_tool_handler,
    &allowed_dynamic_tools,
    &request.dynamic_tool_context,
    event_observer,
  )
  .map(|result| result.with_codex_thread_id(thread_id))
}

fn resolve_dynamic_tools(
  registered: Vec<Value>,
  policy: &ToolPolicy,
) -> Result<(Vec<Value>, HashSet<String>), String> {
  let registered_by_name: HashMap<_, _> = registered
    .into_iter()
    .filter_map(|spec| {
      spec["name"]
        .as_str()
        .map(ToOwned::to_owned)
        .map(|name| (name, spec))
    })
    .collect();
  let ToolPolicy::NamedSet(requested) = policy else {
    return Ok((Vec::new(), HashSet::new()));
  };
  if requested.is_empty() {
    return Err("dynamic tool policy named set must not be empty".to_owned());
  }
  let mut allowed = HashSet::new();
  let mut selected = Vec::with_capacity(requested.len());
  for name in requested {
    if name.trim().is_empty() || name != name.trim() {
      return Err(format!("invalid dynamic tool name in policy: {name:?}"));
    }
    if !allowed.insert(name.clone()) {
      return Err(format!("duplicate dynamic tool in policy: {name}"));
    }
    let Some(spec) = registered_by_name.get(name) else {
      return Err(format!("unknown dynamic tool in policy: {name}"));
    };
    selected.push(spec.clone());
  }
  Ok((selected, allowed))
}

fn thread_start_params(ephemeral_threads: bool, dynamic_tools: Vec<Value>) -> Value {
  let mut params = json!({
    "ephemeral": ephemeral_threads,
  });
  if !dynamic_tools.is_empty() {
    params["dynamicTools"] = Value::Array(dynamic_tools);
  }
  params
}

fn is_stale_resume_thread_error(error: &str) -> bool {
  error.contains(" is archived") || error.contains("no rollout found for thread id")
}

fn send_request<T: JsonlTransport>(
  transport: &mut T,
  id: u64,
  method: &str,
  params: &Value,
) -> Result<(), String> {
  transport.write_json(json!({
    "jsonrpc": "2.0",
    "id": id,
    "method": method,
    "params": params,
  }))
}

fn send_notification<T: JsonlTransport>(transport: &mut T, method: &str) -> Result<(), String> {
  transport.write_json(json!({
    "jsonrpc": "2.0",
    "method": method,
  }))
}

fn read_response<T: JsonlTransport>(
  transport: &mut T,
  expected_id: u64,
  method: &str,
) -> Result<Value, String> {
  loop {
    let response = transport.read_json()?;
    if response.get("id").is_none() && response["method"].is_string() {
      continue;
    }
    if response["id"].as_u64() != Some(expected_id) {
      return Err(format!("codex app server {method} response id mismatch"));
    }
    if let Some(error) = response.get("error") {
      let message = error["message"].as_str().unwrap_or("unknown error");
      return Err(format!("codex app server {method} failed: {message}"));
    }
    return Ok(response.get("result").cloned().unwrap_or_else(|| json!({})));
  }
}

fn wait_for_terminal_turn<T, H, O>(
  transport: &mut T,
  thread_id: &str,
  turn_id: &str,
  dynamic_tool_handler: &H,
  allowed_dynamic_tools: &HashSet<String>,
  dynamic_tool_context: &CodexDynamicToolContext,
  event_observer: &O,
) -> Result<AgentTaskResult, String>
where
  T: JsonlTransport,
  H: CodexDynamicToolHandler,
  O: CodexTurnEventObserver,
{
  let mut final_text = None;
  let mut agent_message_phases = HashMap::new();
  loop {
    let message = transport.read_json()?;
    if let Some(error) = message.get("error") {
      let message = error["message"].as_str().unwrap_or("unknown error");
      return Err(format!("codex app server turn failed: {message}"));
    }
    let method = message["method"].as_str();
    let params = &message["params"];
    match method {
      Some("item/tool/call") => {
        respond_to_tool_call(
          transport,
          &message,
          thread_id,
          turn_id,
          dynamic_tool_handler,
          allowed_dynamic_tools,
          dynamic_tool_context,
        )?;
      }
      Some(method) if is_unsupported_interaction_request(method) => {
        respond_to_unsupported_interaction(transport, &message, method, thread_id, turn_id)?;
      }
      Some("item/started")
        if params["threadId"].as_str() == Some(thread_id)
          && params["turnId"].as_str() == Some(turn_id) =>
      {
        observe_started_agent_message(event_observer, &mut agent_message_phases, params);
      }
      Some("item/agentMessage/delta")
        if params["threadId"].as_str() == Some(thread_id)
          && params["turnId"].as_str() == Some(turn_id) =>
      {
        observe_agent_message_delta(event_observer, &agent_message_phases, params);
      }
      Some("item/completed") if params["threadId"].as_str() == Some(thread_id) => {
        if params["turnId"].as_str() == Some(turn_id) {
          final_text = final_text.or_else(|| final_agent_text(&params["item"]));
        }
      }
      Some("turn/completed") if params["threadId"].as_str() == Some(thread_id) => {
        let turn = &params["turn"];
        if turn["id"].as_str() != Some(turn_id) {
          continue;
        }
        let status = turn["status"].as_str().unwrap_or("unknown");
        final_text = final_text.or_else(|| final_agent_text_from_items(&turn["items"]));
        return match status {
          "completed" => {
            Ok(final_text.map_or_else(AgentTaskResult::accepted_dispatch, AgentTaskResult::draft))
          }
          "failed" => Err(format!(
            "codex app server turn failed: {}",
            turn["error"]["message"].as_str().unwrap_or("unknown error")
          )),
          "interrupted" => Err("codex app server turn interrupted".to_owned()),
          other => Err(format!(
            "codex app server turn completed with unexpected status: {other}"
          )),
        };
      }
      _ => {}
    }
  }
}

fn observe_started_agent_message<O>(
  event_observer: &O,
  agent_message_phases: &mut HashMap<String, Option<String>>,
  params: &Value,
) where
  O: CodexTurnEventObserver,
{
  let item = &params["item"];
  if item["type"].as_str() != Some("agentMessage") {
    return;
  }
  let Some(item_id) = item["id"].as_str() else {
    return;
  };
  let phase = item["phase"].as_str().map(str::to_owned);
  agent_message_phases.insert(item_id.to_owned(), phase);
  let Some(thread_id) = params["threadId"].as_str() else {
    return;
  };
  let Some(turn_id) = params["turnId"].as_str() else {
    return;
  };
  event_observer.observe_codex_turn_event(CodexTurnEvent::AgentMessageStarted(
    CodexAgentMessageStartedEvent {
      thread_id: thread_id.to_owned(),
      turn_id: turn_id.to_owned(),
      item_id: item_id.to_owned(),
      phase: agent_message_phases.get(item_id).cloned().flatten(),
    },
  ));
}

fn observe_agent_message_delta<O>(
  event_observer: &O,
  agent_message_phases: &HashMap<String, Option<String>>,
  params: &Value,
) where
  O: CodexTurnEventObserver,
{
  let Some(item_id) = params["itemId"].as_str() else {
    return;
  };
  let Some(delta) = params["delta"].as_str() else {
    return;
  };
  let Some(thread_id) = params["threadId"].as_str() else {
    return;
  };
  let Some(turn_id) = params["turnId"].as_str() else {
    return;
  };
  event_observer.observe_codex_turn_event(CodexTurnEvent::AgentMessageDelta(
    CodexAgentMessageDeltaEvent {
      thread_id: thread_id.to_owned(),
      turn_id: turn_id.to_owned(),
      item_id: item_id.to_owned(),
      phase: agent_message_phases.get(item_id).cloned().flatten(),
      delta: delta.to_owned(),
    },
  ));
}

fn respond_to_tool_call<T, H>(
  transport: &mut T,
  message: &Value,
  thread_id: &str,
  turn_id: &str,
  dynamic_tool_handler: &H,
  allowed_dynamic_tools: &HashSet<String>,
  dynamic_tool_context: &CodexDynamicToolContext,
) -> Result<(), String>
where
  T: JsonlTransport,
  H: CodexDynamicToolHandler,
{
  let id = message["id"].clone();
  let params = &message["params"];
  let output = if params["threadId"].as_str() == Some(thread_id)
    && params["turnId"].as_str() == Some(turn_id)
  {
    let tool = params["tool"]
      .as_str()
      .or_else(|| params["name"].as_str())
      .unwrap_or("");
    if tool.is_empty() {
      dynamic_tool_failure("tool call missing tool name")
    } else if !allowed_dynamic_tools.contains(tool) {
      dynamic_tool_failure(format!("dynamic tool denied by task policy: {tool}"))
    } else {
      dynamic_tool_handler.handle_tool_call(dynamic_tool_context, tool, params["arguments"].clone())
    }
  } else {
    dynamic_tool_failure("tool call thread or turn did not match active turn")
  };
  transport.write_json(json!({
    "jsonrpc": "2.0",
    "id": id,
    "result": normalize_dynamic_tool_output(output),
  }))
}

fn respond_to_unsupported_interaction<T: JsonlTransport>(
  transport: &mut T,
  message: &Value,
  method: &str,
  thread_id: &str,
  turn_id: &str,
) -> Result<(), String> {
  let response_method = format!("{method}/response");
  transport.write_json(json!({
    "jsonrpc": "2.0",
    "id": message["id"].clone(),
    "result": {
      "method": response_method,
      "threadId": thread_id,
      "turnId": turn_id,
      "approved": false,
      "accepted": false,
      "granted": false,
      "success": false,
      "message": "Codeoff does not support interactive approval, permission, user-input, or elicitation requests during channel dispatch.",
    },
  }))
}

fn is_unsupported_interaction_request(method: &str) -> bool {
  let method = method.to_ascii_lowercase();
  method.contains("approval")
    || method.contains("requestapproval")
    || method.contains("userinput")
    || method.contains("requestuserinput")
    || method.contains("user-input")
    || method.contains("permission")
    || method.contains("elicitation")
}

#[must_use]
pub fn dynamic_tool_success(content: &Value) -> Value {
  json!({
    "success": true,
    "contentItems": [
      {
        "type": "inputText",
        "text": content.to_string(),
      }
    ],
  })
}

pub fn dynamic_tool_failure(message: impl Into<String>) -> Value {
  json!({
    "success": false,
    "contentItems": [
      {
        "type": "inputText",
        "text": message.into(),
      }
    ],
  })
}

fn normalize_dynamic_tool_output(output: Value) -> Value {
  if output["success"].is_boolean() && output["contentItems"].as_array().is_some() {
    output
  } else {
    dynamic_tool_failure("dynamic tool handler returned an invalid response")
  }
}

fn final_agent_text_from_items(items: &Value) -> Option<String> {
  let items = items.as_array()?;
  items.iter().rev().find_map(final_agent_text)
}

fn final_agent_text(item: &Value) -> Option<String> {
  if item["type"].as_str() != Some("agentMessage") {
    return None;
  }
  let text = item["text"].as_str()?.trim();
  if text.is_empty() {
    return None;
  }
  match item["phase"].as_str() {
    Some("final_answer") | None => Some(text.to_owned()),
    _ => None,
  }
}

#[derive(Debug, Clone)]
pub struct CodexAppServerBackend<C> {
  client: C,
  max_prompt_bytes: usize,
  previous_success_context_max_bytes: usize,
}

impl<C> CodexAppServerBackend<C> {
  pub fn new(client: C) -> Self {
    Self {
      client,
      max_prompt_bytes: DEFAULT_MAX_PROMPT_BYTES,
      previous_success_context_max_bytes: DEFAULT_PREVIOUS_SUCCESS_CONTEXT_MAX_BYTES,
    }
  }

  #[must_use]
  pub const fn with_prompt_limits(
    mut self,
    max_prompt_bytes: usize,
    previous_success_context_max_bytes: usize,
  ) -> Self {
    self.max_prompt_bytes = max_prompt_bytes;
    self.previous_success_context_max_bytes = previous_success_context_max_bytes;
    self
  }
}

impl<C: CodexAppServerClient> AgentBackend for CodexAppServerBackend<C> {
  fn provider_name(&self) -> &'static str {
    "codex-app-server"
  }

  fn run(&self, task: AgentTask) -> Result<AgentTaskResult, String> {
    task.validate().map_err(str::to_owned)?;
    let prompt = render_prompt(
      &task,
      self.max_prompt_bytes,
      self.previous_success_context_max_bytes,
    )?;
    let conversation_id = task.channel.as_ref().map_or_else(
      || task.task_id.clone(),
      |channel| channel.conversation_key.clone(),
    );
    let resume_thread_id = match &task.session {
      SessionMode::Fresh => None,
      SessionMode::Resume { thread_id } => Some(thread_id.clone()),
    };
    self.client.start_turn(&CodexAppServerRequest {
      conversation_id,
      resume_thread_id,
      prompt,
      tool_policy: task.tool_policy,
      dynamic_tool_context: CodexDynamicToolContext {
        source: task.source,
        principal: task.principal,
        channel: task.channel,
      },
    })
  }
}

fn render_prompt(
  task: &AgentTask,
  max_prompt_bytes: usize,
  previous_success_context_max_bytes: usize,
) -> Result<String, String> {
  if task.instruction.trim().is_empty() {
    return Err("agent task instruction must not be empty".to_owned());
  }
  let mut required = format!(
    "You are executing a bounded task through Codeoff.\nReturn a concise final result or use only the dynamic tools allowed for this task.\n\nObjective: {}",
    task.instruction
  );
  match &task.tool_policy {
    ToolPolicy::None => required.push_str("\n\nAllowed Codeoff dynamic tools: none."),
    ToolPolicy::NamedSet(names) => {
      let _ = write!(
        required,
        "\n\nAllowed Codeoff dynamic tools: {}.",
        names.join(", ")
      );
    }
  }
  let mut optional_sections = Vec::new();
  if let Some(channel) = &task.channel {
    append_channel_prompt(&mut required, &mut optional_sections, channel);
  }
  append_invocation_source(&mut required, &task.source);
  if required.len() > max_prompt_bytes {
    return Err("codex prompt required content exceeds max_prompt_bytes".to_owned());
  }
  if let Some(previous) = &task.previous_success {
    let source = if previous.was_truncated && !previous.content.ends_with(TRUNCATION_MARKER) {
      format!("{}{}", previous.content, TRUNCATION_MARKER)
    } else {
      previous.content.clone()
    };
    let (content, truncated_now) =
      truncate_utf8_with_marker(&source, previous_success_context_max_bytes);
    let label = if previous.was_truncated || truncated_now {
      "Previous successful result (bounded snapshot)"
    } else {
      "Previous successful result"
    };
    optional_sections.push((label, content));
  }
  let mut prompt = required;
  for (label, content) in optional_sections {
    append_bounded_section(&mut prompt, label, &content, max_prompt_bytes);
  }
  Ok(prompt)
}

fn append_channel_prompt(
  required: &mut String,
  optional_sections: &mut Vec<(&'static str, String)>,
  channel: &ChannelTaskContext,
) {
  let reply_instruction = match channel.reply_strategy {
    ChannelReplyStrategy::FinalAnswer => {
      "For direct messages, return the reply as your final answer; Codeoff will deliver it to the channel."
    }
    ChannelReplyStrategy::DynamicTool => {
      "If a reply is needed, call the channel_reply_to_event dynamic tool."
    }
  };
  let _ = write!(
    required,
    "\n\nYou are handling a live channel event through Codeoff.\n{reply_instruction}\n\nAnswer Quality Contract:\n- Classify the incoming message as standalone or context-dependent before answering.\n- context-dependent indicators include follow-ups, pronouns, omitted subjects, references such as this/that/above/previous, and requests to inspect code, files, links, screenshots, or implementation details.\n- If the message is context-dependent, use the available channel context or tools before answering.\n- Prefer exact source message data, then thread or direct-message history, then the conversation summary.\n- Use channel_get_message to inspect the exact source message when text, blocks, attachments, or file references matter.\n- Use channel_get_thread_context or channel_get_recent_messages when the recent context is insufficient or has a next_cursor.\n- Use channel_get_resource_info first for files, channel_read_resource_text for text-like files, and channel_download_resource only when a local artifact is necessary.\n- Do not ask the user to resend channel context before trying the available channel tools.\n- If context remains incomplete after tool use, state the missing context and answer from explicit assumptions.\n\nSource references:\n- provider: {}\n- workspace_id: {}\n- conversation_key: {}\n- conversation_kind: {:?}\n- channel_id: {}\n- thread_id: {}\n- message_ts: {}\n- user_id: {}",
    channel.provider,
    channel.workspace_id,
    channel.conversation_key,
    channel.conversation_kind,
    channel.channel_id.as_deref().unwrap_or("none"),
    channel.thread_id.as_deref().unwrap_or("none"),
    channel.message_ts.as_deref().unwrap_or("none"),
    channel.user_id.as_deref().unwrap_or("none"),
  );
  if let Some(message) = channel.message_text.as_deref() {
    optional_sections.push(("Incoming channel message text", message.to_owned()));
  }
  if let Some(context) = channel.recent_context.as_deref() {
    optional_sections.push(("Recent channel conversation context", context.to_owned()));
  }
  if let Some(summary) = channel.conversation_summary.as_deref() {
    optional_sections.push(("Conversation summary", summary.to_owned()));
  }
}

fn append_invocation_source(required: &mut String, source: &InvocationSource) {
  match source {
    InvocationSource::ChannelEvent {
      event_id,
      dedupe_key,
      source_reference,
      ..
    } => {
      let _ = write!(
        *required,
        "\n- event_id: {event_id}\n- dedupe_key: {dedupe_key}\n- source_reference: {}",
        source_reference.as_deref().unwrap_or("none")
      );
    }
    InvocationSource::ScheduledRun {
      job_id,
      run_id,
      scheduled_for,
    } => {
      let _ = write!(
        *required,
        "\n\nExecution context: independent scheduled run. This run has no live channel and must return a non-empty final result.\n- job_id: {job_id}\n- run_id: {run_id}\n- scheduled_for: {scheduled_for}"
      );
    }
    InvocationSource::TrustedOperator { request_id } => {
      let _ = write!(
        *required,
        "\n\nExecution source: trusted operator request {request_id}."
      );
    }
    InvocationSource::InternalService {
      service,
      request_id,
    } => {
      let _ = write!(
        *required,
        "\n\nExecution source: internal service {service}, request {request_id}."
      );
    }
  }
}

fn append_bounded_section(prompt: &mut String, label: &str, content: &str, max_bytes: usize) {
  let prefix = format!("\n\n{label}:\n");
  let available = max_bytes.saturating_sub(prompt.len());
  if available <= prefix.len() {
    return;
  }
  let (content, _) = truncate_utf8_with_marker(content, available - prefix.len());
  prompt.push_str(&prefix);
  prompt.push_str(&content);
}

fn truncate_utf8_with_marker(content: &str, max_bytes: usize) -> (String, bool) {
  if content.len() <= max_bytes {
    return (content.to_owned(), false);
  }
  if max_bytes < TRUNCATION_MARKER.len() {
    return (String::new(), true);
  }
  let mut boundary = max_bytes - TRUNCATION_MARKER.len();
  while !content.is_char_boundary(boundary) {
    boundary -= 1;
  }
  let mut truncated = content[..boundary].to_owned();
  truncated.push_str(TRUNCATION_MARKER);
  (truncated, true)
}

#[cfg(test)]
mod tests {
  use super::*;
  use codeoff_agent_contract::{
    ChannelTaskContext, ConversationKind, FeedbackTarget, InvocationPrincipal,
    PreviousSuccessContext,
  };
  use std::cell::RefCell;
  use std::rc::Rc;

  fn test_dynamic_tool_context() -> CodexDynamicToolContext {
    CodexDynamicToolContext {
      source: InvocationSource::ChannelEvent {
        provider: "slack".to_owned(),
        workspace_id: "W1".to_owned(),
        event_id: "E1".to_owned(),
        dedupe_key: "d1".to_owned(),
        source_reference: None,
      },
      principal: InvocationPrincipal::channel_actor("slack", "W1", "U1"),
      channel: None,
    }
  }

  #[derive(Debug, Clone)]
  struct FakeJsonlTransport {
    inner: Rc<RefCell<FakeJsonlTransportState>>,
  }

  #[derive(Debug)]
  struct FakeJsonlTransportState {
    reads: Vec<Value>,
    writes: Vec<Value>,
    event_log: Option<Rc<RefCell<Vec<String>>>>,
  }

  impl FakeJsonlTransport {
    fn new<const N: usize>(reads: [&str; N]) -> Self {
      Self::new_with_event_log(reads, None)
    }

    fn new_with_event_log<const N: usize>(
      reads: [&str; N],
      event_log: Option<Rc<RefCell<Vec<String>>>>,
    ) -> Self {
      let reads = reads
        .into_iter()
        .map(|line| serde_json::from_str(line).expect("fake json response"))
        .rev()
        .collect();
      Self {
        inner: Rc::new(RefCell::new(FakeJsonlTransportState {
          reads,
          writes: Vec::new(),
          event_log,
        })),
      }
    }

    fn writes(&self) -> Vec<Value> {
      self.inner.borrow().writes.clone()
    }
  }

  impl JsonlTransport for FakeJsonlTransport {
    fn write_json(&mut self, value: Value) -> Result<(), String> {
      self.inner.borrow_mut().writes.push(value);
      Ok(())
    }

    fn read_json(&mut self) -> Result<Value, String> {
      let value = self
        .inner
        .borrow_mut()
        .reads
        .pop()
        .ok_or_else(|| "fake transport has no response".to_owned())?;
      if let Some(event_log) = &self.inner.borrow().event_log
        && let Some(method) = value["method"].as_str()
      {
        event_log.borrow_mut().push(format!("read:{method}"));
      }
      Ok(value)
    }
  }

  #[derive(Default)]
  struct FakeClient(RefCell<Vec<CodexAppServerRequest>>);

  impl CodexAppServerClient for FakeClient {
    fn start_turn(&self, request: &CodexAppServerRequest) -> Result<AgentTaskResult, String> {
      self.0.borrow_mut().push(request.clone());
      Ok(AgentTaskResult::draft("Private draft"))
    }
  }

  impl CodexAppServerClient for &FakeClient {
    fn start_turn(&self, request: &CodexAppServerRequest) -> Result<AgentTaskResult, String> {
      (*self).start_turn(request)
    }
  }

  struct FakeThreadClient(AgentTaskResult);

  impl FakeThreadClient {
    fn new(result: AgentTaskResult) -> Self {
      Self(result)
    }
  }

  impl CodexAppServerClient for &FakeThreadClient {
    fn start_turn(&self, _request: &CodexAppServerRequest) -> Result<AgentTaskResult, String> {
      Ok(self.0.clone())
    }
  }

  fn slack_task() -> AgentTask {
    AgentTask {
      task_id: "slack:W1:d1".to_owned(),
      instruction: "Handle the mention".to_owned(),
      source: InvocationSource::ChannelEvent {
        provider: "slack".to_owned(),
        workspace_id: "W1".to_owned(),
        event_id: "E1".to_owned(),
        dedupe_key: "d1".to_owned(),
        source_reference: Some("slack://W1/C1/100.0".to_owned()),
      },
      principal: InvocationPrincipal::channel_actor("slack", "W1", "U1"),
      session: SessionMode::Fresh,
      channel: Some(ChannelTaskContext {
        provider: "slack".to_owned(),
        workspace_id: "W1".to_owned(),
        conversation_key: "slack:W1:thread:C1:99.0".to_owned(),
        conversation_kind: ConversationKind::Thread,
        reply_strategy: ChannelReplyStrategy::DynamicTool,
        message_text: Some("please restart the failed worker".to_owned()),
        channel_id: Some("C1".to_owned()),
        thread_id: Some("99.0".to_owned()),
        message_ts: Some("100.0".to_owned()),
        user_id: Some("U1".to_owned()),
        recent_context: None,
        conversation_summary: Some("User previously reported a failed worker.".to_owned()),
      }),
      previous_success: None,
      tool_policy: ToolPolicy::NamedSet(vec!["channel_reply_to_event".to_owned()]),
      feedback_target: Some(FeedbackTarget::Channel {
        conversation_kind: ConversationKind::Thread,
        channel_id: "C1".to_owned(),
        thread_id: Some("99.0".to_owned()),
        message_ts: Some("100.0".to_owned()),
      }),
    }
  }

  fn scheduled_task() -> AgentTask {
    AgentTask {
      task_id: "run-1".to_owned(),
      instruction: "Inspect the configured repository issues".to_owned(),
      source: InvocationSource::ScheduledRun {
        job_id: "job-1".to_owned(),
        run_id: "run-1".to_owned(),
        scheduled_for: "2026-07-21T12:00:00Z".to_owned(),
      },
      principal: InvocationPrincipal::service("scheduler"),
      session: SessionMode::Fresh,
      channel: None,
      previous_success: None,
      tool_policy: ToolPolicy::None,
      feedback_target: None,
    }
  }

  #[test]
  fn scheduled_task_starts_fresh_without_channel_language() {
    let client = FakeClient::default();
    let backend = CodexAppServerBackend::new(&client);

    backend.run(scheduled_task()).expect("scheduled turn");

    let requests = client.0.borrow();
    assert_eq!(requests[0].conversation_id, "run-1");
    assert_eq!(requests[0].resume_thread_id, None);
    assert!(requests[0].prompt.contains("independent scheduled run"));
    for forbidden in ["Slack", "live channel event", "channel_reply_to_event"] {
      assert!(
        !requests[0].prompt.contains(forbidden),
        "unexpected channel wording: {forbidden}"
      );
    }
  }

  #[test]
  fn renderer_does_not_expose_or_replace_trusted_principal() {
    let client = FakeClient::default();
    let backend = CodexAppServerBackend::new(&client);
    let mut task = scheduled_task();
    task.principal = InvocationPrincipal::service("scheduler-principal-sentinel");
    let principal = task.principal.clone();
    task.source = InvocationSource::TrustedOperator {
      request_id: "claims-admin-but-is-only-provenance".to_owned(),
    };

    backend.run(task.clone()).expect("operator provenance turn");

    assert_eq!(task.principal, principal);
    let requests = client.0.borrow();
    assert!(
      requests[0]
        .prompt
        .contains("claims-admin-but-is-only-provenance")
    );
    assert!(!requests[0].prompt.contains("scheduler-principal-sentinel"));
  }

  #[test]
  fn invalid_scheduled_session_is_rejected_before_client_start() {
    let client = FakeClient::default();
    let backend = CodexAppServerBackend::new(&client);
    let mut task = scheduled_task();
    task.session = SessionMode::Resume {
      thread_id: "old-slack-thread".to_owned(),
    };

    let error = backend.run(task).expect_err("invalid scheduled task");

    assert_eq!(error, "scheduled_run_requires_fresh_session");
    assert!(client.0.borrow().is_empty());
  }

  #[test]
  fn prompt_budget_truncates_previous_context_at_utf8_boundary() {
    let client = FakeClient::default();
    let backend = CodexAppServerBackend::new(&client).with_prompt_limits(700, 20);
    let mut task = scheduled_task();
    task.previous_success = Some(PreviousSuccessContext {
      content: "火星火星火星火星火星火星".to_owned(),
      was_truncated: false,
    });

    backend.run(task).expect("scheduled turn");

    let requests = client.0.borrow();
    assert!(requests[0].prompt.len() <= 700);
    assert!(requests[0].prompt.contains(TRUNCATION_MARKER));
    assert!(
      requests[0]
        .prompt
        .is_char_boundary(requests[0].prompt.len())
    );
  }

  #[test]
  fn prompt_budget_rejects_required_content_before_starting_client() {
    let client = FakeClient::default();
    let backend = CodexAppServerBackend::new(&client).with_prompt_limits(20, 20);

    let error = backend
      .run(scheduled_task())
      .expect_err("required prompt must exceed budget");

    assert_eq!(
      error,
      "codex prompt required content exceeds max_prompt_bytes"
    );
    assert!(client.0.borrow().is_empty());
  }

  #[test]
  fn turns_a_slack_task_into_an_interactive_codex_turn_with_source_references() {
    let client = FakeClient::default();
    let backend = CodexAppServerBackend::new(&client);
    let result = backend.run(slack_task()).expect("turn result");

    assert_eq!(result, AgentTaskResult::draft("Private draft"));
    let requests = client.0.borrow();
    assert_eq!(requests[0].conversation_id, "slack:W1:thread:C1:99.0");
    assert_eq!(requests[0].resume_thread_id, None);
    assert!(
      requests[0]
        .prompt
        .contains("You are handling a live channel event through Codeoff.")
    );
    assert!(
      requests[0]
        .prompt
        .contains("If a reply is needed, call the channel_reply_to_event dynamic tool.")
    );
    assert!(requests[0].prompt.contains("Answer Quality Contract"));
    assert!(requests[0].prompt.contains(
      "Classify the incoming message as standalone or context-dependent before answering."
    ));
    assert!(
      requests[0]
        .prompt
        .contains("If the message is context-dependent, use the available channel context or tools before answering.")
    );
    assert!(requests[0].prompt.contains(
      "Do not ask the user to resend channel context before trying the available channel tools."
    ));
    assert!(
      requests[0]
        .prompt
        .contains("Use channel_get_message to inspect the exact source message")
    );
    for tool_name in [
      "channel_get_resource_info",
      "channel_read_resource_text",
      "channel_download_resource",
    ] {
      assert!(
        requests[0].prompt.contains(tool_name),
        "missing {tool_name}"
      );
    }
    assert!(
      !requests[0]
        .prompt
        .contains("Do not send a public Slack reply.")
    );
    assert!(
      requests[0]
        .prompt
        .contains("Incoming channel message text:\nplease restart the failed worker")
    );
    assert!(
      requests[0]
        .prompt
        .contains("Conversation summary:\nUser previously reported a failed worker.")
    );
    for reference in [
      "channel_id: C1",
      "thread_id: 99.0",
      "message_ts: 100.0",
      "user_id: U1",
      "event_id: E1",
      "dedupe_key: d1",
    ] {
      assert!(
        requests[0].prompt.contains(reference),
        "missing {reference}"
      );
    }
  }

  #[test]
  fn direct_message_task_prompts_codex_to_return_final_answer_with_context() {
    let client = FakeClient::default();
    let backend = CodexAppServerBackend::new(&client);

    let mut task = slack_task();
    task.instruction = "Handle the direct message".to_owned();
    let channel = task.channel.as_mut().expect("channel");
    channel.conversation_key = "slack:W1:dm:D1".to_owned();
    channel.conversation_kind = ConversationKind::DirectMessage;
    channel.reply_strategy = ChannelReplyStrategy::FinalAnswer;
    channel.message_text = Some("那火星呢？".to_owned());
    channel.channel_id = Some("not-prefixed-as-dm".to_owned());
    channel.thread_id = Some("200.0".to_owned());
    channel.message_ts = Some("201.0".to_owned());
    channel.recent_context = Some(r#"{"events":[{"text":"月球上都有什么"}]}"#.to_owned());
    channel.conversation_summary = None;
    backend.run(task).expect("turn result");

    let requests = client.0.borrow();
    assert!(requests[0].prompt.contains(
      "For direct messages, return the reply as your final answer; Codeoff will deliver it to the channel."
    ));
    assert!(
      !requests[0]
        .prompt
        .contains("If a reply is needed, call the channel_reply_to_event dynamic tool.")
    );
    assert!(
      requests[0]
        .prompt
        .contains("Recent channel conversation context:")
    );
    assert!(
      requests[0]
        .prompt
        .contains("context-dependent indicators include follow-ups, pronouns, omitted subjects")
    );
    assert!(requests[0].prompt.contains("月球上都有什么"));
  }

  #[test]
  fn passes_resume_thread_id_to_existing_codex_turn() {
    let client = FakeClient::default();
    let backend = CodexAppServerBackend::new(&client);

    let mut task = slack_task();
    task.session = SessionMode::Resume {
      thread_id: "thread-existing".to_owned(),
    };
    backend.run(task).expect("turn result");

    let requests = client.0.borrow();
    assert_eq!(
      requests[0].resume_thread_id.as_deref(),
      Some("thread-existing")
    );
  }

  #[test]
  fn reports_stdio_codex_thread_id_as_durable_conversation_state() {
    let client =
      FakeThreadClient::new(AgentTaskResult::accepted_dispatch_with_thread("thread-new"));
    let backend = CodexAppServerBackend::new(&client);

    let result = backend.run(slack_task()).expect("turn result");

    assert_eq!(result.codex_thread_id(), Some("thread-new"));
  }

  #[test]
  fn jsonl_client_starts_thread_and_turn_without_slack_body_or_history() {
    let transport = FakeJsonlTransport::new([
      r#"{"jsonrpc":"2.0","id":1,"result":{"server":"codex-app-server"}}"#,
      r#"{"jsonrpc":"2.0","id":2,"result":{"thread":{"id":"thread-1"}}}"#,
      r#"{"jsonrpc":"2.0","id":3,"result":{"turn":{"id":"turn-1","items":[],"status":"inProgress"}}}"#,
      r#"{"jsonrpc":"2.0","method":"turn/completed","params":{"threadId":"thread-1","turn":{"id":"turn-1","status":"completed","items":[{"id":"agent-1","type":"agentMessage","phase":"final_answer","text":"Final private draft"}]}}}"#,
    ]);
    let client = CodexAppServerJsonlClient::new(|| Ok(transport.clone()), true);

    let result = client
      .start_turn(&CodexAppServerRequest {
        conversation_id: "slack:W1:d1".to_owned(),
        resume_thread_id: None,
        prompt: "Source references:\n- channel_id: C1\n- event_id: E1\n- dedupe_key: d1".to_owned(),
        tool_policy: ToolPolicy::None,
        dynamic_tool_context: test_dynamic_tool_context(),
      })
      .expect("accepted turn");

    assert_eq!(
      result,
      AgentTaskResult::draft_with_thread("Final private draft", "thread-1")
    );
    let writes = transport.writes();
    let methods = writes
      .iter()
      .map(|value| value["method"].as_str().expect("method"))
      .collect::<Vec<_>>();
    assert_eq!(
      methods,
      ["initialize", "initialized", "thread/start", "turn/start"]
    );
    assert_eq!(writes[0]["params"]["clientInfo"]["name"], "codeoff");
    assert!(writes[1].get("params").is_none());
    assert_eq!(writes[2]["params"]["ephemeral"], true);
    assert_eq!(writes[3]["params"]["threadId"], "thread-1");
    assert_eq!(writes[3]["params"]["clientUserMessageId"], "slack:W1:d1");
    assert_eq!(writes[3]["params"]["input"][0]["type"], "text");
    assert_eq!(
      writes[3]["params"]["input"][0]["text"],
      "Source references:\n- channel_id: C1\n- event_id: E1\n- dedupe_key: d1"
    );
    let serialized = serde_json::to_string(&writes).expect("serialize writes");
    assert!(!serialized.contains("raw_payload_json"));
    assert!(!serialized.contains("Slack message text"));
    assert!(!serialized.contains("recent_messages"));
    assert!(!serialized.contains("thread_history"));
  }

  #[test]
  fn jsonl_client_declares_channel_dynamic_tools_on_turn_start() {
    let transport = FakeJsonlTransport::new([
      r#"{"jsonrpc":"2.0","id":1,"result":{}}"#,
      r#"{"jsonrpc":"2.0","id":2,"result":{"thread":{"id":"thread-1"}}}"#,
      r#"{"jsonrpc":"2.0","id":3,"result":{"turn":{"id":"turn-1","items":[],"status":"inProgress"}}}"#,
      r#"{"jsonrpc":"2.0","method":"turn/completed","params":{"threadId":"thread-1","turn":{"id":"turn-1","status":"completed","items":[]}}}"#,
    ]);
    let client = CodexAppServerJsonlClient::new(|| Ok(transport.clone()), true)
      .with_dynamic_tool_handler(StaticDynamicToolHandler::new(vec![json!({
        "name": "channel_reply_to_event",
        "description": "Queue a bounded reply to the source channel event.",
        "inputSchema": { "type": "object" }
      })]));

    client
      .start_turn(&CodexAppServerRequest {
        conversation_id: "slack:W1:d1".to_owned(),
        resume_thread_id: None,
        prompt: "Source references only".to_owned(),
        tool_policy: ToolPolicy::NamedSet(vec!["channel_reply_to_event".to_owned()]),
        dynamic_tool_context: test_dynamic_tool_context(),
      })
      .expect("completed turn");

    let writes = transport.writes();
    assert_eq!(writes[0]["params"]["capabilities"]["experimentalApi"], true);
    assert_eq!(
      writes[2]["params"]["dynamicTools"][0]["name"],
      "channel_reply_to_event"
    );
  }

  #[test]
  fn jsonl_client_does_not_enable_dynamic_tools_for_default_deny_policy() {
    let transport = FakeJsonlTransport::new([
      r#"{"jsonrpc":"2.0","id":1,"result":{}}"#,
      r#"{"jsonrpc":"2.0","id":2,"result":{"thread":{"id":"thread-1"}}}"#,
      r#"{"jsonrpc":"2.0","id":3,"result":{"turn":{"id":"turn-1","items":[],"status":"inProgress"}}}"#,
      r#"{"jsonrpc":"2.0","method":"turn/completed","params":{"threadId":"thread-1","turn":{"id":"turn-1","status":"completed","items":[]}}}"#,
    ]);
    let client = CodexAppServerJsonlClient::new(|| Ok(transport.clone()), true)
      .with_dynamic_tool_handler(StaticDynamicToolHandler::new(vec![json!({
        "name": "channel_reply_to_event",
        "description": "reply",
        "inputSchema": { "type": "object" }
      })]));

    client
      .start_turn(&CodexAppServerRequest {
        conversation_id: "run-1".to_owned(),
        resume_thread_id: None,
        prompt: "Run".to_owned(),
        tool_policy: ToolPolicy::None,
        dynamic_tool_context: test_dynamic_tool_context(),
      })
      .expect("completed turn");

    let writes = transport.writes();
    assert!(writes[0]["params"].get("capabilities").is_none());
    assert!(writes[2]["params"].get("dynamicTools").is_none());
  }

  #[test]
  fn jsonl_client_rejects_empty_unknown_and_duplicate_named_tool_policies() {
    let client = CodexAppServerJsonlClient::new(
      || Err::<FakeJsonlTransport, _>("transport must not start".to_owned()),
      true,
    )
    .with_dynamic_tool_handler(StaticDynamicToolHandler::new(vec![json!({
      "name": "known_tool",
      "description": "known",
      "inputSchema": { "type": "object" }
    })]));

    for (policy, expected) in [
      (
        ToolPolicy::NamedSet(Vec::new()),
        "dynamic tool policy named set must not be empty",
      ),
      (
        ToolPolicy::NamedSet(vec!["unknown_tool".to_owned()]),
        "unknown dynamic tool in policy: unknown_tool",
      ),
      (
        ToolPolicy::NamedSet(vec!["known_tool".to_owned(), "known_tool".to_owned()]),
        "duplicate dynamic tool in policy: known_tool",
      ),
    ] {
      let error = client
        .start_turn(&CodexAppServerRequest {
          conversation_id: "run-1".to_owned(),
          resume_thread_id: None,
          prompt: "Run".to_owned(),
          tool_policy: policy,
          dynamic_tool_context: test_dynamic_tool_context(),
        })
        .expect_err("invalid policy");
      assert_eq!(error, expected);
    }
  }

  #[test]
  fn jsonl_client_handles_channel_dynamic_tool_call_while_waiting_for_turn_completion() {
    let transport = FakeJsonlTransport::new([
      r#"{"jsonrpc":"2.0","id":1,"result":{}}"#,
      r#"{"jsonrpc":"2.0","id":2,"result":{"thread":{"id":"thread-1"}}}"#,
      r#"{"jsonrpc":"2.0","id":3,"result":{"turn":{"id":"turn-1","items":[],"status":"inProgress"}}}"#,
      r#"{"jsonrpc":"2.0","id":10,"method":"item/tool/call","params":{"threadId":"thread-1","turnId":"turn-1","tool":"channel_reply_to_event","arguments":{"text":"hello"}}}"#,
      r#"{"jsonrpc":"2.0","method":"turn/completed","params":{"threadId":"thread-1","turn":{"id":"turn-1","status":"completed","items":[]}}}"#,
    ]);
    let handler = RecordingDynamicToolHandler::new(json!({
      "success": true,
      "contentItems": [
        {
          "type": "inputText",
          "text": "{\"queued\":true}"
        }
      ]
    }));
    let client = CodexAppServerJsonlClient::new(|| Ok(transport.clone()), true)
      .with_dynamic_tool_handler(handler.clone());

    client
      .start_turn(&CodexAppServerRequest {
        conversation_id: "slack:W1:d1".to_owned(),
        resume_thread_id: None,
        prompt: "Source references only".to_owned(),
        tool_policy: ToolPolicy::NamedSet(vec!["channel_reply_to_event".to_owned()]),
        dynamic_tool_context: test_dynamic_tool_context(),
      })
      .expect("completed turn");

    assert_eq!(
      handler.calls.borrow().as_slice(),
      [(
        "channel_reply_to_event".to_owned(),
        json!({"text": "hello"})
      )]
    );
    assert_eq!(
      handler.contexts.borrow().as_slice(),
      &[test_dynamic_tool_context()]
    );
    let writes = transport.writes();
    let response = writes
      .iter()
      .find(|value| value["id"] == 10)
      .expect("tool call response");
    assert_eq!(response["result"]["success"], true);
    assert_eq!(response["result"]["contentItems"][0]["type"], "inputText");
  }

  #[test]
  fn resumed_thread_rejects_tool_allowed_by_previous_task_but_denied_now() {
    let transport = FakeJsonlTransport::new([
      r#"{"jsonrpc":"2.0","id":1,"result":{}}"#,
      r#"{"jsonrpc":"2.0","id":2,"result":{"thread":{"id":"thread-existing"}}}"#,
      r#"{"jsonrpc":"2.0","id":3,"result":{"turn":{"id":"turn-1","items":[],"status":"inProgress"}}}"#,
      r#"{"jsonrpc":"2.0","id":10,"method":"item/tool/call","params":{"threadId":"thread-existing","turnId":"turn-1","tool":"old_tool","arguments":{}}}"#,
      r#"{"jsonrpc":"2.0","method":"turn/completed","params":{"threadId":"thread-existing","turn":{"id":"turn-1","status":"completed","items":[]}}}"#,
    ]);
    let handler = RecordingDynamicToolHandler::new(dynamic_tool_success(&json!({"ok": true})));
    let client = CodexAppServerJsonlClient::new(|| Ok(transport.clone()), true)
      .with_dynamic_tool_handler(handler.clone());

    client
      .start_turn(&CodexAppServerRequest {
        conversation_id: "conversation-2".to_owned(),
        resume_thread_id: Some("thread-existing".to_owned()),
        prompt: "Continue".to_owned(),
        tool_policy: ToolPolicy::None,
        dynamic_tool_context: test_dynamic_tool_context(),
      })
      .expect("completed turn");

    assert!(handler.calls.borrow().is_empty());
    let writes = transport.writes();
    let response = writes
      .iter()
      .find(|value| value["id"] == 10)
      .expect("denied tool response");
    assert_eq!(response["result"]["success"], false);
    assert!(
      response["result"]["contentItems"][0]["text"]
        .as_str()
        .expect("failure text")
        .contains("dynamic tool denied by task policy: old_tool")
    );
  }

  #[test]
  fn jsonl_client_rejects_unsupported_interaction_requests_without_hanging() {
    let transport = FakeJsonlTransport::new([
      r#"{"jsonrpc":"2.0","id":1,"result":{}}"#,
      r#"{"jsonrpc":"2.0","id":2,"result":{"thread":{"id":"thread-1"}}}"#,
      r#"{"jsonrpc":"2.0","id":3,"result":{"turn":{"id":"turn-1","items":[],"status":"inProgress"}}}"#,
      r#"{"jsonrpc":"2.0","id":11,"method":"approval/request","params":{"threadId":"thread-1","turnId":"turn-1"}}"#,
      r#"{"jsonrpc":"2.0","id":12,"method":"userInput/request","params":{"threadId":"thread-1","turnId":"turn-1"}}"#,
      r#"{"jsonrpc":"2.0","id":13,"method":"permission/request","params":{"threadId":"thread-1","turnId":"turn-1"}}"#,
      r#"{"jsonrpc":"2.0","id":14,"method":"elicitation/request","params":{"threadId":"thread-1","turnId":"turn-1"}}"#,
      r#"{"jsonrpc":"2.0","id":15,"method":"item/commandExecution/requestApproval","params":{"threadId":"thread-1","turnId":"turn-1"}}"#,
      r#"{"jsonrpc":"2.0","id":16,"method":"item/tool/requestUserInput","params":{"threadId":"thread-1","turnId":"turn-1"}}"#,
      r#"{"jsonrpc":"2.0","method":"turn/completed","params":{"threadId":"thread-1","turn":{"id":"turn-1","status":"completed","items":[]}}}"#,
    ]);
    let client = CodexAppServerJsonlClient::new(|| Ok(transport.clone()), true);

    client
      .start_turn(&CodexAppServerRequest {
        conversation_id: "slack:W1:d1".to_owned(),
        resume_thread_id: None,
        prompt: "Source references only".to_owned(),
        tool_policy: ToolPolicy::None,
        dynamic_tool_context: test_dynamic_tool_context(),
      })
      .expect("completed turn");

    let writes = transport.writes();
    let negative_responses = writes
      .iter()
      .filter(|value| value["result"]["method"].as_str().is_some())
      .collect::<Vec<_>>();
    assert_eq!(negative_responses.len(), 6);
    assert!(
      negative_responses
        .iter()
        .all(|value| value["result"]["approved"] == false
          || value["result"]["accepted"] == false
          || value["result"]["granted"] == false
          || value["result"]["success"] == false)
    );
  }

  #[test]
  fn jsonl_client_resumes_thread_when_resume_thread_id_is_present() {
    let transport = FakeJsonlTransport::new([
      r#"{"jsonrpc":"2.0","id":1,"result":{}}"#,
      r#"{"jsonrpc":"2.0","id":2,"result":{"thread":{"id":"thread-existing"}}}"#,
      r#"{"jsonrpc":"2.0","id":3,"result":{"turn":{"id":"turn-1","items":[],"status":"inProgress"}}}"#,
      r#"{"jsonrpc":"2.0","method":"turn/completed","params":{"threadId":"thread-existing","turn":{"id":"turn-1","status":"completed","items":[]}}}"#,
    ]);
    let client = CodexAppServerJsonlClient::new(|| Ok(transport.clone()), true);

    let result = client
      .start_turn(&CodexAppServerRequest {
        conversation_id: "slack:W1:d2".to_owned(),
        resume_thread_id: Some("thread-existing".to_owned()),
        prompt: "Source references only".to_owned(),
        tool_policy: ToolPolicy::None,
        dynamic_tool_context: test_dynamic_tool_context(),
      })
      .expect("completed turn");

    assert_eq!(
      result,
      AgentTaskResult::accepted_dispatch_with_thread("thread-existing")
    );
    let writes = transport.writes();
    let methods = writes
      .iter()
      .map(|value| value["method"].as_str().expect("method"))
      .collect::<Vec<_>>();
    assert_eq!(
      methods,
      ["initialize", "initialized", "thread/resume", "turn/start"]
    );
    assert_eq!(writes[2]["params"]["threadId"], "thread-existing");
    assert!(writes[2]["params"].get("ephemeral").is_none());
    assert_eq!(writes[3]["params"]["threadId"], "thread-existing");
    assert_eq!(writes[3]["params"]["clientUserMessageId"], "slack:W1:d2");
  }

  #[test]
  fn jsonl_client_starts_replacement_thread_when_resume_session_is_archived() {
    let transport = FakeJsonlTransport::new([
      r#"{"jsonrpc":"2.0","id":1,"result":{}}"#,
      r#"{"jsonrpc":"2.0","id":2,"error":{"code":-32000,"message":"session thread-archived is archived. Run `codex unarchive thread-archived` to unarchive it first."}}"#,
      r#"{"jsonrpc":"2.0","id":3,"result":{"thread":{"id":"thread-replacement"}}}"#,
      r#"{"jsonrpc":"2.0","id":4,"result":{"turn":{"id":"turn-1","items":[],"status":"inProgress"}}}"#,
      r#"{"jsonrpc":"2.0","method":"turn/completed","params":{"threadId":"thread-replacement","turn":{"id":"turn-1","status":"completed","items":[]}}}"#,
    ]);
    let client = CodexAppServerJsonlClient::new(|| Ok(transport.clone()), true);

    let result = client
      .start_turn(&CodexAppServerRequest {
        conversation_id: "slack:W1:d2".to_owned(),
        resume_thread_id: Some("thread-archived".to_owned()),
        prompt: "Source references only".to_owned(),
        tool_policy: ToolPolicy::None,
        dynamic_tool_context: test_dynamic_tool_context(),
      })
      .expect("completed turn");

    assert_eq!(
      result,
      AgentTaskResult::accepted_dispatch_with_thread("thread-replacement")
    );
    let writes = transport.writes();
    let methods = writes
      .iter()
      .map(|value| value["method"].as_str().expect("method"))
      .collect::<Vec<_>>();
    assert_eq!(
      methods,
      [
        "initialize",
        "initialized",
        "thread/resume",
        "thread/start",
        "turn/start"
      ]
    );
    assert_eq!(writes[2]["params"]["threadId"], "thread-archived");
    assert_eq!(writes[3]["params"]["ephemeral"], true);
    assert_eq!(writes[4]["params"]["threadId"], "thread-replacement");
  }

  #[test]
  fn jsonl_client_starts_replacement_thread_when_resume_rollout_is_missing() {
    let transport = FakeJsonlTransport::new([
      r#"{"jsonrpc":"2.0","id":1,"result":{}}"#,
      r#"{"jsonrpc":"2.0","id":2,"error":{"code":-32000,"message":"no rollout found for thread id 019f746f-68db-7cf0-ab67-837fe466dca5"}}"#,
      r#"{"jsonrpc":"2.0","id":3,"result":{"thread":{"id":"thread-replacement"}}}"#,
      r#"{"jsonrpc":"2.0","id":4,"result":{"turn":{"id":"turn-1","items":[],"status":"inProgress"}}}"#,
      r#"{"jsonrpc":"2.0","method":"turn/completed","params":{"threadId":"thread-replacement","turn":{"id":"turn-1","status":"completed","items":[]}}}"#,
    ]);
    let client = CodexAppServerJsonlClient::new(|| Ok(transport.clone()), true);

    let result = client
      .start_turn(&CodexAppServerRequest {
        conversation_id: "slack:W1:d2".to_owned(),
        resume_thread_id: Some("thread-missing-rollout".to_owned()),
        prompt: "Source references only".to_owned(),
        tool_policy: ToolPolicy::None,
        dynamic_tool_context: test_dynamic_tool_context(),
      })
      .expect("completed turn");

    assert_eq!(
      result,
      AgentTaskResult::accepted_dispatch_with_thread("thread-replacement")
    );
    let writes = transport.writes();
    let methods = writes
      .iter()
      .map(|value| value["method"].as_str().expect("method"))
      .collect::<Vec<_>>();
    assert_eq!(
      methods,
      [
        "initialize",
        "initialized",
        "thread/resume",
        "thread/start",
        "turn/start"
      ]
    );
    assert_eq!(writes[2]["params"]["threadId"], "thread-missing-rollout");
    assert_eq!(writes[4]["params"]["threadId"], "thread-replacement");
  }

  #[test]
  fn jsonl_client_ignores_server_notifications_while_waiting_for_responses() {
    let transport = FakeJsonlTransport::new([
      r#"{"jsonrpc":"2.0","id":1,"result":{}}"#,
      r#"{"jsonrpc":"2.0","method":"remoteControl/status/changed","params":{"status":"disabled"}}"#,
      r#"{"jsonrpc":"2.0","id":2,"result":{"thread":{"id":"thread-1"}}}"#,
      r#"{"jsonrpc":"2.0","id":3,"result":{"turn":{"id":"turn-1","items":[],"status":"inProgress"}}}"#,
      r#"{"jsonrpc":"2.0","method":"turn/completed","params":{"threadId":"thread-1","turn":{"id":"turn-1","status":"completed","items":[]}}}"#,
    ]);
    let client = CodexAppServerJsonlClient::new(|| Ok(transport.clone()), true);

    let result = client
      .start_turn(&CodexAppServerRequest {
        conversation_id: "slack:W1:d1".to_owned(),
        resume_thread_id: None,
        prompt: "Source references only".to_owned(),
        tool_policy: ToolPolicy::None,
        dynamic_tool_context: test_dynamic_tool_context(),
      })
      .expect("completed turn after server notification");

    assert_eq!(
      result,
      AgentTaskResult::accepted_dispatch_with_thread("thread-1")
    );
  }

  #[test]
  fn jsonl_client_keeps_transport_open_until_turn_completed() {
    let transport = FakeJsonlTransport::new([
      r#"{"jsonrpc":"2.0","id":1,"result":{}}"#,
      r#"{"jsonrpc":"2.0","id":2,"result":{"thread":{"id":"thread-1"}}}"#,
      r#"{"jsonrpc":"2.0","id":3,"result":{"turn":{"id":"turn-1","items":[],"status":"inProgress"}}}"#,
      r#"{"jsonrpc":"2.0","method":"turn/started","params":{"threadId":"thread-1","turn":{"id":"turn-1","items":[],"status":"inProgress"}}}"#,
      r#"{"jsonrpc":"2.0","method":"item/completed","params":{"threadId":"thread-1","turnId":"turn-1","completedAtMs":1,"item":{"id":"agent-1","type":"agentMessage","phase":"final_answer","text":"Draft after work"}}}"#,
      r#"{"jsonrpc":"2.0","method":"turn/completed","params":{"threadId":"thread-1","turn":{"id":"turn-1","status":"completed","items":[{"id":"agent-1","type":"agentMessage","phase":"final_answer","text":"Draft after work"}]}}}"#,
    ]);
    let client = CodexAppServerJsonlClient::new(|| Ok(transport.clone()), true);

    let result = client
      .start_turn(&CodexAppServerRequest {
        conversation_id: "slack:W1:d1".to_owned(),
        resume_thread_id: None,
        prompt: "Source references only".to_owned(),
        tool_policy: ToolPolicy::None,
        dynamic_tool_context: test_dynamic_tool_context(),
      })
      .expect("completed turn");

    assert_eq!(
      result,
      AgentTaskResult::draft_with_thread("Draft after work", "thread-1")
    );
    assert_eq!(transport.inner.borrow().reads.len(), 0);
  }

  #[test]
  fn jsonl_client_observes_final_answer_delta_before_turn_completed() {
    let event_log = Rc::new(RefCell::new(Vec::new()));
    let observer = RecordingTurnEventObserver::new(event_log.clone());
    let transport = FakeJsonlTransport::new_with_event_log(
      [
        r#"{"jsonrpc":"2.0","id":1,"result":{}}"#,
        r#"{"jsonrpc":"2.0","id":2,"result":{"thread":{"id":"thread-1"}}}"#,
        r#"{"jsonrpc":"2.0","id":3,"result":{"turn":{"id":"turn-1","items":[],"status":"inProgress"}}}"#,
        r#"{"jsonrpc":"2.0","method":"item/started","params":{"threadId":"thread-1","turnId":"turn-1","item":{"id":"agent-final","type":"agentMessage","phase":"final_answer"}}}"#,
        r#"{"jsonrpc":"2.0","method":"item/agentMessage/delta","params":{"threadId":"thread-1","turnId":"turn-1","itemId":"agent-final","delta":"Hello"}}"#,
        r#"{"jsonrpc":"2.0","method":"turn/completed","params":{"threadId":"thread-1","turn":{"id":"turn-1","status":"completed","items":[{"id":"agent-final","type":"agentMessage","phase":"final_answer","text":"Hello world"}]}}}"#,
      ],
      Some(event_log.clone()),
    );
    let client = CodexAppServerJsonlClient::new(|| Ok(transport.clone()), true)
      .with_event_observer(observer.clone());

    let result = client
      .start_turn(&CodexAppServerRequest {
        conversation_id: "slack:W1:d1".to_owned(),
        resume_thread_id: None,
        prompt: "Source references only".to_owned(),
        tool_policy: ToolPolicy::None,
        dynamic_tool_context: test_dynamic_tool_context(),
      })
      .expect("completed turn");

    assert_eq!(
      result,
      AgentTaskResult::draft_with_thread("Hello world", "thread-1")
    );
    assert_eq!(
      observer.events.borrow().as_slice(),
      [
        CodexTurnEvent::AgentMessageStarted(CodexAgentMessageStartedEvent {
          thread_id: "thread-1".to_owned(),
          turn_id: "turn-1".to_owned(),
          item_id: "agent-final".to_owned(),
          phase: Some("final_answer".to_owned()),
        }),
        CodexTurnEvent::AgentMessageDelta(CodexAgentMessageDeltaEvent {
          thread_id: "thread-1".to_owned(),
          turn_id: "turn-1".to_owned(),
          item_id: "agent-final".to_owned(),
          phase: Some("final_answer".to_owned()),
          delta: "Hello".to_owned(),
        })
      ]
    );
    assert_eq!(
      event_log.borrow().as_slice(),
      [
        "read:item/started",
        "started:agent-final:final_answer",
        "read:item/agentMessage/delta",
        "delta:agent-final:Hello",
        "read:turn/completed",
      ]
    );
  }

  #[test]
  fn jsonl_client_distinguishes_commentary_and_final_answer_deltas_by_item_id() {
    let observer = RecordingTurnEventObserver::default();
    let transport = FakeJsonlTransport::new([
      r#"{"jsonrpc":"2.0","id":1,"result":{}}"#,
      r#"{"jsonrpc":"2.0","id":2,"result":{"thread":{"id":"thread-1"}}}"#,
      r#"{"jsonrpc":"2.0","id":3,"result":{"turn":{"id":"turn-1","items":[],"status":"inProgress"}}}"#,
      r#"{"jsonrpc":"2.0","method":"item/started","params":{"threadId":"thread-1","turnId":"turn-1","item":{"id":"agent-commentary","type":"agentMessage","phase":"commentary"}}}"#,
      r#"{"jsonrpc":"2.0","method":"item/agentMessage/delta","params":{"threadId":"thread-1","turnId":"turn-1","itemId":"agent-commentary","delta":"Working"}}"#,
      r#"{"jsonrpc":"2.0","method":"item/started","params":{"threadId":"thread-1","turnId":"turn-1","item":{"id":"agent-final","type":"agentMessage","phase":"final_answer"}}}"#,
      r#"{"jsonrpc":"2.0","method":"item/agentMessage/delta","params":{"threadId":"thread-1","turnId":"turn-1","itemId":"agent-final","delta":"Done"}}"#,
      r#"{"jsonrpc":"2.0","method":"turn/completed","params":{"threadId":"thread-1","turn":{"id":"turn-1","status":"completed","items":[{"id":"agent-final","type":"agentMessage","phase":"final_answer","text":"Done"}]}}}"#,
    ]);
    let client = CodexAppServerJsonlClient::new(|| Ok(transport.clone()), true)
      .with_event_observer(observer.clone());

    let result = client
      .start_turn(&CodexAppServerRequest {
        conversation_id: "slack:W1:d1".to_owned(),
        resume_thread_id: None,
        prompt: "Source references only".to_owned(),
        tool_policy: ToolPolicy::None,
        dynamic_tool_context: test_dynamic_tool_context(),
      })
      .expect("completed turn");

    assert_eq!(
      result,
      AgentTaskResult::draft_with_thread("Done", "thread-1")
    );
    let events = observer.events.borrow();
    assert_eq!(
      events.as_slice(),
      [
        CodexTurnEvent::AgentMessageStarted(CodexAgentMessageStartedEvent {
          thread_id: "thread-1".to_owned(),
          turn_id: "turn-1".to_owned(),
          item_id: "agent-commentary".to_owned(),
          phase: Some("commentary".to_owned()),
        }),
        CodexTurnEvent::AgentMessageDelta(CodexAgentMessageDeltaEvent {
          thread_id: "thread-1".to_owned(),
          turn_id: "turn-1".to_owned(),
          item_id: "agent-commentary".to_owned(),
          phase: Some("commentary".to_owned()),
          delta: "Working".to_owned(),
        }),
        CodexTurnEvent::AgentMessageStarted(CodexAgentMessageStartedEvent {
          thread_id: "thread-1".to_owned(),
          turn_id: "turn-1".to_owned(),
          item_id: "agent-final".to_owned(),
          phase: Some("final_answer".to_owned()),
        }),
        CodexTurnEvent::AgentMessageDelta(CodexAgentMessageDeltaEvent {
          thread_id: "thread-1".to_owned(),
          turn_id: "turn-1".to_owned(),
          item_id: "agent-final".to_owned(),
          phase: Some("final_answer".to_owned()),
          delta: "Done".to_owned(),
        })
      ]
    );
  }

  #[test]
  fn jsonl_client_reports_terminal_turn_without_draft_as_accepted_dispatch() {
    let transport = FakeJsonlTransport::new([
      r#"{"jsonrpc":"2.0","id":1,"result":{}}"#,
      r#"{"jsonrpc":"2.0","id":2,"result":{"thread":{"id":"thread-1"}}}"#,
      r#"{"jsonrpc":"2.0","id":3,"result":{"turn":{"id":"turn-1","items":[],"status":"inProgress"}}}"#,
      r#"{"jsonrpc":"2.0","method":"turn/completed","params":{"threadId":"thread-1","turn":{"id":"turn-1","status":"completed","items":[]}}}"#,
    ]);
    let client = CodexAppServerJsonlClient::new(|| Ok(transport.clone()), true);

    let result = client
      .start_turn(&CodexAppServerRequest {
        conversation_id: "slack:W1:d1".to_owned(),
        resume_thread_id: None,
        prompt: "Source references only".to_owned(),
        tool_policy: ToolPolicy::None,
        dynamic_tool_context: test_dynamic_tool_context(),
      })
      .expect("completed turn");

    assert_eq!(
      result,
      AgentTaskResult::accepted_dispatch_with_thread("thread-1")
    );
  }

  #[test]
  fn jsonl_client_rejects_turn_start_errors() {
    let transport = FakeJsonlTransport::new([
      r#"{"jsonrpc":"2.0","id":1,"result":{}}"#,
      r#"{"jsonrpc":"2.0","id":2,"result":{"thread":{"id":"thread-1"}}}"#,
      r#"{"jsonrpc":"2.0","id":3,"error":{"message":"denied"}}"#,
    ]);
    let client = CodexAppServerJsonlClient::new(|| Ok(transport.clone()), true);

    let error = client
      .start_turn(&CodexAppServerRequest {
        conversation_id: "slack:W1:d1".to_owned(),
        resume_thread_id: None,
        prompt: "Source references only".to_owned(),
        tool_policy: ToolPolicy::None,
        dynamic_tool_context: test_dynamic_tool_context(),
      })
      .expect_err("turn/start error");

    assert_eq!(error, "codex app server turn/start failed: denied");
  }

  #[test]
  fn builds_stdio_backend_from_config_without_starting_process() {
    let mut config = CodeoffConfig::default();
    config.agent.codex_app_server.command = "codex app-server".to_owned();
    config.agent.codex_app_server.transport = "stdio".to_owned();
    config.agent.codex_app_server.ephemeral_threads = false;

    let backend = build_codex_app_server_backend(&config).expect("build backend");

    assert_eq!(backend.provider_name(), "codex-app-server");
  }

  #[test]
  fn rejects_unsupported_app_server_transport() {
    let mut config = CodeoffConfig::default();
    config.agent.codex_app_server.transport = "http".to_owned();

    let error = build_codex_app_server_backend(&config).expect_err("unsupported transport");

    assert_eq!(
      error,
      "unsupported codex app server transport: http (only stdio is supported)"
    );
  }

  #[derive(Clone)]
  struct StaticDynamicToolHandler {
    specs: Vec<Value>,
  }

  impl StaticDynamicToolHandler {
    fn new(specs: Vec<Value>) -> Self {
      Self { specs }
    }
  }

  impl CodexDynamicToolHandler for StaticDynamicToolHandler {
    fn tool_specs(&self, _context: &CodexDynamicToolContext) -> Vec<Value> {
      self.specs.clone()
    }

    fn handle_tool_call(
      &self,
      _context: &CodexDynamicToolContext,
      _tool: &str,
      _arguments: Value,
    ) -> Value {
      json!({
        "success": false,
        "contentItems": [
          {
            "type": "inputText",
            "text": "not implemented"
          }
        ]
      })
    }
  }

  #[derive(Clone)]
  struct RecordingDynamicToolHandler {
    result: Value,
    calls: Rc<RefCell<Vec<(String, Value)>>>,
    contexts: Rc<RefCell<Vec<CodexDynamicToolContext>>>,
  }

  impl RecordingDynamicToolHandler {
    fn new(result: Value) -> Self {
      Self {
        result,
        calls: Rc::new(RefCell::new(Vec::new())),
        contexts: Rc::new(RefCell::new(Vec::new())),
      }
    }
  }

  impl CodexDynamicToolHandler for RecordingDynamicToolHandler {
    fn tool_specs(&self, _context: &CodexDynamicToolContext) -> Vec<Value> {
      ["channel_reply_to_event", "old_tool"]
        .into_iter()
        .map(|name| {
          json!({
            "name": name,
            "description": "test tool",
            "inputSchema": { "type": "object" }
          })
        })
        .collect()
    }

    fn handle_tool_call(
      &self,
      context: &CodexDynamicToolContext,
      tool: &str,
      arguments: Value,
    ) -> Value {
      self.contexts.borrow_mut().push(context.clone());
      self.calls.borrow_mut().push((tool.to_owned(), arguments));
      self.result.clone()
    }
  }

  #[derive(Clone, Default)]
  struct RecordingTurnEventObserver {
    events: Rc<RefCell<Vec<CodexTurnEvent>>>,
    event_log: Option<Rc<RefCell<Vec<String>>>>,
  }

  impl RecordingTurnEventObserver {
    fn new(event_log: Rc<RefCell<Vec<String>>>) -> Self {
      Self {
        events: Rc::new(RefCell::new(Vec::new())),
        event_log: Some(event_log),
      }
    }
  }

  impl CodexTurnEventObserver for RecordingTurnEventObserver {
    fn observe_codex_turn_event(&self, event: CodexTurnEvent) {
      if let Some(event_log) = &self.event_log {
        match &event {
          CodexTurnEvent::AgentMessageStarted(started) => {
            event_log.borrow_mut().push(format!(
              "started:{}:{}",
              started.item_id,
              started.phase.as_deref().unwrap_or("")
            ));
          }
          CodexTurnEvent::AgentMessageDelta(delta) => {
            event_log
              .borrow_mut()
              .push(format!("delta:{}:{}", delta.item_id, delta.delta));
          }
        }
      }
      self.events.borrow_mut().push(event);
    }
  }
}
