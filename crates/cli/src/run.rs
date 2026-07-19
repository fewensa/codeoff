use std::collections::HashMap;
use std::error::Error;
use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use clap::Parser;
use codeoff_agent_codex::{
  CodexAppServerBackend, CodexDynamicToolHandler, CodexTurnEvent, CodexTurnEventObserver,
  StdioCodexAppServerClient, build_codex_app_server_backend,
};
use codeoff_agent_contract::{AgentBackend, AgentTask, AgentTaskResult};
use codeoff_channel_contract::{
  ChannelContextPage, ChannelContextRequest, ChannelEvent, ChannelMessageReceipt,
  ChannelReplyTarget,
};
use codeoff_channel_slack::{
  SlackConfigError, SlackDeliveryQueue, SlackIntake, SlackIntakeResult, SlackReqwestWebApiClient,
  SlackSocketClient, SlackWebApiClient, SlackWebApiError, SocketWorkerAction, SocketWorkerOptions,
  check_slack_worker, run_socket_worker,
};
use codeoff_config::{
  CodeoffConfig, ConfigLoadOptions, SlackDirectMessageFeedbackMode, SlackResponseFeedbackMode,
};
use codeoff_mcp::McpTcpServer;
use codeoff_runtime::{
  ConversationDispatchLocks, DispatchOutcome, ProcessingStreamFinishOutcome,
  ProcessingStreamFinishRequest, ProcessingStreamManager, ProcessingStreamStartRequest,
  StateProcessingStreamManager,
  channel_tools::{
    ChannelContextProvider, ChannelContextProviderError, ChannelDynamicToolHandler,
    ChannelResourceProvider,
  },
  dispatch_next_channel_event_with_processing_streams_context_and_locks,
};
use codeoff_state::{RetentionPolicy, StateError, StateStore};

use crate::command::{Cli, Command, ConfigCommand, WorkerCommand};

/// Parses CLI arguments and runs the selected Codeoff command.
///
/// # Errors
///
/// Returns an error when a command needs configuration and loading or validation fails.
pub fn run() -> Result<(), Box<dyn Error>> {
  run_with_cli(Cli::parse())
}

fn run_with_cli(cli: Cli) -> Result<(), Box<dyn Error>> {
  match cli.command {
    Command::Serve { check } => run_serve(check, cli.config, cli.state_dir),
    Command::Worker { command } => run_worker(command, cli.config, cli.state_dir),
    Command::Migrate => run_migrate(cli.config, cli.state_dir),
    Command::Config { command } => run_config(command, cli.config, cli.state_dir),
    Command::Dev => {
      println!("codeoff dev is not implemented yet");
      Ok(())
    }
  }
}

fn run_serve(
  check: bool,
  config_path: Option<PathBuf>,
  state_dir: Option<PathBuf>,
) -> Result<(), Box<dyn Error>> {
  let config = load_config(config_path, state_dir)?;
  config.validate()?;
  let runtime = tokio::runtime::Runtime::new()?;
  let state = runtime.block_on(StateStore::initialize(
    config.state_dir(),
    config.database_url(),
  ))?;

  if check {
    let status = ServeStatus::from_config(&config, check, false);
    println!("serve check ok");
    for line in status.status_lines() {
      println!("{line}");
    }
    return Ok(());
  }

  let mcp_server_started = runtime.block_on(maybe_spawn_mcp_tcp_server(&config, state.clone()))?;
  let status = ServeStatus::from_config(&config, check, mcp_server_started);
  println!("serve started");
  for line in status.status_lines() {
    println!("{line}");
  }
  runtime.block_on(run_serve_loops(config, state))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ServeStatus {
  slack_intake: String,
  channel_dispatch: String,
  codex_backend: String,
  mcp: String,
  slack_delivery: String,
}

impl ServeStatus {
  fn from_config(config: &CodeoffConfig, check: bool, mcp_server_started: bool) -> Self {
    Self {
      slack_intake: slack_intake_status(config),
      channel_dispatch: channel_dispatch_status(config, check),
      codex_backend: codex_backend_status(config),
      mcp: mcp_status(config, check, mcp_server_started),
      slack_delivery: slack_delivery_status(config, check),
    }
  }

  fn status_lines(&self) -> Vec<&str> {
    vec![
      "state=initialized",
      &self.slack_intake,
      &self.channel_dispatch,
      &self.codex_backend,
      &self.mcp,
      &self.slack_delivery,
    ]
  }
}

fn slack_intake_status(config: &CodeoffConfig) -> String {
  let slack = &config.slack;
  if slack.transport != "socket_mode" {
    return format!("slack_intake=disabled transport={}", slack.transport);
  }

  match check_slack_worker(slack) {
    Ok(_) => format!(
      "slack_intake=ready transport=socket_mode workspace_id={}",
      slack.workspace_id
    ),
    Err(SlackConfigError::MissingSecret { env_var }) => {
      format!("slack_intake=unavailable transport=socket_mode missing_env={env_var}")
    }
    Err(error) => format!("slack_intake=unavailable transport=socket_mode reason={error}"),
  }
}

fn channel_dispatch_status(config: &CodeoffConfig, check: bool) -> String {
  match build_codex_app_server_backend(config) {
    Ok(_) => format!(
      "channel_dispatch={} backend=codex_app_server",
      if check { "wired" } else { "started" }
    ),
    Err(error) => format!("channel_dispatch=unavailable reason={error}"),
  }
}

fn codex_backend_status(config: &CodeoffConfig) -> String {
  match build_codex_app_server_backend(config) {
    Ok(_) => format!(
      "codex_backend=constructed transport={}",
      config.agent.codex_app_server.transport
    ),
    Err(error) => format!("codex_backend=unavailable reason={error}"),
  }
}

fn slack_delivery_status(config: &CodeoffConfig, check: bool) -> String {
  match std::env::var(&config.slack.bot_token_env) {
    Ok(_) => format!(
      "slack_delivery={} queue=next_due",
      if check { "wired" } else { "started" }
    ),
    Err(_) => format!(
      "slack_delivery=unavailable missing_env={}",
      config.slack.bot_token_env
    ),
  }
}

fn mcp_status(config: &CodeoffConfig, check: bool, server_started: bool) -> String {
  if !config.mcp.enabled {
    return "mcp=disabled".to_owned();
  }

  match config.mcp.transport.as_str() {
    "stdio" => "mcp=configured transport=stdio server_loop=not-started".to_owned(),
    "tcp" => format!(
      "mcp=configured transport=tcp bind={} server_loop={}",
      config.mcp.bind,
      if check {
        "wired"
      } else if server_started {
        "started"
      } else {
        "not-started"
      }
    ),
    transport => format!("mcp=unavailable transport={transport}"),
  }
}

async fn maybe_spawn_mcp_tcp_server(
  config: &CodeoffConfig,
  state: StateStore,
) -> Result<bool, Box<dyn Error>> {
  if !config.mcp.enabled || config.mcp.transport != "tcp" {
    return Ok(false);
  }

  let server_started = match build_channel_resource_provider(config) {
    Some(resource_provider) => {
      let server = match build_channel_address_provider(config) {
        Some(address_provider) => {
          McpTcpServer::bind_with_resource_and_address_provider(
            config.mcp.bind.as_str(),
            state,
            build_channel_context_provider(config),
            resource_provider,
            address_provider,
          )
          .await?
        }
        None => {
          McpTcpServer::bind_with_resource_provider(
            config.mcp.bind.as_str(),
            state,
            build_channel_context_provider(config),
            resource_provider,
          )
          .await?
        }
      };
      tokio::spawn(async move {
        if let Err(error) = server.run().await {
          eprintln!("MCP TCP server loop stopped: {error}");
        }
      });
      true
    }
    None => {
      let server = McpTcpServer::bind(
        config.mcp.bind.as_str(),
        state,
        build_channel_context_provider(config),
      )
      .await?;
      tokio::spawn(async move {
        if let Err(error) = server.run().await {
          eprintln!("MCP TCP server loop stopped: {error}");
        }
      });
      true
    }
  };
  Ok(server_started)
}

fn build_channel_context_provider(config: &CodeoffConfig) -> ServeChannelContextProvider {
  match std::env::var(&config.slack.bot_token_env) {
    Ok(bot_token) => {
      ServeChannelContextProvider::Slack(Arc::new(build_slack_web_api_client(config, bot_token)))
    }
    Err(_) => ServeChannelContextProvider::Unavailable,
  }
}

fn build_channel_resource_provider(
  config: &CodeoffConfig,
) -> Option<Arc<dyn ChannelResourceProvider>> {
  let bot_token = std::env::var(&config.slack.bot_token_env).ok()?;
  Some(Arc::new(build_slack_web_api_client(config, bot_token)))
}

fn build_channel_address_provider(
  config: &CodeoffConfig,
) -> Option<Arc<SlackWebApiClient<SlackReqwestWebApiClient>>> {
  let bot_token = std::env::var(&config.slack.bot_token_env).ok()?;
  Some(Arc::new(build_slack_web_api_client(config, bot_token)))
}

fn build_slack_web_api_client(
  config: &CodeoffConfig,
  bot_token: String,
) -> SlackWebApiClient<SlackReqwestWebApiClient> {
  SlackWebApiClient::new_with_artifact_root(
    SlackReqwestWebApiClient::new(),
    "slack-default",
    bot_token,
    config.slack.clone(),
    now_unix_seconds(),
    config.state_dir().to_path_buf(),
  )
}

#[derive(Clone)]
enum ServeChannelContextProvider {
  Slack(Arc<SlackWebApiClient<SlackReqwestWebApiClient>>),
  Unavailable,
}

#[async_trait]
impl ChannelContextProvider for ServeChannelContextProvider {
  async fn fetch_context(
    &self,
    request: ChannelContextRequest,
  ) -> Result<ChannelContextPage, ChannelContextProviderError> {
    match self {
      Self::Slack(client) => client
        .fetch_context(&request)
        .await
        .map_err(channel_context_provider_error),
      Self::Unavailable => Err(ChannelContextProviderError::Unavailable),
    }
  }
}

fn channel_context_provider_error(error: SlackWebApiError) -> ChannelContextProviderError {
  match error {
    SlackWebApiError::Request { message } => ChannelContextProviderError::Request { message },
    SlackWebApiError::RateLimited {
      retry_after_seconds,
    } => ChannelContextProviderError::RateLimited {
      retry_after_seconds,
    },
    SlackWebApiError::Unavailable => ChannelContextProviderError::Unavailable,
    SlackWebApiError::InvalidResponse { message } => {
      ChannelContextProviderError::InvalidResponse { message }
    }
    SlackWebApiError::Provider { message } => ChannelContextProviderError::Provider { message },
    SlackWebApiError::UnsupportedTarget => ChannelContextProviderError::UnsupportedTarget,
    SlackWebApiError::Deferred { available_at } => {
      ChannelContextProviderError::Deferred { available_at }
    }
  }
}

#[derive(Clone)]
struct ServeDispatchContextProvider {
  inner: ServeChannelContextProvider,
  slack_streams: SlackCodexStreamController,
}

impl ServeDispatchContextProvider {
  const fn new(
    inner: ServeChannelContextProvider,
    slack_streams: SlackCodexStreamController,
  ) -> Self {
    Self {
      inner,
      slack_streams,
    }
  }
}

#[async_trait]
impl ChannelContextProvider for ServeDispatchContextProvider {
  async fn fetch_context(
    &self,
    request: ChannelContextRequest,
  ) -> Result<ChannelContextPage, ChannelContextProviderError> {
    match &request.target {
      ChannelReplyTarget::Channel { channel_id }
      | ChannelReplyTarget::Thread { channel_id, .. }
        if channel_id.starts_with('D') =>
      {
        self
          .slack_streams
          .ensure_direct_message_loading(channel_id, AssistantState::Searching);
      }
      _ => {}
    }
    self.inner.fetch_context(request).await
  }
}

async fn run_serve_loops(config: CodeoffConfig, state: StateStore) -> Result<(), Box<dyn Error>> {
  let tick_limit = serve_tick_limit();
  if tick_limit.is_none() {
    maybe_spawn_slack_intake_loop(&config, state.clone());
    maybe_spawn_retention_cleanup_loop(&config, state.clone());
  }
  let assistant_status = build_assistant_status_controller(&config);
  let slack_streams = build_slack_codex_stream_controller(&config, assistant_status.clone());
  let backend = build_serve_codex_app_server_backend(
    &config,
    state.clone(),
    assistant_status.clone(),
    slack_streams.clone(),
  )
  .ok()
  .map(|backend| {
    build_feedback_agent_backend(&config, backend, assistant_status, slack_streams.clone())
  });
  let dispatch_context_provider = ServeDispatchContextProvider::new(
    build_channel_context_provider(&config),
    slack_streams.clone(),
  );
  let processing_streams = build_processing_stream_manager(&config, state.clone());
  let delivery = build_slack_delivery_queue(&config, state.clone());

  if should_spawn_background_dispatch_loop(tick_limit, backend.is_some()) {
    if backend.is_some() {
      spawn_channel_dispatch_loops(
        config.clone(),
        state.clone(),
        processing_streams,
        channel_dispatch_worker_count(&config),
      );
    }
    return run_slack_delivery_loop(delivery.as_ref()).await;
  }

  let mut ticks = 0_u64;

  loop {
    if let Some(limit) = tick_limit {
      if ticks >= limit {
        break;
      }
    }
    ticks = ticks.saturating_add(1);
    let dispatched = match backend.as_ref() {
      Some(backend) => {
        run_channel_dispatch_tick(
          &state,
          backend,
          &processing_streams,
          &dispatch_context_provider,
          config.slack.recent_message_limit,
          None,
        )
        .await?
      }
      None => false,
    };
    let delivered = match delivery.as_ref() {
      Some(delivery) => run_slack_delivery_tick(delivery).await?,
      None => false,
    };
    if !dispatched && !delivered {
      tokio::time::sleep(Duration::from_millis(250)).await;
    }
  }
  Ok(())
}

fn should_spawn_background_dispatch_loop(tick_limit: Option<u64>, has_backend: bool) -> bool {
  tick_limit.is_none() && has_backend
}

fn channel_dispatch_worker_count(config: &CodeoffConfig) -> usize {
  config.agent.codex_app_server.max_parallel_turns.max(1)
}

fn serve_tick_limit() -> Option<u64> {
  std::env::var("CODEOFF_SERVE_TICK_LIMIT")
    .ok()
    .and_then(|value| value.parse().ok())
}

const SLACK_INTAKE_RESTART_MAX_DELAY_SECS: u64 = 30;

fn maybe_spawn_slack_intake_loop(config: &CodeoffConfig, state: StateStore) {
  if check_slack_worker(&config.slack).is_err() {
    return;
  }
  let Ok(app_token) = std::env::var(&config.slack.app_token_env) else {
    return;
  };
  let slack = config.slack.clone();
  tokio::spawn(async move {
    let intake = SlackIntake::with_slack_config(state, "slack-default", &slack);
    let mut restart_count = 0_u32;
    loop {
      let mut transport = SlackSocketClient::new();
      let result = run_socket_worker(
        &mut transport,
        &app_token,
        SocketWorkerOptions::default(),
        {
          let intake = intake.clone();
          move |raw_envelope| {
            let intake = intake.clone();
            async move {
              match intake.accept(&raw_envelope).await {
                Ok(SlackIntakeResult::Ignored) => {
                  eprintln!("ignored unsupported Slack Socket Mode envelope");
                }
                Ok(SlackIntakeResult::Queued | SlackIntakeResult::Duplicate) => {}
                Err(error) => {
                  eprintln!("failed to intake Slack Socket Mode envelope: {error}");
                }
              }
              SocketWorkerAction::Continue
            }
          }
        },
      )
      .await;
      match result {
        Ok(_) => return,
        Err(error) => {
          let delay = slack_intake_restart_delay(restart_count);
          restart_count = restart_count.saturating_add(1);
          eprintln!(
            "Slack Socket Mode intake loop stopped: {error}; restarting in {}s",
            delay.as_secs()
          );
          tokio::time::sleep(delay).await;
        }
      }
    }
  });
}

fn slack_intake_restart_delay(restart_count: u32) -> Duration {
  let delay = 1_u64
    .checked_shl(restart_count.min(5))
    .unwrap_or(SLACK_INTAKE_RESTART_MAX_DELAY_SECS);
  Duration::from_secs(delay.min(SLACK_INTAKE_RESTART_MAX_DELAY_SECS))
}

fn maybe_spawn_retention_cleanup_loop(config: &CodeoffConfig, state: StateStore) {
  let policy = retention_policy_from_config(config);
  if !policy.enabled {
    return;
  }
  let workspace_id = config.slack.workspace_id.clone();
  tokio::spawn(async move {
    loop {
      if let Err(error) = state
        .cleanup_retained_data(Some(&workspace_id), now_unix_seconds(), &policy)
        .await
      {
        eprintln!("retention cleanup failed: {error}");
      }
      tokio::time::sleep(Duration::from_secs(24 * 60 * 60)).await;
    }
  });
}

fn retention_policy_from_config(config: &CodeoffConfig) -> RetentionPolicy {
  RetentionPolicy {
    enabled: config.data_retention.enabled,
    inbound_payload_days: config.data_retention.inbound_payload_days,
    delivery_days: config.data_retention.delivery_days,
    context_attempt_days: config.data_retention.context_attempt_days,
    conversation_summary_days: config.data_retention.conversation_summary_days,
    artifact_days: config.data_retention.artifact_days,
  }
}

fn spawn_channel_dispatch_loops(
  config: CodeoffConfig,
  state: StateStore,
  processing_streams: ServeProcessingStreamManager,
  worker_count: usize,
) {
  let locks = ConversationDispatchLocks::default();
  for _ in 0..worker_count.max(1) {
    let config = config.clone();
    let state = state.clone();
    let processing_streams = processing_streams.clone();
    let locks = locks.clone();
    let assistant_status = build_assistant_status_controller(&config);
    let slack_streams = build_slack_codex_stream_controller(&config, assistant_status.clone());
    let Ok(backend) = build_serve_codex_app_server_backend(
      &config,
      state.clone(),
      assistant_status.clone(),
      slack_streams.clone(),
    )
    .map(|backend| {
      build_feedback_agent_backend(&config, backend, assistant_status, slack_streams.clone())
    }) else {
      continue;
    };
    let context_provider = ServeDispatchContextProvider::new(
      build_channel_context_provider(&config),
      slack_streams.clone(),
    );
    let context_limit = config.slack.recent_message_limit;
    tokio::spawn(async move {
      loop {
        match run_channel_dispatch_tick_on_blocking_pool(
          state.clone(),
          backend.clone(),
          processing_streams.clone(),
          context_provider.clone(),
          context_limit,
          Some(locks.clone()),
        )
        .await
        {
          Ok(true) => {}
          Ok(false) => tokio::time::sleep(Duration::from_millis(250)).await,
          Err(error) => {
            eprintln!("channel dispatch tick failed: {error}");
            tokio::time::sleep(Duration::from_secs(1)).await;
          }
        }
      }
    });
  }
}

fn build_processing_stream_manager(
  config: &CodeoffConfig,
  state: StateStore,
) -> ServeProcessingStreamManager {
  let state_manager = StateProcessingStreamManager::new(state);
  match std::env::var(&config.slack.bot_token_env) {
    Ok(bot_token) => ServeProcessingStreamManager::Slack {
      state_manager,
      _client: Arc::new(SlackWebApiClient::new(
        SlackReqwestWebApiClient::new(),
        "slack-default",
        bot_token,
        config.slack.clone(),
        now_unix_seconds(),
      )),
    },
    Err(_) => ServeProcessingStreamManager::Unavailable { state_manager },
  }
}

#[derive(Clone)]
enum ServeProcessingStreamManager {
  Slack {
    state_manager: StateProcessingStreamManager,
    _client: Arc<SlackWebApiClient<SlackReqwestWebApiClient>>,
  },
  Unavailable {
    state_manager: StateProcessingStreamManager,
  },
}

#[async_trait]
impl ProcessingStreamManager for ServeProcessingStreamManager {
  async fn start_processing_stream(
    &self,
    _request: ProcessingStreamStartRequest,
  ) -> Result<(), StateError> {
    Ok(())
  }

  async fn finish_processing_stream(
    &self,
    request: ProcessingStreamFinishRequest,
  ) -> Result<ProcessingStreamFinishOutcome, StateError> {
    match self {
      Self::Slack { state_manager, .. } | Self::Unavailable { state_manager } => {
        state_manager.finish_processing_stream(request).await
      }
    }
  }
}

fn build_feedback_agent_backend<B>(
  config: &CodeoffConfig,
  backend: B,
  assistant_status: AssistantStatusController,
  slack_streams: SlackCodexStreamController,
) -> FeedbackAgentBackend<B> {
  FeedbackAgentBackend {
    inner: backend,
    config: config.clone(),
    assistant_status,
    slack_streams,
  }
}

#[derive(Clone)]
struct FeedbackAgentBackend<B> {
  inner: B,
  config: CodeoffConfig,
  assistant_status: AssistantStatusController,
  slack_streams: SlackCodexStreamController,
}

impl<B: AgentBackend> AgentBackend for FeedbackAgentBackend<B> {
  fn provider_name(&self) -> &'static str {
    self.inner.provider_name()
  }

  fn run(&self, task: AgentTask) -> Result<AgentTaskResult, String> {
    let target = assistant_status_target(
      &self.config,
      task.context.channel_id.as_deref(),
      task.context.thread_id.as_deref(),
      task.context.message_ts.as_deref(),
    );
    let guard = target.map(|target| {
      self
        .assistant_status
        .start(target, self.config.slack.response_feedback.status_delay_ms)
    });
    let stream_target = slack_codex_stream_target(&self.config, &task);
    let stream_guard = stream_target.map(|target| self.slack_streams.start(target));
    let result = self.inner.run(task);
    let result = match (result, stream_guard.as_ref()) {
      (
        Ok(AgentTaskResult::Draft {
          content,
          codex_thread_id,
        }),
        Some(_),
      ) if self.slack_streams.finish_final_answer(&content) => Ok(match codex_thread_id {
        Some(codex_thread_id) => AgentTaskResult::accepted_dispatch_with_thread(codex_thread_id),
        None => AgentTaskResult::accepted_dispatch(),
      }),
      (result, _) => result,
    };
    drop(stream_guard);
    drop(guard);
    result
  }
}

#[derive(Clone, Hash, PartialEq, Eq)]
struct AssistantStatusTarget {
  channel_id: String,
  thread_ts: String,
}

fn assistant_status_target(
  config: &CodeoffConfig,
  channel_id: Option<&str>,
  thread_ts: Option<&str>,
  message_ts: Option<&str>,
) -> Option<AssistantStatusTarget> {
  if matches!(
    config.slack.response_feedback.mode,
    SlackResponseFeedbackMode::Off | SlackResponseFeedbackMode::StreamMessage
  ) {
    return None;
  }
  let channel_id = channel_id?;
  if channel_id.starts_with('D')
    && config.slack.response_feedback.direct_message_feedback
      != SlackDirectMessageFeedbackMode::AssistantStatus
  {
    match (thread_ts, message_ts) {
      (Some(thread_ts), Some(message_ts)) if thread_ts != message_ts => {}
      _ => return None,
    }
  }
  let thread_ts = thread_ts.or(message_ts)?;
  Some(AssistantStatusTarget {
    channel_id: channel_id.to_owned(),
    thread_ts: thread_ts.to_owned(),
  })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AssistantState {
  ReviewingFindings,
  Searching,
  Processing,
  SummarizingFindings,
}

impl AssistantState {
  const fn status_text(self) -> &'static str {
    match self {
      Self::ReviewingFindings => "Reviewing findings...",
      Self::Searching => "Searching...",
      Self::Processing => "Processing...",
      Self::SummarizingFindings => "Summarizing findings...",
    }
  }

  fn loading_text(self, loading_tick: usize) -> String {
    let dots = (loading_tick % DIRECT_MESSAGE_LOADING_MAX_DOTS) + 1;
    format!(
      "{}{}",
      self.status_text().trim_end_matches('.'),
      ".".repeat(dots)
    )
  }
}

fn assistant_state_for_tool(tool: &str) -> Option<AssistantState> {
  match tool {
    "channel_get_thread_context" | "channel_get_recent_messages" => Some(AssistantState::Searching),
    "channel_get_delivery_status" => Some(AssistantState::Processing),
    "channel_reply_to_event" | "channel_send_message" => Some(AssistantState::SummarizingFindings),
    _ => None,
  }
}

fn assistant_state_for_agent_phase(phase: Option<&str>) -> Option<AssistantState> {
  match phase {
    Some("commentary") => Some(AssistantState::Processing),
    Some("final_answer") => Some(AssistantState::SummarizingFindings),
    _ => None,
  }
}

#[derive(Clone)]
struct AssistantStatusController {
  runtime: tokio::runtime::Handle,
  client: Option<Arc<dyn AssistantStatusTransport>>,
  active_sessions: Arc<Mutex<HashMap<std::thread::ThreadId, ActiveAssistantStatus>>>,
  dispatchers: Arc<Mutex<HashMap<AssistantStatusTarget, AssistantStatusDispatcher>>>,
  next_session_id: Arc<AtomicU64>,
}

#[derive(Clone)]
struct ActiveAssistantStatus {
  target: AssistantStatusTarget,
  session_id: u64,
  closed: Arc<AtomicBool>,
  terminal_clear_queued: Arc<AtomicBool>,
  should_clear: Arc<AtomicBool>,
}

#[derive(Clone)]
struct AssistantStatusDispatcher {
  sender: tokio::sync::mpsc::UnboundedSender<AssistantStatusCommand>,
  state: Arc<Mutex<AssistantStatusDispatcherState>>,
  target: Option<AssistantStatusTarget>,
  dispatchers: std::sync::Weak<Mutex<HashMap<AssistantStatusTarget, AssistantStatusDispatcher>>>,
}

struct AssistantStatusDispatcherState {
  current_session_id: u64,
  visible_session_id: u64,
  pending_set: Option<PendingAssistantStatusSet>,
  set_flush_scheduled: bool,
}

#[derive(Clone, Copy)]
struct PendingAssistantStatusSet {
  session_id: u64,
  state: AssistantState,
}

enum AssistantStatusCommand {
  FlushSet,
  Clear {
    session_id: u64,
    log_completion: bool,
  },
}

impl AssistantStatusDispatcher {
  fn without_client() -> Self {
    let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
    drop(receiver);
    Self {
      sender,
      state: Arc::new(Mutex::new(AssistantStatusDispatcherState {
        current_session_id: 0,
        visible_session_id: 0,
        pending_set: None,
        set_flush_scheduled: false,
      })),
      target: None,
      dispatchers: std::sync::Weak::new(),
    }
  }

  fn new(
    runtime: &tokio::runtime::Handle,
    client: Arc<dyn AssistantStatusTransport>,
    target: AssistantStatusTarget,
    dispatchers: std::sync::Weak<Mutex<HashMap<AssistantStatusTarget, AssistantStatusDispatcher>>>,
  ) -> Self {
    let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
    let state = Arc::new(Mutex::new(AssistantStatusDispatcherState {
      current_session_id: 0,
      visible_session_id: 0,
      pending_set: None,
      set_flush_scheduled: false,
    }));
    Self::spawn_worker(
      runtime,
      client,
      target.clone(),
      dispatchers.clone(),
      state.clone(),
      receiver,
    );
    Self {
      sender,
      state,
      target: Some(target),
      dispatchers,
    }
  }

  fn spawn_worker(
    runtime: &tokio::runtime::Handle,
    client: Arc<dyn AssistantStatusTransport>,
    target: AssistantStatusTarget,
    dispatchers: std::sync::Weak<Mutex<HashMap<AssistantStatusTarget, AssistantStatusDispatcher>>>,
    state: Arc<Mutex<AssistantStatusDispatcherState>>,
    mut receiver: tokio::sync::mpsc::UnboundedReceiver<AssistantStatusCommand>,
  ) {
    runtime.spawn(async move {
      while let Some(command) = receiver.recv().await {
        match command {
          AssistantStatusCommand::FlushSet => {
            Self::flush_pending_set(&client, &target, &state).await;
          }
          AssistantStatusCommand::Clear {
            session_id,
            log_completion,
          } => {
            Self::clear_visible_status(
              &client,
              &target,
              &dispatchers,
              &state,
              session_id,
              log_completion,
            )
            .await;
          }
        }
      }
    });
  }

  async fn flush_pending_set(
    client: &Arc<dyn AssistantStatusTransport>,
    target: &AssistantStatusTarget,
    state: &Arc<Mutex<AssistantStatusDispatcherState>>,
  ) {
    let pending = {
      let mut state = state.lock().expect("assistant status dispatcher");
      let pending = state.pending_set.take();
      state.set_flush_scheduled = false;
      pending
    };
    let Some(PendingAssistantStatusSet {
      session_id,
      state: assistant_state,
    }) = pending
    else {
      return;
    };
    if state
      .lock()
      .expect("assistant status dispatcher")
      .current_session_id
      != session_id
    {
      return;
    }
    let status = assistant_state.status_text();
    if let Err(error) = client
      .set(&target.channel_id, &target.thread_ts, status)
      .await
    {
      eprintln!("failed to set Slack assistant status: {error}");
      return;
    }
    eprintln!(
      "set Slack assistant status channel={} thread_ts={} status={status}",
      target.channel_id, target.thread_ts
    );
    state
      .lock()
      .expect("assistant status dispatcher")
      .visible_session_id = session_id;
  }

  async fn clear_visible_status(
    client: &Arc<dyn AssistantStatusTransport>,
    target: &AssistantStatusTarget,
    dispatchers: &std::sync::Weak<Mutex<HashMap<AssistantStatusTarget, AssistantStatusDispatcher>>>,
    state: &Arc<Mutex<AssistantStatusDispatcherState>>,
    session_id: u64,
    log_completion: bool,
  ) {
    if state
      .lock()
      .expect("assistant status dispatcher")
      .visible_session_id
      != session_id
    {
      return;
    }
    if let Err(error) = client.clear(&target.channel_id, &target.thread_ts).await {
      eprintln!("failed to clear Slack assistant status: {error}");
    } else if log_completion {
      eprintln!(
        "cleared Slack assistant status channel={} thread_ts={} session_id={session_id}",
        target.channel_id, target.thread_ts
      );
    }
    let retired = {
      let mut state = state.lock().expect("assistant status dispatcher");
      if state.visible_session_id == session_id {
        state.visible_session_id = 0;
      }
      if state.current_session_id == session_id {
        state.current_session_id = 0;
      }
      state.current_session_id == 0 && state.visible_session_id == 0
    };
    if retired {
      Self::remove_dispatcher_if_current(dispatchers, target, state);
    }
  }

  fn remove_dispatcher_if_current(
    dispatchers: &std::sync::Weak<Mutex<HashMap<AssistantStatusTarget, AssistantStatusDispatcher>>>,
    target: &AssistantStatusTarget,
    state: &Arc<Mutex<AssistantStatusDispatcherState>>,
  ) {
    let Some(dispatchers) = dispatchers.upgrade() else {
      return;
    };
    let mut dispatchers = dispatchers.lock().expect("assistant status dispatchers");
    if dispatchers
      .get(target)
      .is_some_and(|dispatcher| Arc::ptr_eq(&dispatcher.state, state))
    {
      dispatchers.remove(target);
    }
  }

  fn set(&self, active: &ActiveAssistantStatus, state: AssistantState) {
    if active.closed.load(Ordering::SeqCst) {
      return;
    }
    let schedule_flush = {
      let mut dispatcher_state = self.state.lock().expect("assistant status dispatcher");
      if dispatcher_state.current_session_id != active.session_id {
        return;
      }
      dispatcher_state.pending_set = Some(PendingAssistantStatusSet {
        session_id: active.session_id,
        state,
      });
      if dispatcher_state.set_flush_scheduled {
        false
      } else {
        dispatcher_state.set_flush_scheduled = true;
        true
      }
    };
    if schedule_flush {
      let _ = self.sender.send(AssistantStatusCommand::FlushSet);
    }
  }

  fn clear(&self, session_id: u64, log_completion: bool) {
    let _ = self.sender.send(AssistantStatusCommand::Clear {
      session_id,
      log_completion,
    });
  }

  fn close_session(active: &ActiveAssistantStatus) {
    active.closed.store(true, Ordering::SeqCst);
  }

  fn activate_session(&self, session_id: u64) {
    self
      .state
      .lock()
      .expect("assistant status dispatcher")
      .current_session_id = session_id;
  }

  fn retire_session(&self, session_id: u64) {
    let retired = {
      let mut state = self.state.lock().expect("assistant status dispatcher");
      if state.current_session_id == session_id {
        state.current_session_id = 0;
        state.visible_session_id == 0
      } else {
        false
      }
    };
    if !retired {
      return;
    }
    let Some(target) = self.target.as_ref() else {
      return;
    };
    Self::remove_dispatcher_if_current(&self.dispatchers, target, &self.state);
  }
}

#[async_trait]
trait AssistantStatusTransport: Send + Sync {
  async fn set(
    &self,
    channel_id: &str,
    thread_ts: &str,
    status: &str,
  ) -> Result<(), SlackWebApiError>;

  async fn clear(&self, channel_id: &str, thread_ts: &str) -> Result<(), SlackWebApiError>;
}

#[async_trait]
impl AssistantStatusTransport for SlackWebApiClient<SlackReqwestWebApiClient> {
  async fn set(
    &self,
    channel_id: &str,
    thread_ts: &str,
    status: &str,
  ) -> Result<(), SlackWebApiError> {
    self
      .set_assistant_status(channel_id, thread_ts, status, &[])
      .await
  }

  async fn clear(&self, channel_id: &str, thread_ts: &str) -> Result<(), SlackWebApiError> {
    self.clear_assistant_status(channel_id, thread_ts).await
  }
}

fn build_assistant_status_controller(config: &CodeoffConfig) -> AssistantStatusController {
  let client = std::env::var(&config.slack.bot_token_env)
    .ok()
    .map(|bot_token| {
      Arc::new(SlackWebApiClient::new(
        SlackReqwestWebApiClient::new(),
        "slack-default",
        bot_token,
        config.slack.clone(),
        now_unix_seconds(),
      )) as Arc<dyn AssistantStatusTransport>
    });
  AssistantStatusController {
    runtime: tokio::runtime::Handle::current(),
    client,
    active_sessions: Arc::new(Mutex::new(HashMap::new())),
    dispatchers: Arc::new(Mutex::new(HashMap::new())),
    next_session_id: Arc::new(AtomicU64::new(1)),
  }
}

impl AssistantStatusController {
  fn start(&self, target: AssistantStatusTarget, delay_ms: u64) -> AssistantStatusGuard {
    let (cancel, mut receiver) = tokio::sync::oneshot::channel();
    let active = ActiveAssistantStatus {
      target: target.clone(),
      session_id: self.next_session_id.fetch_add(1, Ordering::Relaxed),
      closed: Arc::new(AtomicBool::new(false)),
      terminal_clear_queued: Arc::new(AtomicBool::new(false)),
      should_clear: Arc::new(AtomicBool::new(false)),
    };
    self
      .dispatcher_for(&target)
      .activate_session(active.session_id);
    self
      .active_sessions
      .lock()
      .expect("assistant status sessions")
      .insert(std::thread::current().id(), active.clone());
    if self.client.is_some() {
      let status = self.clone();
      let delayed_active = active.clone();
      self.runtime.spawn(async move {
        tokio::select! {
          _ = tokio::time::sleep(Duration::from_millis(delay_ms)) => {
            status.set_state_for_session(&delayed_active, AssistantState::ReviewingFindings);
          }
          _ = &mut receiver => {}
        }
      });
    }
    AssistantStatusGuard {
      controller: self.clone(),
      active,
      cancel: Some(cancel),
    }
  }

  fn update_for_tool(&self, tool: &str) {
    if let Some(state) = assistant_state_for_tool(tool) {
      self.set_state_for_active_target(state);
    }
  }

  fn update_for_agent_phase(&self, phase: Option<&str>) {
    if let Some(state) = assistant_state_for_agent_phase(phase) {
      self.set_state_for_active_target(state);
    }
  }

  fn set_state_for_active_target(&self, state: AssistantState) {
    let Some(active) = self.active_for_current_thread() else {
      return;
    };
    self.set_state_for_session(&active, state);
  }

  fn set_state_for_session(&self, active: &ActiveAssistantStatus, state: AssistantState) {
    active.should_clear.store(true, Ordering::SeqCst);
    self.dispatcher_for(&active.target).set(active, state);
  }

  fn clear_active_now(&self) {
    let Some(active) = self.active_for_current_thread() else {
      return;
    };
    self.finish_session(&active, false);
  }

  fn active_for_current_thread(&self) -> Option<ActiveAssistantStatus> {
    self
      .active_sessions
      .lock()
      .expect("assistant status sessions")
      .get(&std::thread::current().id())
      .cloned()
  }

  fn finish_session(&self, active: &ActiveAssistantStatus, log_completion: bool) {
    if active.terminal_clear_queued.swap(true, Ordering::SeqCst) {
      return;
    }
    let dispatcher = self.dispatcher_for(&active.target);
    AssistantStatusDispatcher::close_session(active);
    dispatcher.clear(active.session_id, log_completion);
  }

  fn dispatcher_for(&self, target: &AssistantStatusTarget) -> AssistantStatusDispatcher {
    let Some(client) = self.client.clone() else {
      return AssistantStatusDispatcher::without_client();
    };
    let mut dispatchers = self
      .dispatchers
      .lock()
      .expect("assistant status dispatchers");
    dispatchers
      .entry(target.clone())
      .or_insert_with(|| {
        AssistantStatusDispatcher::new(
          &self.runtime,
          client,
          target.clone(),
          Arc::downgrade(&self.dispatchers),
        )
      })
      .clone()
  }
}

struct AssistantStatusGuard {
  controller: AssistantStatusController,
  active: ActiveAssistantStatus,
  cancel: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Drop for AssistantStatusGuard {
  fn drop(&mut self) {
    if let Some(cancel) = self.cancel.take() {
      let _ = cancel.send(());
    }
    let mut active_sessions = self
      .controller
      .active_sessions
      .lock()
      .expect("assistant status sessions");
    if active_sessions
      .get(&std::thread::current().id())
      .is_some_and(|active| active.session_id == self.active.session_id)
    {
      active_sessions.remove(&std::thread::current().id());
    }
    drop(active_sessions);
    if !self.active.should_clear.load(Ordering::SeqCst) {
      let dispatcher = self.controller.dispatcher_for(&self.active.target);
      AssistantStatusDispatcher::close_session(&self.active);
      dispatcher.retire_session(self.active.session_id);
      return;
    }
    self.controller.finish_session(&self.active, true);
  }
}

#[derive(Clone)]
struct SlackCodexStreamController {
  runtime: tokio::runtime::Handle,
  client: Option<Arc<SlackWebApiClient<SlackReqwestWebApiClient>>>,
  assistant_status: AssistantStatusController,
  direct_update_min_chars: usize,
  direct_message_feedback: SlackDirectMessageFeedbackMode,
  active: Arc<Mutex<Option<ActiveSlackCodexStream>>>,
}

#[derive(Clone)]
struct ActiveSlackCodexStream {
  target: SlackCodexStreamTarget,
  message_ts: Option<String>,
  final_text: String,
  last_update_len: usize,
  assistant_state: AssistantState,
  loading_tick: usize,
  loading_cancel: Option<Arc<AtomicBool>>,
  failed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SlackCodexStreamTarget {
  channel_id: String,
  kind: SlackCodexStreamTargetKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SlackCodexStreamTargetKind {
  DirectMessageUpdate,
  ThreadStream { thread_ts: String },
}

const DIRECT_MESSAGE_LOADING_MAX_DOTS: usize = 6;
const DIRECT_MESSAGE_LOADING_INTERVAL_MS: u64 = 850;

#[derive(Clone)]
struct SlackCodexStreamObserver {
  controller: SlackCodexStreamController,
}

struct SlackCodexStreamGuard {
  controller: SlackCodexStreamController,
}

fn build_slack_codex_stream_controller(
  config: &CodeoffConfig,
  assistant_status: AssistantStatusController,
) -> SlackCodexStreamController {
  let client = std::env::var(&config.slack.bot_token_env)
    .ok()
    .map(|bot_token| {
      Arc::new(SlackWebApiClient::new(
        SlackReqwestWebApiClient::new(),
        "slack-default",
        bot_token,
        config.slack.clone(),
        now_unix_seconds(),
      ))
    });
  SlackCodexStreamController {
    runtime: tokio::runtime::Handle::current(),
    client,
    assistant_status,
    direct_update_min_chars: config.slack.response_feedback.stream_min_content_chars,
    direct_message_feedback: config
      .slack
      .response_feedback
      .direct_message_feedback
      .clone(),
    active: Arc::new(Mutex::new(None)),
  }
}

fn slack_codex_stream_target(
  config: &CodeoffConfig,
  task: &AgentTask,
) -> Option<SlackCodexStreamTarget> {
  if matches!(
    config.slack.response_feedback.mode,
    SlackResponseFeedbackMode::Off | SlackResponseFeedbackMode::AssistantStatus
  ) {
    return None;
  }
  let channel_id = task.context.channel_id.as_deref()?;
  if !channel_id.starts_with('D') {
    return None;
  }
  if config.slack.response_feedback.direct_message_feedback
    == SlackDirectMessageFeedbackMode::AssistantStatus
  {
    return None;
  }
  let kind = match (
    task.context.thread_id.as_deref(),
    task.context.message_ts.as_deref(),
  ) {
    (Some(thread_ts), Some(message_ts)) if thread_ts != message_ts => {
      SlackCodexStreamTargetKind::ThreadStream {
        thread_ts: thread_ts.to_owned(),
      }
    }
    _ => SlackCodexStreamTargetKind::DirectMessageUpdate,
  };
  Some(SlackCodexStreamTarget {
    channel_id: channel_id.to_owned(),
    kind,
  })
}

fn should_flush_direct_message_update(
  current_len: usize,
  last_update_len: usize,
  min_content_chars: usize,
) -> bool {
  current_len.saturating_sub(last_update_len) >= min_content_chars.max(1)
}

impl SlackCodexStreamController {
  fn observer(&self) -> SlackCodexStreamObserver {
    SlackCodexStreamObserver {
      controller: self.clone(),
    }
  }

  fn start(&self, target: SlackCodexStreamTarget) -> SlackCodexStreamGuard {
    if self.reuse_existing_direct_message_loading(&target) {
      self.update_direct_message_loading_state(AssistantState::ReviewingFindings);
      return SlackCodexStreamGuard {
        controller: self.clone(),
      };
    }
    let mut active = ActiveSlackCodexStream {
      target,
      message_ts: None,
      final_text: String::new(),
      last_update_len: 0,
      assistant_state: AssistantState::ReviewingFindings,
      loading_tick: 0,
      loading_cancel: None,
      failed: false,
    };
    if matches!(
      active.target.kind,
      SlackCodexStreamTargetKind::DirectMessageUpdate
    ) {
      self.assistant_status.clear_active_now();
      let mut loading_target = None;
      if let Some(client) = self.client.clone() {
        let channel_id = active.target.channel_id.clone();
        match self.block_on_slack(client.post_message(
          &channel_id,
          None,
          &active.assistant_state.loading_text(active.loading_tick),
        )) {
          Ok(message) => {
            let message_ts = message.message_ts;
            active.message_ts = Some(message_ts.clone());
            loading_target = Some((client, channel_id, message_ts));
          }
          Err(error) => {
            active.failed = true;
            eprintln!("failed to start Slack direct message placeholder: {error}");
          }
        }
      }
      *self.active.lock().expect("slack codex stream") = Some(active);
      if let Some((client, channel_id, message_ts)) = loading_target {
        let cancel = self.start_direct_message_loading(client, channel_id, message_ts);
        if let Some(active) = self.active.lock().expect("slack codex stream").as_mut() {
          active.loading_cancel = Some(cancel);
        }
      }
      return SlackCodexStreamGuard {
        controller: self.clone(),
      };
    }
    *self.active.lock().expect("slack codex stream") = Some(active);
    SlackCodexStreamGuard {
      controller: self.clone(),
    }
  }

  fn reuse_existing_direct_message_loading(&self, target: &SlackCodexStreamTarget) -> bool {
    if !matches!(target.kind, SlackCodexStreamTargetKind::DirectMessageUpdate) {
      return false;
    }
    let active = self.active.lock().expect("slack codex stream");
    let Some(active) = active.as_ref() else {
      return false;
    };
    active.target.channel_id == target.channel_id
      && matches!(
        active.target.kind,
        SlackCodexStreamTargetKind::DirectMessageUpdate
      )
      && active.message_ts.is_some()
      && !active.failed
  }

  fn ensure_direct_message_loading(&self, channel_id: &str, state: AssistantState) {
    if self.direct_message_feedback != SlackDirectMessageFeedbackMode::Message {
      return;
    }
    let target = SlackCodexStreamTarget {
      channel_id: channel_id.to_owned(),
      kind: SlackCodexStreamTargetKind::DirectMessageUpdate,
    };
    if self.reuse_existing_direct_message_loading(&target) {
      self.update_direct_message_loading_state(state);
      return;
    }
    let mut active = ActiveSlackCodexStream {
      target,
      message_ts: None,
      final_text: String::new(),
      last_update_len: 0,
      assistant_state: state,
      loading_tick: 0,
      loading_cancel: None,
      failed: false,
    };
    let Some(client) = self.client.clone() else {
      *self.active.lock().expect("slack codex stream") = Some(active);
      return;
    };
    let mut loading_target = None;
    match self.block_on_slack(client.post_message(
      channel_id,
      None,
      &active.assistant_state.loading_text(active.loading_tick),
    )) {
      Ok(message) => {
        let message_ts = message.message_ts;
        active.message_ts = Some(message_ts.clone());
        loading_target = Some((client, channel_id.to_owned(), message_ts));
      }
      Err(error) => {
        active.failed = true;
        eprintln!("failed to start Slack direct message context loading: {error}");
      }
    }
    *self.active.lock().expect("slack codex stream") = Some(active);
    if let Some((client, channel_id, message_ts)) = loading_target {
      let cancel = self.start_direct_message_loading(client, channel_id, message_ts);
      if let Some(active) = self.active.lock().expect("slack codex stream").as_mut() {
        active.loading_cancel = Some(cancel);
      }
    }
  }

  fn update_direct_message_loading_state(&self, state: AssistantState) {
    let update = {
      let mut active = self.active.lock().expect("slack codex stream");
      let Some(active) = active.as_mut() else {
        return;
      };
      if active.failed
        || !matches!(
          active.target.kind,
          SlackCodexStreamTargetKind::DirectMessageUpdate
        )
        || !active.final_text.is_empty()
      {
        return;
      }
      active.assistant_state = state;
      active.loading_tick = 0;
      let Some(message_ts) = active.message_ts.clone() else {
        return;
      };
      let Some(client) = self.client.clone() else {
        return;
      };
      (
        client,
        active.target.channel_id.clone(),
        message_ts,
        active.assistant_state.loading_text(active.loading_tick),
      )
    };
    let (client, channel_id, message_ts, text) = update;
    self.runtime.spawn(async move {
      if let Err(error) = client.update_message(&channel_id, &message_ts, &text).await {
        eprintln!("failed to update Slack direct message tool state: {error}");
      }
    });
  }

  fn start_direct_message_loading(
    &self,
    client: Arc<SlackWebApiClient<SlackReqwestWebApiClient>>,
    channel_id: String,
    message_ts: String,
  ) -> Arc<AtomicBool> {
    let cancel = Arc::new(AtomicBool::new(false));
    let cancel_for_task = cancel.clone();
    let active = self.active.clone();
    self.runtime.spawn(async move {
      let mut interval =
        tokio::time::interval(Duration::from_millis(DIRECT_MESSAGE_LOADING_INTERVAL_MS));
      loop {
        interval.tick().await;
        if cancel_for_task.load(Ordering::SeqCst) {
          break;
        }
        let text = {
          let mut active = active.lock().expect("slack codex stream");
          let Some(active) = active.as_mut() else {
            break;
          };
          if active.failed
            || !matches!(
              active.target.kind,
              SlackCodexStreamTargetKind::DirectMessageUpdate
            )
          {
            break;
          }
          if !active.final_text.is_empty() {
            break;
          }
          active.loading_tick += 1;
          active.assistant_state.loading_text(active.loading_tick)
        };
        if let Err(error) = client.update_message(&channel_id, &message_ts, &text).await {
          eprintln!("failed to update Slack direct message loading state: {error}");
          break;
        }
      }
    });
    cancel
  }

  fn update_for_tool(&self, tool: &str) {
    let Some(state) = assistant_state_for_tool(tool) else {
      return;
    };
    self.update_direct_message_loading_state(state);
  }

  fn update_for_agent_phase(&self, phase: Option<&str>) {
    self.assistant_status.update_for_agent_phase(phase);
    let Some(state) = assistant_state_for_agent_phase(phase) else {
      return;
    };
    self.update_direct_message_loading_state(state);
  }

  fn append_final_delta(&self, delta: &str) {
    if delta.is_empty() {
      return;
    }
    let Some(client) = self.client.clone() else {
      return;
    };
    let mut active = self.active.lock().expect("slack codex stream");
    let Some(active) = active.as_mut() else {
      return;
    };
    if active.failed {
      return;
    }
    if let Some(cancel) = active.loading_cancel.take() {
      cancel.store(true, Ordering::SeqCst);
    }
    active.final_text.push_str(delta);
    let channel_id = active.target.channel_id.clone();
    if let Some(message_ts) = active.message_ts.clone() {
      match &active.target.kind {
        SlackCodexStreamTargetKind::DirectMessageUpdate => {
          if !should_flush_direct_message_update(
            active.final_text.len(),
            active.last_update_len,
            self.direct_update_min_chars,
          ) {
            return;
          }
          if let Err(error) =
            self.block_on_slack(client.update_message(&channel_id, &message_ts, &active.final_text))
          {
            active.failed = true;
            eprintln!("failed to update Slack direct message stream: {error}");
          } else {
            active.last_update_len = active.final_text.len();
          }
        }
        SlackCodexStreamTargetKind::ThreadStream { .. } => {
          if let Err(error) =
            self.block_on_slack(client.append_stream(&channel_id, &message_ts, delta))
          {
            active.failed = true;
            eprintln!("failed to append Slack stream: {error}");
          }
        }
      }
      return;
    }

    self.assistant_status.clear_active_now();
    match &active.target.kind {
      SlackCodexStreamTargetKind::DirectMessageUpdate => {
        match self.block_on_slack(client.post_message(&channel_id, None, delta)) {
          Ok(message) => {
            active.message_ts = Some(message.message_ts);
          }
          Err(error) => {
            active.failed = true;
            eprintln!("failed to start Slack direct message stream: {error}");
          }
        }
      }
      SlackCodexStreamTargetKind::ThreadStream { thread_ts } => {
        match self.block_on_slack(client.start_stream(&channel_id, thread_ts, delta)) {
          Ok(stream) => {
            active.message_ts = Some(stream.message_ts);
          }
          Err(error) => {
            active.failed = true;
            eprintln!("failed to start Slack stream: {error}");
          }
        }
      }
    }
  }

  fn finish_final_answer(&self, final_answer: &str) -> bool {
    let Some(client) = self.client.clone() else {
      return false;
    };
    let mut active = self.active.lock().expect("slack codex stream");
    let Some(active) = active.as_mut() else {
      return false;
    };
    if active.failed {
      return false;
    }
    let Some(message_ts) = active.message_ts.clone() else {
      return false;
    };
    let channel_id = active.target.channel_id.clone();
    let text = if final_answer.trim().is_empty() {
      active.final_text.clone()
    } else {
      final_answer.to_owned()
    };
    if let Some(cancel) = active.loading_cancel.take() {
      cancel.store(true, Ordering::SeqCst);
    }
    active.final_text.clone_from(&text);
    let result = match &active.target.kind {
      SlackCodexStreamTargetKind::DirectMessageUpdate => self
        .block_on_slack(client.update_message(&channel_id, &message_ts, &text))
        .map(|_| ()),
      SlackCodexStreamTargetKind::ThreadStream { .. } => self
        .block_on_slack(client.stop_stream(&channel_id, &message_ts, &text))
        .map(|_| ()),
    };
    match result {
      Ok(()) => true,
      Err(error) => {
        active.failed = true;
        eprintln!("failed to finish Slack stream: {error}");
        false
      }
    }
  }

  fn finish_active_direct_message_reply(&self, final_answer: &str) -> bool {
    let Some(client) = self.client.clone() else {
      return false;
    };
    let mut active = self.active.lock().expect("slack codex stream");
    let Some(active) = active.as_mut() else {
      return false;
    };
    if active.failed
      || !matches!(
        active.target.kind,
        SlackCodexStreamTargetKind::DirectMessageUpdate
      )
    {
      return false;
    }
    let Some(message_ts) = active.message_ts.clone() else {
      return false;
    };
    let channel_id = active.target.channel_id.clone();
    if let Some(cancel) = active.loading_cancel.take() {
      cancel.store(true, Ordering::SeqCst);
    }
    let text = final_answer.to_owned();
    active.final_text.clone_from(&text);
    match self.block_on_slack(client.update_message(&channel_id, &message_ts, &text)) {
      Ok(_) => true,
      Err(error) => {
        active.failed = true;
        eprintln!("failed to finish Slack direct message tool reply: {error}");
        false
      }
    }
  }

  fn block_on_slack<F: Future>(&self, future: F) -> F::Output {
    if tokio::runtime::Handle::try_current().is_ok() {
      tokio::task::block_in_place(|| self.runtime.block_on(future))
    } else {
      self.runtime.block_on(future)
    }
  }
}

impl CodexTurnEventObserver for SlackCodexStreamObserver {
  fn observe_codex_turn_event(&self, event: CodexTurnEvent) {
    match event {
      CodexTurnEvent::AgentMessageStarted(started) => {
        self
          .controller
          .update_for_agent_phase(started.phase.as_deref());
      }
      CodexTurnEvent::AgentMessageDelta(delta) => {
        self
          .controller
          .update_for_agent_phase(delta.phase.as_deref());
        if delta.phase.as_deref() == Some("final_answer") {
          self.controller.append_final_delta(&delta.delta);
        }
      }
    }
  }
}

impl Drop for SlackCodexStreamGuard {
  fn drop(&mut self) {
    let active = self
      .controller
      .active
      .lock()
      .expect("slack codex stream")
      .take();
    if let Some(active) = active
      && let Some(cancel) = active.loading_cancel
    {
      cancel.store(true, Ordering::SeqCst);
    }
  }
}

fn build_serve_codex_app_server_backend(
  config: &CodeoffConfig,
  state: StateStore,
  assistant_status: AssistantStatusController,
  slack_streams: SlackCodexStreamController,
) -> Result<
  CodexAppServerBackend<
    StdioCodexAppServerClient<ServeCodexDynamicToolHandler, SlackCodexStreamObserver>,
  >,
  String,
> {
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
  Ok(CodexAppServerBackend::new(
    StdioCodexAppServerClient::with_dynamic_tool_handler(
      codex.command.clone(),
      codex.ephemeral_threads,
      ServeCodexDynamicToolHandler {
        inner: build_serve_channel_dynamic_tool_handler(config, state),
        runtime: tokio::runtime::Handle::current(),
        assistant_status,
        slack_streams: slack_streams.clone(),
      },
    )
    .with_event_observer(slack_streams.observer()),
  ))
}

fn build_serve_channel_dynamic_tool_handler(
  config: &CodeoffConfig,
  state: StateStore,
) -> ChannelDynamicToolHandler {
  let context_provider: Arc<dyn ChannelContextProvider> =
    Arc::new(build_channel_context_provider(config));
  match build_channel_resource_provider(config) {
    Some(resource_provider) => match build_channel_address_provider(config) {
      Some(address_provider) => ChannelDynamicToolHandler::new_with_all_providers_and_now(
        state,
        context_provider,
        resource_provider,
        address_provider,
        now_unix_seconds(),
      ),
      None => ChannelDynamicToolHandler::new_with_providers_and_now(
        state,
        context_provider,
        resource_provider,
        now_unix_seconds(),
      ),
    },
    None => ChannelDynamicToolHandler::new_with_context_provider(state, context_provider),
  }
}

#[derive(Clone)]
struct ServeCodexDynamicToolHandler {
  inner: ChannelDynamicToolHandler,
  runtime: tokio::runtime::Handle,
  assistant_status: AssistantStatusController,
  slack_streams: SlackCodexStreamController,
}

impl CodexDynamicToolHandler for ServeCodexDynamicToolHandler {
  fn tool_specs(&self) -> Vec<serde_json::Value> {
    self.inner.tool_specs()
  }

  fn handle_tool_call(&self, tool: &str, arguments: serde_json::Value) -> serde_json::Value {
    self.assistant_status.update_for_tool(tool);
    self.slack_streams.update_for_tool(tool);
    if let Some((request_dedupe_key, text)) =
      direct_message_reply_to_event_override(tool, &arguments)
      && self.slack_streams.finish_active_direct_message_reply(text)
    {
      return direct_message_reply_to_event_override_success(request_dedupe_key);
    }
    tokio::task::block_in_place(|| {
      self
        .runtime
        .block_on(self.inner.handle_tool_call_async(tool, arguments))
    })
  }
}

fn direct_message_reply_to_event_override<'a>(
  tool: &str,
  arguments: &'a serde_json::Value,
) -> Option<(&'a str, &'a str)> {
  if tool != "channel_reply_to_event" {
    return None;
  }
  let request_dedupe_key = arguments["request_dedupe_key"].as_str()?;
  let text = arguments["text"].as_str()?;
  if request_dedupe_key.is_empty() || text.is_empty() {
    return None;
  }
  Some((request_dedupe_key, text))
}

fn direct_message_reply_to_event_override_success(request_dedupe_key: &str) -> serde_json::Value {
  serde_json::json!({
    "success": true,
    "contentItems": [
      {
        "type": "inputText",
        "text": serde_json::json!({
          "request_dedupe_key": request_dedupe_key,
          "queued": false,
        }).to_string(),
      }
    ],
  })
}

fn build_slack_delivery_queue(
  config: &CodeoffConfig,
  state: StateStore,
) -> Option<SlackDeliveryQueue<SlackReqwestWebApiClient>> {
  let bot_token = std::env::var(&config.slack.bot_token_env).ok()?;
  let now = now_unix_seconds();
  Some(SlackDeliveryQueue::new(
    SlackWebApiClient::new(
      SlackReqwestWebApiClient::new(),
      "slack-default",
      bot_token,
      config.slack.clone(),
      now,
    ),
    state,
    now,
  ))
}

async fn run_slack_delivery_loop(
  delivery: Option<&SlackDeliveryQueue<SlackReqwestWebApiClient>>,
) -> Result<(), Box<dyn Error>> {
  loop {
    let delivered = match delivery {
      Some(delivery) => run_slack_delivery_tick(delivery).await?,
      None => false,
    };
    if !delivered {
      tokio::time::sleep(Duration::from_millis(250)).await;
    }
  }
}

async fn run_channel_dispatch_tick_on_blocking_pool<B>(
  state: StateStore,
  backend: B,
  processing_streams: ServeProcessingStreamManager,
  context_provider: ServeDispatchContextProvider,
  context_limit: u16,
  conversation_locks: Option<ConversationDispatchLocks>,
) -> Result<bool, Box<dyn Error + Send + Sync>>
where
  B: codeoff_agent_contract::AgentBackend + Send + 'static,
{
  let handle = tokio::runtime::Handle::current();
  tokio::task::spawn_blocking(move || {
    handle.block_on(async move {
      run_channel_dispatch_tick(
        &state,
        &backend,
        &processing_streams,
        &context_provider,
        context_limit,
        conversation_locks.as_ref(),
      )
      .await
      .map_err(|error| -> Box<dyn Error + Send + Sync> { Box::new(error) })
    })
  })
  .await
  .map_err(|error| -> Box<dyn Error + Send + Sync> { Box::new(error) })?
}

async fn run_channel_dispatch_tick(
  state: &StateStore,
  backend: &impl codeoff_agent_contract::AgentBackend,
  processing_streams: &impl ProcessingStreamManager,
  context_provider: &ServeDispatchContextProvider,
  context_limit: u16,
  conversation_locks: Option<&ConversationDispatchLocks>,
) -> Result<bool, codeoff_state::StateError> {
  Ok(!matches!(
    dispatch_next_channel_event_with_processing_streams_context_and_locks(
      state,
      backend,
      processing_streams,
      Some(context_provider),
      Some(context_limit),
      conversation_locks,
    )
    .await?,
    DispatchOutcome::Idle
  ))
}

async fn run_slack_delivery_tick(
  delivery: &SlackDeliveryQueue<SlackReqwestWebApiClient>,
) -> Result<bool, codeoff_channel_slack::SlackWebApiError> {
  delivery.set_now_unix_seconds(now_unix_seconds());
  delivery_tick_activity(delivery.drain_due_once().await)
}

fn delivery_tick_activity(
  result: Result<Option<ChannelMessageReceipt>, codeoff_channel_slack::SlackWebApiError>,
) -> Result<bool, codeoff_channel_slack::SlackWebApiError> {
  match result {
    Ok(receipt) => Ok(receipt.is_some()),
    Err(error) => {
      eprintln!("Slack delivery tick deferred or retried: {error}");
      Ok(true)
    }
  }
}

fn now_unix_seconds() -> u64 {
  SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap_or_default()
    .as_secs()
}

fn run_worker(
  command: WorkerCommand,
  config_path: Option<PathBuf>,
  state_dir: Option<PathBuf>,
) -> Result<(), Box<dyn Error>> {
  match command {
    WorkerCommand::Slack { check } => {
      let config = load_config(config_path, state_dir)?;
      config.validate()?;
      let slack_check = check_slack_worker(&config.slack)?;

      let runtime = tokio::runtime::Runtime::new()?;
      let state = runtime.block_on(StateStore::initialize(
        config.state_dir(),
        config.database_url(),
      ))?;

      if !check {
        let app_token = std::env::var(&config.slack.app_token_env)?;
        let mut transport = SlackSocketClient::new();
        let intake = SlackIntake::with_slack_config(state, "slack-default", &config.slack);
        runtime.block_on(run_socket_worker(
          &mut transport,
          &app_token,
          SocketWorkerOptions::default(),
          move |raw_envelope| {
            let intake = intake.clone();
            async move {
              match intake.accept(&raw_envelope).await {
                Ok(SlackIntakeResult::Ignored) => {
                  eprintln!("ignored unsupported Slack Socket Mode envelope");
                }
                Ok(SlackIntakeResult::Queued | SlackIntakeResult::Duplicate) => {}
                Err(error) => {
                  eprintln!("failed to intake Slack Socket Mode envelope: {error}");
                }
              }
              SocketWorkerAction::Continue
            }
          },
        ))?;
      }

      println!("{}", slack_check.status_line());
      Ok(())
    }
    WorkerCommand::ChannelEvents { dry_run } => {
      if !dry_run {
        return Err("channel event processing is only available with --dry-run".into());
      }

      let config = load_config(config_path, state_dir)?;
      config.validate()?;
      let runtime = tokio::runtime::Runtime::new()?;
      let event = runtime.block_on(async {
        let store = StateStore::initialize(config.state_dir(), config.database_url()).await?;
        let Some(event) = store.claim_next_channel_event().await? else {
          return Ok(None);
        };
        store.complete_channel_event(event.id).await?;
        Ok::<_, codeoff_state::StateError>(Some(event))
      })?;

      match event {
        Some(event) => println!(
          "dry-run channel event: {}",
          channel_event_summary(&event.event)
        ),
        None => println!("no pending channel events"),
      }
      Ok(())
    }
  }
}

fn channel_event_summary(event: &ChannelEvent) -> String {
  format!(
    "kind={:?} connector={} target={} dedupe_key={} source_id={}",
    event.kind,
    event.connector_id,
    reply_target_summary(event.reply_target.as_ref()),
    event.dedupe_key,
    event.event_id,
  )
}

fn reply_target_summary(target: Option<&ChannelReplyTarget>) -> String {
  match target {
    Some(ChannelReplyTarget::Channel { channel_id }) => format!("channel:{channel_id}"),
    Some(ChannelReplyTarget::Thread {
      channel_id,
      thread_id,
    }) => format!("thread:{channel_id}:{thread_id}"),
    Some(ChannelReplyTarget::DirectMessage { user_account_id }) => {
      format!("direct_message:{user_account_id}")
    }
    Some(ChannelReplyTarget::Ephemeral {
      channel_id,
      user_account_id,
    }) => format!("ephemeral:{channel_id}:{user_account_id}"),
    None => "none".to_owned(),
  }
}

fn run_config(
  command: ConfigCommand,
  config_path: Option<PathBuf>,
  state_dir: Option<PathBuf>,
) -> Result<(), Box<dyn Error>> {
  match command {
    ConfigCommand::Check => {
      let mut options = ConfigLoadOptions::new();

      if let Some(config_path) = config_path {
        options = options.config_path(config_path);
      }

      if let Some(state_dir) = state_dir {
        options = options.explicit_state_dir(state_dir);
      }

      let config = CodeoffConfig::load(options)?;
      config.validate()?;
      println!(
        "config ok: state_dir={}, database=configured, mcp={}, mcp_transport={}",
        config.state_dir().display(),
        if config.mcp.enabled {
          "enabled"
        } else {
          "disabled"
        },
        config.mcp.transport
      );
      Ok(())
    }
  }
}

fn run_migrate(
  config_path: Option<PathBuf>,
  state_dir: Option<PathBuf>,
) -> Result<(), Box<dyn Error>> {
  let config = load_config(config_path, state_dir)?;
  config.validate()?;

  let runtime = tokio::runtime::Runtime::new()?;
  runtime.block_on(StateStore::initialize(
    config.state_dir(),
    config.database_url(),
  ))?;

  println!("state migrated: state_dir={}", config.state_dir().display());
  Ok(())
}

fn load_config(
  config_path: Option<PathBuf>,
  state_dir: Option<PathBuf>,
) -> Result<CodeoffConfig, Box<dyn Error>> {
  let mut options = ConfigLoadOptions::new();

  if let Some(config_path) = config_path {
    options = options.config_path(config_path);
  }

  if let Some(state_dir) = state_dir {
    options = options.explicit_state_dir(state_dir);
  }

  Ok(CodeoffConfig::load(options)?)
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::sync::{
    Arc, Barrier,
    atomic::{AtomicBool, Ordering},
  };

  #[derive(Clone, Debug, PartialEq, Eq)]
  enum AssistantStatusOperation {
    Set { target: String, status: String },
    Clear { target: String },
  }

  struct BlockingAssistantStatusTransport {
    operations: Mutex<Vec<AssistantStatusOperation>>,
    set_started: tokio::sync::Notify,
    release_set: tokio::sync::Notify,
    first_set_blocked: AtomicBool,
    clear_completed: tokio::sync::Notify,
    operation_completed: tokio::sync::Notify,
  }

  impl BlockingAssistantStatusTransport {
    fn new() -> Self {
      Self {
        operations: Mutex::new(Vec::new()),
        set_started: tokio::sync::Notify::new(),
        release_set: tokio::sync::Notify::new(),
        first_set_blocked: AtomicBool::new(false),
        clear_completed: tokio::sync::Notify::new(),
        operation_completed: tokio::sync::Notify::new(),
      }
    }

    async fn wait_for_operation_count(&self, expected: usize) {
      loop {
        let notified = self.operation_completed.notified();
        if self.operations.lock().expect("operations").len() >= expected {
          return;
        }
        notified.await;
      }
    }
  }

  #[async_trait]
  impl AssistantStatusTransport for BlockingAssistantStatusTransport {
    async fn set(
      &self,
      _channel_id: &str,
      thread_ts: &str,
      status: &str,
    ) -> Result<(), SlackWebApiError> {
      if !self.first_set_blocked.swap(true, Ordering::SeqCst) {
        self.set_started.notify_one();
        self.release_set.notified().await;
      }
      self
        .operations
        .lock()
        .expect("operations")
        .push(AssistantStatusOperation::Set {
          target: thread_ts.to_owned(),
          status: status.to_owned(),
        });
      self.operation_completed.notify_one();
      Ok(())
    }

    async fn clear(&self, _channel_id: &str, thread_ts: &str) -> Result<(), SlackWebApiError> {
      self
        .operations
        .lock()
        .expect("operations")
        .push(AssistantStatusOperation::Clear {
          target: thread_ts.to_owned(),
        });
      self.operation_completed.notify_one();
      self.clear_completed.notify_one();
      Ok(())
    }
  }

  fn assistant_status_controller_for_tests(
    client: Arc<dyn AssistantStatusTransport>,
  ) -> AssistantStatusController {
    AssistantStatusController {
      runtime: tokio::runtime::Handle::current(),
      client: Some(client),
      active_sessions: Arc::new(Mutex::new(HashMap::new())),
      dispatchers: Arc::new(Mutex::new(HashMap::new())),
      next_session_id: Arc::new(AtomicU64::new(1)),
    }
  }

  struct RecordingAssistantStatusTransport {
    operations: Mutex<Vec<AssistantStatusOperation>>,
    operation_completed: tokio::sync::Notify,
  }

  impl RecordingAssistantStatusTransport {
    fn new() -> Self {
      Self {
        operations: Mutex::new(Vec::new()),
        operation_completed: tokio::sync::Notify::new(),
      }
    }

    async fn wait_for_operation_count(&self, expected: usize) {
      loop {
        let notified = self.operation_completed.notified();
        if self.operations.lock().expect("operations").len() >= expected {
          return;
        }
        notified.await;
      }
    }
  }

  struct BlockingClearAssistantStatusTransport {
    operations: Mutex<Vec<AssistantStatusOperation>>,
    operation_completed: tokio::sync::Notify,
    clear_started: tokio::sync::Notify,
    release_clear: tokio::sync::Notify,
  }

  impl BlockingClearAssistantStatusTransport {
    fn new() -> Self {
      Self {
        operations: Mutex::new(Vec::new()),
        operation_completed: tokio::sync::Notify::new(),
        clear_started: tokio::sync::Notify::new(),
        release_clear: tokio::sync::Notify::new(),
      }
    }

    async fn wait_for_operation_count(&self, expected: usize) {
      loop {
        let notified = self.operation_completed.notified();
        if self.operations.lock().expect("operations").len() >= expected {
          return;
        }
        notified.await;
      }
    }
  }

  #[async_trait]
  impl AssistantStatusTransport for BlockingClearAssistantStatusTransport {
    async fn set(
      &self,
      _channel_id: &str,
      thread_ts: &str,
      status: &str,
    ) -> Result<(), SlackWebApiError> {
      self
        .operations
        .lock()
        .expect("operations")
        .push(AssistantStatusOperation::Set {
          target: thread_ts.to_owned(),
          status: status.to_owned(),
        });
      self.operation_completed.notify_one();
      Ok(())
    }

    async fn clear(&self, _channel_id: &str, thread_ts: &str) -> Result<(), SlackWebApiError> {
      self.clear_started.notify_one();
      self.release_clear.notified().await;
      self
        .operations
        .lock()
        .expect("operations")
        .push(AssistantStatusOperation::Clear {
          target: thread_ts.to_owned(),
        });
      self.operation_completed.notify_one();
      Ok(())
    }
  }

  #[async_trait]
  impl AssistantStatusTransport for RecordingAssistantStatusTransport {
    async fn set(
      &self,
      _channel_id: &str,
      thread_ts: &str,
      status: &str,
    ) -> Result<(), SlackWebApiError> {
      self
        .operations
        .lock()
        .expect("operations")
        .push(AssistantStatusOperation::Set {
          target: thread_ts.to_owned(),
          status: status.to_owned(),
        });
      self.operation_completed.notify_one();
      Ok(())
    }

    async fn clear(&self, _channel_id: &str, thread_ts: &str) -> Result<(), SlackWebApiError> {
      self
        .operations
        .lock()
        .expect("operations")
        .push(AssistantStatusOperation::Clear {
          target: thread_ts.to_owned(),
        });
      self.operation_completed.notify_one();
      Ok(())
    }
  }

  #[test]
  fn delivery_tick_errors_are_retry_activity_not_daemon_fatal() {
    for error in [
      SlackWebApiError::RateLimited {
        retry_after_seconds: Some(30),
      },
      SlackWebApiError::Provider {
        message: "temporarily unavailable".to_owned(),
      },
      SlackWebApiError::Deferred { available_at: 200 },
    ] {
      assert!(delivery_tick_activity(Err(error)).expect("activity"));
    }
  }

  #[test]
  fn delivery_tick_reports_whether_delivery_progressed() {
    assert!(!delivery_tick_activity(Ok(None)).expect("idle"));
    assert!(
      delivery_tick_activity(Ok(Some(ChannelMessageReceipt {
        connector_id: "slack-default".to_owned(),
        workspace_id: "workspace-1".to_owned(),
        request_dedupe_key: "message-1".to_owned(),
        message_id: "200.0".to_owned(),
      })))
      .expect("delivered")
    );
  }

  #[test]
  fn production_serve_dispatch_runs_in_background_when_backend_exists() {
    assert!(should_spawn_background_dispatch_loop(None, true));
    assert!(!should_spawn_background_dispatch_loop(None, false));
    assert!(!should_spawn_background_dispatch_loop(Some(1), true));
  }

  #[test]
  fn channel_dispatch_worker_count_uses_codex_parallel_turns_with_minimum_one() {
    let mut config = CodeoffConfig::default();
    config.agent.codex_app_server.max_parallel_turns = 4;
    assert_eq!(channel_dispatch_worker_count(&config), 4);

    config.agent.codex_app_server.max_parallel_turns = 0;
    assert_eq!(channel_dispatch_worker_count(&config), 1);
  }

  #[test]
  fn slack_intake_restart_delay_uses_capped_exponential_backoff() {
    assert_eq!(slack_intake_restart_delay(0), Duration::from_secs(1));
    assert_eq!(slack_intake_restart_delay(1), Duration::from_secs(2));
    assert_eq!(slack_intake_restart_delay(4), Duration::from_secs(16));
    assert_eq!(slack_intake_restart_delay(5), Duration::from_secs(30));
    assert_eq!(slack_intake_restart_delay(99), Duration::from_secs(30));
  }

  #[test]
  fn retention_policy_uses_data_retention_config() {
    let mut config = CodeoffConfig::default();
    config.data_retention.enabled = false;
    config.data_retention.inbound_payload_days = 11;
    config.data_retention.delivery_days = 12;
    config.data_retention.context_attempt_days = 13;
    config.data_retention.conversation_summary_days = 14;
    config.data_retention.artifact_days = 15;

    let policy = retention_policy_from_config(&config);

    assert!(!policy.enabled);
    assert_eq!(policy.inbound_payload_days, 11);
    assert_eq!(policy.delivery_days, 12);
    assert_eq!(policy.context_attempt_days, 13);
    assert_eq!(policy.conversation_summary_days, 14);
    assert_eq!(policy.artifact_days, 15);
  }

  #[test]
  fn assistant_status_target_uses_channel_thread_or_message_ts() {
    let config = CodeoffConfig::default();
    let target = assistant_status_target(&config, Some("C1"), Some("100.0"), Some("100.0"))
      .expect("status target");

    assert_eq!(target.channel_id, "C1");
    assert_eq!(target.thread_ts, "100.0");
  }

  #[test]
  fn assistant_status_target_ignores_direct_message_main_message_ts() {
    let config = CodeoffConfig::default();
    assert!(assistant_status_target(&config, Some("D1"), Some("200.0"), Some("200.0")).is_none());
  }

  #[test]
  fn assistant_status_target_can_use_direct_message_main_message_ts() {
    let mut config = CodeoffConfig::default();
    config.slack.response_feedback.direct_message_feedback =
      SlackDirectMessageFeedbackMode::AssistantStatus;

    let target = assistant_status_target(&config, Some("D1"), Some("200.0"), Some("200.0"))
      .expect("status target");

    assert_eq!(target.channel_id, "D1");
    assert_eq!(target.thread_ts, "200.0");
  }

  #[test]
  fn assistant_status_target_allows_threaded_direct_messages() {
    let config = CodeoffConfig::default();
    let target = assistant_status_target(&config, Some("D1"), Some("199.0"), Some("200.0"))
      .expect("status target");

    assert_eq!(target.channel_id, "D1");
    assert_eq!(target.thread_ts, "199.0");
  }

  #[test]
  fn assistant_status_target_respects_off_mode() {
    let mut config = CodeoffConfig::default();
    config.slack.response_feedback.mode = codeoff_config::SlackResponseFeedbackMode::Off;

    assert!(assistant_status_target(&config, Some("C1"), Some("100.0"), Some("100.0")).is_none());
  }

  #[tokio::test]
  async fn assistant_status_clear_is_last_after_a_late_set_response() {
    let transport = Arc::new(BlockingAssistantStatusTransport::new());
    let controller = assistant_status_controller_for_tests(transport.clone());
    let guard = controller.start(
      AssistantStatusTarget {
        channel_id: "C1".to_owned(),
        thread_ts: "100.0".to_owned(),
      },
      60_000,
    );

    let set_started = transport.set_started.notified();
    controller.set_state_for_active_target(AssistantState::Processing);
    set_started.await;

    let clear_completed = transport.clear_completed.notified();
    drop(guard);
    tokio::task::yield_now().await;
    transport.release_set.notify_one();
    clear_completed.await;
    tokio::task::yield_now().await;

    assert_eq!(
      transport.operations.lock().expect("operations").last(),
      Some(&AssistantStatusOperation::Clear {
        target: "100.0".to_owned(),
      })
    );
  }

  #[tokio::test]
  async fn assistant_status_terminal_clear_retires_its_dispatcher() {
    let transport = Arc::new(RecordingAssistantStatusTransport::new());
    let controller = assistant_status_controller_for_tests(transport.clone());
    let target = AssistantStatusTarget {
      channel_id: "C1".to_owned(),
      thread_ts: "100.0".to_owned(),
    };
    let guard = controller.start(target.clone(), 60_000);

    controller.update_for_tool("channel_get_delivery_status");
    transport.wait_for_operation_count(1).await;
    drop(guard);
    transport.wait_for_operation_count(2).await;

    tokio::time::timeout(Duration::from_secs(1), async {
      loop {
        if !controller
          .dispatchers
          .lock()
          .expect("assistant status dispatchers")
          .contains_key(&target)
        {
          return;
        }
        tokio::task::yield_now().await;
      }
    })
    .await
    .expect("dispatcher retired after terminal clear");

    let reused = controller.start(target, 60_000);
    controller.update_for_tool("channel_get_thread_context");
    transport.wait_for_operation_count(3).await;
    drop(reused);
    transport.wait_for_operation_count(4).await;
  }

  #[tokio::test]
  async fn assistant_status_without_updates_retires_its_dispatcher_and_can_restart() {
    let transport = Arc::new(RecordingAssistantStatusTransport::new());
    let controller = assistant_status_controller_for_tests(transport.clone());
    let target = AssistantStatusTarget {
      channel_id: "C1".to_owned(),
      thread_ts: "100.0".to_owned(),
    };

    drop(controller.start(target.clone(), 60_000));

    assert!(
      !controller
        .dispatchers
        .lock()
        .expect("assistant status dispatchers")
        .contains_key(&target)
    );

    let restarted = controller.start(target, 60_000);
    controller.update_for_tool("channel_get_delivery_status");
    transport.wait_for_operation_count(1).await;
    drop(restarted);
    transport.wait_for_operation_count(2).await;
  }

  #[tokio::test]
  async fn assistant_status_queued_clear_survives_a_newer_session_without_status() {
    let transport = Arc::new(BlockingClearAssistantStatusTransport::new());
    let controller = assistant_status_controller_for_tests(transport.clone());
    let target = AssistantStatusTarget {
      channel_id: "C1".to_owned(),
      thread_ts: "100.0".to_owned(),
    };
    let first = controller.start(target.clone(), 60_000);
    controller.update_for_tool("channel_get_delivery_status");
    transport.wait_for_operation_count(1).await;

    let clear_started = transport.clear_started.notified();
    drop(first);
    clear_started.await;
    drop(controller.start(target.clone(), 60_000));
    transport.release_clear.notify_one();
    transport.wait_for_operation_count(2).await;

    assert_eq!(
      transport.operations.lock().expect("operations").as_slice(),
      [
        AssistantStatusOperation::Set {
          target: "100.0".to_owned(),
          status: "Processing...".to_owned(),
        },
        AssistantStatusOperation::Clear {
          target: "100.0".to_owned(),
        },
      ]
    );
    tokio::time::timeout(Duration::from_secs(1), async {
      loop {
        if !controller
          .dispatchers
          .lock()
          .expect("assistant status dispatchers")
          .contains_key(&target)
        {
          return;
        }
        tokio::task::yield_now().await;
      }
    })
    .await
    .expect("dispatcher retired after queued clear");
  }

  #[tokio::test]
  async fn assistant_status_coalesces_pending_sets_before_terminal_clear() {
    let transport = Arc::new(BlockingAssistantStatusTransport::new());
    let controller = assistant_status_controller_for_tests(transport.clone());
    let guard = controller.start(
      AssistantStatusTarget {
        channel_id: "C1".to_owned(),
        thread_ts: "100.0".to_owned(),
      },
      60_000,
    );

    let set_started = transport.set_started.notified();
    controller.update_for_tool("channel_get_delivery_status");
    set_started.await;
    for _ in 0..32 {
      controller.update_for_tool("channel_get_thread_context");
    }
    controller.update_for_tool("channel_reply_to_event");
    let clear_completed = transport.clear_completed.notified();
    drop(guard);
    transport.release_set.notify_one();
    clear_completed.await;

    assert_eq!(
      transport.operations.lock().expect("operations").as_slice(),
      [
        AssistantStatusOperation::Set {
          target: "100.0".to_owned(),
          status: "Processing...".to_owned(),
        },
        AssistantStatusOperation::Set {
          target: "100.0".to_owned(),
          status: "Summarizing findings...".to_owned(),
        },
        AssistantStatusOperation::Clear {
          target: "100.0".to_owned(),
        },
      ]
    );
  }

  #[tokio::test]
  async fn assistant_status_stale_set_cannot_replace_a_newer_pending_set() {
    let transport = Arc::new(BlockingAssistantStatusTransport::new());
    let controller = assistant_status_controller_for_tests(transport.clone());
    let first = controller.start(
      AssistantStatusTarget {
        channel_id: "C1".to_owned(),
        thread_ts: "100.0".to_owned(),
      },
      60_000,
    );

    let set_started = transport.set_started.notified();
    controller.set_state_for_session(&first.active, AssistantState::Processing);
    set_started.await;

    let second = controller.start(first.active.target.clone(), 60_000);
    controller.set_state_for_session(&second.active, AssistantState::Searching);
    controller.set_state_for_session(&first.active, AssistantState::SummarizingFindings);
    transport.release_set.notify_one();
    transport.wait_for_operation_count(2).await;

    assert_eq!(
      transport.operations.lock().expect("operations").as_slice(),
      [
        AssistantStatusOperation::Set {
          target: "100.0".to_owned(),
          status: "Processing...".to_owned(),
        },
        AssistantStatusOperation::Set {
          target: "100.0".to_owned(),
          status: "Searching...".to_owned(),
        },
      ]
    );
    drop(first);
    drop(second);
  }

  #[tokio::test]
  async fn assistant_status_clear_rejects_a_later_set_for_the_same_session() {
    let transport = Arc::new(RecordingAssistantStatusTransport::new());
    let controller = assistant_status_controller_for_tests(transport.clone());
    let guard = controller.start(
      AssistantStatusTarget {
        channel_id: "C1".to_owned(),
        thread_ts: "100.0".to_owned(),
      },
      60_000,
    );

    controller.set_state_for_active_target(AssistantState::Processing);
    transport.wait_for_operation_count(1).await;
    controller.clear_active_now();
    transport.wait_for_operation_count(2).await;
    controller.set_state_for_active_target(AssistantState::Searching);
    tokio::task::yield_now().await;

    assert_eq!(
      transport.operations.lock().expect("operations").as_slice(),
      [
        AssistantStatusOperation::Set {
          target: "100.0".to_owned(),
          status: "Processing...".to_owned(),
        },
        AssistantStatusOperation::Clear {
          target: "100.0".to_owned(),
        },
      ]
    );
    drop(guard);
  }

  #[tokio::test]
  async fn assistant_status_sessions_dispatch_to_their_own_targets() {
    let transport = Arc::new(RecordingAssistantStatusTransport::new());
    let controller = assistant_status_controller_for_tests(transport.clone());
    let first = controller.start(
      AssistantStatusTarget {
        channel_id: "C1".to_owned(),
        thread_ts: "100.0".to_owned(),
      },
      60_000,
    );
    controller.set_state_for_session(&first.active, AssistantState::Processing);
    transport.wait_for_operation_count(1).await;

    let second = controller.start(
      AssistantStatusTarget {
        channel_id: "C2".to_owned(),
        thread_ts: "200.0".to_owned(),
      },
      60_000,
    );
    controller.set_state_for_session(&second.active, AssistantState::Searching);
    transport.wait_for_operation_count(2).await;

    assert_eq!(
      transport.operations.lock().expect("operations").as_slice(),
      [
        AssistantStatusOperation::Set {
          target: "100.0".to_owned(),
          status: "Processing...".to_owned(),
        },
        AssistantStatusOperation::Set {
          target: "200.0".to_owned(),
          status: "Searching...".to_owned(),
        },
      ]
    );
    drop(second);
    drop(first);
  }

  #[tokio::test]
  async fn assistant_status_public_updates_are_isolated_between_controllers_on_one_thread() {
    let first_transport = Arc::new(RecordingAssistantStatusTransport::new());
    let first_controller = assistant_status_controller_for_tests(first_transport.clone());
    let first = first_controller.start(
      AssistantStatusTarget {
        channel_id: "C1".to_owned(),
        thread_ts: "100.0".to_owned(),
      },
      60_000,
    );

    let second_transport = Arc::new(RecordingAssistantStatusTransport::new());
    let second_controller = assistant_status_controller_for_tests(second_transport.clone());
    let second = second_controller.start(
      AssistantStatusTarget {
        channel_id: "C2".to_owned(),
        thread_ts: "200.0".to_owned(),
      },
      60_000,
    );

    first_controller.update_for_tool("channel_get_delivery_status");
    first_transport.wait_for_operation_count(1).await;

    assert_eq!(
      first_transport
        .operations
        .lock()
        .expect("operations")
        .as_slice(),
      [AssistantStatusOperation::Set {
        target: "100.0".to_owned(),
        status: "Processing...".to_owned(),
      }]
    );
    assert!(
      second_transport
        .operations
        .lock()
        .expect("operations")
        .is_empty()
    );
    drop(second);
    drop(first);
  }

  #[tokio::test]
  async fn assistant_status_old_session_clear_does_not_clear_a_newer_same_target_session() {
    let transport = Arc::new(RecordingAssistantStatusTransport::new());
    let controller = assistant_status_controller_for_tests(transport.clone());
    let first = controller.start(
      AssistantStatusTarget {
        channel_id: "C1".to_owned(),
        thread_ts: "100.0".to_owned(),
      },
      60_000,
    );
    controller.set_state_for_session(&first.active, AssistantState::Processing);
    transport.wait_for_operation_count(1).await;

    let second = controller.start(first.active.target.clone(), 60_000);
    controller.set_state_for_session(&second.active, AssistantState::Searching);
    transport.wait_for_operation_count(2).await;
    drop(first);
    tokio::task::yield_now().await;

    assert_eq!(transport.operations.lock().expect("operations").len(), 2);
    drop(second);
    transport.wait_for_operation_count(3).await;
    assert_eq!(
      transport.operations.lock().expect("operations").last(),
      Some(&AssistantStatusOperation::Clear {
        target: "100.0".to_owned(),
      })
    );
  }

  #[tokio::test]
  async fn assistant_status_public_updates_keep_a_newer_same_target_session_active() {
    let transport = Arc::new(RecordingAssistantStatusTransport::new());
    let controller = assistant_status_controller_for_tests(transport.clone());
    let old_ready = Arc::new(Barrier::new(2));
    let release_old = Arc::new(Barrier::new(2));
    let old_controller = controller.clone();
    let old_ready_for_thread = old_ready.clone();
    let release_old_for_thread = release_old.clone();
    let old_turn = std::thread::spawn(move || {
      let _old = old_controller.start(
        AssistantStatusTarget {
          channel_id: "C1".to_owned(),
          thread_ts: "100.0".to_owned(),
        },
        60_000,
      );
      old_controller.update_for_tool("channel_get_delivery_status");
      old_ready_for_thread.wait();
      release_old_for_thread.wait();
    });

    transport.wait_for_operation_count(1).await;
    old_ready.wait();
    let new_turn = controller.start(
      AssistantStatusTarget {
        channel_id: "C1".to_owned(),
        thread_ts: "100.0".to_owned(),
      },
      60_000,
    );
    controller.update_for_agent_phase(Some("commentary"));
    transport.wait_for_operation_count(2).await;
    release_old.wait();
    old_turn.join().expect("old turn");
    tokio::task::yield_now().await;

    assert_eq!(transport.operations.lock().expect("operations").len(), 2);
    drop(new_turn);
    transport.wait_for_operation_count(3).await;
    assert_eq!(
      transport.operations.lock().expect("operations").as_slice(),
      [
        AssistantStatusOperation::Set {
          target: "100.0".to_owned(),
          status: "Processing...".to_owned(),
        },
        AssistantStatusOperation::Set {
          target: "100.0".to_owned(),
          status: "Processing...".to_owned(),
        },
        AssistantStatusOperation::Clear {
          target: "100.0".to_owned(),
        },
      ]
    );
  }

  #[tokio::test]
  async fn assistant_status_public_updates_are_isolated_across_controller_threads() {
    let transport = Arc::new(RecordingAssistantStatusTransport::new());
    let controller = assistant_status_controller_for_tests(transport.clone());
    let updates_started = Arc::new(Barrier::new(3));
    let updates_finished = Arc::new(Barrier::new(3));
    let mut turns = Vec::new();

    for (channel_id, thread_ts) in [("C1", "100.0"), ("C2", "200.0")] {
      let controller = controller.clone();
      let updates_started = updates_started.clone();
      let updates_finished = updates_finished.clone();
      turns.push(std::thread::spawn(move || {
        let _guard = controller.start(
          AssistantStatusTarget {
            channel_id: channel_id.to_owned(),
            thread_ts: thread_ts.to_owned(),
          },
          60_000,
        );
        updates_started.wait();
        controller.update_for_agent_phase(Some("commentary"));
        updates_finished.wait();
      }));
    }

    updates_started.wait();
    updates_finished.wait();
    for turn in turns {
      turn.join().expect("turn");
    }
    transport.wait_for_operation_count(4).await;
    let operations = transport.operations.lock().expect("operations").clone();

    for target in ["100.0", "200.0"] {
      let target_operations: Vec<_> = operations
        .iter()
        .filter(|operation| match operation {
          AssistantStatusOperation::Set {
            target: operation_target,
            ..
          }
          | AssistantStatusOperation::Clear {
            target: operation_target,
          } => operation_target == target,
        })
        .collect();
      assert_eq!(
        target_operations,
        vec![
          &AssistantStatusOperation::Set {
            target: target.to_owned(),
            status: "Processing...".to_owned(),
          },
          &AssistantStatusOperation::Clear {
            target: target.to_owned(),
          },
        ]
      );
    }
  }

  #[test]
  fn slack_codex_stream_target_only_uses_direct_messages_when_enabled() {
    let config = CodeoffConfig::default();
    let dm_task = stream_target_task(Some("D1"), Some("200.0"), Some("200.0"));
    let channel_task = stream_target_task(Some("C1"), Some("100.0"), Some("100.0"));

    let target = slack_codex_stream_target(&config, &dm_task).expect("dm stream target");
    assert_eq!(target.channel_id, "D1");
    assert_eq!(target.kind, SlackCodexStreamTargetKind::DirectMessageUpdate);
    assert!(slack_codex_stream_target(&config, &channel_task).is_none());

    let threaded_dm_task = stream_target_task(Some("D1"), Some("199.0"), Some("200.0"));
    let target =
      slack_codex_stream_target(&config, &threaded_dm_task).expect("threaded dm stream target");
    assert_eq!(target.channel_id, "D1");
    assert_eq!(
      target.kind,
      SlackCodexStreamTargetKind::ThreadStream {
        thread_ts: "199.0".to_owned()
      }
    );

    let mut status_only = config;
    status_only.slack.response_feedback.mode = SlackResponseFeedbackMode::AssistantStatus;
    assert!(slack_codex_stream_target(&status_only, &dm_task).is_none());
  }

  #[test]
  fn slack_codex_stream_target_respects_direct_message_assistant_status() {
    let mut config = CodeoffConfig::default();
    config.slack.response_feedback.direct_message_feedback =
      SlackDirectMessageFeedbackMode::AssistantStatus;
    let dm_task = stream_target_task(Some("D1"), Some("200.0"), Some("200.0"));

    assert!(slack_codex_stream_target(&config, &dm_task).is_none());
  }

  #[tokio::test]
  async fn slack_codex_stream_start_uses_shared_reviewing_status() {
    let controller = SlackCodexStreamController::without_client_for_tests();
    let target = SlackCodexStreamTarget {
      channel_id: "D1".to_owned(),
      kind: SlackCodexStreamTargetKind::DirectMessageUpdate,
    };

    let _guard = controller.start(target);

    let active = controller.active.lock().expect("active stream");
    let active = active.as_ref().expect("active");
    assert_eq!(active.assistant_state, AssistantState::ReviewingFindings);
  }

  #[tokio::test]
  async fn slack_codex_stream_start_resets_reused_direct_message_loading_to_reviewing() {
    let controller = SlackCodexStreamController::without_client_for_tests();
    let target = SlackCodexStreamTarget {
      channel_id: "D1".to_owned(),
      kind: SlackCodexStreamTargetKind::DirectMessageUpdate,
    };
    controller.prime_direct_message_loading_for_tests(target.clone(), AssistantState::Searching);

    let _guard = controller.start(target);

    let active = controller.active.lock().expect("active stream");
    let active = active.as_ref().expect("active");
    assert_eq!(active.assistant_state, AssistantState::ReviewingFindings);
  }

  #[tokio::test]
  async fn slack_codex_stream_tool_status_updates_direct_message_loading_text() {
    let controller = SlackCodexStreamController::without_client_for_tests();
    let target = SlackCodexStreamTarget {
      channel_id: "D1".to_owned(),
      kind: SlackCodexStreamTargetKind::DirectMessageUpdate,
    };
    controller.prime_direct_message_loading_for_tests(target, AssistantState::Searching);

    controller.update_for_tool("channel_reply_to_event");

    let active = controller.active.lock().expect("active stream");
    let active = active.as_ref().expect("active");
    assert_eq!(active.assistant_state, AssistantState::SummarizingFindings);
    assert_eq!(active.loading_tick, 0);
  }

  #[tokio::test]
  async fn slack_codex_stream_agent_phase_updates_direct_message_loading_text() {
    let controller = SlackCodexStreamController::without_client_for_tests();
    let target = SlackCodexStreamTarget {
      channel_id: "D1".to_owned(),
      kind: SlackCodexStreamTargetKind::DirectMessageUpdate,
    };
    controller.prime_direct_message_loading_for_tests(target, AssistantState::ReviewingFindings);

    controller.update_for_agent_phase(Some("final_answer"));

    let active = controller.active.lock().expect("active stream");
    let active = active.as_ref().expect("active");
    assert_eq!(active.assistant_state, AssistantState::SummarizingFindings);
    assert_eq!(active.loading_tick, 0);
  }

  #[test]
  fn direct_message_update_throttle_waits_for_more_content() {
    assert!(!should_flush_direct_message_update(42, 120, 120));
  }

  #[test]
  fn direct_message_update_throttle_flushes_when_enough_content_accumulates() {
    assert!(should_flush_direct_message_update(241, 120, 120));
  }

  #[test]
  fn assistant_state_loading_text_cycles_dots() {
    assert_eq!(AssistantState::Searching.loading_text(0), "Searching.");
    assert_eq!(AssistantState::Searching.loading_text(5), "Searching......");
    assert_eq!(AssistantState::Searching.loading_text(6), "Searching.");
  }

  #[test]
  fn assistant_state_for_tool_tracks_real_channel_work() {
    assert_eq!(
      assistant_state_for_tool("channel_get_thread_context"),
      Some(AssistantState::Searching)
    );
    assert_eq!(
      assistant_state_for_tool("channel_get_recent_messages"),
      Some(AssistantState::Searching)
    );
    assert_eq!(
      assistant_state_for_tool("channel_reply_to_event"),
      Some(AssistantState::SummarizingFindings)
    );
    assert_eq!(
      assistant_state_for_tool("channel_send_message"),
      Some(AssistantState::SummarizingFindings)
    );
    assert_eq!(assistant_state_for_tool("unknown_tool"), None);
  }

  #[test]
  fn assistant_state_for_agent_phase_tracks_codex_message_phase() {
    assert_eq!(
      assistant_state_for_agent_phase(Some("commentary")),
      Some(AssistantState::Processing)
    );
    assert_eq!(
      assistant_state_for_agent_phase(Some("final_answer")),
      Some(AssistantState::SummarizingFindings)
    );
    assert_eq!(assistant_state_for_agent_phase(Some("unknown")), None);
  }

  #[test]
  fn assistant_state_renders_status_and_loading_text_from_one_model() {
    assert_eq!(
      AssistantState::ReviewingFindings.status_text(),
      "Reviewing findings..."
    );
    assert_eq!(
      AssistantState::ReviewingFindings.loading_text(0),
      "Reviewing findings."
    );
  }

  #[test]
  fn direct_message_reply_override_only_accepts_valid_reply_to_event() {
    let arguments = serde_json::json!({
      "request_dedupe_key": "reply-1",
      "text": "Final answer."
    });

    assert_eq!(
      direct_message_reply_to_event_override("channel_reply_to_event", &arguments),
      Some(("reply-1", "Final answer."))
    );
    assert_eq!(
      direct_message_reply_to_event_override("channel_send_message", &arguments),
      None
    );
    assert_eq!(
      direct_message_reply_to_event_override(
        "channel_reply_to_event",
        &serde_json::json!({
          "request_dedupe_key": "reply-1",
          "text": ""
        })
      ),
      None
    );
  }

  #[test]
  fn direct_message_reply_override_reports_inline_delivery_success() {
    let response = direct_message_reply_to_event_override_success("reply-1");

    assert_eq!(response["success"], true);
    let text = response["contentItems"][0]["text"]
      .as_str()
      .expect("tool response text");
    assert!(text.contains("\"request_dedupe_key\":\"reply-1\""));
    assert!(text.contains("\"queued\":false"));
  }

  fn stream_target_task(
    channel_id: Option<&str>,
    thread_id: Option<&str>,
    message_ts: Option<&str>,
  ) -> AgentTask {
    AgentTask {
      task_id: "task-1".to_owned(),
      objective: "Handle event".to_owned(),
      context: codeoff_agent_contract::AgentTaskContext {
        provider: "slack".to_owned(),
        workspace_id: "workspace-1".to_owned(),
        conversation_key: "conversation-1".to_owned(),
        resume_thread_id: None,
        message_text: None,
        channel_id: channel_id.map(ToOwned::to_owned),
        thread_id: thread_id.map(ToOwned::to_owned),
        message_ts: message_ts.map(ToOwned::to_owned),
        user_id: Some("U1".to_owned()),
        channel_context: None,
        conversation_summary: None,
        event_id: "event-1".to_owned(),
        dedupe_key: "dedupe-1".to_owned(),
        source_reference: None,
      },
    }
  }

  #[test]
  fn dispatch_tick_runs_on_blocking_pool_without_stalling_runtime_worker() {
    #[derive(Clone)]
    struct SlowBackend {
      started: Arc<AtomicBool>,
    }

    impl codeoff_agent_contract::AgentBackend for SlowBackend {
      fn provider_name(&self) -> &'static str {
        "slow"
      }

      fn run(
        &self,
        _task: codeoff_agent_contract::AgentTask,
      ) -> Result<codeoff_agent_contract::AgentTaskResult, String> {
        self.started.store(true, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(200));
        Ok(codeoff_agent_contract::AgentTaskResult::accepted_dispatch())
      }
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
      .worker_threads(1)
      .enable_time()
      .build()
      .expect("runtime");
    runtime.block_on(async {
      let temp = tempfile::tempdir().expect("tempdir");
      let config = CodeoffConfig::load(
        ConfigLoadOptions::new()
          .config_path(temp.path().join("missing-codeoff.toml"))
          .explicit_state_dir(temp.path().join("state")),
      )
      .expect("load config");
      let state = StateStore::initialize(config.state_dir(), config.database_url())
        .await
        .expect("state");
      queue_test_mention(&state).await;
      let started = Arc::new(AtomicBool::new(false));
      let processing_streams = ServeProcessingStreamManager::Unavailable {
        state_manager: StateProcessingStreamManager::new(state.clone()),
      };
      let dispatch = run_channel_dispatch_tick_on_blocking_pool(
        state,
        SlowBackend {
          started: started.clone(),
        },
        processing_streams,
        ServeDispatchContextProvider::new(
          ServeChannelContextProvider::Unavailable,
          SlackCodexStreamController::without_client_for_tests(),
        ),
        config.slack.recent_message_limit,
        None,
      );
      tokio::pin!(dispatch);

      for _ in 0..20 {
        if started.load(Ordering::SeqCst) {
          return;
        }
        tokio::select! {
          () = tokio::time::sleep(Duration::from_millis(10)) => {}
          result = &mut dispatch => {
            panic!("dispatch should still be blocked, got {result:?}");
          }
        }
      }
      assert!(started.load(Ordering::SeqCst));
    });
  }

  async fn queue_test_mention(state: &StateStore) {
    let event = codeoff_channel_contract::ChannelEvent::new(
      "slack",
      "slack-default",
      "workspace-1",
      "event-1",
      "dedupe-1",
      codeoff_channel_contract::ChannelEventKind::MentionReceived,
    )
    .expect("event")
    .with_source_details(
      ChannelReplyTarget::Thread {
        channel_id: "C1".to_owned(),
        thread_id: "100.0".to_owned(),
      },
      "slack://workspace-1/C1/100.0",
    )
    .expect("source details");
    state
      .persist_slack_source_event(
        &codeoff_state::SlackSourceEvent {
          workspace_id: "workspace-1".to_owned(),
          event_kind: "app_mention".to_owned(),
          dedupe_key: "dedupe-1".to_owned(),
          envelope_id: Some("envelope-1".to_owned()),
          event_id: Some("event-1".to_owned()),
          channel_id: Some("C1".to_owned()),
          thread_ts: Some("99.0".to_owned()),
          message_ts: Some("100.0".to_owned()),
          user_id: Some("U1".to_owned()),
          raw_payload_json: "{}".to_owned(),
        },
        &event,
      )
      .await
      .expect("queue mention");
  }

  impl SlackCodexStreamController {
    fn without_client_for_tests() -> Self {
      let assistant_status = AssistantStatusController {
        runtime: tokio::runtime::Handle::current(),
        client: None,
        active_sessions: Arc::new(Mutex::new(HashMap::new())),
        dispatchers: Arc::new(Mutex::new(HashMap::new())),
        next_session_id: Arc::new(AtomicU64::new(1)),
      };
      Self {
        runtime: tokio::runtime::Handle::current(),
        client: None,
        assistant_status,
        direct_update_min_chars: 120,
        direct_message_feedback: SlackDirectMessageFeedbackMode::Message,
        active: Arc::new(Mutex::new(None)),
      }
    }

    fn prime_direct_message_loading_for_tests(
      &self,
      target: SlackCodexStreamTarget,
      state: AssistantState,
    ) {
      *self.active.lock().expect("slack codex stream") = Some(ActiveSlackCodexStream {
        target,
        message_ts: Some("100.0".to_owned()),
        final_text: String::new(),
        last_update_len: 0,
        assistant_state: state,
        loading_tick: 0,
        loading_cancel: None,
        failed: false,
      });
    }
  }
}
