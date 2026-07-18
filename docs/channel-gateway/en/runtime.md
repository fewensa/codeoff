# Runtime

Purpose: define Codeoff's daemon runtime, state, and configuration shape.
Read this before changing process startup, SQLite state, dispatch loops, or MCP startup.
This does not define Slack App setup details or Codex prompt behavior.

## Process Shape

The primary runtime is one daemon:

```text
codeoff serve
```

Useful maintenance commands:

```text
codeoff serve --check
codeoff migrate
codeoff config check
```

`codeoff serve` starts the configured gateway loops:

- Slack Socket Mode listener.
- SQLite state store.
- Inbound channel event dispatch to Codex App Server.
- Outbound Slack delivery drain.
- Loopback TCP MCP server when `[mcp] enabled = true` and `transport = "tcp"`.

`serve --check` loads config, validates it, initializes SQLite state, and prints sanitized status. It does not start Slack, Codex, delivery, or MCP live loops.

## State

SQLite stores local gateway state:

- Slack source events and raw payload references.
- Stable dedupe keys.
- Normalized channel event queue.
- Provider-neutral conversation mappings to Codex thread ids.
- Dispatch attempts and failures.
- Outbound delivery queue.
- Slack delivery receipts.
- Channel throttles and rate-limit cooldowns.
- Retention metadata for payloads, deliveries, context attempts, summaries, and artifacts.

## Configuration

Minimal local configuration:

```toml
[state]
dir = "${CODEOFF_STATE_DIR:-./.codeoff}"

[database]
url = "sqlite://${CODEOFF_STATE_DIR:-./.codeoff}/codeoff.db"

[data_retention]
enabled = true
inbound_payload_days = 30
delivery_days = 30
context_attempt_days = 14
conversation_summary_days = 90
artifact_days = 7

[slack]
workspace_id = "T00000000"
transport = "socket_mode"
bot_token_env = "SLACK_BOT_TOKEN"
app_token_env = "SLACK_APP_TOKEN"
signing_secret_env = "SLACK_SIGNING_SECRET"
mention_user_ids = ["U00000000"]
allowed_dm_user_ids = ["U00000000"]
default_channel_ids = []
recent_message_limit = 50
thread_message_limit = 100
history_lookback_hours = 168

[slack.response_feedback]
mode = "adaptive"
direct_message_feedback = "message"
status_delay_ms = 1200
status_refresh_ms = 60000
status_max_duration_ms = 120000
stream_min_content_chars = 300
stream_requires_real_chunks = true

[slack.user_tokens.example]
user_id = "U00000000"
token_env = "SLACK_EXAMPLE_USER_TOKEN"

[agent.codex_app_server]
command = "codex app-server --listen stdio://"
transport = "stdio"
ephemeral_threads = true
max_parallel_turns = 10

[mcp]
enabled = true
transport = "tcp"
bind = "127.0.0.1:7789"
```

Secrets must come from environment variables or a secret manager, not checked-in config files.

`mention_user_ids` matches Slack text such as `<@U00000000>`. `allowed_dm_user_ids` restricts which Slack users can drive DM intake. `[slack.user_tokens.<key>]` allows channel tools to send with `send_as = "user:<key>"`; omitted `send_as` uses the bot token.

## Dispatch

The dispatch payload is source-backed and compact:

```text
event_id
provider
workspace_id
connector_id
channel_id
user_id
message_ts
thread_ts
source_ref
dedupe_key
```

Codeoff can include compact current-message and context hints, but long history and files stay behind bounded channel tools. Codex fetches more source context through MCP when needed.
