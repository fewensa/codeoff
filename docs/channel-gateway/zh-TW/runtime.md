# Runtime

目的：定義 Codeoff daemon runtime、state 與 config shape。
閱讀時機：修改 process startup、SQLite state、dispatch loop 或 MCP startup 前。
不涵蓋：Slack App 點選設定或 Codex prompt 行為。

## Process Shape

主要 runtime 是單一 daemon：

```text
codeoff serve
```

常用 maintenance commands：

```text
codeoff serve --check
codeoff migrate
codeoff config check
```

`codeoff serve` 啟動已設定的 gateway loops：

- Slack Socket Mode listener。
- SQLite state store。
- inbound channel event dispatch to Codex App Server。
- outbound Slack delivery drain。
- `[mcp] enabled = true` 且 `transport = "tcp"` 時啟動 loopback TCP MCP server。

`serve --check` 會載入 config、驗證 config、初始化 SQLite state，並輸出 sanitized status。它不啟動 Slack、Codex、delivery 或 MCP live loops。

## State

SQLite 保存本機 gateway state：

- Slack source events 與 raw payload references。
- stable dedupe keys。
- normalized channel event queue。
- provider-neutral conversation mappings to Codex thread ids。
- dispatch attempts 與 failures。
- outbound delivery queue。
- Slack delivery receipts。
- channel throttles 與 rate-limit cooldowns。
- payload、delivery、context attempt、summary、artifact retention metadata。

## Configuration

最小本機設定：

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

Secrets 必須來自 environment variables 或 secret manager，不寫入版本控制。

`mention_user_ids` 匹配 Slack text 中的 `<@U00000000>`。`allowed_dm_user_ids` 限制可驅動 DM intake 的 Slack users。`[slack.user_tokens.<key>]` 允許 channel tools 使用 `send_as = "user:<key>"`；未指定 `send_as` 時使用 bot token。

## Dispatch

Dispatch payload 以 source references 為主：

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

Codeoff 可以加入 compact current-message 與 context hints，但長歷史與 files 應留在 bounded channel tools 後面，由 Codex 需要時再取。
