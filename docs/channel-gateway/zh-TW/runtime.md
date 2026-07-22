# Runtime

目的：定義 Codeoff daemon runtime、scheduler、state 與 config shape。
閱讀時機：修改 process startup、SQLite state、scheduler/dispatch loops、operational HTTP 或 MCP startup 前。
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
- scheduler materialization、recovery 與 optional Agent execution claims。
- scheduler delivery preparation 與 optional provider delivery claims。
- 每五秒一次的 bounded scheduler observability snapshot。
- 在 `[server].bind` 啟動 operational HTTP server，提供 `GET /healthz`、`/readyz` 與 `/metrics`。
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
- scheduled jobs、immutable occurrence snapshots、run leases/attempts/results、delivery intents/attempts、execution 與 accepted-delivery baselines、operator actions，以及 append-only retention audits。

## Configuration

最小本機設定：

```toml
[server]
bind = "127.0.0.1:7788"
allow_non_loopback = false

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
scheduled_run_days = 30
scheduled_delivery_days = 30
scheduled_retention_batch_limit = 100

[scheduler]
enabled = false
run_claims_enabled = false
delivery_claims_enabled = false
recovery_batch_limit = 32
materialization_batch_limit = 32
tick_interval_ms = 250
error_backoff_ms = 1000
lease_seconds = 60
heartbeat_interval_ms = 15000
total_timeout_seconds = 1800
prepare_grace_ms = 5000
cancellation_grace_ms = 5000
finalization_grace_ms = 5000
retry_delay_seconds = 30
run_deadline_seconds = 3600
max_attempts = 3

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

[agent.scheduled_codex]
codex_program = "/opt/codeoff/bin/codex"
codex_program_sha256 = "<lowercase-sha256>"
codex_home = "/var/lib/codeoff/scheduled-codex"
cwd = "/work/codeoff-scheduled"
github_mcp_url = "http://127.0.0.1:8090/mcp"
github_mcp_artifact_path = "/opt/codeoff/bin/github-mcp-server"
github_mcp_artifact_sha256 = "<lowercase-sha256>"
github_mcp_endpoint_identity = "github-mcp-scheduled-v1"
credential_reference = "kubernetes:codeoff/github-mcp"
permission_policy_revision = "scheduled-read-only-v1"
config_revision = "scheduled-codex-v1"
config_sha256 = "<lowercase-sha256>"
isolation_attestation_path = "/var/run/codeoff/isolation-attestation.json"
isolation_verifier_public_key = "<lowercase-ed25519-public-key>"
trusted_owner_uid = 0
trusted_owner_gid = 0
runtime_uid = 65534
runtime_gid = 65534

[mcp]
enabled = true
transport = "tcp"
bind = "127.0.0.1:7789"
```

Secrets 必須來自 environment variables 或 secret manager，不寫入版本控制。

`scheduler.enabled` 是 scheduler global switch。`run_claims_enabled` 與 `delivery_claims_enabled` 是獨立的 fail-closed kill switches：run claims disabled 時不會消費 pending Agent work；delivery claims disabled 時仍會 prepare payload，但不會送往 provider。啟用 delivery claims 必須提供對應 provider credentials。Scheduler state 可跨 restart 持久保存，delivery retry 或 unknown-resolution operation 不會重新執行 Agent occurrence。

啟用 `run_claims_enabled` 時也必須提供 dedicated `[agent.scheduled_codex]` profile。Startup 會驗證 Codex binary 與 dedicated config 的 exact digest、read-only filesystem boundary、pinned loopback GitHub MCP identity，以及綁定完整 profile 且仍在有效期內的 Ed25519-signed isolation attestation。Evidence 缺失、過期、格式錯誤或 mismatch 時，`serve` 會在 run claims 啟動前 fail closed。Scheduled turn 使用 fresh、channel-independent session，不暴露 dynamic tools，並在 `turn/start` 前持久化已 attested 的 read-only execution surface。

Automatic retention 使用獨立的 run 與 delivery age cutoffs，每次 cleanup 最多刪除 `scheduled_retention_batch_limit` 個 candidate runs。Accepted delivery baseline 的 identity/digest authority 與 append-only audit evidence 會在 source history cleanup 後保留；latest execution-success source 會受保護。設定範圍為 1–3650 天與 1–1024 candidates。

Operational HTTP server 會由 `serve` 一律啟動。除非 deployment 明確允許 non-loopback exposure 並提供自己的 network/authentication boundary，否則應保留預設 loopback bind。Scheduler disabled 時，只要 SQLite 通過即為 ready；scheduler enabled 時，若 loop、required claim dependency 或 scheduler snapshot unavailable/stale，readiness 會 fail closed。

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
