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
occurrence_search_limit = 100000
tick_interval_ms = 250
error_backoff_ms = 1000
minimum_schedule_cadence_seconds = 60
max_active_jobs = 1000
max_active_jobs_per_owner = 100
max_prompt_bytes = 65536
max_result_bytes = 65536
max_summary_bytes = 32768
run_lease_seconds = 60
run_heartbeat_interval_ms = 15000
run_timeout_seconds = 1800
run_prepare_grace_ms = 5000
run_cancellation_grace_ms = 5000
run_finalization_grace_ms = 5000
run_retry_base_seconds = 30
run_retry_max_seconds = 300
run_deadline_seconds = 3600
run_max_attempts = 3
delivery_tick_interval_ms = 250
delivery_batch_limit = 32
delivery_lease_seconds = 60
delivery_heartbeat_interval_ms = 10000
delivery_readiness_timeout_seconds = 10
delivery_send_timeout_seconds = 30
delivery_finalization_timeout_seconds = 5
delivery_max_attempts = 5
delivery_retry_base_seconds = 5
delivery_retry_max_seconds = 300
delivery_retry_after_max_seconds = 3600
delivery_deadline_seconds = 3600
delivery_readiness_retry_base_seconds = 1
delivery_readiness_retry_max_seconds = 60

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
gateway_image_digest = "sha256:<lowercase-sha256>"
runner_image_digest = "sha256:<lowercase-sha256>"
runner_workload_identity = "spiffe://codeoff/runner/production"
runner_client_cert_public_key_fingerprint = "<lowercase-sha256>"
credential_revision = "github-readonly-2026-07"
isolation_attestation_path = "/var/run/codeoff/isolation-attestation.json"
isolation_trust_bundle_path = "/opt/codeoff/attestation/isolation-trust-bundle.json"
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

### Scheduler CLI Authority Boundary

Local entrypoint 為 `codeoff [--config PATH] [--state-dir PATH] scheduler <command>`。它會直接讀取設定的 SQLite control plane，並不是 remote authentication boundary。

- Sanitized read-only diagnostics 不需要 operator identity：`status [--json]`、`runs list [--status STATE] [--limit N] [--json]`、`runs show RUN_ID [--json]`、`deliveries list [--status STATE] [--limit N] [--json]`、`deliveries show DELIVERY_ID [--json]`，以及 `reconcile --dry-run [--limit N] [--json]`。這些 commands 只接受 selector、bounded limit、identifier 與 output mode，不會 mutation scheduler authority。
- Owner-scoped schedule commands 必須由 process environment 同時提供 `CODEOFF_SCHEDULER_OPERATOR_ID` 與 `CODEOFF_SCHEDULER_OPERATOR_REALM`：`create --file PATH [--format json|toml]`、`get JOB_ID`、`list [--status STATUS] [--cursor CURSOR] [--limit N]`、`update JOB_ID --file PATH [--format json|toml] --generation N`，以及 `pause|resume|delete JOB_ID --generation N --request-id ID`。Create 與 update 接受 strict versioned JSON 或 TOML schedule document。CLI 刻意不提供 owner/user override flags。
- High-risk operator mutations 包含 `reconcile --apply [--limit N] --authority-file PATH [--json]`、`retry-run RUN_ID --expected-state STATE --request-id ID --expected-attempt N --expected-fence N --reason-file PATH --authority-file PATH`、`retry-delivery DELIVERY_ID --request-id ID --expected-attempt N --expected-fence N --reason-file PATH --authority-file PATH`，以及 `resolve-delivery-unknown DELIVERY_ID --disposition DISPOSITION --request-id ID --expected-attempt N --expected-fence N --evidence-file PATH [--reason-file PATH] [--acknowledge-duplicate-risk] --authority-file PATH`。Operator file 可用 `-` 指定最多一個 stdin input，內容不可為空，且每個 file 上限為 64 KiB；reason 與 evidence input 必須是 canonical schema-version-1 JSON。Force resend 還必須提供 reason 並明確 acknowledge duplicate risk。

目前 binary 中的 high-risk mutation verifier 刻意 fail closed。只提供 authority file 並不足夠：在 Issue 09 deployment integration 注入 trusted authority verifier 前，`reconcile --apply`、retry 與 unknown-resolution commands 都無法 mutation state。所有 scheduler CLI invocation 都必須保留在可存取 configured state filesystem 的 trusted host/container boundary 內。

每次 create、update 或 resume job 都會保存一份 validated operational policy snapshot。Materialized run 與 delivery intent 會繼承該 immutable snapshot，因此 retry、deadline、lease、size 與 attempt 行為在 restart 或後續 config 變更後仍保持穩定。`data_retention` 仍是 retention-day policy 的唯一 authority；scheduler operational snapshot 不會複製 retention 設定。

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
