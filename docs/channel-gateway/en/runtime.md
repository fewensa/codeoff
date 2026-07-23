# Runtime

Purpose: define Codeoff's daemon runtime, scheduler, state, and configuration shape.
Read this before changing process startup, SQLite state, scheduler/dispatch loops, operational HTTP, or MCP startup.
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
- Scheduler materialization, recovery, and optional Agent execution claims.
- Scheduler delivery preparation and optional provider delivery claims.
- Five-second bounded scheduler observability snapshots.
- Operational HTTP server on `[server].bind` with `GET /healthz`, `/readyz`, and `/metrics`.
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
- Scheduled jobs, immutable occurrence snapshots, run leases/attempts/results, delivery intents/attempts, execution and accepted-delivery baselines, operator actions, and append-only retention audits.

## Configuration

Minimal local configuration:

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

Secrets must come from environment variables or a secret manager, not checked-in config files.

`scheduler.enabled` is the global scheduler switch. `run_claims_enabled` and `delivery_claims_enabled` are independent fail-closed kill switches: disabled run claims do not consume pending Agent work; disabled delivery claims still allow payload preparation but do not send to the provider. Enabling delivery claims requires the configured provider credentials. Scheduler state remains durable across restarts, and delivery retry or unknown-resolution operations never rerun the Agent occurrence.

### Scheduler CLI Authority Boundary

The local entrypoint is `codeoff [--config PATH] [--state-dir PATH] scheduler <command>`. It reads the configured SQLite control plane directly and is not a remote authentication boundary.

- Sanitized read-only diagnostics require no operator identity: `status [--json]`, `runs list [--status STATE] [--limit N] [--json]`, `runs show RUN_ID [--json]`, `deliveries list [--status STATE] [--limit N] [--json]`, `deliveries show DELIVERY_ID [--json]`, and `reconcile --dry-run [--limit N] [--json]`. They accept only selectors, bounded limits, identifiers, and output mode; they do not mutate scheduler authority.
- Owner-scoped schedule commands require both `CODEOFF_SCHEDULER_OPERATOR_ID` and `CODEOFF_SCHEDULER_OPERATOR_REALM` from the process environment: `create --file PATH [--format json|toml]`, `get JOB_ID`, `list [--status STATUS] [--cursor CURSOR] [--limit N]`, `update JOB_ID --file PATH [--format json|toml] --generation N`, and `pause|resume|delete JOB_ID --generation N --request-id ID`. Create and update accept a strict versioned JSON or TOML schedule document. CLI owner/user override flags are intentionally absent.
- High-risk operator mutations are `reconcile --apply [--limit N] --authority-file PATH [--json]`, `retry-run RUN_ID --expected-state STATE --request-id ID --expected-attempt N --expected-fence N --reason-file PATH --authority-file PATH`, `retry-delivery DELIVERY_ID --request-id ID --expected-attempt N --expected-fence N --reason-file PATH --authority-file PATH`, and `resolve-delivery-unknown DELIVERY_ID --disposition DISPOSITION --request-id ID --expected-attempt N --expected-fence N --evidence-file PATH [--reason-file PATH] [--acknowledge-duplicate-risk] --authority-file PATH`. Operator files may use `-` for at most one stdin input, must be non-empty, and are capped at 64 KiB each; reason and evidence inputs must be canonical schema-version-1 JSON. Force resend additionally requires a reason and explicit duplicate-risk acknowledgement.

The high-risk mutation verifier is intentionally fail-closed in the current binary. Supplying an authority file is not sufficient: `reconcile --apply`, retry, and unknown-resolution commands cannot mutate state until the Issue 09 deployment integration injects a trusted authority verifier. Keep every scheduler CLI invocation inside a trusted host/container boundary with filesystem access to the configured state.

Every created, updated, or resumed job snapshots the validated operational policy. Materialized runs and delivery intents inherit that immutable snapshot, so retry, deadline, lease, size, and attempt behavior remains stable across restarts and later config changes. `data_retention` remains the only authority for retention-day policy; scheduler operational snapshots do not duplicate retention settings.

Enabling `run_claims_enabled` also requires the dedicated `[agent.scheduled_codex]` profile. Startup verifies the exact Codex binary and dedicated config digests, read-only filesystem boundaries, pinned loopback GitHub MCP identity, and a current Ed25519-signed isolation attestation bound to that complete profile. Missing, stale, malformed, or mismatched evidence stops `serve` before run claims start. Scheduled turns are fresh and channel-independent, use no dynamic tools, and persist the attested read-only execution surface before `turn/start`.

Automatic retention uses separate run and delivery age cutoffs and deletes at most `scheduled_retention_batch_limit` candidate runs per cleanup call. Accepted delivery baseline identity/digest authority and append-only audit evidence survive source-history cleanup; the latest execution-success source remains protected. The limits validate as 1–3650 days and 1–1024 candidates.

The operational HTTP server is always started by `serve`. Keep the default loopback bind unless the deployment deliberately enables non-loopback exposure and supplies its own network/authentication boundary. Scheduler-disabled readiness is healthy after SQLite passes; enabled scheduler readiness fails closed for unavailable loops, required claim dependencies, or missing/stale scheduler snapshots.

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
