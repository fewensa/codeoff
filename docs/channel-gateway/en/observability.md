# Observability

Purpose: define the deferred observability direction for the Codeoff channel gateway.
Read this before designing operational visibility, readiness checks, metrics, or production diagnostics.
This does not define an implemented API, CLI surface, dashboard, alert policy, or deployment manifest.

## Status

Observability is intentionally deferred. The current priority is the local channel gateway loop: Slack intake, SQLite queueing, Codex App Server dispatch, MCP channel tools, outbound delivery, receipts, and rate-limit handling.

When observability is implemented, it should be cluster-friendly and service-oriented:

- HTTP admin/read-only API for health, readiness, queue state, delivery state, and bounded diagnostics.
- Prometheus-compatible metrics endpoint.
- Structured logs emitted by the daemon.

Operational visibility should not depend on CLI inspection commands. CLI commands may remain useful for local development or one-shot maintenance, but they should not be the primary interface for health checks, dashboards, alerts, or cluster probes.

## HTTP Admin And Read-Only API

The future HTTP surface should be read-only by default. Any mutation or replay endpoint must be designed as a separate, explicitly guarded admin operation.

Recommended endpoints:

- `GET /healthz`: process liveness. This should avoid expensive dependency checks.
- `GET /readyz`: readiness for configured runtime loops, database access, and required provider configuration.
- `GET /admin/runtime`: sanitized runtime summary, including enabled loops, configured transports, build/version information, and current process role.
- `GET /admin/queues/inbound`: bounded inbound queue summary by status, age, attempts, and next due time.
- `GET /admin/queues/outbound`: bounded outbound delivery summary by status, age, attempts, next due time, and rate-limit cooldown.
- `GET /admin/events/{event_id}`: sanitized source-backed event diagnostics for a single known event id.
- `GET /admin/deliveries/{delivery_id}`: sanitized delivery request and receipt diagnostics for a single known delivery id.
- `GET /admin/conversations/{conversation_key}`: mapping diagnostics for provider thread/channel scope to Codex thread id, without message bodies by default.
- `GET /metrics`: Prometheus metrics.

Read endpoints should use explicit pagination or small hard limits. Responses should avoid raw Slack tokens, signing secrets, user tokens, full message bodies by default, Codex prompts, Codex final answers, and unbounded raw provider payloads.

## Prometheus Metrics

Metrics should describe gateway health and backlog without exposing sensitive content.

Recommended counters:

- `codeoff_slack_events_received_total{workspace, event_type}`
- `codeoff_slack_events_deduped_total{workspace}`
- `codeoff_channel_events_enqueued_total{provider, workspace}`
- `codeoff_dispatch_attempts_total{provider, workspace, result}`
- `codeoff_outbound_delivery_attempts_total{provider, workspace, result}`
- `codeoff_mcp_tool_calls_total{tool, result}`
- `codeoff_rate_limit_events_total{provider, workspace, scope}`

Recommended gauges:

- `codeoff_inbound_queue_depth{provider, workspace, status}`
- `codeoff_outbound_queue_depth{provider, workspace, status}`
- `codeoff_oldest_inbound_event_age_seconds{provider, workspace}`
- `codeoff_oldest_outbound_delivery_age_seconds{provider, workspace}`
- `codeoff_rate_limit_cooldown_seconds{provider, workspace, scope}`
- `codeoff_runtime_loop_up{loop}`

Recommended histograms:

- `codeoff_dispatch_latency_seconds{provider, workspace}`
- `codeoff_outbound_delivery_latency_seconds{provider, workspace}`
- `codeoff_slack_api_request_duration_seconds{method, result}`
- `codeoff_mcp_tool_call_duration_seconds{tool, result}`
- `codeoff_sqlite_operation_duration_seconds{operation, result}`

Labels must remain low-cardinality. Do not label metrics with Slack channel ids, Slack user ids, event ids, delivery ids, message text, Codex thread ids, or raw error strings.

## Structured Logs

The daemon should emit structured logs suitable for local files, container logs, or centralized collectors.

Recommended fields:

- `timestamp`
- `level`
- `component`
- `operation`
- `provider`
- `workspace_id`
- `event_id` or `delivery_id` when available
- `dedupe_key` when useful and safe
- `attempt`
- `status`
- `duration_ms`
- `error_kind`
- `retry_after_ms`

Logs should prefer stable error kinds over raw provider responses. Sensitive fields, tokens, full message bodies, raw Codex prompts, raw Codex answers, and unbounded Slack payloads must be omitted or redacted.

## Security Boundary

The admin/read-only API is an operational interface, not a user-facing product API.

Required boundaries:

- Bind to loopback by default for local daemon use.
- Require explicit configuration before binding to a non-loopback address.
- Require authentication when exposed beyond loopback.
- Keep read-only endpoints separate from any future mutating admin endpoints.
- Redact secrets and sensitive content in every response.
- Use bounded response sizes and pagination.
- Keep metrics free of high-cardinality identifiers and message content.
- Treat raw provider payload access as privileged diagnostics, not a default API feature.

Cluster deployments should put the HTTP admin surface behind the platform's normal service, network policy, and authentication controls. Health and readiness probes may be unauthenticated only when they are reachable solely from trusted local or cluster networks.
