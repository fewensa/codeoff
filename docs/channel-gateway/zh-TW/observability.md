# Observability

目的：定義 Codeoff channel gateway 未來、暫緩實作的 observability 方向。
閱讀時機：設計 operational visibility、readiness checks、metrics 或 production diagnostics 前。
不涵蓋：已實作 API、CLI surface、dashboard、alert policy 或 deployment manifest。

## 狀態

Observability 目前刻意暫緩。當前優先順序仍是 local channel gateway loop：Slack intake、SQLite queue、Codex App Server dispatch、MCP channel tools、outbound delivery、receipts 與 rate-limit handling。

未來實作 observability 時，方向應是 cluster-friendly、service-oriented：

- HTTP admin/read-only API，用於 health、readiness、queue state、delivery state 與 bounded diagnostics。
- Prometheus-compatible metrics endpoint。
- daemon 輸出的 structured logs。

Operational visibility 不應依賴 CLI inspection commands。CLI commands 可以繼續服務 local development 或一次性 maintenance，但不應是 health checks、dashboards、alerts 或 cluster probes 的主要介面。

## HTTP Admin And Read-Only API

未來 HTTP surface 預設應是 read-only。任何 mutation 或 replay endpoint 都必須作為獨立、明確受保護的 admin operation 設計。

建議 endpoints：

- `GET /healthz`: process liveness，避免昂貴 dependency checks。
- `GET /readyz`: runtime loops、database access 與必要 provider configuration 的 readiness。
- `GET /admin/runtime`: sanitized runtime summary，包含 enabled loops、configured transports、build/version information 與 current process role。
- `GET /admin/queues/inbound`: bounded inbound queue summary，按 status、age、attempts 與 next due time 呈現。
- `GET /admin/queues/outbound`: bounded outbound delivery summary，按 status、age、attempts、next due time 與 rate-limit cooldown 呈現。
- `GET /admin/events/{event_id}`: 單一已知 event id 的 sanitized source-backed event diagnostics。
- `GET /admin/deliveries/{delivery_id}`: 單一已知 delivery id 的 sanitized delivery request 與 receipt diagnostics。
- `GET /admin/conversations/{conversation_key}`: provider thread/channel scope 到 Codex thread id 的 mapping diagnostics，預設不包含 message bodies。
- `GET /metrics`: Prometheus metrics。

Read endpoints 應使用明確 pagination 或小型 hard limits。Responses 預設應避免 raw Slack tokens、signing secrets、user tokens、完整 message bodies、Codex prompts、Codex final answers 與 unbounded raw provider payloads。

## Prometheus Metrics

Metrics 應描述 gateway health 與 backlog，不暴露 sensitive content。

建議 counters：

- `codeoff_slack_events_received_total{workspace, event_type}`
- `codeoff_slack_events_deduped_total{workspace}`
- `codeoff_channel_events_enqueued_total{provider, workspace}`
- `codeoff_dispatch_attempts_total{provider, workspace, result}`
- `codeoff_outbound_delivery_attempts_total{provider, workspace, result}`
- `codeoff_mcp_tool_calls_total{tool, result}`
- `codeoff_rate_limit_events_total{provider, workspace, scope}`

建議 gauges：

- `codeoff_inbound_queue_depth{provider, workspace, status}`
- `codeoff_outbound_queue_depth{provider, workspace, status}`
- `codeoff_oldest_inbound_event_age_seconds{provider, workspace}`
- `codeoff_oldest_outbound_delivery_age_seconds{provider, workspace}`
- `codeoff_rate_limit_cooldown_seconds{provider, workspace, scope}`
- `codeoff_runtime_loop_up{loop}`

建議 histograms：

- `codeoff_dispatch_latency_seconds{provider, workspace}`
- `codeoff_outbound_delivery_latency_seconds{provider, workspace}`
- `codeoff_slack_api_request_duration_seconds{method, result}`
- `codeoff_mcp_tool_call_duration_seconds{tool, result}`
- `codeoff_sqlite_operation_duration_seconds{operation, result}`

Labels 必須維持 low-cardinality。不要用 Slack channel ids、Slack user ids、event ids、delivery ids、message text、Codex thread ids 或 raw error strings 作為 metric labels。

## Structured Logs

Daemon 應輸出適合 local files、container logs 或 centralized collectors 的 structured logs。

建議 fields：

- `timestamp`
- `level`
- `component`
- `operation`
- `provider`
- `workspace_id`
- `event_id` 或 `delivery_id`，如果可用
- `dedupe_key`，如果有用且安全
- `attempt`
- `status`
- `duration_ms`
- `error_kind`
- `retry_after_ms`

Logs 應優先使用 stable error kinds，而不是 raw provider responses。Sensitive fields、tokens、完整 message bodies、raw Codex prompts、raw Codex answers 與 unbounded Slack payloads 必須省略或 redacted。

## Security Boundary

Admin/read-only API 是 operational interface，不是 user-facing product API。

必要邊界：

- Local daemon 預設 bind to loopback。
- 綁定 non-loopback address 前必須有明確 configuration。
- 暴露到 loopback 以外時必須要求 authentication。
- Read-only endpoints 與任何未來 mutating admin endpoints 必須分離。
- 每個 response 都要 redacts secrets 與 sensitive content。
- 使用 bounded response sizes 與 pagination。
- Metrics 不包含 high-cardinality identifiers 或 message content。
- Raw provider payload access 應視為 privileged diagnostics，而不是 default API feature。

Cluster deployments 應把 HTTP admin surface 放在平台既有 service、network policy 與 authentication controls 後面。Health 與 readiness probes 只有在僅能由 trusted local 或 cluster networks 存取時，才可以 unauthenticated。
