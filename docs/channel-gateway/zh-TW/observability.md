# Observability

目的：說明已實作的 operational HTTP、scheduler telemetry、readiness 與 logging surface。
閱讀時機：設定 probes、metrics collection 或 production diagnostics 時。
不涵蓋：user-facing API 或可 mutation 的 remote administration surface。

## 已實作 Operational HTTP

`codeoff serve` 一律會在 `[server].bind` 啟動 bounded HTTP/1 operational server。預設為 `127.0.0.1:7788`；除非設定 `[server].allow_non_loopback = true`，否則 non-loopback address 會被拒絕。

目前只實作以下 read-only `GET` routes：

- `GET /healthz`：process liveness，回傳 `{"status":"alive"}`。
- `GET /readyz`：SQLite readability 加上 scheduler component、loop、provider 與 snapshot readiness。
- `GET /metrics`：Prometheus/OpenMetrics scheduler telemetry。

其他 path 回傳 `404`，非 `GET` method 回傳 `405`，帶 query string 的 request 會被拒絕。Response 有大小限制、包含 `Cache-Control: no-store`，且不暴露 instruction、payload body、provider receipt、token 或 raw error。

以下 admin routes 尚未實作，仍屬未來工作：runtime summary、inbound/outbound queue inspection、event lookup、delivery lookup 與 conversation mapping diagnostics。CLI scheduler diagnostics 是 trusted-local maintenance commands，不是 HTTP admin endpoints。

## Readiness Contract

若 SQLite 無法在 250 ms 內完成 bounded read probe，`/readyz` 會 fail closed 並回傳 `503`。Scheduler disabled 時，SQLite probe 通過後回傳 `200` 與 `scheduler_disabled`。

Scheduler enabled 時，readiness 另外要求：

- scheduler execution 與 delivery/preparation loops 已回報 started；
- required claim-side dependencies 可用；
- bounded SQLite scheduler snapshot 曾成功；
- 沒有 snapshot read/timeout error，且 snapshot age 不超過 15 秒。

`run_claims_enabled` 與 `delivery_claims_enabled` 是獨立 kill switches。若啟用 claim path 卻缺少必要 executor/provider，readiness 會失敗，不會默默丟棄工作。Provider claims disabled 時，delivery preparation loop 仍可運行。

## 已實作 Scheduler Metrics

Metrics endpoint 提供 low-cardinality scheduler telemetry，包括：

- `codeoff_scheduler_events_total`，使用固定 worker、operation、status 與 stable error kind labels；
- `codeoff_scheduler_operation_duration_seconds`；
- `codeoff_scheduler_last_attempt`；
- `codeoff_scheduler_transitions_total`，使用固定 `kind` vocabulary。這些 totals 會與已接受的
  state/audit transition 在同一個 SQLite transaction 內遞增，daemon restart 後仍會保留；
- `codeoff_scheduler_worker_capacity` 與 `codeoff_scheduler_worker_available_slots`，使用固定 worker；
- due jobs、pending/leased/executing/unknown runs、unprepared/pending/sending/retryable/unknown deliveries 與 oldest work ages 的 bounded gauges；
- snapshot success、age 與 saturation gauges。

Durable transition kinds 涵蓋 materialization/coalescing/overlap 決策；run claim、terminal、
recovery、stale-fence 與 policy-limit outcomes；delivery claim、success、retry、failure、unknown、
skip 與 forced-unknown resend outcomes；彼此獨立的 execution baseline 與 accepted-delivery
baseline advances；executor validation categories；以及 unauthorized scheduler mutations。
Counter 只會在 authoritative transaction 接受 outcome 後遞增；rollback 與重複 metrics scrape
不會重複計數。特別是 `delivery_retry` 為 durable 且不依賴 Agent execution，因此可直接驗證
no-Agent delivery retry invariant。

Decision counter 使用 durable authority，而不是 poll 次數。`overlap_suppressed` 對每個新的
`(job generation, scheduled_for)` decision 只遞增一次，restart 後亦同。其 cursor 透過
cascading foreign key 歸 job 所有，accepted schedule update 會重設 cursor；active 與 paused
job 的 cursor 會保留，completed 與 deleted job 的 cursor 則由 bounded retention batch 清除。
Counter exhaustion policy limit 對每個受影響的 run 或 delivery 只遞增一次；request policy
limit 對每一筆已接受的 typed audit row 遞增一次。真正的 idempotent replay 不會插入新的
audit row，因此不會遞增 counter；terminal deadline/retry limit 則與已接受的 terminal
transition 一起遞增一次。
`stale_fence_rejected` 對每個被拒絕的 authoritative CAS、stale exact reconcile，或只能接受為
diagnostic evidence 的 late completion/failure 遞增一次。重複送出的 stale attempt 是新的拒絕
嘗試，因此會再次遞增。

Executor validation 由 typed failure source 分類。只有 error kind 精確為
`profile_validation_failed`、`artifact_validation_failed` 與 `tool_list_validation_failed` 的
preflight transition 會遞增對應 counter；一般 schedule request validation 不會被重新分類成
artifact failure。

Worker gauge 反映實際 spawn topology。Scheduler enabled 時有一個 execution worker；provider
可用時有一個 delivery worker，否則有一個 standalone delivery preparation worker。Worker 的
available slot 會在 `tick/started` 從 `1` 變成 `0`，並在相對應的 terminal tick status 回到
`1`；nested attempt 不會改變 slot availability。

SQLite snapshot 每 5 秒 refresh，count 上限為 100,000、age 上限為 30 天，timeout 為 500 ms。Refresh 失敗時會保留上一份 bounded gauge values，但 readiness 會將 snapshot 視為 unavailable。

Labels 不包含 job、run、delivery、owner、channel、user、thread、Slack 或 Codex id；instruction、
prompt、result、payload、token、secret、receipt 與 raw error string 也全部排除。Metric labels
只會從固定 enum 中選取。

## Structured Scheduler Tracing

Daemon 會初始化無 ANSI 的 JSON tracing。Scheduler workers 會輸出固定 worker/operation/status/error-kind events 與 monotonic durations。這是已實作的 scheduler tracing path；legacy gateway components 仍可能輸出既有格式，且不一定全部包含在 scheduler metrics 中。

Secret、完整 provider payload、Codex prompt/answer、instruction、rendered delivery body 與 unbounded error 都必須省略或 redacted。

## Exposure Boundary

Operational server 沒有 application-layer authentication。除非 deployment 明確設定 `allow_non_loopback = true`，並提供 platform network policy、authentication proxy 與 trusted probe access，否則應保留預設 loopback bind。`/healthz` 與 `/readyz` 只有在 trusted local 或 cluster network 內才應 unauthenticated。
