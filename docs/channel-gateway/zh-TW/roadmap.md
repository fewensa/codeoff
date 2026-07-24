# Roadmap

目的：描述目前 gateway work priorities。
閱讀時機：安排 Codeoff implementation work 前。
不涵蓋：Codex product work。

## 已實作或已有測試覆蓋

- Slack Socket Mode intake、mention filtering、DM filtering、queue persistence、dry-run queue inspection。
- Codex App Server stdio JSONL client 與 config-backed backend construction。
- Slack DM/thread/channel conversations 映射到 Codex App Server conversations。
- Interactive runtime dispatch with dynamic channel tools。
- Provider-neutral MCP tools：reply/send、context、resources、users、channels、senders、workspaces、connector status。
- Slack delivery queue、receipts、production Web API client construction、rate-limit behavior、delivery drain。
- Gateway records 與 artifacts 的 data retention config。
- Durable scheduler control plane 與 dynamic tools：create/get/list/update/pause/resume/delete。
- Scheduler materialization、fenced Agent execution、delivery preparation/claims、exact `on_change` suppression、restart recovery、retryable 與 ambiguous-delivery operator recovery，以及 audited bounded history retention。
- Trusted-local scheduler status/run/delivery diagnostics 與 bounded reconciliation commands。
- Operational HTTP `GET /healthz`、`/readyz`、`/metrics`，以及 bounded scheduler snapshots、Prometheus/OpenMetrics telemetry 與 JSON scheduler tracing。
- Docker image：包含 Codeoff、Codex 與常用 operational tools。

## 下一步 Gateway Work

- 持續強化 provider failure 與 parallel conversation dispatch 的 production reliability，但不削弱既有 scheduler restart/retry lifecycle coverage。
- 只有在 implemented health/readiness/metrics surface 不足以支援實際運維時，才新增 authenticated、bounded admin read endpoints。
- 擴充 Codex 明確要求檢查的 file resource extraction。
- 需要新 communication provider 時，掛到同一套 `channel.*` tool model 後面。
- 保持 config examples 與 Docker deployment docs 和 checked-in config structs 一致。
