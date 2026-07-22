# Roadmap

Purpose: describe current gateway work priorities.
Read this when prioritizing Codeoff implementation work.
This does not define Codex product work.

## Implemented Or Test-Backed

- Slack Socket Mode intake, mention filtering, DM filtering, queue persistence, and dry-run queue inspection.
- Codex App Server stdio JSONL client and config-backed backend construction.
- Mapped Slack DM/thread/channel conversations to Codex App Server conversations.
- Interactive runtime dispatch with dynamic channel tools.
- Provider-neutral MCP tools for reply/send, context, resources, users, channels, senders, workspaces, and connector status.
- Slack delivery queue, receipts, production Web API client construction, rate-limit behavior, and delivery drain.
- Data retention configuration for gateway records and artifacts.
- Durable scheduler control plane and dynamic tools for create/get/list/update/pause/resume/delete.
- Scheduler materialization, fenced Agent execution, delivery preparation/claims, exact `on_change` suppression, restart recovery, retryable and ambiguous-delivery operator recovery, and audited bounded history retention.
- Trusted-local scheduler status/run/delivery diagnostics and bounded reconciliation commands.
- Operational HTTP `GET /healthz`, `/readyz`, and `/metrics`, bounded scheduler snapshots, Prometheus/OpenMetrics telemetry, and JSON scheduler tracing.
- Docker image with Codeoff, Codex, and common operational tools.

## Next Gateway Work

- Continue production reliability work for provider failures and parallel conversation dispatch without weakening the existing scheduler restart/retry lifecycle coverage.
- Add authenticated, bounded admin read endpoints only when operational use requires more than the implemented health/readiness/metrics surface.
- Expand resource extraction for files that Codex asks to inspect.
- Add additional communication providers behind the same `channel.*` tool model when needed.
- Keep config examples and Docker deployment docs aligned with the checked-in config structs.
