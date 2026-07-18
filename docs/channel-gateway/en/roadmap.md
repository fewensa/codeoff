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
- Docker image with Codeoff, Codex, and common operational tools.

## Next Gateway Work

- Improve production reliability tests for restart recovery, queue retry, delivery retry, and parallel conversation dispatch.
- Add service-oriented observability: health/readiness, Prometheus metrics, and structured logs.
- Expand resource extraction for files that Codex asks to inspect.
- Add additional communication providers behind the same `channel.*` tool model when needed.
- Keep config examples and Docker deployment docs aligned with the checked-in config structs.
