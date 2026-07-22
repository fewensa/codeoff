# Codeoff Channel Gateway Docs

Purpose: route the current Codeoff channel gateway documents.
Read this when you need the current product boundary, runtime shape, or Slack/Codex integration contract.
This does not replace the topic documents.

## Current Boundary

Codeoff is a single daemon that connects Slack to a local Codex environment. It receives channel events, persists gateway state, dispatches work to Codex App Server, and exposes provider-neutral channel tools through dynamic App Server tools and MCP.

```text
Slack App
  -> Codeoff daemon
  -> SQLite queue / dedupe / receipts
  -> local Codex App Server
  -> Codex decides and calls tools
  -> Codeoff channel tools / MCP
  -> Slack Web API
```

Codeoff owns the transport and delivery boundary:

- Slack Socket Mode intake.
- Slack event normalization and filtering.
- SQLite queueing, dedupe, dispatch state, delivery receipts, and rate-limit bookkeeping.
- Codex App Server dispatch over stdio JSONL.
- Local MCP server for channel operations.
- Bounded Slack context and resource access when Codex requests it.

Codex owns the agent side:

- Reasoning and tool choice.
- Project understanding and workspace-specific instructions.
- Conversation continuity beyond Codeoff's gateway references.
- Deciding whether and how to reply.

## English

- `en/overview.md`: product boundary and responsibility split.
- `en/runtime.md`: single-daemon process, SQLite state, dispatcher, and local MCP surface.
- `en/observability.md`: implemented operational health/readiness/metrics, scheduler telemetry, and structured tracing surface.
- `en/deployment.md`: Docker image and runtime deployment notes.
- `en/channels.md`: Slack channel gateway model and connector constraints.
- `en/agents.md`: Codex App Server dispatch boundary; Codeoff is not an agent runtime.
- `en/roadmap.md`: current gateway roadmap.
- `en/codex-app-server.md`: local Codex App Server integration.
- `en/slack-connector.md`: Slack gateway implementation.

## Traditional Chinese

- `zh-TW/overview.md`: product boundary and responsibility split.
- `zh-TW/runtime.md`: single-daemon process, SQLite state, dispatcher, and local MCP surface.
- `zh-TW/observability.md`: 已實作的運維 health/readiness/metrics、scheduler telemetry 與結構化 tracing 介面。
- `zh-TW/deployment.md`: Docker image and runtime deployment notes.
- `zh-TW/channels.md`: Slack channel gateway model and connector constraints.
- `zh-TW/agents.md`: Codex App Server dispatch boundary; Codeoff is not an agent runtime.
- `zh-TW/roadmap.md`: current gateway roadmap.
- `zh-TW/codex-app-server.md`: local Codex App Server integration.
- `zh-TW/slack-connector.md`: Slack gateway implementation.
- `zh-TW/slack-app-setup-runbook.md`: Slack App Socket Mode setup, permissions, configuration, and smoke-test runbook.

## Structure Rule

Keep this directory organized by durable topic. Prefer concise current-state notes over historical plans.
