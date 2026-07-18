# Overview

Purpose: define the current Codeoff product boundary.
Read this before changing channel gateway code, docs, or deployment configuration.
This does not define Codex agent behavior, project instructions, or business workflow policy.

## Summary

Codeoff is a local communication gateway for Codex.

```text
Slack App
  -> Codeoff daemon
  -> SQLite queue / dedupe / receipts
  -> local Codex App Server
  -> Codex decides and calls tools
  -> Codeoff channel tools / MCP
  -> Slack Web API
```

The daemon receives Slack events, stores source-backed gateway records, dispatches each eligible event to a mapped Codex App Server conversation, and exposes channel tools that let Codex fetch context or send replies through Codeoff.

## Current Implementation

The checked-in code includes:

- Slack Socket Mode intake, mention filtering, DM filtering, queue persistence, and dry-run queue inspection.
- SQLite state for inbound source events, normalized channel events, conversation mappings, dispatch attempts, outbound delivery, receipts, throttles, and retention configuration.
- Codex App Server stdio JSONL client construction and interactive dispatch that starts or resumes mapped Codex conversations.
- Runtime channel handlers for replies, sends, context fetch, current context, resources, user/channel lookup, sender listing, workspace listing, connector status, and thread replies.
- MCP JSON-RPC dispatch for `initialize`, `tools/list`, `tools/call`, and the channel tools.
- Loopback TCP MCP server startup from `codeoff serve` when enabled.
- Slack Web API delivery queue, receipts, rate-limit handling, and next-due delivery drain.
- Docker image build that packages the compiled `codeoff` binary, Codex, and common operational tools.

`codeoff serve --check` validates configuration and initializes state without starting live loops. Non-check `codeoff serve` starts configured Slack intake, Codex dispatch, outbound Slack delivery drain, and the enabled TCP MCP server.

## Ownership

Codeoff owns:

- Provider intake and acknowledgement.
- Gateway filtering, queueing, dedupe, retries, receipts, and rate-limit handling.
- Dispatch transport to Codex App Server.
- Provider-neutral channel tools and MCP exposure.
- Bounded source/context/resource access on request.

Codex owns:

- Reasoning, response content, and tool choice.
- Project understanding and workspace instructions.
- Whether to reply, ask follow-up questions, fetch more context, or take no action.

## Design Rule

Keep Codeoff boring. Add gateway primitives when Codex needs a safer or more reliable way to talk to a communication provider. Put reasoning, planning, and domain decisions in Codex or in tools configured for Codex.
