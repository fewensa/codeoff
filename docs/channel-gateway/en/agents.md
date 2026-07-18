# Codex Boundary

Purpose: define how Codeoff interacts with Codex.
Read this when changing Codex App Server dispatch, channel tools, or conversation mapping.
This does not define Codex prompts or workspace project knowledge.

## Boundary

Codeoff calls Codex App Server for each eligible channel event. Codex decides what to do and may call Codeoff tools during the turn.

```text
ChannelEvent
  -> mapped Codex App Server conversation
  -> Codex turn
  -> dynamic channel tool calls
  -> Codeoff delivery/context/resource operations
```

Codeoff's job is to provide reliable source references and communication tools. Codex's job is to reason over the request and choose actions.

## Conversation Mapping

Codeoff maps provider conversation scopes to Codex thread ids. Follow-up messages in the same Slack DM, thread, or channel scope resume the mapped Codex conversation when possible.

The mapping lets Codex keep continuity without Codeoff building a separate reasoning context system.

## Dynamic Tools And MCP

The same channel primitives are available through App Server dynamic tools and the local MCP surface. Tool names are provider-neutral and use the `channel.*` namespace.

Codex should prefer these tools for source lookup and Slack writes instead of receiving unbounded Slack history in the initial prompt.

## Current Context

For the active event, Codeoff exposes:

- Current source event.
- Current conversation mapping.
- A compact context pack.
- Source links and attachment/resource references.
- Tool hints for fetching additional message, thread, user, channel, or resource details.

This keeps the first dispatch small while still giving Codex a path to retrieve more context.
