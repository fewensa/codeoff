# Codex App Server

Purpose: define the local Codex App Server integration used by Codeoff.
Read this when changing dispatch payloads, conversation mapping, dynamic tools, or App Server process startup.
This does not define Codex model prompts or project instructions.

## Integration Shape

Codeoff launches or connects to the configured command:

```toml
[agent.codex_app_server]
command = "codex app-server --listen stdio://"
transport = "stdio"
ephemeral_threads = true
max_parallel_turns = 10
max_prompt_bytes = 65536
previous_success_context_max_bytes = 8192
```

The current client uses stdio JSONL. Dispatch waits for the Codex turn to complete and records final draft text only when Codex returns it.

## Dispatch Flow

```text
queued channel event
  -> resolve provider conversation mapping
  -> start or resume Codex App Server conversation
  -> send compact source-backed event
  -> expose dynamic channel tools
  -> wait for turn/completed
  -> persist dispatch result
```

## Payload Contract

The payload is identifier-first:

```json
{
  "provider": "slack",
  "workspace_id": "T00000000",
  "connector_id": "slack:T00000000",
  "event_kind": "message.im",
  "channel_id": "D00000000",
  "thread_ts": "1720000000.000000",
  "message_ts": "1720000000.000000",
  "user_id": "U00000000",
  "source_ref": "slack:T00000000:D00000000:1720000000.000000",
  "dedupe_key": "slack:event:Ev00000000"
}
```

Compact message text and context hints may be included for the active event, but Slack history and files should remain behind bounded channel tools.

## Dynamic Tools

Each task carries a default-deny dynamic-tool policy. During an interactive channel turn, Codeoff
declares only the channel tools in that task's allowlist and checks the same policy again on every
tool call. Codex can use those allowed tools to:

- Reply to the current event or a known thread.
- Send a message as the bot or a configured user token.
- Fetch current event/conversation/context pack.
- Fetch messages, thread replies, or recent messages.
- Resolve users/channels/workspaces.
- Inspect delivery status.
- Read or download referenced resources.

All Slack writes still go through Codeoff delivery queue and receipts.
