# Channels

Purpose: describe the provider-neutral channel gateway model, with Slack as the current connector.
Read this when changing Slack intake, delivery, context fetch, resources, addressing, or MCP channel tools.
This does not define agent reasoning or provider-specific project policy.

## Flow

```text
Slack Socket Mode
  -> Codeoff Slack listener
  -> source event + dedupe key
  -> normalized channel event queue
  -> Codex App Server dispatch
  -> Codex calls Codeoff tools
  -> Slack Web API delivery
  -> delivery receipt
```

## Slack Intake

The Slack connector uses a manually installed Slack App with Socket Mode. It acknowledges envelopes quickly, normalizes supported events, applies DM and mention filters, and persists source-backed queue records.

Supported first-class intake:

- App mentions.
- Direct messages from allowed Slack users.
- Channel messages that match configured target user mentions.
- Thread replies in scopes already mapped to Codex conversations.

`mention_user_ids` must use Slack user IDs and matches Slack text such as `<@U00000000>`.

Private channels require both Slack scopes and bot membership in the channel.

## Delivery

All Slack writes go through the delivery queue. Delivery uses Slack Web API `chat.postMessage` for DMs, channel sends, and thread replies. Codeoff records Slack response metadata, message timestamps, failures, attempts, and rate-limit cooldowns.

MCP send tools accept optional `send_as`:

- omitted, `null`, or `bot`: use the configured bot token.
- `user:<key>`: use `[slack.user_tokens.<key>]`.

## Context And Resources

Codex can fetch bounded provider context instead of receiving large Slack payloads up front.

Available fetch categories:

- Current event and conversation.
- Context pack for the active turn.
- Individual message lookup.
- Thread replies.
- Recent channel messages.
- Resource/file metadata.
- Best-effort text extraction for supported resources.
- Lazy resource download to a local artifact path.

Files and attachments are source references first. Codeoff should download or extract them only when Codex asks.

## Addressing

Codeoff exposes provider-neutral lookup tools for:

- Workspaces/connectors.
- Users.
- Channels.
- Senders.
- Connector status.

Search and resolve tools should return clear candidates when names are ambiguous.

## MCP Tools

Current channel tools:

```text
channel.reply_to_event
channel.send_message
channel.get_thread_context
channel.get_recent_messages
channel.get_current_event
channel.get_current_conversation
channel.get_context_pack
channel.get_delivery_status
channel.get_message
channel.get_resource_info
channel.read_resource_text
channel.download_resource
channel.search_users
channel.get_user
channel.resolve_user
channel.search_channels
channel.get_channel
channel.resolve_channel
channel.list_senders
channel.list_workspaces
channel.get_connector_status
channel.reply_to_thread
```

The MCP server starts from `codeoff serve` only when `[mcp] enabled = true`, `transport = "tcp"`, and `bind` is loopback.

## Slack References

- [Slack Events API](https://docs.slack.dev/apis/events-api/)
- [Slack Socket Mode](https://docs.slack.dev/apis/events-api/using-socket-mode/)
- [Slack Web API rate limits](https://docs.slack.dev/apis/web-api/rate-limits/)
- [Slack conversations.history](https://docs.slack.dev/reference/methods/conversations.history/)
- [Slack conversations.replies](https://docs.slack.dev/reference/methods/conversations.replies/)
- [Slack chat.postMessage](https://docs.slack.dev/reference/methods/chat.postMessage/)
