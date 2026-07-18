# Channels

目的：描述 provider-neutral channel gateway model，目前 connector 是 Slack。
閱讀時機：修改 Slack intake、delivery、context fetch、resources、addressing 或 MCP channel tools 前。
不涵蓋：agent reasoning 或 provider-specific project policy。

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

Slack connector 使用手動安裝的 Slack App 與 Socket Mode。它快速 ack envelopes，normalize supported events，套用 DM/mention filters，並保存 source-backed queue records。

目前主要 intake：

- app mentions。
- 來自 allowed Slack users 的 direct messages。
- 匹配 configured target user mentions 的 channel messages。
- 屬於已映射 Codex conversation scope 的 thread replies。

`mention_user_ids` 必須使用 Slack user IDs，並匹配 `<@U00000000>` 形式。

Private channel 需要 Slack scopes，也需要 bot 已加入該 channel。

## Delivery

所有 Slack writes 都走 delivery queue。Delivery 使用 Slack Web API `chat.postMessage` 發送 DM、channel message 與 thread reply。Codeoff 保存 Slack response metadata、message timestamps、failures、attempts 與 rate-limit cooldowns。

MCP send tools 可選 `send_as`：

- 省略、`null` 或 `bot`：使用 bot token。
- `user:<key>`：使用 `[slack.user_tokens.<key>]`。

## Context And Resources

Codex 可以主動取得 bounded provider context，而不是一開始就接收大量 Slack payloads。

可取得的類型：

- current event and conversation。
- active turn context pack。
- individual message lookup。
- thread replies。
- recent channel messages。
- resource/file metadata。
- supported resources 的 best-effort text extraction。
- lazy resource download to local artifact path。

Files and attachments 預設是 source references。只有 Codex 要求時，Codeoff 才下載或抽取內容。

## Addressing

Codeoff 提供 provider-neutral lookup tools：

- workspaces/connectors。
- users。
- channels。
- senders。
- connector status。

Search/resolve tools 在名稱不唯一時應返回 candidates，而不是自行猜測。

## MCP Tools

目前 channel tools：

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

MCP server 只在 `[mcp] enabled = true`、`transport = "tcp"` 且 `bind` 是 loopback 時由 `codeoff serve` 啟動。
