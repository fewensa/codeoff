# Slack App Socket Mode 設定手冊

目的：建立一個手動安裝到單一 Slack workspace 的 Slack App，讓 Codeoff 以 Socket Mode 作為本機 channel gateway。
閱讀時機：設定 Slack realtime listener、測試 private channel visibility、驗證 `mention_user_ids` 或排查 Slack delivery 前。
不涵蓋：Marketplace OAuth distribution、HTTP Events API deployment 或 Codex agent 行為。

## 運作邊界

Codeoff 使用 Slack App 的 Socket Mode，不是使用者帳號 listener。Slack event 進入 Codeoff 後會被 queue / dedupe，再 dispatch 到本機 Codex App Server。Codex 若要回覆，會呼叫 Codeoff dynamic channel tools 或 local MCP channel tools，最後由 Codeoff 使用 Slack Web API `chat.postMessage` 發送。

「可發送訊息」和「可監聽頻道」是不同 Slack permission path：

- `chat:write` 授權 bot 呼叫 Web API 發送訊息。
- `app_mentions:read`、`message.*` events 與對應 history/read scopes 才讓 App 接收或查詢訊息。
- 私人頻道必須邀請 App/bot 加入；scope 不會讓 bot 自動看見未加入的 private channels。

## 1. 建立並安裝 Slack App

1. 在 Slack API 建立新的 App，選擇要安裝的 workspace。
2. 在 **Socket Mode** 啟用 Socket Mode。
3. 在 **Basic Information** 的 **App-Level Tokens** 建立 token，加入 `connections:write` scope。安全保存 `xapp-...`，稍後設為 `SLACK_APP_TOKEN`。
4. 在 **App Home** 啟用 Bot User，名稱可使用 `Codeoff`。
5. 在 **OAuth & Permissions** 設定 Bot Token Scopes，然後重新安裝 App。重新安裝後安全保存 `xoxb-...`，稍後設為 `SLACK_BOT_TOKEN`。

Minimum scopes:

```text
app_mentions:read
im:history
im:read
im:write
chat:write
users:read
```

Optional bounded context and private-channel scopes:

```text
channels:history
channels:read
groups:history
groups:read
mpim:history
mpim:read
```

Schedule target resolver 會在建立或更新 Schedule 前呼叫 Slack Web API 並保存 canonical conversation ID；依啟用的 target kind，最小 bot scopes 為：

- Channel validation：public channel 使用 `channels:read`，private channel 使用 `groups:read`；bot 仍必須加入目標 conversation。
- Thread parent validation：另需相應的 `channels:history` 或 `groups:history`。
- DM user lookup 與 user → conversation open：`users:read`、`im:read`、`im:write`。
- 後續 message delivery：`chat:write`。

這些 scopes 只授權 Slack App；token 仍由既有 `SLACK_BOT_TOKEN` Secret owner 提供。不要把 token、Authorization header 或 Slack 完整錯誤 body 寫入 config、values 或 logs。

若需要 slash command，可另外加入 `commands` scope 並建立 `/codeoff`。

6. 從 **Basic Information** 複製 Signing Secret，安全保存為 `SLACK_SIGNING_SECRET`。Socket Mode 主要走 WebSocket envelope；HTTP Events API 驗證才需要 signing secret。

## 2. 設定即時事件

在 **Event Subscriptions** 啟用 events。Socket Mode 不需要 Request URL。將下列事件加入 **Subscribe to bot events**：

Minimum events:

```text
app_mention
message.im
```

Optional broader message events:

```text
message.channels
message.groups
message.mpim
```

`message.channels` 對應 public channels，`message.groups` 對應 private channels，`message.im` 對應 DM，`message.mpim` 對應 group DM。

Codeoff 的 `mention_user_ids` 會匹配 Slack 文字中的 `<@USERID>`。設定值必須是 Slack user ID，例如 `U01234567`，不是 display name、email 或 handle。

儲存 events 或 scopes 後，Slack 通常會要求重新安裝 App；請完成重新安裝，否則 workspace 不會取得新權限。

## 3. 頻道可見性

把 bot 邀請進要監聽或回覆的每個測試／正式頻道。對 private channel，這是必要條件；未被邀請的 bot 看不到該頻道，即使已設定 `groups:read`、`groups:history` 與 `message.groups`。

DM 與 group DM 也受 App 安裝與 conversation visibility 限制。不應假設 workspace 的所有私人對話都會因為 scopes 自動暴露給 Codeoff。

## 4. 配置 Codeoff 與 Secrets

Secrets 應放在 secrets manager 或 shell environment，不要寫入 `codeoff.toml`、版本控制或命令歷程。

```text
SLACK_APP_TOKEN
SLACK_BOT_TOKEN
SLACK_SIGNING_SECRET
SLACK_EXAMPLE_USER_TOKEN
```

最小 `codeoff.toml`：

```toml
[slack]
workspace_id = "T01234567"
transport = "socket_mode"
mention_user_ids = ["U01234567"]
allowed_dm_user_ids = ["U01234567"]

[slack.user_tokens.example]
user_id = "U01234567"
token_env = "SLACK_EXAMPLE_USER_TOKEN"

[agent.codex_app_server]
command = "codex app-server --listen stdio://"
transport = "stdio"
ephemeral_threads = true
max_parallel_turns = 10

[mcp]
enabled = true
transport = "tcp"
bind = "127.0.0.1:7789"
```

## 5. Delivery Queue 與 Receipts

Codeoff 發送 Slack 訊息時使用 delivery queue。

每筆 outbound request 應保存：

- workspace_id。
- channel_id。
- thread_ts，如果是 thread reply。
- text。
- idempotency_key。
- attempt_count。
- Slack Web API response。
- Slack message `ts`。
- error 與 retry-after。

發送 API 使用 `chat.postMessage`。Thread reply 使用同一 API 並帶 `thread_ts`。

Slack rate limit 由 Codeoff delivery layer 處理。遇到 `429` 時保存 retry-after 並稍後重試；不要讓 Codex 重新產生同一則回覆。

## 6. Smoke Test

1. 啟動 Codeoff daemon。
2. 確認 Socket Mode connected。
3. 在 public test channel 邀請 bot。
4. 發送包含 `<@USERID>` 的訊息，確認 inbound event queue 只有一筆。
5. 在 private test channel 邀請 bot，重複同樣測試。
6. 移除 bot 或在未邀請 private channel 測試，確認 Codeoff 不會收到事件。
7. 讓 Codex 或 fake MCP client 呼叫 `channel.reply_to_event`。
8. 確認 Codeoff 透過 `chat.postMessage` 回覆 thread，並保存 delivery receipt 與 Slack `ts`。
