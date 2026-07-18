# Slack Connector

目的：定義目前 Slack connector 行為。
閱讀時機：修改 Socket Mode intake、Slack filtering、context fetch、file/resource access 或 Slack delivery 前。
不涵蓋：Codex response behavior。

## App Model

Codeoff 使用 Slack App，不使用 Slack user session。Socket Mode 是預設 realtime transport，不需要 public HTTP endpoint。

Runtime tokens：

```text
SLACK_APP_TOKEN
SLACK_BOT_TOKEN
```

`SLACK_SIGNING_SECRET` 用於 HTTP Events API compatibility；只有 HTTP event verification 需要它。

Optional user sender tokens 透過 `[slack.user_tokens.<key>]` 與 environment variables 設定，例如 `SLACK_EXAMPLE_USER_TOKEN`。

## Intake Rules

Connector 處理：

- `app_mention`。
- `message.im`。
- 已訂閱且有權限的 channel/group/mpim messages。
- 屬於已映射 conversation scope 的 thread replies。

Filtering rules：

- `mention_user_ids` 匹配 Slack text 中的 `<@USERID>`。
- `allowed_dm_user_ids` 限制 DM intake 到明確 Slack user ids。
- Private channel visibility 需要 bot membership。

## Queue Records

Slack intake 會保存 source-backed records：

```text
workspace_id
event_kind
dedupe_key
envelope_id
event_id
channel_id
thread_ts
message_ts
user_id
raw_payload_json
status
error
```

Normalized channel events 接著驅動 Codex dispatch。

## Context And Files

Context tools 以 bounded limits 呼叫 Slack Web API：

- `conversations.replies` for threads。
- `conversations.history` for recent messages。
- message lookup by channel and timestamp。
- file/resource metadata and lazy download。

Codeoff 回傳 ids、timestamps、links、metadata 與 bounded text。它不應 eager download 每個 attachment。

## Delivery

Slack sends 使用 `chat.postMessage`。Thread replies 帶 `thread_ts`。Delivery 會 queue、retry，並以 request dedupe keys 與 Slack response metadata 記錄。

遇到 Slack `429` 時，Codeoff 依 `Retry-After` 延後 affected scope 後續 sends。

## Setup Reference

目前 Slack App 設定流程見 `slack-app-setup-runbook.md`。
