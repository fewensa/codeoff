# Codex App Server

目的：定義 Codeoff 使用的本機 Codex App Server integration。
閱讀時機：修改 dispatch payloads、conversation mapping、dynamic tools 或 App Server process startup 前。
不涵蓋：Codex model prompts 或 project instructions。

## Integration Shape

Codeoff 使用設定中的 command：

```toml
[agent.codex_app_server]
command = "codex app-server --listen stdio://"
transport = "stdio"
ephemeral_threads = true
max_parallel_turns = 10
max_prompt_bytes = 65536
previous_success_context_max_bytes = 8192
```

目前 client 使用 stdio JSONL。Dispatch 會等待 Codex turn completed，並只在 Codex 回傳 final agent text 時保存 final draft text。

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

Payload 以 identifiers 為主：

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

Active event 可以附帶 compact message text 與 context hints，但 Slack history 與 files 應透過 bounded channel tools 取得。

## Dynamic Tools

每個 task 都帶有 default-deny dynamic-tool policy。Interactive channel turn 只會宣告該 task
allowlist 內的 channel tools，而且每次 tool call 都會再次檢查同一份 policy。Codex 可使用這些
允許的 tools：

- reply to current event or known thread。
- 以 bot 或 configured user token send message。
- fetch current event/conversation/context pack。
- fetch messages、thread replies、recent messages。
- resolve users/channels/workspaces。
- inspect delivery status。
- read or download referenced resources。

所有 Slack writes 仍然走 Codeoff delivery queue 與 receipts。
