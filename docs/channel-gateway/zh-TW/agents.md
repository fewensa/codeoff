# Codex Boundary

目的：定義 Codeoff 如何與 Codex 互動。
閱讀時機：修改 Codex App Server dispatch、channel tools 或 conversation mapping 前。
不涵蓋：Codex prompts 或 workspace project knowledge。

## 邊界

Codeoff 針對每個 eligible channel event 呼叫 Codex App Server。Codex 決定要做什麼，並可在 turn 中呼叫 Codeoff tools。

```text
ChannelEvent
  -> mapped Codex App Server conversation
  -> Codex turn
  -> dynamic channel tool calls
  -> Codeoff delivery/context/resource operations
```

Codeoff 提供可靠 source references 與 communication tools。Codex 負責理解 request 並選擇 actions。

## Conversation Mapping

Codeoff 將 provider conversation scope 映射到 Codex thread id。同一個 Slack DM、thread 或 channel scope 的 follow-up messages 會盡量 resume 已映射的 Codex conversation。

這個 mapping 讓 Codex 能保持連續性，不需要 Codeoff 建立另一套 reasoning context system。

## Dynamic Tools And MCP

同一組 channel primitives 會透過 App Server dynamic tools 與 local MCP surface 暴露。工具名稱使用 provider-neutral 的 `channel.*` namespace。

Codex 應優先用這些 tools 查 source 與寫 Slack，而不是在 initial prompt 直接接收大量 Slack history。

## Current Context

針對 active event，Codeoff 暴露：

- current source event。
- current conversation mapping。
- compact context pack。
- source links 與 attachment/resource references。
- 可進一步查 message、thread、user、channel 或 resource details 的 tool hints。

這讓 first dispatch 保持小而穩定，同時給 Codex 取得更多 context 的路徑。
