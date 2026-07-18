# Codeoff Channel Gateway

目的：定義目前 Codeoff 的產品邊界。
閱讀時機：修改 channel gateway code、docs 或部署設定前。
不涵蓋：Codex agent 行為、專案知識、prompt 或業務流程政策。

## 摘要

Codeoff 是給 Codex 使用的本機 communication gateway。

```text
Slack App
  -> Codeoff daemon
  -> SQLite queue / dedupe / receipts
  -> local Codex App Server
  -> Codex decides and calls tools
  -> Codeoff channel tools / MCP
  -> Slack Web API
```

Codeoff 接收 Slack event，保存可追溯的 gateway records，將可處理 event dispatch 到對應的 Codex App Server conversation，並提供 channel tools 讓 Codex 查 context 或透過 Codeoff 發送 Slack 訊息。

## 目前實作狀態

Checked-in code 已包含：

- Slack Socket Mode intake、mention filtering、DM filtering、queue persistence、dry-run queue inspection。
- SQLite state：inbound source events、normalized channel events、conversation mappings、dispatch attempts、outbound delivery、receipts、throttles、retention config。
- Codex App Server stdio JSONL client construction，以及可 start/resume mapped Codex conversations 的 interactive dispatch。
- Runtime channel handlers：reply、send、context fetch、current context、resources、user/channel lookup、sender listing、workspace listing、connector status、thread replies。
- MCP JSON-RPC dispatch：`initialize`、`tools/list`、`tools/call` 與 channel tools。
- `[mcp] enabled = true` 且 `transport = "tcp"` 時，由 `codeoff serve` 啟動 loopback TCP MCP server。
- Slack Web API delivery queue、receipts、rate-limit handling、next-due delivery drain。
- Docker image：包含編譯後的 `codeoff` binary、Codex 與常用運維工具。

`codeoff serve --check` 只驗證 config/state，不啟動 live loops。非 check 的 `codeoff serve` 會啟動已設定的 Slack intake、Codex dispatch、outbound Slack delivery drain，以及已啟用的 TCP MCP server。

## 責任邊界

Codeoff 負責：

- provider intake 與 ack。
- gateway filtering、queueing、dedupe、retry、receipt、rate-limit handling。
- dispatch transport to Codex App Server。
- provider-neutral channel tools 與 MCP exposure。
- Codex 要求時提供 bounded source/context/resource access。

Codex 負責：

- reasoning、response content、tool choice。
- project understanding 與 workspace instructions。
- 是否 reply、追問、fetch more context 或 no action。

## 設計原則

Codeoff 應保持單純。當 Codex 需要更安全或更可靠的 provider 溝通能力時，才新增 gateway primitive。推理、計劃與 domain decision 應放在 Codex 或 Codex 已配置的工具中。
