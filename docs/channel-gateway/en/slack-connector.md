# Slack Connector

Purpose: define the current Slack connector behavior.
Read this when changing Socket Mode intake, Slack filtering, context fetch, file/resource access, or Slack delivery.
This does not define Codex response behavior.

## App Model

Codeoff uses a Slack App, not a Slack user session. Socket Mode is the default realtime transport and does not require a public HTTP endpoint.

Required runtime tokens:

```text
SLACK_APP_TOKEN
SLACK_BOT_TOKEN
```

`SLACK_SIGNING_SECRET` is configured for HTTP Events API compatibility and is only required by HTTP event verification.

Optional user sender tokens are configured through `[slack.user_tokens.<key>]` and environment variables such as `SLACK_EXAMPLE_USER_TOKEN`.

## Intake Rules

The connector handles:

- `app_mention`.
- `message.im`.
- Channel/group/mpim messages when subscribed and authorized.
- Thread replies that belong to an already mapped conversation scope.

Filtering rules:

- `mention_user_ids` matches `<@USERID>` in Slack text.
- `allowed_dm_user_ids` restricts DM intake to explicit Slack user ids.
- Private channel visibility requires bot membership.

## Queue Records

Slack intake persists source-backed records with:

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

Normalized channel events then drive Codex dispatch.

## Context And Files

Context tools call Slack Web API with bounded limits:

- `conversations.replies` for threads.
- `conversations.history` for recent messages.
- Message lookup by channel and timestamp.
- File/resource metadata and lazy download.

Codeoff returns ids, timestamps, links, metadata, and bounded text. It should not eagerly download every attachment.

## Delivery

Slack sends use `chat.postMessage`. Thread replies include `thread_ts`. Delivery is queued, retried, and recorded with request dedupe keys and Slack response metadata.

On Slack `429`, Codeoff honors `Retry-After` and delays future sends for the affected scope.

## Setup Reference

Use `zh-TW/slack-app-setup-runbook.md` for the current click-by-click Slack App setup flow.
