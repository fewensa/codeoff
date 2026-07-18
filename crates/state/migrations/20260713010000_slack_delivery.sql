create table slack_delivery_queue (
  id integer primary key,
  connector_id text not null,
  workspace_id text not null,
  request_dedupe_key text not null,
  channel_id text not null,
  thread_ts text,
  text text not null,
  status text not null default 'pending',
  available_at integer not null,
  attempt_count integer not null default 0,
  created_at text not null default (datetime('now')),
  updated_at text not null default (datetime('now')),
  unique (workspace_id, request_dedupe_key),
  check (length(connector_id) > 0),
  check (length(workspace_id) > 0),
  check (length(request_dedupe_key) > 0),
  check (length(channel_id) > 0),
  check (length(text) > 0),
  check (status in ('pending', 'processing', 'delivered', 'failed')),
  check (attempt_count >= 0)
);

create index idx_slack_delivery_queue_status_available_at
  on slack_delivery_queue (status, available_at);

create table slack_delivery_receipts (
  id integer primary key,
  connector_id text not null,
  workspace_id text not null,
  channel_id text not null,
  thread_ts text,
  message_ts text not null,
  request_dedupe_key text not null,
  slack_response_json text not null,
  created_at text not null default (datetime('now')),
  unique (workspace_id, request_dedupe_key),
  check (length(connector_id) > 0),
  check (length(workspace_id) > 0),
  check (length(channel_id) > 0),
  check (length(message_ts) > 0),
  check (length(request_dedupe_key) > 0),
  check (json_valid(slack_response_json))
);

create table slack_channel_throttles (
  workspace_id text not null,
  channel_id text not null,
  next_available_at integer not null,
  primary key (workspace_id, channel_id),
  check (length(workspace_id) > 0),
  check (length(channel_id) > 0)
);
