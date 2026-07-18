create table slack_source_events (
  id integer primary key,
  workspace_id text not null,
  event_kind text not null,
  dedupe_key text not null,
  envelope_id text,
  event_id text,
  channel_id text,
  thread_ts text,
  message_ts text,
  user_id text,
  raw_payload_json text not null,
  received_at text not null default (datetime('now')),
  acknowledged_at text,
  processed_at text,
  status text not null default 'received',
  error text,
  unique (workspace_id, dedupe_key),
  check (length(workspace_id) > 0),
  check (length(event_kind) > 0),
  check (length(dedupe_key) > 0),
  check (json_valid(raw_payload_json)),
  check (status in ('received', 'queued', 'processed', 'failed'))
);

create index idx_slack_source_events_status_received_at
  on slack_source_events (status, received_at);

create table channel_event_queue (
  id integer primary key,
  provider text not null,
  workspace_id text not null,
  dedupe_key text not null,
  event_kind text not null,
  payload_json text not null,
  status text not null default 'pending',
  available_at text not null default (datetime('now')),
  attempt_count integer not null default 0,
  created_at text not null default (datetime('now')),
  updated_at text not null default (datetime('now')),
  unique (provider, workspace_id, dedupe_key),
  check (length(provider) > 0),
  check (length(workspace_id) > 0),
  check (length(dedupe_key) > 0),
  check (length(event_kind) > 0),
  check (json_valid(payload_json)),
  check (status in ('pending', 'processing', 'processed', 'failed')),
  check (attempt_count >= 0)
);

create index idx_channel_event_queue_status_available_at
  on channel_event_queue (status, available_at);
