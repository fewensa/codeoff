alter table slack_delivery_queue
  add column operation text not null default 'post_message' check (operation in ('post_message', 'stop_stream'));

alter table slack_delivery_queue
  add column message_ts text check (message_ts is null or length(message_ts) > 0);

create table slack_processing_indicators (
  id integer primary key,
  workspace_id text not null,
  event_dedupe_key text not null,
  channel_id text not null,
  thread_ts text,
  message_ts text not null,
  status text not null default 'started',
  error text,
  created_at text not null default (datetime('now')),
  updated_at text not null default (datetime('now')),
  completed_at text,
  unique (workspace_id, event_dedupe_key),
  check (length(workspace_id) > 0),
  check (length(event_dedupe_key) > 0),
  check (length(channel_id) > 0),
  check (thread_ts is null or length(thread_ts) > 0),
  check (length(message_ts) > 0),
  check (status in ('started', 'completed', 'failed')),
  check (
    (status = 'started' and completed_at is null)
    or (status in ('completed', 'failed') and completed_at is not null)
  )
);
