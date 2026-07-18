create table agent_drafts (
  id integer primary key,
  channel_event_queue_id integer not null unique,
  provider text not null,
  channel_id text,
  thread_id text,
  message_ts text,
  user_id text,
  event_id text not null,
  dedupe_key text not null,
  content text not null,
  created_at text not null default (datetime('now')),
  foreign key (channel_event_queue_id) references channel_event_queue (id) on delete cascade,
  check (length(provider) > 0),
  check (length(event_id) > 0),
  check (length(dedupe_key) > 0),
  check (length(content) > 0)
);
