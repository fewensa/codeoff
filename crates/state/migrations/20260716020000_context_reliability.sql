create table context_fetch_attempts (
  id integer primary key,
  provider text not null,
  workspace_id text not null,
  connector_id text not null,
  dedupe_key text not null,
  operation text not null,
  channel_id text,
  thread_id text,
  message_ts text,
  status text not null,
  error_kind text,
  error_message text,
  created_at text not null default (datetime('now')),
  check (length(provider) > 0),
  check (length(workspace_id) > 0),
  check (length(connector_id) > 0),
  check (length(dedupe_key) > 0),
  check (length(operation) > 0),
  check (status in ('success', 'failed'))
);

create index idx_context_fetch_attempts_workspace_created_at
  on context_fetch_attempts (workspace_id, created_at);

create index idx_context_fetch_attempts_status_created_at
  on context_fetch_attempts (status, created_at);
