create table idempotency_keys (
  id integer primary key,
  scope text not null,
  key text not null,
  status text not null default 'claimed',
  response_ref text,
  expires_at text,
  created_at text not null default (datetime('now')),
  updated_at text not null default (datetime('now')),
  unique (scope, key),
  check (length(scope) > 0),
  check (length(key) > 0),
  check (status in ('claimed', 'completed', 'failed'))
);

create index idx_idempotency_keys_expires_at
  on idempotency_keys (expires_at)
  where expires_at is not null;

create table work_items (
  id integer primary key,
  provider text not null,
  external_id text not null,
  title text not null,
  status text not null,
  url text,
  metadata_json text not null default '{}',
  created_at text not null default (datetime('now')),
  updated_at text not null default (datetime('now')),
  unique (provider, external_id),
  check (length(provider) > 0),
  check (length(external_id) > 0),
  check (length(title) > 0),
  check (json_valid(metadata_json)),
  check (status in ('open', 'in_progress', 'blocked', 'closed'))
);

create index idx_work_items_provider_status
  on work_items (provider, status);

create table conversation_contexts (
  id integer primary key,
  provider text not null,
  external_thread_id text not null,
  context_json text not null default '{}',
  last_message_at text,
  created_at text not null default (datetime('now')),
  updated_at text not null default (datetime('now')),
  unique (provider, external_thread_id),
  check (length(provider) > 0),
  check (length(external_thread_id) > 0),
  check (json_valid(context_json))
);
