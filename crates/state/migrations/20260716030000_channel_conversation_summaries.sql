create table if not exists channel_conversation_summaries (
  provider text not null,
  workspace_id text not null,
  conversation_kind text not null,
  channel_id text not null default '',
  thread_id text not null default '',
  user_id text not null default '',
  summary text not null,
  created_at text not null default (datetime('now')),
  updated_at text not null default (datetime('now')),
  primary key (
    provider,
    workspace_id,
    conversation_kind,
    channel_id,
    thread_id,
    user_id
  ),
  check (length(provider) > 0),
  check (length(workspace_id) > 0),
  check (conversation_kind in ('thread', 'dm', 'channel')),
  check (length(summary) > 0),
  check (
    conversation_kind <> 'thread'
    or (length(channel_id) > 0 and length(thread_id) > 0 and length(user_id) = 0)
  ),
  check (
    conversation_kind <> 'dm'
    or (length(channel_id) > 0 and length(thread_id) = 0 and length(user_id) > 0)
  ),
  check (
    conversation_kind <> 'channel'
    or (length(channel_id) > 0 and length(thread_id) = 0 and length(user_id) = 0)
  )
);

create index idx_channel_conversation_summaries_workspace_updated_at
  on channel_conversation_summaries (workspace_id, updated_at);
