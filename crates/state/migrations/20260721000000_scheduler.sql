alter table idempotency_keys add column request_digest text;
alter table idempotency_keys add column digest_algorithm text;
alter table idempotency_keys add column response_json text;

create table scheduled_jobs (
  job_id text primary key,
  definition_version integer not null,
  definition_json text not null,
  creator_kind text not null,
  creator_provider text not null,
  creator_tenant text not null,
  creator_subject text not null,
  owner_kind text not null,
  owner_provider text not null,
  owner_tenant text not null,
  owner_subject text not null,
  status text not null default 'active',
  generation integer not null default 0,
  capability_schema_version integer not null,
  capability_digest text not null,
  capability_json text not null,
  created_at integer not null,
  updated_at integer not null,
  deleted_at integer,
  check (length(job_id) between 1 and 255),
  check (definition_version > 0 and json_valid(definition_json)),
  check (length(creator_kind) > 0 and length(creator_provider) > 0 and length(creator_tenant) > 0 and length(creator_subject) > 0),
  check (length(owner_kind) > 0 and length(owner_provider) > 0 and length(owner_tenant) > 0 and length(owner_subject) > 0),
  check (status in ('active', 'paused', 'completed', 'deleted')),
  check (generation >= 0),
  check (capability_schema_version > 0 and length(capability_digest) > 0 and json_valid(capability_json)),
  check ((status = 'deleted' and deleted_at is not null) or (status != 'deleted' and deleted_at is null))
);

create index idx_scheduled_jobs_owner_status
  on scheduled_jobs (owner_kind, owner_provider, owner_tenant, owner_subject, status, job_id);

create table schedules (
  schedule_id text primary key,
  job_id text not null unique references scheduled_jobs(job_id) on delete restrict,
  kind text not null,
  canonical_spec text not null,
  timezone text,
  once_at integer,
  anchor_at integer,
  interval_seconds integer,
  misfire_policy text not null default 'coalesce',
  overlap_policy text not null default 'forbid',
  generation integer not null default 0,
  next_run_at integer,
  created_at integer not null,
  updated_at integer not null,
  unique (schedule_id, job_id),
  check (length(schedule_id) between 1 and 255),
  check (kind in ('once', 'fixed_interval', 'cron')),
  check (misfire_policy = 'coalesce'),
  check (overlap_policy = 'forbid'),
  check (generation >= 0),
  check (
    (kind = 'once' and once_at is not null and anchor_at is null and interval_seconds is null and timezone is null)
    or (kind = 'fixed_interval' and once_at is null and anchor_at is not null and interval_seconds > 0 and timezone is null)
    or (kind = 'cron' and once_at is null and anchor_at is null and interval_seconds is null and timezone is not null)
  )
);

create index idx_schedules_due on schedules (next_run_at, job_id) where next_run_at is not null;

create table scheduled_job_delivery_targets (
  target_id text primary key,
  job_id text not null references scheduled_jobs(job_id) on delete restrict,
  ordinal integer not null,
  provider text not null,
  connector text not null,
  tenant text not null,
  kind text not null,
  address_json text not null,
  resolver_version integer not null,
  resolver_digest text not null,
  identity_digest text not null,
  unique (job_id, ordinal),
  unique (job_id, identity_digest),
  check (ordinal >= 0),
  check (length(provider) > 0 and length(connector) > 0 and length(tenant) > 0 and length(kind) > 0),
  check (json_valid(address_json) and resolver_version > 0 and length(resolver_digest) > 0 and length(identity_digest) > 0)
);

create table scheduled_execution_baselines (
  job_id text primary key references scheduled_jobs(job_id) on delete restrict,
  baseline_version integer not null default 0,
  hash_algorithm text,
  result_hash text,
  previous_success_context text,
  source_run_id text,
  completed_at integer,
  check (baseline_version >= 0),
  check ((result_hash is null and hash_algorithm is null and source_run_id is null and completed_at is null)
    or (result_hash is not null and hash_algorithm is not null and source_run_id is not null and completed_at is not null)),
  foreign key (source_run_id, job_id) references scheduled_runs(run_id, job_id) on delete restrict
);

create table scheduled_runs (
  run_id text primary key,
  job_id text not null references scheduled_jobs(job_id) on delete restrict,
  schedule_id text not null,
  job_generation integer not null,
  schedule_generation integer not null,
  scheduled_for integer not null,
  coalesced_through integer not null,
  skipped_count integer not null default 0,
  skipped_count_saturated integer not null default 0,
  definition_version integer not null,
  definition_json text not null,
  capability_schema_version integer not null,
  capability_digest text not null,
  capability_json text not null,
  targets_json text not null,
  execution_baseline_json text,
  state text not null default 'pending',
  attempt integer not null default 0,
  next_attempt_at integer,
  lease_owner text,
  lease_expires_at integer,
  fence integer not null default 0,
  overlap_slot integer,
  result_context text,
  result_hash_algorithm text,
  result_hash text,
  error_kind text,
  error_message text,
  created_at integer not null,
  updated_at integer not null,
  unique (job_id, scheduled_for),
  unique (run_id, job_id),
  foreign key (schedule_id, job_id) references schedules(schedule_id, job_id) on delete restrict,
  check (job_generation >= 0 and schedule_generation >= 0 and scheduled_for <= coalesced_through),
  check (skipped_count >= 0 and skipped_count_saturated in (0, 1)),
  check (definition_version > 0 and json_valid(definition_json)),
  check (capability_schema_version > 0 and length(capability_digest) > 0 and json_valid(capability_json)),
  check (json_valid(targets_json)),
  check (execution_baseline_json is null or json_valid(execution_baseline_json)),
  check (state in ('pending', 'leased', 'executing', 'succeeded', 'failed', 'timed_out', 'cancelled', 'outcome_unknown')),
  check (attempt >= 0 and fence >= 0),
  check ((lease_owner is null and lease_expires_at is null)
    or (lease_owner is not null and lease_expires_at is not null and state in ('leased', 'executing'))),
  check (next_attempt_at is null or state = 'pending'),
  check ((result_hash_algorithm is null and result_hash is null)
    or (result_hash_algorithm is not null and result_hash is not null and state = 'succeeded')),
  check (result_context is null or state = 'succeeded'),
  check ((error_kind is null and error_message is null)
    or (state in ('failed', 'timed_out', 'outcome_unknown') and error_kind is not null)),
  check ((state in ('pending', 'leased', 'executing', 'outcome_unknown') and overlap_slot = 1)
    or (state in ('succeeded', 'failed', 'timed_out', 'cancelled') and overlap_slot is null))
);

create unique index idx_scheduled_runs_active_overlap
  on scheduled_runs (job_id, overlap_slot) where overlap_slot is not null;
create index idx_scheduled_runs_recovery on scheduled_runs (state, lease_expires_at, run_id);
create index idx_scheduled_runs_retry on scheduled_runs (state, next_attempt_at, run_id);
create index idx_scheduled_runs_history on scheduled_runs (job_id, scheduled_for desc);

create table scheduled_run_deliveries (
  delivery_id text primary key,
  run_id text not null,
  job_id text not null,
  target_identity_digest text not null,
  target_json text not null,
  state text not null default 'pending',
  attempt integer not null default 0,
  next_attempt_at integer,
  lease_owner text,
  lease_expires_at integer,
  fence integer not null default 0,
  provider_receipt text,
  error_message text,
  delivery_policy_version integer not null,
  render_version integer not null,
  hash_algorithm text not null,
  payload_digest text not null,
  expected_baseline_version integer not null,
  created_at integer not null,
  updated_at integer not null,
  unique (run_id, target_identity_digest, delivery_policy_version, render_version, hash_algorithm),
  unique (delivery_id, run_id, job_id),
  foreign key (run_id, job_id) references scheduled_runs(run_id, job_id) on delete restrict,
  check (json_valid(target_json)),
  check (state in ('pending', 'leased', 'sending', 'delivered', 'failed', 'delivery_unknown', 'skipped')),
  check (attempt >= 0 and fence >= 0 and delivery_policy_version > 0 and render_version > 0 and expected_baseline_version >= 0),
  check (length(hash_algorithm) > 0 and length(payload_digest) > 0),
  check ((lease_owner is null and lease_expires_at is null)
    or (lease_owner is not null and lease_expires_at is not null and state in ('leased', 'sending'))),
  check (next_attempt_at is null or state = 'pending'),
  check (provider_receipt is null or state = 'delivered'),
  check (error_message is null or state in ('failed', 'delivery_unknown'))
);

create index idx_scheduled_deliveries_recovery
  on scheduled_run_deliveries (state, lease_expires_at, delivery_id);
create index idx_scheduled_deliveries_retry
  on scheduled_run_deliveries (state, next_attempt_at, delivery_id);

create table scheduled_delivery_baselines (
  job_id text not null references scheduled_jobs(job_id) on delete restrict,
  target_identity_digest text not null,
  delivery_policy_version integer not null,
  render_version integer not null,
  hash_algorithm text not null,
  accepted_payload_digest text not null,
  source_delivery_id text not null,
  source_run_id text not null,
  source_result_hash text not null,
  accepted_at integer not null,
  baseline_version integer not null,
  primary key (job_id, target_identity_digest, delivery_policy_version, render_version, hash_algorithm),
  foreign key (source_run_id, job_id) references scheduled_runs(run_id, job_id) on delete restrict,
  foreign key (source_delivery_id, source_run_id, job_id) references scheduled_run_deliveries(delivery_id, run_id, job_id) on delete restrict,
  check (delivery_policy_version > 0 and render_version > 0 and baseline_version > 0),
  check (length(target_identity_digest) > 0 and length(hash_algorithm) > 0 and length(accepted_payload_digest) > 0)
);
