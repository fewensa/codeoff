create table _scheduler_delivery_baselines_040000 as
select * from scheduled_delivery_baselines;

drop table scheduled_delivery_baselines;

create table _scheduler_run_deliveries_040000 as
select * from scheduled_run_deliveries;

drop table scheduled_run_deliveries;

create unique index idx_scheduled_result_artifact_delivery_binding
  on scheduled_run_result_artifacts (
    artifact_id,
    run_id,
    job_id,
    accepted_attempt,
    accepted_fence
  );

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
  render_version integer,
  hash_algorithm text,
  payload_digest text,
  payload_snapshot blob,
  expected_baseline_version integer,
  result_artifact_id text,
  result_attempt integer,
  result_fence integer,
  target_snapshot_digest_algorithm text,
  target_snapshot_digest text,
  intent_key text,
  authority_kind text not null default 'legacy',
  created_at integer not null,
  updated_at integer not null,
  unique (run_id, target_identity_digest, delivery_policy_version, render_version, hash_algorithm),
  unique (delivery_id, run_id, job_id),
  foreign key (run_id, job_id) references scheduled_runs(run_id, job_id) on delete restrict,
  foreign key (
    result_artifact_id,
    run_id,
    job_id,
    result_attempt,
    result_fence
  ) references scheduled_run_result_artifacts (
    artifact_id,
    run_id,
    job_id,
    accepted_attempt,
    accepted_fence
  ) on delete restrict,
  check (json_valid(target_json)),
  check (state in ('intent', 'pending', 'leased', 'sending', 'delivered', 'failed', 'delivery_unknown', 'skipped')),
  check (attempt >= 0 and fence >= 0 and delivery_policy_version > 0),
  check (
    (render_version is null
      and hash_algorithm is null
      and payload_digest is null
      and payload_snapshot is null
      and expected_baseline_version is null)
    or
    (render_version > 0
      and length(hash_algorithm) > 0
      and length(payload_digest) > 0
      and expected_baseline_version >= 0)
  ),
  check (
    (authority_kind = 'legacy'
      and result_artifact_id is null
      and result_attempt is null
      and result_fence is null
      and target_snapshot_digest_algorithm is null
      and target_snapshot_digest is null
      and intent_key is null)
    or
    (authority_kind = 'intent_v1'
      and length(result_artifact_id) > 0
      and result_attempt > 0
      and result_fence > 0
      and target_snapshot_digest_algorithm = 'sha256-v1'
      and length(target_snapshot_digest) = 64
      and target_snapshot_digest not glob '*[^0-9a-f]*'
      and length(intent_key) = 64
      and intent_key not glob '*[^0-9a-f]*')
  ),
  check (
    (state = 'intent'
      and intent_key is not null
      and attempt = 0
      and fence = 0
      and next_attempt_at is null
      and lease_owner is null
      and lease_expires_at is null
      and provider_receipt is null
      and error_message is null
      and render_version is null
      and payload_snapshot is null)
    or
    (state != 'intent'
      and render_version is not null
      and (intent_key is null or length(payload_snapshot) > 0))
  ),
  check ((state in ('leased', 'sending') and lease_owner is not null and lease_expires_at is not null)
    or (state not in ('leased', 'sending') and lease_owner is null and lease_expires_at is null)),
  check (next_attempt_at is null or state = 'pending'),
  check (provider_receipt is null or state = 'delivered'),
  check (error_message is null or state in ('failed', 'delivery_unknown'))
);

insert into scheduled_run_deliveries (
  delivery_id,
  run_id,
  job_id,
  target_identity_digest,
  target_json,
  state,
  attempt,
  next_attempt_at,
  lease_owner,
  lease_expires_at,
  fence,
  provider_receipt,
  error_message,
  delivery_policy_version,
  render_version,
  hash_algorithm,
  payload_digest,
  expected_baseline_version,
  created_at,
  updated_at
)
select
  delivery_id,
  run_id,
  job_id,
  target_identity_digest,
  target_json,
  state,
  attempt,
  next_attempt_at,
  lease_owner,
  lease_expires_at,
  fence,
  provider_receipt,
  error_message,
  delivery_policy_version,
  render_version,
  hash_algorithm,
  payload_digest,
  expected_baseline_version,
  created_at,
  updated_at
from _scheduler_run_deliveries_040000;

drop table _scheduler_run_deliveries_040000;

create index idx_scheduled_deliveries_recovery
  on scheduled_run_deliveries (state, lease_expires_at, delivery_id);
create index idx_scheduled_deliveries_retry
  on scheduled_run_deliveries (state, next_attempt_at, delivery_id);
create unique index idx_scheduled_delivery_intent_identity
  on scheduled_run_deliveries (run_id, target_identity_digest, delivery_policy_version)
  where intent_key is not null;
create unique index idx_scheduled_delivery_intent_key
  on scheduled_run_deliveries (intent_key)
  where intent_key is not null;

create trigger trg_scheduled_delivery_intent_acceptance
before insert on scheduled_run_deliveries
when new.intent_key is not null
begin
  select case when not exists (
    select 1
    from scheduled_run_result_artifacts a
    join scheduled_runs r on r.run_id = a.run_id and r.job_id = a.job_id
    join scheduled_run_attempts t
      on t.run_id = a.run_id
      and t.attempt = a.accepted_attempt
      and t.fence = a.accepted_fence
    where a.artifact_id = new.result_artifact_id
      and a.run_id = new.run_id
      and a.job_id = new.job_id
      and a.accepted_attempt = new.result_attempt
      and a.accepted_fence = new.result_fence
      and a.schema_version = 1
      and a.provenance = 'native'
      and a.provenance_version = 1
      and r.state = 'executing'
      and r.attempt = a.accepted_attempt
      and r.fence = a.accepted_fence
      and t.state = 'executing'
  ) then raise(abort, 'scheduled delivery intent result authority mismatch') end;
end;

create trigger trg_scheduled_delivery_intent_identity_immutable
before update on scheduled_run_deliveries
when old.intent_key is not null and (
  new.delivery_id is not old.delivery_id
  or new.run_id is not old.run_id
  or new.job_id is not old.job_id
  or new.target_identity_digest is not old.target_identity_digest
  or new.target_json is not old.target_json
  or new.delivery_policy_version is not old.delivery_policy_version
  or new.result_artifact_id is not old.result_artifact_id
  or new.result_attempt is not old.result_attempt
  or new.result_fence is not old.result_fence
  or new.target_snapshot_digest_algorithm is not old.target_snapshot_digest_algorithm
  or new.target_snapshot_digest is not old.target_snapshot_digest
  or new.intent_key is not old.intent_key
  or new.authority_kind is not old.authority_kind
)
begin
  select raise(abort, 'scheduled delivery intent identity is immutable');
end;

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

insert into scheduled_delivery_baselines
select * from _scheduler_delivery_baselines_040000;

drop table _scheduler_delivery_baselines_040000;

create table _scheduler_delivery_intents_guard (
  invalid_count integer not null check (invalid_count = 0)
);

insert into _scheduler_delivery_intents_guard (invalid_count)
select count(*) from pragma_foreign_key_check;

drop table _scheduler_delivery_intents_guard;
