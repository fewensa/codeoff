create table _scheduler_target_identity_guard_040000 (
  invalid_count integer not null check (invalid_count = 0)
);

insert into _scheduler_target_identity_guard_040000 (invalid_count)
select
  (select count(*)
   from scheduled_job_delivery_targets target
   where length(target.identity_digest) != 64
      or target.identity_digest glob '*[^0-9a-f]*')
  +
  (select count(*)
   from scheduled_runs run
   where json_type(run.targets_json) is not 'array'
      or json_array_length(run.targets_json) = 0
      or exists (
        select 1
        from json_each(run.targets_json) target
        where json_type(target.value) is not 'object'
           or json_type(target.value, '$.identity_digest') is not 'text'
           or length(json_extract(target.value, '$.identity_digest')) != 64
           or json_extract(target.value, '$.identity_digest') glob '*[^0-9a-f]*'
      ));

drop table _scheduler_target_identity_guard_040000;

create trigger trg_scheduled_job_target_identity_insert
before insert on scheduled_job_delivery_targets
when length(new.identity_digest) != 64
  or new.identity_digest glob '*[^0-9a-f]*'
begin
  select raise(abort, 'scheduled job target identity must be lowercase sha256');
end;

create trigger trg_scheduled_job_target_identity_update
before update of identity_digest on scheduled_job_delivery_targets
when length(new.identity_digest) != 64
  or new.identity_digest glob '*[^0-9a-f]*'
begin
  select raise(abort, 'scheduled job target identity must be lowercase sha256');
end;

create trigger trg_scheduled_run_target_identities_insert
before insert on scheduled_runs
when json_type(new.targets_json) is not 'array'
  or json_array_length(new.targets_json) = 0
  or exists (
    select 1
    from json_each(new.targets_json) target
    where json_type(target.value) is not 'object'
       or json_type(target.value, '$.identity_digest') is not 'text'
       or length(json_extract(target.value, '$.identity_digest')) != 64
       or json_extract(target.value, '$.identity_digest') glob '*[^0-9a-f]*'
  )
begin
  select raise(abort, 'scheduled run target identity must be lowercase sha256');
end;

create trigger trg_scheduled_run_target_identities_update
before update of targets_json on scheduled_runs
when json_type(new.targets_json) is not 'array'
  or json_array_length(new.targets_json) = 0
  or exists (
    select 1
    from json_each(new.targets_json) target
    where json_type(target.value) is not 'object'
       or json_type(target.value, '$.identity_digest') is not 'text'
       or length(json_extract(target.value, '$.identity_digest')) != 64
       or json_extract(target.value, '$.identity_digest') glob '*[^0-9a-f]*'
  )
begin
  select raise(abort, 'scheduled run target identity must be lowercase sha256');
end;

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
      and result_artifact_id is not null
      and length(result_artifact_id) > 0
      and result_attempt is not null
      and result_attempt > 0
      and result_fence is not null
      and result_fence > 0
      and delivery_policy_version = 1
      and target_snapshot_digest_algorithm is not null
      and target_snapshot_digest_algorithm = 'sha256-v1'
      and target_snapshot_digest is not null
      and length(target_snapshot_digest) = 64
      and target_snapshot_digest not glob '*[^0-9a-f]*'
      and length(cast(run_id as blob)) between 1 and 1050
      and length(target_identity_digest) = 64
      and target_identity_digest not glob '*[^0-9a-f]*'
      and intent_key is not null
      and length(intent_key) between 72 and 2170
      and intent_key = 'v1:' || lower(hex(cast(run_id as blob))) || ':' || target_identity_digest || ':1'
      and delivery_id = 'intent:' || intent_key)
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
  check (authority_kind != 'intent_v1' or state in ('intent', 'pending')),
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
when new.authority_kind = 'intent_v1' or new.intent_key is not null
begin
  select case when not (
    new.state = 'intent'
    and new.attempt = 0
    and new.fence = 0
    and new.next_attempt_at is null
    and new.lease_owner is null
    and new.lease_expires_at is null
    and new.provider_receipt is null
    and new.error_message is null
    and new.render_version is null
    and new.hash_algorithm is null
    and new.payload_digest is null
    and new.payload_snapshot is null
    and new.expected_baseline_version is null
  ) then raise(abort, 'scheduled delivery intent must start unrendered') end;
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
      and new.target_json = json(new.target_json)
      and json_type(new.target_json) = 'object'
      and json_extract(new.target_json, '$.identity_digest') = new.target_identity_digest
      and exists (
        select 1
        from json_each(r.targets_json) target
        where json(target.value) = new.target_json
          and json_type(target.value) = 'object'
          and json_extract(target.value, '$.identity_digest') = new.target_identity_digest
      )
  ) then raise(abort, 'scheduled delivery intent result authority mismatch') end;
end;

create trigger trg_scheduled_delivery_intent_insert_collision
before insert on scheduled_run_deliveries
when exists (
  select 1
  from scheduled_run_deliveries existing
  where existing.authority_kind = 'intent_v1'
    and (
      existing.delivery_id = new.delivery_id
      or (new.intent_key is not null and existing.intent_key = new.intent_key)
    )
)
begin
  select raise(abort, 'scheduled delivery intent cannot be replaced');
end;

create trigger trg_scheduled_delivery_intent_enrichment_only
before update on scheduled_run_deliveries
when old.authority_kind = 'intent_v1' and not (
  old.state = 'intent'
  and new.state = 'pending'
  and old.render_version is null
  and old.hash_algorithm is null
  and old.payload_digest is null
  and old.payload_snapshot is null
  and old.expected_baseline_version is null
  and new.render_version > 0
  and length(new.hash_algorithm) > 0
  and length(new.payload_digest) > 0
  and length(new.payload_snapshot) > 0
  and new.expected_baseline_version >= 0
  and new.delivery_id is old.delivery_id
  and new.run_id is old.run_id
  and new.job_id is old.job_id
  and new.target_identity_digest is old.target_identity_digest
  and new.target_json is old.target_json
  and new.attempt is old.attempt
  and new.next_attempt_at is old.next_attempt_at
  and new.lease_owner is old.lease_owner
  and new.lease_expires_at is old.lease_expires_at
  and new.fence is old.fence
  and new.provider_receipt is old.provider_receipt
  and new.error_message is old.error_message
  and new.delivery_policy_version is old.delivery_policy_version
  and new.result_artifact_id is old.result_artifact_id
  and new.result_attempt is old.result_attempt
  and new.result_fence is old.result_fence
  and new.target_snapshot_digest_algorithm is old.target_snapshot_digest_algorithm
  and new.target_snapshot_digest is old.target_snapshot_digest
  and new.intent_key is old.intent_key
  and new.authority_kind is old.authority_kind
  and new.created_at is old.created_at
  and new.updated_at >= old.updated_at
)
begin
  select raise(abort, 'scheduled delivery intent only permits one complete enrichment');
end;

create trigger trg_scheduled_delivery_intent_update_collision
before update on scheduled_run_deliveries
when exists (
  select 1
  from scheduled_run_deliveries existing
  where existing.authority_kind = 'intent_v1'
    and existing.rowid != old.rowid
    and (
      existing.delivery_id = new.delivery_id
      or (new.intent_key is not null and existing.intent_key = new.intent_key)
      or (
        existing.run_id = new.run_id
        and existing.target_identity_digest = new.target_identity_digest
        and existing.delivery_policy_version = new.delivery_policy_version
      )
    )
)
begin
  select raise(abort, 'scheduled delivery update conflicts with intent authority');
end;

create trigger trg_scheduled_delivery_intent_promotion_forbidden
before update on scheduled_run_deliveries
when old.authority_kind != 'intent_v1'
  and (new.authority_kind = 'intent_v1' or new.intent_key is not null)
begin
  select raise(abort, 'existing delivery cannot become an intent');
end;

create trigger trg_scheduled_delivery_intent_delete_forbidden
before delete on scheduled_run_deliveries
when old.authority_kind = 'intent_v1'
begin
  select raise(abort, 'scheduled delivery intent cannot be deleted');
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
