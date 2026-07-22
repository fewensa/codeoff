create table _scheduled_delivery_baselines_220000 as
select * from scheduled_delivery_baselines;

drop table scheduled_delivery_baselines;

create table _scheduled_run_deliveries_220000 as
select * from scheduled_run_deliveries;

drop table scheduled_run_deliveries;

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
  idempotency_key text,
  provider_receipt text,
  provider_outcome text,
  error_kind text,
  error_message text,
  delivery_policy_version integer not null,
  render_version integer,
  payload_schema_version integer,
  content_type text,
  hash_algorithm text,
  payload_digest text,
  payload_snapshot blob,
  payload_created_at integer,
  expected_baseline_version integer,
  result_artifact_id text,
  result_attempt integer,
  result_fence integer,
  target_snapshot_digest_algorithm text,
  target_snapshot_digest text,
  target_snapshot_version integer,
  intent_key text,
  authority_kind text not null default 'legacy',
  created_at integer not null,
  updated_at integer not null,
  unique (
    run_id,
    target_identity_digest,
    delivery_policy_version,
    render_version,
    hash_algorithm
  ),
  unique (delivery_id, run_id, job_id),
  foreign key (run_id, job_id)
    references scheduled_runs(run_id, job_id) on delete restrict,
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
  check (json_valid(target_json) and json_type(target_json) = 'object'),
  check (state in (
    'pending',
    'sending',
    'delivered',
    'failed_retryable',
    'failed_terminal',
    'delivery_unknown',
    'skipped_none'
  )),
  check (
    attempt >= 0
    and fence >= 0
    and delivery_policy_version > 0
    and updated_at >= created_at
  ),
  check (
    (payload_snapshot is null
      and render_version is null
      and payload_schema_version is null
      and content_type is null
      and hash_algorithm is null
      and payload_digest is null
      and payload_created_at is null
      and expected_baseline_version is null
      and target_snapshot_version is null)
    or
    (length(payload_snapshot) > 0
      and render_version > 0
      and payload_schema_version = 1
      and length(content_type) > 0
      and hash_algorithm = 'sha256-utf8-exact-v1'
      and length(payload_digest) = 64
      and payload_digest not glob '*[^0-9a-f]*'
      and payload_created_at >= created_at
      and expected_baseline_version >= 0
      and target_snapshot_version > 0)
  ),
  check (
    authority_kind != 'intent_v1'
    or (
      result_artifact_id is not null
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
      and length(target_identity_digest) = 64
      and target_identity_digest not glob '*[^0-9a-f]*'
      and intent_key is not null
      and length(intent_key) between 72 and 2170
      and intent_key = 'v1:' || lower(hex(cast(run_id as blob))) || ':' || target_identity_digest || ':1'
      and delivery_id = 'intent:' || intent_key
      and (
        (state = 'pending' and payload_snapshot is null)
        or payload_snapshot is not null
      )
    )
  ),
  check (
    (state = 'sending'
      and lease_owner is not null
      and length(lease_owner) > 0
      and lease_expires_at is not null
      and idempotency_key is not null
      and length(idempotency_key) > 0)
    or
    (state != 'sending'
      and lease_owner is null
      and lease_expires_at is null)
  ),
  check (next_attempt_at is null or state = 'failed_retryable'),
  check (provider_receipt is null or state = 'delivered'),
  check (
    (state in ('pending', 'sending') and provider_outcome is null)
    or (state = 'delivered' and provider_outcome = 'confirmed_success')
    or (state = 'failed_retryable' and provider_outcome = 'confirmed_no_write_retryable')
    or (state = 'failed_terminal' and provider_outcome = 'confirmed_no_write_terminal')
    or (state = 'delivery_unknown' and provider_outcome = 'ambiguous_post_write')
    or (state = 'skipped_none' and provider_outcome = 'skipped_none')
  ),
  check (
    (state in ('failed_retryable', 'failed_terminal', 'delivery_unknown')
      and error_kind is not null
      and length(error_kind) > 0)
    or
    (state not in ('failed_retryable', 'failed_terminal', 'delivery_unknown')
      and error_kind is null
      and error_message is null)
  ),
  check (
    state not in ('sending', 'delivered', 'failed_retryable', 'failed_terminal', 'delivery_unknown')
    or authority_kind != 'intent_v1'
    or payload_snapshot is not null
  )
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
  idempotency_key,
  provider_receipt,
  provider_outcome,
  error_kind,
  error_message,
  delivery_policy_version,
  render_version,
  payload_schema_version,
  content_type,
  hash_algorithm,
  payload_digest,
  payload_snapshot,
  payload_created_at,
  expected_baseline_version,
  result_artifact_id,
  result_attempt,
  result_fence,
  target_snapshot_digest_algorithm,
  target_snapshot_digest,
  target_snapshot_version,
  intent_key,
  authority_kind,
  created_at,
  updated_at
)
select
  delivery_id,
  run_id,
  job_id,
  target_identity_digest,
  target_json,
  case
    when state = 'intent' then 'pending'
    when state = 'pending' and authority_kind = 'intent_v1' then 'pending'
    when state in ('sending', 'failed', 'delivery_unknown') then 'delivery_unknown'
    when state = 'delivered' then 'delivered'
    when state = 'skipped' and json_extract(target_json, '$.kind') = 'none' then 'skipped_none'
    else 'failed_terminal'
  end,
  attempt,
  null,
  null,
  null,
  fence,
  null,
  case when state = 'delivered' then provider_receipt end,
  case
    when state = 'delivered' then 'confirmed_success'
    when state in ('sending', 'failed', 'delivery_unknown') then 'ambiguous_post_write'
    when state = 'skipped' and json_extract(target_json, '$.kind') = 'none' then 'skipped_none'
    when state in ('pending', 'leased', 'skipped') and authority_kind != 'intent_v1'
      then 'confirmed_no_write_terminal'
  end,
  case
    when state = 'sending' then 'legacy_sending_recovered_unknown'
    when state = 'failed' then 'legacy_failure_recovered_unknown'
    when state = 'delivery_unknown' then coalesce(nullif(error_message, ''), 'legacy_delivery_unknown')
    when state = 'leased' then 'legacy_lease_missing_payload'
    when state = 'pending' and authority_kind != 'intent_v1' then 'legacy_pending_missing_payload'
    when state = 'skipped' and json_extract(target_json, '$.kind') is not 'none'
      then 'legacy_skipped_target_not_none'
  end,
  case
    when state in ('sending', 'failed', 'delivery_unknown', 'leased')
      or (state = 'pending' and authority_kind != 'intent_v1')
      or (state = 'skipped' and json_extract(target_json, '$.kind') is not 'none')
      then coalesce(nullif(error_message, ''), 'legacy delivery requires operator review')
  end,
  delivery_policy_version,
  case when payload_snapshot is not null then render_version end,
  case when payload_snapshot is not null then 1 end,
  case when payload_snapshot is not null then 'text/plain; charset=utf-8' end,
  case when payload_snapshot is not null then 'sha256-utf8-exact-v1' end,
  case when payload_snapshot is not null then payload_digest end,
  payload_snapshot,
  case when payload_snapshot is not null then updated_at end,
  case when payload_snapshot is not null then expected_baseline_version end,
  result_artifact_id,
  result_attempt,
  result_fence,
  target_snapshot_digest_algorithm,
  target_snapshot_digest,
  case
    when payload_snapshot is not null
      then cast(json_extract(target_json, '$.resolver_version') as integer)
  end,
  intent_key,
  authority_kind,
  created_at,
  updated_at
from _scheduled_run_deliveries_220000;

drop table _scheduled_run_deliveries_220000;

create index idx_scheduled_deliveries_claim
  on scheduled_run_deliveries (state, next_attempt_at, created_at, delivery_id);
create index idx_scheduled_deliveries_retry
  on scheduled_run_deliveries (state, next_attempt_at, delivery_id);
create index idx_scheduled_deliveries_recovery
  on scheduled_run_deliveries (state, lease_expires_at, delivery_id);
create unique index idx_scheduled_delivery_intent_identity
  on scheduled_run_deliveries (run_id, target_identity_digest, delivery_policy_version)
  where intent_key is not null;
create unique index idx_scheduled_delivery_intent_key
  on scheduled_run_deliveries (intent_key)
  where intent_key is not null;
create unique index idx_scheduled_delivery_active_baseline_identity
  on scheduled_run_deliveries (
    job_id,
    target_identity_digest,
    target_snapshot_digest,
    delivery_policy_version,
    render_version,
    hash_algorithm
  ) where state = 'sending';

create table scheduled_delivery_attempts (
  delivery_id text not null,
  attempt integer not null,
  fence integer not null,
  lease_owner text not null,
  lease_expires_at integer not null,
  idempotency_key text not null,
  state text not null,
  provider_receipt text,
  provider_outcome text,
  error_kind text,
  error_message text,
  started_at integer not null,
  completed_at integer,
  primary key (delivery_id, attempt),
  unique (delivery_id, fence),
  unique (idempotency_key),
  foreign key (delivery_id) references scheduled_run_deliveries(delivery_id) on delete restrict,
  check (attempt > 0 and fence > 0),
  check (length(lease_owner) > 0 and lease_expires_at > started_at),
  check (length(idempotency_key) > 0),
  check (state in (
    'sending',
    'delivered',
    'failed_retryable',
    'failed_terminal',
    'delivery_unknown'
  )),
  check ((state = 'sending' and completed_at is null)
    or (state != 'sending' and completed_at is not null)),
  check (provider_receipt is null or state = 'delivered'),
  check (
    (state = 'sending' and provider_outcome is null)
    or (state = 'delivered' and provider_outcome = 'confirmed_success')
    or (state = 'failed_retryable' and provider_outcome = 'confirmed_no_write_retryable')
    or (state = 'failed_terminal' and provider_outcome = 'confirmed_no_write_terminal')
    or (state = 'delivery_unknown' and provider_outcome = 'ambiguous_post_write')
  )
);

create index idx_scheduled_delivery_attempts_recovery
  on scheduled_delivery_attempts (state, lease_expires_at, delivery_id, attempt);

create table scheduled_delivery_baselines (
  job_id text not null references scheduled_jobs(job_id) on delete restrict,
  target_identity_digest text not null,
  target_snapshot_digest_algorithm text not null,
  target_snapshot_digest text not null,
  delivery_policy_version integer not null,
  render_version integer not null,
  hash_algorithm text not null,
  accepted_payload_digest text not null,
  source_delivery_id text not null,
  source_run_id text not null,
  source_result_id text,
  source_result_hash text not null,
  accepted_at integer not null,
  baseline_version integer not null,
  primary key (
    job_id,
    target_identity_digest,
    target_snapshot_digest_algorithm,
    target_snapshot_digest,
    delivery_policy_version,
    render_version,
    hash_algorithm
  ),
  check (
    delivery_policy_version > 0
    and render_version > 0
    and baseline_version > 0
    and accepted_at >= 0
  ),
  check (
    length(target_identity_digest) > 0
    and length(target_snapshot_digest_algorithm) > 0
    and length(target_snapshot_digest) > 0
    and length(hash_algorithm) > 0
    and length(accepted_payload_digest) > 0
    and length(source_delivery_id) > 0
    and length(source_run_id) > 0
    and length(source_result_hash) > 0
  )
);

insert into scheduled_delivery_baselines (
  job_id,
  target_identity_digest,
  target_snapshot_digest_algorithm,
  target_snapshot_digest,
  delivery_policy_version,
  render_version,
  hash_algorithm,
  accepted_payload_digest,
  source_delivery_id,
  source_run_id,
  source_result_id,
  source_result_hash,
  accepted_at,
  baseline_version
)
select
  baseline.job_id,
  baseline.target_identity_digest,
  coalesce(delivery.target_snapshot_digest_algorithm, 'legacy-target-identity-sha256-v1'),
  coalesce(delivery.target_snapshot_digest, baseline.target_identity_digest),
  baseline.delivery_policy_version,
  baseline.render_version,
  baseline.hash_algorithm,
  baseline.accepted_payload_digest,
  baseline.source_delivery_id,
  baseline.source_run_id,
  delivery.result_artifact_id,
  baseline.source_result_hash,
  baseline.accepted_at,
  baseline.baseline_version
from _scheduled_delivery_baselines_220000 baseline
join scheduled_run_deliveries delivery
  on delivery.delivery_id = baseline.source_delivery_id
  and delivery.run_id = baseline.source_run_id
  and delivery.job_id = baseline.job_id;

drop table _scheduled_delivery_baselines_220000;

create trigger trg_scheduled_delivery_intent_acceptance
before insert on scheduled_run_deliveries
when new.authority_kind = 'intent_v1' or new.intent_key is not null
begin
  select case when not (
    new.state = 'pending'
    and new.attempt = 0
    and new.fence = 0
    and new.payload_snapshot is null
    and new.idempotency_key is null
  ) then raise(abort, 'scheduled delivery intent must start pending and unrendered') end;
  select case when not exists (
    select 1
    from scheduled_run_result_artifacts artifact
    join scheduled_runs run
      on run.run_id = artifact.run_id and run.job_id = artifact.job_id
    where artifact.artifact_id = new.result_artifact_id
      and artifact.run_id = new.run_id
      and artifact.job_id = new.job_id
      and artifact.accepted_attempt = new.result_attempt
      and artifact.accepted_fence = new.result_fence
      and artifact.schema_version = 1
      and artifact.provenance = 'native'
      and artifact.provenance_version = 1
      and new.target_json = json(new.target_json)
      and json_extract(new.target_json, '$.identity_digest') = new.target_identity_digest
      and exists (
        select 1
        from json_each(run.targets_json) target
        where json(target.value) = new.target_json
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
      or (
        existing.run_id = new.run_id
        and existing.target_identity_digest = new.target_identity_digest
        and existing.delivery_policy_version = new.delivery_policy_version
      )
    )
)
begin
  select raise(abort, 'scheduled delivery authority cannot be replaced');
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
  select raise(abort, 'scheduled delivery update conflicts with authority');
end;

create trigger trg_scheduled_delivery_identity_immutable
before update on scheduled_run_deliveries
when old.authority_kind = 'intent_v1' and (
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
  or new.created_at is not old.created_at
)
begin
  select raise(abort, 'scheduled delivery authority identity is immutable');
end;

create trigger trg_scheduled_delivery_payload_immutable
before update on scheduled_run_deliveries
when old.authority_kind = 'intent_v1'
  and old.payload_snapshot is not null
  and (
    new.render_version is not old.render_version
    or new.payload_schema_version is not old.payload_schema_version
    or new.content_type is not old.content_type
    or new.hash_algorithm is not old.hash_algorithm
    or new.payload_digest is not old.payload_digest
    or new.payload_snapshot is not old.payload_snapshot
    or new.payload_created_at is not old.payload_created_at
    or new.target_snapshot_version is not old.target_snapshot_version
  )
begin
  select raise(abort, 'scheduled delivery payload is immutable');
end;

create trigger trg_scheduled_delivery_state_transition
before update of state on scheduled_run_deliveries
when old.state != new.state and not (
  (old.state = 'pending' and new.state in ('sending', 'skipped_none'))
  or (old.state = 'sending' and new.state in (
    'delivered',
    'failed_retryable',
    'failed_terminal',
    'delivery_unknown'
  ))
  or (old.state = 'failed_retryable' and new.state = 'pending')
)
begin
  select raise(abort, 'invalid scheduled delivery state transition');
end;

create trigger trg_scheduled_delivery_intent_promotion_forbidden
before update on scheduled_run_deliveries
when old.authority_kind != 'intent_v1'
  and (new.authority_kind = 'intent_v1' or new.intent_key is not null)
begin
  select raise(abort, 'legacy delivery cannot become intent authority');
end;

create trigger trg_scheduled_delivery_intent_delete_forbidden
before delete on scheduled_run_deliveries
when old.authority_kind = 'intent_v1'
begin
  select raise(abort, 'scheduled delivery authority cannot be deleted');
end;

create table _scheduler_delivery_authority_guard_220000 (
  invalid_count integer not null check (invalid_count = 0)
);

insert into _scheduler_delivery_authority_guard_220000 (invalid_count)
select count(*) from pragma_foreign_key_check;

drop table _scheduler_delivery_authority_guard_220000;
