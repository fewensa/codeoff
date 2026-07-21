alter table scheduled_run_result_artifacts
  add column provenance text not null default 'native'
  check (provenance in ('native', 'legacy'));

alter table scheduled_run_result_artifacts
  add column provenance_version integer not null default 1
  check (provenance_version > 0);

create table _scheduler_execution_hardening_guard (
  invalid_count integer not null check (invalid_count = 0)
);

insert into _scheduler_execution_hardening_guard (invalid_count)
select count(*)
from scheduled_runs r
where r.state in ('leased', 'executing')
  and exists (
    select 1 from scheduled_run_attempts a where a.run_id = r.run_id
  )
  and not exists (
    select 1
    from scheduled_run_attempts a
    where a.run_id = r.run_id
      and a.job_id = r.job_id
      and a.attempt = r.attempt
      and a.fence = r.fence
      and a.lease_owner = r.lease_owner
      and a.state = r.state
  );

update scheduled_run_attempts
set state = 'lease_expired',
    completed_at = (select updated_at from scheduled_runs r where r.run_id = scheduled_run_attempts.run_id),
    error_kind = 'lease_recovered_during_upgrade',
    error_message = 'lease_recovered_during_upgrade'
where state = 'leased'
  and exists (
    select 1
    from scheduled_runs r
    where r.run_id = scheduled_run_attempts.run_id
      and r.job_id = scheduled_run_attempts.job_id
      and r.attempt = scheduled_run_attempts.attempt
      and r.fence = scheduled_run_attempts.fence
      and r.lease_owner = scheduled_run_attempts.lease_owner
      and r.state = 'leased'
  );

update scheduled_run_attempts
set state = 'outcome_unknown',
    completed_at = (select updated_at from scheduled_runs r where r.run_id = scheduled_run_attempts.run_id),
    error_kind = 'execution_recovered_during_upgrade',
    error_message = 'execution_recovered_during_upgrade'
where state = 'executing'
  and exists (
    select 1
    from scheduled_runs r
    where r.run_id = scheduled_run_attempts.run_id
      and r.job_id = scheduled_run_attempts.job_id
      and r.attempt = scheduled_run_attempts.attempt
      and r.fence = scheduled_run_attempts.fence
      and r.lease_owner = scheduled_run_attempts.lease_owner
      and r.state = 'executing'
  );

update scheduled_runs
set attempt = case when attempt < 1 then 1 else attempt end,
    fence = case when fence < 1 then 1 else fence end
where state in ('leased', 'executing')
  and not exists (
    select 1 from scheduled_run_attempts a where a.run_id = scheduled_runs.run_id
  );

insert into scheduled_run_attempts (
  run_id,
  job_id,
  attempt,
  fence,
  lease_owner,
  state,
  claimed_at,
  lease_expires_at,
  completed_at,
  error_kind,
  error_message
)
select
  run_id,
  job_id,
  attempt,
  fence,
  lease_owner,
  'lease_expired',
  min(updated_at, lease_expires_at - 1),
  lease_expires_at,
  updated_at,
  'legacy_lease_recovered',
  'legacy_lease_recovered'
from scheduled_runs
where state = 'leased'
  and not exists (
    select 1 from scheduled_run_attempts a where a.run_id = scheduled_runs.run_id
  );

insert into scheduled_run_attempts (
  run_id,
  job_id,
  attempt,
  fence,
  lease_owner,
  state,
  claimed_at,
  lease_expires_at,
  preflight_completed_at,
  executing_at,
  completed_at,
  attested_profile_schema_version,
  attested_profile_json,
  attested_profile_hash_algorithm,
  attested_profile_digest,
  error_kind,
  error_message
)
select
  run_id,
  job_id,
  attempt,
  fence,
  lease_owner,
  'outcome_unknown',
  min(updated_at, lease_expires_at - 1),
  lease_expires_at,
  updated_at,
  updated_at,
  updated_at,
  1,
  '{"legacy_unattested_execution":true}',
  'migration-v1',
  'unavailable',
  'legacy_execution_unattested',
  'legacy_execution_unattested'
from scheduled_runs
where state = 'executing'
  and not exists (
    select 1 from scheduled_run_attempts a where a.run_id = scheduled_runs.run_id
  );

update scheduled_runs
set state = 'pending',
    next_attempt_at = updated_at,
    lease_owner = null,
    lease_expires_at = null,
    error_kind = null,
    error_message = null
where state = 'leased';

update scheduled_runs
set state = 'outcome_unknown',
    lease_owner = null,
    lease_expires_at = null,
    error_kind = 'legacy_execution_unattested',
    error_message = 'legacy_execution_unattested'
where state = 'executing';

drop trigger trg_scheduled_run_result_artifacts_acceptance;

create table _scheduler_legacy_success (
  run_id text primary key,
  is_valid integer not null check (is_valid in (0, 1))
);

insert into _scheduler_legacy_success (run_id, is_valid)
select
  r.run_id,
  case when r.result_artifact_id is null
    and r.result_context is not null
    and r.result_hash_algorithm is not null
    and r.result_hash is not null
    and (
      not exists (select 1 from scheduled_run_attempts a where a.run_id = r.run_id)
      or exists (
        select 1
        from scheduled_run_attempts a
        where a.run_id = r.run_id
          and a.job_id = r.job_id
          and a.attempt = r.attempt
          and a.fence = r.fence
          and a.state = 'succeeded'
          and a.completed_at is not null
      )
    )
  then 1 else 0 end
from scheduled_runs r
where r.state = 'succeeded' and r.result_artifact_id is null;

insert into _scheduler_execution_hardening_guard (invalid_count)
select count(*)
from scheduled_runs r
where r.state = 'succeeded'
  and r.result_artifact_id is not null
  and not exists (
    select 1
    from scheduled_run_result_artifacts a
    join scheduled_run_attempts t
      on t.run_id = a.run_id
      and t.attempt = a.accepted_attempt
      and t.fence = a.accepted_fence
    where a.artifact_id = r.result_artifact_id
      and a.run_id = r.run_id
      and a.job_id = r.job_id
      and a.accepted_attempt = r.attempt
      and a.accepted_fence = r.fence
      and a.hash_algorithm = r.result_hash_algorithm
      and a.result_hash = r.result_hash
      and a.previous_success_context = r.result_context
      and a.provenance = 'native'
      and a.provenance_version = 1
      and t.state = 'succeeded'
  );

insert into _scheduler_execution_hardening_guard (invalid_count)
select count(*)
from _scheduler_legacy_success s
join scheduled_runs r on r.run_id = s.run_id
where s.is_valid = 0
  and exists (select 1 from scheduled_runs active where active.job_id = r.job_id and active.overlap_slot = 1);

insert into _scheduler_execution_hardening_guard (invalid_count)
select count(*)
from _scheduler_legacy_success s
join scheduled_runs r on r.run_id = s.run_id
where s.is_valid = 0
  and exists (select 1 from scheduled_run_attempts a where a.run_id = r.run_id)
  and not exists (
    select 1
    from scheduled_run_attempts a
    where a.run_id = r.run_id
      and a.job_id = r.job_id
      and a.attempt = r.attempt
      and a.fence = r.fence
      and a.state = 'succeeded'
  );

update scheduled_runs
set attempt = case when attempt < 1 then 1 else attempt end,
    fence = case when fence < 1 then 1 else fence end
where run_id in (select run_id from _scheduler_legacy_success);

update scheduled_run_attempts
set state = 'outcome_unknown',
    error_kind = 'legacy_result_unverified',
    error_message = 'legacy_result_unverified'
where state = 'succeeded'
  and run_id in (select run_id from _scheduler_legacy_success where is_valid = 0);

insert into scheduled_run_attempts (
  run_id,
  job_id,
  attempt,
  fence,
  lease_owner,
  state,
  claimed_at,
  lease_expires_at,
  preflight_completed_at,
  executing_at,
  completed_at,
  attested_profile_schema_version,
  attested_profile_json,
  attested_profile_hash_algorithm,
  attested_profile_digest,
  error_kind,
  error_message
)
select
  r.run_id,
  r.job_id,
  r.attempt,
  r.fence,
  'legacy-result-migration',
  case when s.is_valid = 1 then 'succeeded' else 'outcome_unknown' end,
  -1,
  0,
  r.updated_at,
  r.updated_at,
  r.updated_at,
  1,
  '{"legacy_unattested_execution":true}',
  'migration-v1',
  'unavailable',
  case when s.is_valid = 1 then null else 'legacy_result_unverified' end,
  case when s.is_valid = 1 then null else 'legacy_result_unverified' end
from _scheduler_legacy_success s
join scheduled_runs r on r.run_id = s.run_id
where not exists (select 1 from scheduled_run_attempts a where a.run_id = r.run_id);

insert into scheduled_run_result_artifacts (
  artifact_id,
  run_id,
  job_id,
  accepted_attempt,
  accepted_fence,
  schema_version,
  result_json,
  hash_algorithm,
  result_hash,
  previous_success_context,
  completed_at,
  provenance,
  provenance_version
)
select
  'legacy-result:' || r.run_id,
  r.run_id,
  r.job_id,
  r.attempt,
  r.fence,
  1,
  '{"provenance":"legacy","schema_version":1}',
  r.result_hash_algorithm,
  r.result_hash,
  r.result_context,
  r.updated_at,
  'legacy',
  1
from _scheduler_legacy_success s
join scheduled_runs r on r.run_id = s.run_id
where s.is_valid = 1;

update scheduled_runs
set result_artifact_id = 'legacy-result:' || run_id
where run_id in (select run_id from _scheduler_legacy_success where is_valid = 1);

update scheduled_runs
set state = 'outcome_unknown',
    overlap_slot = 1,
    result_artifact_id = null,
    result_context = null,
    result_hash_algorithm = null,
    result_hash = null,
    error_kind = 'legacy_result_unverified',
    error_message = 'legacy_result_unverified'
where run_id in (select run_id from _scheduler_legacy_success where is_valid = 0);

drop table _scheduler_legacy_success;
drop table _scheduler_execution_hardening_guard;

create trigger trg_scheduled_run_result_artifacts_acceptance
before insert on scheduled_run_result_artifacts
when new.provenance != 'native'
  or new.provenance_version != 1
  or not exists (
    select 1
    from scheduled_runs r
    join scheduled_run_attempts a
      on a.run_id = r.run_id
      and a.attempt = r.attempt
      and a.fence = r.fence
    where r.run_id = new.run_id
      and r.job_id = new.job_id
      and r.attempt = new.accepted_attempt
      and r.fence = new.accepted_fence
      and r.state = 'executing'
      and a.state = 'executing'
  )
begin
  select raise(abort, 'scheduled run result acceptance binding mismatch');
end;

create trigger trg_scheduled_run_result_artifacts_delete_guard
before delete on scheduled_run_result_artifacts
begin
  select raise(abort, 'scheduled run result artifacts require explicit retention authority');
end;

create trigger trg_scheduled_run_result_artifacts_insert_once
before insert on scheduled_run_result_artifacts
when exists (
  select 1
  from scheduled_run_result_artifacts a
  where a.artifact_id = new.artifact_id or a.run_id = new.run_id
)
begin
  select raise(abort, 'scheduled run result artifact already exists');
end;

create trigger trg_scheduled_runs_insert_result_artifact_guard
before insert on scheduled_runs
when new.result_artifact_id is not null
begin
  select raise(abort, 'scheduled run result artifact cannot be supplied at run creation');
end;

create trigger trg_scheduled_runs_insert_succeeded_guard
before insert on scheduled_runs
when new.state = 'succeeded'
begin
  select raise(abort, 'scheduled run success requires an accepted state transition');
end;

create trigger trg_scheduled_runs_success_authority
before update of state on scheduled_runs
when new.state = 'succeeded' and old.state != 'succeeded'
begin
  select case when not exists (
    select 1
    from scheduled_run_result_artifacts a
    join scheduled_run_attempts t
      on t.run_id = a.run_id
      and t.attempt = a.accepted_attempt
      and t.fence = a.accepted_fence
    where a.artifact_id = new.result_artifact_id
      and a.run_id = new.run_id
      and a.job_id = new.job_id
      and a.accepted_attempt = new.attempt
      and a.accepted_fence = new.fence
      and a.hash_algorithm = new.result_hash_algorithm
      and a.result_hash = new.result_hash
      and a.previous_success_context = new.result_context
      and a.provenance = 'native'
      and a.provenance_version = 1
      and t.state = 'succeeded'
      and t.completed_at is not null
  ) then raise(abort, 'scheduled run success requires its accepted result artifact') end;
end;

create trigger trg_scheduled_runs_success_result_immutable
before update on scheduled_runs
when old.state = 'succeeded' and (
  new.result_artifact_id is not old.result_artifact_id
  or new.result_hash_algorithm is not old.result_hash_algorithm
  or new.result_hash is not old.result_hash
  or new.result_context is not old.result_context
)
begin
  select raise(abort, 'scheduled run accepted result is immutable');
end;

create trigger trg_scheduled_run_late_evidence_contract
before insert on scheduled_run_late_evidence
when new.evidence_kind not in (
  'completion_after_lease_loss',
  'preflight_after_lease_loss',
  'heartbeat_after_lease_loss'
)
  or length(cast(new.evidence_id as blob)) > 128
  or new.hash_algorithm != 'sha256-v1'
  or length(new.evidence_digest) != 64
  or new.evidence_digest glob '*[^0-9a-f]*'
  or new.redacted_message is not null
begin
  select raise(abort, 'invalid scheduled run late evidence');
end;

create trigger trg_scheduled_run_late_evidence_quota
before insert on scheduled_run_late_evidence
when (
  select count(*)
  from scheduled_run_late_evidence e
  where e.run_id = new.run_id and e.attempt = new.attempt
) >= 32
begin
  select raise(abort, 'scheduled run late evidence quota exceeded');
end;
