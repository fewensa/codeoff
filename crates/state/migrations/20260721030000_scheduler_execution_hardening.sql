update scheduled_runs
set attempt = case when attempt < 1 then 1 else attempt end,
    fence = case when fence < 1 then 1 else fence end
where state in ('leased', 'executing');

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
where state = 'leased';

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
where state = 'executing';

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
