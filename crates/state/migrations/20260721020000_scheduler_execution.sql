alter table scheduled_runs add column result_artifact_id text;

create table scheduled_run_attempts (
  run_id text not null,
  job_id text not null,
  attempt integer not null,
  fence integer not null,
  lease_owner text not null,
  state text not null,
  claimed_at integer not null,
  lease_expires_at integer not null,
  preflight_completed_at integer,
  executing_at integer,
  completed_at integer,
  attested_profile_schema_version integer,
  attested_profile_json text,
  attested_profile_hash_algorithm text,
  attested_profile_digest text,
  error_kind text,
  error_message text,
  primary key (run_id, attempt),
  unique (run_id, fence),
  unique (run_id, attempt, fence),
  foreign key (run_id, job_id) references scheduled_runs(run_id, job_id) on delete restrict,
  check (attempt > 0 and fence > 0),
  check (length(lease_owner) > 0),
  check (state in (
    'leased',
    'executing',
    'retry_scheduled',
    'preflight_rejected',
    'lease_expired',
    'succeeded',
    'failed',
    'timed_out',
    'cancelled',
    'outcome_unknown'
  )),
  check (lease_expires_at > claimed_at),
  check (
    (attested_profile_schema_version is null
      and attested_profile_json is null
      and attested_profile_hash_algorithm is null
      and attested_profile_digest is null)
    or
    (attested_profile_schema_version > 0
      and json_valid(attested_profile_json)
      and length(attested_profile_hash_algorithm) > 0
      and length(attested_profile_digest) > 0)
  ),
  check (
    state not in ('executing', 'succeeded', 'failed', 'timed_out', 'cancelled', 'outcome_unknown')
    or attested_profile_json is not null
    or state in ('failed', 'cancelled')
  ),
  check ((state = 'executing' and executing_at is not null and completed_at is null)
    or (state != 'executing')),
  check ((state in ('leased', 'executing') and completed_at is null)
    or (state not in ('leased', 'executing') and completed_at is not null)),
  check ((error_kind is null and error_message is null)
    or (error_kind is not null and state not in ('leased', 'executing')))
);

create index idx_scheduled_run_attempts_recovery
  on scheduled_run_attempts (state, lease_expires_at, run_id, attempt);

create table scheduled_run_result_artifacts (
  artifact_id text primary key,
  run_id text not null unique,
  job_id text not null,
  accepted_attempt integer not null,
  accepted_fence integer not null,
  schema_version integer not null,
  result_json text not null,
  hash_algorithm text not null,
  result_hash text not null,
  previous_success_context text not null,
  completed_at integer not null,
  unique (run_id, job_id, hash_algorithm, result_hash),
  foreign key (run_id, job_id) references scheduled_runs(run_id, job_id) on delete restrict,
  foreign key (run_id, accepted_attempt, accepted_fence)
    references scheduled_run_attempts(run_id, attempt, fence) on delete restrict,
  check (length(artifact_id) > 0),
  check (accepted_attempt > 0 and accepted_fence > 0 and schema_version > 0),
  check (json_valid(result_json)),
  check (length(hash_algorithm) > 0 and length(result_hash) > 0)
);

create trigger trg_scheduled_run_result_artifacts_acceptance
before insert on scheduled_run_result_artifacts
begin
  select case when not exists (
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
  ) then raise(abort, 'scheduled run result acceptance binding mismatch') end;
end;

create trigger trg_scheduled_run_result_artifacts_immutable
before update on scheduled_run_result_artifacts
begin
  select raise(abort, 'scheduled run result artifacts are immutable');
end;

create trigger trg_scheduled_runs_result_artifact_binding
before update of result_artifact_id on scheduled_runs
when new.result_artifact_id is not null
begin
  select case when not exists (
    select 1
    from scheduled_run_result_artifacts a
    where a.artifact_id = new.result_artifact_id
      and a.run_id = new.run_id
      and a.job_id = new.job_id
      and a.accepted_attempt = new.attempt
      and a.accepted_fence = new.fence
  ) then raise(abort, 'scheduled run result artifact binding mismatch') end;
end;

create trigger trg_scheduled_runs_result_artifact_immutable
before update of result_artifact_id on scheduled_runs
when old.result_artifact_id is not null and new.result_artifact_id is not old.result_artifact_id
begin
  select raise(abort, 'scheduled run result artifact reference is immutable');
end;

create table scheduled_run_late_evidence (
  evidence_id text primary key,
  run_id text not null,
  attempt integer not null,
  fence integer not null,
  evidence_kind text not null,
  hash_algorithm text not null,
  evidence_digest text not null,
  redacted_message text,
  observed_at integer not null,
  unique (run_id, attempt, fence, evidence_kind, hash_algorithm, evidence_digest),
  foreign key (run_id, attempt, fence)
    references scheduled_run_attempts(run_id, attempt, fence) on delete restrict,
  check (length(evidence_id) > 0 and attempt > 0 and fence > 0),
  check (length(evidence_kind) > 0 and length(hash_algorithm) > 0 and length(evidence_digest) > 0)
);

create index idx_scheduled_run_late_evidence_attempt
  on scheduled_run_late_evidence (run_id, attempt, observed_at, evidence_id);

create index idx_scheduled_runs_claim
  on scheduled_runs (state, next_attempt_at, scheduled_for, run_id);
