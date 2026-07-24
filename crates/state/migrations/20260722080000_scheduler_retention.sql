create index idx_scheduled_runs_retention
  on scheduled_runs (updated_at, run_id)
  where state in ('succeeded', 'failed', 'timed_out', 'cancelled');

create index idx_scheduled_deliveries_retention
  on scheduled_run_deliveries (run_id, updated_at, delivery_id)
  where authority_kind = 'intent_v1'
    and state in ('delivered', 'failed_terminal', 'skipped_none', 'skipped_unchanged');

alter table scheduled_delivery_retention_audit add column job_generation integer;
alter table scheduled_delivery_retention_audit add column schedule_generation integer;
alter table scheduled_delivery_retention_audit add column run_terminal_at integer;
alter table scheduled_delivery_retention_audit add column run_cutoff_at integer;
alter table scheduled_delivery_retention_audit add column delivery_cutoff_at integer;

drop trigger trg_scheduled_delivery_retention_audit_acceptance;

create trigger trg_scheduled_delivery_retention_audit_acceptance
before insert on scheduled_delivery_retention_audit
when new.completed_at is not null
  or new.attempts_deleted != 0
  or new.job_generation is null
  or new.schedule_generation is null
  or new.run_terminal_at is null
  or new.run_cutoff_at is null
  or new.delivery_cutoff_at is null
  or not exists (
    select 1
    from scheduled_run_deliveries delivery
    join scheduled_runs run on run.run_id = delivery.run_id and run.job_id = delivery.job_id
    join scheduled_run_attempts attempt
      on attempt.run_id = run.run_id and attempt.job_id = run.job_id
      and attempt.attempt = run.attempt and attempt.fence = run.fence
    join scheduled_run_result_artifacts artifact
      on artifact.artifact_id = run.result_artifact_id
      and artifact.run_id = run.run_id and artifact.job_id = run.job_id
      and artifact.accepted_attempt = run.attempt and artifact.accepted_fence = run.fence
    where delivery.delivery_id = new.delivery_id
      and delivery.run_id = new.run_id
      and delivery.job_id = new.job_id
      and delivery.state = new.delivery_state
      and delivery.payload_digest = new.payload_digest
      and delivery.authority_kind = 'intent_v1'
      and delivery.payload_snapshot is not null
      and delivery.state in ('delivered', 'failed_terminal', 'skipped_none', 'skipped_unchanged')
      and delivery.updated_at <= new.delivery_cutoff_at
      and run.state = 'succeeded'
      and run.job_generation = new.job_generation
      and run.schedule_generation = new.schedule_generation
      and run.updated_at <= new.run_cutoff_at
      and attempt.state = 'succeeded'
      and attempt.completed_at = new.run_terminal_at
      and attempt.completed_at <= new.run_cutoff_at
      and artifact.completed_at = attempt.completed_at
      and artifact.hash_algorithm = run.result_hash_algorithm
      and artifact.result_hash = run.result_hash
      and artifact.previous_success_context = run.result_context
      and new.run_cutoff_at <= new.authorized_at
      and new.delivery_cutoff_at <= new.authorized_at
      and not exists (
        select 1 from scheduled_execution_baselines baseline
        where baseline.source_run_id = run.run_id and baseline.job_id = run.job_id
      )
      and not exists (
        select 1 from scheduled_run_deliveries item
        where item.run_id = run.run_id
          and not (
            item.authority_kind = 'intent_v1'
            and item.payload_snapshot is not null
            and item.state in ('delivered', 'failed_terminal', 'skipped_none', 'skipped_unchanged')
            and item.updated_at <= new.delivery_cutoff_at
          )
      )
  )
begin
  select raise(abort, 'scheduled delivery retention authority mismatch');
end;

drop trigger trg_scheduled_delivery_retention_audit_update;

create trigger trg_scheduled_delivery_retention_audit_update
before update on scheduled_delivery_retention_audit
when not (
  old.completed_at is null
  and new.completed_at is not null
  and new.completed_at >= old.authorized_at
  and new.operation_id is old.operation_id
  and new.delivery_id is old.delivery_id
  and new.run_id is old.run_id
  and new.job_id is old.job_id
  and new.delivery_state is old.delivery_state
  and new.payload_digest is old.payload_digest
  and new.authorized_at is old.authorized_at
  and new.job_generation is old.job_generation
  and new.schedule_generation is old.schedule_generation
  and new.run_terminal_at is old.run_terminal_at
  and new.run_cutoff_at is old.run_cutoff_at
  and new.delivery_cutoff_at is old.delivery_cutoff_at
  and new.attempts_deleted >= 0
)
begin
  select raise(abort, 'scheduled delivery retention audit is immutable');
end;

create table scheduled_run_retention_audit (
  operation_id text not null,
  run_id text not null,
  job_id text not null references scheduled_jobs(job_id) on delete restrict,
  job_generation integer not null,
  schedule_generation integer not null,
  run_state text not null,
  terminal_at integer not null,
  cutoff_at integer not null,
  authorized_at integer not null,
  attempts_deleted integer not null default 0,
  late_evidence_deleted integer not null default 0,
  expected_attempts_deleted integer not null,
  expected_late_evidence_deleted integer not null,
  deleted_rows integer not null default 0,
  completed_at integer,
  primary key (operation_id, run_id),
  unique (run_id),
  check (length(operation_id) > 0 and length(run_id) > 0),
  check (job_generation >= 0 and schedule_generation >= 0),
  check (run_state in ('failed', 'timed_out', 'cancelled')),
  check (terminal_at >= 0 and terminal_at <= cutoff_at and authorized_at >= cutoff_at),
  check (attempts_deleted >= 0 and late_evidence_deleted >= 0 and deleted_rows >= 0),
  check (expected_attempts_deleted >= 0 and expected_late_evidence_deleted >= 0),
  check (completed_at is null or completed_at >= authorized_at)
);

create trigger trg_scheduled_run_retention_audit_acceptance
before insert on scheduled_run_retention_audit
when new.completed_at is not null
  or new.attempts_deleted != 0
  or new.late_evidence_deleted != 0
  or new.deleted_rows != 0
  or not exists (
    select 1
    from scheduled_runs run
    where run.run_id = new.run_id
      and run.job_id = new.job_id
      and run.job_generation = new.job_generation
      and run.schedule_generation = new.schedule_generation
      and run.state = new.run_state
      and run.state in ('failed', 'timed_out', 'cancelled')
      and run.result_artifact_id is null
      and run.updated_at <= new.cutoff_at
      and not exists (
        select 1 from scheduled_run_deliveries delivery where delivery.run_id = run.run_id
      )
      and not exists (
        select 1
        from scheduled_execution_baselines baseline
        where baseline.source_run_id = run.run_id and baseline.job_id = run.job_id
      )
      and (
        (run.attempt = 0 and run.state = 'cancelled' and run.updated_at = new.terminal_at)
        or exists (
          select 1
          from scheduled_run_attempts attempt
          where attempt.run_id = run.run_id
            and attempt.job_id = run.job_id
            and attempt.attempt = run.attempt
            and attempt.fence = run.fence
            and (
              attempt.state = run.state
              or (run.state = 'failed' and attempt.state in ('preflight_rejected', 'lease_expired'))
            )
            and attempt.completed_at = new.terminal_at
        )
      )
      and new.expected_attempts_deleted = (
        select count(*) from scheduled_run_attempts item where item.run_id = run.run_id
      )
      and new.expected_late_evidence_deleted = (
        select count(*) from scheduled_run_late_evidence item where item.run_id = run.run_id
      )
  )
begin
  select raise(abort, 'scheduled run retention authority mismatch');
end;

create trigger trg_scheduled_run_retention_audit_update
before update on scheduled_run_retention_audit
when not (
  old.completed_at is null
  and new.completed_at is not null
  and new.completed_at >= old.authorized_at
  and new.operation_id is old.operation_id
  and new.run_id is old.run_id
  and new.job_id is old.job_id
  and new.job_generation is old.job_generation
  and new.schedule_generation is old.schedule_generation
  and new.run_state is old.run_state
  and new.terminal_at is old.terminal_at
  and new.cutoff_at is old.cutoff_at
  and new.authorized_at is old.authorized_at
  and new.expected_attempts_deleted is old.expected_attempts_deleted
  and new.expected_late_evidence_deleted is old.expected_late_evidence_deleted
  and new.attempts_deleted = old.expected_attempts_deleted
  and new.late_evidence_deleted = old.expected_late_evidence_deleted
  and new.deleted_rows = 1 + old.expected_attempts_deleted + old.expected_late_evidence_deleted
  and not exists (select 1 from scheduled_runs run where run.run_id = old.run_id)
  and not exists (select 1 from scheduled_run_attempts attempt where attempt.run_id = old.run_id)
  and not exists (select 1 from scheduled_run_late_evidence evidence where evidence.run_id = old.run_id)
)
begin
  select raise(abort, 'scheduled run retention audit is immutable');
end;

create trigger trg_scheduled_run_retention_audit_delete
before delete on scheduled_run_retention_audit
begin
  select raise(abort, 'scheduled run retention audit cannot be deleted');
end;

drop trigger trg_scheduled_run_late_evidence_retention_delete_guard;

create trigger trg_scheduled_run_late_evidence_retention_delete_guard
before delete on scheduled_run_late_evidence
when not exists (
  select 1
  from scheduled_run_attempts attempt
  join scheduled_delivery_retention_audit audit
    on audit.run_id = attempt.run_id and audit.job_id = attempt.job_id
  where attempt.run_id = old.run_id
    and attempt.attempt = old.attempt
    and attempt.fence = old.fence
    and audit.completed_at is null
    and not exists (
      select 1
      from scheduled_execution_baselines baseline
      where baseline.source_run_id = attempt.run_id and baseline.job_id = attempt.job_id
    )
)
and not exists (
  select 1
  from scheduled_run_attempts attempt
  join scheduled_run_retention_audit audit
    on audit.run_id = attempt.run_id and audit.job_id = attempt.job_id
  join scheduled_runs run
    on run.run_id = attempt.run_id and run.job_id = attempt.job_id
  where attempt.run_id = old.run_id
    and attempt.attempt = old.attempt
    and attempt.fence = old.fence
    and audit.completed_at is null
    and audit.run_state = run.state
    and audit.job_generation = run.job_generation
    and audit.schedule_generation = run.schedule_generation
)
begin
  select raise(abort, 'scheduled late evidence deletion requires retention authority');
end;

drop trigger trg_scheduled_run_attempt_retention_delete_guard;

create trigger trg_scheduled_run_attempt_retention_delete_guard
before delete on scheduled_run_attempts
when not exists (
  select 1
  from scheduled_delivery_retention_audit audit
  where audit.run_id = old.run_id
    and audit.job_id = old.job_id
    and audit.completed_at is null
    and not exists (
      select 1
      from scheduled_execution_baselines baseline
      where baseline.source_run_id = old.run_id and baseline.job_id = old.job_id
    )
)
and not exists (
  select 1
  from scheduled_run_retention_audit audit
  join scheduled_runs run on run.run_id = old.run_id and run.job_id = old.job_id
  where audit.run_id = old.run_id
    and audit.job_id = old.job_id
    and audit.completed_at is null
    and audit.run_state = run.state
    and audit.job_generation = run.job_generation
    and audit.schedule_generation = run.schedule_generation
)
begin
  select raise(abort, 'scheduled run attempt deletion requires retention authority');
end;

drop trigger trg_scheduled_run_retention_delete_guard;

create trigger trg_scheduled_run_retention_delete_guard
before delete on scheduled_runs
when not exists (
  select 1
  from scheduled_delivery_retention_audit audit
  where audit.run_id = old.run_id
    and audit.job_id = old.job_id
    and audit.completed_at is null
    and old.state = 'succeeded'
    and not exists (
      select 1
      from scheduled_execution_baselines baseline
      where baseline.source_run_id = old.run_id and baseline.job_id = old.job_id
    )
)
and not exists (
  select 1
  from scheduled_run_retention_audit audit
  where audit.run_id = old.run_id
    and audit.job_id = old.job_id
    and audit.completed_at is null
    and audit.run_state = old.state
    and audit.job_generation = old.job_generation
    and audit.schedule_generation = old.schedule_generation
    and old.state in ('failed', 'timed_out', 'cancelled')
    and not exists (
      select 1 from scheduled_run_deliveries delivery where delivery.run_id = old.run_id
    )
    and not exists (
      select 1
      from scheduled_execution_baselines baseline
      where baseline.source_run_id = old.run_id and baseline.job_id = old.job_id
    )
)
begin
  select raise(abort, 'scheduled run deletion requires retention authority');
end;
