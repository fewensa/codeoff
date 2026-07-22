create table scheduled_delivery_retention_ledger (
  delivery_id text primary key,
  operation_id text not null,
  run_id text not null,
  job_id text not null references scheduled_jobs(job_id) on delete restrict,
  claimed_at integer not null,
  completed_at integer,
  check (length(operation_id) > 0 and length(delivery_id) > 0 and length(run_id) > 0),
  check (claimed_at >= 0 and (completed_at is null or completed_at >= claimed_at))
);

insert into scheduled_delivery_retention_ledger (
  delivery_id, operation_id, run_id, job_id, claimed_at, completed_at
)
select
  delivery_id,
  min(operation_id),
  min(run_id),
  min(job_id),
  min(authorized_at),
  case when count(completed_at) = count(*) then max(completed_at) end
from scheduled_delivery_retention_audit
group by delivery_id;

create trigger trg_scheduled_delivery_retention_ledger_update
before update on scheduled_delivery_retention_ledger
when not (
  old.completed_at is null
  and new.completed_at is not null
  and new.completed_at >= old.claimed_at
  and new.delivery_id is old.delivery_id
  and new.operation_id is old.operation_id
  and new.run_id is old.run_id
  and new.job_id is old.job_id
  and new.claimed_at is old.claimed_at
  and not exists (
    select 1 from scheduled_delivery_retention_audit audit
    where audit.delivery_id = old.delivery_id
      and (audit.completed_at is null or audit.completed_at > new.completed_at)
  )
)
begin
  select raise(abort, 'scheduled delivery retention ledger is immutable');
end;

create trigger trg_scheduled_delivery_retention_ledger_delete
before delete on scheduled_delivery_retention_ledger
begin
  select raise(abort, 'scheduled delivery retention ledger cannot be deleted');
end;

alter table scheduled_delivery_retention_audit add column expected_deliveries_deleted integer;
alter table scheduled_delivery_retention_audit add column expected_delivery_attempts_deleted integer;
alter table scheduled_delivery_retention_audit add column expected_run_attempts_deleted integer;
alter table scheduled_delivery_retention_audit add column expected_late_evidence_deleted integer;
alter table scheduled_delivery_retention_audit add column expected_result_artifacts_deleted integer;
alter table scheduled_delivery_retention_audit add column expected_runs_deleted integer;
alter table scheduled_delivery_retention_audit add column deliveries_deleted integer not null default 0;
alter table scheduled_delivery_retention_audit add column run_attempts_deleted integer not null default 0;
alter table scheduled_delivery_retention_audit add column late_evidence_deleted integer not null default 0;
alter table scheduled_delivery_retention_audit add column result_artifacts_deleted integer not null default 0;
alter table scheduled_delivery_retention_audit add column runs_deleted integer not null default 0;

drop trigger trg_scheduled_delivery_retention_audit_acceptance;

create trigger trg_scheduled_delivery_retention_audit_acceptance
before insert on scheduled_delivery_retention_audit
when new.completed_at is not null
  or new.attempts_deleted != 0
  or new.deliveries_deleted != 0
  or new.run_attempts_deleted != 0
  or new.late_evidence_deleted != 0
  or new.result_artifacts_deleted != 0
  or new.runs_deleted != 0
  or new.job_generation is null
  or new.schedule_generation is null
  or new.run_terminal_at is null
  or new.run_cutoff_at is null
  or new.delivery_cutoff_at is null
  or new.expected_deliveries_deleted is null
  or new.expected_delivery_attempts_deleted is null
  or new.expected_run_attempts_deleted is null
  or new.expected_late_evidence_deleted is null
  or new.expected_result_artifacts_deleted is null
  or new.expected_runs_deleted is null
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
    join scheduled_delivery_retention_ledger ledger
      on ledger.delivery_id = delivery.delivery_id
      and ledger.operation_id = new.operation_id
      and ledger.run_id = run.run_id and ledger.job_id = run.job_id
      and ledger.completed_at is null
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
      and new.expected_deliveries_deleted = (
        select count(*) from scheduled_run_deliveries item where item.run_id = run.run_id
      )
      and new.expected_delivery_attempts_deleted = (
        select count(*) from scheduled_delivery_attempts item
        where item.delivery_id in (
          select target.delivery_id from scheduled_run_deliveries target where target.run_id = run.run_id
        )
      )
      and new.expected_run_attempts_deleted = (
        select count(*) from scheduled_run_attempts item where item.run_id = run.run_id
      )
      and new.expected_late_evidence_deleted = (
        select count(*) from scheduled_run_late_evidence item where item.run_id = run.run_id
      )
      and new.expected_result_artifacts_deleted = (
        select count(*) from scheduled_run_result_artifacts item where item.run_id = run.run_id
      )
      and new.expected_runs_deleted = 1
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
  and new.expected_deliveries_deleted is old.expected_deliveries_deleted
  and new.expected_delivery_attempts_deleted is old.expected_delivery_attempts_deleted
  and new.expected_run_attempts_deleted is old.expected_run_attempts_deleted
  and new.expected_late_evidence_deleted is old.expected_late_evidence_deleted
  and new.expected_result_artifacts_deleted is old.expected_result_artifacts_deleted
  and new.expected_runs_deleted is old.expected_runs_deleted
  and new.attempts_deleted = old.expected_delivery_attempts_deleted
  and new.deliveries_deleted = old.expected_deliveries_deleted
  and new.run_attempts_deleted = old.expected_run_attempts_deleted
  and new.late_evidence_deleted = old.expected_late_evidence_deleted
  and new.result_artifacts_deleted = old.expected_result_artifacts_deleted
  and new.runs_deleted = old.expected_runs_deleted
  and not exists (select 1 from scheduled_runs run where run.run_id = old.run_id)
  and not exists (select 1 from scheduled_run_deliveries delivery where delivery.run_id = old.run_id)
  and not exists (
    select 1 from scheduled_delivery_attempts attempt
    join scheduled_delivery_retention_ledger ledger on ledger.delivery_id = attempt.delivery_id
    where ledger.run_id = old.run_id
  )
  and not exists (select 1 from scheduled_run_attempts attempt where attempt.run_id = old.run_id)
  and not exists (select 1 from scheduled_run_late_evidence evidence where evidence.run_id = old.run_id)
  and not exists (select 1 from scheduled_run_result_artifacts artifact where artifact.run_id = old.run_id)
)
begin
  select raise(abort, 'scheduled delivery retention audit is immutable');
end;
