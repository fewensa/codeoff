drop trigger trg_scheduled_delivery_retention_ledger_delete;

delete from scheduled_delivery_retention_ledger
where completed_at is null
  and exists (
    select 1
    from scheduled_delivery_retention_audit audit
    where audit.delivery_id = scheduled_delivery_retention_ledger.delivery_id
      and audit.operation_id = scheduled_delivery_retention_ledger.operation_id
      and audit.run_id = scheduled_delivery_retention_ledger.run_id
      and audit.job_id = scheduled_delivery_retention_ledger.job_id
      and (
        audit.job_generation is null
        or audit.schedule_generation is null
        or audit.run_terminal_at is null
        or audit.run_cutoff_at is null
        or audit.delivery_cutoff_at is null
        or audit.expected_deliveries_deleted is null
        or audit.expected_delivery_attempts_deleted is null
        or audit.expected_run_attempts_deleted is null
        or audit.expected_late_evidence_deleted is null
        or audit.expected_result_artifacts_deleted is null
        or audit.expected_runs_deleted is null
      )
  );

create trigger trg_scheduled_delivery_retention_ledger_delete
before delete on scheduled_delivery_retention_ledger
begin
  select raise(abort, 'scheduled delivery retention ledger cannot be deleted');
end;

create trigger trg_scheduled_delivery_retention_audit_null_safe_insert
before insert on scheduled_delivery_retention_audit
when new.job_generation is null
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
begin
  select raise(abort, 'scheduled delivery retention audit requires canonical nonnull authority');
end;

create trigger trg_scheduled_delivery_retention_audit_null_safe_update
before update on scheduled_delivery_retention_audit
when old.job_generation is null
  or old.schedule_generation is null
  or old.run_terminal_at is null
  or old.run_cutoff_at is null
  or old.delivery_cutoff_at is null
  or old.expected_deliveries_deleted is null
  or old.expected_delivery_attempts_deleted is null
  or old.expected_run_attempts_deleted is null
  or old.expected_late_evidence_deleted is null
  or old.expected_result_artifacts_deleted is null
  or old.expected_runs_deleted is null
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
begin
  select raise(abort, 'legacy nullable scheduled delivery retention audit is historical');
end;

create trigger trg_scheduled_delivery_retention_ledger_null_safe_insert
before insert on scheduled_delivery_retention_ledger
when 1 != (
  select count(*)
  from scheduled_delivery_retention_audit audit
  where audit.delivery_id = new.delivery_id
    and audit.operation_id = new.operation_id
    and audit.run_id = new.run_id
    and audit.job_id = new.job_id
    and audit.authorized_at is new.claimed_at
    and audit.completed_at is null
    and audit.job_generation is not null
    and audit.schedule_generation is not null
    and audit.run_terminal_at is not null
    and audit.run_cutoff_at is not null
    and audit.delivery_cutoff_at is not null
    and audit.expected_deliveries_deleted is not null
    and audit.expected_delivery_attempts_deleted is not null
    and audit.expected_run_attempts_deleted is not null
    and audit.expected_late_evidence_deleted is not null
    and audit.expected_result_artifacts_deleted is not null
    and audit.expected_runs_deleted is not null
)
begin
  select raise(abort, 'scheduled delivery retention ledger requires nonnull audit authority');
end;

drop trigger trg_scheduled_delivery_retention_ledger_update;

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
  and 1 = (
    select count(*)
    from scheduled_delivery_retention_audit audit
    where audit.delivery_id = old.delivery_id
      and audit.operation_id = old.operation_id
      and audit.run_id = old.run_id
      and audit.job_id = old.job_id
      and audit.completed_at is new.completed_at
      and audit.job_generation is not null
      and audit.schedule_generation is not null
      and audit.run_terminal_at is not null
      and audit.run_cutoff_at is not null
      and audit.delivery_cutoff_at is not null
      and audit.expected_deliveries_deleted is not null
      and audit.expected_delivery_attempts_deleted is not null
      and audit.expected_run_attempts_deleted is not null
      and audit.expected_late_evidence_deleted is not null
      and audit.expected_result_artifacts_deleted is not null
      and audit.expected_runs_deleted is not null
      and audit.attempts_deleted is audit.expected_delivery_attempts_deleted
      and audit.deliveries_deleted is audit.expected_deliveries_deleted
      and audit.run_attempts_deleted is audit.expected_run_attempts_deleted
      and audit.late_evidence_deleted is audit.expected_late_evidence_deleted
      and audit.result_artifacts_deleted is audit.expected_result_artifacts_deleted
      and audit.runs_deleted is audit.expected_runs_deleted
  )
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
  select raise(abort, 'scheduled delivery retention ledger is immutable');
end;

create trigger trg_scheduled_delivery_retention_delete_null_safe_guard
before delete on scheduled_run_deliveries
when not exists (
  select 1
  from scheduled_delivery_retention_audit audit
  join scheduled_delivery_retention_ledger ledger
    on ledger.delivery_id = audit.delivery_id
    and ledger.operation_id = audit.operation_id
    and ledger.run_id = audit.run_id
    and ledger.job_id = audit.job_id
  where audit.delivery_id = old.delivery_id
    and audit.run_id = old.run_id
    and audit.job_id = old.job_id
    and audit.delivery_state = old.state
    and audit.payload_digest = old.payload_digest
    and audit.completed_at is null
    and ledger.completed_at is null
    and audit.job_generation is not null
    and audit.schedule_generation is not null
    and audit.run_terminal_at is not null
    and audit.run_cutoff_at is not null
    and audit.delivery_cutoff_at is not null
    and audit.expected_deliveries_deleted is not null
    and audit.expected_delivery_attempts_deleted is not null
    and audit.expected_run_attempts_deleted is not null
    and audit.expected_late_evidence_deleted is not null
    and audit.expected_result_artifacts_deleted is not null
    and audit.expected_runs_deleted is not null
)
begin
  select raise(abort, 'scheduled delivery deletion requires nonnull retention authority');
end;

create trigger trg_scheduled_delivery_attempt_retention_delete_null_safe_guard
before delete on scheduled_delivery_attempts
when not exists (
  select 1
  from scheduled_run_deliveries delivery
  join scheduled_delivery_retention_audit audit
    on audit.delivery_id = delivery.delivery_id
    and audit.run_id = delivery.run_id
    and audit.job_id = delivery.job_id
    and audit.delivery_state = delivery.state
    and audit.payload_digest = delivery.payload_digest
  join scheduled_delivery_retention_ledger ledger
    on ledger.delivery_id = audit.delivery_id
    and ledger.operation_id = audit.operation_id
    and ledger.run_id = audit.run_id
    and ledger.job_id = audit.job_id
  where delivery.delivery_id = old.delivery_id
    and audit.completed_at is null
    and ledger.completed_at is null
    and audit.job_generation is not null
    and audit.schedule_generation is not null
    and audit.run_terminal_at is not null
    and audit.run_cutoff_at is not null
    and audit.delivery_cutoff_at is not null
    and audit.expected_deliveries_deleted is not null
    and audit.expected_delivery_attempts_deleted is not null
    and audit.expected_run_attempts_deleted is not null
    and audit.expected_late_evidence_deleted is not null
    and audit.expected_result_artifacts_deleted is not null
    and audit.expected_runs_deleted is not null
)
begin
  select raise(abort, 'scheduled delivery attempt deletion requires nonnull retention authority');
end;

create trigger trg_scheduled_run_result_artifacts_retention_delete_null_safe_guard
before delete on scheduled_run_result_artifacts
when exists (
  select 1 from scheduled_runs run
  where run.run_id = old.run_id and run.job_id = old.job_id and run.state = 'succeeded'
)
and not exists (
  select 1
  from scheduled_runs run
  join scheduled_delivery_retention_ledger ledger
    on ledger.run_id = run.run_id and ledger.job_id = run.job_id
  join scheduled_delivery_retention_audit audit
    on audit.delivery_id = ledger.delivery_id
    and audit.operation_id = ledger.operation_id
    and audit.run_id = ledger.run_id
    and audit.job_id = ledger.job_id
  where run.run_id = old.run_id
    and run.job_id = old.job_id
    and run.result_artifact_id = old.artifact_id
    and audit.completed_at is null
    and ledger.completed_at is null
    and audit.job_generation is not null
    and audit.schedule_generation is not null
    and audit.run_terminal_at is not null
    and audit.run_cutoff_at is not null
    and audit.delivery_cutoff_at is not null
    and audit.expected_deliveries_deleted is not null
    and audit.expected_delivery_attempts_deleted is not null
    and audit.expected_run_attempts_deleted is not null
    and audit.expected_late_evidence_deleted is not null
    and audit.expected_result_artifacts_deleted is not null
    and audit.expected_runs_deleted is not null
    and audit.expected_deliveries_deleted is (
      select count(*) from scheduled_delivery_retention_ledger item where item.run_id = run.run_id
    )
    and not exists (
      select 1 from scheduled_delivery_retention_ledger item
      where item.run_id = run.run_id
        and not exists (
          select 1 from scheduled_delivery_retention_audit authority
          where authority.delivery_id = item.delivery_id
            and authority.operation_id = item.operation_id
            and authority.run_id = item.run_id
            and authority.job_id = item.job_id
            and authority.completed_at is null
            and authority.job_generation is not null
            and authority.schedule_generation is not null
            and authority.run_terminal_at is not null
            and authority.run_cutoff_at is not null
            and authority.delivery_cutoff_at is not null
            and authority.expected_deliveries_deleted is not null
            and authority.expected_delivery_attempts_deleted is not null
            and authority.expected_run_attempts_deleted is not null
            and authority.expected_late_evidence_deleted is not null
            and authority.expected_result_artifacts_deleted is not null
            and authority.expected_runs_deleted is not null
        )
    )
)
begin
  select raise(abort, 'scheduled result deletion requires nonnull retention authority');
end;

create trigger trg_scheduled_run_late_evidence_retention_delete_null_safe_guard
before delete on scheduled_run_late_evidence
when exists (
  select 1
  from scheduled_run_attempts attempt
  join scheduled_runs run on run.run_id = attempt.run_id and run.job_id = attempt.job_id
  where attempt.run_id = old.run_id
    and attempt.attempt = old.attempt
    and attempt.fence = old.fence
    and run.state = 'succeeded'
)
and not exists (
  select 1
  from scheduled_run_attempts attempt
  join scheduled_delivery_retention_ledger ledger
    on ledger.run_id = attempt.run_id and ledger.job_id = attempt.job_id
  join scheduled_delivery_retention_audit audit
    on audit.delivery_id = ledger.delivery_id
    and audit.operation_id = ledger.operation_id
    and audit.run_id = ledger.run_id
    and audit.job_id = ledger.job_id
  where attempt.run_id = old.run_id
    and attempt.attempt = old.attempt
    and attempt.fence = old.fence
    and audit.completed_at is null
    and ledger.completed_at is null
    and audit.job_generation is not null
    and audit.schedule_generation is not null
    and audit.run_terminal_at is not null
    and audit.run_cutoff_at is not null
    and audit.delivery_cutoff_at is not null
    and audit.expected_deliveries_deleted is not null
    and audit.expected_delivery_attempts_deleted is not null
    and audit.expected_run_attempts_deleted is not null
    and audit.expected_late_evidence_deleted is not null
    and audit.expected_result_artifacts_deleted is not null
    and audit.expected_runs_deleted is not null
    and audit.expected_deliveries_deleted is (
      select count(*) from scheduled_delivery_retention_ledger item where item.run_id = attempt.run_id
    )
    and not exists (
      select 1 from scheduled_delivery_retention_ledger item
      where item.run_id = attempt.run_id
        and not exists (
          select 1 from scheduled_delivery_retention_audit authority
          where authority.delivery_id = item.delivery_id
            and authority.operation_id = item.operation_id
            and authority.run_id = item.run_id
            and authority.job_id = item.job_id
            and authority.completed_at is null
            and authority.job_generation is not null
            and authority.schedule_generation is not null
            and authority.run_terminal_at is not null
            and authority.run_cutoff_at is not null
            and authority.delivery_cutoff_at is not null
            and authority.expected_deliveries_deleted is not null
            and authority.expected_delivery_attempts_deleted is not null
            and authority.expected_run_attempts_deleted is not null
            and authority.expected_late_evidence_deleted is not null
            and authority.expected_result_artifacts_deleted is not null
            and authority.expected_runs_deleted is not null
        )
    )
)
begin
  select raise(abort, 'scheduled late evidence deletion requires nonnull retention authority');
end;

create trigger trg_scheduled_run_attempt_retention_delete_null_safe_guard
before delete on scheduled_run_attempts
when exists (
  select 1 from scheduled_runs run
  where run.run_id = old.run_id and run.job_id = old.job_id and run.state = 'succeeded'
)
and not exists (
  select 1
  from scheduled_delivery_retention_ledger ledger
  join scheduled_delivery_retention_audit audit
    on audit.delivery_id = ledger.delivery_id
    and audit.operation_id = ledger.operation_id
    and audit.run_id = ledger.run_id
    and audit.job_id = ledger.job_id
  where ledger.run_id = old.run_id
    and ledger.job_id = old.job_id
    and audit.completed_at is null
    and ledger.completed_at is null
    and audit.job_generation is not null
    and audit.schedule_generation is not null
    and audit.run_terminal_at is not null
    and audit.run_cutoff_at is not null
    and audit.delivery_cutoff_at is not null
    and audit.expected_deliveries_deleted is not null
    and audit.expected_delivery_attempts_deleted is not null
    and audit.expected_run_attempts_deleted is not null
    and audit.expected_late_evidence_deleted is not null
    and audit.expected_result_artifacts_deleted is not null
    and audit.expected_runs_deleted is not null
    and audit.expected_deliveries_deleted is (
      select count(*) from scheduled_delivery_retention_ledger item where item.run_id = old.run_id
    )
    and not exists (
      select 1 from scheduled_delivery_retention_ledger item
      where item.run_id = old.run_id
        and not exists (
          select 1 from scheduled_delivery_retention_audit authority
          where authority.delivery_id = item.delivery_id
            and authority.operation_id = item.operation_id
            and authority.run_id = item.run_id
            and authority.job_id = item.job_id
            and authority.completed_at is null
            and authority.job_generation is not null
            and authority.schedule_generation is not null
            and authority.run_terminal_at is not null
            and authority.run_cutoff_at is not null
            and authority.delivery_cutoff_at is not null
            and authority.expected_deliveries_deleted is not null
            and authority.expected_delivery_attempts_deleted is not null
            and authority.expected_run_attempts_deleted is not null
            and authority.expected_late_evidence_deleted is not null
            and authority.expected_result_artifacts_deleted is not null
            and authority.expected_runs_deleted is not null
        )
    )
)
begin
  select raise(abort, 'scheduled run attempt deletion requires nonnull retention authority');
end;

create trigger trg_scheduled_run_retention_delete_null_safe_guard
before delete on scheduled_runs
when old.state = 'succeeded'
  and not exists (
    select 1
    from scheduled_delivery_retention_ledger ledger
    join scheduled_delivery_retention_audit audit
      on audit.delivery_id = ledger.delivery_id
      and audit.operation_id = ledger.operation_id
      and audit.run_id = ledger.run_id
      and audit.job_id = ledger.job_id
    where ledger.run_id = old.run_id
      and ledger.job_id = old.job_id
      and audit.completed_at is null
      and ledger.completed_at is null
      and audit.job_generation is not null
      and audit.schedule_generation is not null
      and audit.run_terminal_at is not null
      and audit.run_cutoff_at is not null
      and audit.delivery_cutoff_at is not null
      and audit.expected_deliveries_deleted is not null
      and audit.expected_delivery_attempts_deleted is not null
      and audit.expected_run_attempts_deleted is not null
      and audit.expected_late_evidence_deleted is not null
      and audit.expected_result_artifacts_deleted is not null
      and audit.expected_runs_deleted is not null
      and audit.expected_deliveries_deleted is (
        select count(*) from scheduled_delivery_retention_ledger item where item.run_id = old.run_id
      )
      and not exists (
        select 1 from scheduled_delivery_retention_ledger item
        where item.run_id = old.run_id
          and not exists (
            select 1 from scheduled_delivery_retention_audit authority
            where authority.delivery_id = item.delivery_id
              and authority.operation_id = item.operation_id
              and authority.run_id = item.run_id
              and authority.job_id = item.job_id
              and authority.completed_at is null
              and authority.job_generation is not null
              and authority.schedule_generation is not null
              and authority.run_terminal_at is not null
              and authority.run_cutoff_at is not null
              and authority.delivery_cutoff_at is not null
              and authority.expected_deliveries_deleted is not null
              and authority.expected_delivery_attempts_deleted is not null
              and authority.expected_run_attempts_deleted is not null
              and authority.expected_late_evidence_deleted is not null
              and authority.expected_result_artifacts_deleted is not null
              and authority.expected_runs_deleted is not null
          )
      )
  )
begin
  select raise(abort, 'scheduled run deletion requires nonnull retention authority');
end;
