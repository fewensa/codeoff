drop trigger trg_scheduler_metrics_validation_failure;
drop trigger trg_scheduler_metrics_late_evidence_stale_fence;

create table scheduler_transition_cursors (
  kind text not null,
  entity_id text not null,
  cursor_value integer not null,
  primary key (kind, entity_id),
  check (kind = 'overlap_suppressed'),
  check (length(entity_id) between 1 and 255),
  check (cursor_value >= 0)
);

create table scheduler_metric_request_decisions (
  kind text not null,
  principal_kind text not null,
  principal_provider text not null,
  principal_tenant text not null,
  principal_subject text not null,
  operation text not null,
  request_id text not null,
  primary key (
    kind,
    principal_kind,
    principal_provider,
    principal_tenant,
    principal_subject,
    operation,
    request_id
  ),
  check (kind = 'policy_limit_rejected'),
  check (length(principal_kind) between 1 and 255),
  check (length(principal_provider) between 1 and 255),
  check (length(principal_tenant) between 1 and 255),
  check (length(principal_subject) between 1 and 255),
  check (operation in ('create', 'get', 'list', 'update', 'pause', 'resume', 'delete')),
  check (length(request_id) between 1 and 255)
);

alter table scheduled_runs
  add column telemetry_counter_limit_recorded integer not null default 0
  check (telemetry_counter_limit_recorded in (0, 1));

alter table scheduled_run_deliveries
  add column telemetry_counter_limit_recorded integer not null default 0
  check (telemetry_counter_limit_recorded in (0, 1));

create trigger trg_scheduler_metrics_run_policy_limit
after update of state on scheduled_runs
when old.state != new.state
  and new.state = 'failed'
  and new.error_kind in ('run_deadline_exceeded', 'run_retry_exhausted')
begin
  update scheduler_transition_totals
    set value = case when value < 9223372036854775807 then value + 1 else value end
    where kind = 'policy_limit_rejected';
end;

create trigger trg_scheduler_metrics_delivery_policy_limit
after update of state on scheduled_run_deliveries
when old.state != new.state
  and new.state = 'failed_terminal'
  and new.error_kind in ('delivery_deadline_exceeded', 'delivery_retry_exhausted')
begin
  update scheduler_transition_totals
    set value = case when value < 9223372036854775807 then value + 1 else value end
    where kind = 'policy_limit_rejected';
end;

create trigger trg_scheduler_metrics_request_policy_limit
after insert on schedule_mutation_audit
when new.error_code in ('active_job_limit_exceeded', 'policy_limit_rejected')
  and new.principal_kind is not null
  and new.principal_provider is not null
  and new.principal_tenant is not null
  and new.principal_subject is not null
  and not exists (
    select 1 from scheduler_metric_request_decisions decision
    where decision.kind = 'policy_limit_rejected'
      and decision.principal_kind = new.principal_kind
      and decision.principal_provider = new.principal_provider
      and decision.principal_tenant = new.principal_tenant
      and decision.principal_subject = new.principal_subject
      and decision.operation = new.operation
      and decision.request_id = new.request_id
  )
begin
  update scheduler_transition_totals
    set value = case when value < 9223372036854775807 then value + 1 else value end
    where kind = 'policy_limit_rejected';
  insert into scheduler_metric_request_decisions (
    kind,
    principal_kind,
    principal_provider,
    principal_tenant,
    principal_subject,
    operation,
    request_id
  ) values (
    'policy_limit_rejected',
    new.principal_kind,
    new.principal_provider,
    new.principal_tenant,
    new.principal_subject,
    new.operation,
    new.request_id
  );
end;
