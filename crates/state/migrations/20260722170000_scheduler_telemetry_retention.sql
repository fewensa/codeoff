drop trigger trg_scheduler_metrics_request_policy_limit;
drop table scheduler_metric_request_decisions;

create trigger trg_scheduler_metrics_request_policy_limit
after insert on schedule_mutation_audit
when new.error_code in ('active_job_limit_exceeded', 'policy_limit_rejected')
begin
  update scheduler_transition_totals
    set value = case when value < 9223372036854775807 then value + 1 else value end
    where kind = 'policy_limit_rejected';
end;

alter table scheduler_transition_cursors
  rename to scheduler_transition_cursors_unbounded;

create table scheduler_transition_cursors (
  kind text not null,
  job_id text not null references scheduled_jobs(job_id) on delete cascade,
  job_generation integer not null,
  cursor_value integer not null,
  created_at integer not null,
  updated_at integer not null,
  primary key (kind, job_id),
  check (kind = 'overlap_suppressed'),
  check (length(job_id) between 1 and 255),
  check (job_generation >= 0),
  check (cursor_value >= 0),
  check (created_at >= 0 and updated_at >= created_at)
);

insert into scheduler_transition_cursors (
  kind,
  job_id,
  job_generation,
  cursor_value,
  created_at,
  updated_at
)
select
  cursor.kind,
  cursor.entity_id,
  job.generation,
  cursor.cursor_value,
  max(cursor.cursor_value, job.updated_at),
  max(cursor.cursor_value, job.updated_at)
from scheduler_transition_cursors_unbounded cursor
join scheduled_jobs job on job.job_id = cursor.entity_id;

drop table scheduler_transition_cursors_unbounded;

create index idx_scheduler_transition_cursors_updated
  on scheduler_transition_cursors (updated_at, job_id);

create index idx_scheduled_jobs_transition_cursor_retention
  on scheduled_jobs (coalesce(deleted_at, updated_at), job_id)
  where status in ('completed', 'deleted');
