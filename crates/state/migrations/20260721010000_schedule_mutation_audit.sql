create table schedule_mutation_audit (
  audit_id text primary key,
  principal_kind text not null,
  principal_provider text not null,
  principal_tenant text not null,
  principal_subject text not null,
  operation text not null,
  job_id text not null references scheduled_jobs(job_id) on delete restrict,
  request_id text not null,
  outcome text not null,
  occurred_at integer not null,
  check (length(audit_id) between 1 and 255),
  check (length(principal_kind) > 0 and length(principal_provider) > 0 and length(principal_tenant) > 0 and length(principal_subject) > 0),
  check (operation in ('create', 'update', 'pause', 'resume', 'delete')),
  check (length(request_id) between 1 and 255),
  check (outcome = 'applied')
);

create index idx_schedule_mutation_audit_principal
  on schedule_mutation_audit (
    principal_kind,
    principal_provider,
    principal_tenant,
    principal_subject,
    occurred_at,
    audit_id
  );
