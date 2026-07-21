create table schedule_mutation_audit (
  audit_id text primary key,
  principal_kind text,
  principal_provider text,
  principal_tenant text,
  principal_subject text,
  operation text not null,
  job_id text,
  request_id text not null,
  outcome text not null,
  decision text not null,
  reason text,
  error_code text,
  old_generation integer,
  new_generation integer,
  resolver_provider text,
  target_kind text,
  resolver_version integer,
  resolver_digest text,
  capability_version integer,
  capability_digest text,
  idempotency_outcome text,
  latency_ms integer not null,
  correlation_id text not null,
  occurred_at integer not null,
  check (length(audit_id) between 1 and 255),
  check ((principal_kind is null and principal_provider is null and principal_tenant is null and principal_subject is null)
    or (length(principal_kind) > 0 and length(principal_provider) > 0 and length(principal_tenant) > 0 and length(principal_subject) > 0)),
  check (operation in ('create', 'get', 'list', 'update', 'pause', 'resume', 'delete')),
  check (length(request_id) between 1 and 255),
  check (outcome in ('applied', 'replay', 'conflict', 'in_progress', 'denied', 'validation', 'resolver', 'capability', 'storage')),
  check (decision in ('allow', 'deny', 'error')),
  check (latency_ms >= 0 and length(correlation_id) between 1 and 255)
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
