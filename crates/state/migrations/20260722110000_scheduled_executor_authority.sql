create table scheduled_executor_epochs (
  authority_key text primary key,
  schema_version integer not null,
  deployment_epoch integer not null,
  attestation_id text not null,
  attestation_digest text not null,
  profile_digest text not null,
  issued_at integer not null,
  expires_at integer not null,
  registered_at integer not null,
  check (authority_key = 'scheduled-codex-v1'),
  check (schema_version = 1),
  check (deployment_epoch > 0),
  check (length(attestation_id) = 64 and attestation_id = lower(attestation_id)),
  check (length(attestation_digest) = 64 and attestation_digest = lower(attestation_digest)),
  check (length(profile_digest) = 64 and profile_digest = lower(profile_digest)),
  check (issued_at > 0 and expires_at > issued_at and registered_at > 0)
) strict;

create table scheduled_execution_permit_consumptions (
  permit_id text primary key,
  schema_version integer not null,
  authority_key text not null,
  deployment_epoch integer not null,
  attestation_id text not null,
  profile_digest text not null,
  run_id text not null,
  job_id text not null,
  attempt integer not null,
  fence integer not null,
  authority_digest text not null,
  nonce text not null,
  consumed_at integer not null,
  foreign key (authority_key) references scheduled_executor_epochs(authority_key),
  unique (run_id, attempt, fence),
  unique (deployment_epoch, nonce),
  check (schema_version = 1),
  check (authority_key = 'scheduled-codex-v1'),
  check (deployment_epoch > 0 and attempt > 0 and fence > 0 and consumed_at > 0),
  check (length(attestation_id) = 64 and attestation_id = lower(attestation_id)),
  check (length(profile_digest) = 64 and profile_digest = lower(profile_digest)),
  check (length(authority_digest) = 64 and authority_digest = lower(authority_digest)),
  check (length(nonce) = 64 and nonce = lower(nonce)),
  check (length(permit_id) = 64 and permit_id = lower(permit_id)),
  check (length(run_id) > 0 and length(job_id) > 0)
) strict;

create trigger scheduled_executor_epoch_no_delete
before delete on scheduled_executor_epochs
begin
  select raise(abort, 'scheduled executor epoch authority is append-only');
end;

create trigger scheduled_execution_permit_no_update
before update on scheduled_execution_permit_consumptions
begin
  select raise(abort, 'scheduled execution permit consumption is immutable');
end;

create trigger scheduled_execution_permit_no_delete
before delete on scheduled_execution_permit_consumptions
begin
  select raise(abort, 'scheduled execution permit consumption is append-only');
end;
