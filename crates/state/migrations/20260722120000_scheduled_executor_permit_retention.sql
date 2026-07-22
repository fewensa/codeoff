alter table scheduled_execution_permit_consumptions
  add column authority_expires_at integer;

update scheduled_execution_permit_consumptions
set authority_expires_at = (
  select expires_at
  from scheduled_executor_epochs
  where scheduled_executor_epochs.authority_key = scheduled_execution_permit_consumptions.authority_key
    and scheduled_executor_epochs.deployment_epoch = scheduled_execution_permit_consumptions.deployment_epoch
);

create index idx_scheduled_execution_permit_retention
  on scheduled_execution_permit_consumptions (
    authority_expires_at,
    deployment_epoch,
    consumed_at,
    permit_id
  );

create table scheduled_execution_permit_retention_guard (
  singleton integer primary key,
  enabled integer not null,
  check (singleton = 1),
  check (enabled in (0, 1))
) strict;

insert into scheduled_execution_permit_retention_guard (singleton, enabled)
values (1, 0);

drop trigger scheduled_execution_permit_no_delete;

create trigger scheduled_execution_permit_no_delete
before delete on scheduled_execution_permit_consumptions
when coalesce(
  (select enabled from scheduled_execution_permit_retention_guard where singleton = 1),
  0
) != 1
begin
  select raise(abort, 'scheduled execution permit consumption requires retention authority');
end;

create trigger scheduled_execution_permit_retention_guard_no_delete
before delete on scheduled_execution_permit_retention_guard
begin
  select raise(abort, 'scheduled execution permit retention guard is permanent');
end;
