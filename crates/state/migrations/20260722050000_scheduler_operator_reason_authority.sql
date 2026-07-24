drop trigger trg_scheduler_operator_reason_insert_authority;

create trigger trg_scheduler_operator_reason_insert_authority
before insert on scheduler_operator_actions
when coalesce((
  (new.action in ('retry_run', 'force_delivery_resend')
    and new.reason_schema_version = 1
    and new.reason_hash_algorithm = 'sha256-v1'
    and new.reason_json is not null
    and new.reason_digest is not null
    and length(cast(new.reason_json as blob)) between 1 and 65536
    and json_valid(new.reason_json)
    and json_extract(new.reason_json, '$.schema_version') = 1
    and json_type(new.reason_json, '$.reason_code') = 'text'
    and length(json_extract(new.reason_json, '$.reason_code')) between 1 and 64
    and json_extract(new.reason_json, '$.reason_code') not glob '*[^a-z0-9_]*'
    and json_type(new.reason_json, '$.reason') = 'text'
    and length(cast(json_extract(new.reason_json, '$.reason') as blob)) between 1 and 4096
    and trim(json_extract(new.reason_json, '$.reason')) = json_extract(new.reason_json, '$.reason')
    and (select count(*) from json_each(new.reason_json)) = 3
    and length(new.reason_digest) = 64
    and new.reason_digest not glob '*[^0-9a-f]*')
  or (new.action not in ('retry_run', 'force_delivery_resend')
    and new.reason_schema_version = 0
    and new.reason_hash_algorithm is null
    and new.reason_json is null
    and new.reason_digest is null)
), 0) = 0
begin
  select raise(abort, 'operator action reason authority is invalid');
end;

drop trigger trg_scheduler_operator_run_retry;

create trigger trg_scheduler_operator_run_retry
after update of state on scheduled_runs
when old.state in ('failed', 'timed_out', 'cancelled') and new.state = 'pending'
begin
  select case when (
    select count(*) from scheduler_operator_actions
    where target_kind = 'run' and target_id = new.run_id and action = 'retry_run'
      and expected_attempt = old.attempt and expected_fence = old.fence
      and before_state = old.state and after_state = 'pending'
      and effective_at = new.next_attempt_at and occurred_at = new.updated_at
      and reason_schema_version = 1 and reason_hash_algorithm = 'sha256-v1'
      and reason_json is not null and reason_digest is not null
      and not exists (select 1 from scheduler_operator_action_consumptions consumed
        where consumed.action_id = scheduler_operator_actions.action_id)
  ) != 1 then raise(abort, 'manual run retry requires one reason-bound operator action') end;
  insert into scheduler_operator_action_consumptions (action_id, target_kind, target_id, consumed_at)
  select action_id, 'run', new.run_id, new.updated_at from scheduler_operator_actions
  where target_kind = 'run' and target_id = new.run_id and action = 'retry_run'
    and expected_attempt = old.attempt and expected_fence = old.fence
    and before_state = old.state and after_state = 'pending'
    and effective_at = new.next_attempt_at and occurred_at = new.updated_at
    and reason_schema_version = 1 and reason_hash_algorithm = 'sha256-v1'
    and reason_json is not null and reason_digest is not null
    and not exists (select 1 from scheduler_operator_action_consumptions consumed
      where consumed.action_id = scheduler_operator_actions.action_id);
end;
