alter table schedules
  add column cadence_proof_version integer not null default 1
  check (cadence_proof_version = 1);

alter table schedules
  add column cadence_proof_json text not null default '{"kind":"legacy_minute_granularity","minimum_seconds":1,"occurrence_limit":100000,"policy_digest":"legacy","result":"valid","schedule_digest":"legacy","schema_version":1}'
  check (json_valid(cadence_proof_json));

drop trigger if exists trg_scheduler_operator_delivery_retry;

create trigger trg_scheduler_operator_delivery_retry
after update of state on scheduled_run_deliveries
when old.state = 'failed_retryable' and new.state = 'pending'
begin
  select case when new.updated_at != old.next_attempt_at and (
    select count(*) from scheduler_operator_actions
    where target_kind = 'delivery' and target_id = new.delivery_id and action = 'retry_delivery'
      and expected_attempt = old.attempt and expected_fence = old.fence
      and before_state = 'failed_retryable' and after_state = 'pending'
      and evidence_digest is not null and effective_at = new.updated_at
      and occurred_at <= effective_at
      and not exists (select 1 from scheduler_operator_action_consumptions consumed
        where consumed.action_id = scheduler_operator_actions.action_id)
  ) != 1 then raise(abort, 'delivery retry requires due timing or one snapshot-bound operator action') end;
  insert into scheduler_operator_action_consumptions (action_id, target_kind, target_id, consumed_at)
  select action_id, 'delivery', new.delivery_id, new.updated_at from scheduler_operator_actions
  where target_kind = 'delivery' and target_id = new.delivery_id and action = 'retry_delivery'
    and expected_attempt = old.attempt and expected_fence = old.fence
    and before_state = 'failed_retryable' and after_state = 'pending'
    and evidence_digest is not null and effective_at = new.updated_at
    and occurred_at <= effective_at
    and not exists (select 1 from scheduler_operator_action_consumptions consumed
      where consumed.action_id = scheduler_operator_actions.action_id);
end;
