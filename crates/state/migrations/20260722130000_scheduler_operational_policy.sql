create table scheduler_operational_policy_lock (
  lock_id integer primary key check (lock_id = 1),
  touched_at integer not null
);

insert into scheduler_operational_policy_lock (lock_id, touched_at) values (1, 0);

alter table schedules
  add column cadence_proof_version integer not null default 1
  check (cadence_proof_version = 1);

alter table schedules
  add column cadence_proof_json text not null default '{"kind":"legacy_minute_granularity","minimum_seconds":1,"occurrence_limit":100000,"policy_digest":"legacy","result":"valid","schedule_digest":"legacy","schema_version":1}'
  check (json_valid(cadence_proof_json));

alter table scheduled_jobs
  add column scheduler_policy_version integer not null default 1
  check (scheduler_policy_version = 1);

alter table scheduled_jobs
  add column scheduler_policy_json text not null default '{"schema_version":1,"recovery_batch_limit":32,"materialization_batch_limit":32,"occurrence_search_limit":100000,"tick_interval_ms":250,"error_backoff_ms":1000,"minimum_schedule_cadence_seconds":1,"max_active_jobs":1000000,"max_active_jobs_per_owner":1000000,"max_prompt_bytes":65536,"max_result_bytes":65536,"max_summary_bytes":65536,"run_lease_seconds":60,"run_heartbeat_interval_ms":15000,"run_timeout_seconds":1800,"run_prepare_grace_ms":5000,"run_cancellation_grace_ms":5000,"run_finalization_grace_ms":5000,"run_retry_base_seconds":30,"run_retry_max_seconds":30,"run_deadline_seconds":3600,"run_max_attempts":3,"delivery_tick_interval_ms":250,"delivery_batch_limit":32,"delivery_lease_seconds":60,"delivery_heartbeat_interval_ms":10000,"delivery_readiness_timeout_seconds":10,"delivery_send_timeout_seconds":30,"delivery_finalization_timeout_seconds":5,"delivery_max_attempts":5,"delivery_retry_base_seconds":5,"delivery_retry_max_seconds":300,"delivery_retry_after_max_seconds":3600,"delivery_deadline_seconds":3600,"delivery_readiness_retry_base_seconds":1,"delivery_readiness_retry_max_seconds":60}'
  check (json_valid(scheduler_policy_json));

alter table scheduled_runs
  add column scheduler_policy_version integer not null default 1
  check (scheduler_policy_version = 1);

alter table scheduled_runs
  add column scheduler_policy_json text not null default '{"schema_version":1,"recovery_batch_limit":32,"materialization_batch_limit":32,"occurrence_search_limit":100000,"tick_interval_ms":250,"error_backoff_ms":1000,"minimum_schedule_cadence_seconds":1,"max_active_jobs":1000000,"max_active_jobs_per_owner":1000000,"max_prompt_bytes":65536,"max_result_bytes":65536,"max_summary_bytes":65536,"run_lease_seconds":60,"run_heartbeat_interval_ms":15000,"run_timeout_seconds":1800,"run_prepare_grace_ms":5000,"run_cancellation_grace_ms":5000,"run_finalization_grace_ms":5000,"run_retry_base_seconds":30,"run_retry_max_seconds":30,"run_deadline_seconds":3600,"run_max_attempts":3,"delivery_tick_interval_ms":250,"delivery_batch_limit":32,"delivery_lease_seconds":60,"delivery_heartbeat_interval_ms":10000,"delivery_readiness_timeout_seconds":10,"delivery_send_timeout_seconds":30,"delivery_finalization_timeout_seconds":5,"delivery_max_attempts":5,"delivery_retry_base_seconds":5,"delivery_retry_max_seconds":300,"delivery_retry_after_max_seconds":3600,"delivery_deadline_seconds":3600,"delivery_readiness_retry_base_seconds":1,"delivery_readiness_retry_max_seconds":60}'
  check (json_valid(scheduler_policy_json));

alter table scheduled_run_deliveries
  add column scheduler_policy_version integer not null default 1
  check (scheduler_policy_version = 1);

alter table scheduled_run_deliveries
  add column scheduler_policy_json text not null default '{"schema_version":1,"recovery_batch_limit":32,"materialization_batch_limit":32,"occurrence_search_limit":100000,"tick_interval_ms":250,"error_backoff_ms":1000,"minimum_schedule_cadence_seconds":1,"max_active_jobs":1000000,"max_active_jobs_per_owner":1000000,"max_prompt_bytes":65536,"max_result_bytes":65536,"max_summary_bytes":65536,"run_lease_seconds":60,"run_heartbeat_interval_ms":15000,"run_timeout_seconds":1800,"run_prepare_grace_ms":5000,"run_cancellation_grace_ms":5000,"run_finalization_grace_ms":5000,"run_retry_base_seconds":30,"run_retry_max_seconds":30,"run_deadline_seconds":3600,"run_max_attempts":3,"delivery_tick_interval_ms":250,"delivery_batch_limit":32,"delivery_lease_seconds":60,"delivery_heartbeat_interval_ms":10000,"delivery_readiness_timeout_seconds":10,"delivery_send_timeout_seconds":30,"delivery_finalization_timeout_seconds":5,"delivery_max_attempts":5,"delivery_retry_base_seconds":5,"delivery_retry_max_seconds":300,"delivery_retry_after_max_seconds":3600,"delivery_deadline_seconds":3600,"delivery_readiness_retry_base_seconds":1,"delivery_readiness_retry_max_seconds":60}'
  check (json_valid(scheduler_policy_json));

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
