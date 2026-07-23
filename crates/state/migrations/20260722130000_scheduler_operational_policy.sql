create table scheduler_operational_policy_lock (
  lock_id integer primary key check (lock_id = 1),
  touched_at integer not null
);

insert into scheduler_operational_policy_lock (lock_id, touched_at) values (1, 0);

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
