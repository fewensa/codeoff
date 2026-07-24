create table scheduler_transition_totals (
  kind text primary key,
  value integer not null default 0,
  check (kind in (
    'occurrences_materialized',
    'misfire_coalesced_skipped',
    'overlap_suppressed',
    'run_claimed',
    'run_completed',
    'run_failed',
    'run_timed_out',
    'run_cancelled',
    'run_outcome_unknown',
    'run_observe_only_reexecution',
    'run_lease_reclaimed',
    'stale_fence_rejected',
    'policy_limit_rejected',
    'delivery_claimed',
    'delivery_delivered',
    'delivery_retry',
    'delivery_failure',
    'delivery_unknown',
    'delivery_skipped',
    'delivery_forced_unknown_resend',
    'execution_baseline_advanced',
    'accepted_delivery_baseline_advanced',
    'profile_validation_failed',
    'artifact_validation_failed',
    'tool_list_validation_failed',
    'unauthorized_scheduler_mutation'
  )),
  check (value >= 0)
);

insert into scheduler_transition_totals (kind) values
  ('occurrences_materialized'),
  ('misfire_coalesced_skipped'),
  ('overlap_suppressed'),
  ('run_claimed'),
  ('run_completed'),
  ('run_failed'),
  ('run_timed_out'),
  ('run_cancelled'),
  ('run_outcome_unknown'),
  ('run_observe_only_reexecution'),
  ('run_lease_reclaimed'),
  ('stale_fence_rejected'),
  ('policy_limit_rejected'),
  ('delivery_claimed'),
  ('delivery_delivered'),
  ('delivery_retry'),
  ('delivery_failure'),
  ('delivery_unknown'),
  ('delivery_skipped'),
  ('delivery_forced_unknown_resend'),
  ('execution_baseline_advanced'),
  ('accepted_delivery_baseline_advanced'),
  ('profile_validation_failed'),
  ('artifact_validation_failed'),
  ('tool_list_validation_failed'),
  ('unauthorized_scheduler_mutation');

create trigger trg_scheduler_metrics_run_materialized
after insert on scheduled_runs
begin
  update scheduler_transition_totals set value = case when value < 9223372036854775807 then value + 1 else value end
    where kind = 'occurrences_materialized';
  update scheduler_transition_totals set value = value + min(new.skipped_count, 9223372036854775807 - value)
    where kind = 'misfire_coalesced_skipped';
end;

create trigger trg_scheduler_metrics_run_transition
after update of state on scheduled_runs
when old.state != new.state
begin
  update scheduler_transition_totals set value = case when value < 9223372036854775807 then value + 1 else value end
    where kind = case
      when new.state = 'leased' then 'run_claimed'
      when new.state = 'succeeded' then 'run_completed'
      when new.state = 'failed' then 'run_failed'
      when new.state = 'timed_out' then 'run_timed_out'
      when new.state = 'cancelled' then 'run_cancelled'
      when new.state = 'outcome_unknown' then 'run_outcome_unknown'
      else ''
    end;
end;

create trigger trg_scheduler_metrics_delivery_transition
after update of state on scheduled_run_deliveries
when old.state != new.state
begin
  update scheduler_transition_totals set value = case when value < 9223372036854775807 then value + 1 else value end
    where kind = case
      when new.state = 'sending' then 'delivery_claimed'
      when new.state = 'delivered' then 'delivery_delivered'
      when new.state = 'failed_retryable' then 'delivery_retry'
      when new.state = 'failed_terminal' then 'delivery_failure'
      when new.state = 'delivery_unknown' then 'delivery_unknown'
      when new.state in ('skipped_none', 'skipped_unchanged') then 'delivery_skipped'
      else ''
    end;
end;

create trigger trg_scheduler_metrics_execution_baseline
after update of baseline_version on scheduled_execution_baselines
when new.baseline_version = old.baseline_version + 1
begin
  update scheduler_transition_totals set value = case when value < 9223372036854775807 then value + 1 else value end
    where kind = 'execution_baseline_advanced';
end;

create trigger trg_scheduler_metrics_delivery_baseline_insert
after insert on scheduled_delivery_baselines
begin
  update scheduler_transition_totals set value = case when value < 9223372036854775807 then value + 1 else value end
    where kind = 'accepted_delivery_baseline_advanced';
end;

create trigger trg_scheduler_metrics_delivery_baseline_update
after update of baseline_version on scheduled_delivery_baselines
when new.baseline_version = old.baseline_version + 1
begin
  update scheduler_transition_totals set value = case when value < 9223372036854775807 then value + 1 else value end
    where kind = 'accepted_delivery_baseline_advanced';
end;

create trigger trg_scheduler_metrics_unauthorized_mutation
after insert on schedule_mutation_audit
when new.outcome in ('denied', 'resolver_not_allowed')
begin
  update scheduler_transition_totals set value = case when value < 9223372036854775807 then value + 1 else value end
    where kind = 'unauthorized_scheduler_mutation';
end;

create trigger trg_scheduler_metrics_validation_failure
after insert on schedule_mutation_audit
when new.outcome in ('validation', 'capability_invalid')
begin
  update scheduler_transition_totals set value = case when value < 9223372036854775807 then value + 1 else value end
    where kind = case
      when new.outcome = 'capability_invalid' then 'tool_list_validation_failed'
      else 'artifact_validation_failed'
    end;
end;

create trigger trg_scheduler_metrics_forced_unknown_resend
after insert on scheduler_operator_action_consumptions
when exists (
  select 1 from scheduler_operator_actions action
  where action.action_id = new.action_id
    and action.action = 'force_delivery_resend'
)
begin
  update scheduler_transition_totals set value = case when value < 9223372036854775807 then value + 1 else value end
    where kind = 'delivery_forced_unknown_resend';
end;

create trigger trg_scheduler_metrics_late_evidence_stale_fence
after insert on scheduled_run_late_evidence
begin
  update scheduler_transition_totals set value = case when value < 9223372036854775807 then value + 1 else value end
    where kind = 'stale_fence_rejected';
end;

create trigger trg_scheduler_metrics_profile_validation_failure
after update of state on scheduled_run_attempts
when old.state != new.state
  and new.error_kind = 'profile_validation_failed'
begin
  update scheduler_transition_totals set value = case when value < 9223372036854775807 then value + 1 else value end
    where kind = 'profile_validation_failed';
end;

create trigger trg_scheduler_metrics_artifact_validation_failure
after update of state on scheduled_run_attempts
when old.state != new.state
  and new.error_kind = 'artifact_validation_failed'
begin
  update scheduler_transition_totals set value = case when value < 9223372036854775807 then value + 1 else value end
    where kind = 'artifact_validation_failed';
end;

create trigger trg_scheduler_metrics_tool_list_validation_failure
after update of state on scheduled_run_attempts
when old.state != new.state
  and new.error_kind = 'tool_list_validation_failed'
begin
  update scheduler_transition_totals set value = case when value < 9223372036854775807 then value + 1 else value end
    where kind = 'tool_list_validation_failed';
end;
