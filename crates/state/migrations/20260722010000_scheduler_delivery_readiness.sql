create trigger trg_scheduled_delivery_skipped_none_insert_guard
before insert on scheduled_run_deliveries
when new.state = 'skipped_none'
begin
  select raise(abort, 'skipped none delivery must be prepared from pending authority');
end;

create trigger trg_scheduled_delivery_skipped_none_acceptance
before update of state on scheduled_run_deliveries
when new.state = 'skipped_none' and not (
  old.state is 'pending'
  and new.authority_kind is 'intent_v1'
  and json_extract(new.target_json, '$.kind') is 'none'
  and new.delivery_policy_version is 1
  and new.payload_snapshot is not null
  and new.provider_outcome is 'skipped_none'
  and new.provider_receipt is null
  and new.error_kind is null
  and new.error_message is null
  and new.next_attempt_at is null
  and new.lease_owner is null
  and new.lease_expires_at is null
  and new.claimed_baseline_version is null
  and new.attempt is old.attempt
  and new.fence is old.fence
)
begin
  select raise(abort, 'skipped none delivery requires exact none policy authority');
end;

create trigger trg_scheduled_delivery_readiness_rejection_acceptance
before update of state on scheduled_run_deliveries
when new.state = 'failed_terminal'
  and old.state in ('pending', 'failed_retryable')
  and not (
    new.authority_kind is 'intent_v1'
    and new.payload_snapshot is not null
    and new.provider_outcome is 'confirmed_no_write_terminal'
    and new.error_kind is not null
    and length(new.error_kind) > 0
    and new.error_message is 'provider rejected exact delivery target during readiness'
    and new.provider_receipt is null
    and new.next_attempt_at is null
    and new.lease_owner is null
    and new.lease_expires_at is null
    and new.attempt is old.attempt
    and new.fence is old.fence
    and new.updated_at is not null
    and new.updated_at >= old.updated_at
    and (
      old.state = 'pending'
      or (old.next_attempt_at is not null and old.next_attempt_at <= new.updated_at)
    )
  )
begin
  select raise(abort, 'readiness rejection requires exact unclaimed delivery authority');
end;

drop trigger trg_scheduled_delivery_state_transition;

create trigger trg_scheduled_delivery_state_transition
before update of state on scheduled_run_deliveries
when old.state != new.state and not (
  (old.state = 'pending' and new.state in (
    'sending',
    'failed_terminal',
    'skipped_none',
    'skipped_unchanged'
  ))
  or (old.state = 'sending' and new.state in (
    'delivered',
    'failed_retryable',
    'failed_terminal',
    'delivery_unknown'
  ))
  or (old.state = 'failed_retryable' and new.state in ('pending', 'failed_terminal'))
)
begin
  select raise(abort, 'invalid scheduled delivery state transition');
end;
