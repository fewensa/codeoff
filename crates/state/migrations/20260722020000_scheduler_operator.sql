create table scheduler_operator_actions (
  action_id text primary key,
  principal_kind text not null,
  principal_provider text not null,
  principal_tenant text not null,
  principal_subject text not null,
  request_id text not null,
  request_hash_algorithm text not null,
  request_digest text not null,
  action text not null,
  target_kind text not null,
  target_id text not null,
  expected_attempt integer not null,
  expected_fence integer not null,
  before_state text not null,
  after_state text not null,
  evidence_hash_algorithm text,
  evidence_json text,
  evidence_digest text,
  provider_receipt text,
  duplicate_risk_acknowledged integer not null default 0,
  effective_at integer not null,
  occurred_at integer not null,
  unique (principal_kind, principal_provider, principal_tenant, principal_subject, request_id),
  check (length(action_id) between 1 and 128),
  check (length(request_id) between 1 and 256),
  check (request_hash_algorithm = 'sha256-v1' and length(request_digest) = 64
    and request_digest not glob '*[^0-9a-f]*'),
  check (action in (
    'retry_run',
    'confirm_delivery_delivered',
    'confirm_delivery_no_write',
    'force_delivery_resend',
    'acknowledge_delivery_unknown'
  )),
  check (target_kind in ('run', 'delivery')),
  check (length(target_id) between 1 and 1050),
  check (expected_attempt > 0 and expected_fence > 0),
  check ((evidence_hash_algorithm is null and evidence_json is null and evidence_digest is null)
    or (evidence_hash_algorithm = 'sha256-v1'
      and length(cast(evidence_json as blob)) between 1 and 65536
      and json_valid(evidence_json)
      and length(evidence_digest) = 64
      and evidence_digest not glob '*[^0-9a-f]*')),
  check (provider_receipt is null or length(cast(provider_receipt as blob)) between 1 and 65536),
  check ((target_kind = 'run' and evidence_json is null and provider_receipt is null)
    or (target_kind = 'delivery' and evidence_json is not null)),
  check ((action = 'retry_run' and target_kind = 'run')
    or (action != 'retry_run' and target_kind = 'delivery')),
  check ((action = 'confirm_delivery_delivered' and provider_receipt is not null
      and json_valid(provider_receipt))
    or (action != 'confirm_delivery_delivered' and provider_receipt is null)),
  check ((action = 'force_delivery_resend' and duplicate_risk_acknowledged = 1)
    or (action != 'force_delivery_resend' and duplicate_risk_acknowledged = 0)),
  check (effective_at >= 0 and occurred_at >= 0)
);

create table scheduler_operator_action_consumptions (
  action_id text primary key references scheduler_operator_actions(action_id) on delete restrict,
  target_kind text not null,
  target_id text not null,
  consumed_at integer not null,
  check (target_kind in ('run', 'delivery')),
  check (length(target_id) between 1 and 1050),
  check (consumed_at >= 0)
);

create index idx_scheduler_operator_actions_target
  on scheduler_operator_actions (target_kind, target_id, occurred_at, action_id);

create trigger trg_scheduler_operator_actions_update_immutable
before update on scheduler_operator_actions
begin
  select raise(abort, 'scheduler operator actions are append-only');
end;

create trigger trg_scheduler_operator_actions_delete_immutable
before delete on scheduler_operator_actions
begin
  select raise(abort, 'scheduler operator actions are append-only');
end;

create trigger trg_scheduler_operator_consumptions_update_immutable
before update on scheduler_operator_action_consumptions
begin
  select raise(abort, 'scheduler operator action consumptions are append-only');
end;

create trigger trg_scheduler_operator_consumptions_delete_immutable
before delete on scheduler_operator_action_consumptions
begin
  select raise(abort, 'scheduler operator action consumptions are append-only');
end;

create trigger trg_scheduler_operator_run_retry
after update of state on scheduled_runs
when old.state in ('failed', 'timed_out', 'cancelled') and new.state = 'pending'
begin
  select case when (
    select count(*)
    from scheduler_operator_actions
    where target_kind = 'run'
      and target_id = new.run_id
      and action = 'retry_run'
      and expected_attempt = old.attempt
      and expected_fence = old.fence
      and before_state = old.state
      and after_state = 'pending'
      and effective_at = new.next_attempt_at
      and occurred_at = new.updated_at
      and not exists (
        select 1 from scheduler_operator_action_consumptions consumed
        where consumed.action_id = scheduler_operator_actions.action_id
      )
  ) != 1 then raise(abort, 'manual run retry requires one unconsumed operator action') end;
  insert into scheduler_operator_action_consumptions (action_id, target_kind, target_id, consumed_at)
  select action_id, 'run', new.run_id, new.updated_at
  from scheduler_operator_actions
  where target_kind = 'run'
    and target_id = new.run_id
    and action = 'retry_run'
    and expected_attempt = old.attempt
    and expected_fence = old.fence
    and before_state = old.state
    and after_state = 'pending'
    and effective_at = new.next_attempt_at
    and occurred_at = new.updated_at
    and not exists (
      select 1 from scheduler_operator_action_consumptions consumed
      where consumed.action_id = scheduler_operator_actions.action_id
    );
end;

drop trigger trg_scheduled_delivery_claimed_baseline_authority;

create trigger trg_scheduled_delivery_claimed_baseline_authority
before update of claimed_baseline_version on scheduled_run_deliveries
when old.authority_kind = 'intent_v1' and not (
  (old.state = 'pending'
    and new.state in ('sending', 'skipped_unchanged')
    and old.claimed_baseline_version is null
    and new.claimed_baseline_version >= 0)
  or (old.state = 'failed_retryable'
    and new.state = 'pending'
    and old.claimed_baseline_version is not null
    and new.claimed_baseline_version is null)
  or (old.state = 'delivery_unknown'
    and new.state in ('delivered', 'failed_terminal')
    and new.claimed_baseline_version is old.claimed_baseline_version)
  or (old.state = 'delivery_unknown'
    and new.state = 'pending'
    and old.claimed_baseline_version is not null
    and new.claimed_baseline_version is null)
)
begin
  select raise(abort, 'scheduled delivery claim baseline authority is immutable');
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
  or (old.state = 'delivery_unknown' and new.state in ('delivered', 'failed_terminal', 'pending'))
)
begin
  select raise(abort, 'invalid scheduled delivery state transition');
end;

create trigger trg_scheduler_operator_delivery_resolution
after update of state on scheduled_run_deliveries
when old.state = 'delivery_unknown' and new.state in ('delivered', 'failed_terminal', 'pending')
begin
  select case when (
    select count(*)
    from scheduler_operator_actions
    where target_kind = 'delivery'
      and target_id = new.delivery_id
      and expected_attempt = old.attempt
      and expected_fence = old.fence
      and before_state = 'delivery_unknown'
      and after_state = new.state
      and occurred_at = new.updated_at
      and effective_at = new.updated_at
      and (
        (action = 'confirm_delivery_delivered'
          and new.state = 'delivered'
          and provider_receipt = new.provider_receipt
          and evidence_digest is not null)
        or (action = 'confirm_delivery_no_write'
          and new.state = 'failed_terminal'
          and evidence_digest is not null)
        or (action = 'force_delivery_resend'
          and new.state = 'pending'
          and duplicate_risk_acknowledged = 1
          and evidence_digest is not null)
      )
      and not exists (
        select 1 from scheduler_operator_action_consumptions consumed
        where consumed.action_id = scheduler_operator_actions.action_id
      )
  ) != 1 then raise(abort, 'delivery unknown transition requires one unconsumed operator action') end;
  insert into scheduler_operator_action_consumptions (action_id, target_kind, target_id, consumed_at)
  select action_id, 'delivery', new.delivery_id, new.updated_at
  from scheduler_operator_actions
  where target_kind = 'delivery'
    and target_id = new.delivery_id
    and expected_attempt = old.attempt
    and expected_fence = old.fence
    and before_state = 'delivery_unknown'
    and after_state = new.state
    and occurred_at = new.updated_at
    and effective_at = new.updated_at
    and (
      (action = 'confirm_delivery_delivered'
        and new.state = 'delivered'
        and provider_receipt = new.provider_receipt
        and evidence_digest is not null)
      or (action = 'confirm_delivery_no_write'
        and new.state = 'failed_terminal'
        and evidence_digest is not null)
      or (action = 'force_delivery_resend'
        and new.state = 'pending'
        and duplicate_risk_acknowledged = 1
        and evidence_digest is not null)
    )
    and not exists (
      select 1 from scheduler_operator_action_consumptions consumed
      where consumed.action_id = scheduler_operator_actions.action_id
    );
end;
