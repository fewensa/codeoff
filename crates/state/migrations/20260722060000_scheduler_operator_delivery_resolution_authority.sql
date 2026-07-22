drop trigger trg_scheduler_operator_delivery_resolution;

create trigger trg_scheduler_operator_delivery_resolution
after update of state on scheduled_run_deliveries
when old.state = 'delivery_unknown' and new.state in ('delivered', 'failed_terminal', 'pending')
begin
  select case when (
    select count(*) from scheduler_operator_actions
    where target_kind = 'delivery' and target_id = new.delivery_id
      and expected_attempt = old.attempt and expected_fence = old.fence
      and before_state = 'delivery_unknown' and after_state = new.state
      and occurred_at = new.updated_at and effective_at = new.updated_at
      and evidence_json is not null and evidence_digest is not null
      and json_valid(evidence_json)
      and json_extract(evidence_json, '$.provider_query_scope') = 'canonical_delivery_target'
      and json_type(evidence_json, '$.provider_query_started_at') = 'integer'
      and json_type(evidence_json, '$.provider_query_completed_at') = 'integer'
      and json_type(evidence_json, '$.provider_query_window_start') = 'integer'
      and json_type(evidence_json, '$.provider_query_window_end') = 'integer'
      and json_extract(evidence_json, '$.provider_query_started_at') >= 0
      and json_extract(evidence_json, '$.provider_query_completed_at')
        >= json_extract(evidence_json, '$.provider_query_started_at')
      and json_extract(evidence_json, '$.provider_query_window_start') >= 0
      and json_extract(evidence_json, '$.provider_query_window_end')
        >= json_extract(evidence_json, '$.provider_query_window_start')
      and json_extract(evidence_json, '$.provider_query_window_end')
        <= json_extract(evidence_json, '$.provider_query_completed_at')
      and json_extract(evidence_json, '$.provider_query_window_end')
        - json_extract(evidence_json, '$.provider_query_window_start') <= 2678400
      and length(json_extract(evidence_json, '$.provider_query_summary_digest')) = 64
      and json_extract(evidence_json, '$.provider_query_summary_digest') not glob '*[^0-9a-f]*'
      and (
        (action = 'confirm_delivery_delivered' and new.state = 'delivered'
          and provider_receipt = new.provider_receipt
          and json_extract(evidence_json, '$.provider_query_result') = 'write_confirmed')
        or (action = 'confirm_delivery_no_write' and new.state = 'failed_terminal'
          and json_extract(evidence_json, '$.provider_query_result') = 'no_write_confirmed')
        or (action = 'force_delivery_resend' and new.state = 'pending'
          and duplicate_risk_acknowledged = 1
          and reason_schema_version = 1 and reason_hash_algorithm = 'sha256-v1'
          and reason_json is not null and reason_digest is not null
          and json_extract(evidence_json, '$.provider_query_result') = 'no_matching_write_found')
      )
      and not exists (select 1 from scheduler_operator_action_consumptions consumed
        where consumed.action_id = scheduler_operator_actions.action_id)
  ) != 1 then raise(abort, 'delivery unknown transition requires one query-bound operator action') end;
  insert into scheduler_operator_action_consumptions (action_id, target_kind, target_id, consumed_at)
  select action_id, 'delivery', new.delivery_id, new.updated_at from scheduler_operator_actions
  where target_kind = 'delivery' and target_id = new.delivery_id
    and expected_attempt = old.attempt and expected_fence = old.fence
    and before_state = 'delivery_unknown' and after_state = new.state
    and occurred_at = new.updated_at and effective_at = new.updated_at
    and evidence_json is not null and evidence_digest is not null
    and json_valid(evidence_json)
    and json_extract(evidence_json, '$.provider_query_scope') = 'canonical_delivery_target'
    and json_type(evidence_json, '$.provider_query_started_at') = 'integer'
    and json_type(evidence_json, '$.provider_query_completed_at') = 'integer'
    and json_type(evidence_json, '$.provider_query_window_start') = 'integer'
    and json_type(evidence_json, '$.provider_query_window_end') = 'integer'
    and json_extract(evidence_json, '$.provider_query_started_at') >= 0
    and json_extract(evidence_json, '$.provider_query_completed_at')
      >= json_extract(evidence_json, '$.provider_query_started_at')
    and json_extract(evidence_json, '$.provider_query_window_start') >= 0
    and json_extract(evidence_json, '$.provider_query_window_end')
      >= json_extract(evidence_json, '$.provider_query_window_start')
    and json_extract(evidence_json, '$.provider_query_window_end')
      <= json_extract(evidence_json, '$.provider_query_completed_at')
    and json_extract(evidence_json, '$.provider_query_window_end')
      - json_extract(evidence_json, '$.provider_query_window_start') <= 2678400
    and length(json_extract(evidence_json, '$.provider_query_summary_digest')) = 64
    and json_extract(evidence_json, '$.provider_query_summary_digest') not glob '*[^0-9a-f]*'
    and (
      (action = 'confirm_delivery_delivered' and new.state = 'delivered'
        and provider_receipt = new.provider_receipt
        and json_extract(evidence_json, '$.provider_query_result') = 'write_confirmed')
      or (action = 'confirm_delivery_no_write' and new.state = 'failed_terminal'
        and json_extract(evidence_json, '$.provider_query_result') = 'no_write_confirmed')
      or (action = 'force_delivery_resend' and new.state = 'pending'
        and duplicate_risk_acknowledged = 1
        and reason_schema_version = 1 and reason_hash_algorithm = 'sha256-v1'
        and reason_json is not null and reason_digest is not null
        and json_extract(evidence_json, '$.provider_query_result') = 'no_matching_write_found')
    )
    and not exists (select 1 from scheduler_operator_action_consumptions consumed
      where consumed.action_id = scheduler_operator_actions.action_id);
end;
