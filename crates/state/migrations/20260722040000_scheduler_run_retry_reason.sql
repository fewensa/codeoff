alter table scheduler_operator_actions
  add column reason_schema_version integer not null default 0;
alter table scheduler_operator_actions
  add column reason_hash_algorithm text;
alter table scheduler_operator_actions
  add column reason_json text;
alter table scheduler_operator_actions
  add column reason_digest text;

create trigger trg_scheduler_operator_reason_insert_authority
before insert on scheduler_operator_actions
when not (
  (new.action = 'retry_run'
    and new.reason_schema_version = 1
    and new.reason_hash_algorithm = 'sha256-v1'
    and new.reason_json is not null
    and length(cast(new.reason_json as blob)) between 1 and 65536
    and json_valid(new.reason_json)
    and json_extract(new.reason_json, '$.schema_version') = 1
    and json_type(new.reason_json, '$.reason_code') = 'text'
    and length(json_extract(new.reason_json, '$.reason_code')) between 1 and 64
    and json_extract(new.reason_json, '$.reason_code') not glob '*[^a-z0-9_]*'
    and json_type(new.reason_json, '$.reason') = 'text'
    and length(cast(json_extract(new.reason_json, '$.reason') as blob)) between 1 and 4096
    and (select count(*) from json_each(new.reason_json)) = 3
    and length(new.reason_digest) = 64
    and new.reason_digest not glob '*[^0-9a-f]*')
  or (new.action != 'retry_run'
    and new.reason_schema_version = 0
    and new.reason_hash_algorithm is null
    and new.reason_json is null
    and new.reason_digest is null)
)
begin
  select raise(abort, 'operator action reason authority is invalid');
end;
