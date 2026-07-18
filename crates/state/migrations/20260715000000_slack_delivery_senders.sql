alter table slack_delivery_queue
  add column sender_kind text not null default 'bot' check (sender_kind in ('bot', 'user'));

alter table slack_delivery_queue
  add column sender_key text check (
    (sender_kind = 'bot' and sender_key is null)
    or (sender_kind = 'user' and sender_key is not null and length(sender_key) > 0)
  );

alter table slack_delivery_receipts
  add column sender_kind text not null default 'bot' check (sender_kind in ('bot', 'user'));

alter table slack_delivery_receipts
  add column sender_key text check (
    (sender_kind = 'bot' and sender_key is null)
    or (sender_kind = 'user' and sender_key is not null and length(sender_key) > 0)
  );
