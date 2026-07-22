create index idx_scheduled_runs_observability
  on scheduled_runs (state, scheduled_for);

create index idx_scheduled_deliveries_observability
  on scheduled_run_deliveries (state, created_at);

create index idx_scheduled_deliveries_observability_unprepared
  on scheduled_run_deliveries (created_at)
  where state = 'pending'
    and payload_snapshot is null;

create index idx_scheduled_deliveries_observability_prepared
  on scheduled_run_deliveries (created_at)
  where state = 'pending'
    and payload_snapshot is not null;
