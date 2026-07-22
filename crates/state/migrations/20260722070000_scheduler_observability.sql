create index idx_scheduled_runs_observability
  on scheduled_runs (state, scheduled_for);

create index idx_scheduled_deliveries_observability
  on scheduled_run_deliveries (state, created_at);
