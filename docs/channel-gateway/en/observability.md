# Observability

Purpose: describe the implemented operational HTTP, scheduler telemetry, readiness, and logging surface.
Read this when configuring probes, metrics collection, or production diagnostics.
This does not define a user-facing API or mutating remote administration surface.

## Implemented Operational HTTP

`codeoff serve` always starts a bounded HTTP/1 operational server on `[server].bind`. The default is `127.0.0.1:7788`; a non-loopback address is rejected unless `[server].allow_non_loopback = true`.

Only these read-only `GET` routes are implemented:

- `GET /healthz`: process liveness, returning `{"status":"alive"}`.
- `GET /readyz`: SQLite readability plus scheduler component, loop, provider, and snapshot readiness.
- `GET /metrics`: Prometheus/OpenMetrics scheduler telemetry.

Other paths return `404`; non-`GET` methods return `405`; query strings are rejected. Responses are bounded, carry `Cache-Control: no-store`, and do not expose instructions, payload bodies, provider receipts, tokens, or raw errors.

The following admin routes are not implemented and remain future work: runtime summaries, inbound/outbound queue inspection, event lookup, delivery lookup, and conversation mapping diagnostics. CLI scheduler diagnostics are trusted-local maintenance commands, not HTTP admin endpoints.

## Readiness Contract

`/readyz` fails closed with `503` when SQLite cannot answer its bounded read probe within 250 ms. With the scheduler disabled it returns `200` and `scheduler_disabled` after SQLite passes.

With the scheduler enabled, readiness additionally requires:

- scheduler execution and delivery/preparation loops to have reported started;
- required claim-side dependencies to be available;
- a successful bounded SQLite scheduler snapshot;
- no snapshot read/timeout error and a snapshot no older than 15 seconds.

`run_claims_enabled` and `delivery_claims_enabled` are independent kill switches. Enabling a claim path without its required executor/provider makes readiness fail rather than silently dropping work. The delivery preparation loop can run while provider claims are disabled.

## Implemented Scheduler Metrics

The metrics endpoint exposes low-cardinality scheduler telemetry, including:

- `codeoff_scheduler_events_total` by fixed worker, operation, status, and stable error kind;
- `codeoff_scheduler_operation_duration_seconds`;
- `codeoff_scheduler_last_attempt`;
- `codeoff_scheduler_transitions_total` by a fixed `kind` vocabulary. These totals are advanced in
  the same SQLite transaction as the accepted state/audit transition and survive daemon restarts;
- `codeoff_scheduler_worker_capacity` and `codeoff_scheduler_worker_available_slots` by fixed worker;
- bounded gauges for due jobs, pending/leased/executing/unknown runs, unprepared/pending/sending/retryable/unknown deliveries, and oldest work ages;
- snapshot success, age, and saturation gauges.

The durable transition kinds cover materialization/coalescing/overlap decisions; run claim,
terminal, recovery, stale-fence, and policy-limit outcomes; delivery claim, success, retry, failure,
unknown, skip, and forced-unknown resend outcomes; independent execution and accepted-delivery
baseline advances; executor validation categories; and unauthorized scheduler mutations. Counters
advance only after the authoritative transaction accepts the outcome. Rollback and repeated metric
scrapes do not increment them. In particular, `delivery_retry` is durable and independent of an
Agent execution, so the no-Agent delivery retry invariant can be checked directly.

The SQLite snapshot refreshes every 5 seconds, is capped at 100,000 rows/counts and 30 days of age, and has a 500 ms timeout. A failed refresh preserves the last bounded gauge values but marks the snapshot unavailable for readiness.

Labels never contain job, run, delivery, owner, channel, user, thread, Slack, or Codex ids;
instructions, prompts, results, payloads, tokens, secrets, receipts, and raw error strings are also
excluded. Metric labels are selected only from fixed enums.

## Structured Scheduler Tracing

The daemon initializes JSON tracing without ANSI output. Scheduler workers emit fixed worker/operation/status/error-kind events and monotonic durations. This is the implemented scheduler tracing path; legacy gateway components may still emit their existing output and are not all represented by scheduler metrics.

Secrets, full provider payloads, Codex prompts/answers, instructions, rendered delivery bodies, and unbounded errors must remain absent or redacted.

## Exposure Boundary

The operational server has no application-layer authentication. Keep the default loopback bind unless a deployment deliberately sets `allow_non_loopback = true` and supplies platform network policy, authentication proxying, and trusted probe access. `/healthz` and `/readyz` should be unauthenticated only inside a trusted local or cluster network.
