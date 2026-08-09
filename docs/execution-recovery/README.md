# Production Execution Lifecycle / Recovery

This RDC v1 workstream is active after Phase 1P. The implemented foundation
makes execution retry timing a server-owned policy shared by stale-lease
recovery and worker-reported retryable failure handling. It also persists an
immutable, server-derived deadline on every execution lease.

The policy uses validated bounded exponential backoff, allows retries only for
failed or timed-out attempts below the configured maximum, and refuses to
requeue work whose durable dispatch outbox row is missing. Immutable execution
audit events include whether a retry was scheduled and its server-derived
`next_attempt_at`; workers cannot choose that timestamp.

Build deadlines come from the immutable Agent manifest timeout captured in the
durable dispatch outbox. Run deadlines come from the server-validated effective
runtime timeout. Cancellation leases use the server lease maximum. Initial and
renewed lease expiry is clamped to both the lease lifetime ceiling and the
deadline. A deadline-exceeded Build or Run is terminally `TIMED_OUT`, its outbox
source becomes `FAILED`, no retry is scheduled, outstanding secret grants are
expired, and immutable audit lineage records
`execution.lease.deadline_exceeded`.

Run cancellation now has a server-derived immutable `cancel_deadline_at` and a
single durable `CANCEL` outbox row even under concurrent requests with distinct
idempotency keys. Cancellation intent wins over late `RUN_START` status or
completion reports. Worker-confirmed cancellation, loss of a Run/Cancel lease,
or expiry of the cancellation deadline fences every active Run lease, revokes
issued secret grants, cancels pending/claimed commands, terminally marks the Run
`ABORTED`, and records `run.cancellation_converged` lineage.

Recovery no longer depends on worker heartbeat or claim traffic. The dedicated
`execution-recovery` process runs bounded lease and cancellation batches on a
validated interval. A transaction-scoped PostgreSQL advisory lock makes
multiple replicas single-winner, while `SKIP LOCKED` preserves safe concurrent
row recovery. A process crash rolls back the entire batch; the next interval or
replacement process can recover the same durable work.

Migration `20260809_0018` adds singleton scheduler health and counters.
`/health/recovery` exposes only operational status and aggregate counts, and
API readiness degrades when the enabled scheduler has never succeeded, reports
failure, or becomes stale.

Remaining increments cover bounded project and worker admission, broader
crash/restart scenarios, and production operations.

See the [threat model](THREAT_MODEL.md) and [runbook](RUNBOOK.md).
