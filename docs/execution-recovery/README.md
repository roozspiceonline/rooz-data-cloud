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

Migration `20260809_0019` persists a bounded server-owned
`projects.max_active_leases`, caps persisted worker registration concurrency at
16, and adds partial active-lease admission indexes. Claim transactions take a
per-worker advisory lock and row lock, select only capacity-eligible work with
`SKIP LOCKED`, lock the owning project, and recount valid active leases before
creating the lease. Only ACTIVE BUILD and RUN_START leases whose expiry and
immutable deadline are still in the future consume a project slot. Every ACTIVE
unexpired worker lease consumes a worker slot. Recovery therefore releases
capacity without a separate counter or cleanup write that could drift.

RUN_CANCEL deliberately bypasses project admission so saturation cannot prevent
termination, but it still consumes the cancellation worker's own capacity.
Claim receipts and immutable audit details record the effective limits and
pre-claim aggregate counts. `/health/recovery` also exposes aggregate active
lease and saturated project/worker counts without tenant or worker identifiers.

Migration `20260809_0020` persists worker loss, recovery, and forced-cleanup
evidence plus scheduler counters. The scheduler detects an ACTIVE worker with a
valid lease whose server-observed activity is older than
`RDC_WORKER_LOST_AFTER_SECONDS`, disables its sandbox authority, shortens its
leases for immediate normal recovery, and records `worker.lost` and
`execution.lease.worker_lost` audit lineage. Retry remains bounded by the same
durable source, attempt, deadline, and backoff policy.

The sandbox worker now heartbeats and renews while a claim executes. Every RDC
Run and browser container carries the exact `io.rooz.rdc.managed=true` label.
Startup, renewal failure, signal handling, normal Run completion, and shutdown
force-remove only labeled containers with validated RDC names and remove only
bounded non-symlink RDC workspaces. A lost worker remains excluded from claims
and lease-scoped RLS until a strict `rdc.worker-recovery/v1` cleanup report is
accepted. Cleanup reports contain only counts and a startup identifier, never
container output, tenant data, or credentials.

Remaining increments cover production operational gates.

See the [threat model](THREAT_MODEL.md) and [runbook](RUNBOOK.md).
