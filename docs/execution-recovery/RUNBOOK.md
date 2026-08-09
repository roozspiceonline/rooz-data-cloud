# Execution recovery runbook

Configure `RDC_WORKER_RETRY_BASE_SECONDS` and
`RDC_WORKER_RETRY_MAX_SECONDS`; startup rejects a base below one second, a base
above 60 seconds, a maximum below the base, or a maximum above one hour. Keep
`RDC_WORKER_MAX_ATTEMPTS` between 1 and 20.
Configure `RDC_WORKER_CANCEL_CONVERGENCE_SECONDS` between 30 and 3600 seconds;
the default is five minutes.

Migration `20260809_0016` backfills existing lease deadlines to their current
expiry, adds an immutable deadline trigger, and installs deadline-aware recovery
policies. Deploy the migration before the API and worker protocol change.
Migration `20260809_0017` backfills cancellation deadlines for existing
cancel-requested Runs, adds the cancellation deadline index, and prevents
mutation of the first cancellation request or deadline.
Migration `20260809_0018` creates the singleton
`control.execution_recovery_state` row used for scheduler freshness, bounded
batch counts, and failure counters.
Migration `20260809_0019` adds `control.projects.max_active_leases`, constrains
it to 1–1000, clamps existing worker limits to 16, enforces worker limits of
1–16, and installs partial admission indexes. Deploy it before enabling the
corresponding API claim path. Configure
`RDC_EXECUTION_PROJECT_DEFAULT_MAX_ACTIVE_LEASES` from 1–1000 and
`RDC_WORKER_REGISTRATION_MAX_CONCURRENCY` from 1–16. These are server policy;
do not treat a worker registration request as authoritative.

Monitor `execution.lease.expired`, `execution.lease.deadline_exceeded`, and
`execution.lease.completed` audit events.
For retried work, `retry_scheduled` or `retryable` is true and
`next_attempt_at` is a server-derived timestamp. If the dispatch outbox row is
missing, retry must be false and the workload must terminate for investigation.

Do not manually set outbox rows to `PENDING` without reconciling the target
Build or Run, the latest lease, attempts, audit lineage, and any issued secret
grants. Recovery must remain idempotent under concurrent sweepers through row
locking and `SKIP LOCKED`.

A deadline-exceeded workload must have lease status `FAILED`, target status
`TIMED_OUT`, outbox status `FAILED`, error code
`WORKLOAD_DEADLINE_EXCEEDED`, `retry_scheduled=false`, and no issued secret
grant. Do not extend `deadline_at` during incident handling: the database
immutability trigger intentionally rejects that mutation. Queue a new Build or
Run through the normal tenant-authorized API when an operator-approved retry is
required.

Monitor `run.cancellation_converged` and
`execution.lease.cancellation_converged`. A converged Run must be `ABORTED`,
must have no ACTIVE execution lease or ISSUED secret grant, and must have no
`PENDING` or `CLAIMED` Run command. The audit `reason` distinguishes
`WORKER_CONFIRMED`, `RUN_START_LEASE_LOST`, `RUN_CANCEL_LEASE_LOST`,
`LATE_RUN_START_COMPLETION`, and `CANCEL_DEADLINE_EXCEEDED`. Do not mutate the
cancellation deadline or manually reactivate a fenced lease; create a new Run
through the normal authorized API if execution is needed again.

## Scheduled recovery service

Run `python -m app.recovery_scheduler` as an independent service. Compose does
this with the `execution-recovery` service. Configure:

- `RDC_EXECUTION_RECOVERY_SWEEP_ENABLED` (normally `true`)
- `RDC_EXECUTION_RECOVERY_SWEEP_INTERVAL_SECONDS` (1–300, default 10)
- `RDC_EXECUTION_RECOVERY_SWEEP_BATCH_SIZE` (1–500, default 100)
- `RDC_EXECUTION_RECOVERY_STALE_AFTER_SECONDS` (at least two intervals, at most
  3600, default 60)

Check `/health/recovery` or run
`python -m app.recovery_scheduler --healthcheck`. Healthy output requires a
recent successful sweep. Inspect aggregate `last_leases_reaped`,
`last_cancellations_converged`, `total_sweeps`, and `total_failures`; no tenant,
payload, token, or secret data is exposed.

Admission diagnostics in the same response are aggregate
`active_execution_leases`, `saturated_projects`, and `saturated_workers`.
Saturation is not itself a recovery failure. If it persists, verify that ACTIVE
leases have future `expires_at` and `deadline_at`, that the recovery scheduler
is healthy, and that workers are completing or failing leases normally. Do not
increase limits to conceal stale work or manually decrement derived capacity.
Project capacity is recomputed from valid ACTIVE BUILD/RUN_START leases; worker
capacity is recomputed from all valid ACTIVE leases. RUN_CANCEL is exempt only
from the project limit so cancellation can drain a saturated project.

Multiple scheduler replicas are safe: only the replica holding
`pg_try_advisory_xact_lock` performs a batch. Do not delete or manually rewrite
the singleton state row. On a crash, restart the process normally; PostgreSQL
rolls back partial batch mutations and releases the session lock. If health is
stale, first verify PostgreSQL reachability and scheduler process availability,
then inspect the bounded `last_error_code`. Do not bypass row locks or mutate
leases directly during incident recovery.
