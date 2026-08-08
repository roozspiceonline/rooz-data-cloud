# Execution recovery runbook

Configure `RDC_WORKER_RETRY_BASE_SECONDS` and
`RDC_WORKER_RETRY_MAX_SECONDS`; startup rejects a base below one second, a base
above 60 seconds, a maximum below the base, or a maximum above one hour. Keep
`RDC_WORKER_MAX_ATTEMPTS` between 1 and 20.

Migration `20260809_0016` backfills existing lease deadlines to their current
expiry, adds an immutable deadline trigger, and installs deadline-aware recovery
policies. Deploy the migration before the API and worker protocol change.

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
