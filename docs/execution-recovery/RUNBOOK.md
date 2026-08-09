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
Migration `20260809_0020` adds worker loss/recovery timestamps, cleanup
generation evidence, recovery counters, and a worker-RLS recovery fence.
Configure `RDC_WORKER_LOST_AFTER_SECONDS` from 15–300 seconds (default 45).
Sandbox workers must use `RDC_WORKER_HEARTBEAT_SECONDS` from 5–30 seconds and
`RDC_WORKER_LEASE_RENEW_SECONDS` from 15–300 seconds; keep the heartbeat
comfortably below the loss threshold.

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

Worker-loss diagnostics include `last_workers_lost`,
`last_worker_leases_fenced`, their cumulative totals, and
`recovery_pending_workers`. Investigate a nonzero pending count by checking the
worker service and its rootless containerd namespace. A detected loss must have
`worker.lost` audit lineage; affected leases must become `EXPIRED` with
`WORKER_LOST`, issued grants must expire, and retry eligibility must remain
server-derived. Do not clear recovery timestamps or manually reactivate RLS.

On worker restart, startup cleanup must successfully list only containers with
label `io.rooz.rdc.managed=true`, validate the `rdc-run-*` or `rdc-browser-*`
name, force-remove them, and delete only bounded `run-*`/`build-*` workspace
directories that are real directories rather than symlinks. The worker then
submits `rdc.worker-recovery/v1`; until accepted, claims fail with
`WORKER_RECOVERY_REQUIRED`. If discovery or cleanup fails, keep the worker down
and repair the dedicated rootless runtime. Never broaden cleanup to the host
Docker socket, another containerd namespace, unlabeled containers, or arbitrary
workspace paths.

Multiple scheduler replicas are safe: only the replica holding
`pg_try_advisory_xact_lock` performs a batch. Do not delete or manually rewrite
the singleton state row. On a crash, restart the process normally; PostgreSQL
rolls back partial batch mutations and releases the session lock. If health is
stale, first verify PostgreSQL reachability and scheduler process availability,
then inspect the bounded `last_error_code`. Do not bypass row locks or mutate
leases directly during incident recovery.

## Production supervision and readiness

Install the units in `infrastructure/systemd` on immutable Linux releases.
Start `rdc.target` on the control-plane host and enable the sandbox-worker unit
only on its dedicated rootless execution host. Before every rollout, run
`systemd-analyze verify`, confirm environment-file permissions, then execute:

```text
python scripts/check_production_readiness.py --base-url https://api.example.com
```

API, scheduler, and worker services must run as their dedicated non-root users.
Do not remove control-group termination, final cleanup, capability bounding,
filesystem protection, readiness probes, or restart policy during incidents.
If a worker is killed, `ExecStopPost` must complete label/name-scoped cleanup;
keep the unit failed if cleanup cannot prove completion.

## PostgreSQL backup and restore drill

Set `RDC_ENV` and `RDC_DEPLOYMENT_ID` in a protected operator environment. Set
the read-only `RDC_BACKUP_DATABASE_URL` for backup and the distinct
`RDC_RESTORE_DATABASE_URL` only for the restore drill. The latter must point to
the isolated drill cluster and may create/drop disposable databases. URLs are
read only from the environment and converted to libpq child variables; they are
never placed in argv or output.

```text
python scripts/production_recovery_drill.py backup \
  --archive-dir /var/backups/rdc/postgres
python scripts/production_recovery_drill.py restore-drill \
  --archive /var/backups/rdc/postgres/<verified-archive>.dump
```

The backup must have mode `0600`, a matching `.manifest.json`, SHA-256, size,
environment/deployment identity, and Alembic revision. Copy both files to
immutable off-host storage. The restore drill creates a random bounded database,
verifies the backed-up revision, downgrades one migration, upgrades to current
head, verifies the final revision, and drops the database in success and failure
paths. A missing cleanup confirmation is a failed drill. Run a restore drill at
least monthly and before a migration-bearing release; retain its nonsensitive
JSON result with release evidence.

## Object-storage recovery drill

Enable bucket versioning, then run the canary using a dedicated credential
limited to bucket-version inspection and the generated recovery-drill prefix:

```text
python scripts/object_storage_recovery_drill.py
```

The script permits HTTPS and the exact environment bucket only. It writes one
generated `recovery-drill/<deployment>/...` key, creates two versions and a
delete marker, reads the original exact version, verifies its bytes, and removes
only those bounded versions. Never point it at a shared or mismatched bucket.
The daily systemd timer makes failure visible without touching tenant keys.

## Recovery SLO response

Scrape `/metrics/recovery` only from the monitoring network and load
`infrastructure/monitoring/rdc-execution-recovery.rules.yml`. A stale/unavailable
scheduler or new sweep failure is critical. A cleanup-pending worker beyond five
minutes or a worker-loss burst requires sandbox-host investigation. The metrics
are global aggregates; do not add tenant or runtime identifiers as labels.
