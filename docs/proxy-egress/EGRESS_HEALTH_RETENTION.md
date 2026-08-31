# Egress health rollups and retention

Egress health summary APIs keep their existing 1–24 hour response contracts.
For every fully covered closed hour they read tenant-isolated hourly
Project/route/outcome rollups. The first partial hour, the current partial hour,
and any not-yet-rolled bucket are read from raw observations, so maintenance
lag cannot create gaps or double counting.

`app.egress_health_maintenance_runner` is a dedicated server process. It runs
an immediate sweep and then waits for the configured interval. A PostgreSQL
transaction advisory lock makes each sweep singleton and restart-safe. Each
sweep rolls at most 168 Project-hour buckets, purges at most 10,000 raw rows and
10,000 rollup rows, and uses the database clock. Raw retention is configurable
from 48 to 168 hours; rollup retention is configurable from 7 to 90 days. The
defaults are 48 hours and 30 days.

Raw rows are eligible for deletion only after a rollup exists for the same
Project and hour. Row triggers reject ordinary update/delete operations and
permit retention deletes only with a bounded transaction-local cutoff. Rollup
rows are tenant-lineage checked on insert, RLS protected for reads, immutable
outside bounded retention, and cannot authorize retry or route selection.

Every sweep that rolls or purges data appends one
`egress_health.maintenance_completed` event to the existing immutable audit
log. The event records only aggregate counts and configured bounds; it contains
no target, credential, raw evidence, Run, lease or worker identity.

Production must run `rdc-egress-health-maintenance.service` alongside the API
and execution recovery service. Its database-backed health check requires a
recent successful sweep. Operators should alert on a stale or failed state,
investigate database capacity or migration drift, and never widen retention or
batch limits without a reviewed migration and load test.
