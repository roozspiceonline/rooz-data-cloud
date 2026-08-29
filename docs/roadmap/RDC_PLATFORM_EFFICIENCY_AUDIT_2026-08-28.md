# RDC Platform Efficiency Audit — 2026-08-28

## Authoritative state at audit

- Current main SHA: `c2ef47498bc0a9b947361b5728a40c2ffab41fe8`.
- Audit branch: `feat/platform-efficiency-cleanup`, created from exact `origin/main`.
- Working tree at branch creation: clean. Issue #93 canary work is preserved in a
  named local stash on its separate feature branch and is not part of this work.
- Merged database head: `20260828_0024`.
- Current open product issue: #93, credential-rotation canary foundation.
- Current open product PR: none.
- Latest merged product feature: PR #92, privacy-preserving route health
  aggregation.
- Current CI: merged-main RDC CI #33161869705 succeeded at the exact main SHA.

## Evidence and findings

| Priority | Problem and evidence | Waste / risk | Proposed fix | Benefit | Complexity | Migration | API / security change |
| --- | --- | --- | --- | --- | --- | --- | --- |
| P1 | Every normal health observation inserts an immutable JSONB telemetry row and a second `audit_events` row. `record_egress_health_observation` also commits each item independently. | At least two heap rows, both tables' indexes, WAL and backup/replication traffic per sample. Operational telemetry is duplicated as security audit data. | Keep immutable lease/run/worker lineage in the observation, remove the routine audit row, normalize the six-field bounded evidence object into compact typed columns, and document retention. | Roughly halves heap-row count per accepted sample before index/WAL effects and removes JSONB key overhead. | Medium | Yes | Worker/API request and response stay compatible; security lineage stays in the RLS-protected immutable row. |
| P1 | The observation table maintains the primary key, replay unique index and six secondary indexes. No service query uses standalone organization, run, lease-time or worker indexes. | Each accepted sample updates eight observation indexes. Four indexes have no current read path. | Retain primary key, replay `(lease_id, client_observation_id)`, Project/time and Project/route/time; drop four unused secondary indexes. | Four fewer index writes per sample and slower index growth. | Low | Yes | No API or security behavior change; foreign keys and RLS remain. |
| P1 | Summary and route endpoints issue two `COUNT/GROUP BY` scans over raw observations for every request. Windows are capped at 24 hours, but cost still grows with event rate. | Read amplification and latency grow linearly within the window. | After compact persistence lands, add one PostgreSQL time-bucket rollup table and bounded retention in a separate migration; keep raw replay lineage for its documented retention window. | Bounded summary reads without new infrastructure. | Medium | Yes, later | Response contract unchanged; RLS required on rollups. |
| P1 | No explicit telemetry retention contract exists. Immutability currently implies indefinite growth. | Unbounded heap, index, WAL and backup growth. | Define separate raw and rollup retention, implement a server-owned bounded purge with immutable purge audit summaries, and test tenant isolation. | Predictable storage economics. | Medium | Yes, later | No caller deletion authority; security-relevant aggregate purge evidence remains. |
| P2 | CI runs frontend install/lint/typecheck/test/build, PostgreSQL backend, all tests, 21 verifiers and Compose for every PR change. | Unnecessary runner minutes during iteration. | Add changed-path classification and focused advisory iteration jobs, but retain a required complete exact-head job and the full merged-main run. | Faster feedback without weakening the merge gate. | Medium | No | No security behavior change; full exact-head gate remains mandatory. |
| P2 | `.github/workflows/ci.yml` lists 21 verifier commands individually and scripts repeat file-reading/marker helpers. | Workflow churn and duplicated verifier plumbing. | Add one manifest-driven verifier runner; preserve phase entrypoints and coverage. | One maintained CI entrypoint and consistent failure reporting. | Low | No | Coverage is consolidated, not deleted. |
| P2 | Status is duplicated in README, roadmap and a platform audit already stale at `b3f8fbc` / migration 0022. | Handoffs and planning can act on obsolete state. | Add a canonical machine-readable status file plus a validator that checks migration head and referenced repository paths; make narrative docs link to it. | Detectable drift and less manual duplication. | Low | No | No runtime change. |
| P2 | API Docker context includes `.venv`, caches and test artifacts; console root context has no `.dockerignore` and can include `.git`, all `node_modules`, local builds and coverage. | Large context transfer, cache invalidation and accidental local-artifact inclusion. | Add root and API `.dockerignore` files. | Smaller, safer, more stable builds. | Low | No | Runtime images and security controls unchanged. |
| P3 | Operator experience is behind the API, but a broad SDK/CLI would add surface before operational priorities stabilize. | Cognitive and maintenance cost if implemented prematurely. | Defer broad CLI; later add only authenticated read-only Run inspection and egress health after status/telemetry cleanup. | Avoids over-engineering. | Low | No | Must use existing APIs and authorization. |

## Focused audits

### Telemetry storage and indexes

The merged row stores five UUID lineage fields, one client UUID, JSONB evidence,
digest, classification flags, route dimensions and timestamp. Evidence admits
only transport failure, HTTP status, response bytes, latency and two booleans;
typed columns can preserve the same database validation without JSONB storage.
The current observation-index write set is the primary key, replay unique index,
organization, Project/time, Run/time, lease/time, worker, and Project/route/time.
Only the replay unique index and two Project/time indexes match current queries.

### Audit-event amplification

Policy creation, activation, credential issuance and denied/stale lifecycle
events are control-plane security actions and remain audit events. A successful
normal health sample is high-volume operational telemetry. Its immutable row
already contains exact server-derived organization, Project, Run, lease, worker,
digest and classification lineage under RLS and database guards. A duplicate
audit row adds cost but no independent authorization fact, so routine success
auditing should be removed. Security violations and administrative retention
actions should remain selectively audited.

### Aggregation bottleneck

Both APIs run totals and outcome groups directly against raw rows. The route API
adds route grouping and a second per-outcome query. The 1–24 hour bound prevents
unbounded history but not high-rate scans. A simple PostgreSQL bucket rollup is
the next dependency after compact persistence; Kafka, ClickHouse, Elasticsearch
and adaptive routing are not justified.

### CI, verifier, documentation and Docker assessment

CI has three unconditional jobs and no path classification or dependency cache
configuration. Full exact-head and merged-main verification are correct and must
remain. Twenty-one verifier entrypoints contain repeated marker-check patterns;
thin compatibility scripts can remain behind one runner. The root README and
dated platform audit duplicate roadmap state and are already stale. Docker has
no ignore files despite local Python and Node dependency trees inside its build
contexts.

The local ignored artifacts measured 200 MiB for `apps/api/.venv`, 417 MiB for
root `node_modules`, 46 MiB for the console `.next` output and 2.6 MiB for
`.git`. The new ignore files therefore exclude at least 665 MiB from this
checkout's potential build contexts; actual transferred size remains builder-
and-cache-dependent.

## Dependency-ordered implementation

1. Add this audit and canonical status validation.
2. Add migration 0025 for compact typed health evidence and index reduction;
   remove only the routine telemetry audit write and add scale-shape tests.
3. Add Docker ignore files and the consolidated verifier runner.
4. Verify upgrade, downgrade, re-upgrade, RLS, replay, tenant isolation and the
   full repository suite; capture actual benchmark measurements only when an
   isolated PostgreSQL environment is available.
5. In a separate increment, add rollups and bounded retention.
6. In a separate CI-only increment, add advisory focused jobs plus a required
   complete exact-head gate.

## Measured compact-evidence result

On isolated PostgreSQL 18, read-only `pg_column_size` measurements compared the
same bounded successful sample represented as the former six-key JSONB object
and as the six typed compact fields. Results were 14,000 versus 4,600 bytes for
100 samples, 140,000 versus 46,000 for 1,000, and 1,400,000 versus 460,000 for
10,000. This is a measured 67.1% reduction in evidence-payload representation;
it is not a claim about complete heap/WAL size, which also includes fixed row
lineage and database overhead. PostgreSQL confirmed exactly four retained
observation indexes: primary key, replay unique, Project/time and
Project/route/time. The fresh PostgreSQL-backed suite passed 352 tests after an
upgrade/downgrade/re-upgrade cycle.

## Expected files and migrations

This increment is expected to change the health model/service, a new forward
migration, health PostgreSQL/contract tests, verifier/status tooling, CI-neutral
Docker ignore files, the roadmap/runbook/threat model and canonical status.
Migration `20260828_0025` is expected. Public health request/response schemas are
not expected to change.

## Security invariants that remain unchanged

PostgreSQL RLS, tenant isolation, server-derived ownership, exact active-lease
lineage, worker authentication, replay conflict detection, false-by-default
capabilities, isolated Chromium, networkless Agents, write-only secrets,
credential envelopes, Project authorization, cross-tenant denial tests,
migration tests, adversarial tests and full exact-head CI are non-negotiable.
Health data remains informational and cannot authorize retry or routing.
