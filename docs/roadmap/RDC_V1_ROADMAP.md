# RDC v1 Roadmap

## Status

This roadmap is the durable delivery plan for RDC v1. It records implemented
behavior only; a capability is not complete until its documented security and
test gates pass on the exact merged commit.

## Completed baseline

| Capability | Status | Evidence |
| --- | --- | --- |
| Identity, sessions, API keys, tenancy and authorization | Complete | migrations `0001`–`0002`, API tests and RLS controls |
| Agents, immutable versions, builds, Runs and worker leases | Complete baseline | migrations `0003`–`0008`, execution verifiers |
| Controlled web/browser canaries and egress boundaries | Complete baseline | Phase 1J–1M threat models and verifiers |
| Tenant-scoped Datasets | Complete | Phase 1N, append receipts, RLS, signed pagination/export |
| Tenant-scoped Key-Value Stores | Complete | Phase 1O, version history, RLS, controlled worker capability |
| Tenant-scoped Request Queues | Complete | Phase 1P, PR #56, migration `0015`, RDC CI #189 |

## Active work

| Workstream | Status | Dependency |
| --- | --- | --- |
| Production Execution Lifecycle / Recovery | Implementation complete — final audit and merge gate | Request Queue, Runs and worker leases |

The first recovery increment centralizes server-owned retry eligibility and
bounded exponential backoff, refuses to retry when the durable outbox source is
missing, and records the scheduled retry time in immutable execution audit
lineage. The second increment persists server-derived immutable Build/Run
deadlines, clamps renewals, and terminally times out overdue workloads under
race-safe recovery. The third increment makes cancellation dispatch idempotent,
persists an immutable convergence deadline, fences late/lost worker leases, and
terminally aborts cancelled Runs. The fourth increment adds an independently
scheduled recovery process with transaction-scoped singleton ownership, bounded
`SKIP LOCKED` batches, crash-safe rollback/restart behavior, and durable health
telemetry. The fifth increment persists bounded server-owned project and worker
limits and enforces them atomically at claim time with recovery-derived release;
RUN_CANCEL remains available when project execution capacity is saturated.
The sixth increment detects stale workers from server-observed activity, fences
and retries their leases, renews healthy in-flight work, performs bounded
label-scoped runtime cleanup on failure/restart/signal, and requires persisted
cleanup recovery evidence before claims and RLS authority resume.
The seventh increment adds hardened service supervision, environment identity
separation, PostgreSQL backup/restore and migration rollback rehearsal,
versioned-object recovery canaries, aggregate recovery metrics, and SLO alerts.
The workstream is ready for its final exact-head security and merge gate.

## Remaining RDC v1 workstreams

1. Scheduler: one-time/recurring schedules, missed-run policy, duplicate
   prevention and audit history.
2. Scraping runtime: reusable controlled HTTP/browser, queue, Dataset and KV
   primitives without expanding egress authority.
3. Proxy/egress: tenant-scoped policy, credential isolation, rotation and audit.
4. Events/webhooks: signed delivery, retry/idempotency, history and failure
   disablement.
5. Observability: structured run/worker logs, diagnostics, metrics and safe
   correlation identifiers.
6. Usage controls: quotas, rate limits, concurrency and auditable failures.
7. SDK/CLI and Console: API-backed operations for all major resources.
8. Platform-wide production operations: release automation, registry/SBOM,
   capacity, disaster recovery, and environment promotion for all workstreams.
9. End-to-end acceptance and final release/security audit.

## Dependency order

`execution recovery → scheduler/runtime integration → egress and
webhooks → observability/usage controls → SDK/CLI/Console → production
operations → end-to-end release audit`.

## Permanent security gates

- PostgreSQL RLS and server-derived ownership for tenant data.
- No Agent/Chromium PostgreSQL or object-storage credentials.
- False-by-default worker capabilities bound to ACTIVE unexpired leases.
- No anonymous Dataset, KV or Queue access; signed resource/filter-bound cursors.
- Egress, browser isolation, path/object-key safety, quotas and auditability
  must not regress.

## Test and merge gates

Every workstream requires clean diff review, migrations, targeted adversarial
tests, `ruff`, `mypy`, `pytest`, frontend lint/typecheck/tests/build, verifier
scripts, Compose validation, and exact-head GitHub CI success. A PR is merged
only after a final security review, verified mergeability and no blocking review
threads; its feature branch is preserved.

## Definition of done

RDC v1 is complete only when every listed workstream is implemented and
documented; API, worker and console paths are coherent; migrations/RLS/security
invariants pass; the authenticated end-to-end flow (Agent → Queue → Run →
controlled worker → Dataset/KV → logs/results) passes, including cross-tenant
denial tests; production recovery docs exist; and final-main CI plus the final
security audit are green.
