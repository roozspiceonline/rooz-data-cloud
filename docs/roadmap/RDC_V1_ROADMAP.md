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

## Active work

| Workstream | Status | Dependency |
| --- | --- | --- |
| Phase 1P: Request Queue | Implemented — final merge gate pending | Runs, worker leases, Dataset and KV controls |

Phase 1P supplies strict protocol validation; Queue/request/immutable-history
persistence under command-specific tenant and lease-scoped worker RLS;
race-safe claim/reclaim/terminal transitions; idempotency; a false-by-default
worker path; authenticated bounded reads with filter-bound signed cursors;
tenant-bound audit events; adversarial tests; threat model; and runbook. It
becomes complete only after PR #56 is merged and the exact merged commit is
verified.

## Remaining RDC v1 workstreams

1. Production execution lifecycle: retries, timeouts, cancellation, stale lease
   and crash recovery, bounded concurrency.
2. Scheduler: one-time/recurring schedules, missed-run policy, duplicate
   prevention and audit history.
3. Scraping runtime: reusable controlled HTTP/browser, queue, Dataset and KV
   primitives without expanding egress authority.
4. Proxy/egress: tenant-scoped policy, credential isolation, rotation and audit.
5. Events/webhooks: signed delivery, retry/idempotency, history and failure
   disablement.
6. Observability: structured run/worker logs, diagnostics, metrics and safe
   correlation identifiers.
7. Usage controls: quotas, rate limits, concurrency and auditable failures.
8. SDK/CLI and Console: API-backed operations for all major resources.
9. Production operations: deployment, health/readiness, backups, restore,
   migration rollback and environment separation.
10. End-to-end acceptance and final release/security audit.

## Dependency order

`Request Queue → execution recovery → scheduler/runtime integration → egress and
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
