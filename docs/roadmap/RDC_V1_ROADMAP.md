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
| Production Execution Lifecycle / Recovery | Complete | PR #57, migrations `0016`–`0020`, RDC CI #198 |
| Scheduler | Complete | PR #66, migration `0021`, RDC CI #206 |
| Scraping runtime | Complete baseline | PR #76, RDC CI #220 and main CI #221; Queue-bound offline/HTTP/browser acquisition with Dataset/KV composition |

## Active work

| Workstream | Status | Dependency |
| --- | --- | --- |
| Proxy/egress | Tenant policy metadata, immutable revisions, activation/disable lifecycle, credential references and RLS implemented | Scraping runtime and write-only Project secrets |

The merged recovery workstream centralizes server-owned retry eligibility and
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
The merged Scheduler foundation adds persistent one-time and fixed-interval
schedules, bounded missed-run behavior, duplicate-safe Run creation, immutable
trigger history, tenant RLS and a singleton-safe dispatch service.

The first scraping-runtime increment binds a Run to one server-verified tenant
Queue, issues an exact lease-scoped capability, independently validates the
claim in the worker, withholds claim tokens from Agent input, and completes one
request per Run. It remains false-by-default. The second increment
derives one Queue-claimed GET through the existing bounded
HTTPS egress broker, binds its policy digest into v2 Run/lease receipts, rejects
caller web-intent injection, and keeps Agent networking disabled. The third
increment adds gated v3 Queue/browser receipts and exact worker capabilities,
derives one bounded navigation from the validated Queue claim, runs Chromium
behind the Unix egress gateway, withholds the claim token, and then executes the
Agent with networking disabled. The fourth increment composes the existing
idempotent Dataset append boundary with every Queue acquisition mode and
requires Dataset persistence before Queue HANDLED completion. The fifth
increment composes KV reads and idempotent mutations with all Queue acquisition
modes and requires KV persistence before Queue HANDLED completion.

The first proxy/egress increment persists server-owned Project policy metadata
and immutable revisions containing exact normalized HTTPS hosts, GET/HEAD
methods and bounded request/byte/redirect/timeout budgets. Optimistic,
row-locked activation and disable transitions select an exact revision;
credential material remains in write-only Project secrets and API responses
expose only whether a reference is configured. PostgreSQL RLS and reference
triggers independently enforce organization, Project, revision and secret
tenancy. Live Run/worker binding, credential delivery/rotation and broker
enforcement remain active work and the existing canary allowlist is unchanged.

## Remaining RDC v1 workstreams

1. Proxy/egress: bind active revisions to Runs/workers and broker enforcement;
   implement credential delivery/rotation without plaintext exposure.
2. Events/webhooks: signed delivery, retry/idempotency, history and failure
   disablement.
3. Observability: structured run/worker logs, diagnostics, metrics and safe
   correlation identifiers.
4. Usage controls: quotas, rate limits, concurrency and auditable failures.
5. SDK/CLI and Console: API-backed operations for all major resources.
6. Platform-wide production operations: release automation, registry/SBOM,
   capacity, disaster recovery, and environment promotion for all workstreams.
7. End-to-end acceptance and final release/security audit.

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
