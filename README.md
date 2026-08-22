# Rooz Data Cloud

Rooz Data Cloud is a tenant-isolated scraping and automation control plane.
The merged baseline includes identity and authorization, Projects, immutable
Agent versions, source/build and Run lifecycle, isolated worker execution,
controlled web and browser canaries, durable Dataset results, and versioned
Key-Value Store state under PostgreSQL RLS.

All untrusted Agent and browser execution remains release-blocked. PostgreSQL,
object-storage, worker and lease credentials never enter Agent or Chromium
containers; worker capabilities are false-by-default and lease-scoped.

Phase 1P, tenant-scoped Request Queues, is complete after PR #56 and exact-head
RDC CI #189. It adds bounded idempotent enqueue, race-safe
claim/reclaim/completion, immutable transition and audit lineage, signed reads,
and tenant/lease-scoped PostgreSQL RLS without weakening existing tenancy,
egress, Dataset, or KV protections. See [the Phase 1P documentation](docs/phase1p/README.md)
and [the RDC v1 roadmap](docs/roadmap/RDC_V1_ROADMAP.md) for security controls,
remaining work, and release gates. Production Execution Lifecycle / Recovery is
now active with server-owned bounded retry, immutable workload and cancellation
deadlines, lease fencing, cancellation convergence, and an independently
scheduled singleton-safe recovery service with durable health telemetry.
Persisted project limits, server-capped worker limits, and atomic claim-time
admission now prevent concurrent BUILD/RUN_START oversubscription while keeping
RUN_CANCEL available to drain saturated projects.
The recovery scheduler also detects stale workers, fences their active leases,
and requires label-scoped container/workspace cleanup evidence before a
restarted worker can resume claims.
Production service supervision, environment separation, database and object
restore drills, aggregate recovery metrics, and SLO alert contracts completed
the execution-recovery workstream in PR #57 with exact-head RDC CI #198.

The Scheduler workstream completed in PR #66 with exact-head RDC CI #206. It
persists tenant-scoped one-time and fixed-interval Run schedules, bounded
missed-run policies, immutable trigger history and duplicate-safe singleton
dispatch. See [the Scheduler documentation](docs/scheduler/README.md).

The active scraping-runtime workstream now binds one Run to one server-verified
tenant Queue through an exact lease capability. The trusted worker validates
and injects one claim without exposing its claim token or any control-plane
credential to the Agent. An independently gated mode derives one GET from the
claimed URL through the existing brokered HTTPS policy while the Agent remains
networkless. See
[the Scraping Runtime documentation](docs/scraping-runtime/README.md).
