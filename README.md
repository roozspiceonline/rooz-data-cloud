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
