# Phase 1N — Tenant-scoped Dataset Protocol & Durable Result Storage

Phase 1N adds durable append-only Run results without giving Agent or browser
containers database credentials.

## Verified increments

### Increment 1 — protocol foundation

Established strict `rdc.dataset-append/v1`, canonical SHA-256 request digests,
bounded JSON objects, idempotency keys and payload limits.

### Increment 2 — persistence + tenant RLS

Added `control.datasets`, `control.dataset_items`, server-derived Run lineage,
tenant triggers, PostgreSQL RLS and authenticated Dataset metadata APIs.

### Increment 3 — replay-safe control-plane append

Added `control.dataset_append_receipts`, Dataset row locking, monotonic
sequences, item/byte quotas, immutable append provenance and the authenticated
control-plane item append route.

## Increment 4 — controlled worker append path

Increment 4 wires Dataset append into the existing private execution plane.

Security properties:

- independent master gate:
  `RDC_SANDBOX_CANARY_DATASET_WRITES_ENABLED=false`
- the gate is false by default in API and worker configuration
- only `RUN_START` leases can append
- worker must carry explicit `DATASET_APPEND` capability
- exact configured canary Worker and AgentVersion are required
- browser + Dataset capability is rejected in this increment
- claim contains `rdc.dataset-worker-capability/v1`
- claim receipt is bound into the immutable lease payload digest/snapshot
- Agent output must itself be a valid `rdc.dataset-append/v1` envelope
- worker validates the envelope before forwarding
- internal append requires worker token + ACTIVE lease token
- control plane independently recomputes and compares the capability receipt
- the target is only the Run-scoped `default` Dataset
- Dataset ownership is derived from the lease and Run
- existing Increment 3 append/idempotency/quota transaction is reused
- Dataset RLS gains only ACTIVE-lease-scoped worker SELECT/INSERT/UPDATE access
  required by the API's worker-authenticated DB transaction
- no Dataset worker DELETE policy exists
- DatasetItem and append-receipt mutation triggers remain in force
- Agent and Chromium receive no worker token, lease token or Postgres
  credentials

## Current capability boundary

```text
Dataset metadata API                    available
control-plane Dataset append            available
worker Dataset append code              wired
worker Dataset append default           disabled
worker Dataset capability               explicit DATASET_APPEND
worker Dataset RLS                      active-lease scoped
Agent direct PostgreSQL                 prohibited
Chromium direct PostgreSQL              prohibited
arbitrary Dataset item mutation         prohibited
KV Store                                out of scope (Phase 1O)
Request Queue                           out of scope (Phase 1P)
```

## Next increment

Add paginated DatasetItem reads, bounded export/download, expanded audit
verification and Phase 1N final hardening. The implementation PR remains DRAFT
until full exact-head CI is green.
