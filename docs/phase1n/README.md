# Phase 1N — Tenant-scoped Dataset Protocol & Durable Result Storage

Phase 1N adds durable append-only Run results without giving Agent or browser
containers database credentials.

## Completed increments

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

### Increment 4 — controlled worker append path

Added an independent false-by-default Dataset write gate, explicit
`DATASET_APPEND` worker capability, `rdc.dataset-worker-capability/v1`, worker
side protocol validation, a private ACTIVE-lease-scoped append endpoint and
operation-specific worker RLS. Worker Dataset append default           disabled.

### Increment 5 — bounded reads, export and final hardening

DatasetItem reads use a signed HMAC cursor bound to the exact Dataset ID and
monotonic sequence. Page size is limited to 1–200 records.

Whole-Dataset export is:

- authenticated and separately scoped with `dataset.export`;
- CSRF protected for session users;
- canonical JSONL only;
- limited to 10,000 items;
- limited to 16 MiB including JSONL newlines;
- rejected on sequence gaps or item-count inconsistency;
- SHA-256 identified in the response;
- recorded as `dataset.exported` in the audit log;
- never public or unauthenticated.

Datasets above either whole-export limit remain fully readable through signed
cursor pagination.

## Final capability boundary

```text
Dataset metadata API                    available
control-plane Dataset append            available
DatasetItem cursor pagination           available / signed / Dataset-bound
bounded JSONL export                    available / authenticated / audited
public Dataset export                   disabled
worker Dataset append code              wired
worker Dataset append default           disabled
worker Dataset capability               explicit DATASET_APPEND
worker Dataset RLS                      active-lease scoped
Agent direct PostgreSQL                 prohibited
Chromium direct PostgreSQL              prohibited
arbitrary Dataset item mutation         prohibited
DatasetItem UPDATE/PATCH/DELETE         absent
KV Store                                out of scope (Phase 1O)
Request Queue                           out of scope (Phase 1P)
```

Agent direct PostgreSQL                 prohibited.
General untrusted execution remains release-blocked. The implementation PR
remains DRAFT until final exact-head authoritative CI is green and explicit
Phase 1N merge approval is received.
