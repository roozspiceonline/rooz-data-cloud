# Phase 1N — Tenant-scoped Dataset Protocol & Durable Result Storage

Phase 1N adds the first durable structured Run-output primitive required for an
Apify-class scraping platform.

## Increment 1 — protocol foundation

Established the strict `rdc.dataset-append/v1` bounded JSON-object contract,
canonical SHA-256 digest, idempotency key and payload limits.

## Increment 2 — Dataset metadata persistence + RLS

Added `control.datasets`, `control.dataset_items`, server-derived Run lineage,
tenant triggers, PostgreSQL RLS, authenticated metadata routes and
`dataset.create` / `dataset.read`.

## Increment 3 — idempotent append + quotas

Increment 3 activates **control-plane Dataset item append**:

- `POST /api/v1/datasets/{dataset_id}/items`
- `dataset.write` permission
- exact `rdc.dataset-append/v1` server revalidation
- API/worker canonical digest parity verification
- `control.dataset_append_receipts`
- unique `(dataset_id, idempotency_key)`
- immutable request SHA-256 binding
- Dataset row lock before replay/sequence/quota decisions
- exact replay returns the original receipt without duplicate items
- mismatched replay fails with `DATASET_IDEMPOTENCY_CONFLICT`
- monotonic sequences allocated transactionally
- each DatasetItem binds to its append receipt
- DatasetItem and append-receipt mutation blocked by database triggers
- maximum 100,000 items per Dataset
- maximum 268,435,456 encoded item bytes per Dataset
- existing protocol limits remain 100 items / 65,536 bytes per item /
  262,144 bytes per append envelope
- first append writes `dataset.items_appended` audit metadata without item
  content

## Current capability boundary

```text
Dataset request contract          available
Dataset metadata persistence      available
Dataset metadata API              available
Dataset item append API           available (authenticated control plane)
Dataset append idempotency        enforced
Dataset sequence allocation       transactional
Dataset item/byte quotas          enforced
DatasetItem mutation              database-blocked
worker Dataset writes             disabled
worker Dataset RLS policy         absent
Agent direct Postgres access      prohibited
KV Store                           out of scope (Phase 1O)
Request Queue                      out of scope (Phase 1P)
```

No worker or Agent can write Dataset records yet. Increment 4 will add a narrow
worker-to-control-plane append capability without giving Agent/browser
containers database credentials.

## Planned increments

1. Protocol foundation.
2. Dataset/DatasetItem persistence, RLS and metadata API.
3. Idempotent append transaction, quotas and monotonic sequences.
4. Controlled worker append path with no Agent database credentials.
5. Paginated item reads, bounded export, audit expansion and final hardening.

PR #52 remains DRAFT until the full Phase 1N scope is exact-head green.
