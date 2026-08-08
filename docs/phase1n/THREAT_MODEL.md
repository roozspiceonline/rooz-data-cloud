# Phase 1N Threat Model

Phase 1N assumes Agent output and scraped Dataset content are hostile.

## Core controls

- strict bounded `rdc.dataset-append/v1`
- tenant-scoped Dataset/DatasetItem RLS
- server-derived ownership
- immutable append receipts
- replay-safe idempotency
- transactional sequence allocation
- item and byte quotas
- immutable DatasetItems and append receipts

## Increment 4 worker-path threats

### Credential exfiltration

The Agent must never receive worker tokens, lease tokens or database credentials.
The worker reads Agent output only after sandbox execution and forwards it
itself.

### Stolen or stale worker request

Internal append requires both worker authentication and an ACTIVE,
unexpired lease token. RLS independently requires an ACTIVE matching
`RUN_START` lease for the current worker.

### Cross-Run Dataset targeting

The worker does not submit a Dataset ID. The control plane resolves or creates
only the `default` Dataset belonging to the lease's exact Run.

### Capability escalation

`dataset=true` requires the sandbox master execution gate, canary activation
mode, independent Dataset-write gate, exact configured AgentVersion, exact
configured worker, explicit `DATASET_APPEND`, non-browser `RUN_START` and the
immutable capability receipt. Any mismatch fails closed.

### Replay and retry

The internal path reuses Increment 3's Dataset-scoped idempotency receipt,
request digest, Dataset row lock, sequence allocation and quotas.

### RLS overreach

Worker Dataset policies are operation-specific. Dataset DELETE, DatasetItem
UPDATE/DELETE and append-receipt UPDATE/DELETE remain unavailable.

## Increment 5 read/export threats

### Cursor substitution

DatasetItem cursors are HMAC signed and contain the Dataset ID plus monotonic
sequence. Reusing a cursor against another Dataset or tampering with its
sequence fails as `INVALID_CURSOR`.

### Unbounded enumeration

DatasetItem page size remains limited to 200. Reads use sequence-keyset
pagination rather than caller-controlled offsets.

### Export memory exhaustion

Whole-Dataset export is refused above 10,000 items or 16 MiB encoded JSONL.
Larger Datasets must be consumed through cursor pages.

### Corrupt or inconsistent export

Before export, the service verifies persisted item count and exact monotonic
sequence continuity. JSONL is generated with the canonical Dataset encoder and
the response carries a SHA-256 digest.

### Unauthorized exfiltration

Export requires authenticated Dataset access plus the separate
`dataset.export` permission. Session export is CSRF protected. Public and
unauthenticated Dataset export remain disabled.

### Provenance loss

Every successful export emits `dataset.exported` audit lineage including Run,
AgentVersion, item count, encoded byte size and SHA-256.

## Phase 1N completion conditions

- paginated item reads with bounded page sizes: implemented
- bounded export/download: implemented
- audit verification of worker append lineage: preserved
- export audit lineage: implemented
- final status/documentation update: implemented
- exact-head authoritative CI: required before merge readiness
