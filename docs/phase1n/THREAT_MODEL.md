# Phase 1N Threat Model

Phase 1N assumes Agent output and scraped Dataset content are hostile.

## Existing controls

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

`dataset=true` requires:

- sandbox master execution gate
- canary activation mode
- independent Dataset-write gate
- exact configured AgentVersion
- exact configured worker
- worker `DATASET_APPEND` capability
- non-browser `RUN_START`
- immutable claim capability receipt

Any mismatch fails closed.

### Replay and retry

The internal path reuses Increment 3's Dataset-scoped idempotency receipt,
request digest, Dataset row lock, sequence allocation and quotas. A worker
retry cannot duplicate an already accepted batch with the same key/digest.

### RLS overreach

Worker Dataset policies are operation-specific. Dataset DELETE, DatasetItem
UPDATE/DELETE and append-receipt UPDATE/DELETE are not granted by Increment 4.
Existing database immutability triggers remain mandatory.

## Mandatory before Phase 1N completion

- paginated item reads with bounded page sizes
- bounded export/download
- audit verification of worker append lineage
- final status/documentation update
- exact-head authoritative CI green
