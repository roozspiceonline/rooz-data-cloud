# Phase 1N Operator Runbook

## Worker Dataset state

Worker Dataset append is wired but remains disabled by default.

```text
RDC_SANDBOX_CANARY_DATASET_WRITES_ENABLED=false
```

Do not enable this gate unless the sandbox master gate is enabled, activation
mode is `canary`, and one immutable AgentVersion plus one worker name are
configured. The worker must be registered with `DATASET_APPEND`.

## Worker append protocol

A Dataset-enabled Agent emits its normal Run output as a strict
`rdc.dataset-append/v1` envelope. The worker validates that bounded output after
sandbox execution and forwards it through:

`POST /internal/v1/leases/{lease_id}/dataset-append`

The private endpoint requires worker authentication and an ACTIVE, unexpired `RUN_START` lease.
The Agent never receives worker tokens, lease tokens or database credentials.

The worker does not supply a Dataset ID. The control plane resolves only the
Run-scoped `default` Dataset and reuses the Increment 3 idempotency, quota and
sequence transaction.

## RLS

Worker policies are limited to Dataset SELECT/INSERT/counter UPDATE,
DatasetItem INSERT and DatasetAppendReceipt SELECT/INSERT. Every worker policy
is bound to the exact active lease. There is no worker DELETE policy.

## DatasetItem reads

Use:

`GET /api/v1/datasets/{dataset_id}/items?limit=100&cursor=...`

The page limit is 1–200. The cursor is HMAC signed, bound to the exact Dataset
ID and carries only the last monotonic sequence. A cursor from another Dataset
fails with `INVALID_CURSOR`.

There is no item PUT, PATCH or DELETE route.

## Bounded export

Use:

`POST /api/v1/datasets/{dataset_id}/export`

with body:

```json
{"format":"jsonl"}
```

Export requires the explicit `dataset.export` permission. Session requests are
CSRF protected. Output is `application/x-ndjson` with SHA-256 and item-count
response headers.

Whole-Dataset export limits:

```text
items       <= 10,000
encoded     <= 16,777,216 bytes
format      jsonl only
public      disabled
```

If a Dataset exceeds either bound, use signed cursor pagination instead. Export
also fails closed if persisted item count or monotonic sequence continuity does
not match Dataset metadata.

Every successful export records `dataset.exported` with Run, AgentVersion,
item count, byte size and SHA-256 lineage.

## Stop conditions

Stop if any implementation:

- sends worker or lease tokens into Agent input/environment;
- sends database credentials into Agent or Chromium;
- accepts a Dataset ID from the worker;
- permits a non-default cross-Run worker Dataset target;
- skips worker-side protocol validation;
- skips control-plane receipt recomputation;
- permits an expired/non-`RUN_START` worker lease;
- adds Dataset worker DELETE access;
- bypasses Increment 3 idempotency/quota/sequence logic;
- exposes an unsigned or cross-Dataset item cursor;
- raises export limits without explicit review;
- adds public or unauthenticated Dataset export;
- adds item UPDATE/PATCH/DELETE;
- weakens Phase 1M network isolation.
