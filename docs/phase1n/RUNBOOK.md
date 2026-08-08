# Phase 1N Operator Runbook

## Increment 4 state

Worker Dataset append is wired but remains disabled by default.

```text
RDC_SANDBOX_CANARY_DATASET_WRITES_ENABLED=false
```

Do not enable this gate unless the sandbox master gate is enabled, activation
mode is `canary`, and one immutable AgentVersion plus one worker name are
configured.

The worker must be registered with `DATASET_APPEND`.

## Worker append protocol

A Dataset-enabled Agent emits its normal Run output as:

```json
{
  "schema_version": "rdc.dataset-append/v1",
  "idempotency_key": "run-123:batch-1",
  "items": [{"example": "value"}]
}
```

The worker:

1. keeps the Agent container network-isolated under the existing sandbox model;
2. reads the bounded output file after Agent execution;
3. validates `rdc.dataset-append/v1` locally;
4. calls the private lease-scoped endpoint using its worker token and lease
   token;
5. never passes those credentials into the Agent container.

Internal endpoint:

`POST /internal/v1/leases/{lease_id}/dataset-append`

The endpoint is excluded from public OpenAPI.

## Capability receipt

The claim must contain exact
`rdc.dataset-worker-capability/v1` data bound to:

- Run ID
- AgentVersion ID
- worker name
- default Dataset name
- append schema and size limits
- Dataset total item/byte limits

The control plane recomputes this receipt at append time. Gate disablement,
lease expiry, worker change, AgentVersion change or receipt mismatch fails
closed.

## RLS

Increment 4 adds only the worker policies needed by the API transaction:

- Dataset SELECT
- Dataset INSERT
- Dataset UPDATE for counters/sequence
- DatasetItem INSERT
- DatasetAppendReceipt SELECT
- DatasetAppendReceipt INSERT

Every policy requires an ACTIVE, unexpired `RUN_START` lease for the exact
current worker and matching organization/project/Run.

There is no worker DELETE policy.

## Stop conditions

Stop if any implementation:

- sends worker or lease tokens into Agent input/environment;
- sends database credentials into Agent or Chromium;
- accepts a Dataset ID from the worker;
- permits a non-default cross-Run Dataset target;
- skips worker-side protocol validation;
- skips control-plane receipt recomputation;
- permits an expired/non-`RUN_START` lease;
- adds Dataset worker DELETE access;
- bypasses Increment 3 idempotency/quota/sequence logic;
- weakens Phase 1M network isolation.
