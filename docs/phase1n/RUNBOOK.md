# Phase 1N Operator Runbook

## Increment 2 state

Dataset metadata persistence and authenticated metadata APIs are available.
Dataset item writes remain intentionally disabled.

Expected state:

```text
rdc.dataset-append/v1           available
control.datasets                present + RLS
control.dataset_items           present + RLS
Dataset metadata REST routes    available
Dataset item append route       absent
worker Dataset append           absent
Agent database credentials      absent
direct Agent Postgres access    absent
```

## Metadata routes

- `POST /api/v1/runs/{run_id}/datasets`
- `GET /api/v1/projects/{project_id}/datasets`
- `GET /api/v1/datasets/{dataset_id}`

Dataset creation derives organization/project/Run/Agent/AgentVersion lineage
from the already-authorized Run. Ownership identifiers are not accepted in the
request body.

## RLS requirements

Both `control.datasets` and `control.dataset_items` must have row-level
security enabled and tenant policies tied to:

- `security.rdc_current_org_id()`
- `security.rdc_has_org_membership(organization_id)`

The Dataset resolver is `security.rdc_dataset_org(uuid)`.

There is no worker Dataset RLS policy in Increment 2 because worker writes are
not yet activated.

## Safe protocol limits reserved for Increment 3 append

- items per append: 1–100
- encoded item bytes: <= 65,536
- encoded batch bytes: <= 262,144
- JSON nesting depth: <= 32
- idempotency key: 1–128 characters, restricted safe alphabet

## Stop conditions

Stop Phase 1N work if an implementation:

- accepts organization/project/Run ownership from Dataset creation payloads
- gives Agent or browser containers direct PostgreSQL credentials
- adds a worker Dataset RLS policy before the controlled append protocol
- permits cross-project Dataset access
- permits arbitrary DatasetItem mutation
- activates Dataset item writes before idempotency/quota/sequence guarantees
- weakens the Phase 1M network isolation model

## Next increment

Add idempotent Dataset item append with a Dataset-scoped idempotency receipt,
transactional sequence allocation, record/byte quotas, canonical request
digest binding, and replay-safe behavior. Worker writes remain disabled until
Increment 4.
