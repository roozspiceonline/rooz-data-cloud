# Rooz Data Cloud — Phase 1N merge candidate

Rooz Data Cloud Phase 1N adds the first durable structured-result primitive:
tenant-scoped, append-only Datasets bound to immutable Run and AgentVersion
lineage.

The phase now includes strict `rdc.dataset-append/v1`, PostgreSQL RLS,
idempotent append receipts, monotonic sequence allocation, Dataset quotas,
lease-scoped worker append, signed DatasetItem pagination and bounded canonical
JSONL export.

Worker Dataset writes remain behind the independent false-by-default gate:
`RDC_SANDBOX_CANARY_DATASET_WRITES_ENABLED=false`. The worker path requires an
ACTIVE unexpired `RUN_START` lease, exact configured AgentVersion and worker,
and explicit `DATASET_APPEND` capability. Agent and Chromium containers never
receive worker, lease or PostgreSQL credentials.

Dataset item pages are signed and Dataset-bound, with a maximum page size of
200. Whole-Dataset JSONL export is authenticated, separately scoped by
`dataset.export`, audited, limited to 10,000 items and 16 MiB, and never
public. Larger Datasets must be consumed through cursor pagination.

The previous Phase 1M merge candidate established the controlled browser
navigation boundary. `RDC_SANDBOX_CANARY_BROWSER_LIVE_NAVIGATION_ENABLED=false`
remains false by default. Agent containers and Chromium remain `--network none`.
General untrusted browser execution remains release-blocked.

PR #52 remains DRAFT and unmerged until the full Phase 1N exact-head
authoritative CI is green and the Product Owner explicitly says
`approve Phase 1N merge`. The feature branch must be preserved.
