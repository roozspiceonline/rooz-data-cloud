# Scraping Runtime

The first RDC v1 scraping-runtime increment connects a Run to exactly one
tenant Request Queue without giving Agent code direct control-plane authority.
A caller supplies only a Queue resource ID in the strict `rdc.run-queue/v1`
Run input. The API resolves that Queue against the immutable Agent version's
server-derived organization and Project, then persists a binding digest and
receipt in the Run input reference.

An eligible sandbox worker receives a false-by-default, lease-scoped
`rdc.request-queue-worker-capability/v1` receipt. It may claim at most one
request from the exact bound Queue, inject a normalized claim into the Agent's
read-only input as `_rdc_queue`, and complete that claim after the Agent exits.
The claim token is retained by the trusted worker and never enters the Agent
container.

This increment intentionally remains offline. Queue-enabled Agent versions
must declare `network=none`, `browser=false`, `dataset=false`, and
`keyValueStore=false`. Controlled HTTP/browser fetching and composed
Dataset/KV output are the next scraping-runtime increments; they must reuse
the existing broker/browser and storage protocols without widening egress.

The feature remains disabled unless both API and worker use
`RDC_SANDBOX_CANARY_REQUEST_QUEUE_ENABLED=true`, the sandbox master gate and
canary activation are enabled, and the exact worker has
`REQUEST_QUEUE_ACCESS`.
