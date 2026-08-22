# Scraping Runtime

The RDC v1 scraping-runtime foundation connects a Run to exactly one
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

The second increment permits an independently gated `network=web-egress`
Queue mode. After claiming one item, the trusted worker derives one GET from
the claimed URL and sends it through the existing pinned-address HTTPS broker.
The worker injects the normalized response as `_rdc_queue_http`; it never gives
the Agent direct networking. Operator host allowlists, public-DNS validation,
redirect revalidation, header stripping, timeouts, and byte/request budgets all
remain authoritative. The v2 binding and worker capability receipts bind the
current egress-policy digest and `brokered-http` acquisition mode.

Queue Runs still cannot combine Dataset and KV, caller-supplied web-fetch, or
legacy `_rdc_web_requests` intent. Dataset composition is independently gated: the
control plane binds the Queue receipt to the default Dataset, and the worker
must persist the validated `rdc.dataset-append/v1` output under an idempotency
key derived from the Queue request before it may mark the claim HANDLED. KV
composition uses a dedicated capability receipt.

Queue plus Key-Value Store composition is also implemented behind an
independent false-by-default gate. The API validates an optional
`_rdc_kv_read` request and binds its digest, the default Run-scoped store, the
Queue receipt, and `kv-before-queue-handled` ordering into
`rdc.request-queue-key-value-store-receipt/v1`. The worker claims first, reads
KV state through the lease-scoped API, runs the networkless Agent, and replaces
Agent-supplied mutation replay keys with `queue:<request-id>:kv:<index>` before
persistence. KV read or mutation failure marks the claim FAILED before the Run
failure is recorded; a successful claim cannot become HANDLED until every KV
mutation is durable.

A strict `rdc.request-queue-binding-receipt/v3` intent is also available for an
Agent version declaring `requestQueue=true`, `browser=true`, and
`network=web-egress`. It binds the Queue, Agent version, browser policy, and
browser-egress policy. It persists as DRAFT unless every independent Queue,
browser-navigation, web-egress, exact-version, and exact-worker canary gate is
enabled. An eligible Run is QUEUED with `dispatch_enabled=true`.

The trusted worker boundary now also defines the only admissible Queue/browser
acquisition plan: one `goto` to the validated claimed HTTPS URL followed by one
bounded `html` extraction. The normalized `rdc.queue-browser-result/v1`
envelope binds the Queue and request identifiers to the validated browser
navigation result and never contains the claim token. Caller input reserves
`_rdc_queue_browser` for this worker-produced envelope.

The independently false-by-default API and worker setting
`RDC_SANDBOX_CANARY_REQUEST_QUEUE_BROWSER_ENABLED` is now defined, and the
control plane derives an exact v3 worker capability only when both stored
browser-policy digests match current trusted policy and the v3 receipt is
dispatch-enabled. The worker independently reconstructs both policies, claims
at most one Queue request, derives the fixed navigation plan from its validated
URL, executes Chromium behind the Unix egress gateway, and then runs the Agent
with networking disabled. Browser failure marks the claim FAILED with a generic
code; Agent exit completes it through the existing token-bound lifecycle.

The feature remains disabled unless both API and worker use
`RDC_SANDBOX_CANARY_REQUEST_QUEUE_ENABLED=true`, the sandbox master gate and
canary activation are enabled, and the exact worker has
`REQUEST_QUEUE_ACCESS`.

Brokered Queue HTTP additionally requires
`RDC_SANDBOX_CANARY_REQUEST_QUEUE_HTTP_ENABLED=true` and the existing web-egress
gate and exact hostname allowlist in both the API and worker environments.
Queue/browser acquisition additionally requires
`RDC_SANDBOX_CANARY_REQUEST_QUEUE_BROWSER_ENABLED=true` plus both browser gates.
Queue plus Dataset additionally requires
`RDC_SANDBOX_CANARY_REQUEST_QUEUE_DATASET_ENABLED=true` and the existing Dataset
write gate in both API and worker environments. The v4 Queue capability and v2
Dataset capability bind the same Queue, Run, Agent version, worker and
`dataset-before-queue-handled` ordering; Agent and Chromium remain credential-
free and networkless at the persistence boundary.

Queue plus KV requires
`RDC_SANDBOX_CANARY_REQUEST_QUEUE_KEY_VALUE_STORE_ENABLED=true`, the Queue and
KV gates, and `KV_ACCESS` on the exact worker. The v5 Queue capability and v2 KV
capability bind the same Queue, Run, Agent version, worker, default store,
server-derived mutation replay scope, and completion ordering. The composition
gate can be disabled without disabling standalone Queue or KV canaries.
