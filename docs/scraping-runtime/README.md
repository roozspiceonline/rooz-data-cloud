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

Queue Runs still cannot combine browser, Dataset, KV, caller-supplied web-fetch,
or legacy `_rdc_web_requests` intent. Composed Dataset/KV output and controlled
Queue-bound browser acquisition remain later scraping-runtime increments.

A strict `rdc.request-queue-binding-receipt/v3` intent is also available for an
Agent version declaring `requestQueue=true`, `browser=true`, and
`network=web-egress`. It binds the Queue, Agent version, browser policy, and
browser-egress policy but always persists as DRAFT with
`dispatch_enabled=false`; no worker capability or live browser execution is
issued by this foundation.

The trusted worker boundary now also defines the only admissible Queue/browser
acquisition plan: one `goto` to the validated claimed HTTPS URL followed by one
bounded `html` extraction. The normalized `rdc.queue-browser-result/v1`
envelope binds the Queue and request identifiers to the validated browser
navigation result and never contains the claim token. Caller input reserves
`_rdc_queue_browser` for this future worker-produced envelope. This protocol is
deliberately inert while the v3 receipt remains non-dispatching.

The independently false-by-default API and worker setting
`RDC_SANDBOX_CANARY_REQUEST_QUEUE_BROWSER_ENABLED` is now defined, and the
control plane can derive an exact v3 worker capability only when both stored
browser-policy digests match current trusted policy and the v3 receipt is
dispatch-enabled. The current Run path still writes `dispatch_enabled=false`,
so this capability cannot yet be issued; activation and execution wiring remain
the next increment.

The feature remains disabled unless both API and worker use
`RDC_SANDBOX_CANARY_REQUEST_QUEUE_ENABLED=true`, the sandbox master gate and
canary activation are enabled, and the exact worker has
`REQUEST_QUEUE_ACCESS`.

Brokered Queue HTTP additionally requires
`RDC_SANDBOX_CANARY_REQUEST_QUEUE_HTTP_ENABLED=true` and the existing web-egress
gate and exact hostname allowlist in both the API and worker environments.
