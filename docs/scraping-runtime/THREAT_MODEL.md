# Scraping Runtime Threat Model

Queue URLs, user data, Agent input/output, and Agent exit behavior are hostile.
The API derives organization and Project from the immutable Agent version and
accepts only a Queue ID. A same-ID lookup constrained by organization and
Project hides cross-tenant resources with 404.

The durable binding receipt covers the normalized Queue binding and immutable
Agent version. Claim-time activation independently recomputes an exact
Run/Agent/worker/Queue capability. Internal claim and completion also compare
the requested Queue to that capability and enforce lease tenancy, active claim
ownership, token equality, and expiry under row locks.

The worker independently validates response fields, UUIDs, HTTPS hostname URL,
JSON depth/size, attempt count, and Queue scope. IP literals and credentialed
URLs fail closed. It removes the claim token before mounting Agent input. Agent
containers retain `--network none` and receive no worker, lease, database, or
object-storage credentials.

Brokered Queue HTTP treats the claimed URL, DNS, redirects, headers, and body as
hostile. Only the trusted worker can derive the single GET, and it must use the
existing egress broker with exact operator hostname allowlisting, public address
resolution, address pinning, redirect revalidation, safe headers, identity
encoding, bounded response bytes, and bounded timeouts. The v2 Run binding and
lease capability bind the current egress-policy digest. Caller input cannot add
legacy or versioned web requests, and the Agent container remains networkless.

Queue capability composition remains deliberately narrow. Dataset access
requires a separate false-by-default composition
receipt and exact v4 Queue/v2 Dataset capabilities. A successful Agent output
is validated and persisted under a server-derived request idempotency key before
the claim becomes HANDLED; a
Dataset failure marks the claim FAILED with a generic code. If persistence
succeeds but Queue completion is interrupted, a retry is safe because Dataset
idempotency and digest conflict checks prevent duplicate or divergent writes.
KV access requires its own false-by-default composition gate and exact v5
Queue/v2 KV capabilities. The API validates and digests read intent; the worker
never exposes lease or claim tokens, derives mutation idempotency from the
validated Queue request UUID and bounded mutation index, and persists mutations
before HANDLED. A retry therefore replays the same keys, while the existing KV
request-fingerprint and optimistic-version checks reject divergent or racing
writes. Read and mutation failures complete the claim as FAILED with generic
codes before the Run terminal transition. Queue, Run, and Run-scoped store
tenancy are independently rechecked by the internal APIs.
Web egress is valid only for independently
gated one-claim Queue HTTP or Queue/browser acquisition. Queue/browser uses a
fixed claim-derived plan, independently reconstructed browser and egress-policy
digests, a networkless Chromium container behind the bounded Unix gateway, and
a networkless Agent container. The claim token never enters either untrusted
input envelope. A worker crash may delay the request only until its bounded
claim expiry; the existing reclaim transition supplies immutable evidence.
Logs and audit details must not include URL, user data, response content, claim
tokens, or Agent output. Browser failures use only the generic
`QUEUE_BROWSER_NAVIGATION_FAILED` code and bounded summary.
