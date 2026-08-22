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

Queue capability composition remains deliberately narrow. Dataset, KV, and
browser cannot accompany Queue access; web egress is valid only for the
independently gated one-claim/one-GET Queue HTTP mode. A worker crash may delay
the request only until its bounded claim expiry; the existing reclaim
transition supplies immutable evidence. Logs and audit details must not include
URL, user data, response content, claim tokens, or Agent output.
