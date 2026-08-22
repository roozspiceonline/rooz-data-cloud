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

Queue capability composition is deliberately exclusive in this increment.
Dataset, KV, browser, and network capabilities cannot accompany Request Queue
access. A worker crash may delay the request only until its bounded claim
expiry; the existing reclaim transition supplies immutable evidence. Logs and
audit details must not include URL, user data, claim tokens, or Agent output.
