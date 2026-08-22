# Phase 1P runbook

Apply migration `20260809_0015` before enabling request queue APIs. Verify that
all four queue tables have RLS enabled and the `rdc_request_queue_org` resolver
exists. Confirm tenant policies are command-specific, Queue/request worker
policies require an ACTIVE unexpired `RUN_START` lease for the same organization
and project, and there is no tenant update policy on requests, transitions, or
enqueue receipts. Direct mutation of request identity, receipts, transitions,
or audit events must fail.

For an enqueue replay, return the original receipt only when its canonical
request digest matches. Treat a digest mismatch or cross-tenant lookup as an
incident and retain immutable transition history for investigation.

Authenticated queue readers can retrieve bounded transition history. Treat it
as forensic data: it is immutable and should not be edited or deleted.
Project Queue listings and transition history return at most 200 records and a
signed `next_cursor`. Preserve the original project, Queue, state, and optional
request filter when following a cursor. Treat `INVALID_CURSOR` responses as a
client replay/tampering signal; never decode or rewrite cursors outside the API.

Monitor the immutable audit stream for `request_queue.request_enqueued`,
`request_queue.request_claimed`, `request_queue.request_reclaimed`,
`request_queue.request_handled`, and `request_queue.request_failed`. Correlate
an event through its request ID, request resource ID, Queue ID, actor, and
transition history. Audit payloads intentionally omit URLs, user data, claim
tokens, and failure summaries. A rejected audit tenancy trigger or attempted
audit mutation is a security incident.

Worker Queue access remains off unless sandbox execution, canary activation,
and `RDC_SANDBOX_CANARY_REQUEST_QUEUE_ENABLED` are all enabled. Enable it only
for the pinned canary and monitor stale-claim, retry, and tenancy failures.
Queue-bound Run input must carry the server-persisted binding receipt and the
lease snapshot must carry the exact Run/worker/Queue capability. Never expose
the claim token to Agent input or allow a worker to select another Queue.

CI runs the migration against PostgreSQL and exercises simultaneous claims,
cross-project and cross-request trigger rejection, lifecycle audit lineage,
tenant RLS visibility and mutation denial, immutable request identity and
receipts, audit tenancy guards, and audit immutability. Rollback removes the
Phase 1P policies and audit/receipt triggers before receipts and transition
rows, then removes requests and queues so foreign-key dependencies remain
valid.
