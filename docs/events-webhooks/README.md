# Events and Webhooks

Migration `20260829_0029` establishes the Events foundation without enabling
outbound webhook delivery. `control.events` stores immutable `rdc.event/v1`
envelopes for the initial `build.created` and `run.created` types. Each event is
bound to one exact Project and one exact same-tenant Build or Run. PostgreSQL
derives organization ownership from the Project and revalidates payload lineage
against the subject row before insert.

Run and Build creation append their event in the same database transaction as
the resource, outbox, idempotency record and audit event. The unique Project,
type and subject key makes an exact retry return the original event; changed
content fails with `EVENT_REPLAY_CONFLICT`.

`GET /api/v1/projects/{project_id}/events` requires `event.read`, returns at
most 100 events, optionally filters by the two allowlisted types, and orders by
`occurred_at DESC, id DESC`. Its signed cursor is bound to the Project and exact
filter. Event payloads are strict per-type objects, limited to 16 KiB in Python
and PostgreSQL, recursively bounded, and reject credential-shaped keys.

The event-persistence increment contains no webhook delivery attempt, retry
scheduler, delivery worker, Agent/Chromium capability, or outbound HTTP path.

Migration `20260830_0030` adds destination metadata without broadening that
network boundary. Destinations accept canonical HTTPS hostnames, reject IP
literals, credentials, fragments, non-443 ports and local/internal suffixes,
and remain `PENDING_VERIFICATION` or `DISABLED`. Signing secrets use the
existing envelope-encrypted ProjectSecret custody, are write-only in the API,
and rotate with optimistic version fencing. PostgreSQL derives organization
ownership, validates the exact same-Project secret and applies Project RLS.
There is still no activation or outbound delivery path.

Migration `20260830_0031` adds durable delivery intent without performing a
delivery. Each destination/event pair is idempotent. Claims use PostgreSQL row
locks, `SKIP LOCKED`, expiring UUID fences and bounded attempts. Retry waits use
deterministic capped backoff; exhaustion becomes `DEAD_LETTERED`. Every state
change appends a sequenced immutable transition snapshot under Project RLS.
No public route, HTTP client, DNS resolver or signing-secret decryption path is
connected to this lifecycle.

Migration `20260831_0032` adds a false-by-default trusted delivery canary. A
global bounded `SKIP LOCKED` claim function persists only a SHA-256 claim-token
digest and returns the raw token only to the claiming process. Delivery rows
snapshot the endpoint and exact signing-secret version at enqueue time. A
claim-scoped security-definer loader releases encrypted material only while the
exact claim is live and the destination and secret version remain valid.

The separate `webhook-delivery-runner` decrypts only inside trusted process
memory, signs canonical event bytes with timestamped HMAC-SHA256, zeroes the
plaintext byte buffer, and completes through the same claim fence. Its direct
TLS transport resolves and validates the complete public DNS set, connects to
one exact IP with hostname-verified TLS/SNI, validates the connected peer, and
never uses ambient proxies, redirects, retries, or address failover. Request,
response, timeout, concurrency, claim, and attempt bounds are enforced. The
runner receives only the database and Project-secret master key; it receives no
Redis, S3, session, API-key, worker, or lease credentials.

`RDC_WEBHOOK_DELIVERY_CANARY_ENABLED` remains false by default. This canary is
limited to `PENDING_VERIFICATION` destinations. General activation, operator
replay history, and automatic failure disablement remain separate work.
