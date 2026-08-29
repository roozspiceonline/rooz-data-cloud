# Proxy/Egress Policy and Runtime Binding

This increment adds authenticated, tenant-scoped Project egress-policy
metadata without widening live network access. A policy begins as `DRAFT` with
immutable revision 1. Revisions contain canonical exact hostnames, a subset of
`GET`/`HEAD`, and bounded request, response-byte, total-byte, redirect and
timeout limits. Wildcards, URL strings, IP literals, single-label names and
special-use hostnames are rejected.

Creation requires `Idempotency-Key`; a server fingerprint binds the principal,
Project, name, canonical policy digest and optional credential reference.
Activation selects one exact same-policy revision under a row lock and
`expected_version`; disable uses the same optimistic-concurrency boundary.
Rotation creates a new immutable revision and does not silently alter the
active revision. An explicit activation is required.

Credential material is never stored in policy tables. A revision may reference
one write-only `security.project_secrets` row from the same organization and
Project. Responses and audit details expose only `credential_configured`; they
never return the secret ID, ciphertext or plaintext. PostgreSQL triggers repeat
the policy/revision/secret tenancy checks below the service layer.

Public endpoints are:

- `POST/GET /api/v1/projects/{project_id}/egress-policies`
- `GET /api/v1/egress-policies/{policy_id}`
- `GET/POST /api/v1/egress-policies/{policy_id}/revisions`
- `POST /api/v1/egress-policies/{policy_id}/activate`
- `POST /api/v1/egress-policies/{policy_id}/disable`
- `GET /api/v1/projects/{project_id}/egress-health/summary`
- `GET /api/v1/projects/{project_id}/egress-health/routes`
- `GET /api/v1/projects/{project_id}/egress-credential-canaries`

Policy and revision list cursors are signed and bound to the exact Project,
status filter or policy resource; both collections are page-bounded.
Organization and Project ownership always come from authenticated resources,
never request bodies. `egress.create`, `egress.read` and `egress.update`
permissions apply to session and scoped API-key principals.

Lease-authenticated workers may append one immutable health observation through
`POST /internal/v1/leases/{lease_id}/egress-health-observations`. The body
contains only a client observation UUID and the bounded provider-neutral
evidence schema. Organization, Project, Run, lease, worker, outcome and retry
classification are server-derived. The `(lease, observation ID)` key is
idempotent: an exact replay returns the original row and changed evidence
returns `EGRESS_HEALTH_REPLAY_CONFLICT`. Targets, response content, credentials,
provider identity and route-selection instructions are not accepted or stored.
The public summary is permission-checked, tenant-RLS protected and accepts only
a 1–24 hour aggregate window; it never returns raw evidence or per-Run rows.

Each API deployment stamps a validated opaque provider and region key from
operator configuration; callers and workers cannot choose either dimension.
Migration `20260828_0024` attributes pre-existing observations to
`legacy/unknown` and preserves immutable lineage. The route aggregate releases
only groups with the configured minimum of 5–1000 observations, rejects more
than 32 dimensions in a window, and returns integer basis-point health plus
bounded outcome counts. It contains no target, raw evidence, Run/lease/worker
identifier, credential or routing decision. Neither aggregate authorizes a
retry or changes an active route.

Migration `20260828_0025` keeps the worker request/response contract unchanged
but stores accepted evidence in typed bounded columns rather than JSONB. Legacy
JSONB inserts are normalized and cleared by the database trigger. The immutable
row remains the authoritative security lineage and replay record; normal
high-volume samples no longer create a duplicate control-plane audit event.
Only the replay, Project/time and Project/route/time indexes remain because
those are the implemented read paths.

Eligible Run requests may supply only
`egress_policy: {schema_version: rdc.run-egress-policy/v1, policy_id: ...}`.
The server derives organization and Project from the authenticated Agent
version, locks the referenced policy, accepts only its current `ACTIVE`
revision, reconstructs its canonical digest, and persists the exact
policy/revision/runtime snapshot in Run input lineage. Revision IDs, digests,
specifications and credentials supplied by callers are rejected.
Known web-fetch and browser targets and methods must be subsets of that
revision at Run creation; Queue acquisition additionally requires `GET`.

The immutable `rdc.run-egress-policy-receipt/v1` binding digest is propagated
into sandbox activation and, for Queue work, the lease-scoped
`rdc.request-queue-worker-capability/v6` receipt. The trusted worker
independently reconstructs both revision and runtime digests before use. Its
configured static canary allowlist and every request/byte/redirect/timeout
budget remain a maximum ceiling: a Project policy can narrow access but cannot
widen it. The broker enforces revision methods as well as hosts and budgets.

Credential-bound revisions persist only `credential_configured=true`; the
secret reference and material never enter Run lineage, Agent input, Chromium,
activation or Queue capabilities. At execution time the lease-authenticated
trusted worker submits the policy binding digest and an ephemeral X25519 public
key. The server locks and revalidates the Run, ACTIVE policy, exact revision and
same-tenant secret before returning an AES-GCM envelope bound to the worker,
lease, Run and policy digest for at most 60 seconds. Its decrypted value is used
only as the broker's complete `Authorization` header value and is never added to
Agent input or broker output. Credential-bound Chromium paths fail closed.

Secret replacement serializes with envelope issuance, revokes outstanding
database grants, and changes the idempotency fingerprint by secret version.
Already decrypted authorization values remain bounded by the envelope/lease
TTL; the operator egress kill switch is the immediate containment mechanism.

Migration `20260829_0026` adds the false-by-default credential-rotation canary
foundation. When explicitly enabled with one credential-free HTTPS operator
target, secret replacement transactionally enqueues one idempotent attempt for
each ACTIVE bound revision. PostgreSQL derives organization, Project, policy,
revision, secret and current secret version; claim/reclaim uses row locks and
bounded leases, exact claim tokens fence completion, and every lifecycle change
is appended to immutable transition history. Terminal results use a fixed
outcome taxonomy and recheck the current secret version and target digest.

Migration `20260829_0027` replaces the broad transaction-local scheduler GUC
and scheduler RLS policies with three narrow `SECURITY DEFINER` operations.
Enqueue accepts only an exact rotated secret and derives eligible active
bindings; claim/reclaim is globally bounded; completion requires one exact
attempt plus the digest of its unexpired bearer token. Raw 256-bit claim tokens
are returned once to the trusted claimant and only SHA-256 digests persist.
Completion and rotation serialize on the exact Project secret before touching
the attempt, so the lock winner deterministically controls success versus
`SECRET_VERSION_SUPERSEDED`. Organization RLS remains RDC's tenant boundary;
the route additionally resolves and permission-checks the exact Project.

The live-runner increment wires those network-policy gates into a separate trusted
service. Migration `20260829_0028` adds one claim-fenced, fixed-search-path
`SECURITY DEFINER` loader that returns encrypted material only for the exact
unexpired claim and exact secret version. The runner decrypts that material only
inside its process, sends it only as the complete Authorization value, and clears
its mutable plaintext buffer after the request. It resolves and validates every
DNS address, connects directly to one validated IP while retaining the original
hostname for TLS/SNI, validates the actual connected peer, rejects redirects,
uses no proxy-aware HTTP client, and bounds request time, bytes, retries and
concurrency. Network outcomes are reduced to the existing bounded taxonomy.

The Project endpoint returns at most 100 sanitized attempt summaries and never
returns a secret reference/version, target/digest, claim token, credential or
external response. The runner remains false by default behind
`RDC_EGRESS_CREDENTIAL_CANARY_LIVE_EXECUTOR_ENABLED=false`, and adaptive routing
remains disabled until a separately reviewed live adversarial canary is complete.

Immediately before a bound `RUN_START` consumes a lease, admission locks the
Run and referenced policy and requires the policy to remain `ACTIVE` with the
same revision selected. Disablement, rotation, deletion, cross-tenant
substitution, receipt tampering, digest mismatch or a changed credential
presence terminally fails the Run and START outbox with
`EGRESS_POLICY_BINDING_REVOKED`; no lease or worker capability is issued. The
immutable original Run snapshot is retained as audit lineage. Unbound legacy
static-canary Runs keep their existing behavior.
