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

Policy and revision list cursors are signed and bound to the exact Project,
status filter or policy resource; both collections are page-bounded.
Organization and Project ownership always come from authenticated resources,
never request bodies. `egress.create`, `egress.read` and `egress.update`
permissions apply to session and scoped API-key principals.

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

Credential-bound revisions remain fail-closed with
`EGRESS_POLICY_CREDENTIAL_DELIVERY_UNAVAILABLE`. No secret reference or
material enters Run lineage, Agent input, Chromium, activation or Queue
capabilities. Isolated credential-envelope delivery and rotation convergence
remain separate work.
