# Rooz Data Cloud API Contracts

**Document ID:** RDC-ARCH-API-001  
**Task:** RDC-P0-CHAT-001  
**Status:** Phase 0 baseline  
**Contract version:** 1.0.0-draft  
**API version:** `/api/v1`  
**Owner:** ChatGPT — Architecture, Backend, Security, DevOps, and Integration  
**Consumers:** RDC console, future SDKs, CLI, integrations, and execution-plane services

---

## 1. Purpose

This document defines the stable interface conventions for the Rooz Data Cloud control plane. It is a contract, not a Phase 1 implementation.

The contract covers:

- Browser sessions
- CSRF protection
- API keys and personal access tokens
- Authorization and tenant scoping
- Request and response formats
- Errors and validation failures
- Idempotency
- Pagination, filtering, and sorting
- Optimistic concurrency
- Asynchronous operations
- Server-Sent Events
- Audit requirements
- Write-only project secrets
- The initial Phase 1 endpoint inventory

No endpoint described here permits arbitrary Agent code to run inside the public API process.

---

## 2. Normative language

The terms **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are normative.

A production implementation is conformant only when all applicable MUST and MUST NOT requirements are satisfied.

---

## 3. Protocol and representation

### 3.1 Transport

- Production traffic MUST use HTTPS.
- Plain HTTP MAY be used only on loopback interfaces during local development.
- TLS termination MUST preserve the original scheme and client-address metadata through trusted proxy headers.
- Proxy headers MUST be accepted only from configured trusted proxies.

### 3.2 Base path

All public application APIs are rooted at:

```text
/api/v1
```

Internal execution-plane APIs MUST use a separate route group and authentication mechanism. They MUST NOT be exposed as ordinary browser APIs.

### 3.3 Media types

Default request and response type:

```http
Content-Type: application/json
Accept: application/json
```

SSE endpoints use:

```http
Accept: text/event-stream
Content-Type: text/event-stream
```

File exports MAY use CSV, JSON Lines, ZIP, or other explicitly documented media types.

### 3.4 Character encoding

UTF-8 is mandatory.

### 3.5 Timestamps

- Timestamps MUST be UTC RFC 3339 strings.
- Stored timestamps MUST preserve sub-second precision where available.
- Examples:

```text
2026-08-06T01:56:32Z
2026-08-06T01:56:32.481Z
```

### 3.6 Identifiers

- IDs are opaque strings.
- Clients MUST NOT infer resource type, creation time, tenancy, or ordering from an ID.
- UUIDs MAY be used internally, but the API contract does not require clients to parse them.
- External IDs MUST never expose sequential database keys.

---

## 4. Authentication modes

RDC supports two separate authentication modes.

### 4.1 Browser session authentication

The browser console uses an opaque server-managed session.

Cookie example:

```http
Set-Cookie: rdc_session=<opaque-value>; Path=/; Secure; HttpOnly; SameSite=Lax
```

Requirements:

- The cookie value MUST be cryptographically random.
- Only a digest of the session token MUST be stored server-side.
- The cookie MUST be `Secure` in non-local environments.
- The cookie MUST be `HttpOnly`.
- The cookie MUST use `SameSite=Lax` by default.
- The cookie MUST NOT be readable by browser JavaScript.
- The frontend MUST NOT store session tokens or JWTs in localStorage or sessionStorage.
- Sessions MUST support revocation.
- Sessions MUST rotate after login, privilege elevation, password change, account recovery, and suspicious activity.
- Absolute and idle expirations MUST be enforced server-side.
- Session truth resides on the server; frontend route guards are not authorization controls.

Recommended initial policy:

| Setting | Default |
|---|---:|
| Idle timeout | 30 minutes |
| Absolute lifetime | 7 days |
| Remember-me lifetime | Deferred |
| Concurrent session limit | Configurable |
| Rotation grace period | 60 seconds |

These values are operational defaults and MAY be changed without an API-version change when security is not weakened.

### 4.2 CSRF protection

Every state-changing request authenticated by the session cookie MUST include a valid CSRF token.

Header:

```http
X-RDC-CSRF: <token>
```

Contract:

1. `GET /api/v1/auth/session` returns the current session representation and a short-lived CSRF token.
2. The frontend keeps the CSRF token in memory.
3. The frontend sends it in `X-RDC-CSRF` for POST, PUT, PATCH, and DELETE requests.
4. The backend validates the token, session, origin, and method.
5. The token MUST be bound to the session.
6. A failed validation returns `AUTH_CSRF_INVALID`.
7. Login, registration, password-reset completion, and other unauthenticated state-changing endpoints MUST use explicit origin checks and endpoint-specific anti-automation controls.
8. CORS MUST use an explicit allowlist and MUST NOT combine wildcard origins with credentials.

### 4.3 Programmatic authentication

API keys and personal access tokens use:

```http
Authorization: Bearer <credential>
```

Requirements:

- Credentials MUST be shown only once at creation.
- Only a cryptographic digest MUST be stored.
- Credentials MUST have a public prefix and a non-secret last-four display.
- Credentials MUST be scoped.
- Credentials MUST be revocable and optionally expirable.
- Authentication failures MUST not disclose whether a key prefix exists.
- Programmatic credentials MUST NOT authenticate browser sessions.
- Query-string credentials are prohibited.

Recommended visible formats:

```text
rdc_live_<public-prefix>_<secret>
rdc_test_<public-prefix>_<secret>
rdc_pat_<public-prefix>_<secret>
```

The exact secret length and encoding are implementation details but MUST provide at least 128 bits of entropy.

### 4.4 Internal service authentication

Control-plane to execution-plane calls MUST use a separate internal identity mechanism, such as short-lived signed service tokens or mTLS.

Internal credentials MUST:

- Be audience-restricted
- Be short-lived
- Be scoped to one service action
- Never be accepted by public browser endpoints
- Never be written to Agent logs or datasets

---

## 5. Authorization and tenancy

### 5.1 Authorization model

Authorization is permission-based. Roles are collections of permissions.

Initial organization roles:

- `owner`
- `administrator`
- `developer`
- `analyst`
- `operator`
- `viewer`
- `billing_manager`

Representative permissions:

```text
organization.read
organization.update
organization.delete
membership.read
membership.invite
membership.update_role
membership.remove
project.create
project.read
project.update
project.delete
agent.create
agent.read
agent.update
agent.version_create
build.create
build.read
run.create
run.read
run.cancel
execution.read
dataset.read
dataset.export
secret.read_metadata
secret.create
secret.replace
secret.delete
api_key.create
api_key.read_metadata
api_key.revoke
audit.read
```

Endpoints MUST check permissions, not role names, except where a business invariant explicitly requires the organization owner.

### 5.2 Tenant rules

- Every tenant-owned resource belongs to exactly one organization.
- Project-owned resources also belong to exactly one project.
- The server derives organization and project context from authenticated membership and resource relationships.
- A client-supplied `organization_id` or `project_id` is never trusted by itself.
- Cross-organization access MUST return `404 RESOURCE_NOT_FOUND` where revealing existence would leak tenant information.
- The backend MUST apply explicit tenant predicates.
- PostgreSQL RLS is a mandatory defense-in-depth control.
- Background jobs MUST carry a verified tenant context.
- Audit records MUST include organization and project context when applicable.

### 5.3 No frontend authority

The frontend MAY hide unavailable controls, but the backend MUST enforce every permission independently.

---

## 6. Standard request headers

| Header | Required | Purpose |
|---|---|---|
| `Accept` | Recommended | Response media type |
| `Content-Type` | For request bodies | Body media type |
| `Authorization` | Programmatic clients | Bearer API key or PAT |
| `X-RDC-CSRF` | Cookie-authenticated mutations | CSRF token |
| `Idempotency-Key` | Required for selected commands | Safe retry key |
| `If-Match` | Required for selected updates | Optimistic concurrency |
| `X-Request-ID` | Optional | Caller-provided correlation ID |
| `Last-Event-ID` | SSE reconnects | Resume event stream |

Rules:

- `X-Request-ID` MUST be validated and length-limited.
- If absent or invalid, the server generates a request ID.
- The authoritative request ID is returned in `X-Request-ID` and the error body.
- Sensitive headers MUST be redacted from logs.

---

## 7. Standard success representation

Single-resource response:

```json
{
  "data": {
    "id": "prj_opaque",
    "name": "Research"
  },
  "meta": {
    "request_id": "req_opaque"
  }
}
```

Collection response:

```json
{
  "data": [
    {
      "id": "agt_opaque",
      "name": "Product collector"
    }
  ],
  "meta": {
    "request_id": "req_opaque",
    "page": {
      "next_cursor": "opaque-cursor",
      "has_more": true
    }
  }
}
```

Creation responses SHOULD use HTTP `201 Created`.

A successful command with no response object MAY use HTTP `204 No Content`.

Accepted asynchronous commands use HTTP `202 Accepted`.

---

## 8. Standard error representation

All JSON API errors use this stable structure:

```json
{
  "error": {
    "code": "VALIDATION_FAILED",
    "message": "One or more fields are invalid.",
    "request_id": "req_opaque",
    "field_errors": [
      {
        "field": "name",
        "code": "REQUIRED",
        "message": "Name is required."
      }
    ],
    "details": {
      "safe_key": "safe_value"
    }
  }
}
```

### 8.1 Rules

- `code` is stable and machine-readable.
- `message` is safe for display but MAY be humanized by the frontend.
- `request_id` is always present.
- `field_errors` is an array and MAY be empty.
- `details` MUST contain only allowlisted, non-sensitive metadata.
- Stack traces, SQL, internal paths, headers, cookies, tokens, secret values, and provider credentials MUST never appear.
- Unknown exceptions return a generic `INTERNAL_ERROR`.

### 8.2 Core error codes

| HTTP | Code | Meaning |
|---:|---|---|
| 400 | `INVALID_REQUEST` | Malformed or semantically invalid request |
| 400 | `AUTH_CSRF_INVALID` | CSRF validation failed |
| 400 | `INVALID_CURSOR` | Pagination cursor is invalid or expired |
| 401 | `AUTH_REQUIRED` | Authentication is missing or invalid |
| 401 | `SESSION_EXPIRED` | Browser session expired |
| 401 | `CREDENTIAL_INVALID` | API key or PAT is invalid |
| 403 | `PERMISSION_DENIED` | Authenticated principal lacks permission |
| 404 | `RESOURCE_NOT_FOUND` | Resource absent or hidden by tenancy |
| 409 | `RESOURCE_CONFLICT` | Current resource state conflicts with request |
| 409 | `IDEMPOTENCY_CONFLICT` | Same key reused with a different request |
| 409 | `VERSION_CONFLICT` | `If-Match` value is stale |
| 413 | `PAYLOAD_TOO_LARGE` | Request or upload exceeds limit |
| 415 | `UNSUPPORTED_MEDIA_TYPE` | Unsupported body type |
| 422 | `VALIDATION_FAILED` | Field validation failed |
| 429 | `RATE_LIMITED` | Request quota exceeded |
| 500 | `INTERNAL_ERROR` | Unexpected server error |
| 502 | `UPSTREAM_ERROR` | Approved upstream dependency failed |
| 503 | `SERVICE_UNAVAILABLE` | Service temporarily unavailable |
| 504 | `OPERATION_TIMED_OUT` | Operation exceeded its time budget |

### 8.3 Validation fields

Field paths use dotted notation and array indices:

```text
input.start_urls[0]
runtime.memory_mb
manifest.permissions.network
```

---

## 9. Idempotency

### 9.1 Header

```http
Idempotency-Key: <client-generated-value>
```

### 9.2 Required operations

The header is required for commands that can create cost, duplicate work, or irreversible side effects, including:

- Create Build
- Start Run
- Create API key
- Create invitation
- Create export
- Replace a secret
- Future payment commands

### 9.3 Semantics

- Keys are scoped to authenticated principal, organization, endpoint, and method.
- The server stores a request fingerprint and final response.
- Repeating the same request returns the original result.
- Reusing a key with a different fingerprint returns `IDEMPOTENCY_CONFLICT`.
- A key SHOULD remain valid for at least 24 hours.
- Keys MUST be length-limited and treated as untrusted input.
- Failed validation before command acceptance MAY remain uncached.
- The server MUST prevent concurrent duplicate execution.

---

## 10. Pagination, filtering, and sorting

### 10.1 Cursor pagination

Collection endpoints use cursor pagination.

Example:

```http
GET /api/v1/projects/prj_123/agents?limit=50&cursor=<opaque>
```

Rules:

- Default limit: 50
- Maximum limit: 200 unless endpoint documentation states otherwise
- Cursors are opaque and integrity-protected
- Cursors encode stable ordering state
- Clients MUST NOT construct or modify cursors
- Invalid cursors return `INVALID_CURSOR`

### 10.2 Sorting

Example:

```http
?sort=-created_at,name
```

- Prefix `-` means descending.
- Each endpoint defines an allowlist.
- A unique tie-breaker MUST be applied to ensure stable pages.

### 10.3 Filtering

Example:

```http
?status=RUNNING&agent_id=agt_123
```

- Filter fields are endpoint-specific and allowlisted.
- Arbitrary SQL-like filter expressions are not accepted in Phase 1.
- Search terms MUST have strict size limits.
- Hidden resources remain hidden by tenant rules regardless of filters.

---

## 11. Optimistic concurrency

Mutable resources SHOULD return an ETag:

```http
ETag: "resource-version-7"
```

Sensitive updates require:

```http
If-Match: "resource-version-7"
```

A stale update returns:

```text
409 VERSION_CONFLICT
```

Required initially for:

- Organization settings
- Project settings
- Agent mutable metadata
- Membership role changes
- Secret metadata changes

Immutable Agent versions do not support in-place updates.

---

## 12. Rate limiting

Responses MAY include:

```http
RateLimit-Limit: 1000
RateLimit-Remaining: 742
RateLimit-Reset: 1785978000
Retry-After: 60
```

Policy dimensions:

- Authentication principal
- Organization
- Endpoint class
- Source IP for unauthenticated endpoints
- Concurrent operations
- Resource consumption

Requirements:

- Login and recovery endpoints receive stronger anti-automation controls.
- Administrative principals are not unlimited.
- A limit failure returns `RATE_LIMITED`.
- Rate-limit keys MUST not contain raw secret credentials.
- Policies MUST be observable and auditable without exposing security thresholds unnecessarily.

---

## 13. Asynchronous operation contract

Long-running work returns HTTP `202 Accepted`.

Example:

```json
{
  "data": {
    "job_id": "job_opaque",
    "kind": "schema_generation",
    "status": "QUEUED",
    "status_url": "/api/v1/jobs/job_opaque"
  },
  "meta": {
    "request_id": "req_opaque"
  }
}
```

Common job statuses:

```text
QUEUED
STARTING
RUNNING
SUCCEEDED
FAILED
CANCELLED
TIMED_OUT
```

Requirements:

- The creation response MUST identify the job.
- Jobs MUST be tenant-scoped.
- Jobs MUST be queryable.
- Failures MUST use stable error codes.
- Generated schemas and code remain drafts until explicit user approval.
- Future job events MAY also be emitted through SSE.

---

## 14. Server-Sent Events contract

### 14.1 Endpoint

```http
GET /api/v1/runs/{run_id}/events
Accept: text/event-stream
```

### 14.2 Event frame

```text
id: 0000000000000042
event: run.log
data: {"schema_version":"1","run_id":"run_opaque","sequence":42,"timestamp":"2026-08-06T01:56:32.481Z","payload":{"stream":"stdout","level":"INFO","message":"Processing page"}}
```

### 14.3 Event envelope

```json
{
  "schema_version": "1",
  "run_id": "run_opaque",
  "sequence": 42,
  "timestamp": "2026-08-06T01:56:32.481Z",
  "payload": {}
}
```

### 14.4 Initial event types

```text
run.connected
run.status
run.log
run.metric
run.warning
run.completed
run.failed
run.heartbeat
```

### 14.5 Reconnection

- Every persisted event has a monotonically increasing per-Run sequence.
- The SSE `id` equals the event sequence or an opaque equivalent.
- Clients reconnect with `Last-Event-ID`.
- The server replays available events after that ID.
- If replay data is no longer available, the server emits `run.replay_reset`; the client refetches Run state and recent logs.
- Clients MUST tolerate duplicate delivery.
- Heartbeats SHOULD occur at least every 20 seconds.
- Terminal events are `run.completed` and `run.failed`.
- A stream MUST terminate after a terminal event and a bounded flush period.

### 14.5 Project lifecycle-event history

`GET /api/v1/projects/{project_id}/events` is the authenticated durable event
history contract. It requires `event.read`, accepts an optional allowlisted
`event_type`, limits pages to 100, and uses a signed cursor bound to the Project
and filter. Results are ordered by `occurred_at DESC, id DESC`. The initial
`rdc.event/v1` types are `build.created` and `run.created`; no public event
creation or webhook delivery endpoint exists.

### 14.6 Security

- The connection is authenticated and tenant-authorized before streaming.
- Authorization is revalidated when the server detects session revocation or permission change.
- Logs MUST pass through secret-redaction filters.
- Log messages have length and rate limits.
- ANSI control sequences MUST be sanitized before browser display.
- The endpoint MUST limit concurrent streams.

---

## 15. Audit contract

Security-relevant operations MUST create an audit event.

Minimum fields:

```json
{
  "event_id": "aud_opaque",
  "event_type": "project.secret.replaced",
  "timestamp": "2026-08-06T01:56:32.481Z",
  "organization_id": "org_opaque",
  "project_id": "prj_opaque",
  "actor": {
    "type": "user",
    "id": "usr_opaque"
  },
  "target": {
    "type": "project_secret",
    "id": "sec_opaque"
  },
  "request_id": "req_opaque",
  "outcome": "success",
  "metadata": {
    "secret_name": "PROXY_TOKEN"
  }
}
```

Audit metadata MUST NOT contain:

- Passwords
- Session tokens
- CSRF tokens
- API keys
- Personal access tokens
- Authorization headers
- Cookie headers
- Secret values
- Full sensitive request bodies

Audit events are append-only through normal application interfaces.

---

## 16. Project-secret contract

Project secrets are write-only after creation.

### 16.1 Metadata representation

```json
{
  "id": "sec_opaque",
  "project_id": "prj_opaque",
  "name": "PROXY_API_KEY",
  "description": "Primary provider credential",
  "environment": "production",
  "has_value": true,
  "created_at": "2026-08-06T01:56:32Z",
  "updated_at": "2026-08-06T01:56:32Z",
  "last_used_at": null,
  "version": 1
}
```

### 16.2 Rules

- Secret values are accepted only on create or replace.
- Existing plaintext values are never returned.
- There is no reveal endpoint.
- Listing returns metadata only.
- Secret values MUST be encrypted at rest through envelope encryption.
- Decryption occurs only in the execution-plane secret-injection path.
- Secret access is audited without recording the value.
- A Run receives only secrets explicitly allowed by its Agent version and runtime configuration.
- Secret values MUST not be placed in environment dumps, errors, logs, datasets, build arguments, or image layers.

---

## 17. Initial Phase 1 endpoint inventory

This inventory defines contract scope. It does not constitute implementation.

### 17.1 Authentication

| Method | Path | Purpose | Auth |
|---|---|---|---|
| POST | `/api/v1/auth/register` | Register account | Public |
| POST | `/api/v1/auth/login` | Create browser session | Public |
| POST | `/api/v1/auth/logout` | Revoke current session | Session + CSRF |
| POST | `/api/v1/auth/session/refresh` | Rotate eligible session | Session + CSRF |
| GET | `/api/v1/auth/session` | Read session and obtain CSRF token | Session |
| POST | `/api/v1/auth/verify-email` | Verify email token | Public token |
| POST | `/api/v1/auth/forgot-password` | Begin recovery | Public |
| POST | `/api/v1/auth/reset-password` | Complete recovery | Public token |

Security behavior:

- Registration and recovery responses MUST resist account enumeration.
- Login success rotates the session.
- Password-reset completion revokes existing sessions unless an explicit safer policy is approved.
- Passwords use Argon2id.

### 17.2 Organizations and memberships

| Method | Path | Permission |
|---|---|---|
| GET | `/api/v1/organizations` | Authenticated membership |
| POST | `/api/v1/organizations` | Authenticated user |
| GET | `/api/v1/organizations/{organization_id}` | `organization.read` |
| PATCH | `/api/v1/organizations/{organization_id}` | `organization.update` |
| GET | `/api/v1/organizations/{organization_id}/members` | `membership.read` |
| POST | `/api/v1/organizations/{organization_id}/invitations` | `membership.invite` |
| PATCH | `/api/v1/organizations/{organization_id}/members/{membership_id}` | `membership.update_role` |
| DELETE | `/api/v1/organizations/{organization_id}/members/{membership_id}` | `membership.remove` |

Rules:

- The final owner cannot be removed.
- Ownership transfer requires reauthentication and a dedicated command.
- Invitation creation requires idempotency.
- Membership changes are audited.

### 17.3 Projects

| Method | Path | Permission |
|---|---|---|
| GET | `/api/v1/organizations/{organization_id}/projects` | `project.read` |
| POST | `/api/v1/organizations/{organization_id}/projects` | `project.create` |
| GET | `/api/v1/projects/{project_id}` | `project.read` |
| PATCH | `/api/v1/projects/{project_id}` | `project.update` |
| DELETE | `/api/v1/projects/{project_id}` | `project.delete` |

Deletion is initially a controlled soft-delete operation. Cascading permanent deletion requires a later retention contract.

### 17.4 Agents and versions

| Method | Path | Permission |
|---|---|---|
| GET | `/api/v1/projects/{project_id}/agents` | `agent.read` |
| POST | `/api/v1/projects/{project_id}/agents` | `agent.create` |
| GET | `/api/v1/agents/{agent_id}` | `agent.read` |
| PATCH | `/api/v1/agents/{agent_id}` | `agent.update` |
| GET | `/api/v1/agents/{agent_id}/versions` | `agent.read` |
| POST | `/api/v1/agents/{agent_id}/versions` | `agent.version_create` |
| GET | `/api/v1/agent-versions/{version_id}` | `agent.read` |

Agent versions are immutable after creation. Corrections produce a new version.

### 17.5 Builds

| Method | Path | Permission |
|---|---|---|
| POST | `/api/v1/agent-versions/{version_id}/builds` | `build.create` |
| GET | `/api/v1/builds/{build_id}` | `build.read` |
| GET | `/api/v1/agents/{agent_id}/builds` | `build.read` |

Build creation:

- Requires `Idempotency-Key`.
- Returns `202 Accepted`.
- Records metadata in the control plane.
- Queues work for an isolated execution-plane build worker.
- Never invokes BuildKit inside the API process.

### 17.6 Runs

| Method | Path | Permission |
|---|---|---|
| POST | `/api/v1/agent-versions/{version_id}/runs` | `run.create` |
| GET | `/api/v1/runs/{run_id}` | `run.read` |
| POST | `/api/v1/runs/{run_id}/cancel` | `run.cancel` |
| GET | `/api/v1/runs/{run_id}/events` | `run.read` |
| GET | `/api/v1/projects/{project_id}/runs` | `run.read` |

Run creation requires `Idempotency-Key` and returns `202 Accepted`.

Phase 1E implementation rules:

- A Run references a successful Build artifact for the same immutable Agent version.
- Inline JSON input is limited to 64 KiB; large object-storage inputs are deferred.
- Runtime overrides may reduce but cannot exceed immutable manifest resource limits.
- Run creation writes a durable `START` command and an initial persisted status event.
- Cancellation requires `Idempotency-Key`; queued Runs are aborted before dispatch, while active Runs receive one durable `CANCEL` command and an immutable server-derived `cancel_deadline_at`.
- The public API never executes Agent code or decrypts project secrets.

Cancellation is a command, not a resource deletion.

### Execution recovery health

`GET /health/recovery` reports the independently scheduled recovery service as
`ready`, `stale`, `failed`, `never_run`, `unavailable`, or `disabled`. It exposes
successful sweep and failure counters plus last-success timestamps, but never
scheduler owner identity, tenant identifiers, work payloads, exception text, or
credentials. When scheduling is enabled, any non-ready recovery status also
degrades `GET /health/ready`.

### 17.7 API keys

| Method | Path | Permission |
|---|---|---|
| GET | `/api/v1/organizations/{organization_id}/api-keys` | `api_key.read_metadata` |
| POST | `/api/v1/organizations/{organization_id}/api-keys` | `api_key.create` |
| DELETE | `/api/v1/api-keys/{api_key_id}` | `api_key.revoke` |

The creation response displays the full key exactly once.

### 17.8 Audit events

| Method | Path | Permission |
|---|---|---|
| GET | `/api/v1/organizations/{organization_id}/audit-events` | `audit.read` |
| GET | `/api/v1/projects/{project_id}/audit-events` | `audit.read` |

### 17.9 Project secrets

| Method | Path | Permission |
|---|---|---|
| GET | `/api/v1/projects/{project_id}/secrets` | `secret.read_metadata` |
| POST | `/api/v1/projects/{project_id}/secrets` | `secret.create` |
| PUT | `/api/v1/secrets/{secret_id}` | `secret.replace` |
| DELETE | `/api/v1/secrets/{secret_id}` | `secret.delete` |

---

## 18. Endpoint-level contract checklist

Every endpoint specification MUST define:

- Purpose
- Authentication mode
- Required permission
- Tenant derivation
- Request schema and size limit
- Response schema
- Error codes
- Idempotency behavior
- Concurrency behavior
- Audit event
- Rate-limit class
- Sensitive-field handling

---

## Scheduler API

```text
POST /api/v1/agent-versions/{version_id}/schedules
GET  /api/v1/projects/{project_id}/schedules
GET  /api/v1/schedules/{schedule_id}
POST /api/v1/schedules/{schedule_id}/pause
POST /api/v1/schedules/{schedule_id}/resume
GET  /api/v1/schedules/{schedule_id}/triggers
```

Create requires `Idempotency-Key`, `schedule.create`, CSRF for sessions and a
strict `rdc.schedule/v1` body. Ownership is derived from the authorized Agent
version. Mutation requires `schedule.update`; metadata/history requires
`schedule.read`. Collection cursors are signed and bound to Project/Schedule
and the active status/outcome filter. No route accepts a trigger, Run ID,
organization ID, Project ID or Agent ID from the request body.

## 19. API evolution

- Breaking changes require a new major URL version.
- Additive optional fields do not require a new version.
- Clients MUST ignore unknown response fields.
- Removing fields, changing meanings, narrowing accepted values, or changing status semantics is breaking.
- OpenAPI is the machine-readable contract source.
- Generated TypeScript and SDK types are derived artifacts.
- Contract changes require ChatGPT approval and Gemini consumption review.

---

## 20. Phase 0 open decisions

The following do not block this baseline but require later documented decisions:

1. Exact session idle and absolute timeout values for production plans
2. Personal-access-token lifecycle and user-facing management
3. Organization ownership-transfer workflow
4. Retention period for idempotency records
5. Retention and replay limits for SSE events and logs
6. Exact rate-limit tiers
7. Data-export size thresholds and asynchronous-export rules
8. Permanent-deletion and legal-retention workflow


---

## Phase 1F internal execution-plane contract

The internal execution-plane protocol is rooted at `/internal/v1`. It is not a browser API, is excluded from the public OpenAPI document, and does not accept browser sessions, CSRF tokens, API keys, or personal access tokens.

Worker bootstrap registration returns a write-only worker token. All subsequent worker calls require that token. Every claimed command additionally receives a short-lived lease token that is valid only for the assigned worker and lease.

Initial internal routes:

```text
POST /internal/v1/workers/register
GET  /internal/v1/workers/me
POST /internal/v1/workers/me/heartbeat
POST /internal/v1/leases/claim
POST /internal/v1/leases/{lease_id}/renew
POST /internal/v1/leases/{lease_id}/status
POST /internal/v1/leases/{lease_id}/events
POST /internal/v1/leases/{lease_id}/secret-envelope
POST /internal/v1/leases/{lease_id}/complete
```

Public metadata routes:

```text
GET /api/v1/projects/{project_id}/execution-leases
GET /api/v1/projects/{project_id}/execution-artifacts
```

Claims MUST be transactionally leased, MUST prevent concurrent duplicate claims, MUST expire, and MUST have bounded retries. Secret envelopes MUST be limited to declared Agent-manifest names, matching project and environment, the active `RUN_START` lease, and a short expiry. Artifact registration MUST be digest-addressed and tenant-bound.

BUILD and RUN_START claims MUST also enforce the persisted owning Project's
server-derived active-lease limit and the claiming worker's server-capped limit
inside the claim transaction. Capacity counts include only ACTIVE leases whose
expiry and immutable deadline remain in the future. RUN_CANCEL MUST bypass the
Project execution limit so cancellation can drain a saturated Project, while
still consuming worker capacity. Claim payload admission metadata is
informational; persisted locks, counts, and limits are authoritative.

Workers executing a claim MUST heartbeat and renew below the server loss
threshold. A worker marked lost MAY authenticate to submit a strict
`rdc.worker-recovery/v1` heartbeat report, but MUST NOT claim or use
lease-scoped authority until server acceptance. The report contains a startup
UUID, forced-cleanup completion literal, and bounded container/workspace counts;
it does not select tenancy, leases, or cleanup targets.

`GET /metrics/recovery` is excluded from public OpenAPI and exposes only global
low-cardinality recovery/admission metrics for a trusted monitoring network. It
MUST NOT include organization, Project, worker, lease, payload, token, secret,
or error-summary labels. A stale or unavailable enabled scheduler returns 503
and `rdc_execution_recovery_healthy 0`.

Phase 1F claim payloads MUST contain `execution_enabled: false`. This contract does not authorize an implementation to execute Agent code, invoke container runtimes, or expose project-secret plaintext.


## Phase 1G storage contracts

- `POST /api/v1/agents/{agent_id}/source-uploads` creates a pending `AGENT_SOURCE` object and exact-size presigned POST.
- `POST /api/v1/storage-objects/{storage_object_id}/complete` verifies object metadata, SHA-256, and safe-ZIP policy.
- `GET /api/v1/projects/{project_id}/storage-objects` and `GET /api/v1/storage-objects/{storage_object_id}` expose metadata only.
- `POST /api/v1/storage-objects/{storage_object_id}/download-grant` creates a short-lived tenant download capability.
- `POST /internal/v1/leases/{lease_id}/source-download` is excluded from public OpenAPI and requires worker plus lease credentials.
- Presigned URLs are returned once and never persisted by the control plane.

## Phase 1H internal sandbox contracts

Worker heartbeats may include a strict `rdc.sandbox/v1` attestation. The control plane sets `execution_enabled: true` only when the global sandbox gate is enabled and the claiming worker has a current compliant attestation. Claim payloads include a `sandbox` policy block with immutable limits. Internal lease endpoints add `artifact-upload` and `artifact-download` grants; they remain excluded from public OpenAPI. Uploaded execution artifacts are accepted only after object metadata, byte length, media type, lease binding, and server-streamed SHA-256 verification match.



## Phase 1I controlled sandbox activation

Phase 1I does not add a public execution-enablement API. Activation is an
operator configuration boundary. A worker claim may set `execution_enabled`
to true only when the Phase 1H sandbox policy and the Phase 1I `activation`
object both validate.

The activation object is stored inside the immutable execution-lease payload
snapshot and contains:

- `mode = canary`
- exact immutable `agent_version_id`
- exact authenticated `worker_name`
- sandbox attestation digest
- sandbox-policy digest
- canary-constraints digest
- `no_secrets = true`
- `capability_profile = offline-minimal`
- `max_concurrency = 1`

Artifact registration verifies that worker provenance reproduces the same
activation object and expected source/image lineage.

## Scraping Runtime Queue binding

`POST /api/v1/agent-versions/{version_id}/runs` accepts an optional strict
`request_queue` object with `schema_version=rdc.run-queue/v1` and `queue_id`.
The Queue ID is resolved against the immutable Agent version's server-derived
organization and Project. Cross-tenant or missing Queues return the same 404.
The field cannot be combined with web-fetch or browser intent. Caller input
cannot set `_rdc_queue`, `_rdc_queue_http`, `_rdc_queue_browser`, `_rdc_web_requests`, or
`_rdc_web_fetch_result`.

Eligible execution claims carry immutable Queue binding and worker-capability
receipts. The hidden internal routes are:

```text
POST /internal/v1/leases/{lease_id}/queue-claim
POST /internal/v1/leases/{lease_id}/queue-complete
```

Both require the authenticated worker, active lease token, exact bound Queue,
lease tenancy and the false-by-default Request Queue gate. A Run may claim at
most one item. The trusted worker removes `claim_token` before injecting the
normalized claim into Agent input and retains `--network none`. Completion is
claim-token/worker/expiry bound and uses the existing immutable Queue transition
and audit lineage.

When the immutable Agent version declares `network=web-egress`, the API emits
`rdc.request-queue-binding-receipt/v2`, binding `brokered-http`, the current
`rdc.egress/v1` policy digest, dispatch state, and networkless Agent boundary.
The lease carries `rdc.request-queue-worker-capability/v2`. The trusted worker
derives exactly one GET from the claimed URL, uses only the existing bounded
HTTPS broker, validates its result, and injects `_rdc_queue_http` without the
claim token. This mode is false by default and cannot be combined with browser,
KV, caller web-fetch, or legacy web-request input.

When the immutable version also declares `browser=true`, the independently
gated live canary emits `rdc.request-queue-binding-receipt/v3` and
`rdc.request-queue-worker-capability/v3`, binding both current browser-policy
digests. The trusted worker derives one bounded v2 navigation plan from the
claimed HTTPS URL, validates the browser result, and injects the token-free
`_rdc_queue_browser` envelope before running the Agent with network disabled.

When the immutable version also declares `dataset=true`, the separate
`rdc.request-queue-dataset-receipt/v1` must be dispatch-enabled. The lease
carries `rdc.request-queue-worker-capability/v4` and
`rdc.dataset-worker-capability/v2`, both bound to the exact Queue and default
Dataset with `dataset-before-queue-handled`. The trusted worker validates and
idempotently appends the Agent's bounded `rdc.dataset-append/v1` output before
completing the Queue claim. No Agent or Chromium database/object credentials
are introduced.

## Egress policy metadata and runtime binding

Authenticated Project routes create and list tenant policies; policy routes
read metadata, append immutable revisions, activate an exact revision and
disable a policy. Creation requires `Idempotency-Key`. Mutation requests use an
`expected_version` and return 409 on stale state. Policy specifications admit
exact normalized HTTPS hostnames, `GET`/`HEAD`, bounded budgets and an optional
same-Project secret reference. Revision responses expose
`credential_configured`, never a secret identifier or value.

An eligible Run may additionally carry only
`egress_policy={schema_version: rdc.run-egress-policy/v1, policy_id}`. The
server derives tenancy from the immutable Agent version, row-locks the ACTIVE
policy and snapshots its exact current revision into
`rdc.run-egress-policy-receipt/v1`. The binding digest is repeated in the
sandbox activation and, for Queue acquisition, the lease-scoped
`rdc.request-queue-worker-capability/v6`. Static worker canary configuration is
always a maximum host/method/budget ceiling. Credential-bound revisions are
not dispatchable until isolated credential delivery is implemented.
