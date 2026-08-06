# Rooz Data Cloud (RDC) — Frontend Information Architecture

**Document ID:** RDC-FE-IA-001  
**Phase:** Phase 0 contract baseline  
**Status:** Reconciled  
**Owners:** Gemini — Frontend/UX; ChatGPT — architecture integration

## 1. Scope

This document defines the route hierarchy, layout boundaries, navigation model, UI state rules, and backend contracts consumed by `apps/console`.

The hierarchy is explicit:

```text
User → Organization → Project → Resource
```

The approved project route root is:

```text
/console/organizations/[orgId]/projects/[projectId]
```

Phase 0 is specification-only. Routes reserved for later phases MUST NOT be bound to invented API endpoints.

## 2. Security and state directives

- Browser authentication uses an opaque server-side session delivered through a `Secure`, `HttpOnly`, `SameSite=Lax` cookie.
- Session credentials, API keys, PATs, and JWTs MUST NOT be stored in `localStorage` or `sessionStorage`.
- `GET /api/v1/auth/session` is the browser session source of truth and returns the in-memory CSRF token.
- State-changing session-authenticated requests send `X-RDC-CSRF`.
- Frontend route guards, hidden actions, and disabled controls are user-experience aids only. Backend authorization remains authoritative.
- TanStack Query manages server state.
- React Hook Form manages form state.
- Heavy libraries such as Monaco Editor and React Flow are lazy-loaded behind explicit loading boundaries.
- Project secrets are metadata-only after creation. The UI never exposes a reveal or copy-existing-value action.

## 3. Canonical route map

```text
/
├── /login
├── /register
├── /forgot-password
├── /reset-password
└── /console
    ├── /select-organization
    └── /organizations/[orgId]
        ├── /projects
        ├── /members
        ├── /api-keys
        ├── /audit
        ├── /settings
        └── /projects/[projectId]
            ├── /dashboard
            ├── /agents
            │   └── /[agentId]
            │       └── /versions/[versionId]
            ├── /builds
            │   └── /[buildId]
            ├── /runs
            │   └── /[runId]
            ├── /secrets
            ├── /audit
            ├── /settings
            ├── /pipelines          # reserved; later-phase disabled shell
            ├── /datasets           # reserved; later-phase disabled shell
            ├── /storage            # reserved; later-phase disabled shell
            └── /connectors         # reserved; later-phase disabled shell
```

### 3.1 Route decisions

- `/login` and account-recovery routes are public and live outside `/console`.
- `/console/select-organization` is the authenticated fallback when no active organization can be resolved.
- `/console/organizations/[orgId]/projects` is required for project selection and project creation.
- API keys are organization-scoped in the Phase 1 API contract and therefore live at the organization level.
- Project secrets and project audit events remain project-scoped.
- Billing, global search, platform administration, notification preferences, MFA implementation, marketplace, and AI Studio are outside the Phase 0 scaffold.
- Reserved later-phase routes render a disabled or “coming later” shell and MUST NOT call missing APIs.

## 4. Layout hierarchy

### 4.1 Root layout

Provides:

- document metadata;
- theme provider;
- global error boundary;
- accessibility skip link;
- toast/status regions;
- no authenticated data assumptions.

### 4.2 Public authentication layout

Provides:

- login, registration, and recovery content;
- focused single-column presentation;
- no application sidebar;
- explicit link back to login after recovery.

### 4.3 Console organization layout

Path:

```text
/console/organizations/[orgId]
```

Provides:

- organization switcher;
- organization navigation;
- project selector/list entry;
- member, API-key, audit, and settings navigation;
- permission-aware action presentation.

### 4.4 Project workspace layout

Path:

```text
/console/organizations/[orgId]/projects/[projectId]
```

Provides:

- project switcher;
- project sidebar;
- breadcrumbs;
- project-level error/loading boundary;
- main content focus target;
- route-level permission context for presentation only.

## 5. Context-switching rules

### Organization switch

1. Clear active project UI state and project-scoped query caches.
2. Navigate to `/console/organizations/[newOrgId]/projects`.
3. Do not retain stale permissions from the previous organization.
4. Refetch session/permission context.
5. Never derive tenancy from a client-supplied organization name alone.

### Project switch

1. Keep the active organization fixed.
2. Navigate to `/console/organizations/[orgId]/projects/[newProjectId]/dashboard`.
3. Invalidate project-scoped queries.
4. Let backend authorization determine whether the project is accessible.
5. Treat `RESOURCE_NOT_FOUND` as absent-or-hidden; do not reveal cross-tenant existence.

## 6. Universal UI state matrix

Every data-driven route supports:

| State | Required behavior |
|---|---|
| Loading | Stable skeleton, no layout shift, `aria-busy="true"` |
| Empty | Clear explanation and permitted primary action |
| Error | Safe message, stable `error.code`, copyable `request_id` |
| Permission-aware | Explain unavailable action without implying frontend enforcement |
| Ready | Semantic content, keyboard-operable controls |
| Stale/reconnecting | Preserve last safe state and show refresh/reconnection status |

## 7. Authentication and recovery UX

### 7.1 Session expired

Backend response:

```text
401 SESSION_EXPIRED
```

Frontend behavior:

1. Stop authenticated background refetches.
2. Preserve only a relative return path; never preserve credentials.
3. Redirect to `/login`.
4. Explain that the session expired.
5. After successful login, validate the return path before navigation.

### 7.2 Session revoked or otherwise invalid

Use the contract-defined `AUTH_REQUIRED` response unless a future contract explicitly adds a separate revocation code.

Frontend behavior:

- clear session-derived in-memory state;
- redirect to login;
- do not retry authenticated mutations.

### 7.3 CSRF failure

Backend response:

```text
400 AUTH_CSRF_INVALID
```

Frontend behavior:

1. Refetch `GET /api/v1/auth/session`.
2. Retry once only when the backend guarantees the failed request was rejected before command acceptance.
3. Cost-bearing or duplicate-prone commands MUST retain the same `Idempotency-Key`.
4. Never retry indefinitely.
5. On a second failure, ask the user to refresh or sign in again.

### 7.4 Permission change

Backend response:

```text
403 PERMISSION_DENIED
```

Frontend behavior:

- invalidate session/permission queries;
- update action availability;
- preserve safe unsaved form state where possible;
- never reinterpret a backend denial as a client error.

## 8. Standard API error presentation

The frontend consumes:

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
    "details": {}
  }
}
```

Rules:

- `message` may be displayed when safe.
- `request_id` is copyable for support.
- `field_errors` bind to form controls.
- `details` is treated as optional allowlisted metadata.
- raw stack traces or provider errors are never rendered.

## 9. Cursor pagination

Collection responses use opaque cursors:

```json
{
  "data": [],
  "meta": {
    "page": {
      "next_cursor": "opaque",
      "has_more": true
    }
  }
}
```

Frontend rules:

- never construct or edit a cursor;
- maintain a client-side cursor history stack for “Previous” navigation;
- reset cursor history when filters or sorting change;
- preserve table dimensions during page transitions;
- surface `INVALID_CURSOR` with a reset-to-first-page action.

## 10. Run events and SSE

Endpoint:

```text
GET /api/v1/runs/{run_id}/events
```

Rules:

- consume `id`, `event`, and the versioned JSON envelope;
- rely on the SSE `id` and `Last-Event-ID` reconnect contract;
- do not invent a query-string replay parameter;
- tolerate duplicate delivery;
- on `run.replay_reset`, refetch Run state and recent logs;
- distinguish `Live`, `Reconnecting`, and `Offline`;
- sanitize log rendering and never interpret ANSI/HTML as trusted markup;
- announce only meaningful status changes through live regions, not every log line.

## 11. Write-only secrets UX

Existing secret rows display metadata only:

- name;
- description;
- environment;
- configured state;
- created/updated timestamps;
- last-used timestamp when available.

Rules:

- no reveal action;
- no copy-existing-value action;
- replacement requires a newly entered value;
- closing or cancelling a replacement form preserves the existing secret;
- replacement and deletion require clear consequence messaging;
- secret values are never included in telemetry, client logs, error reports, or persisted browser state.

## 12. Backend contracts consumed

### Session

- `POST /api/v1/auth/login`
- `POST /api/v1/auth/logout`
- `GET /api/v1/auth/session`
- `POST /api/v1/auth/session/refresh`

### Organizations and projects

- `GET /api/v1/organizations`
- `GET /api/v1/organizations/{organization_id}`
- `GET /api/v1/organizations/{organization_id}/projects`
- `POST /api/v1/organizations/{organization_id}/projects`
- `GET /api/v1/projects/{project_id}`

### Memberships and organization credentials

- `GET /api/v1/organizations/{organization_id}/members`
- `GET /api/v1/organizations/{organization_id}/api-keys`
- `POST /api/v1/organizations/{organization_id}/api-keys`
- `DELETE /api/v1/api-keys/{api_key_id}`

### Agents, builds, and Runs

- `GET /api/v1/projects/{project_id}/agents`
- `GET /api/v1/agents/{agent_id}`
- `GET /api/v1/agents/{agent_id}/versions`
- `GET /api/v1/agent-versions/{version_id}`
- `POST /api/v1/agent-versions/{version_id}/builds`
- `GET /api/v1/builds/{build_id}`
- `GET /api/v1/projects/{project_id}/runs`
- `GET /api/v1/runs/{run_id}`
- `POST /api/v1/runs/{run_id}/cancel`
- `GET /api/v1/runs/{run_id}/events`

### Project secrets and audit

- `GET /api/v1/projects/{project_id}/secrets`
- `POST /api/v1/projects/{project_id}/secrets`
- `PUT /api/v1/secrets/{secret_id}`
- `DELETE /api/v1/secrets/{secret_id}`
- `GET /api/v1/projects/{project_id}/audit-events`
- `GET /api/v1/organizations/{organization_id}/audit-events`

No other endpoint may be assumed without a contract change.


## Phase 1F project navigation

`Execution plane` is a first-class project page after `Runs`. It displays tenant-scoped lease attempts and artifact metadata. It does not expose worker registration, credentials, lease tokens, secret grants, or decrypted values. Operational worker administration remains a future organization-level module.
