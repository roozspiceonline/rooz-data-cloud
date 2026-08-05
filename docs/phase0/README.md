# Rooz Data Cloud — Phase 0 Foundation

Status: **Approved foundation awaiting pull-request merge**

This directory set contains the source-of-truth contracts and frontend foundations produced during RDC Phase 0.

## Architecture and security

- `docs/architecture/API_CONTRACTS.md`
- `docs/architecture/DB_SCHEMA.md`
- `docs/security/THREAT_MODEL.md`
- `docs/security/MERGE_GATES.md`

## Frontend and developer experience

- `docs/frontend/INFORMATION_ARCHITECTURE.md`
- `docs/frontend/DESIGN_SYSTEM.md`
- `docs/frontend/ACCESSIBILITY_STANDARD.md`
- `docs/frontend/FRONTEND_TESTING.md`
- `docs/frontend/PROJECT_SCAFFOLDS.md`

## Binding decisions

- Public APIs are versioned under `/api/v1`.
- Browser authentication uses opaque server-side sessions.
- State-changing browser requests use `X-RDC-CSRF`.
- Programmatic access uses scoped API keys or personal access tokens.
- Tenant isolation requires explicit service scoping and PostgreSQL Row-Level Security.
- Project secret values are write-only after creation.
- Build workers and Agent execution are isolated from the public API process.
- The console route hierarchy is Organization → Project.
- The approved project route root is `/console/organizations/[orgId]/projects/[projectId]`.
- WCAG 2.1 AA is the frontend accessibility target.

## Scope boundary

These documents define contracts and implementation constraints. They do not claim that Phase 1 authentication, Agents, Builds, Runs, pipelines, datasets, storage, connectors, or execution-plane services are already implemented.

## Next milestone

After this documentation pull request is reviewed and merged, begin the monorepo, Docker Compose, shared package, CI, API shell, and console shell implementation batch.
