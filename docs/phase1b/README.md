# Rooz Data Cloud — Phase 1B Identity and Tenancy

Phase 1B implements the first production-oriented control-plane domain boundary on top of the
approved Phase 0 contracts and merged Phase 1A engineering foundation.

## Included

- Global users with Argon2id password hashes
- Opaque server-side browser sessions
- Session-bound CSRF tokens held only in browser memory
- Redis-backed authentication rate limiting
- Organizations, memberships, and projects
- Permission-based organization authorization
- Organization-scoped API keys shown only once
- Deterministic idempotent API-key issuance without plaintext credential storage
- Security audit events
- PostgreSQL Row-Level Security policies
- Accessible login and organization-selection flows
- CI migration verification against PostgreSQL

## Explicit exclusions

- Email delivery and invitation acceptance
- Password-reset and email-verification delivery
- MFA and external identity providers
- Agents, Builds, Runs, datasets, pipelines, billing, connectors, or workers
- Arbitrary code execution inside the API process

## Security invariants

- Raw passwords, session tokens, CSRF tokens, and API keys are never stored.
- Browser credentials are never written to localStorage or sessionStorage.
- Session-cookie mutations require `X-RDC-CSRF`.
- Every tenant query includes an explicit organization predicate.
- PostgreSQL RLS remains a defense-in-depth control.
- API keys are scoped, revocable, optionally expiring, and organization-bound.
- Cross-tenant access returns `RESOURCE_NOT_FOUND`.
- Privileged mutations emit audit events.
