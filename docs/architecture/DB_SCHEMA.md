# Rooz Data Cloud Database Schema

**Document ID:** RDC-ARCH-DB-001  
**Task:** RDC-P0-CHAT-001  
**Status:** Phase 0 conceptual baseline  
**Database:** PostgreSQL  
**Default transaction isolation:** `READ COMMITTED`  
**Tenant defense:** explicit repository scoping plus PostgreSQL Row-Level Security

---

## 1. Purpose

This document defines the Phase 0 conceptual data model for the Phase 1 control plane. It is not an Alembic migration and does not authorize production implementation.

Covered entities:

- User
- Session
- EmailVerificationToken
- PasswordResetToken
- Organization
- OrganizationMembership
- OrganizationInvitation
- Project
- Agent
- AgentVersion
- Build
- Run
- ApiKey
- AuditEvent
- ProjectSecret

---

## 2. Database principles

1. PostgreSQL is the authoritative control-plane metadata store.
2. Tenant-owned rows contain `organization_id`.
3. Project-owned rows contain both `organization_id` and `project_id`.
4. Tenant filters are explicit in service repositories.
5. RLS provides defense in depth.
6. The runtime application role does not own tenant tables and does not have `BYPASSRLS`.
7. External IDs are opaque and non-sequential.
8. Secret credentials are never stored in plaintext.
9. Audit events are append-only through ordinary application paths.
10. Agent versions are immutable.
11. Builds and Runs use validated state transitions.
12. Foreign keys and unique constraints enforce business invariants where practical.
13. `READ COMMITTED` is the default; narrow operations may use stronger controls.
14. Every schema change is delivered through a reversible Alembic migration.
15. Backfills and destructive migrations require an explicit rollout plan.

---

## 3. Conventions

### 3.1 Primary keys

Recommended internal type:

```text
UUID
```

The API exposes opaque string IDs. Prefixes MAY be added at the API serialization layer.

### 3.2 Common columns

Mutable entities generally include:

```text
id
created_at
updated_at
version
```

Tenant-owned entities include:

```text
organization_id
```

Project-owned entities include:

```text
organization_id
project_id
```

### 3.3 Timestamps

Use timezone-aware PostgreSQL timestamps:

```sql
timestamp with time zone
```

Application code writes UTC.

### 3.4 Soft deletion

Soft deletion is selective, not universal.

- User: controlled deactivation and later erasure workflow
- Organization: controlled deactivation
- Project: soft delete initially
- Agent: archive instead of destructive delete
- AgentVersion: immutable, no ordinary deletion
- Build and Run: retained according to policy
- Session: revocation timestamp
- ApiKey: revocation timestamp
- ProjectSecret: deletion tombstone may be retained in audit, not in secret-value storage

### 3.5 Case normalization

- Emails are stored normalized for uniqueness.
- Secret and environment-variable names use an uppercase constrained format.
- Slugs use lowercase normalized forms.
- Display names preserve user-entered case.

---

## 4. Logical schemas

Recommended PostgreSQL namespaces:

```text
identity
control
security
```

Possible mapping:

| Schema | Entities |
|---|---|
| `identity` | users, sessions, verification tokens, reset tokens, organizations, memberships, invitations |
| `control` | projects, agents, agent_versions, builds, runs |
| `security` | api_keys, audit_events, project_secrets |

Schemas are organizational; they do not replace service boundaries or RLS.

---

## 5. Entity relationships

```text
User
 ├──< Session
 ├──< OrganizationMembership >── Organization
 ├──< OrganizationInvitation (inviter)
 ├──< ApiKey (creator)
 └──< AuditEvent (actor)

Organization
 ├──< OrganizationMembership
 ├──< OrganizationInvitation
 ├──< Project
 ├──< ApiKey
 └──< AuditEvent

Project
 ├──< Agent
 ├──< Build
 ├──< Run
 ├──< ProjectSecret
 └──< AuditEvent

Agent
 ├──< AgentVersion
 ├──< Build
 └──< Run

AgentVersion
 ├──< Build
 └──< Run
```

---

## 6. Entity definitions

## 6.1 User

**Table:** `identity.users`

Purpose: global human identity.

Core columns:

| Column | Type | Constraints |
|---|---|---|
| `id` | UUID | PK |
| `email_normalized` | text | NOT NULL, unique |
| `email_display` | text | NOT NULL |
| `password_hash` | text | nullable for future external-only identity |
| `password_algorithm` | text | nullable; expected `argon2id` |
| `display_name` | text | NOT NULL |
| `email_verified_at` | timestamptz | nullable |
| `status` | text | NOT NULL |
| `failed_login_count` | integer | NOT NULL default 0 |
| `locked_until` | timestamptz | nullable |
| `password_changed_at` | timestamptz | nullable |
| `created_at` | timestamptz | NOT NULL |
| `updated_at` | timestamptz | NOT NULL |
| `deactivated_at` | timestamptz | nullable |
| `version` | bigint | NOT NULL |

Status values:

```text
PENDING_VERIFICATION
ACTIVE
LOCKED
DEACTIVATED
```

Indexes:

- Unique normalized email
- Status
- Created timestamp for administration

Security:

- Password hash uses Argon2id.
- Password reset does not reveal account existence.
- User is global, not tenant-owned, and does not use organization RLS.
- Access to a user through tenant APIs is mediated by membership.

---

## 6.2 Session

**Table:** `identity.sessions`

Purpose: server-side browser session.

Core columns:

| Column | Type | Constraints |
|---|---|---|
| `id` | UUID | PK |
| `user_id` | UUID | FK users, NOT NULL |
| `token_digest` | bytea/text | NOT NULL, unique |
| `csrf_secret_digest` | bytea/text | NOT NULL |
| `created_at` | timestamptz | NOT NULL |
| `last_seen_at` | timestamptz | NOT NULL |
| `idle_expires_at` | timestamptz | NOT NULL |
| `absolute_expires_at` | timestamptz | NOT NULL |
| `rotated_from_session_id` | UUID | nullable self-FK |
| `revoked_at` | timestamptz | nullable |
| `revoke_reason` | text | nullable |
| `user_agent_hash` | text | nullable |
| `ip_prefix_hash` | text | nullable |
| `version` | bigint | NOT NULL |

Indexes:

- Unique token digest
- Active sessions by user
- Expiration cleanup
- Revoked timestamp

Security:

- Raw cookie value is never stored.
- User-agent or IP metadata is minimized and hashed where retained.
- Sessions are global identity records; authorization still requires membership checks.

---

## 6.3 EmailVerificationToken

**Table:** `identity.email_verification_tokens`

Columns:

```text
id UUID PK
user_id UUID FK users NOT NULL
token_digest NOT NULL UNIQUE
created_at timestamptz NOT NULL
expires_at timestamptz NOT NULL
consumed_at timestamptz NULL
request_ip_hash text NULL
```

Rules:

- Raw token not stored.
- Single use.
- Short expiration.
- Issuance and consumption audited.

---

## 6.4 PasswordResetToken

**Table:** `identity.password_reset_tokens`

Columns:

```text
id UUID PK
user_id UUID FK users NOT NULL
token_digest NOT NULL UNIQUE
created_at timestamptz NOT NULL
expires_at timestamptz NOT NULL
consumed_at timestamptz NULL
revoked_at timestamptz NULL
request_ip_hash text NULL
```

Rules:

- Raw token not stored.
- Single use.
- Successful reset revokes outstanding reset tokens.
- Successful reset revokes or rotates existing sessions according to the approved security policy.

---

## 6.5 Organization

**Table:** `identity.organizations`

Columns:

| Column | Type | Constraints |
|---|---|---|
| `id` | UUID | PK |
| `name` | text | NOT NULL |
| `slug` | text | NOT NULL, unique |
| `status` | text | NOT NULL |
| `created_by_user_id` | UUID | FK users |
| `created_at` | timestamptz | NOT NULL |
| `updated_at` | timestamptz | NOT NULL |
| `deleted_at` | timestamptz | nullable |
| `version` | bigint | NOT NULL |

Status:

```text
ACTIVE
SUSPENDED
DELETED
```

Tenancy:

- Organization is the tenant root.
- RLS access is based on verified membership or a privileged internal context.
- Public slug lookup MUST not reveal private organization data.

Invariants:

- An active organization has exactly one effective owner membership.
- Ownership transfer is transactional and audited.

---

## 6.6 OrganizationMembership

**Table:** `identity.organization_memberships`

Columns:

```text
id UUID PK
organization_id UUID FK organizations NOT NULL
user_id UUID FK users NOT NULL
role text NOT NULL
status text NOT NULL
joined_at timestamptz NOT NULL
created_by_user_id UUID FK users NULL
updated_at timestamptz NOT NULL
version bigint NOT NULL
```

Unique constraint:

```text
(organization_id, user_id)
```

Roles:

```text
owner
administrator
developer
analyst
operator
viewer
billing_manager
```

Tenancy:

- RLS by `organization_id`.
- Membership queries must bind the authenticated user and organization.

Invariants:

- The final owner cannot be removed or demoted.
- Role changes use optimistic concurrency.
- Membership deletion is audited.

---

## 6.7 OrganizationInvitation

**Table:** `identity.organization_invitations`

Columns:

```text
id UUID PK
organization_id UUID FK organizations NOT NULL
email_normalized text NOT NULL
role text NOT NULL
token_digest text/bytea NOT NULL UNIQUE
invited_by_user_id UUID FK users NOT NULL
created_at timestamptz NOT NULL
expires_at timestamptz NOT NULL
accepted_at timestamptz NULL
revoked_at timestamptz NULL
idempotency_key_hash text NULL
```

Indexes:

- Organization and active status
- Normalized email
- Expiration cleanup

Tenancy:

- RLS by organization.
- Invitation acceptance verifies the invited email identity.

---

## 6.8 Project

**Table:** `control.projects`

Columns:

| Column | Type | Constraints |
|---|---|---|
| `id` | UUID | PK |
| `organization_id` | UUID | FK organizations, NOT NULL |
| `name` | text | NOT NULL |
| `slug` | text | NOT NULL |
| `description` | text | nullable |
| `status` | text | NOT NULL |
| `created_by_user_id` | UUID | FK users |
| `created_at` | timestamptz | NOT NULL |
| `updated_at` | timestamptz | NOT NULL |
| `deleted_at` | timestamptz | nullable |
| `version` | bigint | NOT NULL |

Unique constraint:

```text
(organization_id, slug)
```

Tenancy:

- RLS by organization.
- Every project lookup checks organization membership.
- Child resources duplicate `organization_id` to strengthen RLS and indexing.

---

## 6.9 Agent

**Table:** `control.agents`

Columns:

```text
id UUID PK
organization_id UUID FK organizations NOT NULL
project_id UUID FK projects NOT NULL
name text NOT NULL
slug text NOT NULL
description text NULL
status text NOT NULL
latest_version_number integer NULL
created_by_user_id UUID FK users NOT NULL
created_at timestamptz NOT NULL
updated_at timestamptz NOT NULL
archived_at timestamptz NULL
version bigint NOT NULL
```

Unique constraint:

```text
(project_id, slug)
```

Status:

```text
DRAFT
ACTIVE
ARCHIVED
```

Tenancy:

- RLS by organization and project.
- Composite foreign-key strategy SHOULD ensure project and organization consistency.

---

## 6.10 AgentVersion

**Table:** `control.agent_versions`

Purpose: immutable versioned Agent contract.

Columns:

```text
id UUID PK
organization_id UUID FK organizations NOT NULL
project_id UUID FK projects NOT NULL
agent_id UUID FK agents NOT NULL
version_number integer NOT NULL
source_type text NOT NULL
source_reference jsonb NOT NULL
manifest jsonb NOT NULL
manifest_schema_version text NOT NULL
input_schema jsonb NOT NULL
output_schema jsonb NOT NULL
dataset_schema jsonb NULL
content_digest text NOT NULL
created_by_user_id UUID FK users NOT NULL
created_at timestamptz NOT NULL
```

Unique constraints:

```text
(agent_id, version_number)
(agent_id, content_digest)
```

Rules:

- Immutable after insertion.
- Manifest and JSON schemas are validated before insertion.
- A correction creates a new version.
- RLS by organization and project.
- Source references MUST not contain plaintext credentials.

---

## 6.11 Build

**Table:** `control.builds`

Columns:

```text
id UUID PK
organization_id UUID FK organizations NOT NULL
project_id UUID FK projects NOT NULL
agent_id UUID FK agents NOT NULL
agent_version_id UUID FK agent_versions NOT NULL
status text NOT NULL
idempotency_key_hash text NULL
request_fingerprint text NULL
image_reference text NULL
image_digest text NULL
registry_provider text NULL
queued_at timestamptz NOT NULL
started_at timestamptz NULL
finished_at timestamptz NULL
failure_code text NULL
failure_summary text NULL
resource_usage jsonb NULL
created_by_actor_type text NOT NULL
created_by_actor_id UUID/text NOT NULL
version bigint NOT NULL
```

Statuses:

```text
QUEUED
STARTING
RUNNING
SCANNING
PUSHING
SUCCEEDED
FAILED
CANCELLED
TIMED_OUT
```

Indexes:

- Project and created time
- Agent and created time
- Status and queued time
- Idempotency scope
- Agent version

Rules:

- State transitions are validated.
- Build logs are stored outside this metadata row.
- The API writes metadata and queues work; it does not run BuildKit.
- RLS by organization and project.

---

## 6.12 Run

**Table:** `control.runs`

Columns:

```text
id UUID PK
organization_id UUID FK organizations NOT NULL
project_id UUID FK projects NOT NULL
agent_id UUID FK agents NOT NULL
agent_version_id UUID FK agent_versions NOT NULL
build_id UUID FK builds NOT NULL
status text NOT NULL
input_reference text/jsonb NOT NULL
runtime_configuration jsonb NOT NULL
memory_mb integer NOT NULL
cpu_millis integer NOT NULL
timeout_seconds integer NOT NULL
idempotency_key_hash text NULL
request_fingerprint text NULL
default_dataset_id UUID NULL
default_key_value_store_id UUID NULL
default_request_queue_id UUID NULL
queued_at timestamptz NOT NULL
started_at timestamptz NULL
finished_at timestamptz NULL
cancel_requested_at timestamptz NULL
cancel_deadline_at timestamptz NULL
failure_code text NULL
failure_summary text NULL
estimated_cost_minor bigint NULL
actual_cost_minor bigint NULL
currency text NULL
version bigint NOT NULL
```

Statuses:

```text
DRAFT
READY
QUEUED
STARTING
RUNNING
PAUSING
PAUSED
SUCCEEDED
PARTIALLY_SUCCEEDED
FAILED
TIMING_OUT
TIMED_OUT
ABORTING
ABORTED
```

Indexes:

- Project and created/queued time
- Agent and time
- Status and queue order
- Build
- Idempotency scope

Rules:

- Status transitions are explicit.
- Cancellation is a unique durable command with an immutable bounded
  convergence deadline.
- Phase 1E accepts inline JSON object inputs up to 64 KiB; larger object-storage inputs remain deferred.
- Runtime configuration is validated against both hard limits and immutable Agent-version limits.
- Run creation and cancellation use a durable command outbox.
- Persisted events are append-only and receive a monotonically increasing per-Run sequence under a transaction-scoped advisory lock.
- Event payloads are size-limited, sanitized, and redact sensitive key names.
- RLS applies to Runs, Run events, and Run command records by organization and project.

---

## 6.13 ApiKey

**Table:** `security.api_keys`

Columns:

```text
id UUID PK
organization_id UUID FK organizations NOT NULL
name text NOT NULL
key_prefix text NOT NULL
key_digest text/bytea NOT NULL UNIQUE
last_four text NOT NULL
environment text NOT NULL
scopes text[]/jsonb NOT NULL
created_by_user_id UUID FK users NOT NULL
created_at timestamptz NOT NULL
expires_at timestamptz NULL
last_used_at timestamptz NULL
revoked_at timestamptz NULL
revoke_reason text NULL
version bigint NOT NULL
```

Rules:

- Full key shown once.
- Raw key never stored.
- RLS by organization.
- Scope checks are mandatory.
- Revocation is immediate at authentication boundaries.
- Last-used writes SHOULD be rate-limited or asynchronously aggregated.

---

## 6.14 AuditEvent

**Table:** `security.audit_events`

Columns:

```text
id UUID PK
organization_id UUID NULL
project_id UUID NULL
event_type text NOT NULL
occurred_at timestamptz NOT NULL
actor_type text NOT NULL
actor_id text NULL
target_type text NULL
target_id text NULL
request_id text NULL
source_ip_hash text NULL
outcome text NOT NULL
reason_code text NULL
metadata jsonb NOT NULL
integrity_hash text NULL
```

Indexes:

- Organization and occurred time
- Project and occurred time
- Event type and occurred time
- Actor and occurred time
- Target and occurred time
- Request ID

Rules:

- Append-only through normal application roles.
- No secret values or credentials in metadata.
- Organization/project may be null for global identity events.
- Update and delete permissions are denied to normal application roles.
- Later archival may copy immutable batches to object storage.

---

## 6.15 ProjectSecret

**Table:** `security.project_secrets`

Columns:

```text
id UUID PK
organization_id UUID FK organizations NOT NULL
project_id UUID FK projects NOT NULL
name text NOT NULL
description text NULL
environment text NOT NULL
ciphertext bytea NOT NULL
encrypted_data_key bytea NOT NULL
key_encryption_key_version text NOT NULL
algorithm text NOT NULL
secret_version integer NOT NULL
created_by_user_id UUID FK users NOT NULL
created_at timestamptz NOT NULL
updated_at timestamptz NOT NULL
last_used_at timestamptz NULL
deleted_at timestamptz NULL
version bigint NOT NULL
```

Unique active constraint:

```text
(project_id, environment, name) WHERE deleted_at IS NULL
```

Rules:

- Values use envelope encryption.
- Plaintext exists only in bounded memory during authorized write or execution injection.
- API responses return metadata only.
- Replacement increments `secret_version`.
- Decryption is not available through the browser API.
- RLS by organization and project.
- Secret names are validated, for example:

```regex
^[A-Z][A-Z0-9_]{0,127}$
```

---

## 7. Tenant isolation and RLS

### 7.1 Runtime database roles

Recommended roles:

```text
rdc_migrator
rdc_api
rdc_worker
rdc_readonly_ops
```

Rules:

- `rdc_migrator` owns schema changes and is unavailable to runtime services.
- `rdc_api` does not own tenant tables.
- `rdc_api` has no `BYPASSRLS`.
- `rdc_worker` receives only permissions needed by execution metadata workflows.
- Operations roles use separately audited access.

### 7.2 Request-scoped context

Within a transaction, the API sets verified context:

```sql
SET LOCAL app.user_id = '<verified-user-id>';
SET LOCAL app.organization_id = '<verified-organization-id>';
SET LOCAL app.project_id = '<verified-project-id>';
```

Values come from authenticated and authorized server context, never directly from unverified headers.

### 7.3 Representative RLS policy

Conceptual example:

```sql
ALTER TABLE control.projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE control.projects FORCE ROW LEVEL SECURITY;

CREATE POLICY project_org_isolation
ON control.projects
USING (
  organization_id = current_setting('app.organization_id', true)::uuid
)
WITH CHECK (
  organization_id = current_setting('app.organization_id', true)::uuid
);
```

Production policies must also account for membership and privileged internal workflows.

### 7.4 Explicit service filters

RLS is not a substitute for correct queries. Repository methods still require organization/project predicates.

Forbidden pattern:

```python
session.get(Project, project_id)
```

Required conceptual pattern:

```python
get_project(project_id=project_id, organization_id=context.organization_id)
```

### 7.5 Tenant tests

Every tenant-owned repository and endpoint requires:

- Same-tenant read success
- Cross-tenant read denial
- Cross-tenant update denial
- Cross-tenant delete denial
- Cross-tenant relationship assignment denial
- Background-job context test
- RLS test using the runtime role

---

## 8. Transaction strategy

Default isolation:

```text
READ COMMITTED
```

Use constraints, row locks, version columns, and idempotency before escalating isolation.

### 8.1 Row locking

`SELECT ... FOR UPDATE` is appropriate for narrow invariants such as:

- Ownership transfer
- Final-owner protection
- Quota reservation
- Credit or balance reservation in later phases

### 8.2 Optimistic concurrency

Mutable resources use a `version` column.

Update pattern:

```sql
UPDATE ...
SET ..., version = version + 1
WHERE id = :id
  AND organization_id = :organization_id
  AND version = :expected_version;
```

Zero updated rows produce `VERSION_CONFLICT` or `RESOURCE_NOT_FOUND` after safe resolution.

### 8.3 Serializable operations

`SERIALIZABLE` is permitted only for explicitly documented critical workflows with whole-transaction retry logic. It is not the global default.

### 8.4 Idempotency records

A later migration should include an idempotency table with:

```text
principal scope
organization_id
method
route template
idempotency_key_hash
request_fingerprint
response status
response reference/body
created_at
expires_at
```

Unique scope prevents concurrent duplicate commands.

---

## 9. Data classification

| Class | Examples | Protection |
|---|---|---|
| Public | Future marketplace descriptions | Integrity, availability |
| Internal | Build status, non-sensitive logs | Tenant authorization |
| Confidential | User profile, project metadata | Encryption, RLS, audit |
| Secret | API keys, project secrets, sessions | Digest/encryption, no reveal, redaction |
| High-risk operational | Runtime credentials, registry credentials | Short-lived, audience-restricted, never persisted in logs |

---

## 10. Migration rules

Every migration MUST:

- Have a clear upgrade path
- Have a downgrade or documented irreversibility
- Avoid unbounded table locks
- Separate schema change from large backfill when needed
- Include index-concurrency planning
- Include RLS and privilege changes
- Update `DB_SCHEMA.md`
- Pass migration tests on an empty database and an upgraded fixture database

Destructive migration requires:

- Data-retention approval
- Backup verification
- Rollback plan
- Bablu approval when product data is affected

---

## 11. Backup and recovery requirements

- Backups are encrypted at rest.
- Backup credentials are separate from application credentials.
- Restore procedures are tested.
- Secret ciphertext and encrypted data keys are backed up; key-management recovery is tested separately.
- Audit events are included in recovery objectives.
- Recovery testing MUST verify RLS, roles, and privileges, not only row data.

---

## 12. Phase 0 unresolved decisions

1. Final PostgreSQL schema names and service ownership boundaries
2. Exact opaque-ID serialization format
3. Organization-level custom roles versus fixed roles
4. Session device metadata retention
5. Audit-integrity chaining in MVP
6. Operational access workflow for support staff
7. Permanent deletion and privacy-erasure sequencing
8. Idempotency table retention
9. Object-storage references for large Run inputs and logs


## Phase 1F execution-plane tables

### `security.worker_identities`

Stores worker metadata, public token prefix, last-four display, token digest, capabilities, concurrency, protocol/software versions, lifecycle state, heartbeat time, expiry, and revocation. Raw worker tokens are never stored.

### `control.execution_leases`

Stores one bounded attempt to process a Build or Run command. It binds the worker, tenant, project, source outbox record, target Build or Run, lease-token digest, immutable payload snapshot and digest, attempt, expiry, renewal, completion, and safe failure metadata. A partial unique index prevents two active leases for the same source command.

### `control.execution_artifacts`

Stores digest-addressed artifact metadata and provenance. Artifact bytes remain in object storage. Each record is bound to one lease and either one Build or one Run.

### `security.secret_injection_grants`

Stores only encrypted worker envelopes and metadata. It binds one active `RUN_START` lease, worker, tenant, project, Run, requested secret names, environment, worker public-key digest, encryption algorithm, expiry, and lifecycle state.

All Phase 1F tenant-owned tables use RLS and tenancy triggers. Worker access is based on transaction-local `rdc.current_worker_id` and active lease relationships.


## Phase 1G storage tables

- `control.storage_objects`: expected and verified object metadata, archive scan state, immutable digest, tenant/Agent ownership.
- `security.storage_grants`: capability digests and short-lived upload/download grant metadata; no URL or credential plaintext.
- `control.agent_versions.source_object_id`: unique immutable source binding for new versions.
- `control.builds.source_object_id`: source snapshot for new Builds.

The migration initially permits null source references for pre-1G rows; all Phase 1G creation paths require them.

## Phase 1H worker attestation columns

`security.worker_identities` adds nullable `sandbox_profile`, nullable SHA-256 `sandbox_attestation_digest`, non-null `sandbox_execution_enabled` default false, and nullable `sandbox_attested_at`. A database check prevents an enabled worker without the required Phase 1H profile, digest, and attestation timestamp.
