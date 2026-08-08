# Phase 1O Threat Model

Phase 1O treats KV keys and values as hostile input.

## Increment 1 threats and controls

### Path traversal / object-key confusion

Logical KV keys use a restricted ASCII alphabet and do not permit `/`, backslash, whitespace or traversal syntax. Future object-storage keys must be server-generated and never trust the logical key as a storage path.

### Oversized state

Decoded JSON, UTF-8 text and binary values are capped at 1 MiB. The canonical mutation envelope is capped at 1.5 MiB.

### Parser ambiguity

Only three exact content-type/encoding pairs are accepted. Binary values must be canonical padded base64. JSON rejects NaN, Infinity, non-string object keys and excessive nesting.

### Ownership injection

Set and delete operations use exact top-level field sets. Organization, project, Run, AgentVersion and store ownership fields are rejected.

### Replay ambiguity

Every mutation carries an idempotency key and canonical SHA-256 request digest. Durable replay handling is not activated until persistence exists.

### Lost updates

The protocol carries `expected_version`. Durable persistence must implement optimistic concurrency before public or worker mutation is enabled.

### Secret / credential exfiltration

Increment 1 provides no persistence or storage credentials. Agent and Chromium retain existing network/database isolation.

## Mandatory before mutation activation

- KeyValueStore metadata under PostgreSQL RLS
- versioned record metadata and immutable record-version lineage
- server-generated object-storage paths
- record/store quotas
- optimistic concurrency
- idempotent mutation receipts
- audit events and authenticated API authorization

General untrusted Agent execution remains release-blocked.

## Increment 2 metadata threats

### Cross-scope lineage confusion

PROJECT stores carry no Run/Agent lineage. RUN stores must match one exact Run,
Project, organization, Agent and AgentVersion. The database trigger checks this
independently of the API service.

### Store identity rewriting

Scope, name, ownership lineage and creator are immutable at the database
trigger boundary.

### Premature mutation activation

Increment 2 intentionally contains no record tables, mutation receipts,
object-storage write path, worker RLS policy or set/delete API endpoint.

## Increment 3 mutation controls

### Stale writers

The control plane locks the store and target record, then applies optimistic
concurrency. `expected_version=0` is create-if-absent; positive values require
an exact current-version match. Mismatches fail closed.

### Idempotency races

The store row serializes mutation decisions. Receipts are unique by
store/idempotency key and immutable. Equal key + equal canonical digest replays;
equal key + different digest conflicts.

### Object-key confusion

SET object keys are generated from organization/store/record/version UUIDs.
The logical KV key is never interpolated into an object-storage path or trusted
filesystem path.

### History rewriting

`control.key_value_record_versions` is append-only. DELETE creates a tombstone
version. A deferred current-version pointer constraint binds each record to its
immutable current version.

### Quota bypass

The trusted service updates store counters while holding the store row lock.
Database constraints cap live records at 10,000 and live bytes at 256 MiB.
The protocol separately caps every decoded value at 1 MiB.

### Credential escape

Only the trusted API control plane uses the internal S3 client. Worker KV access
remains disabled until Increment 4. Agent and Chromium receive neither
PostgreSQL nor object-storage credentials.

General untrusted Agent execution remains release-blocked.
## Increment 4 worker controls

### Credential escape

The Agent receives no PostgreSQL URL, worker token, lease token, S3
access key, S3 secret, KV object key or presigned KV object URL. The
trusted control plane performs storage access.

### Lease replay / confused deputy

Internal KV routes require the normal worker bearer credential and the
exact ACTIVE, unexpired RUN_START lease token. Worker RLS independently
binds visible/mutable KV rows to that worker's matching Run lease.

### Read amplification

Read intent is digest-bound to the immutable lease snapshot, limited to
16 safe unique keys and capped at 256 KiB decoded data.

### Mutation smuggling

The worker accepts mutations only from strict
`rdc.kv-worker-output/v1` after successful Agent execution. At most four
canonical `rdc.kv-write/v1` mutations are forwarded, and every mutation
still passes Increment 3 idempotency, expected-version, quota, tombstone
and immutable-history controls.

### Capability composition

Increment 4 rejects Dataset+KV and controlled-browser+KV in the same
canary Run, keeping the new persistence surface isolated.

General untrusted Agent execution remains release-blocked.
