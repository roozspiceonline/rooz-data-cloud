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
