# Phase 1O Operator Runbook

## Increment 1 state

Phase 1O Increment 1 is protocol-only.

Do not enable or add KV persistence, object-storage writes or worker KV mutation in this increment.

Contract: `rdc.kv-write/v1`.

## Fail-closed requirements

Reject:
- unrecognized top-level fields / caller ownership fields
- path-like keys such as `../secret`
- keys with spaces, slashes or control characters
- unsupported or mismatched content type / encoding
- non-canonical base64
- decoded values above 1 MiB
- envelopes above 1.5 MiB
- NaN / Infinity or JSON nesting above 32
- negative or boolean expected versions

## Stop conditions

Stop if implementation:
- gives Agent/Chromium PostgreSQL or object-storage credentials;
- uses a logical key directly as a filesystem/object-storage path;
- persists records before PostgreSQL RLS exists;
- bypasses version checks once mutation is activated;
- overwrites immutable record-version history;
- adds public/anonymous KV access;
- weakens Phase 1N Dataset controls;
- weakens Phase 1M browser/network isolation;
- enables general untrusted Agent execution.

## Increment 2 metadata state

KeyValueStore metadata is persisted under PostgreSQL RLS.

PROJECT stores are reusable across Runs in one Project. RUN stores inherit the
exact authenticated Run/Agent/AgentVersion lineage. Only `name` is supplied by
the caller.

Store scope, name, ownership IDs and creator are immutable after creation.
There is no record value mutation route in Increment 2. Do not add object
uploads, `kv.write`, worker KV policies or record tables until Increment 3
implements immutable version history, optimistic concurrency, idempotency and
quotas.

## Increment 3 mutation state

Authenticated control-plane mutation is enabled only through the store-scoped
SET and DELETE routes. `kv.write` and `kv.delete` are separate permissions.

For every mutation:

- validate `rdc.kv-write/v1` before persistence;
- lock the KeyValueStore row before idempotency, quota and version decisions;
- same idempotency key + same digest returns the original receipt;
- same idempotency key + different digest fails with conflict;
- `expected_version=0` succeeds only when no record lineage exists;
- a positive expected version must equal the exact current record version;
- SET writes at most 1 MiB to a server-generated object-storage key;
- live store state remains within 10,000 records and 256 MiB;
- DELETE creates a tombstone version instead of deleting history;
- record versions and mutation receipts are immutable at the database boundary.

Do not add worker KV RLS, worker mutation routes, Agent/Chromium database
credentials or Agent/Chromium object-storage credentials in Increment 3.
Increment 4 owns the worker path.
## Increment 4 worker state

The worker KV path remains disabled unless the sandbox master gate is in
canary mode, `RDC_SANDBOX_CANARY_KEY_VALUE_STORE_ENABLED=true`, the
immutable Agent manifest declares `keyValueStore=true`, the configured
worker carries `KV_ACCESS`, and the request is bound to an ACTIVE,
unexpired `RUN_START` lease.

Increment 4 rejects Dataset+KV and controlled-browser+KV composition in
one canary Run.

Read handling:
- only the RUN-scoped `default` store is visible;
- `_rdc_kv_read` is removed before Agent execution;
- at most 16 unique safe logical keys are accepted;
- total returned decoded bytes are capped at 256 KiB;
- the control plane verifies stored SHA-256 and size before returning data;
- object keys and storage/database credentials are never returned.

Mutation handling:
- only successful Agent execution is eligible for mutation forwarding;
- output must be `rdc.kv-worker-output/v1`;
- at most four canonical `rdc.kv-write/v1` mutations are forwarded;
- Increment 3 persistence is reused; there is no alternate SQL/storage path;
- failures stop the Run closed;
- multiple mutations are sequential/idempotent, not one exposed
  multi-record transaction.

## Increment 5 read/list state

KV reads and record listing require `kv.read` on the exact store. Returned
values include only the logical key, current version and content provenance;
never return server object keys, worker tokens, lease tokens or credentials.

Reject malformed, tampered, non-canonical or cross-store pagination cursors.
Listing accepts only the protocol-safe key prefix grammar, limits pages to 200
records, excludes tombstones, and verifies value size and SHA-256 before
decoding a returned object. Public or anonymous KV reads remain prohibited.
