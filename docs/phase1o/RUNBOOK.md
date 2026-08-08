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
