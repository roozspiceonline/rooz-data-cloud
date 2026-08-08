# Phase 1O — Tenant-scoped Key-Value Store

Phase 1O adds bounded, versioned mutable state after the Phase 1N Dataset primitive.

## Increment 1 — protocol foundation

Contract: `rdc.kv-write/v1`

Allowed operations: `set`, `delete`.

Allowed set encodings:

```text
application/json              + json
text/plain; charset=utf-8     + utf8
application/octet-stream      + base64
```

Limits:

```text
logical key        1..256 safe ASCII characters
idempotency key    1..128 safe characters
decoded value      <= 1,048,576 bytes
encoded envelope   <= 1,572,864 bytes
JSON depth         <= 32
expected_version   null or 0..9223372036854775807
```

Logical keys are identifiers only and are never trusted as filesystem paths or object-storage keys. The validator computes canonical mutation and decoded-value SHA-256 lineage.

## Increment 1 capability boundary

```text
KV protocol available                 yes
KV persistence                        disabled
KV public API                         disabled
KV worker writes                      disabled
KV object-storage writes              disabled
Agent direct PostgreSQL               prohibited
Agent direct object-storage creds     prohibited
Chromium direct PostgreSQL            prohibited
Request Queue                         out of scope / Phase 1P
```

The API continues to advertise Phase 1N until durable KV persistence and the rest of Phase 1O are complete.

## Increment 2 — metadata persistence + RLS

Increment 2 enables KeyValueStore **metadata only**.

Two store scopes are supported:

```text
PROJECT  reusable across Runs inside one Project
RUN      bound to one exact Run/Agent/AgentVersion lineage
```

Ownership IDs are never accepted in the request body.

Database controls include `control.key_value_stores`, PostgreSQL RLS,
`security.rdc_key_value_store_org(uuid)`, project/run lineage checks, immutable
store identity fields, scope-specific unique names and `kv_store.created` audit
events.

Record mutation remains disabled:

```text
KV record persistence                 disabled
KV object-storage writes              disabled
KV worker writes                      disabled
KV set/delete API                     absent
```

## Increment 3 — versioned records + object-backed values

Increment 3 enables authenticated control-plane record mutation after RLS and
store metadata are already present.

Current capability boundary:

```text
KV metadata persistence               enabled
KV record persistence                 enabled
Control-plane SET                     enabled / kv.write
Control-plane DELETE                  enabled / kv.delete
Optimistic expected_version           enabled
Idempotent mutation receipts          enabled
Immutable version history             enabled
DELETE tombstone versions             enabled
Server-generated object keys          enabled
Object-backed JSON/text/binary        enabled
Live record quota                     10,000 per store
Live byte quota                       268,435,456 per store
Worker KV mutation                    disabled
Worker KV RLS                         disabled
Agent direct PostgreSQL               prohibited
Agent direct object-storage creds     prohibited
Chromium direct PostgreSQL            prohibited
General untrusted Agent execution     release-blocked
```

`expected_version=0` is create-if-absent. Positive expected versions must match
the exact current record version. A stale conditional writer fails closed.

Each successful mutation creates an immutable record-version row and an
idempotency receipt. Reusing the same idempotency key with the same canonical
request digest replays the original receipt; reusing it with a different digest
is a conflict.

SET values are written by the trusted control plane to server-generated S3
object keys derived only from server-owned UUID lineage. The logical KV key is
never used as an object path. DELETE appends a tombstone version and preserves
historical object-backed versions.

Increment 4 remains responsible for the controlled worker KV path.
