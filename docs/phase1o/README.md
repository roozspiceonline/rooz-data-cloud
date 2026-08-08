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
