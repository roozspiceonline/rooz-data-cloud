# Phase 1J — Restricted Web-Egress Canary

Phase 1J is the next security increment after the Phase 1I offline canary.

## Core decision

**The Agent container does not receive a network interface.**

`workers/sandbox-runtime/run_executor.py` continues to launch Agent containers
with `--network none`.

For a Phase 1J web-egress canary, a worker-side fetch broker validates an
operator-owned egress policy, performs a small number of bounded HTTPS
GET/HEAD requests, and injects the sanitized results into the Agent run input.

This is deliberately narrower than general web access.

## Foundation delivered by the first Phase 1J commit

- canonical egress-policy model
- exact-host allowlisting
- HTTPS-only validation
- IP-literal rejection
- public-DNS-only validation
- redirect target revalidation primitive
- deterministic policy digest
- protocol JSON schema
- executable security verifier
- CI hook

The first commit **does not wire the broker into execution** and therefore does
not enable any new runtime capability.

## Planned activation invariants

A future Phase 1J execution claim may use `network: web-egress` only when:

1. every Phase 1I canary invariant passes;
2. `RDC_SANDBOX_CANARY_WEB_EGRESS_ENABLED=true`;
3. the Agent still declares no secrets;
4. browser, dataset, key-value-store and request-queue remain false;
5. the operator allowlist is non-empty;
6. the canonical egress-policy digest is bound into the activation receipt;
7. the worker independently verifies that digest;
8. the run request stays inside request/byte/timeout ceilings.

General untrusted Agent execution remains release-blocked.
