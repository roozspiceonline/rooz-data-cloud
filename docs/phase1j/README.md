# Phase 1J — Restricted Web-Egress Canary

Phase 1J extends the Phase 1I single-AgentVersion canary with a tightly
restricted, brokered HTTPS fetch path.

## Core boundary

**The Agent container remains network-isolated.**

`workers/sandbox-runtime/run_executor.py` continues to launch every Agent
container with:

```text
--network none
```

A worker-side broker performs the only Phase 1J outbound traffic. The broker
validates an operator-owned policy, pins a globally routable DNS answer before
opening the TLS socket, performs bounded HTTPS GET/HEAD requests, revalidates
every redirect destination, and injects sanitized results into the Agent input.

The Agent itself never receives a general-purpose network interface.

## Activation invariants

A `network: web-egress` canary can be authorized only when all of these hold:

1. every Phase 1I canary invariant passes;
2. `RDC_SANDBOX_CANARY_WEB_EGRESS_ENABLED=true`;
3. one exact immutable AgentVersion remains configured;
4. one exact authenticated worker remains configured;
5. worker `max_concurrency=1`;
6. the Agent declares no secrets;
7. browser, dataset, key-value-store and request-queue remain false;
8. the operator allowlist is non-empty;
9. the canonical `rdc.egress/v1` policy digest is bound into the activation
   receipt;
10. the worker independently reconstructs and verifies that digest.

The egress gate defaults to `false`, so deploying this code does not activate
web access.

## Broker request contract

The Run input may contain `_rdc_web_requests`. The worker removes that key
before Agent execution and injects `_rdc_web_results` plus `_rdc_web_budget`.

Only GET and HEAD are supported in Phase 1J. Agent-authored headers,
credentials, arbitrary ports, IP-literal URLs, private destinations, compressed
responses and unrestricted redirects are rejected.

## SSRF controls

- exact operator-owned hostname allowlist
- IDNA normalization
- no wildcards
- no IP literals
- HTTPS port 443 only
- no URL credentials
- all DNS answers must be globally routable
- validated address is pinned into the outbound socket connection
- TLS certificate validation and SNI still use the allowlisted hostname
- every redirect destination is fully revalidated
- request, redirect, per-response, total-byte and timeout ceilings

## Release boundary

Browser automation, unrestricted internet access, secrets, dataset/KV/request
queue capabilities, multiple canary versions and general untrusted Agent
execution remain outside Phase 1J.

General untrusted Agent execution remains release-blocked.
