# Phase 1K Operator Runbook

## Safe default

Phase 1K adds a contract and adapter only. Existing Phase 1J safe defaults
remain authoritative:

```text
RDC_SANDBOX_CANARY_WEB_EGRESS_ENABLED=false
RDC_SANDBOX_CANARY_WEB_EGRESS_ALLOWED_HOSTS=[]
```

Do not change them to validate the Phase 1K foundation.

## Contract ownership

Agent/run input may describe **what** to fetch: request ID, GET/HEAD and HTTPS
URL. Operator policy continues to decide **whether** the fetch is permitted:
host allowlist, request/redirect count, byte ceilings and timeouts.

The contract cannot widen operator policy.

## Stop conditions

Stop Phase 1K integration if any implementation gives the Agent container a
network interface, accepts Agent-supplied allowlists/headers/cookies/auth,
enables write methods or non-HTTPS URLs, bypasses Phase 1J SSRF controls,
weakens budgets, broadens activation beyond the approved canary, or enables
browser/secrets.

General untrusted Agent execution remains release-blocked.
