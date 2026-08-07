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

## Phase 1K Run request

The control-plane Run API may carry:

```json
{
  "input": {"query": "example"},
  "web_fetch": {
    "schema_version": "rdc.web-fetch/v1",
    "requests": [
      {
        "id": "homepage",
        "method": "GET",
        "url": "https://example.com/"
      }
    ]
  }
}
```

`web_fetch` is accepted only for an immutable Agent version declaring
`network=web-egress`. Actual execution still requires all existing Phase 1J
activation and operator-policy gates.

The Agent does not receive the raw broker transport. It receives the bounded
versioned `_rdc_web_fetch_result` envelope.

## Bounded failure codes

Before Agent execution, Phase 1K can fail with:

- `WEB_FETCH_CONTRACT_INVALID` — versioned request/result contract validation
  failed.
- `WEB_FETCH_POLICY_DENIED` — the broker denied or failed the fetch within the
  operator-owned egress policy.

These summaries intentionally avoid DNS, socket, credential, or internal policy
details.

General untrusted Agent execution remains release-blocked.

