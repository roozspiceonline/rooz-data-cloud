# Rooz Data Cloud — Phase 1I

Phase 1I adds controlled sandbox activation for exactly one configured
immutable AgentVersion and one exact single-concurrency sandbox worker.

## Included

- Global sandbox execution master switch remains disabled by default
- Separate activation mode defaults to `disabled`
- `canary` mode requires one exact AgentVersion UUID and one exact worker name
- Canary worker must use `max_concurrency=1`
- Canary Agent must have no secrets, network, browser, dataset, key-value
  store, or request-queue capability
- Canary-specific resource ceilings are narrower than the Phase 1H sandbox
- Claim payloads include a digest-bound activation receipt
- Sandbox worker independently validates the activation receipt
- Build artifact provenance binds activation, AgentVersion, and source SHA-256
- Run artifact provenance binds activation, Run ID, and image digest
- API rejects provenance that does not match the immutable lease snapshot
- Deterministic offline `examples/canary-agent` fixture and runbook
- General untrusted Agent execution remains release-blocked

## Safe default

```text
RDC_SANDBOX_EXECUTION_ENABLED=false
RDC_SANDBOX_ACTIVATION_MODE=disabled
```

Turning on the master switch alone is insufficient. Phase 1I requires the
exact canary version and exact worker configuration before any execution claim
can become enabled.
