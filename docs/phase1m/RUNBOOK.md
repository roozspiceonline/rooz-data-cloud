# Phase 1M Operator Runbook

## Current status

`rdc.browser/v2` is available as a **receipt-only Run intent**.

It is not executable.

Phase 1L controls remain authoritative:

```text
RDC_SANDBOX_CANARY_BROWSER_ENABLED=false
Agent container network=none
Browser self-test network=none
```

## Receipt-only behavior

When a valid `browser_navigation` v2 request is accepted:

1. exact immutable AgentVersion must declare `browser=true`
2. exact immutable AgentVersion must declare `network=web-egress`
3. every `goto` hostname must match the operator allowlist
4. request limits are checked against browser policy
5. API stores `rdc.browser-navigation-receipt/v1`
6. Run status is `DRAFT`
7. no START outbox command is created
8. control-plane v2 activation remains denied
9. worker-side v2 receipt validation still terminates fail-closed

The receipt binds the deterministic v2 request digest to the browser-policy
digest and records that execution and dispatch are disabled.

## Stop conditions

Stop Phase 1M work immediately if any change:

- queues a START command for a v2 receipt-only Run
- grants v2 a canary sandbox activation
- sends a public URL into the Phase 1L self-test runtime
- removes `--network none` from the Agent
- removes `--network none` from the browser runtime before the dedicated
  browser-egress transport exists
- allows HTTP or IP-literal navigation
- adds click/type/evaluate/CDP
- enables project secrets or persistent browser profiles
- permits a receipt with `execution_enabled=true`
- permits a receipt with `dispatch_enabled=true`

## Next increment

Define the dedicated browser-egress gateway contract and SSRF/subresource
mediation. Chromium must not receive unrestricted host networking.
