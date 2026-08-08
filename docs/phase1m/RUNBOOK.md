# Phase 1M Operator Runbook

## Current status

Protocol foundation only. Do not treat `rdc.browser/v2` as executable.

Phase 1L controls remain authoritative:

```text
RDC_SANDBOX_CANARY_BROWSER_ENABLED=false
Agent container network=none
Browser self-test network=none
```

## Allowed v2 steps

- `goto`
- `wait_for_selector`
- `extract_text`
- `extract_html`
- viewport `screenshot`

The first step must be `goto`.

## Stop conditions

Stop Phase 1M work immediately if any foundation change:

- makes `rdc.browser/v2` API-executable before the browser-egress gateway exists
- sends a public URL into the existing Phase 1L self-test runtime
- removes `--network none` from the Agent
- removes `--network none` from the Phase 1L browser runtime
- allows HTTP or IP-literal navigation
- adds click/type/evaluate/CDP
- allows full-page screenshot in the foundation
- weakens Phase 1L activation or browser-policy receipt validation
- enables project secrets or persistent browser profiles

## Next increment

Add the Run-level v2 intent and immutable receipt representation while keeping
execution fail-closed. The subsequent increment owns the browser-egress gateway
contract and SSRF/subresource mediation.
