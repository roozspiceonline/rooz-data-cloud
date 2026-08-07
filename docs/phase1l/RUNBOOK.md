# Phase 1L Operator Runbook

Do not enable browser execution during the Phase 1L foundation.

Expected defaults:

```text
RDC_SANDBOX_CANARY_BROWSER_ENABLED=false
RDC_SANDBOX_CANARY_BROWSER_MAX_PAGES=1
RDC_SANDBOX_CANARY_BROWSER_MAX_ACTIONS=8
RDC_SANDBOX_CANARY_BROWSER_NAVIGATION_TIMEOUT_SECONDS=15
RDC_SANDBOX_CANARY_BROWSER_MAX_DOM_BYTES=2097152
RDC_SANDBOX_CANARY_BROWSER_MAX_SCREENSHOT_BYTES=2097152
```

Future browser activation requires:

1. sandbox master gate
2. exact canary mode
3. exact immutable AgentVersion
4. exact worker
5. Phase 1J web-egress enabled
6. exact operator allowlist
7. separate browser gate

Stop rollout if Agent `--network none` changes, browser launches inside the
Agent container, `--no-sandbox` is used, external CDP is exposed, project
secrets enter browser context, profiles persist between Runs, or downloads /
uploads are enabled.

General untrusted browser execution remains release-blocked.

## Browser Run contract

A browser Run uses top-level `rdc.browser/v1` intent. The immutable Agent must
declare `browser=true` and `network=web-egress`. The control plane owns the
`rdc.browser-policy/v1` receipt and digest. A future browser worker must
independently reconstruct the policy and reject any mismatch before Chromium
launch.

Live browser navigation remains disabled in this increment.

## Controlled-browser activation verification

The `controlled-browser` canary profile requires the browser gate to be
explicitly enabled in addition to the existing exact-canary and web-egress
gates.

Before a browser Run could execute, the sandbox worker must independently
verify:

1. exact AgentVersion and worker identity
2. single concurrency
3. `browser=true` and `network=web-egress`
4. egress-policy digest
5. browser-policy digest
6. stored Run browser-policy receipt
7. versioned `rdc.browser/v1` plan against the reconstructed worker policy

Phase 1L still stops after verification with
`BROWSER_RUNTIME_NOT_WIRED`. This is intentional and fail-closed.

Do not interpret a successful activation receipt as permission to launch
Chromium until the dedicated browser runtime/egress bridge increment is
implemented and separately verified.

