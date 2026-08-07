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
