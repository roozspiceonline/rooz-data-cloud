# Phase 1L Operator Runbook

Phase 1L is false-by-default. Do not enable the browser canary except for an
explicitly approved exact AgentVersion and worker.

## Expected defaults

```text
RDC_SANDBOX_CANARY_BROWSER_ENABLED=false
RDC_SANDBOX_CANARY_BROWSER_MAX_PAGES=1
RDC_SANDBOX_CANARY_BROWSER_MAX_ACTIONS=8
RDC_SANDBOX_CANARY_BROWSER_NAVIGATION_TIMEOUT_SECONDS=15
RDC_SANDBOX_CANARY_BROWSER_MAX_DOM_BYTES=2097152
RDC_SANDBOX_CANARY_BROWSER_MAX_SCREENSHOT_BYTES=2097152
RDC_SANDBOX_BROWSER_RUNTIME_IMAGE_REF=
RDC_BROWSER_SECCOMP_PROFILE=infrastructure/sandbox/seccomp-rdc-browser.json
RDC_BROWSER_RUNTIME_TIMEOUT_SECONDS=20
```

The browser runtime timeout must remain between 1 and 30 seconds.

## Canary prerequisites

Before the isolated browser self-test can be activated, require all of:

1. sandbox master gate enabled
2. exact canary activation mode
3. exact immutable AgentVersion
4. exact worker
5. Agent manifest `browser=true`
6. Agent manifest `network=web-egress`
7. Phase 1J web-egress gate enabled
8. exact operator hostname allowlist
9. separate browser gate enabled
10. matching egress-policy digest
11. matching browser-policy digest
12. preloaded immutable local browser image
13. dedicated browser seccomp profile

The browser image reference must use:

```text
rdc.local/browser-runtime@sha256:<64 lowercase hex characters>
```

Mutable tags and external registry references are rejected by the worker.

## Runtime boundary

After all receipt and policy checks pass, the worker may invoke only the
dedicated `about:blank` browser self-test.

The worker launch must retain:

```text
--pull never
--user pwuser
--read-only
--security-opt no-new-privileges
--cap-drop ALL
--network none
--self-test
```

The worker also applies bounded CPU/memory/PIDs, the dedicated browser seccomp
profile and AppArmor.

The named browser container is force-cleaned after every launch attempt,
including timeout and process-start failure paths. Browser stderr is not merged
into the JSON result channel.

## Stop conditions

Stop rollout immediately if any of these occur:

- Agent `--network none` changes
- browser runtime `--network none` changes
- `--no-sandbox` appears
- a mutable browser image is accepted
- an external registry browser image is accepted
- remote CDP or a browser server is exposed
- project secrets enter browser context
- browser profiles persist between Runs
- downloads or uploads become available
- a public `start_url` is sent to Chromium in Phase 1L
- browser policy or egress policy digest verification is bypassed
- container cleanup is removed

## Phase boundary

Phase 1L validates public HTTPS browser intent and binds it to immutable policy,
but it intentionally does not navigate Chromium to that public URL.

Phase 1M owns controlled navigation and interaction semantics. Any Phase 1M
network path must preserve SSRF defenses for top-level requests, redirects and
subresources.

General untrusted browser execution remains release-blocked.
