# Phase 1L — Controlled Browser Execution Foundation

Phase 1L starts RDC's browser platform without weakening Phases 1I–1K.

```text
Agent container
  browser: unavailable
  network: none
        |
        v
future versioned browser request
        |
        v
Dedicated RDC browser worker
        |
        v
operator-allowlisted public HTTPS targets
```

This foundation does **not** install or execute Playwright/Chromium.

## `rdc.browser/v1`

The initial contract permits:

- one HTTPS start URL
- `domcontentloaded` or `load`
- snapshot actions only
- optional rendered HTML capture

It excludes clicks, typing, cookies, credentials, downloads, uploads,
arbitrary JavaScript, arbitrary CDP, headers, proxies and persistence.

## Safe default

`RDC_SANDBOX_CANARY_BROWSER_ENABLED=false`

Browser activation additionally depends on the existing sandbox canary and
Phase 1J web-egress gate.

General untrusted browser execution remains release-blocked.

## Browser runtime skeleton

The first browser process boundary lives under `workers/browser-runtime/`.

It pins Playwright Python `1.61.0` and the matching official Noble image,
runs as the non-root `pwuser`, exposes no remote CDP port, and currently accepts
only an explicit `about:blank` self-test.

The runtime is deliberately not imported or launched by
`workers/sandbox-runtime/worker.py`. Live navigation remains disabled until a
later Phase 1L integration supplies browser-specific seccomp and egress
enforcement.

This separation proves the Chromium process boundary without changing the Agent
container, which remains `--network none`.


## Run browser intent and policy receipt

Phase 1L now accepts a top-level `browser` envelope using `rdc.browser/v1`.
The immutable AgentVersion must declare `browser=true` and `network=web-egress`.
The control plane binds the Run to an operator-owned `rdc.browser-policy/v1`
receipt and SHA-256 digest. Agent input cannot supply or modify that policy.

The worker configuration now contains the values needed to independently
reconstruct the same policy in the next integration increment.

`browser` and `web_fetch` are mutually exclusive during Phase 1L. Chromium live
navigation remains unwired.

## Controlled-browser activation receipt

Phase 1L adds a third canary activation profile:
`controlled-browser`.

This profile is valid only for an exact canary `RUN_START` carrying a browser
Run intent, an immutable AgentVersion with `browser=true` and
`network=web-egress`, the existing web-egress gate, and the separate browser
gate.

The activation receipt carries both:

- `egress_policy_digest`
- `browser_policy_digest`

The worker independently reconstructs both policies, compares both digests,
verifies the stored Run browser-policy receipt, and validates the browser plan
again.

Even after all receipt checks pass, Phase 1L deliberately returns
`BROWSER_RUNTIME_NOT_WIRED`. Chromium is not launched by this increment.

## Isolated browser-runtime bridge

The sandbox worker can now bridge a fully verified `controlled-browser`
activation into one isolated Chromium process self-test. The bridge does **not**
consume the Run's `start_url`; it launches the dedicated browser runtime only
with `--self-test`, which opens `about:blank`.

The browser runtime image must already exist in the rootless containerd
namespace and must be configured by immutable local digest:
`rdc.local/browser-runtime@sha256:<64-hex>`.

The bridge uses `--pull never`, non-root `pwuser`, read-only rootfs,
`no-new-privileges`, `cap-drop ALL`, bounded memory/CPU/PIDs, a dedicated
Chromium-compatible seccomp profile, and `--network none`.

A successful bridge emits only a bounded self-test result proving that downloads,
service workers, remote CDP and external navigation remain disabled. Public web
navigation is still not implemented in Phase 1L.

