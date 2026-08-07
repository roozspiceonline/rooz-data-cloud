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

