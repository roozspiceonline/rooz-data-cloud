# Phase 1L — Controlled Browser Execution Foundation

Phase 1L establishes RDC's controlled browser boundary without weakening the
Agent sandbox.

```text
Agent container
  browser implementation: unavailable
  network: none
        |
        v
rdc.browser/v1 Run intent
        |
        v
control-plane browser-policy receipt
        |
        v
controlled-browser activation receipt
        |
        v
sandbox worker independent verification
        |
        v
dedicated browser runtime
  about:blank self-test only
  network: none
```

## Delivered in Phase 1L

Phase 1L provides:

- a separate browser gate that defaults to `false`
- strict `rdc.browser/v1` Run intent
- `rdc.browser-policy/v1` operator-owned policy receipts
- SHA-256 browser-policy binding
- immutable AgentVersion capability checks
- `controlled-browser` canary activation receipts
- independent worker-side policy and plan validation
- an isolated Playwright/Chromium runtime boundary
- Playwright Python and image pinned to `1.61.0`
- immutable local browser image references
- a dedicated Chromium-compatible seccomp profile
- an offline `about:blank` runtime self-test bridge
- Phase 1L CI verification and operator documentation

## Browser contract

The Phase 1L contract permits:

- one HTTPS start URL in the Run intent
- `domcontentloaded` or `load`
- snapshot actions only
- optional HTML inclusion

The public `start_url` is validated and policy-bound, but Phase 1L does **not**
send it to Chromium. Public navigation belongs to the next browser phase.

`browser` and `web_fetch` are intentionally mutually exclusive in one Phase 1L
Run.

## Safe defaults

```text
RDC_SANDBOX_CANARY_BROWSER_ENABLED=false
RDC_SANDBOX_BROWSER_RUNTIME_IMAGE_REF=
RDC_BROWSER_RUNTIME_TIMEOUT_SECONDS=20
```

Browser canary activation additionally requires:

- sandbox execution enabled
- canary activation mode
- one exact immutable AgentVersion
- one exact worker
- Phase 1J web-egress enabled
- an operator hostname allowlist
- the separate browser gate
- matching egress-policy and browser-policy digests
- an immutable preloaded `rdc.local/browser-runtime@sha256:<64-hex>` image

## Isolated runtime bridge

The sandbox worker may invoke the dedicated browser runtime only after the
complete `controlled-browser` activation receipt passes independent worker
verification.

The browser runtime launches with:

- `--pull never`
- non-root `pwuser`
- read-only root filesystem
- `no-new-privileges`
- `cap-drop ALL`
- bounded CPU, memory and PIDs
- dedicated browser seccomp
- `--network none`
- `--self-test` only

The self-test opens only `about:blank`. It accepts no public URL, no credentials,
no project secrets, no cookies, no uploads/downloads, no remote CDP and no
persistent profile.

The worker force-cleans the named browser container on every runtime exit path.
Browser stderr is discarded rather than mixed with the bounded JSON result
channel.

## Explicit exclusions

Phase 1L does not implement:

- public browser navigation
- subresource networking
- redirects in Chromium
- clicks, typing or forms
- cookies or authentication persistence
- arbitrary headers
- arbitrary JavaScript or CDP
- uploads or downloads
- proxies or anti-blocking
- CAPTCHA solving
- WebRTC
- project secrets
- persistent browser profiles
- general untrusted browser execution

The Agent container remains `--network none`.

General untrusted browser execution remains release-blocked.

Phase 1M owns controlled public navigation and interaction semantics.
