# RDC Phase 1L Browser Runtime Skeleton

This directory contains the first isolated Playwright/Chromium runtime boundary.

## Current state

The runtime is intentionally **not connected** to the sandbox worker or Run API.

Its only accepted operation is an explicit local/container self-test:

```bash
python browser_runtime.py --self-test
```

The self-test opens only `about:blank`. It does not accept a URL and does not
perform network navigation.

## Image

The Dockerfile pins the official Playwright Python image and package to
`1.61.0` and switches to the image's non-root `pwuser`.

The browser is launched with Playwright defaults. RDC does not add
`--no-sandbox`.

## Isolation requirements before live deployment

A later Phase 1L increment must add all of the following before this runtime can
navigate the public web:

- dedicated browser worker/container lifecycle
- browser-specific seccomp profile compatible with Chromium sandboxing
- non-root execution
- no host Docker socket
- no externally reachable CDP/WebSocket port
- no project secrets
- ephemeral browser context/profile per Run
- exact-host public-HTTPS egress enforcement for document and subresources
- redirect/subresource DNS and IP revalidation
- bounded pages/actions/time/DOM/screenshot resources
- immutable browser policy digest verification

The Agent container remains `--network none`.

General untrusted browser execution remains release-blocked.
