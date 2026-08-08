# RDC Phase 1L Browser Runtime

This directory contains RDC's isolated Playwright/Chromium runtime boundary.

## Current state

The sandbox worker may invoke this runtime only after a verified
`controlled-browser` canary activation. The only accepted runtime operation is:

```bash
python browser_runtime.py --self-test
```

The self-test opens only `about:blank`. It accepts no URL and performs no
external navigation.

## Image

The Dockerfile pins the Playwright Python image and package to `1.61.0`, and the
container runs as the non-root `pwuser`. RDC does not add `--no-sandbox`.

The worker requires an immutable preloaded local image reference of the form:

```text
rdc.local/browser-runtime@sha256:<64-hex>
```

The worker uses `--pull never`, `--network none`, a read-only root filesystem,
`no-new-privileges`, `cap-drop ALL`, bounded CPU/memory/PIDs and the dedicated
RDC browser seccomp profile.

## Still blocked

Phase 1L does not implement public URL navigation, subresource networking,
redirect handling, cookies, headers, credentials, downloads, uploads, arbitrary
JavaScript, remote CDP, persistent profiles, proxies, CAPTCHA handling, or
project secrets.

The Agent container remains `--network none`.

General untrusted browser execution remains release-blocked.
