# Phase 1M Operator Runbook

## Current status

`rdc.browser/v2` remains receipt-only and non-executable.

The browser-egress policy and Unix gateway transport self-test exist, but live
gateway forwarding is disabled.

```text
Agent network                  none
Browser runtime network        none
Browser→gateway self-test      Unix domain socket
Gateway external request       false
Gateway live forwarding        false
```

## Unix transport self-test

The worker creates one private per-Run IPC directory and socket. The browser
container sees that directory read-only at `/rdc-ipc`.

The exact socket is `/rdc-ipc/gateway.sock`.

The transport handshake must carry the exact `rdc.browser-egress-policy/v1`
SHA-256 digest. Messages are bounded to 4096 bytes. Unknown fields, invalid
nonces and digest mismatches fail closed.

The self-test server performs no DNS, HTTP or TLS forwarding.

## Mandatory browser isolation

- immutable local browser image
- `pwuser`
- read-only rootfs
- no-new-privileges
- browser seccomp + AppArmor
- all capabilities dropped
- bounded PIDs/memory/CPU/tmpfs
- `--network none`
- no published ports
- no host network
- no Docker/containerd socket mount
- only the per-Run IPC directory mounted read-only

## Stop conditions

Stop if any change grants browser Internet networking, publishes browser ports,
mounts a container runtime socket, performs external forwarding in the
transport self-test, weakens gateway-policy digest validation, queues START for
v2, or enables v2 control-plane activation.

## Next increment

Add bounded gateway request/response messages plus Playwright request
interception. The worker gateway may then perform validated/pinned HTTPS
requests while Chromium remains network-none.
