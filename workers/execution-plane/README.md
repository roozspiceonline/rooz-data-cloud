# Phase 1F reference worker client

This directory documents the internal worker protocol and provides a small
reference client. It deliberately does **not** execute Agent code or invoke
Docker, Kubernetes, BuildKit, shells, or subprocesses.

The client supports:

- worker-token authentication;
- heartbeat and draining state;
- explicit work claims;
- lease renewal;
- X25519 secret-envelope requests and decryption;
- short-lived, lease-bound source archive download grants.

A production execution runtime must be a separately reviewed service with a
restricted operating-system identity, no control-plane database credentials,
network policy, resource limits, immutable images, artifact verification, and
sandbox escape monitoring. Phase 1G adds verified source-object delivery while preserving the execution-disabled boundary.

Never print worker tokens, lease tokens, decrypted secrets, Run input, or
secret-envelope ciphertext to logs.

## Phase 1H

The protocol now supports a separate `workers/sandbox-runtime` implementation. The reference client still does not execute code automatically. Controlled execution is gated by a strict `rdc.sandbox/v1` attestation and the default-off `RDC_SANDBOX_EXECUTION_ENABLED` setting. Artifact upload/download capabilities are lease-scoped and short-lived.
