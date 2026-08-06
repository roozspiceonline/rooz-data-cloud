# Phase 1F reference worker client

This directory documents the internal worker protocol and provides a small
reference client. It deliberately does **not** execute Agent code or invoke
Docker, Kubernetes, BuildKit, shells, or subprocesses.

The client supports:

- worker-token authentication;
- heartbeat and draining state;
- explicit work claims;
- lease renewal;
- X25519 secret-envelope requests and decryption.

A production execution runtime must be a separately reviewed service with a
restricted operating-system identity, no control-plane database credentials,
network policy, resource limits, immutable images, artifact verification, and
sandbox escape monitoring. Phase 1F establishes the protocol boundary only.

Never print worker tokens, lease tokens, decrypted secrets, Run input, or
secret-envelope ciphertext to logs.
