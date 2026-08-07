# Rooz Data Cloud — Phase 1H

Phase 1H adds a separately isolated, attested sandbox worker for controlled Build and Run execution. The API remains a control plane and never receives BuildKit/containerd sockets.

## Included

- Strict `rdc.sandbox/v1` worker attestation and execution gating
- Rootless BuildKit and rootless containerd/nerdctl worker implementation
- No host Docker socket, no privileged containers, no control-plane credentials
- Non-root runtime, dropped capabilities, no-new-privileges, read-only root filesystem
- Seccomp/AppArmor policy, cgroup/time/output limits, disposable workspaces
- Phase 1H `deny-all` networking; web egress and browser Agents remain blocked
- Short-lived worker artifact upload/download grants with server-side SHA-256 verification
- OCI image scanning, SBOM and provenance generation
- Build/Run cancellation and cleanup paths
- Migration, protocol schemas, tests, documentation, and CI verification

## Safe default

`RDC_SANDBOX_EXECUTION_ENABLED=false` remains the default. Only explicitly attested workers can receive `execution_enabled: true` after an operator enables the Phase 1H gate. General untrusted Agent execution remains disabled.
