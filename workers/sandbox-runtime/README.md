# Phase 1H sandbox worker

This worker is the first RDC component permitted to invoke BuildKit or a container runtime. It must run on a dedicated Linux execution host as a non-root user. It refuses to start if a host Docker socket is visible, if the BuildKit/containerd sockets are not rootless per-user sockets, or if the required policy tooling is absent.

Phase 1H defaults the control plane to `RDC_SANDBOX_EXECUTION_ENABLED=false`. Set it to true only after the host passes `preflight.py` and the operator has installed the AppArmor/seccomp profiles. Even when globally enabled, only workers that heartbeat with the strict `rdc.sandbox/v1` attestation receive claims with `execution_enabled: true`.

The initial network policy is `deny-all`; Agents requesting `web-egress` or browser capability are not execution-eligible in Phase 1H. Build and runtime containers run without the Docker socket or control-plane credentials, as a non-root UID, with all Linux capabilities dropped, `no-new-privileges`, a read-only root filesystem, PID/CPU/memory limits, and no network.
