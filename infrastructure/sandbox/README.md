# Phase 1H sandbox host policy

The sandbox runtime is intentionally not added as a privileged Docker Compose service. Production and serious local verification must run on a dedicated Linux execution host with rootless BuildKit and rootless containerd/nerdctl. The API and console never receive container-runtime sockets.

Required controls: non-root execution identity, no host Docker socket, rootless per-user BuildKit/containerd sockets, no insecure BuildKit entitlements, AppArmor profile `rdc-agent-default`, RDC seccomp profile, `no-new-privileges`, all capabilities dropped, read-only root filesystem, cgroup limits, disposable workspaces, and `--network none`.
