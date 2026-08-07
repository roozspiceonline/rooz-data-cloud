# RDC sandbox runtime worker

The worker is the only Phase 1H/1I component allowed to invoke BuildKit or
containerd/nerdctl. The API remains a pure control plane.

## Phase 1I canary activation

The worker accepts executable Build and Run claims only when the claim contains
both:

- a valid `rdc.sandbox/v1` sandbox policy; and
- a `canary` activation receipt bound to the authenticated worker name and
  immutable AgentVersion.

The worker requires `max_concurrency=1`, recomputes the sandbox-policy digest,
rejects secrets and any capability outside `offline-minimal`, re-verifies
source/image digests, and attaches activation/source/image lineage to every
uploaded execution artifact.

`RUN_CANCEL` remains available for cleanup even when execution is later
disabled.

## Host boundary

A production worker host must remain non-root, must not expose a host Docker
socket, and must use rootless BuildKit and rootless containerd sockets under
`/run/user/<uid>`. Seccomp/AppArmor, read-only root filesystems, dropped
capabilities, cgroup/time/output limits, and deny-all networking remain
mandatory.

General untrusted Agent execution is not authorized by Phase 1I.
