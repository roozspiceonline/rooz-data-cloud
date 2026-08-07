# Phase 1H — Sandboxed Build & Runtime Foundation

Phase 1H introduces the first separately isolated worker that may invoke BuildKit or a container runtime. The API remains a control plane and never receives a container-runtime socket or executes Agent code itself.

## Activation model

`RDC_SANDBOX_EXECUTION_ENABLED` defaults to `false`. When enabled, a worker must heartbeat with a strict `rdc.sandbox/v1` attestation before claim payloads can set `execution_enabled: true`. The attestation requires rootless BuildKit, rootless containerd, no host Docker socket, `no-new-privileges`, a read-only root filesystem, all capabilities dropped, RDC seccomp/AppArmor profiles, cgroup limits, and `deny-all` networking.

Phase 1H intentionally rejects Agents requesting `web-egress` or browser capability. Network egress will be a later phase with a dedicated proxy and SSRF policy.

## Build path

The worker downloads the already verified Phase 1G source ZIP, re-verifies its digest, extracts it only into a disposable worker workspace, validates the root Dockerfile against an approved base-image allowlist, builds with rootless BuildKit and no network, scans the OCI archive with Trivy, generates an SBOM and provenance, obtains short-lived artifact upload grants, and uploads artifacts directly to object storage. The control plane streams the uploaded artifact to recompute SHA-256 before accepting metadata.

## Run path

A Run worker downloads only the passed container artifact bound to the Build, verifies its digest, imports it into rootless containerd, and launches it with nerdctl as UID 65532, all capabilities dropped, no network, read-only root filesystem, seccomp/AppArmor, PID/CPU/memory/time limits, and no control-plane credentials. Inline input is mounted read-only and output is written to a dedicated disposable output mount.

General untrusted production execution remains a later release gate; Phase 1H establishes controlled sandbox execution for explicitly attested workers only.
