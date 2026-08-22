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
rejects secrets, re-verifies source/image digests, and attaches
activation/source/image lineage to every uploaded execution artifact. The
initial Phase 1I profile was `offline-minimal`.

Later canary profiles add independently gated brokered web egress, controlled
browser, Dataset, KV and Request Queue paths. Each path must reproduce its
immutable operation-specific capability receipt; capabilities are not implied
by the sandbox master gate.

## Queue-bound scraping input

With the Request Queue gate enabled, an offline `RUN_START` may claim one item
from the exact Queue bound into the Run. The worker validates the response,
injects `_rdc_queue` without its claim token, runs the Agent with network none,
then completes the claim from the trusted worker process. Queue access cannot
currently be combined with browser, Dataset, KV, or network capabilities.

`RUN_CANCEL` remains available for cleanup even when execution is later
disabled.

## Loss and restart recovery

The worker runs a lease watchdog during every claim. It sends an active
heartbeat every `RDC_WORKER_HEARTBEAT_SECONDS` and renews by
`RDC_WORKER_LEASE_RENEW_SECONDS`. Renewal failure force-cleans the managed
runtime and terminates the worker so the service supervisor restarts it.

Every RDC Run/browser container is created inside the dedicated rootless
namespace with `io.rooz.rdc.managed=true`. Startup and shutdown list only that
label, reject names outside `rdc-run-*`/`rdc-browser-*`, cap targets at 256, and
force-remove exact targets. Workspace cleanup is limited to at most 256 real,
non-symlink `run-*`/`build-*` directories under the configured workspace root.
The worker reports only cleanup counts and a new startup UUID. The API rejects
claims from a previously lost worker until that report is accepted.

## Host boundary

A production worker host must remain non-root, must not expose a host Docker
socket, and must use rootless BuildKit and rootless containerd sockets under
`/run/user/<uid>`. Seccomp/AppArmor, read-only root filesystems, dropped
capabilities, cgroup/time/output limits, and deny-all networking remain
mandatory.

General untrusted Agent execution is not authorized by Phase 1I.
