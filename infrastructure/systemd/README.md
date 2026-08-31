# Production systemd contracts

These units are reference production contracts for a Linux control-plane host
and a separate Linux sandbox-worker host. Install immutable releases under
`/opt/rdc/releases/<release-id>`, atomically point `/opt/rdc/current` at the
selected release, and install units under `/etc/systemd/system`.

The control-plane host runs `rdc-api.service` and
`rdc-execution-recovery.service` plus `rdc-egress-health-maintenance.service`
as the unprivileged `rdc-api` identity. The recovery and telemetry maintenance
schedulers are continuously restarted and expose database-backed health
contracts. These units use control-group termination, empty capability sets,
strict filesystem protection, no-new-privileges, and environment files outside
the release tree.

The sandbox host runs `rdc-sandbox-worker.service` as a dedicated
`rdc-worker` identity. Rootless containerd and BuildKit must already be running
for that same identity; no Docker socket may exist. The unit performs validated
managed-runtime cleanup before start and after every stop, while the Python
worker also cleans and reports recovery evidence. `KillMode=control-group`, a
bounded graceful timeout, final `SIGKILL`, and `ExecStopPost` ensure worker and
watchdog processes terminate and labeled runtime resources are removed.

Create `/var/lib/rdc-sandbox` owned by `rdc-worker` with mode `0700`.
Environment files under `/etc/rdc/production` must be owned by root, readable
only by the service group, and mode `0640` or stricter. The object-recovery
timer uses a dedicated prefix-scoped credential file and never loads API
secrets. Never copy an example containing `REQUIRED_FROM_*` into service use.

`rdc-postgres-backup.timer` creates mode-`0600` custom-format backups every 15
minutes. A separate restricted transfer agent must copy each `.dump` and its
manifest to immutable off-host storage before the backup counts toward RPO.
`rdc-object-recovery-drill.timer` verifies bucket versioning and exact-version
restore daily using one generated `recovery-drill/` key and removes every canary
version and delete marker.

Before enabling units, run `systemd-analyze verify` on every service and timer,
verify the environment file identities, and execute the runbook restore drill.
The sandbox-worker unit is intentionally not part of `rdc.target`; enable it
only on the dedicated execution host.
