from __future__ import annotations

import json

from config import SandboxWorkerConfig
from policy import verify_host
from worker_recovery import force_startup_cleanup


def main() -> None:
    config = SandboxWorkerConfig.from_env()
    verify_host(config)
    report = force_startup_cleanup(config)
    print(
        json.dumps(
            {
                "schema_version": "rdc.supervisor-cleanup/v1",
                "managed_containers_removed": report.managed_containers_removed,
                "workspace_directories_removed": (
                    report.workspace_directories_removed
                ),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )


if __name__ == "__main__":
    main()
