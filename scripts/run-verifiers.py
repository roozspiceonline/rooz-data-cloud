from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GROUPS = {
    "foundation": [
        "verify-scaffold.py",
        "verify-phase1b.py",
        "verify-phase1c.py",
        "verify-phase1d.py",
        "verify-phase1e.py",
        "verify-phase1f.py",
        "verify-phase1g.py",
        "verify-phase1h.py",
        "verify-phase1i.py",
        "verify-phase1j.py",
        "verify-phase1k.py",
        "verify-phase1l.py",
        "verify-phase1m.py",
        "verify-phase1n.py",
        "verify-phase1o.py",
        "verify-phase1p.py",
    ],
    "operations": [
        "verify-execution-recovery.py",
        "verify-scheduler.py",
        "verify-events.py",
        "verify-webhook-destinations.py",
        "verify-webhook-deliveries.py",
        "verify-webhook-delivery-security.py",
    ],
    "acquisition": [
        "verify-scraping-runtime.py",
        "verify-proxy-egress.py",
        "verify-egress-health.py",
    ],
    "status": ["validate-project-status.py"],
}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--group", action="append", choices=sorted(GROUPS))
    args = parser.parse_args()
    selected = args.group or list(GROUPS)
    scripts = [script for group in selected for script in GROUPS[group]]
    failures: list[str] = []
    for script in scripts:
        print(f"==> {script}", flush=True)
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / script)],
            cwd=ROOT,
            check=False,
        )
        if result.returncode != 0:
            failures.append(script)
    if failures:
        raise SystemExit("Verifier failures: " + ", ".join(failures))
    print(f"All {len(scripts)} verifier entrypoints passed")


if __name__ == "__main__":
    main()
