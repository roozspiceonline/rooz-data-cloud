from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATUS_PATH = ROOT / "docs/roadmap/rdc-status.json"
MIGRATIONS = ROOT / "apps/api/migrations/versions"
REVISION = re.compile(r'^revision: str = "([0-9A-Za-z_]+)"$', re.MULTILINE)
DOWN_REVISION = re.compile(
    r'^down_revision: str \| None = (?:"([0-9A-Za-z_]+)"|None)$', re.MULTILINE
)


def migration_head() -> str:
    revisions: set[str] = set()
    parents: set[str] = set()
    for path in MIGRATIONS.glob("*.py"):
        source = path.read_text(encoding="utf-8")
        revision = REVISION.search(source)
        parent = DOWN_REVISION.search(source)
        if revision is None or parent is None:
            continue
        revisions.add(revision.group(1))
        if parent.group(1) is not None:
            parents.add(parent.group(1))
    heads = revisions - parents
    if len(heads) != 1:
        raise SystemExit(f"Expected one migration head, found: {sorted(heads)}")
    return heads.pop()


def validate_github_issue(issue_number: int) -> None:
    result = subprocess.run(
        [
            "gh", "issue", "view", str(issue_number), "--repo",
            "roozspiceonline/rooz-data-cloud", "--json", "state", "--jq", ".state",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    if result.stdout.strip() != "OPEN":
        raise SystemExit(f"Referenced product issue #{issue_number} is not open")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--github", action="store_true")
    args = parser.parse_args()
    status = json.loads(STATUS_PATH.read_text(encoding="utf-8"))
    if status.get("schema_version") != "rdc.project-status/v1":
        raise SystemExit("Project status schema version is invalid")
    documented_head = status.get("database_head")
    actual_head = migration_head()
    if documented_head != actual_head:
        raise SystemExit(
            f"Documented database head {documented_head!r} != {actual_head!r}"
        )
    roadmap = status.get("canonical_roadmap")
    if not isinstance(roadmap, str) or not (ROOT / roadmap).is_file():
        raise SystemExit("Canonical roadmap path is invalid")
    workstreams = status.get("workstreams")
    if not isinstance(workstreams, dict) or not workstreams:
        raise SystemExit("Project status must contain workstreams")
    proxy = workstreams.get("proxy_egress")
    if not isinstance(proxy, dict) or proxy.get("status") != "active":
        raise SystemExit("Active proxy/egress workstream is missing")
    referenced_issues = [
        stream.get("current_issue")
        for stream in workstreams.values()
        if isinstance(stream, dict) and "current_issue" in stream
    ]
    if not referenced_issues or any(
        not isinstance(issue, int) or issue < 1 for issue in referenced_issues
    ):
        raise SystemExit("A referenced active product issue is invalid")
    if args.github:
        for issue in referenced_issues:
            assert isinstance(issue, int)
            validate_github_issue(issue)
    print(f"RDC project status is consistent at migration {actual_head}")


if __name__ == "__main__":
    main()
