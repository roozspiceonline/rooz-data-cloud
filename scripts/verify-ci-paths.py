"""Verify advisory path classification and permanent full-CI invariants."""

from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from types import ModuleType
from typing import NoReturn

ROOT = Path(__file__).resolve().parents[1]
CLASSIFIER_PATH = ROOT / "scripts/classify-ci-paths.py"
WORKFLOW_PATH = ROOT / ".github/workflows/ci.yml"


def fail(message: str) -> NoReturn:
    print("ERROR:", message, file=sys.stderr)
    raise SystemExit(1)


def load_classifier() -> ModuleType:
    spec = importlib.util.spec_from_file_location("ci_path_classifier", CLASSIFIER_PATH)
    if spec is None or spec.loader is None:
        fail("Unable to load CI path classifier")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def job_block(workflow: str, job_id: str) -> str:
    match = re.search(
        rf"(?ms)^  {re.escape(job_id)}:\n(?P<body>.*?)(?=^  [a-z][a-z0-9-]*:\n|\Z)",
        workflow,
    )
    if match is None:
        fail(f"CI workflow is missing job {job_id!r}")
    return match.group("body")


def main() -> None:
    classifier = load_classifier()
    cases = {
        ("apps/api/app/main.py",): {
            "backend": True, "frontend": False, "scaffold": False,
        },
        ("apps/api/migrations/versions/example.py",): {
            "backend": True, "frontend": False, "scaffold": True,
        },
        ("apps/console/src/app/page.tsx", "packages/ui/src/index.ts"): {
            "backend": False, "frontend": True, "scaffold": False,
        },
        ("docs/security/MERGE_GATES.md",): {
            "backend": False, "frontend": False, "scaffold": True,
        },
        (".github/workflows/ci.yml",): {
            "backend": True, "frontend": True, "scaffold": True,
        },
        ("new-area/contract.txt",): {
            "backend": False, "frontend": False, "scaffold": True,
        },
    }
    for paths, expected in cases.items():
        actual = classifier.classify_paths(list(paths))
        if actual != expected:
            fail(f"Classification mismatch for {paths}: {actual!r} != {expected!r}")
    try:
        classifier.classify_paths(["../outside"])
    except ValueError:
        pass
    else:
        fail("Classifier accepted a path traversal")

    with tempfile.TemporaryDirectory() as temporary_directory:
        temporary_path = Path(temporary_directory)
        nul_file = temporary_path / "paths"
        github_output = temporary_path / "github-output"
        nul_file.write_bytes(b"apps/api/app/main.py\0docs/security/CI_GATES.md\0")
        subprocess.run(
            [
                sys.executable,
                str(CLASSIFIER_PATH),
                "--nul-file",
                str(nul_file),
                "--github-output",
                str(github_output),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        if github_output.read_text(encoding="utf-8").splitlines() != [
            "backend=true",
            "frontend=false",
            "scaffold=true",
        ]:
            fail("Classifier CLI emitted invalid GitHub outputs")

    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
    required_jobs = {
        "frontend": ("Frontend checks", "pnpm build"),
        "backend": ("Backend checks", "uv run pytest"),
        "scaffold": ("Scaffold and Compose checks", "docker compose config --quiet"),
    }
    for job_id, (name, terminal_command) in required_jobs.items():
        block = job_block(workflow, job_id)
        if f"name: {name}" not in block or terminal_command not in block:
            fail(f"Required full job {name!r} lost its complete command set")
        if re.search(r"(?m)^    (?:if|needs):", block):
            fail(f"Required full job {name!r} must remain unconditional")

    required_markers = [
        "Changed-path classification",
        "Advisory backend static checks",
        "Advisory frontend checks",
        "Advisory scaffold checks",
        "git diff --name-only -z --diff-filter=ACMRDT",
        "python3 scripts/classify-ci-paths.py",
        "fetch-depth: 0",
        "github.event_name == 'pull_request'",
    ]
    for marker in required_markers:
        if marker not in workflow:
            fail(f"CI workflow is missing advisory marker {marker!r}")
    if "push:\n    branches: [main]" not in workflow:
        fail("Complete merged-main CI trigger is missing")
    runner = (ROOT / "scripts/run-verifiers.py").read_text(encoding="utf-8")
    if '"verify-ci-paths.py"' not in runner:
        fail("Consolidated verifier runner does not include verify-ci-paths.py")

    print("RDC_ADVISORY_CI_PATHS_OK")


if __name__ == "__main__":
    main()
