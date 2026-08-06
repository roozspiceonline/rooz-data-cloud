#!/usr/bin/env python3
"""Validate the RDC Phase 1A scaffold without third-party dependencies."""

import compileall
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = [
    "docker-compose.yml",
    "package.json",
    "pnpm-workspace.yaml",
    "turbo.json",
    "apps/api/app/main.py",
    "apps/api/app/api/routes/health.py",
    "apps/api/migrations/versions/20260806_0001_foundation.py",
    "apps/console/src/app/layout.tsx",
    "apps/console/src/components/project-shell.tsx",
    "packages/api-client/src/index.ts",
    "packages/shared-types/src/index.ts",
    "packages/ui/src/index.ts",
    ".github/workflows/ci.yml",
]
FORBIDDEN = [
    (re.compile(r"sk-[A-Za-z0-9_-]{16,}"), "OpenAI-style secret"),
    (re.compile(r"AIza[A-Za-z0-9_-]{20,}"), "Google API key"),
    (re.compile(r"github_pat_[A-Za-z0-9_]{20,}"), "GitHub token"),
    (re.compile(r"ghp_[A-Za-z0-9]{20,}"), "GitHub classic token"),
]


def fail(message: str) -> None:
    print("ERROR:", message, file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    missing = [path for path in REQUIRED if not (ROOT / path).exists()]
    if missing:
        fail("Missing required files: " + ", ".join(missing))

    for path in ROOT.rglob("*.json"):
        try:
            json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            fail(f"Invalid JSON in {path.relative_to(ROOT)}: {exc}")

    if not compileall.compile_dir(str(ROOT / "apps/api/app"), quiet=1, force=True):
        fail("Python API compilation failed")
    if not compileall.compile_dir(str(ROOT / "apps/api/migrations"), quiet=1, force=True):
        fail("Python migration compilation failed")

    text_files = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or path.suffix in {".pyc", ".zip"}:
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        text_files.append((path, content))

    for path, content in text_files:
        for pattern, label in FORBIDDEN:
            if pattern.search(content):
                fail(f"{label} detected in {path.relative_to(ROOT)}")

    client = (ROOT / "packages/api-client/src/index.ts").read_text(encoding="utf-8")
    for required in ['credentials: "include"', "X-RDC-CSRF"]:
        if required not in client:
            fail(f"API client is missing {required}")
    if "localStorage" in client or "sessionStorage" in client:
        fail("API client must not store credentials in browser storage")

    api = (ROOT / "apps/api/app/main.py").read_text(encoding="utf-8")
    if "/api/v1" not in api or "arbitrary_code_in_api" not in api:
        fail("API versioning or execution-plane invariant is missing")

    navigation = (ROOT / "apps/console/src/lib/navigation.ts").read_text(encoding="utf-8")
    for required in ["dashboard", "agents", "builds", "runs", "secrets", "audit"]:
        if required not in navigation:
            fail(f"Navigation is missing {required}")

    print("RDC_PHASE1A_SCAFFOLD_OK")
    print("Required files:", len(REQUIRED))
    print("Text files scanned:", len(text_files))


if __name__ == "__main__":
    main()
