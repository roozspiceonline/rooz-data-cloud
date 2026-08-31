"""Classify changed repository paths for advisory CI feedback."""

from __future__ import annotations

import argparse
import json
from pathlib import Path, PurePosixPath

GROUPS = ("backend", "frontend", "scaffold")
GLOBAL_PATHS = {
    ".github",
    "package.json",
    "pnpm-workspace.yaml",
    "turbo.json",
    "tsconfig.base.json",
}
SCAFFOLD_ROOT_PATHS = {
    ".dockerignore",
    ".env.example",
    "CHANGELOG.md",
    "README.md",
    "docker-compose.yml",
}


def _normalized_path(raw_path: str) -> str:
    path = PurePosixPath(raw_path)
    if not raw_path or path.is_absolute() or ".." in path.parts:
        raise ValueError(f"unsafe repository path: {raw_path!r}")
    normalized = path.as_posix()
    if normalized in {"", "."}:
        raise ValueError(f"invalid repository path: {raw_path!r}")
    return normalized


def classify_paths(paths: list[str]) -> dict[str, bool]:
    """Return conservative advisory groups for a set of Git paths."""

    selected = {group: False for group in GROUPS}
    for raw_path in paths:
        path = _normalized_path(raw_path)
        first_part = path.split("/", 1)[0]

        if first_part == ".github" or path in GLOBAL_PATHS:
            return {group: True for group in GROUPS}
        if path.startswith("apps/api/"):
            selected["backend"] = True
            if path.startswith("apps/api/migrations/"):
                selected["scaffold"] = True
            continue
        if path.startswith(("apps/console/", "packages/")):
            selected["frontend"] = True
            continue
        if (
            path in SCAFFOLD_ROOT_PATHS
            or path.startswith(("docs/", "infrastructure/", "scripts/"))
        ):
            selected["scaffold"] = True
            continue

        # Unknown paths receive the lightweight repository-wide checks. This is
        # deliberately fail-safe so a new top-level area is never ignored.
        selected["scaffold"] = True
    return selected


def _read_nul_paths(path: Path) -> list[str]:
    raw = path.read_bytes()
    if not raw:
        return []
    if not raw.endswith(b"\0"):
        raise ValueError("changed-path input must be NUL terminated")
    return [item.decode("utf-8") for item in raw[:-1].split(b"\0")]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("paths", nargs="*")
    parser.add_argument("--nul-file", type=Path)
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args()
    if args.nul_file is not None and args.paths:
        parser.error("paths and --nul-file are mutually exclusive")

    paths = _read_nul_paths(args.nul_file) if args.nul_file else args.paths
    result = classify_paths(paths)
    if args.github_output is not None:
        with args.github_output.open("a", encoding="utf-8") as output:
            for group in GROUPS:
                output.write(f"{group}={str(result[group]).lower()}\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
