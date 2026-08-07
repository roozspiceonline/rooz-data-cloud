#!/usr/bin/env python3
"""Build the deterministic Phase 1I canary Agent source ZIP."""

from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "examples" / "canary-agent"
OUTPUT = ROOT / "phase1i-canary-source.zip"
FILES = [
    "Dockerfile",
    "agent.json",
    "main.py",
    "schemas/input.json",
    "schemas/output.json",
]


def main() -> None:
    with zipfile.ZipFile(
        OUTPUT,
        "w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    ) as archive:
        for relative in FILES:
            path = SOURCE / relative
            data = path.read_bytes()
            info = zipfile.ZipInfo(relative)
            info.date_time = (2026, 1, 1, 0, 0, 0)
            info.external_attr = 0o100644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data)

    digest = hashlib.sha256(OUTPUT.read_bytes()).hexdigest()
    print("Created:", OUTPUT)
    print("SHA-256:", digest)
    print("Bytes:", OUTPUT.stat().st_size)


if __name__ == "__main__":
    main()
