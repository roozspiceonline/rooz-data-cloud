from __future__ import annotations

import re
from pathlib import Path

from policy import SandboxPolicyError

_REMOTE_ADD = re.compile(r"^https?://", re.IGNORECASE)


def validate_dockerfile(path: Path, approved_base_images: tuple[str, ...]) -> None:
    if not path.is_file():
        raise SandboxPolicyError("Agent source must contain a root Dockerfile.")
    text = path.read_text(encoding="utf-8")
    if len(text.encode()) > 256 * 1024:
        raise SandboxPolicyError("Dockerfile exceeds the Phase 1H size limit.")
    saw_from = False
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        instruction, _, value = line.partition(" ")
        instruction = instruction.upper()
        value = value.strip()
        if instruction == "FROM":
            saw_from = True
            image = value.split(" AS ", 1)[0].split(" as ", 1)[0].strip()
            if image not in approved_base_images:
                raise SandboxPolicyError(
                    "Dockerfile base image is not in the approved Phase 1H allowlist."
                )
        if instruction == "ADD":
            source = value.split()[0] if value else ""
            if _REMOTE_ADD.match(source):
                raise SandboxPolicyError("Remote Dockerfile ADD is prohibited.")
        if instruction in {"HEALTHCHECK", "STOPSIGNAL"}:
            raise SandboxPolicyError(
                f"Dockerfile instruction is not allowed in Phase 1H: {instruction}"
            )
    if not saw_from:
        raise SandboxPolicyError("Dockerfile must contain an approved FROM instruction.")
