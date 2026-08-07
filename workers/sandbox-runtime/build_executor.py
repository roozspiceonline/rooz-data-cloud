from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path

from config import SandboxWorkerConfig
from dockerfile_policy import validate_dockerfile
from io_utils import sha256_file
from policy import SandboxPolicyError


@dataclass(frozen=True)
class LocalArtifact:
    kind: str
    path: Path
    media_type: str
    digest: str
    size_bytes: int
    scan_status: str
    provenance: dict[str, object]


def _run(argv: list[str], *, timeout: int, cwd: Path | None = None) -> None:
    completed = subprocess.run(
        argv,
        cwd=cwd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=timeout,
        check=False,
    )
    if completed.returncode != 0:
        tail = completed.stdout[-4000:] if completed.stdout else ""
        raise SandboxPolicyError("Sandbox command failed: " + tail)


def build_agent(
    *,
    config: SandboxWorkerConfig,
    source_dir: Path,
    workspace: Path,
    build_id: str,
    agent_version_id: str,
    source_sha256: str,
    activation: dict[str, object],
    timeout_seconds: int,
) -> list[LocalArtifact]:
    validate_dockerfile(source_dir / "Dockerfile", config.approved_base_images)
    image_ref = "rdc.local/agent:" + build_id.replace("-", "")
    image_path = workspace / "image.oci.tar"
    sbom_path = workspace / "sbom.cdx.json"
    provenance_path = workspace / "provenance.json"
    _run(
        [
            "buildctl",
            "--addr",
            config.buildkit_address,
            "build",
            "--frontend",
            "dockerfile.v0",
            "--local",
            "context=" + str(source_dir),
            "--local",
            "dockerfile=" + str(source_dir),
            "--opt",
            "filename=Dockerfile",
            "--opt",
            "network=none",
            "--output",
            f"type=oci,dest={image_path},name={image_ref}",
        ],
        timeout=timeout_seconds,
    )
    _run(
        [
            "trivy",
            "image",
            "--input",
            str(image_path),
            "--severity",
            "HIGH,CRITICAL",
            "--ignore-unfixed",
            "--exit-code",
            "1",
            "--quiet",
        ],
        timeout=min(timeout_seconds, 300),
    )
    _run(
        [
            "trivy",
            "image",
            "--input",
            str(image_path),
            "--format",
            "cyclonedx",
            "--output",
            str(sbom_path),
            "--quiet",
        ],
        timeout=min(timeout_seconds, 300),
    )
    provenance = {
        "schema_version": "rdc.provenance/v1",
        "builder": "buildkit-rootless",
        "runtime": "containerd-rootless",
        "network_policy": "deny-all",
        "image_ref": image_ref,
        "agent_version_id": agent_version_id,
        "source_sha256": source_sha256,
        "activation": dict(activation),
    }
    provenance_path.write_text(json.dumps(provenance, sort_keys=True), encoding="utf-8")
    artifacts: list[LocalArtifact] = []
    for kind, path, media_type, scan_status, extra in [
        (
            "CONTAINER_IMAGE",
            image_path,
            "application/vnd.oci.image.layer.v1.tar",
            "PASSED",
            provenance,
        ),
        (
            "SBOM",
            sbom_path,
            "application/vnd.cyclonedx+json",
            "NOT_REQUIRED",
            {
                "agent_version_id": agent_version_id,
                "source_sha256": source_sha256,
                "activation": dict(activation),
            },
        ),
        (
            "PROVENANCE",
            provenance_path,
            "application/json",
            "NOT_REQUIRED",
            provenance,
        ),
    ]:
        digest, size = sha256_file(path)
        artifacts.append(
            LocalArtifact(
                kind=kind,
                path=path,
                media_type=media_type,
                digest=digest,
                size_bytes=size,
                scan_status=scan_status,
                provenance=dict(extra),
            )
        )
    return artifacts
