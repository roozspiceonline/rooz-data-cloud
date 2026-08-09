from __future__ import annotations

import os
import subprocess
from pathlib import Path

from config import SandboxWorkerConfig
from io_utils import write_private_json
from policy import SandboxPolicyError
from worker_recovery import MANAGED_LABEL


def _container_name(run_id: str) -> str:
    return "rdc-run-" + run_id.replace("-", "")[:32]


def load_image(
    config: SandboxWorkerConfig,
    image_archive: Path,
    *,
    timeout_seconds: int = 120,
) -> None:
    completed = subprocess.run(
        [
            "nerdctl",
            "--address",
            config.containerd_address,
            "--namespace",
            config.namespace,
            "load",
            "--input",
            str(image_archive),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=timeout_seconds,
        check=False,
    )
    if completed.returncode != 0:
        raise SandboxPolicyError("OCI image import failed: " + completed.stdout[-4000:])


def run_agent(
    *,
    config: SandboxWorkerConfig,
    run_id: str,
    image_ref: str,
    entrypoint: list[str],
    input_value: dict[str, object],
    secrets: dict[str, object],
    workspace: Path,
    policy: dict[str, object],
) -> tuple[int, Path, Path]:
    input_dir = workspace / "input"
    output_dir = workspace / "output"
    input_dir.mkdir(mode=0o700)
    output_dir.mkdir(mode=0o700)
    input_path = input_dir / "input.json"
    output_path = output_dir / "output.json"
    env_path = workspace / "secrets.env"
    write_private_json(input_path, input_value)
    lines: list[str] = []
    for key, value in sorted(secrets.items()):
        if not isinstance(value, str) or "\n" in value or "\r" in value:
            raise SandboxPolicyError("Secret envelope contains an unsafe value.")
        lines.append(key + "=" + value)
    env_path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    os.chmod(env_path, 0o600)
    log_path = workspace / "run.log"
    name = _container_name(run_id)
    cpus = max(0.1, int(policy["cpu_millis"]) / 1000)
    command = [
        "nerdctl",
        "--address",
        config.containerd_address,
        "--namespace",
        config.namespace,
        "run",
        "--rm",
        "--name",
        name,
        "--label",
        MANAGED_LABEL,
        "--pull",
        "never",
        "--user",
        "65532:65532",
        "--read-only",
        "--security-opt",
        "no-new-privileges",
        "--security-opt",
        "seccomp=" + str(config.seccomp_profile),
        "--security-opt",
        "apparmor=" + config.apparmor_profile,
        "--cap-drop",
        "ALL",
        "--pids-limit",
        str(policy["pids"]),
        "--memory",
        str(policy["memory_mb"]) + "m",
        "--cpus",
        str(cpus),
        "--network",
        "none",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=64m",
        "--mount",
        f"type=bind,src={input_path},dst=/rdc/input/input.json,ro",
        "--mount",
        f"type=bind,src={output_dir},dst=/rdc/output,rw",
        "--env-file",
        str(env_path),
        "--env",
        "RDC_INPUT_PATH=/rdc/input/input.json",
        "--env",
        "RDC_OUTPUT_PATH=/rdc/output/output.json",
        image_ref,
        *entrypoint,
    ]
    timeout = int(policy["timeout_seconds"])
    try:
        with log_path.open("wb") as log_handle:
            completed = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                stdout=log_handle,
                stderr=subprocess.STDOUT,
                timeout=timeout,
                check=False,
            )
    except subprocess.TimeoutExpired as exc:
        cancel_run(config=config, run_id=run_id)
        raise SandboxPolicyError("Run exceeded its sandbox timeout.") from exc
    finally:
        cancel_run(config=config, run_id=run_id)
        env_path.unlink(missing_ok=True)
    return completed.returncode, output_path, log_path


def cancel_run(*, config: SandboxWorkerConfig, run_id: str) -> None:
    try:
        subprocess.run(
            [
                "nerdctl",
                "--address",
                config.containerd_address,
                "--namespace",
                config.namespace,
                "rm",
                "--force",
                _container_name(run_id),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return
