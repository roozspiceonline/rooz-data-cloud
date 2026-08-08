from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

from browser_egress_policy import BrowserEgressPolicy
from browser_gateway_transport import (
    BrowserGatewayBroker,
    BrowserGatewayLiveServer,
    BrowserGatewaySelfTestServer,
    BrowserGatewayTransportError,
)
from browser_navigation_result import (
    BrowserNavigationResultError,
    validate_browser_navigation_result,
)
from config import SandboxWorkerConfig
from policy import SandboxPolicyError

_IMAGE_REF = re.compile(r"^rdc\.local/browser-runtime@sha256:[0-9a-f]{64}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_GATEWAY_SOCKET_IN_CONTAINER = "/rdc-ipc/gateway.sock"
_TRANSPORT_EXPECTED_KEYS = {
    "schema_version",
    "browser",
    "page_url",
    "downloads_enabled",
    "service_workers",
    "remote_cdp",
    "external_navigation",
    "gateway_transport",
    "gateway_policy_digest",
    "gateway_policy_enforced",
    "gateway_external_request",
    "gateway_live_forwarding",
    "browser_network",
}
_EXPECTED_KEYS = {
    "schema_version",
    "browser",
    "page_url",
    "downloads_enabled",
    "service_workers",
    "remote_cdp",
    "external_navigation",
}


class BrowserRuntimeError(SandboxPolicyError):
    pass


def validate_browser_self_test(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != _EXPECTED_KEYS:
        raise BrowserRuntimeError(
            "Browser self-test returned an invalid envelope."
        )
    expected = {
        "schema_version": "rdc.browser-runtime-self-test/v1",
        "browser": "chromium",
        "page_url": "about:blank",
        "downloads_enabled": False,
        "service_workers": "blocked",
        "remote_cdp": False,
        "external_navigation": False,
    }
    if value != expected:
        raise BrowserRuntimeError(
            "Browser self-test did not preserve isolation."
        )
    return {str(key): item for key, item in value.items()}


def validate_browser_transport_self_test(
    value: object,
    *,
    gateway_policy_digest: str,
) -> dict[str, object]:
    if _DIGEST.fullmatch(gateway_policy_digest) is None:
        raise BrowserRuntimeError(
            "Browser gateway policy digest is invalid."
        )
    if not isinstance(value, dict) or set(value) != _TRANSPORT_EXPECTED_KEYS:
        raise BrowserRuntimeError(
            "Browser transport self-test returned an invalid envelope."
        )
    expected = {
        "schema_version": "rdc.browser-gateway-transport-self-test/v1",
        "browser": "chromium",
        "page_url": "about:blank",
        "downloads_enabled": False,
        "service_workers": "blocked",
        "remote_cdp": False,
        "external_navigation": False,
        "gateway_transport": "unix",
        "gateway_policy_digest": gateway_policy_digest,
        "gateway_policy_enforced": True,
        "gateway_external_request": False,
        "gateway_live_forwarding": False,
        "browser_network": "none",
    }
    if value != expected:
        raise BrowserRuntimeError(
            "Browser gateway transport did not preserve isolation."
        )
    return {str(key): item for key, item in value.items()}



def _browser_container_name(run_id: str) -> str:
    normalized = "".join(
        character for character in run_id if character.isalnum()
    )[:32]
    if not normalized:
        raise BrowserRuntimeError("Browser Run id is invalid.")
    return "rdc-browser-" + normalized


def _cleanup_browser_container(
    config: SandboxWorkerConfig,
    name: str,
) -> None:
    command = [
        "nerdctl",
        "--address",
        config.containerd_address,
        "--namespace",
        config.namespace,
        "rm",
        "-f",
        name,
    ]
    try:
        subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return


def browser_self_test_command(
    *,
    config: SandboxWorkerConfig,
    run_id: str,
) -> tuple[str, list[str]]:
    image_ref = config.browser_runtime_image_ref
    if _IMAGE_REF.fullmatch(image_ref) is None:
        raise BrowserRuntimeError(
            "Browser runtime requires an immutable local image digest."
        )
    if not config.browser_seccomp_profile.is_file():
        raise BrowserRuntimeError("Browser seccomp profile is unavailable.")
    if not 1 <= config.browser_runtime_timeout_seconds <= 30:
        raise BrowserRuntimeError(
            "Browser runtime timeout is outside the safe range."
        )

    name = _browser_container_name(run_id)
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
        "--pull",
        "never",
        "--init",
        "--user",
        "pwuser",
        "--read-only",
        "--security-opt",
        "no-new-privileges",
        "--security-opt",
        "seccomp=" + str(config.browser_seccomp_profile),
        "--security-opt",
        "apparmor=" + config.apparmor_profile,
        "--cap-drop",
        "ALL",
        "--pids-limit",
        "128",
        "--memory",
        "512m",
        "--cpus",
        "1.0",
        "--network",
        "none",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,size=128m",
        image_ref,
        "--self-test",
    ]
    return name, command


def run_browser_self_test(
    *,
    config: SandboxWorkerConfig,
    run_id: str,
    workspace: Path,
) -> tuple[Path, Path]:
    output_path = workspace / "browser-runtime-output.json"
    log_path = workspace / "browser-runtime.log"
    name, command = browser_self_test_command(
        config=config,
        run_id=run_id,
    )

    try:
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=config.browser_runtime_timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise BrowserRuntimeError(
            "Browser self-test exceeded its timeout."
        ) from exc
    except OSError as exc:
        raise BrowserRuntimeError(
            "Browser runtime process could not start."
        ) from exc
    finally:
        _cleanup_browser_container(config, name)

    raw = completed.stdout.strip()
    log_path.write_text(
        "browser-runtime self-test exit="
        + str(completed.returncode)
        + "\n",
        encoding="utf-8",
    )
    if completed.returncode != 0:
        raise BrowserRuntimeError("Browser runtime self-test failed.")
    if not raw or len(raw.encode("utf-8")) > 16_384:
        raise BrowserRuntimeError("Browser self-test output is invalid.")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise BrowserRuntimeError(
            "Browser self-test output is not JSON."
        ) from exc

    validated = validate_browser_self_test(payload)
    output_path.write_text(
        json.dumps(
            validated,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )
    return output_path, log_path

def browser_transport_self_test_command(
    *,
    config: SandboxWorkerConfig,
    run_id: str,
    ipc_dir: Path,
    gateway_policy_digest: str,
) -> tuple[str, list[str]]:
    if _DIGEST.fullmatch(gateway_policy_digest) is None:
        raise BrowserRuntimeError(
            "Browser gateway policy digest is invalid."
        )
    if not ipc_dir.is_dir() or ipc_dir.name != "browser-ipc":
        raise BrowserRuntimeError(
            "Browser gateway IPC directory is invalid."
        )
    image_ref = config.browser_runtime_image_ref
    if _IMAGE_REF.fullmatch(image_ref) is None:
        raise BrowserRuntimeError(
            "Browser runtime requires an immutable local image digest."
        )
    if not config.browser_seccomp_profile.is_file():
        raise BrowserRuntimeError("Browser seccomp profile is unavailable.")
    if not 1 <= config.browser_runtime_timeout_seconds <= 30:
        raise BrowserRuntimeError(
            "Browser runtime timeout is outside the safe range."
        )

    name = _browser_container_name(run_id)
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
        "--pull",
        "never",
        "--init",
        "--user",
        "pwuser",
        "--read-only",
        "--security-opt",
        "no-new-privileges",
        "--security-opt",
        "seccomp=" + str(config.browser_seccomp_profile),
        "--security-opt",
        "apparmor=" + config.apparmor_profile,
        "--cap-drop",
        "ALL",
        "--pids-limit",
        "128",
        "--memory",
        "512m",
        "--cpus",
        "1.0",
        "--network",
        "none",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,size=128m",
        "--volume",
        str(ipc_dir) + ":/rdc-ipc:ro",
        image_ref,
        "--transport-self-test",
        "--gateway-socket",
        _GATEWAY_SOCKET_IN_CONTAINER,
        "--gateway-policy-digest",
        gateway_policy_digest,
    ]
    return name, command


def run_browser_transport_self_test(
    *,
    config: SandboxWorkerConfig,
    run_id: str,
    workspace: Path,
    gateway_policy_digest: str,
) -> tuple[Path, Path]:
    output_path = workspace / "browser-transport-output.json"
    log_path = workspace / "browser-transport.log"
    ipc_dir = workspace / "browser-ipc"
    ipc_dir.mkdir(mode=0o755)
    socket_path = ipc_dir / "gateway.sock"
    server = BrowserGatewaySelfTestServer(
        socket_path=socket_path,
        gateway_policy_digest=gateway_policy_digest,
    )
    name, command = browser_transport_self_test_command(
        config=config,
        run_id=run_id,
        ipc_dir=ipc_dir,
        gateway_policy_digest=gateway_policy_digest,
    )

    try:
        with server:
            try:
                completed = subprocess.run(
                    command,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                    timeout=config.browser_runtime_timeout_seconds,
                    check=False,
                )
            except subprocess.TimeoutExpired as exc:
                raise BrowserRuntimeError(
                    "Browser gateway transport self-test exceeded its timeout."
                ) from exc
            except OSError as exc:
                raise BrowserRuntimeError(
                    "Browser runtime process could not start."
                ) from exc
            finally:
                _cleanup_browser_container(config, name)
            server.wait()
    except BrowserGatewayTransportError as exc:
        raise BrowserRuntimeError(
            "Browser gateway Unix transport self-test failed."
        ) from exc
    finally:
        server.close()
        try:
            socket_path.unlink(missing_ok=True)
            ipc_dir.rmdir()
        except OSError:
            pass

    raw = completed.stdout.strip()
    log_path.write_text(
        "browser-gateway transport-self-test exit="
        + str(completed.returncode)
        + "\n",
        encoding="utf-8",
    )
    if completed.returncode != 0:
        raise BrowserRuntimeError(
            "Browser gateway transport self-test failed."
        )
    if not raw or len(raw.encode("utf-8")) > 16_384:
        raise BrowserRuntimeError(
            "Browser gateway transport self-test output is invalid."
        )
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise BrowserRuntimeError(
            "Browser gateway transport self-test output is not JSON."
        ) from exc

    validated = validate_browser_transport_self_test(
        payload,
        gateway_policy_digest=gateway_policy_digest,
    )
    output_path.write_text(
        json.dumps(validated, sort_keys=True, separators=(",", ":"))
        + "\n",
        encoding="utf-8",
    )
    return output_path, log_path


def browser_live_navigation_command(
    *,
    config: SandboxWorkerConfig,
    run_id: str,
    ipc_dir: Path,
    output_dir: Path,
    gateway_policy_digest: str,
    browser_policy_digest: str,
    request_digest: str,
    max_screenshot_bytes: int,
    navigation_timeout_seconds: int,
) -> tuple[str, list[str]]:
    for digest in (
        gateway_policy_digest,
        browser_policy_digest,
        request_digest,
    ):
        if _DIGEST.fullmatch(digest) is None:
            raise BrowserRuntimeError(
                "Browser live-navigation digest is invalid."
            )
    navigation_file = ipc_dir / "navigation.json"
    if (
        not ipc_dir.is_dir()
        or ipc_dir.name != "browser-ipc"
        or not navigation_file.is_file()
        or navigation_file.is_symlink()
        or not output_dir.is_dir()
        or output_dir.name != "browser-output"
    ):
        raise BrowserRuntimeError(
            "Browser live-navigation mount directory is invalid."
        )
    if (
        isinstance(max_screenshot_bytes, bool)
        or not 65_536 <= max_screenshot_bytes <= 4_194_304
        or not 1 <= navigation_timeout_seconds <= 30
    ):
        raise BrowserRuntimeError(
            "Browser live-navigation limit is unsafe."
        )
    image_ref = config.browser_runtime_image_ref
    if _IMAGE_REF.fullmatch(image_ref) is None:
        raise BrowserRuntimeError(
            "Browser runtime requires an immutable local image digest."
        )
    if not config.browser_seccomp_profile.is_file():
        raise BrowserRuntimeError("Browser seccomp profile is unavailable.")
    name = _browser_container_name(run_id)
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
        "--pull",
        "never",
        "--init",
        "--user",
        "pwuser",
        "--read-only",
        "--security-opt",
        "no-new-privileges",
        "--security-opt",
        "seccomp=" + str(config.browser_seccomp_profile),
        "--security-opt",
        "apparmor=" + config.apparmor_profile,
        "--cap-drop",
        "ALL",
        "--pids-limit",
        "64",
        "--memory",
        "256m",
        "--cpus",
        "0.5",
        "--network",
        "none",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,size=128m",
        "--volume",
        str(ipc_dir) + ":/rdc-ipc:ro",
        "--volume",
        str(output_dir) + ":/rdc-output:rw",
        image_ref,
        "--live-navigation",
        "--gateway-socket",
        _GATEWAY_SOCKET_IN_CONTAINER,
        "--gateway-policy-digest",
        gateway_policy_digest,
        "--browser-policy-digest",
        browser_policy_digest,
        "--request-digest",
        request_digest,
        "--max-screenshot-bytes",
        str(max_screenshot_bytes),
        "--navigation-timeout-ms",
        str(navigation_timeout_seconds * 1000),
    ]
    return name, command


def validate_live_navigation_result_file(
    *,
    result_path: Path,
    request_digest: str,
    browser_policy_digest: str,
    browser_egress_policy_digest: str,
    navigation_plan: object,
    max_screenshot_bytes: int,
) -> dict[str, object]:
    if (
        not result_path.is_file()
        or result_path.is_symlink()
        or result_path.name != "result.json"
    ):
        raise BrowserRuntimeError(
            "Browser navigation result file is unavailable."
        )
    raw = result_path.read_bytes()
    if not raw or len(raw) > 16_777_216:
        raise BrowserRuntimeError(
            "Browser navigation result file is outside the safe size limit."
        )
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BrowserRuntimeError(
            "Browser navigation result file is invalid JSON."
        ) from exc
    try:
        return validate_browser_navigation_result(
            value,
            request_digest=request_digest,
            browser_policy_digest=browser_policy_digest,
            browser_egress_policy_digest=browser_egress_policy_digest,
            navigation_plan=navigation_plan,
            max_screenshot_bytes=max_screenshot_bytes,
        )
    except BrowserNavigationResultError as exc:
        raise BrowserRuntimeError(
            "Browser navigation result failed independent validation."
        ) from exc

def run_browser_live_navigation(
    *,
    config: SandboxWorkerConfig,
    run_id: str,
    workspace: Path,
    navigation_plan: dict[str, object],
    browser_policy_digest: str,
    browser_egress_policy: BrowserEgressPolicy,
    request_digest: str,
    max_screenshot_bytes: int,
    navigation_timeout_seconds: int,
    runtime_timeout_seconds: int,
) -> tuple[Path, Path]:
    if not config.browser_live_navigation_enabled:
        raise BrowserRuntimeError("Worker live browser navigation gate is disabled.")
    if not 1 <= runtime_timeout_seconds <= 120:
        raise BrowserRuntimeError("Live browser runtime timeout is outside the safe range.")
    encoded_plan = json.dumps(
        navigation_plan,
        sort_keys=True,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")
    if not encoded_plan or len(encoded_plan) > 65_536:
        raise BrowserRuntimeError("Browser navigation plan is outside the safe size limit.")
    import hashlib
    if hashlib.sha256(encoded_plan).hexdigest() != request_digest:
        raise BrowserRuntimeError("Browser navigation plan digest does not match the receipt.")

    ipc_dir = workspace / "browser-ipc"
    output_dir = workspace / "browser-output"
    ipc_dir.mkdir(mode=0o755)
    output_dir.mkdir(mode=0o700)
    navigation_file = ipc_dir / "navigation.json"
    navigation_file.write_bytes(encoded_plan)
    navigation_file.chmod(0o444)
    socket_path = ipc_dir / "gateway.sock"
    result_path = output_dir / "result.json"
    final_output = workspace / "browser-navigation-output.json"
    log_path = workspace / "browser-navigation.log"

    broker = BrowserGatewayBroker(
        policy=browser_egress_policy,
        gateway_policy_digest=browser_egress_policy.digest,
        live_forwarding_enabled=True,
    )
    server = BrowserGatewayLiveServer(socket_path=socket_path, broker=broker)
    name, command = browser_live_navigation_command(
        config=config,
        run_id=run_id,
        ipc_dir=ipc_dir,
        output_dir=output_dir,
        gateway_policy_digest=browser_egress_policy.digest,
        browser_policy_digest=browser_policy_digest,
        request_digest=request_digest,
        max_screenshot_bytes=max_screenshot_bytes,
        navigation_timeout_seconds=navigation_timeout_seconds,
    )
    server.start()
    try:
        try:
            completed = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=runtime_timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise BrowserRuntimeError("Live browser navigation exceeded its Run timeout.") from exc
        except OSError as exc:
            raise BrowserRuntimeError("Live browser runtime process could not start.") from exc
        finally:
            _cleanup_browser_container(config, name)
    finally:
        server.stop()
    try:
        server.raise_if_failed()
    except BrowserGatewayTransportError as exc:
        raise BrowserRuntimeError("Live browser gateway failed closed.") from exc

    raw = completed.stdout.strip()
    if completed.returncode != 0:
        raise BrowserRuntimeError("Live browser navigation runtime failed.")
    if not raw or len(raw.encode("utf-8")) > 4096:
        raise BrowserRuntimeError("Live browser completion envelope is invalid.")
    try:
        completion = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise BrowserRuntimeError("Live browser completion envelope is not JSON.") from exc
    if completion != {
        "schema_version": "rdc.browser-navigation-runtime-complete/v1",
        "result_written": True,
        "browser_network": "none",
    }:
        raise BrowserRuntimeError("Live browser completion envelope changed.")

    validated = validate_live_navigation_result_file(
        result_path=result_path,
        request_digest=request_digest,
        browser_policy_digest=browser_policy_digest,
        browser_egress_policy_digest=browser_egress_policy.digest,
        navigation_plan=navigation_plan,
        max_screenshot_bytes=max_screenshot_bytes,
    )
    final_output.write_text(
        json.dumps(validated, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    budget = validated.get("egress_budget")
    if not isinstance(budget, dict):
        raise BrowserRuntimeError("Validated browser result lacks egress budget.")
    log_path.write_text(
        "browser-navigation exit=0 requests="
        + str(budget.get("requests_used", 0))
        + " bytes=" + str(budget.get("bytes_received", 0))
        + " redirects=" + str(budget.get("redirects_used", 0))
        + "\n",
        encoding="utf-8",
    )
    return final_output, log_path

