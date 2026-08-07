from __future__ import annotations

import hashlib
import json
import time
import zipfile
from pathlib import Path
from typing import Any

from browser_policy import (
    BrowserPolicy,
    BrowserPolicyError,
    validate_browser_plan,
)
from build_executor import LocalArtifact, build_agent
from config import SandboxWorkerConfig
from egress_broker import broker_web_requests
from egress_policy import EgressPolicy, EgressPolicyError
from io_utils import cleanup_tree, download_file, private_temp_dir, sha256_file, upload_file
from policy import SandboxPolicyError, verify_host
from rdc_worker_client import RdcWorkerClient, decrypt_secret_envelope, generate_worker_key_pair
from run_executor import cancel_run, load_image, run_agent
from web_fetch_contract import (
    WebFetchContractError,
    phase1j_broker_adapter,
    phase1j_broker_result_adapter,
)


def _data(response: dict[str, Any]) -> dict[str, Any]:
    value = response.get("data")
    if not isinstance(value, dict):
        raise SandboxPolicyError("Worker protocol response is missing data.")
    return value


def _extract_zip(archive: Path, destination: Path) -> None:
    with zipfile.ZipFile(archive) as package:
        for info in package.infolist():
            name = info.filename.replace("\\", "/")
            parts = [part for part in name.split("/") if part not in {"", "."}]
            if name.startswith("/") or ".." in parts:
                raise SandboxPolicyError("Source archive contains an unsafe path.")
        package.extractall(destination)


def _canonical_digest(value: dict[str, object]) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _worker_egress_policy(
    config: SandboxWorkerConfig,
) -> EgressPolicy | None:
    if not config.web_egress_enabled:
        return None
    return EgressPolicy.create(
        config.web_egress_allowed_hosts,
        max_requests=config.web_egress_max_requests,
        max_response_bytes=config.web_egress_max_response_bytes,
        max_total_bytes=config.web_egress_max_total_bytes,
        max_redirects=config.web_egress_max_redirects,
        connect_timeout_seconds=config.web_egress_connect_timeout_seconds,
        request_timeout_seconds=config.web_egress_request_timeout_seconds,
    )


def _worker_browser_policy(
    config: SandboxWorkerConfig,
) -> BrowserPolicy | None:
    if not config.browser_enabled:
        return None
    return BrowserPolicy.create(
        enabled=True,
        allowed_hosts=config.web_egress_allowed_hosts,
        max_pages=config.browser_max_pages,
        max_actions=config.browser_max_actions,
        navigation_timeout_seconds=(
            config.browser_navigation_timeout_seconds
        ),
        max_dom_bytes=config.browser_max_dom_bytes,
        max_screenshot_bytes=config.browser_max_screenshot_bytes,
    )


def _require_canary_activation(
    payload: dict[str, Any],
    *,
    worker_name: str,
    egress_policy: EgressPolicy | None,
    browser_policy: BrowserPolicy | None,
) -> dict[str, object]:
    activation = payload.get("activation")
    sandbox = payload.get("sandbox")
    if not isinstance(activation, dict) or not isinstance(sandbox, dict):
        raise SandboxPolicyError(
            "The control plane did not provide a canary activation receipt."
        )
    if activation.get("mode") != "canary":
        raise SandboxPolicyError("Only canary activation is accepted.")
    if activation.get("worker_name") != worker_name:
        raise SandboxPolicyError(
            "Canary activation is bound to a different worker identity."
        )
    if activation.get("agent_version_id") != payload.get("agent_version_id"):
        raise SandboxPolicyError(
            "Canary activation does not match the immutable Agent version."
        )
    if activation.get("max_concurrency") != 1:
        raise SandboxPolicyError(
            "Canary activation requires single-concurrency execution."
        )
    if activation.get("no_secrets") is not True:
        raise SandboxPolicyError(
            "Canary execution cannot inject project secrets."
        )
    if activation.get("attestation_digest") != sandbox.get(
        "attestation_digest"
    ):
        raise SandboxPolicyError(
            "Canary activation does not match the sandbox attestation."
        )
    if activation.get("sandbox_policy_digest") != _canonical_digest(sandbox):
        raise SandboxPolicyError(
            "Canary activation does not match the sandbox policy digest."
        )

    manifest = payload.get("manifest")
    if not isinstance(manifest, dict):
        raise SandboxPolicyError("Canary claim is missing the Agent manifest.")
    if manifest.get("secrets"):
        raise SandboxPolicyError(
            "Canary Agent manifests cannot declare secrets."
        )

    capabilities = manifest.get("capabilities")
    if not isinstance(capabilities, dict):
        raise SandboxPolicyError("Canary Agent capabilities are missing.")
    browser = capabilities.get("browser")
    if not isinstance(browser, bool):
        raise SandboxPolicyError(
            "Canary Agent browser capability is invalid."
        )
    if (
        capabilities.get("dataset") is not False
        or capabilities.get("keyValueStore") is not False
        or capabilities.get("requestQueue") is not False
    ):
        raise SandboxPolicyError(
            "Canary Agent requested an unsupported storage capability."
        )

    profile = activation.get("capability_profile")
    network = capabilities.get("network")
    egress_digest = activation.get("egress_policy_digest")
    browser_digest = activation.get("browser_policy_digest")

    if profile == "offline-minimal":
        if network != "none":
            raise SandboxPolicyError(
                "Offline-minimal activation requires network=none."
            )
        if egress_digest is not None:
            raise SandboxPolicyError(
                "Offline-minimal activation cannot carry an egress digest."
            )
    elif profile == "brokered-web-egress":
        if browser is not False:
            raise SandboxPolicyError(
                "Brokered web-egress activation cannot enable browser."
            )
        if network != "web-egress":
            raise SandboxPolicyError(
                "Brokered web-egress activation requires network=web-egress."
            )
        if egress_policy is None:
            raise SandboxPolicyError(
                "Worker web-egress policy is disabled or unavailable."
            )
        if egress_digest != egress_policy.digest:
            raise SandboxPolicyError(
                "Canary activation egress-policy digest does not match "
                "the worker policy."
            )
        if browser_digest is not None:
            raise SandboxPolicyError(
                "Brokered web-egress activation cannot carry browser policy."
            )
    elif profile == "controlled-browser":
        if payload.get("work_kind") != "RUN_START":
            raise SandboxPolicyError(
                "Controlled-browser activation is valid only for RUN_START."
            )
        if browser is not True or network != "web-egress":
            raise SandboxPolicyError(
                "Controlled browser requires browser=true and web-egress."
            )
        if egress_policy is None or browser_policy is None:
            raise SandboxPolicyError(
                "Worker browser or web-egress policy is unavailable."
            )
        if egress_digest != egress_policy.digest:
            raise SandboxPolicyError(
                "Controlled-browser egress-policy digest mismatch."
            )
        if browser_digest != browser_policy.digest:
            raise SandboxPolicyError(
                "Controlled-browser policy digest mismatch."
            )

        input_reference = payload.get("input_reference")
        if not isinstance(input_reference, dict):
            raise SandboxPolicyError(
                "Controlled-browser claim lacks an input reference."
            )
        browser_plan = input_reference.get("browser")
        stored_policy = input_reference.get("browser_policy")
        stored_digest = input_reference.get("browser_policy_digest")
        if not isinstance(stored_policy, dict):
            raise SandboxPolicyError(
                "Controlled-browser claim lacks a policy receipt."
            )
        if _canonical_digest(stored_policy) != browser_policy.digest:
            raise SandboxPolicyError(
                "Stored browser policy receipt does not match worker policy."
            )
        if stored_digest != browser_policy.digest:
            raise SandboxPolicyError(
                "Stored browser policy digest does not match worker policy."
            )
        try:
            validate_browser_plan(browser_plan, policy=browser_policy)
        except BrowserPolicyError as exc:
            raise SandboxPolicyError(
                "Browser plan failed independent worker validation."
            ) from exc
    else:
        raise SandboxPolicyError(
            "Canary activation capability profile is unsupported."
        )

    return {str(key): value for key, value in activation.items()}


def _upload_artifacts(
    client: RdcWorkerClient,
    *,
    lease_id: str,
    lease_token: str,
    artifacts: list[LocalArtifact],
) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for artifact in artifacts:
        grant = _data(
            client.artifact_upload(
                lease_id,
                lease_token,
                {
                    "kind": artifact.kind,
                    "digest_algorithm": "sha256",
                    "digest": artifact.digest,
                    "media_type": artifact.media_type,
                    "size_bytes": artifact.size_bytes,
                },
            )
        )
        upload_file(str(grant["url"]), dict(grant["headers"]), artifact.path)
        result.append(
            {
                "kind": artifact.kind,
                "digest_algorithm": "sha256",
                "digest": artifact.digest,
                "object_key": grant["object_key"],
                "media_type": artifact.media_type,
                "size_bytes": artifact.size_bytes,
                "status": "AVAILABLE",
                "scan_status": artifact.scan_status,
                "provenance": artifact.provenance,
            }
        )
    return result


def _build(
    client: RdcWorkerClient,
    config: SandboxWorkerConfig,
    claim: dict[str, Any],
    *,
    worker_name: str,
) -> None:
    lease = _data(claim)
    payload = dict(lease["payload"])
    lease_id = str(lease["id"])
    token = str(lease["lease_token"])
    if (
        payload.get("execution_enabled") is not True
        or not isinstance(payload.get("sandbox"), dict)
    ):
        client.complete(
            lease_id,
            token,
            {
                "outcome": "FAILED",
                "retryable": False,
                "error_code": "SANDBOX_POLICY_DENIED",
                "error_summary": "The control plane did not authorize sandbox execution.",
            },
        )
        return
    workspace = private_temp_dir(config.workspace_root, "build-")
    try:
        egress_policy = _worker_egress_policy(config)
        browser_policy = _worker_browser_policy(config)
        activation = _require_canary_activation(
            payload,
            worker_name=worker_name,
            egress_policy=egress_policy,
            browser_policy=browser_policy,
        )
        source_zip = workspace / "source.zip"
        source_dir = workspace / "source"
        source_dir.mkdir(mode=0o700)
        grant = _data(client.source_download(lease_id, token))
        source_meta = dict(payload["source"])
        download_file(str(grant["url"]), source_zip, max_bytes=int(source_meta["size_bytes"]))
        digest, size = sha256_file(source_zip)
        if digest != source_meta["sha256_digest"] or size != int(source_meta["size_bytes"]):
            raise SandboxPolicyError("Downloaded source digest or size does not match the claim.")
        _extract_zip(source_zip, source_dir)
        client.status(lease_id, token, status="RUNNING")
        artifacts = build_agent(
            config=config,
            source_dir=source_dir,
            workspace=workspace,
            build_id=str(payload["build_id"]),
            agent_version_id=str(payload["agent_version_id"]),
            source_sha256=str(source_meta["sha256_digest"]),
            activation=activation,
            timeout_seconds=int(payload["sandbox"]["timeout_seconds"]),
        )
        registrations = _upload_artifacts(
            client,
            lease_id=lease_id,
            lease_token=token,
            artifacts=artifacts,
        )
        client.complete(
            lease_id,
            token,
            {"outcome": "SUCCEEDED", "retryable": False, "artifacts": registrations},
        )
    except Exception as exc:
        client.complete(
            lease_id,
            token,
            {
                "outcome": "FAILED",
                "retryable": False,
                "error_code": "SANDBOX_BUILD_FAILED",
                "error_summary": str(exc)[:2000],
            },
        )
    finally:
        cleanup_tree(workspace)


def _run(
    client: RdcWorkerClient,
    config: SandboxWorkerConfig,
    claim: dict[str, Any],
    *,
    worker_name: str,
) -> None:
    lease = _data(claim)
    payload = dict(lease["payload"])
    lease_id = str(lease["id"])
    token = str(lease["lease_token"])
    if payload.get("work_kind") == "RUN_CANCEL":
        cancel_run(config=config, run_id=str(payload["run_id"]))
        client.complete(lease_id, token, {"outcome": "ABORTED", "retryable": False})
        return
    if (
        payload.get("execution_enabled") is not True
        or not isinstance(payload.get("sandbox"), dict)
    ):
        client.complete(
            lease_id,
            token,
            {
                "outcome": "FAILED",
                "retryable": False,
                "error_code": "SANDBOX_POLICY_DENIED",
                "error_summary": (
                    "The control plane did not authorize sandbox execution."
                ),
            },
        )
        return
    workspace = private_temp_dir(config.workspace_root, "run-")
    try:
        egress_policy = _worker_egress_policy(config)
        browser_policy = _worker_browser_policy(config)
        activation = _require_canary_activation(
            payload,
            worker_name=worker_name,
            egress_policy=egress_policy,
            browser_policy=browser_policy,
        )
        if activation.get("capability_profile") == "controlled-browser":
            client.complete(
                lease_id,
                token,
                {
                    "outcome": "FAILED",
                    "retryable": False,
                    "error_code": "BROWSER_RUNTIME_NOT_WIRED",
                    "error_summary": (
                        "Controlled browser policy was verified, but live "
                        "browser execution is not wired in Phase 1L yet."
                    ),
                },
            )
            return

        artifact_grant = _data(client.artifact_download(lease_id, token))
        image_path = workspace / "image.oci.tar"
        download_file(
            str(artifact_grant["url"]),
            image_path,
            max_bytes=int(artifact_grant["size_bytes"]),
        )
        digest, size = sha256_file(image_path)
        if digest != artifact_grant["digest"] or size != int(artifact_grant["size_bytes"]):
            raise SandboxPolicyError("Downloaded image artifact failed digest verification.")
        load_image(config, image_path)
        provenance = dict(artifact_grant.get("provenance") or {})
        image_ref = str(provenance.get("image_ref", ""))
        if not image_ref.startswith("rdc.local/agent:"):
            raise SandboxPolicyError("Container artifact provenance lacks a safe image reference.")
        manifest = dict(payload["manifest"])
        runtime = dict(manifest["runtime"])
        entrypoint = [str(value) for value in runtime["entrypoint"]]
        input_ref = dict(payload["input_reference"])
        input_value = dict(input_ref.get("value") or {})
        web_fetch = input_ref.get("web_fetch")
        profile = activation.get("capability_profile")

        if web_fetch is not None and profile != "brokered-web-egress":
            raise SandboxPolicyError(
                "Web-fetch intent requires brokered-web-egress activation."
            )

        if profile == "brokered-web-egress":
            if egress_policy is None:
                raise SandboxPolicyError(
                    "Brokered web-egress activation lacks worker policy."
                )
            if web_fetch is not None:
                if "_rdc_web_requests" in input_value:
                    raise SandboxPolicyError(
                        "Versioned web fetch cannot be mixed with the "
                        "legacy Phase 1J request key."
                    )
                try:
                    broker_input = phase1j_broker_adapter(web_fetch)
                    broker_output = broker_web_requests(
                        broker_input,
                        policy=egress_policy,
                    )
                    web_fetch_result = phase1j_broker_result_adapter(
                        web_fetch,
                        broker_output,
                    )
                except WebFetchContractError:
                    client.complete(
                        lease_id,
                        token,
                        {
                            "outcome": "FAILED",
                            "retryable": False,
                            "error_code": "WEB_FETCH_CONTRACT_INVALID",
                            "error_summary": (
                                "The versioned web-fetch contract was invalid."
                            ),
                        },
                    )
                    return
                except EgressPolicyError:
                    client.complete(
                        lease_id,
                        token,
                        {
                            "outcome": "FAILED",
                            "retryable": False,
                            "error_code": "WEB_FETCH_POLICY_DENIED",
                            "error_summary": (
                                "Brokered web fetch was denied or failed "
                                "within the operator policy."
                            ),
                        },
                    )
                    return
                input_value["_rdc_web_fetch_result"] = web_fetch_result
            else:
                input_value = broker_web_requests(
                    input_value,
                    policy=egress_policy,
                )
        secrets: dict[str, object] = {}
        names = [str(value) for value in manifest.get("secrets", [])]
        if names:
            key_pair = generate_worker_key_pair()
            envelope = client.request_secret_envelope(
                lease_id,
                token,
                names=names,
                environment="production",
                key_pair=key_pair,
            )
            worker = _data(client.worker())
            secrets = decrypt_secret_envelope(
                envelope,
                key_pair=key_pair,
                lease_id=lease_id,
                worker_id=str(worker["id"]),
                run_id=str(payload["run_id"]),
            )
        client.status(lease_id, token, status="RUNNING")
        code, output_path, log_path = run_agent(
            config=config,
            run_id=str(payload["run_id"]),
            image_ref=image_ref,
            entrypoint=entrypoint,
            input_value=input_value,
            secrets=secrets,
            workspace=workspace,
            policy=dict(payload["sandbox"]),
        )
        image_digest = (
            str(artifact_grant["digest_algorithm"])
            + ":"
            + str(artifact_grant["digest"])
        )
        run_provenance = {
            "activation": activation,
            "run_id": str(payload["run_id"]),
            "image_digest": image_digest,
        }
        artifacts: list[LocalArtifact] = []
        if output_path.is_file():
            digest, size = sha256_file(output_path)
            artifacts.append(
                LocalArtifact(
                    "RUN_OUTPUT",
                    output_path,
                    "application/json",
                    digest,
                    size,
                    "NOT_REQUIRED",
                    dict(run_provenance),
                )
            )
        if log_path.is_file():
            digest, size = sha256_file(log_path)
            artifacts.append(
                LocalArtifact(
                    "LOG_BUNDLE",
                    log_path,
                    "text/plain",
                    digest,
                    size,
                    "NOT_REQUIRED",
                    dict(run_provenance),
                )
            )
        registrations = _upload_artifacts(
            client,
            lease_id=lease_id,
            lease_token=token,
            artifacts=artifacts,
        )
        client.complete(
            lease_id,
            token,
            {
                "outcome": "SUCCEEDED" if code == 0 else "FAILED",
                "retryable": False,
                "error_code": None if code == 0 else "AGENT_EXIT_NONZERO",
                "error_summary": None if code == 0 else f"Agent exited with status {code}.",
                "artifacts": registrations,
            },
        )
    except Exception as exc:
        client.complete(
            lease_id,
            token,
            {
                "outcome": "FAILED",
                "retryable": False,
                "error_code": "SANDBOX_RUN_FAILED",
                "error_summary": str(exc)[:2000],
            },
        )
    finally:
        cleanup_tree(workspace)


def main() -> None:
    config = SandboxWorkerConfig.from_env()
    probe = verify_host(config)
    client = RdcWorkerClient(
        base_url=config.api_base_url,
        worker_token=config.worker_token,
    )
    client.heartbeat(
        software_version=config.software_version,
        active_lease_count=0,
        sandbox=probe.attestation,
    )
    worker = _data(client.worker())
    worker_name = str(worker["name"])
    if int(worker["max_concurrency"]) != 1:
        raise SandboxPolicyError(
            "Phase 1J canary worker must have max_concurrency=1."
        )
    while True:
        claim = client.claim(["RUN_CANCEL", "BUILD", "RUN_START"])
        if claim is None:
            time.sleep(config.poll_seconds)
            client.heartbeat(
                software_version=config.software_version,
                active_lease_count=0,
                sandbox=probe.attestation,
            )
            continue
        data = _data(claim)
        if data["work_kind"] == "BUILD":
            _build(
                client,
                config,
                claim,
                worker_name=worker_name,
            )
        else:
            _run(
                client,
                config,
                claim,
                worker_name=worker_name,
            )


if __name__ == "__main__":
    main()
