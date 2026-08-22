from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.core.config import Settings
from app.core.errors import ApiError
from app.core.security import canonical_fingerprint
from app.execution_schemas import SandboxActivation
from app.models import Run, RunCommandOutbox
from app.run_schemas import CreateRunRequest
from app.services.runs import create_run
from app.services.worker_request_queue import request_queue_capability

WORKER_ROOT = Path(__file__).parents[3] / "workers" / "sandbox-runtime"


def _queue_protocol_module():  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location(
        "rdc_queue_worker_protocol",
        WORKER_ROOT / "queue_worker_protocol.py",
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _worker_config_module():  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location(
        "rdc_sandbox_worker_config",
        WORKER_ROOT / "config.py",
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _worker_module():  # type: ignore[no-untyped-def]
    worker_path = str(WORKER_ROOT)
    if worker_path not in sys.path:
        sys.path.insert(0, worker_path)
    spec = importlib.util.spec_from_file_location(
        "rdc_sandbox_worker",
        WORKER_ROOT / "worker.py",
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _manifest(
    *,
    network: str = "none",
    browser: bool = False,
    dataset: bool = False,
) -> dict[str, object]:
    return {
        "capabilities": {
            "network": network,
            "browser": browser,
            "dataset": dataset,
            "keyValueStore": False,
            "requestQueue": True,
        },
        "resources": {
            "memoryMb": 256,
            "cpuUnits": 500,
            "timeoutSeconds": 120,
            "maxProcesses": 64,
            "ephemeralDiskMb": 256,
        },
        "runtime": {"kind": "container", "entrypoint": ["python", "main.py"]},
        "secrets": [],
    }


def _binding_payload(queue_id: object) -> dict[str, object]:
    return {"schema_version": "rdc.run-queue/v1", "queue_id": str(queue_id)}


def test_run_queue_binding_is_strict_and_reserved() -> None:
    queue_id = uuid4()
    payload = CreateRunRequest.model_validate(
        {
            "build_id": str(uuid4()),
            "input": {"job": "parse"},
            "request_queue": _binding_payload(queue_id),
        }
    )
    assert payload.request_queue is not None
    assert payload.request_queue.queue_id == queue_id

    with pytest.raises(ValidationError, match="reserved _rdc_queue"):
        CreateRunRequest.model_validate(
            {
                "build_id": str(uuid4()),
                "input": {"_rdc_queue": {}},
                "request_queue": _binding_payload(queue_id),
            }
        )
    for reserved in (
        "_rdc_queue_http",
        "_rdc_queue_browser",
        "_rdc_web_requests",
    ):
        with pytest.raises(ValidationError, match="reserved _rdc_queue"):
            CreateRunRequest.model_validate(
                {
                    "build_id": str(uuid4()),
                    "input": {reserved: {}},
                    "request_queue": _binding_payload(queue_id),
                }
            )
    with pytest.raises(ValidationError, match="only one"):
        CreateRunRequest.model_validate(
            {
                "build_id": str(uuid4()),
                "request_queue": _binding_payload(queue_id),
                "web_fetch": {
                    "schema_version": "rdc.web-fetch/v1",
                    "requests": [
                        {
                            "id": "one",
                            "method": "GET",
                            "url": "https://example.com/",
                        }
                    ],
                },
            }
        )


def test_queue_http_gates_are_independent_and_fail_closed() -> None:
    assert Settings().sandbox_canary_request_queue_http_enabled is False
    with pytest.raises(ValueError, match="requires the Request Queue gate"):
        Settings(sandbox_canary_request_queue_http_enabled=True)
    with pytest.raises(ValidationError, match="requires Queue access"):
        SandboxActivation(
            agent_version_id=uuid4(),
            worker_name="scraping-worker",
            attestation_digest="a" * 64,
            sandbox_policy_digest="b" * 64,
            constraints_digest="c" * 64,
            capability_profile="brokered-web-egress",
            egress_policy_digest="d" * 64,
            request_queue_http_enabled=True,
        )
    assert Settings().sandbox_canary_request_queue_browser_enabled is False
    with pytest.raises(ValueError, match="requires the Request Queue gate"):
        Settings(sandbox_canary_request_queue_browser_enabled=True)
    with pytest.raises(ValidationError, match="requires Queue access"):
        SandboxActivation(
            agent_version_id=uuid4(),
            worker_name="scraping-worker",
            attestation_digest="a" * 64,
            sandbox_policy_digest="b" * 64,
            constraints_digest="c" * 64,
            capability_profile="controlled-browser",
            egress_policy_digest="d" * 64,
            browser_policy_digest="e" * 64,
            request_queue_browser_enabled=True,
        )
    assert Settings().sandbox_canary_request_queue_dataset_enabled is False
    with pytest.raises(ValueError, match="requires Queue and Dataset gates"):
        Settings(sandbox_canary_request_queue_dataset_enabled=True)
    with pytest.raises(ValidationError, match="explicit composition receipt"):
        SandboxActivation(
            agent_version_id=uuid4(),
            worker_name="scraping-worker",
            attestation_digest="a" * 64,
            sandbox_policy_digest="b" * 64,
            constraints_digest="c" * 64,
            dataset_write_enabled=True,
            request_queue_enabled=True,
        )


def test_worker_queue_browser_gate_requires_all_dependencies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_module = _worker_config_module()
    monkeypatch.setenv("RDC_WORKER_TOKEN", "worker-token")
    monkeypatch.setenv(
        "RDC_SANDBOX_CANARY_REQUEST_QUEUE_BROWSER_ENABLED", "true"
    )
    with pytest.raises(RuntimeError, match="requires Queue"):
        config_module.SandboxWorkerConfig.from_env()

    for name in (
        "RDC_SANDBOX_CANARY_REQUEST_QUEUE_ENABLED",
        "RDC_SANDBOX_CANARY_WEB_EGRESS_ENABLED",
        "RDC_SANDBOX_CANARY_BROWSER_ENABLED",
        "RDC_SANDBOX_CANARY_BROWSER_LIVE_NAVIGATION_ENABLED",
    ):
        monkeypatch.setenv(name, "true")
    with pytest.raises(RuntimeError, match="allowlist"):
        config_module.SandboxWorkerConfig.from_env()

    monkeypatch.setenv(
        "RDC_SANDBOX_CANARY_WEB_EGRESS_ALLOWED_HOSTS",
        '["example.com"]',
    )
    config = config_module.SandboxWorkerConfig.from_env()
    assert config.request_queue_browser_enabled is True


def test_worker_queue_dataset_gate_requires_both_dependencies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_module = _worker_config_module()
    monkeypatch.setenv("RDC_WORKER_TOKEN", "worker-token")
    monkeypatch.setenv(
        "RDC_SANDBOX_CANARY_REQUEST_QUEUE_DATASET_ENABLED", "true"
    )
    with pytest.raises(RuntimeError, match="requires Queue and Dataset"):
        config_module.SandboxWorkerConfig.from_env()

    monkeypatch.setenv("RDC_SANDBOX_CANARY_REQUEST_QUEUE_ENABLED", "true")
    monkeypatch.setenv("RDC_SANDBOX_CANARY_DATASET_WRITES_ENABLED", "true")
    config = config_module.SandboxWorkerConfig.from_env()
    assert config.request_queue_dataset_enabled is True


def test_queue_worker_protocol_rejects_scope_and_ip_literals() -> None:
    protocol = _queue_protocol_module()
    queue_id = str(uuid4())
    value = {
        "id": str(uuid4()),
        "queue_id": queue_id,
        "url": "https://example.com/path",
        "user_data": {"page": 1},
        "attempt_count": 1,
        "claim_token": str(uuid4()),
    }
    normalized = protocol.validate_queue_claim_result(
        value,
        expected_queue_id=queue_id,
    )
    assert normalized["schema_version"] == "rdc.queue-worker-claim/v1"
    assert "claim_token" in normalized

    with pytest.raises(protocol.QueueWorkerBoundaryError, match="bound Queue"):
        protocol.validate_queue_claim_result(
            value,
            expected_queue_id=str(uuid4()),
        )
    with pytest.raises(protocol.QueueWorkerBoundaryError, match="IP literal"):
        protocol.validate_queue_claim_result(
            {**value, "url": "https://127.0.0.1/private"},
            expected_queue_id=queue_id,
        )
    for url in (
        "https://user:password@example.com/private",
        "https://example.com:444/private",
        "http://example.com/private",
    ):
        with pytest.raises(protocol.QueueWorkerBoundaryError, match="invalid"):
            protocol.validate_queue_claim_result(
                {**value, "url": url},
                expected_queue_id=queue_id,
            )


def test_queue_dataset_idempotency_is_server_derived_and_token_free() -> None:
    protocol = _queue_protocol_module()
    request_id, queue_id = uuid4(), uuid4()
    claim = {
        "schema_version": "rdc.queue-worker-claim/v1",
        "request_id": str(request_id),
        "queue_id": str(queue_id),
        "claim_token": "secret-claim-token",
    }
    key = protocol.queue_dataset_idempotency_key(claim)
    assert key == f"queue:{request_id}"
    assert "secret-claim-token" not in key

    tampered = {**claim, "queue_id": str(uuid4()) + "-invalid"}
    with pytest.raises(
        protocol.QueueWorkerBoundaryError,
        match="scope is invalid",
    ):
        protocol.queue_dataset_idempotency_key(tampered)


def test_queue_dataset_persists_before_handled_completion() -> None:
    worker = (WORKER_ROOT / "worker.py").read_text(encoding="utf-8")
    segment = worker.split("dataset_enabled = (", 1)[1]
    segment = segment.split("image_digest = (", 1)[0]
    assert segment.index("client.dataset_append(") < segment.rindex(
        "client.queue_complete("
    )
    assert 'failure_code="DATASET_APPEND_FAILED"' in segment
    assert "queue_dataset_idempotency_key(queue_claim)" in segment


def test_queue_http_protocol_is_claim_derived_and_token_free() -> None:
    protocol = _queue_protocol_module()
    claim = {
        "schema_version": "rdc.queue-worker-claim/v1",
        "request_id": str(uuid4()),
        "queue_id": str(uuid4()),
        "url": "https://example.com/items/1",
        "user_data": {"page": 1},
        "attempt_count": 1,
        "claim_token": str(uuid4()),
    }
    envelope = protocol.queue_http_fetch_envelope(claim)
    assert envelope == {
        "schema_version": "rdc.web-fetch/v1",
        "requests": [
            {
                "id": "queue-request",
                "method": "GET",
                "url": claim["url"],
            }
        ],
    }
    request_digest = canonical_fingerprint(envelope)
    result = protocol.queue_http_agent_result(
        claim,
        {
            "schema_version": "rdc.web-fetch-result/v1",
            "request_digest": request_digest,
            "results": [
                {
                    "id": "queue-request",
                    "method": "GET",
                    "url": claim["url"],
                    "status": 200,
                    "headers": {"content-type": "text/plain"},
                    "body": {
                        "encoding": "text",
                        "value": "ok",
                        "size_bytes": 2,
                        "sha256": "2" * 64,
                    },
                }
            ],
            "budget": {
                "bytes_received": 2,
                "max_requests": 8,
                "max_total_bytes": 4_194_304,
                "requests_used": 1,
            },
        },
    )
    assert result["schema_version"] == "rdc.queue-http-result/v1"
    assert result["request_id"] == claim["request_id"]
    assert "claim_token" not in result

    with pytest.raises(protocol.QueueWorkerBoundaryError, match="invalid"):
        protocol.queue_http_agent_result(
            claim,
            {
                "schema_version": "rdc.web-fetch-result/v1",
                "request_digest": "0" * 64,
                "results": [],
                "budget": {},
            },
        )


def test_queue_browser_protocol_is_claim_derived_bounded_and_token_free() -> None:
    protocol = _queue_protocol_module()
    claim = {
        "schema_version": "rdc.queue-worker-claim/v1",
        "request_id": str(uuid4()),
        "queue_id": str(uuid4()),
        "url": "https://example.com/items/1",
        "user_data": {"page": 1},
        "attempt_count": 1,
        "claim_token": str(uuid4()),
    }
    plan = protocol.queue_browser_navigation_plan(
        claim,
        max_dom_bytes=131_072,
    )
    assert plan == {
        "schema_version": "rdc.browser/v2",
        "steps": [
            {
                "id": "queue-goto",
                "type": "goto",
                "url": claim["url"],
                "wait_until": "domcontentloaded",
            },
            {
                "id": "queue-html",
                "type": "extract_html",
                "selector": "html",
                "max_bytes": 131_072,
            },
        ],
    }
    navigation_result = {
        "schema_version": "rdc.browser-navigation-result/v1",
        "request_digest": canonical_fingerprint(plan),
        "browser_policy_digest": "a" * 64,
        "browser_egress_policy_digest": "b" * 64,
        "browser_network": "none",
        "gateway_transport": "unix",
        "gateway_live_forwarding": True,
        "final_url": claim["url"],
        "steps": [
            {
                "id": "queue-goto",
                "type": "goto",
                "url": claim["url"],
            },
            {
                "id": "queue-html",
                "type": "extract_html",
                "html": "<html></html>",
                "truncated": False,
            },
        ],
        "egress_budget": {
            "requests_used": 1,
            "bytes_received": 13,
            "redirects_used": 0,
            "max_requests": 8,
            "max_total_bytes": 4_194_304,
            "max_redirects": 3,
        },
    }
    result = protocol.queue_browser_agent_result(
        claim,
        plan,
        navigation_result,
    )
    assert result["schema_version"] == "rdc.queue-browser-result/v1"
    assert result["request_id"] == claim["request_id"]
    assert "claim_token" not in result
    assert "claim_token" not in str(result)

    tampered_plan = {**plan, "steps": [*plan["steps"]]}
    tampered_plan["steps"][0] = {  # type: ignore[index]
        **tampered_plan["steps"][0],  # type: ignore[index]
        "url": "https://attacker.example/",
    }
    with pytest.raises(protocol.QueueWorkerBoundaryError, match="claim"):
        protocol.queue_browser_agent_result(
            claim,
            tampered_plan,
            navigation_result,
        )

    with pytest.raises(protocol.QueueWorkerBoundaryError, match="DOM limit"):
        protocol.queue_browser_navigation_plan(claim, max_dom_bytes=65_535)


def test_queue_capability_is_exact_run_worker_and_queue_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.services import worker_request_queue as service

    queue_id, run_id, version_id = uuid4(), uuid4(), uuid4()
    worker = SimpleNamespace(
        name="scraping-worker",
        capabilities=["RUN_START", "REQUEST_QUEUE_ACCESS"],
    )
    binding = _binding_payload(queue_id)
    receipt = {
        "schema_version": "rdc.request-queue-binding-receipt/v1",
        "binding_digest": canonical_fingerprint(binding),
        "queue_id": str(queue_id),
        "agent_version_id": str(version_id),
        "direct_database_access": False,
        "direct_object_storage_access": False,
    }
    payload = {
        "work_kind": "RUN_START",
        "run_id": str(run_id),
        "agent_version_id": str(version_id),
        "manifest": _manifest(),
        "input_reference": {
            "value": {},
            "request_queue": binding,
            "queue_binding_receipt": receipt,
        },
    }
    monkeypatch.setattr(service.settings, "sandbox_canary_request_queue_enabled", True)
    monkeypatch.setattr(service.settings, "sandbox_canary_worker_name", worker.name)
    monkeypatch.setattr(
        service.settings,
        "sandbox_canary_agent_version_id",
        str(version_id),
    )
    capability = request_queue_capability(
        worker,  # type: ignore[arg-type]
        payload,
        request_queue_enabled=True,
    )
    assert capability is not None
    assert capability["queue_id"] == str(queue_id)
    assert capability["run_id"] == str(run_id)
    assert capability["direct_database_access"] is False

    tampered = {
        **payload,
        "input_reference": {
            **payload["input_reference"],  # type: ignore[dict-item]
            "request_queue": _binding_payload(uuid4()),
        },
    }
    assert (
        request_queue_capability(
            worker,  # type: ignore[arg-type]
            tampered,
            request_queue_enabled=True,
        )
        is None
    )


def test_queue_browser_capability_binds_both_policies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.services import worker_request_queue as service

    queue_id, run_id, version_id = uuid4(), uuid4(), uuid4()
    worker = SimpleNamespace(
        name="scraping-worker",
        capabilities=["RUN_START", "REQUEST_QUEUE_ACCESS"],
    )
    binding = _binding_payload(queue_id)
    browser_policy = {
        "schema_version": "rdc.browser-policy/v1",
        "max_dom_bytes": 131_072,
    }
    browser_egress_policy = {
        "schema_version": "rdc.browser-egress/v1",
        "allowed_hosts": ["example.com"],
    }
    browser_digest = canonical_fingerprint(browser_policy)
    browser_egress_digest = canonical_fingerprint(browser_egress_policy)
    receipt = {
        "schema_version": "rdc.request-queue-binding-receipt/v3",
        "binding_digest": canonical_fingerprint(binding),
        "queue_id": str(queue_id),
        "agent_version_id": str(version_id),
        "acquisition_mode": "controlled-browser",
        "browser_policy_digest": browser_digest,
        "browser_egress_policy_digest": browser_egress_digest,
        "dispatch_enabled": True,
        "agent_container_network": "none",
        "direct_database_access": False,
        "direct_object_storage_access": False,
    }
    payload = {
        "work_kind": "RUN_START",
        "run_id": str(run_id),
        "agent_version_id": str(version_id),
        "manifest": _manifest(network="web-egress", browser=True),
        "input_reference": {
            "value": {},
            "request_queue": binding,
            "queue_binding_receipt": receipt,
            "request_queue_browser_policy": browser_policy,
            "request_queue_browser_policy_digest": browser_digest,
            "request_queue_browser_egress_policy": browser_egress_policy,
            "request_queue_browser_egress_policy_digest": (
                browser_egress_digest
            ),
        },
    }
    for name in (
        "sandbox_canary_request_queue_enabled",
        "sandbox_canary_request_queue_browser_enabled",
        "sandbox_canary_browser_enabled",
        "sandbox_canary_browser_live_navigation_enabled",
        "sandbox_canary_web_egress_enabled",
    ):
        monkeypatch.setattr(service.settings, name, True)
    monkeypatch.setattr(service.settings, "sandbox_canary_worker_name", worker.name)
    monkeypatch.setattr(
        service.settings,
        "sandbox_canary_agent_version_id",
        str(version_id),
    )
    capability = request_queue_capability(
        worker,  # type: ignore[arg-type]
        payload,
        request_queue_enabled=True,
        request_queue_browser_enabled=True,
        browser_policy_digest=browser_digest,
        browser_egress_policy_digest=browser_egress_digest,
    )
    assert capability is not None
    assert capability["schema_version"] == (
        "rdc.request-queue-worker-capability/v3"
    )
    assert capability["acquisition_mode"] == "controlled-browser"
    assert capability["browser_policy_digest"] == browser_digest
    assert capability["browser_egress_policy_digest"] == browser_egress_digest

    payload["manifest"] = _manifest(
        network="web-egress",
        browser=True,
        dataset=True,
    )
    payload["input_reference"][  # type: ignore[index]
        "request_queue_dataset_receipt"
    ] = {
        "schema_version": "rdc.request-queue-dataset-receipt/v1",
        "queue_id": str(queue_id),
        "agent_version_id": str(version_id),
        "queue_binding_receipt_digest": canonical_fingerprint(receipt),
        "dataset_name": "default",
        "dispatch_enabled": True,
        "completion_order": "dataset-before-queue-handled",
        "agent_container_network": "none",
        "direct_database_access": False,
        "direct_object_storage_access": False,
    }
    monkeypatch.setattr(
        service.settings,
        "sandbox_canary_request_queue_dataset_enabled",
        True,
    )
    monkeypatch.setattr(
        service.settings,
        "sandbox_canary_dataset_writes_enabled",
        True,
    )
    composed = request_queue_capability(
        worker,  # type: ignore[arg-type]
        payload,
        request_queue_enabled=True,
        request_queue_browser_enabled=True,
        browser_policy_digest=browser_digest,
        browser_egress_policy_digest=browser_egress_digest,
        request_queue_dataset_enabled=True,
    )
    assert composed is not None
    assert composed["schema_version"] == (
        "rdc.request-queue-worker-capability/v4"
    )
    assert composed["acquisition_mode"] == "controlled-browser"
    assert composed["dataset_write_enabled"] is True

    payload["input_reference"][  # type: ignore[index]
        "request_queue_browser_policy_digest"
    ] = "0" * 64
    assert (
        request_queue_capability(
            worker,  # type: ignore[arg-type]
            payload,
            request_queue_enabled=True,
            request_queue_browser_enabled=True,
            browser_policy_digest=browser_digest,
            browser_egress_policy_digest=browser_egress_digest,
            request_queue_dataset_enabled=True,
        )
        is None
    )


def test_queue_dataset_capabilities_are_exact_and_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.services import execution_plane as execution_service
    from app.services import worker_request_queue as queue_service

    queue_id, run_id, version_id = uuid4(), uuid4(), uuid4()
    binding = _binding_payload(queue_id)
    queue_receipt = {
        "schema_version": "rdc.request-queue-binding-receipt/v1",
        "binding_digest": canonical_fingerprint(binding),
        "queue_id": str(queue_id),
        "agent_version_id": str(version_id),
        "direct_database_access": False,
        "direct_object_storage_access": False,
    }
    composition_receipt = {
        "schema_version": "rdc.request-queue-dataset-receipt/v1",
        "queue_id": str(queue_id),
        "agent_version_id": str(version_id),
        "queue_binding_receipt_digest": canonical_fingerprint(queue_receipt),
        "dataset_name": "default",
        "dispatch_enabled": True,
        "completion_order": "dataset-before-queue-handled",
        "agent_container_network": "none",
        "direct_database_access": False,
        "direct_object_storage_access": False,
    }
    payload = {
        "work_kind": "RUN_START",
        "run_id": str(run_id),
        "agent_version_id": str(version_id),
        "manifest": _manifest(dataset=True),
        "input_reference": {
            "kind": "inline",
            "value": {},
            "request_queue": binding,
            "queue_binding_receipt": queue_receipt,
            "request_queue_dataset_receipt": composition_receipt,
        },
    }
    worker = SimpleNamespace(
        name="scraping-worker",
        max_concurrency=1,
        capabilities=[
            "RUN_START",
            "REQUEST_QUEUE_ACCESS",
            "DATASET_APPEND",
        ],
    )
    for settings in (execution_service.settings, queue_service.settings):
        for name in (
            "sandbox_execution_enabled",
            "sandbox_canary_request_queue_enabled",
            "sandbox_canary_dataset_writes_enabled",
            "sandbox_canary_request_queue_dataset_enabled",
        ):
            monkeypatch.setattr(settings, name, True)
        monkeypatch.setattr(settings, "sandbox_activation_mode", "canary")
        monkeypatch.setattr(
            settings,
            "sandbox_canary_agent_version_id",
            str(version_id),
        )
        monkeypatch.setattr(
            settings,
            "sandbox_canary_worker_name",
            worker.name,
        )

    activation = execution_service._canary_activation(
        worker,  # type: ignore[arg-type]
        payload,
        {"attestation_digest": "a" * 64},
    )
    assert activation is not None
    assert activation.dataset_write_enabled is True
    assert activation.request_queue_enabled is True
    assert activation.request_queue_dataset_enabled is True

    queue_capability = request_queue_capability(
        worker,  # type: ignore[arg-type]
        payload,
        request_queue_enabled=True,
        request_queue_dataset_enabled=True,
    )
    assert queue_capability is not None
    assert queue_capability["schema_version"] == (
        "rdc.request-queue-worker-capability/v4"
    )
    assert queue_capability["completion_order"] == (
        "dataset-before-queue-handled"
    )
    dataset_capability = execution_service._dataset_append_capability(
        worker,  # type: ignore[arg-type]
        payload,
        dataset_write_enabled=True,
        request_queue_dataset_enabled=True,
    )
    assert dataset_capability is not None
    assert dataset_capability["schema_version"] == (
        "rdc.dataset-worker-capability/v2"
    )
    assert dataset_capability["queue_id"] == str(queue_id)

    sandbox = {"attestation_digest": "a" * 64}
    worker_payload = {
        **payload,
        "sandbox": sandbox,
        "activation": activation.model_dump(mode="json"),
        "request_queue_capability": queue_capability,
        "dataset_append_capability": dataset_capability,
    }
    worker_module = _worker_module()
    result = worker_module._require_canary_activation(
        worker_payload,
        worker_name=worker.name,
        egress_policy=None,
        browser_policy=None,
        browser_live_navigation_enabled=False,
        dataset_writes_enabled=True,
        key_value_store_enabled=False,
        request_queue_enabled=True,
        request_queue_http_enabled=False,
        request_queue_browser_enabled=False,
        request_queue_dataset_enabled=True,
    )
    assert result["request_queue_dataset_enabled"] is True

    tampered_worker_payload = {
        **worker_payload,
        "dataset_append_capability": {
            **dataset_capability,
            "queue_id": str(uuid4()),
        },
    }
    with pytest.raises(
        worker_module.SandboxPolicyError,
        match="Dataset capability receipt is invalid",
    ):
        worker_module._require_canary_activation(
            tampered_worker_payload,
            worker_name=worker.name,
            egress_policy=None,
            browser_policy=None,
            browser_live_navigation_enabled=False,
            dataset_writes_enabled=True,
            key_value_store_enabled=False,
            request_queue_enabled=True,
            request_queue_http_enabled=False,
            request_queue_browser_enabled=False,
            request_queue_dataset_enabled=True,
        )

    composition_receipt["completion_order"] = "queue-before-dataset"
    assert (
        request_queue_capability(
            worker,  # type: ignore[arg-type]
            payload,
            request_queue_enabled=True,
            request_queue_dataset_enabled=True,
        )
        is None
    )
    assert (
        execution_service._canary_activation(
            worker,  # type: ignore[arg-type]
            payload,
            {"attestation_digest": "a" * 64},
        )
        is None
    )


def test_queue_browser_control_plane_activation_is_exact_and_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.services import execution_plane as service
    from app.services import worker_request_queue as queue_service

    version_id, run_id, queue_id = uuid4(), uuid4(), uuid4()
    for name in (
        "sandbox_execution_enabled",
        "sandbox_canary_web_egress_enabled",
        "sandbox_canary_browser_enabled",
        "sandbox_canary_browser_live_navigation_enabled",
        "sandbox_canary_request_queue_enabled",
        "sandbox_canary_request_queue_browser_enabled",
    ):
        monkeypatch.setattr(service.settings, name, True)
    monkeypatch.setattr(service.settings, "sandbox_activation_mode", "canary")
    monkeypatch.setattr(
        service.settings,
        "sandbox_canary_agent_version_id",
        str(version_id),
    )
    monkeypatch.setattr(
        service.settings,
        "sandbox_canary_worker_name",
        "scraping-worker",
    )
    monkeypatch.setattr(
        service.settings,
        "sandbox_canary_web_egress_allowed_hosts",
        ["example.com"],
    )
    browser_policy = service._browser_policy_payload()
    browser_egress_policy = service._browser_egress_policy_payload()
    browser_digest = canonical_fingerprint(browser_policy)
    browser_egress_digest = canonical_fingerprint(browser_egress_policy)
    binding = _binding_payload(queue_id)
    receipt = {
        "schema_version": "rdc.request-queue-binding-receipt/v3",
        "binding_digest": canonical_fingerprint(binding),
        "queue_id": str(queue_id),
        "agent_version_id": str(version_id),
        "acquisition_mode": "controlled-browser",
        "browser_policy_digest": browser_digest,
        "browser_egress_policy_digest": browser_egress_digest,
        "dispatch_enabled": True,
        "agent_container_network": "none",
        "direct_database_access": False,
        "direct_object_storage_access": False,
    }
    payload = {
        "work_kind": "RUN_START",
        "run_id": str(run_id),
        "agent_version_id": str(version_id),
        "manifest": _manifest(network="web-egress", browser=True),
        "input_reference": {
            "kind": "inline",
            "value": {},
            "request_queue": binding,
            "queue_binding_receipt": receipt,
            "request_queue_browser_policy": browser_policy,
            "request_queue_browser_policy_digest": browser_digest,
            "request_queue_browser_egress_policy": browser_egress_policy,
            "request_queue_browser_egress_policy_digest": (
                browser_egress_digest
            ),
        },
    }
    worker = SimpleNamespace(
        name="scraping-worker",
        max_concurrency=1,
        capabilities=["RUN_START", "REQUEST_QUEUE_ACCESS"],
    )
    sandbox = {"attestation_digest": "a" * 64}
    activation = service._canary_activation(
        worker,  # type: ignore[arg-type]
        payload,
        sandbox,
    )
    assert activation is not None
    assert activation.capability_profile == "controlled-browser"
    assert activation.request_queue_enabled is True
    assert activation.request_queue_browser_enabled is True
    assert activation.request_queue_http_enabled is False
    assert activation.browser_policy_digest == browser_digest

    capability = request_queue_capability(
        worker,  # type: ignore[arg-type]
        payload,
        request_queue_enabled=True,
        request_queue_browser_enabled=True,
        browser_policy_digest=browser_digest,
        browser_egress_policy_digest=browser_egress_digest,
    )
    assert capability is not None
    snapshot = {
        **payload,
        "activation": activation.model_dump(mode="json"),
        "request_queue_capability": capability,
    }
    lease = SimpleNamespace(
        work_kind="RUN_START",
        payload_snapshot=snapshot,
    )
    assert queue_service._enabled(  # type: ignore[arg-type]
        lease,
        worker,  # type: ignore[arg-type]
    ) == capability

    receipt["dispatch_enabled"] = False
    assert (
        service._canary_activation(
            worker,  # type: ignore[arg-type]
            payload,
            sandbox,
        )
        is None
    )


def test_queue_browser_worker_independently_validates_v3_receipts() -> None:
    worker_module = _worker_module()
    version_id, run_id, queue_id = uuid4(), uuid4(), uuid4()
    egress_policy = worker_module.EgressPolicy.create(["example.com"])
    browser_policy = worker_module.BrowserPolicy.create(
        enabled=True,
        allowed_hosts=("example.com",),
        max_pages=1,
        max_actions=8,
        navigation_timeout_seconds=15,
        max_dom_bytes=131_072,
        max_screenshot_bytes=131_072,
    )
    browser_egress_policy = worker_module.BrowserEgressPolicy.create(
        egress_policy
    )
    binding = _binding_payload(queue_id)
    receipt = {
        "schema_version": "rdc.request-queue-binding-receipt/v3",
        "binding_digest": canonical_fingerprint(binding),
        "queue_id": str(queue_id),
        "agent_version_id": str(version_id),
        "acquisition_mode": "controlled-browser",
        "browser_policy_digest": browser_policy.digest,
        "browser_egress_policy_digest": browser_egress_policy.digest,
        "dispatch_enabled": True,
        "agent_container_network": "none",
        "direct_database_access": False,
        "direct_object_storage_access": False,
    }
    sandbox = {
        "attestation_digest": "a" * 64,
        "timeout_seconds": 120,
    }
    activation = {
        "mode": "canary",
        "agent_version_id": str(version_id),
        "worker_name": "scraping-worker",
        "attestation_digest": "a" * 64,
        "sandbox_policy_digest": canonical_fingerprint(sandbox),
        "constraints_digest": "c" * 64,
        "no_secrets": True,
        "capability_profile": "controlled-browser",
        "egress_policy_digest": egress_policy.digest,
        "browser_policy_digest": browser_policy.digest,
        "dataset_write_enabled": False,
        "key_value_store_enabled": False,
        "request_queue_enabled": True,
        "request_queue_http_enabled": False,
        "request_queue_browser_enabled": True,
        "request_queue_dataset_enabled": False,
        "max_concurrency": 1,
    }
    capability = {
        "schema_version": "rdc.request-queue-worker-capability/v3",
        "queue_id": str(queue_id),
        "run_id": str(run_id),
        "agent_version_id": str(version_id),
        "worker_name": "scraping-worker",
        "max_claims_per_run": 1,
        "claim_completion_required": True,
        "direct_database_access": False,
        "direct_object_storage_access": False,
        "enabled": True,
        "acquisition_mode": "controlled-browser",
        "browser_policy_digest": browser_policy.digest,
        "browser_egress_policy_digest": browser_egress_policy.digest,
        "agent_container_network": "none",
    }
    payload = {
        "work_kind": "RUN_START",
        "run_id": str(run_id),
        "agent_version_id": str(version_id),
        "manifest": _manifest(network="web-egress", browser=True),
        "sandbox": sandbox,
        "activation": activation,
        "input_reference": {
            "kind": "inline",
            "value": {},
            "request_queue": binding,
            "queue_binding_receipt": receipt,
            "request_queue_browser_policy": browser_policy.as_dict(),
            "request_queue_browser_policy_digest": browser_policy.digest,
            "request_queue_browser_egress_policy": (
                browser_egress_policy.as_dict()
            ),
            "request_queue_browser_egress_policy_digest": (
                browser_egress_policy.digest
            ),
        },
        "request_queue_capability": capability,
    }
    result = worker_module._require_canary_activation(
        payload,
        worker_name="scraping-worker",
        egress_policy=egress_policy,
        browser_policy=browser_policy,
        browser_live_navigation_enabled=True,
        dataset_writes_enabled=False,
        key_value_store_enabled=False,
        request_queue_enabled=True,
        request_queue_http_enabled=False,
        request_queue_browser_enabled=True,
    )
    assert result["request_queue_browser_enabled"] is True

    capability["browser_egress_policy_digest"] = "0" * 64
    with pytest.raises(
        worker_module.SandboxPolicyError,
        match="capability receipt is invalid",
    ):
        worker_module._require_canary_activation(
            payload,
            worker_name="scraping-worker",
            egress_policy=egress_policy,
            browser_policy=browser_policy,
            browser_live_navigation_enabled=True,
            dataset_writes_enabled=False,
            key_value_store_enabled=False,
            request_queue_enabled=True,
            request_queue_http_enabled=False,
            request_queue_browser_enabled=True,
        )


def test_queue_browser_live_acquisition_is_claim_derived_and_token_free(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    worker_module = _worker_module()
    egress_policy = worker_module.EgressPolicy.create(["example.com"])
    browser_policy = worker_module.BrowserPolicy.create(
        enabled=True,
        allowed_hosts=("example.com",),
        max_pages=1,
        max_actions=8,
        navigation_timeout_seconds=15,
        max_dom_bytes=131_072,
        max_screenshot_bytes=131_072,
    )
    claim = {
        "schema_version": "rdc.queue-worker-claim/v1",
        "request_id": str(uuid4()),
        "queue_id": str(uuid4()),
        "url": "https://example.com/items/1",
        "user_data": {"page": 1},
        "attempt_count": 1,
        "claim_token": str(uuid4()),
    }

    def fake_browser_runtime(**kwargs: object) -> tuple[Path, Path]:
        plan = kwargs["navigation_plan"]
        assert isinstance(plan, dict)
        steps = plan["steps"]
        assert isinstance(steps, list)
        request_digest = kwargs["request_digest"]
        output = tmp_path / "browser-output.json"
        log = tmp_path / "browser.log"
        output.write_text(
            json.dumps(
                {
                    "schema_version": "rdc.browser-navigation-result/v1",
                    "request_digest": request_digest,
                    "browser_policy_digest": browser_policy.digest,
                    "browser_egress_policy_digest": (
                        worker_module.BrowserEgressPolicy.create(
                            egress_policy
                        ).digest
                    ),
                    "browser_network": "none",
                    "gateway_transport": "unix",
                    "gateway_live_forwarding": True,
                    "final_url": claim["url"],
                    "steps": [
                        {
                            "id": "queue-goto",
                            "type": "goto",
                            "url": claim["url"],
                        },
                        {
                            "id": "queue-html",
                            "type": "extract_html",
                            "html": "<html></html>",
                            "truncated": False,
                        },
                    ],
                    "egress_budget": {
                        "requests_used": 1,
                        "bytes_received": 13,
                        "redirects_used": 0,
                        "max_requests": 8,
                        "max_total_bytes": 4_194_304,
                        "max_redirects": 3,
                    },
                }
            ),
            encoding="utf-8",
        )
        log.write_text("browser completed\n", encoding="utf-8")
        return output, log

    monkeypatch.setattr(
        worker_module,
        "run_browser_live_navigation",
        fake_browser_runtime,
    )
    result, provenance = worker_module._queue_browser_acquire(
        config=SimpleNamespace(),  # type: ignore[arg-type]
        payload={
            "run_id": str(uuid4()),
            "sandbox": {"timeout_seconds": 120},
        },
        workspace=tmp_path,
        queue_claim=claim,
        egress_policy=egress_policy,
        browser_policy=browser_policy,
    )
    assert result["schema_version"] == "rdc.queue-browser-result/v1"
    assert result["request_id"] == claim["request_id"]
    assert "claim_token" not in json.dumps(result)
    assert provenance["agent_container_network"] == "none"
    assert provenance["gateway_transport"] == "unix"


def test_queue_http_capability_binds_egress_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.services import worker_request_queue as service

    queue_id, run_id, version_id = uuid4(), uuid4(), uuid4()
    worker = SimpleNamespace(
        name="scraping-worker",
        capabilities=["RUN_START", "REQUEST_QUEUE_ACCESS"],
    )
    binding = _binding_payload(queue_id)
    egress_policy = {
        "schema_version": "rdc.egress/v1",
        "mode": "brokered",
        "allowed_hosts": ["example.com"],
    }
    egress_digest = canonical_fingerprint(egress_policy)
    receipt = {
        "schema_version": "rdc.request-queue-binding-receipt/v2",
        "binding_digest": canonical_fingerprint(binding),
        "queue_id": str(queue_id),
        "agent_version_id": str(version_id),
        "acquisition_mode": "brokered-http",
        "egress_policy_digest": egress_digest,
        "dispatch_enabled": True,
        "agent_container_network": "none",
        "direct_database_access": False,
        "direct_object_storage_access": False,
    }
    payload = {
        "work_kind": "RUN_START",
        "run_id": str(run_id),
        "agent_version_id": str(version_id),
        "manifest": _manifest(network="web-egress"),
        "input_reference": {
            "value": {},
            "request_queue": binding,
            "queue_binding_receipt": receipt,
            "request_queue_egress_policy": egress_policy,
            "request_queue_egress_policy_digest": egress_digest,
        },
    }
    monkeypatch.setattr(service.settings, "sandbox_canary_request_queue_enabled", True)
    monkeypatch.setattr(
        service.settings, "sandbox_canary_request_queue_http_enabled", True
    )
    monkeypatch.setattr(service.settings, "sandbox_canary_web_egress_enabled", True)
    monkeypatch.setattr(service.settings, "sandbox_canary_worker_name", worker.name)
    monkeypatch.setattr(
        service.settings,
        "sandbox_canary_agent_version_id",
        str(version_id),
    )
    capability = request_queue_capability(
        worker,  # type: ignore[arg-type]
        payload,
        request_queue_enabled=True,
        request_queue_http_enabled=True,
        egress_policy_digest=egress_digest,
    )
    assert capability is not None
    assert capability["schema_version"] == (
        "rdc.request-queue-worker-capability/v2"
    )
    assert capability["acquisition_mode"] == "brokered-http"
    assert capability["egress_policy_digest"] == egress_digest

    payload["input_reference"]["request_queue_egress_policy_digest"] = (  # type: ignore[index]
        "0" * 64
    )
    assert (
        request_queue_capability(
            worker,  # type: ignore[arg-type]
            payload,
            request_queue_enabled=True,
            request_queue_http_enabled=True,
            egress_policy_digest=egress_digest,
        )
        is None
    )


@pytest.mark.asyncio
async def test_create_run_derives_queue_tenancy_and_persists_receipt() -> None:
    organization_id, project_id, agent_id = uuid4(), uuid4(), uuid4()
    version_id, build_id, user_id, queue_id = (
        uuid4(),
        uuid4(),
        uuid4(),
        uuid4(),
    )
    version = SimpleNamespace(
        id=version_id,
        organization_id=organization_id,
        project_id=project_id,
        agent_id=agent_id,
        manifest=_manifest(),
    )
    build = SimpleNamespace(
        id=build_id,
        status="SUCCEEDED",
        artifact_digest="sha256:" + "a" * 64,
    )
    queue = SimpleNamespace(
        id=queue_id,
        organization_id=organization_id,
        project_id=project_id,
    )
    session = SimpleNamespace(
        scalar=AsyncMock(side_effect=[build, queue, None, None]),
        execute=AsyncMock(),
        flush=AsyncMock(),
        add=Mock(),
    )
    result = await create_run(
        session,  # type: ignore[arg-type]
        version=version,  # type: ignore[arg-type]
        user_id=user_id,
        idempotency_key="queue-run-1",
        payload=CreateRunRequest(
            build_id=build_id,
            input={"job": "parse"},
            request_queue=_binding_payload(queue_id),  # type: ignore[arg-type]
        ),
        request_id="queue-run-create",
    )
    added_runs = [
        call.args[0]
        for call in session.add.call_args_list
        if isinstance(call.args[0], Run)
    ]
    assert len(added_runs) == 1
    run = added_runs[0]
    assert run.organization_id == organization_id
    assert run.project_id == project_id
    assert run.input_reference["request_queue"] == _binding_payload(queue_id)
    receipt = run.input_reference["queue_binding_receipt"]
    assert isinstance(receipt, dict)
    assert receipt["queue_id"] == str(queue_id)
    assert result["organization_id"] == str(organization_id)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("dispatch_enabled", "expected_status"),
    [(True, "QUEUED"), (False, "DRAFT")],
)
async def test_create_run_persists_brokered_queue_http_receipt(
    monkeypatch: pytest.MonkeyPatch,
    dispatch_enabled: bool,
    expected_status: str,
) -> None:
    from app.services import runs as run_service

    organization_id, project_id, agent_id = uuid4(), uuid4(), uuid4()
    version_id, build_id, user_id, queue_id = (
        uuid4(),
        uuid4(),
        uuid4(),
        uuid4(),
    )
    version = SimpleNamespace(
        id=version_id,
        organization_id=organization_id,
        project_id=project_id,
        agent_id=agent_id,
        manifest=_manifest(network="web-egress"),
    )
    build = SimpleNamespace(
        id=build_id,
        status="SUCCEEDED",
        artifact_digest="sha256:" + "c" * 64,
    )
    queue = SimpleNamespace(
        id=queue_id,
        organization_id=organization_id,
        project_id=project_id,
    )
    egress_policy = {
        "schema_version": "rdc.egress/v1",
        "mode": "brokered",
        "allowed_hosts": ["example.com"],
    }
    monkeypatch.setattr(
        run_service,
        "_request_queue_http_canary_enabled",
        lambda _version: dispatch_enabled,
    )
    monkeypatch.setattr(
        run_service,
        "_web_egress_policy_payload",
        lambda: egress_policy,
    )
    session = SimpleNamespace(
        scalar=AsyncMock(side_effect=[build, queue, None, None]),
        execute=AsyncMock(),
        flush=AsyncMock(),
        add=Mock(),
    )
    result = await create_run(
        session,  # type: ignore[arg-type]
        version=version,  # type: ignore[arg-type]
        user_id=user_id,
        idempotency_key="queue-http-run-1",
        payload=CreateRunRequest(
            build_id=build_id,
            input={"job": "fetch-and-parse"},
            request_queue=_binding_payload(queue_id),  # type: ignore[arg-type]
        ),
        request_id="queue-http-run-create",
    )
    added_runs = [
        call.args[0]
        for call in session.add.call_args_list
        if isinstance(call.args[0], Run)
    ]
    assert len(added_runs) == 1
    run = added_runs[0]
    assert run.status == expected_status
    assert result["status"] == expected_status
    receipt = run.input_reference["queue_binding_receipt"]
    assert isinstance(receipt, dict)
    assert receipt["schema_version"] == (
        "rdc.request-queue-binding-receipt/v2"
    )
    assert receipt["acquisition_mode"] == "brokered-http"
    assert receipt["dispatch_enabled"] is dispatch_enabled
    assert receipt["agent_container_network"] == "none"
    assert run.input_reference["request_queue_egress_policy"] == egress_policy
    outboxes = [
        call.args[0]
        for call in session.add.call_args_list
        if isinstance(call.args[0], RunCommandOutbox)
    ]
    assert len(outboxes) == (1 if dispatch_enabled else 0)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("dispatch_enabled", "expected_status"),
    [(False, "DRAFT"), (True, "QUEUED")],
)
async def test_create_run_persists_gated_queue_browser_receipt(
    monkeypatch: pytest.MonkeyPatch,
    dispatch_enabled: bool,
    expected_status: str,
) -> None:
    from app.services import runs as run_service

    organization_id, project_id, agent_id = uuid4(), uuid4(), uuid4()
    version_id, build_id, user_id, queue_id = (
        uuid4(),
        uuid4(),
        uuid4(),
        uuid4(),
    )
    version = SimpleNamespace(
        id=version_id,
        organization_id=organization_id,
        project_id=project_id,
        agent_id=agent_id,
        manifest=_manifest(network="web-egress", browser=True),
    )
    build = SimpleNamespace(
        id=build_id,
        status="SUCCEEDED",
        artifact_digest="sha256:" + "d" * 64,
    )
    queue = SimpleNamespace(
        id=queue_id,
        organization_id=organization_id,
        project_id=project_id,
    )
    browser_policy = {
        "schema_version": "rdc.browser-policy/v1",
        "enabled": dispatch_enabled,
        "allowed_hosts": ["example.com"],
    }
    browser_egress_policy = {
        "schema_version": "rdc.browser-egress-policy/v1",
        "mode": "gateway-live-canary",
        "allowed_hosts": ["example.com"],
    }
    monkeypatch.setattr(
        run_service, "_browser_policy_payload", lambda: browser_policy
    )
    monkeypatch.setattr(
        run_service,
        "_browser_egress_policy_payload",
        lambda: browser_egress_policy,
    )
    monkeypatch.setattr(
        run_service,
        "_request_queue_browser_canary_enabled",
        lambda _version: dispatch_enabled,
    )
    session = SimpleNamespace(
        scalar=AsyncMock(side_effect=[build, queue, None, None]),
        execute=AsyncMock(),
        flush=AsyncMock(),
        add=Mock(),
    )
    result = await create_run(
        session,  # type: ignore[arg-type]
        version=version,  # type: ignore[arg-type]
        user_id=user_id,
        idempotency_key="queue-browser-intent-1",
        payload=CreateRunRequest(
            build_id=build_id,
            request_queue=_binding_payload(queue_id),  # type: ignore[arg-type]
        ),
        request_id="queue-browser-intent-create",
    )
    runs = [
        call.args[0]
        for call in session.add.call_args_list
        if isinstance(call.args[0], Run)
    ]
    assert len(runs) == 1
    run = runs[0]
    assert run.status == expected_status
    assert result["status"] == expected_status
    receipt = run.input_reference["queue_binding_receipt"]
    assert isinstance(receipt, dict)
    assert receipt["schema_version"] == (
        "rdc.request-queue-binding-receipt/v3"
    )
    assert receipt["acquisition_mode"] == "controlled-browser"
    assert receipt["dispatch_enabled"] is dispatch_enabled
    assert receipt["agent_container_network"] == "none"
    outboxes = [
        call.args[0]
        for call in session.add.call_args_list
        if isinstance(call.args[0], RunCommandOutbox)
    ]
    assert len(outboxes) == (1 if dispatch_enabled else 0)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("dispatch_enabled", "expected_status"),
    [(False, "DRAFT"), (True, "QUEUED")],
)
async def test_create_run_persists_gated_queue_dataset_composition(
    monkeypatch: pytest.MonkeyPatch,
    dispatch_enabled: bool,
    expected_status: str,
) -> None:
    from app.services import runs as run_service

    organization_id, project_id, agent_id = uuid4(), uuid4(), uuid4()
    version_id, build_id, user_id, queue_id = (
        uuid4(),
        uuid4(),
        uuid4(),
        uuid4(),
    )
    version = SimpleNamespace(
        id=version_id,
        organization_id=organization_id,
        project_id=project_id,
        agent_id=agent_id,
        manifest=_manifest(dataset=True),
    )
    build = SimpleNamespace(
        id=build_id,
        status="SUCCEEDED",
        artifact_digest="sha256:" + "d" * 64,
    )
    queue = SimpleNamespace(
        id=queue_id,
        organization_id=organization_id,
        project_id=project_id,
    )
    monkeypatch.setattr(
        run_service,
        "_request_queue_dataset_canary_enabled",
        lambda _version: dispatch_enabled,
    )
    session = SimpleNamespace(
        scalar=AsyncMock(side_effect=[build, queue, None, None]),
        execute=AsyncMock(),
        flush=AsyncMock(),
        add=Mock(),
    )
    result = await create_run(
        session,  # type: ignore[arg-type]
        version=version,  # type: ignore[arg-type]
        user_id=user_id,
        idempotency_key="queue-dataset-intent-1",
        payload=CreateRunRequest(
            build_id=build_id,
            request_queue=_binding_payload(queue_id),  # type: ignore[arg-type]
        ),
        request_id="queue-dataset-intent-create",
    )
    runs = [
        call.args[0]
        for call in session.add.call_args_list
        if isinstance(call.args[0], Run)
    ]
    assert len(runs) == 1
    run = runs[0]
    assert run.status == expected_status
    assert result["status"] == expected_status
    receipt = run.input_reference["request_queue_dataset_receipt"]
    assert isinstance(receipt, dict)
    assert receipt["schema_version"] == (
        "rdc.request-queue-dataset-receipt/v1"
    )
    assert receipt["dispatch_enabled"] is dispatch_enabled
    assert receipt["completion_order"] == (
        "dataset-before-queue-handled"
    )
    outboxes = [
        call.args[0]
        for call in session.add.call_args_list
        if isinstance(call.args[0], RunCommandOutbox)
    ]
    assert len(outboxes) == (1 if dispatch_enabled else 0)


@pytest.mark.asyncio
async def test_create_run_hides_cross_tenant_queue() -> None:
    version = SimpleNamespace(
        id=uuid4(),
        organization_id=uuid4(),
        project_id=uuid4(),
        agent_id=uuid4(),
        manifest=_manifest(),
    )
    build_id = uuid4()
    build = SimpleNamespace(
        id=build_id,
        status="SUCCEEDED",
        artifact_digest="sha256:" + "b" * 64,
    )
    session = SimpleNamespace(
        scalar=AsyncMock(side_effect=[build, None]),
        execute=AsyncMock(),
        flush=AsyncMock(),
        add=Mock(),
    )
    with pytest.raises(ApiError) as exc_info:
        await create_run(
            session,  # type: ignore[arg-type]
            version=version,  # type: ignore[arg-type]
            user_id=uuid4(),
            idempotency_key="cross-tenant-queue",
            payload=CreateRunRequest(
                build_id=build_id,
                request_queue=_binding_payload(uuid4()),  # type: ignore[arg-type]
            ),
            request_id="cross-tenant-queue",
        )
    assert exc_info.value.status_code == 404
    assert session.add.call_count == 0
