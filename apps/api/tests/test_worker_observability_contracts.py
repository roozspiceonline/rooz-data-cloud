from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path
from types import ModuleType
from uuid import uuid4

import pytest

ROOT = Path(__file__).resolve().parents[3]
CLIENT_PATHS = (
    ROOT / "workers/sandbox-runtime/rdc_worker_client.py",
    ROOT / "workers/execution-plane/rdc_worker_client.py",
)
OBSERVABILITY_PATH = ROOT / "workers/sandbox-runtime/worker_observability.py"


def _load(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def test_worker_clients_derive_identical_lease_correlation_ids() -> None:
    lease_id = uuid4()
    expected = f"lease_{lease_id.hex}"
    for index, path in enumerate(CLIENT_PATHS):
        module = _load(path, f"worker_client_{index}")
        assert (
            module.request_correlation_id(
                f"/internal/v1/leases/{lease_id}/complete"
            )
            == expected
        )
        assert module.request_correlation_id(f"/internal/v1/leases/{lease_id}") == expected


def test_non_lease_and_malformed_paths_receive_random_worker_ids() -> None:
    module = _load(CLIENT_PATHS[0], "sandbox_worker_client_random")
    first = module.request_correlation_id("/internal/v1/leases/claim")
    second = module.request_correlation_id("/internal/v1/workers/me/heartbeat")
    malformed = module.request_correlation_id("/internal/v1/leases/not-a-uuid/renew")
    pattern = re.compile(r"^worker_[0-9a-f]{32}$")
    assert pattern.fullmatch(first)
    assert pattern.fullmatch(second)
    assert pattern.fullmatch(malformed)
    assert len({first, second, malformed}) == 3


def test_worker_clients_propagate_lease_correlation_on_requests(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lease_id = uuid4()
    expected = f"lease_{lease_id.hex}"

    def capture_urlopen(captured: list[object]):
        def fake_urlopen(request: object, *, timeout: int) -> EmptyResponse:
            assert timeout == 30
            captured.append(request)
            return EmptyResponse()

        return fake_urlopen

    class EmptyResponse:
        status = 204

        def __enter__(self) -> EmptyResponse:
            return self

        def __exit__(self, *args: object) -> None:
            return None

    for index, path in enumerate(CLIENT_PATHS):
        module = _load(path, f"worker_client_request_{index}")
        captured: list[object] = []
        monkeypatch.setattr(module, "urlopen", capture_urlopen(captured))
        client = module.RdcWorkerClient(
            base_url="https://control.invalid",
            worker_token="redacted",
        )
        assert client._request("POST", f"/internal/v1/leases/{lease_id}/renew") is None
        assert len(captured) == 1
        assert captured[0].get_header("X-request-id") == expected


def test_clients_send_correlation_without_exposing_lease_token_in_request_id() -> None:
    for path in CLIENT_PATHS:
        source = path.read_text(encoding="utf-8")
        assert '"X-Request-ID": request_correlation_id(path)' in source
        function = source[
            source.index("def request_correlation_id") : source.index(
                "class RdcWorkerClient"
            )
        ]
        assert "lease_token" not in function
        assert "worker_token" not in function


def test_worker_event_is_bounded_json_without_agent_or_token_fields(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("RDC_ENV", "test")
    module = _load(OBSERVABILITY_PATH, "sandbox_worker_observability")
    lease_id = uuid4()
    run_id = uuid4()
    worker_id = uuid4()
    module.log_worker_event(
        "worker.lease.completed",
        request_id=f"lease_{lease_id.hex}",
        worker_id=str(worker_id),
        lease_id=str(lease_id),
        run_id=str(run_id),
        work_kind="RUN_START",
        outcome="succeeded",
    )
    captured = capsys.readouterr()
    payload = json.loads(captured.err)
    assert payload["schema_version"] == "rdc.log/v1"
    assert payload["lease_id"] == str(lease_id)
    assert payload["run_id"] == str(run_id)
    assert payload["worker_id"] == str(worker_id)
    assert payload["outcome"] == "succeeded"
    assert payload["environment"] == "test"
    assert not {
        "authorization",
        "lease_token",
        "payload",
        "secret",
        "stderr",
        "stdout",
        "url",
    }.intersection(payload)


def test_worker_event_rejects_invalid_correlation_and_identifiers() -> None:
    module = _load(OBSERVABILITY_PATH, "sandbox_worker_observability_invalid")
    with pytest.raises(ValueError):
        module.log_worker_event(
            "worker.lease.completed",
            request_id="lease-token-secret",
            worker_id=str(uuid4()),
        )


def test_worker_error_event_is_bounded_and_rejects_invalid_environment(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load(OBSERVABILITY_PATH, "sandbox_worker_observability_error")
    worker_id = uuid4()
    monkeypatch.setenv("RDC_ENV", "production")
    module.log_worker_event(
        "worker.failed",
        request_id=f"worker_{uuid4().hex}",
        worker_id=str(worker_id),
        error_type="SandboxPolicyError",
    )
    payload = json.loads(capsys.readouterr().err)
    assert payload["severity"] == "error"
    assert payload["error_type"] == "SandboxPolicyError"
    assert "error" not in payload

    monkeypatch.setenv("RDC_ENV", "production\nforged")
    with pytest.raises(ValueError):
        module.log_worker_event(
            "worker.failed",
            request_id=f"worker_{uuid4().hex}",
            worker_id=str(worker_id),
            error_type="SandboxPolicyError",
        )


def test_credential_envelope_is_resolved_only_in_the_run_path() -> None:
    source = (ROOT / "workers/sandbox-runtime/worker.py").read_text(encoding="utf-8")
    build = source[source.index("def _build(") : source.index("def _run(")]
    run = source[source.index("def _run(") : source.index("def main(")]
    marker = "client.request_egress_credential_envelope("
    assert marker not in build
    assert marker in run
    assert "authorization=egress_authorization" in run


def test_worker_failure_event_reuses_active_lease_correlation() -> None:
    source = (ROOT / "workers/sandbox-runtime/worker.py").read_text(encoding="utf-8")
    main = source[source.index("def main(") :]
    assert "active_request_id = correlation_id" in main
    assert '"worker.failed"' in main
    assert "request_id=active_request_id" in main
    assert "lease_id=active_lease_id" in main
    assert "run_id=active_run_id" in main
    assert "work_kind=active_work_kind" in main
