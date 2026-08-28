from __future__ import annotations

import importlib.util
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from app.core.errors import ApiError
from app.core.security import canonical_fingerprint
from app.egress_policy_protocol import validate_egress_policy
from app.execution_schemas import EgressCredentialEnvelopeRequest
from app.models import Run, SecretInjectionGrant
from app.run_schemas import CreateRunRequest
from app.services import execution_plane, runs
from app.services.worker_request_queue import request_queue_capability

WORKER_ROOT = Path(__file__).parents[3] / "workers" / "sandbox-runtime"


def _runtime_policy(*, max_requests: int = 4) -> dict[str, object]:
    return {
        "schema_version": "rdc.egress/v1",
        "mode": "brokered",
        "allowed_schemes": ["https"],
        "allowed_methods": ["GET"],
        "allowed_hosts": ["api.example.com"],
        "deny_ip_literals": True,
        "require_global_dns": True,
        "revalidate_redirects": True,
        "container_network": "none",
        "max_requests": max_requests,
        "max_response_bytes": 65_536,
        "max_total_bytes": 131_072,
        "max_redirects": 0,
        "connect_timeout_seconds": 2,
        "request_timeout_seconds": 5,
    }


def _receipt(policy: dict[str, object]) -> dict[str, object]:
    foundation = {
        "allowed_hosts": policy["allowed_hosts"],
        "allowed_methods": policy["allowed_methods"],
        "connect_timeout_seconds": policy["connect_timeout_seconds"],
        "max_redirects": policy["max_redirects"],
        "max_requests": policy["max_requests"],
        "max_response_bytes": policy["max_response_bytes"],
        "max_total_bytes": policy["max_total_bytes"],
        "request_timeout_seconds": policy["request_timeout_seconds"],
        "schema_version": "rdc.egress-policy/v1",
    }
    value: dict[str, object] = {
        "schema_version": "rdc.run-egress-policy-receipt/v1",
        "policy_id": str(uuid4()),
        "revision_id": str(uuid4()),
        "revision_number": 2,
        "policy_digest": canonical_fingerprint(foundation),
        "runtime_policy_digest": canonical_fingerprint(policy),
        "credential_configured": False,
    }
    return {**value, "binding_digest": canonical_fingerprint(value)}


def _ceiling() -> dict[str, object]:
    value = _runtime_policy(max_requests=8)
    value["allowed_methods"] = ["GET", "HEAD"]
    value["max_response_bytes"] = 1_048_576
    value["max_total_bytes"] = 4_194_304
    value["max_redirects"] = 3
    value["connect_timeout_seconds"] = 5
    value["request_timeout_seconds"] = 15
    return value


def _worker_module():  # type: ignore[no-untyped-def]
    worker_path = str(WORKER_ROOT)
    if worker_path not in sys.path:
        sys.path.insert(0, worker_path)
    spec = importlib.util.spec_from_file_location(
        "rdc_runtime_binding_worker",
        WORKER_ROOT / "worker.py",
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_run_schema_accepts_only_policy_reference_on_external_intent() -> None:
    policy_id = uuid4()
    with pytest.raises(ValidationError, match="exactly one external"):
        CreateRunRequest(
            build_id=uuid4(),
            egress_policy={"policy_id": policy_id},  # type: ignore[arg-type]
        )
    with pytest.raises(ValidationError, match="Extra inputs"):
        CreateRunRequest(
            build_id=uuid4(),
            web_fetch={
                "requests": [
                    {"id": "one", "method": "GET", "url": "https://api.example.com/"}
                ]
            },
            egress_policy={
                "policy_id": policy_id,
                "revision_id": uuid4(),
                "policy_digest": "0" * 64,
            },  # type: ignore[arg-type]
        )


def test_control_plane_reconstructs_binding_and_rejects_tamper(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = _runtime_policy()
    receipt = _receipt(policy)
    monkeypatch.setattr(execution_plane, "_egress_policy_payload", _ceiling)
    assert execution_plane._bound_egress_policy(
        {
            "project_egress_policy": policy,
            "project_egress_policy_receipt": receipt,
        }
    ) == (policy, receipt["binding_digest"])

    tampered = {**policy, "max_requests": 9}
    with pytest.raises(ValueError, match="ceiling|digest"):
        execution_plane._bound_egress_policy(
            {
                "project_egress_policy": tampered,
                "project_egress_policy_receipt": receipt,
            }
        )


def test_bound_policy_rejects_unapproved_run_method_and_host() -> None:
    policy = _runtime_policy()
    denied_method = CreateRunRequest.model_validate(
        {
            "build_id": str(uuid4()),
            "web_fetch": {
                "requests": [
                    {
                        "id": "head",
                        "method": "HEAD",
                        "url": "https://api.example.com/",
                    }
                ]
            },
        }
    )
    with pytest.raises(ApiError) as method_error:
        runs._validate_bound_egress_intent(denied_method, policy)
    assert method_error.value.code == "EGRESS_POLICY_INTENT_DENIED"

    denied_host = CreateRunRequest.model_validate(
        {
            "build_id": str(uuid4()),
            "browser": {
                "start_url": "https://other.example.com/",
                "actions": [
                    {"id": "snapshot", "type": "snapshot", "include_html": False}
                ],
            },
        }
    )
    with pytest.raises(ApiError) as host_error:
        runs._validate_bound_egress_intent(denied_host, policy)
    assert host_error.value.code == "EGRESS_POLICY_INTENT_DENIED"


def test_worker_independently_reconstructs_and_enforces_ceiling() -> None:
    worker = _worker_module()
    policy = _runtime_policy()
    receipt = _receipt(policy)
    ceiling = worker.EgressPolicy.create(
        ["api.example.com"],
        max_requests=8,
        max_response_bytes=1_048_576,
        max_total_bytes=4_194_304,
        max_redirects=3,
        connect_timeout_seconds=5,
        request_timeout_seconds=15,
    )
    effective = worker._effective_worker_egress_policy(
        {
            "input_reference": {
                "project_egress_policy": policy,
                "project_egress_policy_receipt": receipt,
            }
        },
        ceiling,
    )
    assert effective.allowed_methods == ("GET",)
    assert effective.digest == receipt["runtime_policy_digest"]

    widened = {**policy, "allowed_hosts": ["other.example.com"]}
    widened_receipt = _receipt(widened)
    with pytest.raises(worker.SandboxPolicyError, match="worker ceiling"):
        worker._effective_worker_egress_policy(
            {
                "input_reference": {
                    "project_egress_policy": widened,
                    "project_egress_policy_receipt": widened_receipt,
                }
            },
            ceiling,
        )


def test_broker_enforces_revision_method_subset() -> None:
    worker = _worker_module()
    policy = worker.EgressPolicy.create(
        ["api.example.com"],
        allowed_methods=["GET"],
    )
    from egress_broker import broker_validated_resource_once, broker_web_requests
    from egress_policy import EgressPolicyError, ValidatedTarget

    with pytest.raises(EgressPolicyError, match="not allowed"):
        broker_validated_resource_once(
            target=ValidatedTarget(
                url="https://api.example.com/",
                hostname="api.example.com",
                addresses=("93.184.216.34",),
            ),
            method="HEAD",
            policy=policy,
        )
    with pytest.raises(EgressPolicyError, match="not allowed"):
        broker_web_requests(
            {
                "_rdc_web_requests": [
                    {
                        "id": "head-denied",
                        "method": "HEAD",
                        "url": "https://api.example.com/",
                    }
                ]
            },
            policy=policy,
        )

    class Response:
        status = 200

        @staticmethod
        def getheaders() -> list[tuple[str, str]]:
            return [("Content-Type", "application/json")]

        @staticmethod
        def getheader(name: str) -> str | None:
            return None

        @staticmethod
        def read(_limit: int) -> bytes:
            return b"{}"

    class Connection:
        headers: dict[str, str] = {}

        def request(
            self, _method: str, _path: str, *, headers: dict[str, str]
        ) -> None:
            self.headers = headers

        @staticmethod
        def getresponse() -> Response:
            return Response()

        @staticmethod
        def close() -> None:
            return None

    connection = Connection()
    broker_validated_resource_once(
        target=ValidatedTarget(
            url="https://api.example.com/",
            hostname="api.example.com",
            addresses=("93.184.216.34",),
        ),
        method="GET",
        policy=policy,
        authorization="Bearer private-value",
        connection_factory=lambda _target, _policy: connection,  # type: ignore[arg-type]
    )
    assert connection.headers["Authorization"] == "Bearer private-value"


def test_queue_capability_binds_same_project_revision_receipt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.services import worker_request_queue as service

    queue_id, run_id, version_id = uuid4(), uuid4(), uuid4()
    worker = SimpleNamespace(
        name="binding-worker",
        capabilities=["RUN_START", "REQUEST_QUEUE_ACCESS"],
    )
    binding = {"schema_version": "rdc.run-queue/v1", "queue_id": str(queue_id)}
    policy = _runtime_policy()
    policy_digest = canonical_fingerprint(policy)
    project_receipt = _receipt(policy)
    queue_receipt = {
        "schema_version": "rdc.request-queue-binding-receipt/v2",
        "binding_digest": canonical_fingerprint(binding),
        "queue_id": str(queue_id),
        "agent_version_id": str(version_id),
        "acquisition_mode": "brokered-http",
        "egress_policy_digest": policy_digest,
        "dispatch_enabled": True,
        "agent_container_network": "none",
        "direct_database_access": False,
        "direct_object_storage_access": False,
    }
    payload = {
        "work_kind": "RUN_START",
        "run_id": str(run_id),
        "agent_version_id": str(version_id),
        "manifest": {
            "capabilities": {
                "network": "web-egress",
                "browser": False,
                "dataset": False,
                "keyValueStore": False,
                "requestQueue": True,
            }
        },
        "input_reference": {
            "value": {},
            "request_queue": binding,
            "queue_binding_receipt": queue_receipt,
            "request_queue_egress_policy": policy,
            "request_queue_egress_policy_digest": policy_digest,
            "project_egress_policy": policy,
            "project_egress_policy_receipt": project_receipt,
        },
    }
    monkeypatch.setattr(service.settings, "sandbox_canary_request_queue_enabled", True)
    monkeypatch.setattr(
        service.settings, "sandbox_canary_request_queue_http_enabled", True
    )
    monkeypatch.setattr(service.settings, "sandbox_canary_web_egress_enabled", True)
    monkeypatch.setattr(service.settings, "sandbox_canary_worker_name", worker.name)
    monkeypatch.setattr(
        service.settings, "sandbox_canary_agent_version_id", str(version_id)
    )
    binding_digest = str(project_receipt["binding_digest"])
    capability = request_queue_capability(
        worker,  # type: ignore[arg-type]
        payload,
        request_queue_enabled=True,
        request_queue_http_enabled=True,
        egress_policy_digest=policy_digest,
        project_egress_policy_binding_digest=binding_digest,
    )
    assert capability is not None
    assert capability["schema_version"] == "rdc.request-queue-worker-capability/v6"
    assert capability["project_egress_policy_binding_digest"] == binding_digest

    assert (
        request_queue_capability(
            worker,  # type: ignore[arg-type]
            payload,
            request_queue_enabled=True,
            request_queue_http_enabled=True,
            egress_policy_digest=policy_digest,
            project_egress_policy_binding_digest="0" * 64,
        )
        is None
    )


@pytest.mark.asyncio
async def test_create_run_persists_server_resolved_policy_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    organization_id, project_id, agent_id = uuid4(), uuid4(), uuid4()
    version_id, build_id, queue_id, user_id, policy_id = (
        uuid4(),
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
        manifest={
            "capabilities": {
                "network": "web-egress",
                "browser": False,
                "dataset": False,
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
        },
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
    policy = _runtime_policy()
    receipt = _receipt(policy)
    resolver = AsyncMock(return_value=(policy, receipt))
    monkeypatch.setattr(runs, "_resolve_run_egress_policy", resolver)
    monkeypatch.setattr(runs, "_request_queue_http_canary_enabled", lambda _v: False)
    session = SimpleNamespace(
        scalar=AsyncMock(side_effect=[build, queue, None, None]),
        execute=AsyncMock(),
        flush=AsyncMock(),
        add=Mock(),
    )
    await runs.create_run(
        session,  # type: ignore[arg-type]
        version=version,  # type: ignore[arg-type]
        user_id=user_id,
        idempotency_key="bound-run-1",
        payload=CreateRunRequest.model_validate(
            {
                "build_id": str(build_id),
                "request_queue": {"queue_id": str(queue_id)},
                "egress_policy": {"policy_id": str(policy_id)},
            }
        ),
        request_id="bound-run-create",
    )
    resolver.assert_awaited_once_with(
        session,
        policy_id=policy_id,
        organization_id=organization_id,
        project_id=project_id,
    )
    record = next(
        call.args[0]
        for call in session.add.call_args_list
        if isinstance(call.args[0], Run)
    )
    assert record.input_reference["project_egress_policy"] == policy
    assert record.input_reference["project_egress_policy_receipt"] == receipt
    assert record.input_reference["request_queue_egress_policy"] == policy
    assert record.status == "DRAFT"


@pytest.mark.asyncio
async def test_active_revision_resolution_is_tenant_scoped_and_canonical(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    organization_id, project_id, policy_id, revision_id = (
        uuid4(),
        uuid4(),
        uuid4(),
        uuid4(),
    )
    validated = validate_egress_policy(
        allowed_hosts=["api.example.com"],
        allowed_methods=["GET"],
        max_requests=4,
        max_response_bytes=65_536,
        max_total_bytes=131_072,
        max_redirects=0,
        connect_timeout_seconds=2,
        request_timeout_seconds=5,
    )
    policy = SimpleNamespace(id=policy_id, active_revision_id=revision_id)
    revision = SimpleNamespace(
        id=revision_id,
        policy_id=policy_id,
        organization_id=organization_id,
        project_id=project_id,
        revision_number=3,
        credential_secret_id=None,
        policy_digest=validated.policy_digest,
        **{
            key: getattr(validated, key)
            for key in (
                "allowed_hosts",
                "allowed_methods",
                "max_requests",
                "max_response_bytes",
                "max_total_bytes",
                "max_redirects",
                "connect_timeout_seconds",
                "request_timeout_seconds",
            )
        },
    )
    session = SimpleNamespace(scalar=AsyncMock(side_effect=[policy, revision]))
    monkeypatch.setattr(runs, "_revision_within_canary_ceiling", lambda _policy: True)
    runtime, receipt = await runs._resolve_run_egress_policy(
        session,  # type: ignore[arg-type]
        policy_id=policy_id,
        organization_id=organization_id,
        project_id=project_id,
    )
    first_statement = str(session.scalar.await_args_list[0].args[0])
    assert "organization_id" in first_statement
    assert "project_id" in first_statement
    assert "status" in first_statement
    assert receipt["revision_id"] == str(revision_id)
    assert receipt["runtime_policy_digest"] == canonical_fingerprint(runtime)

    credential_id = uuid4()
    revision.credential_secret_id = credential_id
    credential_session = SimpleNamespace(
        scalar=AsyncMock(side_effect=[policy, revision])
    )
    _, credential_receipt = await runs._resolve_run_egress_policy(
        credential_session,  # type: ignore[arg-type]
        policy_id=policy_id,
        organization_id=organization_id,
        project_id=project_id,
    )
    assert credential_receipt["credential_configured"] is True
    assert str(credential_id) not in str(credential_receipt)

    missing = SimpleNamespace(scalar=AsyncMock(return_value=None))
    with pytest.raises(ApiError) as error:
        await runs._resolve_run_egress_policy(
            missing,  # type: ignore[arg-type]
            policy_id=policy_id,
            organization_id=uuid4(),
            project_id=uuid4(),
        )
    assert error.value.status_code == 404
    assert error.value.code == "RESOURCE_NOT_FOUND"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("policy_status", "selected_revision", "expected"),
    [
        ("ACTIVE", True, True),
        ("DISABLED", True, False),
        ("ACTIVE", False, False),
    ],
)
async def test_execution_admission_converges_disabled_or_rotated_binding(
    monkeypatch: pytest.MonkeyPatch,
    policy_status: str,
    selected_revision: bool,
    expected: bool,
) -> None:
    policy = _runtime_policy()
    receipt = _receipt(policy)
    organization_id, project_id, run_id = uuid4(), uuid4(), uuid4()
    policy_id = UUID(str(receipt["policy_id"]))
    revision_id = UUID(str(receipt["revision_id"]))
    run = SimpleNamespace(
        id=run_id,
        organization_id=organization_id,
        project_id=project_id,
        status="QUEUED",
        input_reference={
            "project_egress_policy": policy,
            "project_egress_policy_receipt": receipt,
        },
        failure_code=None,
        failure_summary=None,
        finished_at=None,
        updated_at=None,
        version=1,
    )
    policy_record = SimpleNamespace(
        id=policy_id,
        status=policy_status,
        active_revision_id=(
            revision_id if selected_revision else uuid4()
        ),
    )
    revision = SimpleNamespace(
        id=revision_id,
        revision_number=receipt["revision_number"],
        policy_digest=receipt["policy_digest"],
        credential_secret_id=None,
    )
    source = SimpleNamespace(
        run_id=run_id,
        status="PENDING",
        attempts=0,
        claimed_at=None,
        last_error_code=None,
        updated_at=None,
    )
    scalar_results: list[object] = [run, policy_record, revision]
    if not expected:
        scalar_results.extend([None, None])
    session = SimpleNamespace(
        scalar=AsyncMock(side_effect=scalar_results),
        execute=AsyncMock(),
        flush=AsyncMock(),
        add=Mock(),
    )
    monkeypatch.setattr(execution_plane, "_egress_policy_payload", _ceiling)
    result = await execution_plane._bound_run_egress_policy_is_current(
        session,  # type: ignore[arg-type]
        source=source,  # type: ignore[arg-type]
        now=execution_plane.datetime.now(execution_plane.UTC),
        request_id="binding-admission",
    )
    assert result is expected
    assert "FOR UPDATE" in str(session.scalar.await_args_list[0].args[0])
    assert "FOR UPDATE" in str(session.scalar.await_args_list[1].args[0])
    if expected:
        assert source.status == "PENDING"
        assert run.status == "QUEUED"
    else:
        assert source.status == "FAILED"
        assert source.last_error_code == "EGRESS_POLICY_BINDING_REVOKED"
        assert run.status == "FAILED"
        assert run.failure_code == "EGRESS_POLICY_BINDING_REVOKED"
        added_types = {type(call.args[0]).__name__ for call in session.add.call_args_list}
        assert {"RunEvent", "AuditEvent"} <= added_types


@pytest.mark.asyncio
async def test_execution_admission_rejects_incomplete_bound_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id = uuid4()
    run = SimpleNamespace(
        id=run_id,
        organization_id=uuid4(),
        project_id=uuid4(),
        status="QUEUED",
        input_reference={"project_egress_policy": _runtime_policy()},
        failure_code=None,
        failure_summary=None,
        finished_at=None,
        updated_at=None,
        version=1,
    )
    source = SimpleNamespace(
        run_id=run_id,
        status="PENDING",
        attempts=0,
        claimed_at=None,
        last_error_code=None,
        updated_at=None,
    )
    session = SimpleNamespace(
        scalar=AsyncMock(side_effect=[run, None, None, None, None]),
        execute=AsyncMock(),
        flush=AsyncMock(),
        add=Mock(),
    )
    monkeypatch.setattr(execution_plane, "_egress_policy_payload", _ceiling)
    assert not await execution_plane._bound_run_egress_policy_is_current(
        session,  # type: ignore[arg-type]
        source=source,  # type: ignore[arg-type]
        now=execution_plane.datetime.now(execution_plane.UTC),
        request_id="binding-integrity",
    )
    assert run.failure_code == "EGRESS_POLICY_BINDING_REVOKED"


@pytest.mark.asyncio
async def test_egress_credential_envelope_is_lease_and_binding_scoped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime_policy = _runtime_policy()
    receipt = _receipt(runtime_policy)
    receipt["credential_configured"] = True
    receipt["binding_digest"] = canonical_fingerprint(
        {key: value for key, value in receipt.items() if key != "binding_digest"}
    )
    organization_id, project_id, run_id, lease_id, worker_id, secret_id = (
        uuid4() for _ in range(6)
    )
    run = SimpleNamespace(
        id=run_id,
        input_reference={
            "project_egress_policy": runtime_policy,
            "project_egress_policy_receipt": receipt,
        },
    )
    revision_id = UUID(str(receipt["revision_id"]))
    policy_record = SimpleNamespace(
        status="ACTIVE",
        active_revision_id=revision_id,
    )
    revision = SimpleNamespace(
        id=revision_id,
        revision_number=receipt["revision_number"],
        policy_digest=receipt["policy_digest"],
        credential_secret_id=secret_id,
    )
    secret = SimpleNamespace(
        id=secret_id,
        organization_id=organization_id,
        project_id=project_id,
        name="PROXY_AUTH",
        environment="production",
        version=4,
        encrypted_value=b"ciphertext",
        value_nonce=b"nonce",
        wrapped_data_key=b"key",
        key_nonce=b"key-nonce",
        master_key_version=execution_plane.settings.project_secret_master_key_version,
        last_used_at=None,
    )
    lease = SimpleNamespace(
        id=lease_id,
        work_kind="RUN_START",
        run_id=run_id,
        organization_id=organization_id,
        project_id=project_id,
        expires_at=datetime.now(UTC) + timedelta(minutes=1),
    )
    worker_record = SimpleNamespace(
        id=worker_id,
        capabilities=["RUN_START", "SECRET_ENVELOPE"],
    )
    worker_module = _worker_module()
    key_pair = worker_module.generate_worker_key_pair()
    def add_record(record: object) -> None:
        if isinstance(record, SecretInjectionGrant) and record.id is None:
            record.id = uuid4()

    session = SimpleNamespace(
        scalar=AsyncMock(side_effect=[run, policy_record, revision, secret, None]),
        flush=AsyncMock(),
        add=Mock(side_effect=add_record),
    )
    monkeypatch.setattr(execution_plane, "_egress_policy_payload", _ceiling)
    monkeypatch.setattr(
        execution_plane,
        "decrypt_project_secret",
        lambda **_kwargs: b"Bearer private-value",
    )
    response = await execution_plane.issue_egress_credential_envelope(
        session,  # type: ignore[arg-type]
        lease=lease,  # type: ignore[arg-type]
        worker=worker_record,  # type: ignore[arg-type]
        payload=EgressCredentialEnvelopeRequest.model_validate(
            {
                "policy_binding_digest": receipt["binding_digest"],
                "worker_public_key_b64": key_pair.public_key_b64,
            }
        ),
        request_id="egress-credential",
    )
    assert response.policy_binding_digest == receipt["binding_digest"]
    assert "private-value" not in response.ciphertext_b64
    assert worker_module.decrypt_egress_credential_envelope(
        {"data": response.model_dump(mode="json")},
        key_pair=key_pair,
        lease_id=str(lease_id),
        worker_id=str(worker_id),
        run_id=str(run_id),
        policy_binding_digest=str(receipt["binding_digest"]),
    ) == "Bearer private-value"
    grant = next(
        call.args[0]
        for call in session.add.call_args_list
        if isinstance(call.args[0], SecretInjectionGrant)
    )
    assert grant.lease_id == lease_id
    assert grant.secret_names == ["PROXY_AUTH"]
    audits = [
        call.args[0]
        for call in session.add.call_args_list
        if type(call.args[0]).__name__ == "AuditEvent"
    ]
    assert audits
    assert "PROXY_AUTH" not in str(audits[0].details)
    assert str(secret_id) not in str(audits[0].details)
