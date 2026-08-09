from __future__ import annotations

import base64
import importlib.util
import json
import os
import sys
from datetime import UTC, datetime
from io import BytesIO
from pathlib import Path
from types import ModuleType

import pytest
from pydantic import ValidationError

from app.api.routes.health import recovery_metrics_payload
from app.core.config import Settings
from app.services.execution_recovery_sweeper import (
    ExecutionAdmissionHealth,
    ExecutionRecoveryHealth,
)

API_ROOT = Path(__file__).parents[1]
REPO_ROOT = API_ROOT.parents[1]


def _load_script(name: str) -> ModuleType:
    path = REPO_ROOT / "scripts" / name
    module_name = "rdc_test_" + name.removesuffix(".py")
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _production_settings(**overrides: object) -> Settings:
    secret = "production-secret-material-" + "x" * 32
    values: dict[str, object] = {
        "env": "production",
        "deployment_id": "production-primary",
        "database_url": "postgresql+asyncpg://rdc@db.internal/rdc",
        "redis_url": "rediss://cache.internal/0",
        "s3_endpoint": "https://object-storage.internal",
        "s3_public_endpoint": "https://objects.example.com",
        "s3_bucket": "rdc-production-primary",
        "s3_access_key": "production-access-reference",
        "s3_secret_key": secret,
        "allowed_origins": ["https://app.example.com"],
        "session_cookie_secure": True,
        "session_token_pepper": secret,
        "csrf_token_pepper": secret,
        "api_key_pepper": secret,
        "api_key_issuance_secret": secret,
        "rate_limit_key": secret,
        "cursor_signing_key": secret,
        "worker_bootstrap_token": secret,
        "worker_token_pepper": secret,
        "lease_token_pepper": secret,
        "project_secret_master_key_b64": base64.b64encode(b"p" * 32).decode(),
        "project_secret_master_key_version": "production-primary-v1",
    }
    values.update(overrides)
    return Settings(**values)


def test_nonlocal_environment_identity_and_storage_are_separated() -> None:
    settings = _production_settings()
    assert settings.deployment_id == "production-primary"
    with pytest.raises(ValidationError, match="Deployment ID"):
        _production_settings(deployment_id="staging-primary")
    with pytest.raises(ValidationError, match="bucket"):
        _production_settings(s3_bucket="rdc-staging-primary")
    with pytest.raises(ValidationError, match="HTTPS origins"):
        _production_settings(allowed_origins=["http://app.example.com"])
    with pytest.raises(ValidationError, match="HTTPS origins"):
        _production_settings(allowed_origins=["https://"])
    with pytest.raises(ValidationError, match="Object-storage endpoints"):
        _production_settings(s3_endpoint="http://object-storage.internal")
    with pytest.raises(ValidationError, match="key version"):
        _production_settings(
            project_secret_master_key_version="staging-primary-v1"
        )


def test_recovery_metrics_are_bounded_global_aggregates() -> None:
    now = datetime.now(UTC)
    health = ExecutionRecoveryHealth(
        status="HEALTHY",
        last_started_at=now,
        last_completed_at=now,
        last_heartbeat_at=now,
        last_leases_reaped=2,
        last_cancellations_converged=1,
        last_workers_lost=1,
        last_worker_leases_fenced=1,
        total_sweeps=20,
        total_failures=1,
        total_workers_lost=3,
        total_worker_leases_fenced=4,
        last_error_code=None,
    )
    admission = ExecutionAdmissionHealth(
        active_leases=5,
        saturated_projects=1,
        saturated_workers=2,
        recovery_pending_workers=0,
    )
    payload = recovery_metrics_payload(health, admission, now=now)
    assert "rdc_execution_recovery_healthy 1\n" in payload
    assert "rdc_execution_recovery_workers_lost_total 3\n" in payload
    assert "rdc_execution_recovery_pending_workers 0\n" in payload
    for prohibited in ("organization", "project_id", "worker_id", "lease_id"):
        assert prohibited not in payload


def test_production_readiness_rejects_redirectable_or_credentialed_origins(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _load_script("check_production_readiness.py")
    assert (
        module.validate_base_url(
            "http://127.0.0.1:8000",
            allow_loopback_http=True,
        )
        == "http://127.0.0.1:8000"
    )
    with pytest.raises(module.ReadinessError):
        module.validate_base_url(
            "http://api.example.com",
            allow_loopback_http=False,
        )
    with pytest.raises(module.ReadinessError):
        module.validate_base_url(
            "https://user:secret@api.example.com",
            allow_loopback_http=False,
        )

    paths: list[str] = []

    def fake_fetch(_base_url: str, path: str) -> dict[str, object]:
        paths.append(path)
        return {
            "/health/live": {"service": "rdc-api", "status": "ok"},
            "/health/recovery": {
                "service": "rdc-execution-recovery",
                "status": "ready",
            },
            "/health/ready": {"service": "rdc-api", "status": "ready"},
        }[path]

    monkeypatch.setattr(module, "fetch_health", fake_fetch)
    module.probe("https://api.example.com", "all")
    assert paths == ["/health/live", "/health/recovery", "/health/ready"]


def test_production_supervisor_and_slo_contracts_are_fail_closed() -> None:
    systemd = REPO_ROOT / "infrastructure/systemd"
    api = (systemd / "rdc-api.service").read_text()
    recovery = (systemd / "rdc-execution-recovery.service").read_text()
    worker = (systemd / "rdc-sandbox-worker.service").read_text()
    object_recovery = (
        systemd / "rdc-object-recovery-drill.service"
    ).read_text()
    for unit in (api, recovery, worker):
        assert "KillMode=control-group" in unit
        assert "NoNewPrivileges=true" in unit
        assert "ProtectSystem=strict" in unit
        assert "CapabilityBoundingSet=" in unit
        assert "EnvironmentFile=/etc/rdc/production/" in unit
    assert "Restart=always" in recovery
    assert "--mode recovery" in recovery
    assert "ExecStartPre=/usr/bin/test ! -S /var/run/docker.sock" in worker
    assert worker.count("recovery_cli.py") == 2
    assert "ExecStopPost=" in worker
    assert "FinalKillSignal=SIGKILL" in worker
    assert (
        "EnvironmentFile=/etc/rdc/production/object-recovery.env"
        in object_recovery
    )
    assert "api.env" not in object_recovery

    alerts = (
        REPO_ROOT
        / "infrastructure/monitoring/rdc-execution-recovery.rules.yml"
    ).read_text()
    for marker in (
        "RDCExecutionRecoveryUnavailable",
        "RDCExecutionRecoveryHeartbeatMissing",
        "RDCWorkerRecoveryPending",
        "RDCWorkerLossBurst",
        "RDCRecoveryFailure",
    ):
        assert marker in alerts
    assert "rdc_execution_recovery_enabled != 1" in alerts
    assert "project_id" not in alerts
    assert "worker_id" not in alerts


def test_backup_uses_environment_credentials_and_writes_verified_manifest(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    module = _load_script("production_recovery_drill.py")
    monkeypatch.setenv("RDC_BACKUP_DATABASE_URL", "must-not-reach-child")
    monkeypatch.setenv("RDC_RESTORE_DATABASE_URL", "must-not-reach-child")
    connection = module.parse_database_url(
        "postgresql://rdc:top-secret@127.0.0.1:5432/rdc?sslmode=disable"
    )
    calls: list[list[str]] = []

    def fake_run(arguments: list[str], **kwargs: object) -> str:
        calls.append(arguments)
        child_environment = kwargs["environment"]
        assert isinstance(child_environment, dict)
        assert "RDC_BACKUP_DATABASE_URL" not in child_environment
        assert "RDC_RESTORE_DATABASE_URL" not in child_environment
        assert child_environment["PGPASSWORD"] == "top-secret"
        assert "top-secret" not in " ".join(arguments)
        if arguments[0] == "psql":
            return "20260809_0020"
        output = kwargs.get("stdout")
        assert output is not None
        output.write(b"custom-format-backup")
        return ""

    monkeypatch.setattr(module, "_run", fake_run)
    archive = tmp_path / "rdc.dump"
    manifest = module.run_backup(
        connection=connection,
        archive_path=archive,
        environment="production",
        deployment_id="production-primary",
        timeout_seconds=30,
    )
    assert archive.read_bytes() == b"custom-format-backup"
    assert manifest["schema_version"] == "rdc.production-backup/v1"
    assert manifest["alembic_revision"] == "20260809_0020"
    assert (tmp_path / "rdc.dump.manifest.json").is_file()
    assert [call[0] for call in calls] == ["psql", "pg_dump"]
    assert os.stat(archive).st_mode & 0o077 == 0


def _create_backup_fixture(module: ModuleType, root: Path) -> Path:
    archive = root / "rdc.dump"
    archive.write_bytes(b"custom-format-backup")
    checksum = module._sha256(archive)
    manifest = {
        "schema_version": "rdc.production-backup/v1",
        "created_at": datetime.now(UTC).isoformat(),
        "environment": "production",
        "deployment_id": "production-primary",
        "archive_file": archive.name,
        "size_bytes": archive.stat().st_size,
        "sha256": checksum,
        "alembic_revision": "20260809_0020",
    }
    (root / "rdc.dump.manifest.json").write_text(json.dumps(manifest))
    return archive


def test_restore_drill_rolls_migration_and_always_removes_database(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    module = _load_script("production_recovery_drill.py")
    connection = module.parse_database_url(
        "postgresql://rdc:top-secret@127.0.0.1:5432/rdc"
    )
    archive = _create_backup_fixture(module, tmp_path)
    api_root = tmp_path / "api"
    alembic = api_root / ".venv/bin/alembic"
    alembic.parent.mkdir(parents=True)
    alembic.write_text("#!/bin/sh\n")
    alembic.chmod(0o700)
    calls: list[list[str]] = []

    def fake_run(arguments: list[str], **kwargs: object) -> str:
        calls.append(arguments)
        if arguments[0] == str(alembic):
            child_environment = kwargs["environment"]
            assert isinstance(child_environment, dict)
            assert child_environment["RDC_ENV"] == "test"
            assert child_environment["RDC_DATABASE_URL"].startswith(
                "postgresql+asyncpg://"
            )
        if arguments[0] == "psql":
            return "20260809_0020"
        if len(arguments) > 1 and arguments[1] == "heads":
            return "20260809_0020 (head)"
        return ""

    monkeypatch.setattr(module, "_run", fake_run)
    result = module.run_restore_drill(
        connection=connection,
        archive_path=archive,
        environment="production",
        deployment_id="production-primary",
        api_root=api_root,
        timeout_seconds=30,
    )
    assert result["restore_verified"] is True
    assert result["migration_rollback_verified"] is True
    assert [call[0] for call in calls].count("dropdb") == 1
    assert any(call[1:] == ["downgrade", "-1"] for call in calls)
    assert any(call[1:] == ["upgrade", "head"] for call in calls)

    calls.clear()

    def fail_restore(arguments: list[str], **_: object) -> str:
        calls.append(arguments)
        if arguments[0] == "pg_restore":
            raise module.RecoveryDrillError("restore failed")
        return ""

    monkeypatch.setattr(module, "_run", fail_restore)
    with pytest.raises(module.RecoveryDrillError):
        module.run_restore_drill(
            connection=connection,
            archive_path=archive,
            environment="production",
            deployment_id="production-primary",
            api_root=api_root,
            timeout_seconds=30,
        )
    assert [call[0] for call in calls].count("dropdb") == 1


def test_object_storage_drill_restores_version_and_cleans_only_canary() -> None:
    module = _load_script("object_storage_recovery_drill.py")

    class Client:
        def __init__(self) -> None:
            self.values: dict[str, bytes] = {}
            self.records: list[dict[str, str]] = []
            self.deleted: list[dict[str, str]] = []

        def get_bucket_versioning(self, *, Bucket: str) -> dict[str, object]:
            assert Bucket == "rdc-production-primary"
            return {"Status": "Enabled"}

        def put_object(self, **kwargs: object) -> dict[str, object]:
            key = kwargs["Key"]
            body = kwargs["Body"]
            assert isinstance(key, str) and isinstance(body, bytes)
            assert key.startswith("recovery-drill/production-primary/")
            assert kwargs["ServerSideEncryption"] == "AES256"
            version = f"version-{len(self.records) + 1}"
            self.values[version] = body
            self.records.append({"Key": key, "VersionId": version})
            return {"VersionId": version}

        def delete_object(self, *, Bucket: str, Key: str) -> dict[str, object]:
            self.records.append({"Key": Key, "VersionId": "delete-marker"})
            return {"VersionId": "delete-marker"}

        def get_object(self, **kwargs: object) -> dict[str, object]:
            version = kwargs["VersionId"]
            assert isinstance(version, str)
            return {"Body": BytesIO(self.values[version])}

        def list_object_versions(self, **_: object) -> dict[str, object]:
            return {
                "Versions": self.records[:2],
                "DeleteMarkers": self.records[2:],
                "IsTruncated": False,
            }

        def delete_objects(self, **kwargs: object) -> dict[str, object]:
            delete = kwargs["Delete"]
            assert isinstance(delete, dict)
            objects = delete["Objects"]
            assert isinstance(objects, list)
            self.deleted.extend(objects)
            return {"Errors": []}

    client = Client()
    result = module.run_object_recovery_drill(
        client,
        environment="production",
        deployment_id="production-primary",
        endpoint="https://object-storage.internal",
        bucket="rdc-production-primary",
        kms_key_id=None,
    )
    assert result["restore_verified"] is True
    assert result["canary_versions_removed"] == 3
    assert len(client.deleted) == 3
    assert {record["Key"] for record in client.deleted} == {
        client.records[0]["Key"]
    }

    with pytest.raises(module.ObjectRecoveryDrillError):
        module.run_object_recovery_drill(
            client,
            environment="production",
            deployment_id="production-primary",
            endpoint="https://object-storage.internal",
            bucket="rdc-staging-primary",
            kms_key_id=None,
        )
