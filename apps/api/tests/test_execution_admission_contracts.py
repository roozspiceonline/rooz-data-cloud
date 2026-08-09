from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from app.core.config import Settings

API_ROOT = Path(__file__).parents[1]
REPO_ROOT = API_ROOT.parents[1]


def test_admission_migration_persists_limits_and_indexes() -> None:
    migration = (
        API_ROOT
        / "migrations/versions/20260809_0019_execution_concurrency_admission.py"
    ).read_text()
    for required in (
        "max_active_leases",
        "ck_projects_max_active_leases",
        "LEAST(max_concurrency, 16)",
        "max_concurrency BETWEEN 1 AND 16",
        "ix_execution_leases_active_project_admission",
        "ix_execution_leases_active_worker_admission",
    ):
        assert required in migration


def test_claim_path_is_capacity_aware_and_atomic() -> None:
    service = (API_ROOT / "app/services/execution_plane.py").read_text()
    for required in (
        "PROJECT_EXECUTION_SLOT_KINDS",
        "active_project_leases < project_limit",
        "_lock_worker_claims",
        "_lock_project_admission",
        ".with_for_update()",
        'code="PROJECT_CONCURRENCY_LIMIT"',
        'code="WORKER_CONCURRENCY_LIMIT"',
        'claim_payload["admission"]',
        '"project_slot_consumed"',
    ):
        assert required in service


def test_worker_registration_limit_is_server_owned() -> None:
    service = (API_ROOT / "app/services/execution_plane.py").read_text()
    assert "settings.worker_registration_max_concurrency" in service
    assert '"requested_max_concurrency"' in service
    assert '"effective_max_concurrency"' in service


def test_admission_configuration_is_bounded_and_wired() -> None:
    with pytest.raises(ValidationError):
        Settings(worker_registration_max_concurrency=17)
    with pytest.raises(ValidationError):
        Settings(execution_project_default_max_active_leases=0)
    for path in (".env.example", "docker-compose.yml", ".github/workflows/ci.yml"):
        source = (REPO_ROOT / path).read_text()
        assert "RDC_WORKER_REGISTRATION_MAX_CONCURRENCY" in source
        assert "RDC_EXECUTION_PROJECT_DEFAULT_MAX_ACTIVE_LEASES" in source


def test_admission_health_is_aggregate_only() -> None:
    service = (
        API_ROOT / "app/services/execution_recovery_sweeper.py"
    ).read_text()
    route = (API_ROOT / "app/api/routes/health.py").read_text()
    assert "ExecutionAdmissionHealth" in service
    for required in (
        "active_leases",
        "saturated_projects",
        "saturated_workers",
    ):
        assert required in service
        assert required in route
