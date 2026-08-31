from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.core.config import Settings
from app.core.errors import ApiError
from app.egress_health_protocol import EgressHealthObservationRequest
from app.services.egress_health import _validate_reporting_context
from app.services.egress_health_maintenance import (
    EgressHealthMaintenanceHealth,
    egress_health_maintenance_is_fresh,
)

ROOT = Path(__file__).parents[3]


def _lease(*, profile: str = "brokered-web-egress") -> SimpleNamespace:
    return SimpleNamespace(
        work_kind="RUN_START",
        run_id=uuid4(),
        payload_snapshot={
            "activation": {
                "capability_profile": profile,
                "egress_policy_digest": "a" * 64,
            }
        },
    )


def test_observation_request_accepts_only_id_and_bounded_evidence() -> None:
    request = EgressHealthObservationRequest.model_validate(
        {
            "observation_id": uuid4(),
            "evidence": {
                "http_status": 200,
                "response_bytes": 10,
                "latency_ms": 7,
            },
        }
    )
    assert request.evidence.http_status == 200
    with pytest.raises(ValidationError):
        EgressHealthObservationRequest.model_validate(
            {
                "observation_id": uuid4(),
                "outcome": "SUCCESS",
                "organization_id": uuid4(),
                "evidence": {
                    "http_status": 200,
                    "latency_ms": 7,
                    "target_url": "https://tenant-secret.invalid/path",
                },
            }
        )


@pytest.mark.parametrize(
    ("work_kind", "run_id", "capabilities", "profile"),
    [
        ("BUILD", uuid4(), ["EVENT_INGEST"], "brokered-web-egress"),
        ("RUN_START", None, ["EVENT_INGEST"], "brokered-web-egress"),
        ("RUN_START", uuid4(), [], "brokered-web-egress"),
        ("RUN_START", uuid4(), ["EVENT_INGEST"], "offline-minimal"),
    ],
)
def test_reporting_requires_event_ingest_on_egress_enabled_run_lease(
    work_kind: str,
    run_id: object,
    capabilities: list[str],
    profile: str,
) -> None:
    lease = _lease(profile=profile)
    lease.work_kind = work_kind
    lease.run_id = run_id
    with pytest.raises(ApiError, match="lease cannot report"):
        _validate_reporting_context(
            lease, SimpleNamespace(capabilities=capabilities)
        )


def test_persistence_migration_enforces_immutability_rls_and_exact_lease() -> None:
    source = (
        ROOT
        / "apps/api/migrations/versions/20260828_0023_egress_health_observations.py"
    ).read_text(encoding="utf-8")
    for marker in (
        "ENABLE ROW LEVEL SECURITY",
        "egress_health_observations_tenant_select",
        "egress_health_observations_worker_insert",
        "lease.worker_id = NEW.worker_id",
        "lease.organization_id = NEW.organization_id",
        "lease.project_id = NEW.project_id",
        "lease.run_id = NEW.run_id",
        "lease.status = 'ACTIVE'",
        "egress_health_observations_immutable",
        "uq_egress_health_observations_lease_client",
        'op.drop_table("egress_health_observations", schema="control")',
    ):
        assert marker in source


def test_service_derives_ownership_and_classification_and_summary_is_bounded() -> None:
    service = (ROOT / "apps/api/app/services/egress_health.py").read_text(
        encoding="utf-8"
    )
    route = (ROOT / "apps/api/app/api/routes/egress_policies.py").read_text(
        encoding="utf-8"
    )
    assert "organization_id=lease.organization_id" in service
    assert "project_id=lease.project_id" in service
    assert "run_id=lease.run_id" in service
    assert "classify_egress_health(payload.evidence)" in service
    assert "EGRESS_HEALTH_REPLAY_CONFLICT" in service
    assert "Query(ge=1, le=24)" in route
    assert 'require_project_permission("egress.read")' in route
    assert '"/projects/{project_id}/egress-health/routes"' in route
    assert "summarize_egress_health_routes" in route


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("egress_route_provider_key", "Vendor Secret"),
        ("egress_route_region_key", "https://region.invalid"),
        ("egress_health_min_route_samples", 4),
        ("egress_health_min_route_samples", 1001),
        ("egress_health_maintenance_interval_seconds", 299),
        ("egress_health_rollup_batch_size", 169),
        ("egress_health_purge_batch_size", 10001),
        ("egress_health_raw_retention_hours", 47),
        ("egress_health_rollup_retention_days", 6),
        ("egress_health_maintenance_stale_after_seconds", 7199),
    ],
)
def test_route_health_configuration_is_bounded(
    field: str, value: object
) -> None:
    with pytest.raises(ValidationError):
        Settings(**{field: value})


def test_route_dimension_migration_is_bounded_and_reversible() -> None:
    source = (
        ROOT
        / "apps/api/migrations/versions/20260828_0024_egress_health_route_dimensions.py"
    ).read_text(encoding="utf-8")
    for marker in (
        'down_revision: str | None = "20260828_0023"',
        'server_default="legacy"',
        'server_default="unknown"',
        "ck_egress_health_observations_provider_key",
        "ck_egress_health_observations_region_key",
        "ix_egress_health_observations_project_route_time",
        '"provider_key", schema="control"',
    ):
        assert marker in source


def test_compact_evidence_migration_reduces_write_amplification() -> None:
    source = (
        ROOT
        / "apps/api/migrations/versions/20260828_0025_compact_egress_health.py"
    ).read_text(encoding="utf-8")
    for marker in (
        'down_revision: str | None = "20260828_0024"',
        "transport_failure",
        "http_status",
        "response_bytes",
        "latency_ms",
        "ck_egress_health_observations_compact_evidence",
        "NEW.evidence := NULL",
        "ix_egress_health_observations_worker_id",
        "ix_egress_health_observations_lease_id_observed_at",
        "DISABLE TRIGGER egress_health_observations_immutable",
        "ENABLE TRIGGER egress_health_observations_immutable",
    ):
        assert marker in source
    service = (ROOT / "apps/api/app/services/egress_health.py").read_text(
        encoding="utf-8"
    )
    assert "evidence=None" in service
    assert "transport_failure=payload.evidence.transport_failure" in service
    assert "append_audit_event" not in service
    assert "egress_health.observed" not in service


def test_rollup_retention_increment_is_bounded_and_tenant_isolated() -> None:
    source = (
        ROOT
        / "apps/api/migrations/versions/20260902_0034_egress_health_rollups_retention.py"
    ).read_text(encoding="utf-8")
    for marker in (
        'down_revision: str | None = "20260901_0033"',
        "egress_health_rollup_buckets",
        "egress_health_maintenance_state",
        "ENABLE ROW LEVEL SECURITY",
        "egress_health_rollup_buckets_tenant_select",
        "run_egress_health_maintenance",
        "pg_try_advisory_xact_lock",
        "p_rollup_batch_size NOT BETWEEN 1 AND 168",
        "p_purge_batch_size NOT BETWEEN 1 AND 10000",
        "p_raw_retention_hours NOT BETWEEN 48 AND 168",
        "p_rollup_retention_days NOT BETWEEN 7 AND 90",
        "egress_health_raw_retention_cutoff",
        "egress_health_rollup_retention_cutoff",
        "REVOKE ALL ON FUNCTION",
        "DROP FUNCTION IF EXISTS control.run_egress_health_maintenance",
    ):
        assert marker in source


def test_summary_uses_rollups_with_exact_raw_fallback() -> None:
    service = (ROOT / "apps/api/app/services/egress_health.py").read_text(
        encoding="utf-8"
    )
    for marker in (
        "_egress_health_aggregate_rows",
        "control.egress_health_rollup_buckets",
        "control.egress_health_observations",
        "AND NOT EXISTS",
        '"healthy_basis_points"',
        '"minimum_samples"',
    ):
        assert marker in service


def test_maintenance_runner_is_dedicated_and_hardened() -> None:
    runner = (
        ROOT / "apps/api/app/egress_health_maintenance_runner.py"
    ).read_text(encoding="utf-8")
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    unit = (
        ROOT / "infrastructure/systemd/rdc-egress-health-maintenance.service"
    ).read_text(encoding="utf-8")
    assert "run_egress_health_maintenance" in runner
    assert "record_egress_health_maintenance_failure" in runner
    assert "--healthcheck" in runner
    assert "egress-health-maintenance:" in compose
    assert 'app.egress_health_maintenance_runner"' in compose
    assert "no-new-privileges:true" in compose
    assert "read_only: true" in compose
    assert "NoNewPrivileges=true" in unit
    assert "ProtectSystem=strict" in unit
    assert "CapabilityBoundingSet=" in unit


def test_maintenance_health_requires_recent_success() -> None:
    now = datetime.now(UTC)
    values = {
        "status": "HEALTHY",
        "last_started_at": now,
        "last_completed_at": now,
        "last_heartbeat_at": now,
        "last_buckets_rolled": 0,
        "last_raw_rows_purged": 0,
        "last_rollup_rows_purged": 0,
        "total_sweeps": 1,
        "total_failures": 0,
        "total_buckets_rolled": 0,
        "total_raw_rows_purged": 0,
        "total_rollup_rows_purged": 0,
        "last_error_code": None,
    }
    health = EgressHealthMaintenanceHealth(**values)
    assert egress_health_maintenance_is_fresh(
        health, now=now, stale_after_seconds=60
    )
    values["last_completed_at"] = now - timedelta(seconds=61)
    assert not egress_health_maintenance_is_fresh(
        EgressHealthMaintenanceHealth(**values),
        now=now,
        stale_after_seconds=60,
    )
