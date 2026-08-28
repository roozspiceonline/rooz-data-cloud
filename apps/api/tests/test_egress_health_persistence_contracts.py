from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.core.errors import ApiError
from app.egress_health_protocol import EgressHealthObservationRequest
from app.services.egress_health import _validate_reporting_context

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
