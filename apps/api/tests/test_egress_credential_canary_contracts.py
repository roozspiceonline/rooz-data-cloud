from pathlib import Path

import pytest
from pydantic import ValidationError

from app.core.config import Settings
from app.main import app

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    "overrides",
    [
        {"egress_credential_canary_enabled": True},
        {"egress_credential_canary_target_url": "http://canary.example.com/check"},
        {"egress_credential_canary_target_url": "https://127.0.0.1/check"},
        {"egress_credential_canary_target_url": "https://canary.exämple/check"},
        {"egress_credential_canary_target_url": "https://canary.example.com/check?token=x"},
        {"egress_credential_canary_claim_seconds": 14},
        {"egress_credential_canary_claim_seconds": 301},
        {"egress_credential_canary_batch_size": 101},
        {"egress_credential_canary_max_attempts": 6},
    ],
)
def test_credential_canary_configuration_fails_closed(
    overrides: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        Settings(**overrides)


def test_credential_canary_configuration_accepts_bounded_https_target() -> None:
    settings = Settings(
        egress_credential_canary_enabled=True,
        egress_credential_canary_target_url="https://canary.example.com/auth-check",
    )
    assert settings.egress_credential_canary_enabled is True


def test_canary_migration_enforces_lineage_state_history_and_rls() -> None:
    migration = (
        ROOT
        / "migrations/versions/20260829_0026_egress_credential_canaries.py"
    ).read_text(encoding="utf-8")
    for marker in (
        'down_revision: str | None = "20260828_0025"',
        "uq_egress_credential_canary_binding",
        "enforce_egress_credential_canary_insert",
        "enforce_egress_credential_canary_transition",
        "egress_credential_canary_transitions_immutable",
        "ENABLE ROW LEVEL SECURITY",
        "egress_credential_canary_attempts_scheduler_insert",
        "SECRET_VERSION_SUPERSEDED",
        "attempt_version",
        "ck_egress_credential_canary_transition_shape",
        "ck_egress_credential_canary_claim_window",
    ):
        assert marker in migration


def test_canary_api_is_tenant_read_bounded_and_credential_free() -> None:
    paths = app.openapi()["paths"]
    assert "/api/v1/projects/{project_id}/egress-credential-canaries" in paths
    route = (ROOT / "app/api/routes/egress_policies.py").read_text(encoding="utf-8")
    assert 'require_project_permission("egress.read")' in route
    assert "Query(ge=1, le=100)" in route
    service = (ROOT / "app/services/egress_credential_canaries.py").read_text(
        encoding="utf-8"
    )
    summary = service[service.index("async def list_credential_rotation_canaries") :]
    for prohibited in (
        "credential_secret_id",
        "secret_version",
        "target_digest",
        "claim_token",
    ):
        assert prohibited not in summary
