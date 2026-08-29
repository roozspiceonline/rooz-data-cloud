from pathlib import Path

import pytest
from pydantic import ValidationError

from app.core.config import Settings

ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = ROOT.parents[1]


def test_live_runner_configuration_is_false_by_default_and_bounded() -> None:
    settings = Settings()
    assert settings.egress_credential_canary_live_executor_enabled is False
    with pytest.raises(ValidationError):
        Settings(egress_credential_canary_live_executor_enabled=True)
    with pytest.raises(ValidationError):
        Settings(
            egress_credential_canary_enabled=True,
            egress_credential_canary_target_url="https://canary.example.com/check",
            egress_credential_canary_live_executor_enabled=True,
            egress_credential_canary_claim_seconds=20,
            egress_credential_canary_total_timeout_seconds=20,
        )
    enabled = Settings(
        egress_credential_canary_enabled=True,
        egress_credential_canary_target_url="https://canary.example.com/check",
        egress_credential_canary_live_executor_enabled=True,
    )
    assert enabled.egress_credential_canary_max_concurrency == 4
    assert enabled.egress_credential_canary_max_retries == 0


def test_live_runner_uses_claim_fenced_secret_loader_and_direct_transport() -> None:
    migration = (
        ROOT
        / "migrations/versions/20260829_0028_egress_credential_canary_live_runner.py"
    ).read_text(encoding="utf-8")
    for marker in (
        'down_revision: str | None = "20260829_0027"',
        "load_egress_credential_canary_secret",
        "SECURITY DEFINER",
        "SET search_path = pg_catalog, control, security, pg_temp",
        "attempt.status = 'CLAIMED'",
        "attempt.claim_token_digest = p_claim_token_digest",
        "attempt.claim_expires_at > CURRENT_TIMESTAMP",
        "secret.version = attempt.secret_version",
        "REVOKE ALL ON FUNCTION",
    ):
        assert marker in migration

    runner = (ROOT / "app/egress_credential_canary_runner.py").read_text(
        encoding="utf-8"
    )
    for marker in (
        "load_credential_rotation_canary_secret",
        "decrypt_project_secret",
        "run_credential_canary_transport",
        "claim.target_digest != configured_target_digest()",
        "for index in range(len(plaintext))",
        'authorization = ""',
    ):
        assert marker in runner
    for prohibited in (
        "logger.exception",
        "material.secret_name)",
        "settings.egress_credential_canary_target_url)",
    ):
        assert prohibited not in runner

    transport = (ROOT / "app/egress_credential_canary_transport.py").read_text(
        encoding="utf-8"
    )
    for marker in (
        "asyncio.open_connection",
        "server_hostname=hostname",
        "validate_connected_peer",
        "reject_redirect",
        '"Connection: close',
        "tls_client_context",
    ):
        assert marker in transport
    for prohibited in ("httpx", "requests.", "urllib.request"):
        assert prohibited not in transport


def test_live_runner_is_a_separate_false_by_default_compose_service() -> None:
    compose = (REPO_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert "egress-credential-canary-runner:" in compose
    assert 'command: ["python", "-m", "app.egress_credential_canary_runner"]' in compose
    assert (
        "RDC_EGRESS_CREDENTIAL_CANARY_LIVE_EXECUTOR_ENABLED: "
        "${RDC_EGRESS_CREDENTIAL_CANARY_LIVE_EXECUTOR_ENABLED:-false}"
    ) in compose
    assert "RDC_S3_SECRET_KEY" not in compose[
        compose.index("  egress-credential-canary-runner:") : compose.index("  console:")
    ]


def test_foundation_reports_live_executor_setting_without_enabling_adaptive_routing() -> None:
    source = (ROOT / "app/main.py").read_text(encoding="utf-8")
    assert 'v1_router.get("/system/foundation"' in source
    assert "settings.egress_credential_canary_live_executor_enabled" in source
    assert '"egress_adaptive_routing_enabled": False' in source
