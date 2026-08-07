from uuid import UUID

import pytest
from pydantic import ValidationError

from app.core.config import Settings
from app.execution_schemas import SandboxActivation


def _activation(
    *,
    capability_profile: str = "offline-minimal",
    egress_policy_digest: str | None = None,
) -> SandboxActivation:
    return SandboxActivation(
        agent_version_id=UUID("11111111-1111-4111-8111-111111111111"),
        worker_name="rdc-canary-worker",
        attestation_digest="a" * 64,
        sandbox_policy_digest="b" * 64,
        constraints_digest="c" * 64,
        capability_profile=capability_profile,
        egress_policy_digest=egress_policy_digest,
    )


def test_phase1j_web_egress_defaults_disabled() -> None:
    settings = Settings()
    assert settings.sandbox_canary_web_egress_enabled is False
    assert settings.sandbox_canary_web_egress_allowed_hosts == []
    assert settings.sandbox_canary_web_egress_max_requests == 8
    assert settings.sandbox_canary_web_egress_max_response_bytes == 1_048_576
    assert settings.sandbox_canary_web_egress_max_total_bytes == 4_194_304
    assert settings.sandbox_canary_web_egress_max_redirects == 3


def test_phase1j_operator_hosts_are_normalized() -> None:
    settings = Settings(
        sandbox_canary_web_egress_allowed_hosts=[
            "Example.COM.",
            "example.com",
        ]
    )
    assert settings.sandbox_canary_web_egress_allowed_hosts == ["example.com"]


@pytest.mark.parametrize(
    "host",
    [
        "127.0.0.1",
        "169.254.169.254",
        "*.example.com",
        "localhost",
        "service.local",
    ],
)
def test_phase1j_invalid_operator_hosts_are_rejected(host: str) -> None:
    with pytest.raises(ValueError):
        Settings(sandbox_canary_web_egress_allowed_hosts=[host])


def test_phase1j_egress_gate_requires_canary_activation() -> None:
    with pytest.raises(ValueError):
        Settings(
            sandbox_execution_enabled=False,
            sandbox_activation_mode="disabled",
            sandbox_canary_web_egress_enabled=True,
            sandbox_canary_web_egress_allowed_hosts=["example.com"],
        )


def test_phase1j_offline_activation_rejects_egress_digest() -> None:
    with pytest.raises(ValidationError):
        _activation(
            capability_profile="offline-minimal",
            egress_policy_digest="d" * 64,
        )


def test_phase1j_brokered_activation_requires_egress_digest() -> None:
    with pytest.raises(ValidationError):
        _activation(capability_profile="brokered-web-egress")


def test_phase1j_brokered_activation_accepts_digest_bound_policy() -> None:
    activation = _activation(
        capability_profile="brokered-web-egress",
        egress_policy_digest="d" * 64,
    )
    assert activation.capability_profile == "brokered-web-egress"
    assert activation.egress_policy_digest == "d" * 64
    assert activation.no_secrets is True
    assert activation.max_concurrency == 1
