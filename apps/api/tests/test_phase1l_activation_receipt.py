from pydantic import ValidationError

from app.execution_schemas import SandboxActivation


BASE = {
    "agent_version_id": "11111111-1111-1111-1111-111111111111",
    "worker_name": "rdc-canary-worker",
    "attestation_digest": "a" * 64,
    "sandbox_policy_digest": "b" * 64,
    "constraints_digest": "c" * 64,
    "no_secrets": True,
    "max_concurrency": 1,
}


def expect_validation_error(value: dict[str, object]) -> None:
    try:
        SandboxActivation.model_validate(value)
    except ValidationError:
        return
    raise AssertionError("Expected SandboxActivation validation to fail.")


def test_phase1l_controlled_browser_requires_both_policy_digests() -> None:
    activation = SandboxActivation.model_validate(
        {
            **BASE,
            "capability_profile": "controlled-browser",
            "egress_policy_digest": "d" * 64,
            "browser_policy_digest": "e" * 64,
        }
    )
    assert activation.capability_profile == "controlled-browser"


def test_phase1l_controlled_browser_rejects_missing_digest() -> None:
    for missing in ["egress_policy_digest", "browser_policy_digest"]:
        value = {
            **BASE,
            "capability_profile": "controlled-browser",
            "egress_policy_digest": "d" * 64,
            "browser_policy_digest": "e" * 64,
        }
        value.pop(missing)
        expect_validation_error(value)


def test_phase1l_brokered_web_egress_rejects_browser_digest() -> None:
    expect_validation_error(
        {
            **BASE,
            "capability_profile": "brokered-web-egress",
            "egress_policy_digest": "d" * 64,
            "browser_policy_digest": "e" * 64,
        }
    )


def test_phase1l_offline_rejects_browser_digest() -> None:
    expect_validation_error(
        {
            **BASE,
            "capability_profile": "offline-minimal",
            "browser_policy_digest": "e" * 64,
        }
    )
