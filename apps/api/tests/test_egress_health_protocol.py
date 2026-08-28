import pytest
from pydantic import ValidationError

from app.egress_health_protocol import (
    EgressHealthEvidence,
    classify_egress_health,
)


@pytest.mark.parametrize(
    ("payload", "outcome", "healthy", "retryable"),
    [
        ({"http_status": 200, "response_bytes": 12, "latency_ms": 8}, "SUCCESS", True, False),
        ({"http_status": 403, "response_bytes": 12, "latency_ms": 8}, "HTTP_403", False, False),
        ({"http_status": 429, "response_bytes": 12, "latency_ms": 8}, "HTTP_429", False, True),
        ({"http_status": 200, "response_bytes": 0, "latency_ms": 8}, "EMPTY_RESPONSE", False, True),
        ({"transport_failure": "TIMEOUT", "latency_ms": 300_000}, "TIMEOUT", False, True),
    ],
)
def test_classification_is_deterministic_and_bounded(
    payload: dict[str, object], outcome: str, healthy: bool, retryable: bool
) -> None:
    result = classify_egress_health(EgressHealthEvidence.model_validate(payload))
    assert (result.outcome, result.healthy, result.retryable) == (
        outcome,
        healthy,
        retryable,
    )


def test_challenge_signal_takes_precedence_without_content_storage() -> None:
    result = classify_egress_health(
        EgressHealthEvidence.model_validate(
            {
                "http_status": 200,
                "response_bytes": 100,
                "latency_ms": 20,
                "challenge_detected": True,
            }
        )
    )
    assert result.outcome == "BOT_CHALLENGE"


@pytest.mark.parametrize(
    "payload",
    [
        {"latency_ms": 1},
        {"http_status": 200, "transport_failure": "TIMEOUT", "latency_ms": 1},
        {"transport_failure": "TIMEOUT", "response_bytes": 0, "latency_ms": 1},
        {"http_status": 200, "latency_ms": 300_001},
        {"http_status": 200, "latency_ms": 1, "target_url": "https://secret.invalid"},
    ],
)
def test_ambiguous_unbounded_or_target_bearing_evidence_is_rejected(
    payload: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        EgressHealthEvidence.model_validate(payload)
