from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

TransportFailure = Literal[
    "DNS_FAILURE",
    "TLS_FAILURE",
    "TIMEOUT",
    "PROXY_FAILURE",
]
EgressOutcome = Literal[
    "SUCCESS",
    "HTTP_403",
    "HTTP_429",
    "BOT_CHALLENGE",
    "LOGIN_REQUIRED",
    "EMPTY_RESPONSE",
    "HTTP_ERROR",
    "DNS_FAILURE",
    "TLS_FAILURE",
    "TIMEOUT",
    "PROXY_FAILURE",
]


class EgressHealthEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    transport_failure: TransportFailure | None = None
    http_status: int | None = Field(default=None, ge=100, le=599)
    response_bytes: int | None = Field(default=None, ge=0, le=16_777_216)
    latency_ms: int = Field(ge=0, le=300_000)
    challenge_detected: bool = False
    login_required: bool = False

    @model_validator(mode="after")
    def consistent_evidence(self) -> EgressHealthEvidence:
        if (self.transport_failure is None) == (self.http_status is None):
            raise ValueError("Provide exactly one transport failure or HTTP status.")
        if self.transport_failure is not None and (
            self.response_bytes is not None
            or self.challenge_detected
            or self.login_required
        ):
            raise ValueError("Transport failures cannot carry HTTP evidence.")
        return self


class EgressHealthObservationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    observation_id: UUID
    evidence: EgressHealthEvidence


class EgressHealthObservationResult(BaseModel):
    id: UUID
    observation_id: UUID
    outcome: EgressOutcome
    healthy: bool
    retryable: bool
    replayed: bool
    observed_at: datetime


@dataclass(frozen=True)
class ClassifiedEgressHealth:
    outcome: EgressOutcome
    healthy: bool
    retryable: bool


def classify_egress_health(
    evidence: EgressHealthEvidence,
) -> ClassifiedEgressHealth:
    if evidence.transport_failure is not None:
        return ClassifiedEgressHealth(evidence.transport_failure, False, True)
    if evidence.challenge_detected:
        return ClassifiedEgressHealth("BOT_CHALLENGE", False, False)
    if evidence.login_required:
        return ClassifiedEgressHealth("LOGIN_REQUIRED", False, False)
    if evidence.http_status == 403:
        return ClassifiedEgressHealth("HTTP_403", False, False)
    if evidence.http_status == 429:
        return ClassifiedEgressHealth("HTTP_429", False, True)
    if evidence.http_status is not None and evidence.http_status >= 400:
        return ClassifiedEgressHealth(
            "HTTP_ERROR", False, evidence.http_status >= 500
        )
    if evidence.response_bytes == 0:
        return ClassifiedEgressHealth("EMPTY_RESPONSE", False, True)
    return ClassifiedEgressHealth("SUCCESS", True, False)
