from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


def _default_methods() -> list[Literal["GET", "HEAD"]]:
    return ["GET"]


class EgressPolicySpec(StrictModel):
    allowed_hosts: list[str] = Field(min_length=1, max_length=64)
    allowed_methods: list[Literal["GET", "HEAD"]] = Field(
        default_factory=_default_methods, min_length=1, max_length=2
    )
    max_requests: int = Field(default=16, ge=1, le=64)
    max_response_bytes: int = Field(default=1_048_576, ge=65_536, le=8_388_608)
    max_total_bytes: int = Field(default=4_194_304, ge=65_536, le=33_554_432)
    max_redirects: int = Field(default=0, ge=0, le=5)
    connect_timeout_seconds: int = Field(default=5, ge=1, le=10)
    request_timeout_seconds: int = Field(default=15, ge=1, le=30)
    credential_secret_id: UUID | None = None


class CreateEgressPolicyRequest(StrictModel):
    schema_version: Literal["rdc.egress-policy/v1"] = "rdc.egress-policy/v1"
    name: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$",
    )
    spec: EgressPolicySpec


class CreateEgressPolicyRevisionRequest(StrictModel):
    schema_version: Literal["rdc.egress-policy-revision/v1"] = "rdc.egress-policy-revision/v1"
    expected_version: int = Field(ge=1)
    spec: EgressPolicySpec


class ActivateEgressPolicyRequest(StrictModel):
    revision_id: UUID
    expected_version: int = Field(ge=1)


class DisableEgressPolicyRequest(StrictModel):
    expected_version: int = Field(ge=1)


class EgressPolicyRevisionSummary(StrictModel):
    id: UUID
    policy_id: UUID
    revision_number: int
    allowed_hosts: list[str]
    allowed_methods: list[str]
    max_requests: int
    max_response_bytes: int
    max_total_bytes: int
    max_redirects: int
    connect_timeout_seconds: int
    request_timeout_seconds: int
    credential_configured: bool
    policy_digest: str
    created_by_user_id: UUID
    created_at: datetime


class EgressPolicySummary(StrictModel):
    id: UUID
    organization_id: UUID
    project_id: UUID
    name: str
    status: Literal["DRAFT", "ACTIVE", "DISABLED"]
    active_revision_id: UUID | None
    activated_at: datetime | None
    disabled_at: datetime | None
    created_by_user_id: UUID
    created_at: datetime
    updated_at: datetime
    version: int
