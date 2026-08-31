from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, SecretStr


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CreateWebhookDestinationRequest(StrictModel):
    schema_version: Literal["rdc.webhook-destination/v1"] = "rdc.webhook-destination/v1"
    name: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    endpoint_url: str = Field(min_length=1, max_length=2048)
    event_types: list[str] = Field(min_length=1, max_length=16)
    signing_secret: SecretStr = Field(min_length=32, max_length=512)


class RotateWebhookSigningSecretRequest(StrictModel):
    expected_version: int = Field(ge=1)
    signing_secret: SecretStr = Field(min_length=32, max_length=512)


class DisableWebhookDestinationRequest(StrictModel):
    expected_version: int = Field(ge=1)


class VerifyWebhookDestinationRequest(StrictModel):
    expected_version: int = Field(ge=1)
    event_id: UUID


class WebhookDestinationSummary(StrictModel):
    model_config = ConfigDict(extra="forbid", from_attributes=True)
    id: UUID
    organization_id: UUID
    project_id: UUID
    name: str
    endpoint_url: str
    endpoint_origin: str
    event_types: list[str]
    status: Literal["PENDING_VERIFICATION", "ACTIVE", "DISABLED"]
    signing_secret_configured: bool
    signing_secret_version: int
    verified_at: datetime | None
    consecutive_failure_count: int
    failure_threshold: int
    disabled_reason: str | None
    created_by_user_id: UUID
    updated_by_user_id: UUID
    created_at: datetime
    updated_at: datetime
    version: int
