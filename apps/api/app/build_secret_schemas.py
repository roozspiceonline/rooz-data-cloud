from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

from .schemas import ORMModel

SecretName = Annotated[
    str,
    StringConstraints(
        pattern=r"^[A-Z][A-Z0-9_]{0,63}$",
        min_length=1,
        max_length=64,
    ),
]
SecretEnvironment = Literal["development", "test", "staging", "production"]
BuildStatus = Literal[
    "QUEUED",
    "STARTING",
    "RUNNING",
    "SUCCEEDED",
    "FAILED",
    "CANCELLED",
    "TIMED_OUT",
]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CreateProjectSecretRequest(StrictModel):
    name: SecretName
    value: str = Field(min_length=1, max_length=16384)
    description: str | None = Field(default=None, max_length=1000)
    environment: SecretEnvironment = "production"

    @field_validator("value")
    @classmethod
    def reject_nul(cls, value: str) -> str:
        if "\x00" in value:
            raise ValueError("Secret values cannot contain NUL characters.")
        return value


class ReplaceProjectSecretRequest(StrictModel):
    value: str = Field(min_length=1, max_length=16384)
    description: str | None = Field(default=None, max_length=1000)
    environment: SecretEnvironment | None = None

    @field_validator("value")
    @classmethod
    def reject_nul(cls, value: str) -> str:
        if "\x00" in value:
            raise ValueError("Secret values cannot contain NUL characters.")
        return value


class ProjectSecretSummary(ORMModel):
    id: UUID
    project_id: UUID
    name: str
    description: str | None
    environment: SecretEnvironment
    has_value: bool = True
    created_at: datetime
    updated_at: datetime
    last_used_at: datetime | None
    version: int
    etag: str


class BuildSummary(ORMModel):
    id: UUID
    organization_id: UUID
    project_id: UUID
    agent_id: UUID
    agent_version_id: UUID
    manifest_digest: str
    status: BuildStatus
    created_at: datetime
    updated_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    artifact_digest: str | None
    error_code: str | None
    error_message: str | None
    status_url: str
