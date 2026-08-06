import json
from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from .schemas import ORMModel

AgentSlug = Annotated[
    str,
    StringConstraints(
        pattern=r"^[a-z0-9](?:[a-z0-9-]{0,78}[a-z0-9])?$",
        min_length=1,
        max_length=80,
    ),
]
ManifestName = Annotated[
    str,
    StringConstraints(
        pattern=r"^[a-z][a-z0-9-]{2,62}$",
        min_length=3,
        max_length=63,
    ),
]
SemanticVersion = Annotated[
    str,
    StringConstraints(
        pattern=(
            r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\."
            r"(0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?"
            r"(?:\+[0-9A-Za-z.-]+)?$"
        ),
        max_length=80,
    ),
]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


def normalize_agent_name(value: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise ValueError("Agent name cannot be blank.")
    return normalized


def normalize_optional_text(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip()
    return normalized or None


class CreateAgentRequest(StrictModel):
    name: str = Field(min_length=1, max_length=160)
    slug: AgentSlug
    description: str | None = Field(default=None, max_length=4000)

    @field_validator("name")
    @classmethod
    def normalize_name(cls, value: str) -> str:
        return normalize_agent_name(value)

    @field_validator("description")
    @classmethod
    def normalize_description(cls, value: str | None) -> str | None:
        return normalize_optional_text(value)


class UpdateAgentRequest(StrictModel):
    name: str | None = Field(default=None, min_length=1, max_length=160)
    slug: AgentSlug | None = None
    description: str | None = Field(default=None, max_length=4000)
    status: Literal["ACTIVE", "ARCHIVED"] | None = None

    @field_validator("name")
    @classmethod
    def normalize_name(cls, value: str | None) -> str | None:
        return normalize_agent_name(value) if value is not None else None

    @field_validator("description")
    @classmethod
    def normalize_description(cls, value: str | None) -> str | None:
        return normalize_optional_text(value)

    @model_validator(mode="after")
    def require_change(self) -> "UpdateAgentRequest":
        if not self.model_fields_set:
            raise ValueError("At least one Agent field must be supplied.")
        return self


class ManifestRuntime(StrictModel):
    kind: Literal["container"] = "container"
    entrypoint: list[str] = Field(min_length=1, max_length=64)

    @field_validator("entrypoint")
    @classmethod
    def validate_entrypoint(cls, values: list[str]) -> list[str]:
        for value in values:
            if not value or len(value) > 4096:
                raise ValueError(
                    "Each runtime entrypoint value must contain 1 to 4096 characters."
                )
        return values


class ManifestSchemas(StrictModel):
    input: str
    output: str
    dataset: str | None = None

    @field_validator("input", "output", "dataset")
    @classmethod
    def validate_relative_path(cls, value: str | None) -> str | None:
        if value is None:
            return value
        if not value or len(value) > 255 or value.startswith("/"):
            raise ValueError("Schema paths must be relative paths.")
        if ".." in value.split("/"):
            raise ValueError("Schema paths cannot contain parent traversal.")
        return value


class ManifestCapabilities(StrictModel):
    network: Literal["none", "web-egress"]
    browser: bool
    dataset: bool
    key_value_store: bool = Field(alias="keyValueStore")
    request_queue: bool = Field(alias="requestQueue")


class ManifestResources(StrictModel):
    memory_mb: int = Field(alias="memoryMb", ge=128, le=32768)
    cpu_units: int = Field(alias="cpuUnits", ge=100, le=16000)
    timeout_seconds: int = Field(alias="timeoutSeconds", ge=1, le=86400)
    max_processes: int = Field(alias="maxProcesses", ge=1, le=4096)
    ephemeral_disk_mb: int = Field(
        alias="ephemeralDiskMb",
        ge=64,
        le=102400,
    )


class AgentManifest(StrictModel):
    protocol: Literal["rooz.agent/v1"]
    name: ManifestName
    version: SemanticVersion
    runtime: ManifestRuntime
    schemas: ManifestSchemas
    capabilities: ManifestCapabilities
    resources: ManifestResources
    extensions: dict[str, object] = Field(default_factory=dict)

    @model_validator(mode="after")
    def enforce_serialized_size(self) -> "AgentManifest":
        try:
            encoded = json.dumps(
                self.model_dump(mode="json", by_alias=True),
                allow_nan=False,
                separators=(",", ":"),
            ).encode()
        except ValueError as exc:
            raise ValueError("Manifest values must be valid JSON.") from exc
        if len(encoded) > 262_144:
            raise ValueError("The Agent manifest cannot exceed 256 KiB.")
        return self


class CreateAgentVersionRequest(StrictModel):
    manifest: AgentManifest
    release_notes: str | None = Field(default=None, max_length=8000)


class AgentSummary(ORMModel):
    id: UUID
    organization_id: UUID
    project_id: UUID
    name: str
    slug: str
    description: str | None
    status: str
    created_at: datetime
    updated_at: datetime
    version: int


class AgentVersionSummary(ORMModel):
    id: UUID
    organization_id: UUID
    project_id: UUID
    agent_id: UUID
    version_number: int
    protocol: str
    semantic_version: str
    manifest_schema_version: str
    manifest_digest: str
    release_notes: str | None
    created_at: datetime


class AgentVersionDetail(AgentVersionSummary):
    manifest: dict[str, object]
