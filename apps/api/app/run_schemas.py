import json
from datetime import datetime
from typing import Literal
from urllib.parse import urlsplit
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from .schemas import ORMModel

RunStatus = Literal[
    "DRAFT",
    "READY",
    "QUEUED",
    "STARTING",
    "RUNNING",
    "PAUSING",
    "PAUSED",
    "SUCCEEDED",
    "PARTIALLY_SUCCEEDED",
    "FAILED",
    "TIMING_OUT",
    "TIMED_OUT",
    "ABORTING",
    "ABORTED",
]

RunEventType = Literal[
    "run.status",
    "run.log",
    "run.metric",
    "run.warning",
    "run.completed",
    "run.failed",
]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class WebFetchRequestInput(StrictModel):
    id: str = Field(
        min_length=1,
        max_length=64,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$",
    )
    method: Literal["GET", "HEAD"]
    url: str = Field(min_length=9, max_length=8192)

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        if not value.startswith("https://"):
            raise ValueError("Web-fetch URLs must use lowercase https://.")
        try:
            parsed = urlsplit(value)
        except ValueError as exc:
            raise ValueError("Web-fetch URL is malformed.") from exc
        if not parsed.hostname:
            raise ValueError("Web-fetch URL requires a hostname.")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("Web-fetch URL credentials are not allowed.")
        return value


class WebFetchEnvelopeInput(StrictModel):
    schema_version: Literal["rdc.web-fetch/v1"] = "rdc.web-fetch/v1"
    requests: list[WebFetchRequestInput] = Field(min_length=1, max_length=32)

    @model_validator(mode="after")
    def validate_envelope(self) -> "WebFetchEnvelopeInput":
        request_ids = [request.id for request in self.requests]
        if len(request_ids) != len(set(request_ids)):
            raise ValueError("Web-fetch request ids must be unique.")
        encoded = json.dumps(
            self.model_dump(mode="json"),
            allow_nan=False,
            separators=(",", ":"),
        ).encode()
        if len(encoded) > 65_536:
            raise ValueError("Web-fetch envelope cannot exceed 64 KiB.")
        return self


class RuntimeConfigurationInput(StrictModel):
    memory_mb: int | None = Field(default=None, ge=128, le=32768)
    cpu_millis: int | None = Field(default=None, ge=100, le=16000)
    timeout_seconds: int | None = Field(default=None, ge=1, le=86400)


class CreateRunRequest(StrictModel):
    build_id: UUID
    input: dict[str, object] = Field(default_factory=dict)
    web_fetch: WebFetchEnvelopeInput | None = None
    runtime: RuntimeConfigurationInput = Field(
        default_factory=RuntimeConfigurationInput
    )

    @model_validator(mode="after")
    def enforce_input_size(self) -> "CreateRunRequest":
        try:
            encoded = json.dumps(
                self.input,
                allow_nan=False,
                separators=(",", ":"),
            ).encode()
        except (TypeError, ValueError) as exc:
            raise ValueError("Run input must contain valid JSON values.") from exc
        if len(encoded) > 65_536:
            raise ValueError("Inline Run input cannot exceed 64 KiB.")
        return self


class RunSummary(ORMModel):
    id: UUID
    organization_id: UUID
    project_id: UUID
    agent_id: UUID
    agent_version_id: UUID
    build_id: UUID
    status: RunStatus
    input_reference: dict[str, object]
    runtime_configuration: dict[str, object]
    memory_mb: int
    cpu_millis: int
    timeout_seconds: int
    queued_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    cancel_requested_at: datetime | None
    failure_code: str | None
    failure_summary: str | None
    created_at: datetime
    updated_at: datetime
    version: int
    status_url: str
    events_url: str
    cancel_url: str


class RunEventSummary(ORMModel):
    id: UUID
    run_id: UUID
    sequence: int
    event_type: RunEventType
    timestamp: datetime
    payload: dict[str, object]
