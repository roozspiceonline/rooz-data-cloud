from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .run_schemas import CreateRunRequest
from .schemas import ORMModel


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CreateScheduleRequest(StrictModel):
    schema_version: Literal["rdc.schedule/v1"] = "rdc.schedule/v1"
    name: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$",
    )
    cadence_kind: Literal["ONCE", "INTERVAL"]
    starts_at: datetime
    interval_seconds: int | None = Field(default=None, ge=60, le=31_536_000)
    missed_run_policy: Literal["SKIP", "FIRE_ONCE"] = "SKIP"
    misfire_grace_seconds: int = Field(default=300, ge=60, le=86_400)
    run: CreateRunRequest

    @field_validator("starts_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Schedule starts_at must include a timezone offset.")
        return value

    @model_validator(mode="after")
    def validate_cadence(self) -> "CreateScheduleRequest":
        if self.cadence_kind == "ONCE" and self.interval_seconds is not None:
            raise ValueError("One-time schedules cannot include interval_seconds.")
        if self.cadence_kind == "INTERVAL" and self.interval_seconds is None:
            raise ValueError("Recurring schedules require interval_seconds.")
        return self


class ScheduleSummary(ORMModel):
    id: UUID
    organization_id: UUID
    project_id: UUID
    agent_id: UUID
    agent_version_id: UUID
    build_id: UUID
    name: str
    status: Literal["ACTIVE", "PAUSED", "COMPLETED"]
    cadence_kind: Literal["ONCE", "INTERVAL"]
    starts_at: datetime
    interval_seconds: int | None
    missed_run_policy: Literal["SKIP", "FIRE_ONCE"]
    misfire_grace_seconds: int
    next_fire_at: datetime | None
    last_triggered_at: datetime | None
    fired_count: int
    skipped_count: int
    failed_count: int
    created_by_user_id: UUID
    created_at: datetime
    updated_at: datetime
    version: int


class ScheduleTriggerSummary(ORMModel):
    id: UUID
    schedule_id: UUID
    run_id: UUID | None
    scheduled_for: datetime
    observed_at: datetime
    outcome: Literal["FIRED", "SKIPPED", "FAILED"]
    reason: str
    error_code: str | None
    created_at: datetime
