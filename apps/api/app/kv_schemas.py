from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from .schemas import ORMModel


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CreateKeyValueStoreRequest(StrictModel):
    name: str = Field(
        default="default",
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$",
    )


class KeyValueStoreSummary(ORMModel):
    id: UUID
    organization_id: UUID
    project_id: UUID
    scope: Literal["PROJECT", "RUN"]
    run_id: UUID | None
    agent_id: UUID | None
    agent_version_id: UUID | None
    name: str
    record_count: int
    total_bytes: int
    created_by_user_id: UUID
    created_at: datetime
    updated_at: datetime
    version: int
