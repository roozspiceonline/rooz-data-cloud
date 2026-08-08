from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from .schemas import ORMModel


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CreateDatasetRequest(StrictModel):
    name: str = Field(
        default="default",
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$",
    )


class DatasetSummary(ORMModel):
    id: UUID
    organization_id: UUID
    project_id: UUID
    run_id: UUID
    agent_id: UUID
    agent_version_id: UUID
    name: str
    item_count: int
    total_bytes: int
    next_sequence: int
    created_by_user_id: UUID
    created_at: datetime
    updated_at: datetime
    version: int
