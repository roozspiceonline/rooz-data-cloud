from datetime import datetime
from typing import Literal, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .dataset_append_protocol import (
    DatasetAppendProtocolError,
    validate_dataset_append,
)
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


class DatasetAppendRequest(StrictModel):
    schema_version: Literal["rdc.dataset-append/v1"]
    idempotency_key: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",
    )
    items: list[dict[str, object]] = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def validate_protocol(self) -> Self:
        try:
            validate_dataset_append(self.model_dump(mode="python"))
        except DatasetAppendProtocolError as exc:
            raise ValueError(str(exc)) from exc
        return self


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


class DatasetAppendReceiptSummary(ORMModel):
    id: UUID
    organization_id: UUID
    project_id: UUID
    dataset_id: UUID
    run_id: UUID
    schema_version: str
    idempotency_key: str
    request_digest: str
    first_sequence: int
    item_count: int
    total_bytes: int
    created_by_user_id: UUID
    created_at: datetime


class DatasetAppendResult(StrictModel):
    receipt: DatasetAppendReceiptSummary
    replayed: bool
