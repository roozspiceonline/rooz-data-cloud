# ruff: noqa: E501
from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from .schemas import ORMModel


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CreateRequestQueueRequest(StrictModel):
    name: str = Field(default="default", min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class EnqueueRequest(StrictModel):
    schema_version: Literal["rdc.queue-enqueue/v1"]
    idempotency_key: str = Field(min_length=1, max_length=256)
    url: str = Field(min_length=1, max_length=2048)
    unique_key: str | None = Field(default=None, max_length=256)
    user_data: object = Field(default_factory=dict)


class RequestQueueSummary(ORMModel):
    id: UUID
    organization_id: UUID
    project_id: UUID
    name: str
    pending_count: int
    claimed_count: int
    handled_count: int
    failed_count: int
    created_by_user_id: UUID
    created_at: datetime
    updated_at: datetime
    version: int


class QueueRequestSummary(ORMModel):
    id: UUID
    queue_id: UUID
    request_url: str
    unique_key: str | None
    status: Literal["PENDING", "CLAIMED", "HANDLED", "FAILED"]
    attempt_count: int
    max_attempts: int
    available_at: datetime
    handled_at: datetime | None
    failure_code: str | None
    failure_summary: str | None
    created_at: datetime
    updated_at: datetime


class EnqueueReceiptSummary(StrictModel):
    id: UUID
    queue_id: UUID
    request_id: UUID
    idempotency_key: str
    request_digest: str
    replayed: bool
    created_at: datetime
