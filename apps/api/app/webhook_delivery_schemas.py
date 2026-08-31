from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ReplayWebhookDeliveryRequest(StrictModel):
    expected_version: int = Field(ge=1)


class WebhookDeliverySummary(StrictModel):
    id: UUID
    project_id: UUID
    destination_id: UUID
    event_id: UUID
    status: Literal[
        "PENDING", "CLAIMED", "RETRY_WAIT", "SUCCEEDED", "DEAD_LETTERED", "CANCELLED"
    ]
    attempt_count: int
    max_attempts: int
    replay_count: int
    available_at: datetime
    claim_expires_at: datetime | None
    last_error_code: str | None
    last_http_status: int | None
    completed_at: datetime | None
    last_replayed_at: datetime | None
    created_at: datetime
    updated_at: datetime
    version: int


class WebhookDeliveryTransitionSummary(StrictModel):
    sequence: int
    from_status: str | None
    to_status: str
    reason_code: str
    attempt_count: int
    created_at: datetime
