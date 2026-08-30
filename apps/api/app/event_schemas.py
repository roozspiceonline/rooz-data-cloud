from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class EventSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", from_attributes=True)

    id: UUID
    organization_id: UUID
    project_id: UUID
    event_type: str
    schema_version: str
    subject_type: str
    subject_id: UUID
    payload: dict[str, object]
    payload_digest: str
    emitter: str
    request_id: str
    occurred_at: datetime
    created_at: datetime
