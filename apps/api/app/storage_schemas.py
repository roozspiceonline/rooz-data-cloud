from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

from .schemas import ORMModel

Sha256Digest = Annotated[
    str,
    StringConstraints(pattern=r"^[0-9a-f]{64}$", min_length=64, max_length=64),
]
StorageObjectKind = Literal["AGENT_SOURCE"]
StorageObjectStatus = Literal[
    "PENDING_UPLOAD",
    "QUARANTINED",
    "AVAILABLE",
    "REJECTED",
    "DELETED",
]
StorageScanStatus = Literal["PENDING", "PASSED", "FAILED", "NOT_REQUIRED"]
StorageGrantOperation = Literal["UPLOAD", "DOWNLOAD"]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CreateSourceUploadRequest(StrictModel):
    file_name: str = Field(min_length=1, max_length=255)
    media_type: Literal["application/zip", "application/x-zip-compressed"] = (
        "application/zip"
    )
    size_bytes: int = Field(ge=1, le=536_870_912)
    sha256_digest: Sha256Digest

    @field_validator("file_name")
    @classmethod
    def validate_file_name(cls, value: str) -> str:
        normalized = value.strip()
        if (
            not normalized
            or "\x00" in normalized
            or "/" in normalized
            or "\\" in normalized
            or not normalized.casefold().endswith(".zip")
        ):
            raise ValueError("Source upload file_name must be a ZIP base name.")
        return normalized


class StorageObjectSummary(ORMModel):
    id: UUID
    organization_id: UUID
    project_id: UUID
    agent_id: UUID | None
    kind: StorageObjectKind
    provider: str
    bucket: str
    object_key: str
    file_name: str
    media_type: str
    expected_size_bytes: int
    size_bytes: int | None
    expected_sha256_digest: str
    sha256_digest: str | None
    status: StorageObjectStatus
    scan_status: StorageScanStatus
    rejection_code: str | None
    created_at: datetime
    uploaded_at: datetime | None
    available_at: datetime | None


class PresignedUpload(StrictModel):
    url: str
    fields: dict[str, str]
    expires_at: datetime


class SourceUploadIntent(StrictModel):
    object: StorageObjectSummary
    upload: PresignedUpload


class StorageDownloadGrant(StrictModel):
    grant_id: UUID
    object_id: UUID
    url: str
    expires_at: datetime
    headers: dict[str, str] = Field(default_factory=dict)
