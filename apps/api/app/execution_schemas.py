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

WorkerCapability = Literal[
    "BUILD",
    "RUN_START",
    "RUN_CANCEL",
    "EVENT_INGEST",
    "SECRET_ENVELOPE",
    "DATASET_APPEND",
    "KV_ACCESS",
]
WorkKind = Literal["BUILD", "RUN_START", "RUN_CANCEL"]
LeaseStatus = Literal[
    "ACTIVE",
    "COMPLETED",
    "FAILED",
    "EXPIRED",
    "CANCELLED",
]
ArtifactKind = Literal[
    "CONTAINER_IMAGE",
    "SBOM",
    "PROVENANCE",
    "RUN_OUTPUT",
    "LOG_BUNDLE",
]
ArtifactStatus = Literal["AVAILABLE", "QUARANTINED", "REJECTED", "DELETED"]
ArtifactScanStatus = Literal["PENDING", "PASSED", "FAILED", "NOT_REQUIRED"]
SecretEnvironment = Literal["development", "test", "staging", "production"]

SecretName = Annotated[
    str,
    StringConstraints(
        pattern=r"^[A-Z][A-Z0-9_]{0,63}$",
        min_length=1,
        max_length=64,
    ),
]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SandboxActivation(StrictModel):
    mode: Literal["canary"] = "canary"
    agent_version_id: UUID
    worker_name: str = Field(
        min_length=3,
        max_length=160,
        pattern=r"^[a-z0-9][a-z0-9._-]+$",
    )
    attestation_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    sandbox_policy_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    constraints_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    no_secrets: Literal[True] = True
    capability_profile: Literal[
        "offline-minimal",
        "brokered-web-egress",
        "controlled-browser",
    ] = "offline-minimal"
    egress_policy_digest: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    browser_policy_digest: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    dataset_write_enabled: bool = False
    key_value_store_enabled: bool = False
    max_concurrency: Literal[1] = 1

    @model_validator(mode="after")
    def validate_capability_receipt(self) -> "SandboxActivation":
        if (
            self.capability_profile == "brokered-web-egress"
            and self.egress_policy_digest is None
        ):
            raise ValueError(
                "Brokered web egress requires an egress-policy digest."
            )
        if (
            self.capability_profile == "brokered-web-egress"
            and self.browser_policy_digest is not None
        ):
            raise ValueError(
                "Brokered web egress cannot carry a browser-policy digest."
            )
        if self.capability_profile == "controlled-browser":
            if self.egress_policy_digest is None:
                raise ValueError(
                    "Controlled browser requires an egress-policy digest."
                )
            if self.browser_policy_digest is None:
                raise ValueError(
                    "Controlled browser requires a browser-policy digest."
                )
        if self.capability_profile == "offline-minimal":
            if self.egress_policy_digest is not None:
                raise ValueError(
                    "Offline-minimal activation cannot carry an egress-policy digest."
                )
            if self.browser_policy_digest is not None:
                raise ValueError(
                    "Offline-minimal activation cannot carry a browser-policy digest."
                )
        return self


class SandboxAttestation(StrictModel):
    schema_version: Literal["rdc.sandbox/v1"] = "rdc.sandbox/v1"
    runtime: Literal["containerd-rootless"] = "containerd-rootless"
    builder: Literal["buildkit-rootless"] = "buildkit-rootless"
    rootless: Literal[True] = True
    no_host_docker_socket: Literal[True] = True
    no_new_privileges: Literal[True] = True
    read_only_rootfs: Literal[True] = True
    drop_all_capabilities: Literal[True] = True
    seccomp_profile: Literal["rdc-default"] = "rdc-default"
    apparmor_profile: str = Field(min_length=1, max_length=120)
    network_policy: Literal["deny-all"] = "deny-all"
    max_memory_mb: int = Field(ge=128, le=32768)
    max_cpu_millis: int = Field(ge=100, le=16000)
    max_pids: int = Field(ge=16, le=4096)
    max_ephemeral_disk_mb: int = Field(ge=64, le=102400)
    max_build_seconds: int = Field(ge=30, le=3600)
    max_run_seconds: int = Field(ge=1, le=86400)


class RegisterWorkerRequest(StrictModel):
    name: str = Field(min_length=3, max_length=160, pattern=r"^[a-z0-9][a-z0-9._-]+$")
    capabilities: list[WorkerCapability] = Field(min_length=1, max_length=7)
    max_concurrency: int = Field(ge=1, le=256)
    protocol_version: Literal["rdc.worker/v1"] = "rdc.worker/v1"
    software_version: str = Field(min_length=1, max_length=80)
    sandbox: SandboxAttestation | None = None
    metadata: dict[str, object] = Field(default_factory=dict)

    @field_validator("capabilities")
    @classmethod
    def unique_capabilities(
        cls, values: list[WorkerCapability]
    ) -> list[WorkerCapability]:
        if len(set(values)) != len(values):
            raise ValueError("Worker capabilities must be unique.")
        return values

    @field_validator("metadata")
    @classmethod
    def metadata_size(cls, value: dict[str, object]) -> dict[str, object]:
        encoded = json.dumps(value, allow_nan=False, separators=(",", ":")).encode()
        if len(encoded) > 16_384:
            raise ValueError("Worker metadata cannot exceed 16 KiB.")
        return value


class WorkerSummary(BaseModel):
    id: UUID
    name: str
    public_prefix: str
    last_four: str
    capabilities: list[str]
    max_concurrency: int
    status: str
    protocol_version: str
    software_version: str
    metadata: dict[str, object]
    sandbox_profile: str | None
    sandbox_attestation_digest: str | None
    sandbox_execution_enabled: bool
    sandbox_attested_at: datetime | None
    registered_at: datetime
    last_seen_at: datetime | None
    expires_at: datetime | None


class RegisteredWorkerResponse(BaseModel):
    worker: WorkerSummary
    token: str
    warning: str = "This worker token is shown only once."


class WorkerHeartbeatRequest(StrictModel):
    status: Literal["ACTIVE", "DRAINING"] = "ACTIVE"
    software_version: str = Field(min_length=1, max_length=80)
    active_lease_count: int = Field(ge=0, le=256)
    sandbox: SandboxAttestation | None = None
    metadata: dict[str, object] = Field(default_factory=dict)

    @field_validator("metadata")
    @classmethod
    def metadata_size(cls, value: dict[str, object]) -> dict[str, object]:
        encoded = json.dumps(value, allow_nan=False, separators=(",", ":")).encode()
        if len(encoded) > 16_384:
            raise ValueError("Worker metadata cannot exceed 16 KiB.")
        return value


class ClaimWorkRequest(StrictModel):
    kinds: list[WorkKind] = Field(min_length=1, max_length=3)

    @field_validator("kinds")
    @classmethod
    def unique_kinds(cls, values: list[WorkKind]) -> list[WorkKind]:
        if len(set(values)) != len(values):
            raise ValueError("Work kinds must be unique.")
        return values


class LeaseClaim(BaseModel):
    id: UUID
    work_kind: WorkKind
    organization_id: UUID
    project_id: UUID
    build_id: UUID | None
    run_id: UUID | None
    attempt: int
    claimed_at: datetime
    expires_at: datetime
    deadline_at: datetime
    lease_token: str
    payload: dict[str, object]


class RenewLeaseRequest(StrictModel):
    extend_seconds: int = Field(default=60, ge=15, le=300)


class LeaseStatusUpdateRequest(StrictModel):
    status: Literal["STARTING", "RUNNING", "ABORTING"]
    message: str | None = Field(default=None, max_length=1000)


class WorkerRunEvent(StrictModel):
    event_type: Literal[
        "run.log",
        "run.metric",
        "run.warning",
    ]
    payload: dict[str, object]


class AppendWorkerEventsRequest(StrictModel):
    events: list[WorkerRunEvent] = Field(min_length=1, max_length=100)


class ArtifactRegistration(StrictModel):
    kind: ArtifactKind
    digest_algorithm: Literal["sha256"] = "sha256"
    digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    object_key: str = Field(
        min_length=1,
        max_length=1024,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._/=-]*$",
    )
    media_type: str = Field(min_length=1, max_length=160)
    size_bytes: int = Field(ge=0, le=1_099_511_627_776)
    status: ArtifactStatus = "AVAILABLE"
    scan_status: ArtifactScanStatus = "PENDING"
    provenance: dict[str, object] = Field(default_factory=dict)

    @field_validator("provenance")
    @classmethod
    def provenance_size(cls, value: dict[str, object]) -> dict[str, object]:
        encoded = json.dumps(value, allow_nan=False, separators=(",", ":")).encode()
        if len(encoded) > 65_536:
            raise ValueError("Artifact provenance cannot exceed 64 KiB.")
        return value


class ArtifactUploadRequest(StrictModel):
    kind: ArtifactKind
    digest_algorithm: Literal["sha256"] = "sha256"
    digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    media_type: str = Field(min_length=1, max_length=160)
    size_bytes: int = Field(ge=1, le=68_719_476_736)


class ArtifactUploadIntent(BaseModel):
    object_key: str
    url: str
    headers: dict[str, str]
    expires_at: datetime


class ArtifactDownloadGrant(BaseModel):
    artifact_id: UUID
    url: str
    expires_at: datetime
    digest_algorithm: str
    digest: str
    media_type: str
    size_bytes: int
    provenance: dict[str, object]


class CompleteLeaseRequest(StrictModel):
    outcome: Literal["SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED", "CANCELLED"]
    retryable: bool = False
    error_code: str | None = Field(
        default=None,
        max_length=80,
        pattern=r"^[A-Z][A-Z0-9_]*$",
    )
    error_summary: str | None = Field(default=None, max_length=2000)
    artifact: ArtifactRegistration | None = None
    artifacts: list[ArtifactRegistration] = Field(default_factory=list, max_length=4)

    @model_validator(mode="after")
    def validate_artifacts(self) -> "CompleteLeaseRequest":
        if self.artifact is not None and self.artifacts:
            raise ValueError("Use artifact or artifacts, not both.")
        values = [self.artifact] if self.artifact is not None else self.artifacts
        identities = [(item.kind, item.digest) for item in values if item is not None]
        if len(set(identities)) != len(identities):
            raise ValueError("Execution artifacts must be unique by kind and digest.")
        return self


class SecretEnvelopeRequest(StrictModel):
    names: list[SecretName] = Field(min_length=1, max_length=64)
    environment: SecretEnvironment
    worker_public_key_b64: str = Field(min_length=40, max_length=100)

    @field_validator("names")
    @classmethod
    def unique_names(cls, values: list[str]) -> list[str]:
        if len(set(values)) != len(values):
            raise ValueError("Secret names must be unique.")
        return sorted(values)


class SecretEnvelopeResponse(BaseModel):
    grant_id: UUID
    algorithm: str
    ephemeral_public_key_b64: str
    nonce_b64: str
    ciphertext_b64: str
    expires_at: datetime
    secret_names: list[str]
    environment: SecretEnvironment


class ExecutionLeaseSummary(BaseModel):
    id: UUID
    worker_id: UUID
    organization_id: UUID
    project_id: UUID
    work_kind: WorkKind
    build_id: UUID | None
    run_id: UUID | None
    status: LeaseStatus
    attempt: int
    claimed_at: datetime
    expires_at: datetime
    deadline_at: datetime
    completed_at: datetime | None
    failure_code: str | None
    failure_summary: str | None


class ExecutionArtifactSummary(BaseModel):
    id: UUID
    organization_id: UUID
    project_id: UUID
    build_id: UUID | None
    run_id: UUID | None
    lease_id: UUID
    kind: ArtifactKind
    digest_algorithm: str
    digest: str
    object_key: str
    media_type: str
    size_bytes: int
    status: ArtifactStatus
    scan_status: ArtifactScanStatus
    provenance: dict[str, object]
    created_at: datetime
