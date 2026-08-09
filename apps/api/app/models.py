# ruff: noqa: E501
from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    MetaData,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


class UUIDPrimaryKeyMixin:
    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )


class User(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "users"
    __table_args__ = {"schema": "identity"}

    email_normalized: Mapped[str] = mapped_column(
        String(320),
        nullable=False,
        unique=True,
    )
    email_display: Mapped[str] = mapped_column(String(320), nullable=False)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    password_algorithm: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="argon2id",
    )
    display_name: Mapped[str] = mapped_column(String(160), nullable=False)
    email_verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="ACTIVE",
    )
    failed_login_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )
    locked_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    password_changed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    deactivated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    version: Mapped[int] = mapped_column(BigInteger, nullable=False, default=1)


class Session(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "sessions"
    __table_args__ = {"schema": "identity"}

    user_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("identity.users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    token_digest: Mapped[bytes] = mapped_column(
        LargeBinary(32),
        nullable=False,
        unique=True,
    )
    csrf_token_digest: Mapped[bytes] = mapped_column(
        LargeBinary(32),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    idle_expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    absolute_expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoke_reason: Mapped[str | None] = mapped_column(String(100))
    user_agent_hash: Mapped[str | None] = mapped_column(String(64))
    ip_prefix_hash: Mapped[str | None] = mapped_column(String(64))
    version: Mapped[int] = mapped_column(BigInteger, nullable=False, default=1)


class Organization(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "organizations"
    __table_args__ = {"schema": "identity"}

    name: Mapped[str] = mapped_column(String(160), nullable=False)
    slug: Mapped[str] = mapped_column(
        String(80),
        nullable=False,
        unique=True,
    )
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="ACTIVE",
    )
    created_by_user_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("identity.users.id"),
        nullable=False,
    )
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    version: Mapped[int] = mapped_column(BigInteger, nullable=False, default=1)


class OrganizationMembership(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "organization_memberships"
    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "user_id",
            name="uq_organization_memberships_organization_user",
        ),
        {"schema": "identity"},
    )

    organization_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("identity.organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    user_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("identity.users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    role: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="ACTIVE",
    )
    joined_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    created_by_user_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("identity.users.id"),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    version: Mapped[int] = mapped_column(BigInteger, nullable=False, default=1)


class Project(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "projects"
    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "slug",
            name="uq_projects_organization_slug",
        ),
        {"schema": "control"},
    )

    organization_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("identity.organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    slug: Mapped[str] = mapped_column(String(80), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="ACTIVE",
    )
    created_by_user_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("identity.users.id"),
        nullable=False,
    )
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    max_active_leases: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=20,
    )
    version: Mapped[int] = mapped_column(BigInteger, nullable=False, default=1)


class Agent(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "agents"
    __table_args__ = (
        UniqueConstraint(
            "project_id",
            "slug",
            name="uq_agents_project_slug",
        ),
        {"schema": "control"},
    )

    organization_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("identity.organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    project_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("control.projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    slug: Mapped[str] = mapped_column(String(80), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="ACTIVE",
    )
    created_by_user_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("identity.users.id"),
        nullable=False,
    )
    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    version: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
        default=1,
    )


class StorageObject(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "storage_objects"
    __table_args__ = (
        UniqueConstraint(
            "bucket",
            "object_key",
            name="uq_storage_objects_bucket_key",
        ),
        {"schema": "control"},
    )

    organization_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("identity.organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    project_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("control.projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    agent_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("control.agents.id", ondelete="CASCADE"),
        index=True,
    )
    kind: Mapped[str] = mapped_column(String(40), nullable=False)
    provider: Mapped[str] = mapped_column(
        String(24), nullable=False, default="S3"
    )
    bucket: Mapped[str] = mapped_column(String(160), nullable=False)
    object_key: Mapped[str] = mapped_column(String(1024), nullable=False)
    file_name: Mapped[str] = mapped_column(String(255), nullable=False)
    media_type: Mapped[str] = mapped_column(String(160), nullable=False)
    expected_size_bytes: Mapped[int] = mapped_column(
        BigInteger, nullable=False
    )
    size_bytes: Mapped[int | None] = mapped_column(BigInteger)
    expected_sha256_digest: Mapped[str] = mapped_column(
        String(64), nullable=False
    )
    sha256_digest: Mapped[str | None] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(
        String(24), nullable=False, default="PENDING_UPLOAD"
    )
    scan_status: Mapped[str] = mapped_column(
        String(24), nullable=False, default="PENDING"
    )
    rejection_code: Mapped[str | None] = mapped_column(String(80))
    metadata_json: Mapped[dict[str, object]] = mapped_column(
        JSONB, nullable=False, default=dict
    )
    created_by_user_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("identity.users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    uploaded_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    available_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    rejected_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )


class AgentVersion(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "agent_versions"
    __table_args__ = (
        UniqueConstraint(
            "agent_id",
            "version_number",
            name="uq_agent_versions_agent_number",
        ),
        UniqueConstraint(
            "agent_id",
            "semantic_version",
            name="uq_agent_versions_agent_semver",
        ),
        {"schema": "control"},
    )

    organization_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("identity.organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    project_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("control.projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    agent_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("control.agents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    version_number: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(40), nullable=False)
    semantic_version: Mapped[str] = mapped_column(String(80), nullable=False)
    manifest_schema_version: Mapped[str] = mapped_column(
        String(40),
        nullable=False,
    )
    manifest_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    manifest: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False)
    source_object_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("control.storage_objects.id", ondelete="RESTRICT"),
        nullable=True,
        unique=True,
        index=True,
    )
    release_notes: Mapped[str | None] = mapped_column(Text)
    created_by_user_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("identity.users.id"),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )


class ProjectSecret(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "project_secrets"
    __table_args__ = (
        UniqueConstraint(
            "project_id",
            "name",
            name="uq_project_secrets_project_name",
        ),
        {"schema": "security"},
    )

    organization_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("identity.organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    project_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("control.projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(64), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    environment: Mapped[str] = mapped_column(String(24), nullable=False)
    encrypted_value: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    value_nonce: Mapped[bytes] = mapped_column(LargeBinary(12), nullable=False)
    wrapped_data_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    key_nonce: Mapped[bytes] = mapped_column(LargeBinary(12), nullable=False)
    encryption_algorithm: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="AES-256-GCM",
    )
    master_key_version: Mapped[str] = mapped_column(
        String(40),
        nullable=False,
    )
    last_used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    created_by_user_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("identity.users.id"),
        nullable=False,
    )
    updated_by_user_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("identity.users.id"),
        nullable=False,
    )
    version: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
        default=1,
    )


class Build(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "builds"
    __table_args__ = {"schema": "control"}

    organization_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("identity.organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    project_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("control.projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    agent_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("control.agents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    agent_version_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("control.agent_versions.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    manifest_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    source_object_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("control.storage_objects.id", ondelete="RESTRICT"),
        nullable=True,
        index=True,
    )
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="QUEUED",
    )
    requested_by_user_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("identity.users.id"),
        nullable=False,
    )
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    artifact_digest: Mapped[str | None] = mapped_column(String(120))
    error_code: Mapped[str | None] = mapped_column(String(80))
    error_message: Mapped[str | None] = mapped_column(Text)
    version: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
        default=1,
    )


class BuildDispatchOutbox(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "build_dispatch_outbox"
    __table_args__ = (
        UniqueConstraint(
            "build_id",
            name="uq_build_dispatch_outbox_build",
        ),
        {"schema": "control"},
    )

    organization_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("identity.organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    project_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("control.projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    build_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("control.builds.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    topic: Mapped[str] = mapped_column(
        String(120),
        nullable=False,
        default="rdc.build.requested.v1",
    )
    payload: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False)
    status: Mapped[str] = mapped_column(
        String(24),
        nullable=False,
        default="PENDING",
    )
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    available_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    claimed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    delivered_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    last_error_code: Mapped[str | None] = mapped_column(String(80))


class Run(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "runs"
    __table_args__ = {"schema": "control"}

    organization_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("identity.organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    project_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("control.projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    agent_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("control.agents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    agent_version_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("control.agent_versions.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    build_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("control.builds.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="QUEUED",
    )
    input_reference: Mapped[dict[str, object]] = mapped_column(
        JSONB,
        nullable=False,
    )
    runtime_configuration: Mapped[dict[str, object]] = mapped_column(
        JSONB,
        nullable=False,
    )
    memory_mb: Mapped[int] = mapped_column(Integer, nullable=False)
    cpu_millis: Mapped[int] = mapped_column(Integer, nullable=False)
    timeout_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    requested_by_user_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("identity.users.id"),
        nullable=False,
    )
    queued_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    cancel_requested_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    cancel_deadline_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    failure_code: Mapped[str | None] = mapped_column(String(80))
    failure_summary: Mapped[str | None] = mapped_column(Text)
    version: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
        default=1,
    )


class KeyValueStore(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "key_value_stores"
    __table_args__ = {"schema": "control"}

    organization_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("identity.organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    project_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("control.projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    scope: Mapped[str] = mapped_column(String(16), nullable=False)
    run_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("control.runs.id", ondelete="CASCADE"),
        index=True,
    )
    agent_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("control.agents.id", ondelete="CASCADE"),
        index=True,
    )
    agent_version_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("control.agent_versions.id", ondelete="RESTRICT"),
        index=True,
    )
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    record_count: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0
    )
    total_bytes: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0
    )
    created_by_user_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("identity.users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    version: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=1
    )


class RequestQueue(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "request_queues"
    __table_args__ = (UniqueConstraint("project_id", "name", name="uq_request_queues_project_name"), {"schema": "control"})
    organization_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("identity.organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    project_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("control.projects.id", ondelete="CASCADE"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    pending_count: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    claimed_count: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    handled_count: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    failed_count: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    created_by_user_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("identity.users.id", ondelete="RESTRICT"), nullable=False)
    version: Mapped[int] = mapped_column(BigInteger, nullable=False, default=1)


class RequestQueueRequest(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "request_queue_requests"
    __table_args__ = (UniqueConstraint("queue_id", "identity_digest", name="uq_request_queue_requests_identity"), {"schema": "control"})
    organization_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    project_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    queue_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("control.request_queues.id", ondelete="CASCADE"), nullable=False, index=True)
    request_url: Mapped[str] = mapped_column(Text, nullable=False)
    unique_key: Mapped[str | None] = mapped_column(String(256))
    identity_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    user_data: Mapped[object] = mapped_column(JSONB, nullable=False, default=dict)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="PENDING")
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    available_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    claimed_by: Mapped[str | None] = mapped_column(String(128))
    claim_token: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True))
    claim_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    handled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    failure_code: Mapped[str | None] = mapped_column(String(80))
    failure_summary: Mapped[str | None] = mapped_column(Text)
    created_by_user_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("identity.users.id", ondelete="RESTRICT"), nullable=False)
    version: Mapped[int] = mapped_column(BigInteger, nullable=False, default=1)


class RequestQueueTransition(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "request_queue_transitions"
    __table_args__ = {"schema": "control"}
    organization_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    project_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    queue_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("control.request_queues.id", ondelete="RESTRICT"), nullable=False, index=True)
    request_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("control.request_queue_requests.id", ondelete="RESTRICT"), nullable=False, index=True)
    from_status: Mapped[str | None] = mapped_column(String(16))
    to_status: Mapped[str] = mapped_column(String(16), nullable=False)
    reason: Mapped[str] = mapped_column(String(80), nullable=False)
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False)
    details: Mapped[object] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class RequestQueueEnqueueReceipt(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "request_queue_enqueue_receipts"
    __table_args__ = (UniqueConstraint("queue_id", "idempotency_key", name="uq_request_queue_enqueue_idempotency"), {"schema": "control"})
    organization_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    project_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    queue_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("control.request_queues.id", ondelete="CASCADE"), nullable=False, index=True)
    request_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("control.request_queue_requests.id", ondelete="CASCADE"), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(256), nullable=False)
    request_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    identity_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    created_by_user_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("identity.users.id", ondelete="RESTRICT"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class KeyValueRecord(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "key_value_records"
    __table_args__ = (
        UniqueConstraint(
            "store_id",
            "key",
            name="uq_key_value_records_store_key",
        ),
        {"schema": "control"},
    )

    organization_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("identity.organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    project_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("control.projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    store_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("control.key_value_stores.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    key: Mapped[str] = mapped_column(String(256), nullable=False)
    current_version: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
        default=1,
    )
    deleted: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
    )
    current_size_bytes: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
        default=0,
    )
    created_by_user_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("identity.users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    version: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
        default=1,
    )


class KeyValueRecordVersion(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "key_value_record_versions"
    __table_args__ = (
        UniqueConstraint(
            "record_id",
            "version",
            name="uq_key_value_record_versions_record_version",
        ),
        UniqueConstraint(
            "object_key",
            name="uq_key_value_record_versions_object_key",
        ),
        {"schema": "control"},
    )

    organization_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("identity.organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    project_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("control.projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    store_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("control.key_value_stores.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    record_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("control.key_value_records.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    version: Mapped[int] = mapped_column(BigInteger, nullable=False)
    operation: Mapped[str] = mapped_column(String(8), nullable=False)
    tombstone: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
    )
    content_type: Mapped[str | None] = mapped_column(String(160))
    encoding: Mapped[str | None] = mapped_column(String(16))
    object_key: Mapped[str | None] = mapped_column(String(1024))
    value_sha256: Mapped[str | None] = mapped_column(String(64))
    size_bytes: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
        default=0,
    )
    created_by_user_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("identity.users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )


class KeyValueMutationReceipt(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "key_value_mutation_receipts"
    __table_args__ = (
        UniqueConstraint(
            "store_id",
            "idempotency_key",
            name="uq_key_value_mutation_receipts_store_key",
        ),
        UniqueConstraint(
            "record_version_id",
            name="uq_key_value_mutation_receipts_record_version",
        ),
        {"schema": "control"},
    )

    organization_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("identity.organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    project_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("control.projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    store_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("control.key_value_stores.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    record_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("control.key_value_records.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    record_version_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey(
            "control.key_value_record_versions.id",
            ondelete="RESTRICT",
        ),
        nullable=False,
        index=True,
    )
    schema_version: Mapped[str] = mapped_column(
        String(40),
        nullable=False,
        default="rdc.kv-write/v1",
    )
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    request_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    operation: Mapped[str] = mapped_column(String(8), nullable=False)
    key: Mapped[str] = mapped_column(String(256), nullable=False)
    expected_version: Mapped[int | None] = mapped_column(BigInteger)
    result_version: Mapped[int] = mapped_column(BigInteger, nullable=False)
    value_sha256: Mapped[str | None] = mapped_column(String(64))
    size_bytes: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
        default=0,
    )
    created_by_user_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("identity.users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )


class Dataset(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "datasets"
    __table_args__ = (
        UniqueConstraint(
            "run_id",
            "name",
            name="uq_datasets_run_name",
        ),
        {"schema": "control"},
    )

    organization_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("identity.organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    project_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("control.projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    run_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("control.runs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    agent_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("control.agents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    agent_version_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("control.agent_versions.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        default="default",
    )
    item_count: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
        default=0,
    )
    total_bytes: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
        default=0,
    )
    next_sequence: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
        default=1,
    )
    created_by_user_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("identity.users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    version: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False,
        default=1,
    )


class DatasetAppendReceipt(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "dataset_append_receipts"
    __table_args__ = (
        UniqueConstraint(
            "dataset_id",
            "idempotency_key",
            name="uq_dataset_append_receipts_dataset_key",
        ),
        {"schema": "control"},
    )

    organization_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("identity.organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    project_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("control.projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    dataset_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("control.datasets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    run_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("control.runs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    schema_version: Mapped[str] = mapped_column(
        String(40),
        nullable=False,
        default="rdc.dataset-append/v1",
    )
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    request_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    first_sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)
    item_count: Mapped[int] = mapped_column(Integer, nullable=False)
    total_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    created_by_user_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("identity.users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )


class DatasetItem(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "dataset_items"
    __table_args__ = (
        UniqueConstraint(
            "dataset_id",
            "sequence",
            name="uq_dataset_items_dataset_sequence",
        ),
        {"schema": "control"},
    )

    organization_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("identity.organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    project_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("control.projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    dataset_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("control.datasets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    append_receipt_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey(
            "control.dataset_append_receipts.id",
            ondelete="RESTRICT",
        ),
        nullable=False,
        index=True,
    )
    run_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("control.runs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)
    item_json: Mapped[dict[str, object]] = mapped_column(
        JSONB,
        nullable=False,
    )
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    sha256_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )


class RunEvent(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "run_events"
    __table_args__ = (
        UniqueConstraint(
            "run_id",
            "sequence",
            name="uq_run_events_run_sequence",
        ),
        {"schema": "control"},
    )

    organization_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("identity.organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    project_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("control.projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    run_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("control.runs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)
    event_type: Mapped[str] = mapped_column(String(40), nullable=False)
    payload: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )


class RunCommandOutbox(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "run_command_outbox"
    __table_args__ = (
        UniqueConstraint(
            "run_id",
            "command",
            name="uq_run_command_outbox_run_command",
        ),
        {"schema": "control"},
    )

    organization_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("identity.organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    project_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("control.projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    run_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("control.runs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    command: Mapped[str] = mapped_column(String(24), nullable=False)
    topic: Mapped[str] = mapped_column(String(120), nullable=False)
    payload: Mapped[dict[str, object]] = mapped_column(JSONB, nullable=False)
    status: Mapped[str] = mapped_column(
        String(24),
        nullable=False,
        default="PENDING",
    )
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    available_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    claimed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    delivered_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    last_error_code: Mapped[str | None] = mapped_column(String(80))


class ApiKey(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "api_keys"
    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "public_prefix",
            name="uq_api_keys_organization_prefix",
        ),
        {"schema": "security"},
    )

    organization_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("identity.organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    public_prefix: Mapped[str] = mapped_column(String(24), nullable=False)
    last_four: Mapped[str] = mapped_column(String(4), nullable=False)
    token_digest: Mapped[bytes] = mapped_column(
        LargeBinary(32),
        nullable=False,
        unique=True,
    )
    scopes: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    environment: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default="live",
    )
    created_by_user_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("identity.users.id"),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoke_reason: Mapped[str | None] = mapped_column(String(100))
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AuditEvent(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "audit_events"
    __table_args__ = {"schema": "security"}

    organization_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("identity.organizations.id", ondelete="SET NULL"),
        index=True,
    )
    project_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("control.projects.id", ondelete="SET NULL"),
        index=True,
    )
    actor_type: Mapped[str] = mapped_column(String(32), nullable=False)
    actor_id: Mapped[str] = mapped_column(String(100), nullable=False)
    action: Mapped[str] = mapped_column(String(120), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(80), nullable=False)
    resource_id: Mapped[str | None] = mapped_column(String(100))
    request_id: Mapped[str] = mapped_column(String(100), nullable=False)
    details: Mapped[dict[str, object]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )


class IdempotencyRecord(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "idempotency_records"
    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "principal_id",
            "endpoint",
            "key_digest",
            name="uq_idempotency_scope",
        ),
        {"schema": "security"},
    )

    organization_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("identity.organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    principal_id: Mapped[str] = mapped_column(String(100), nullable=False)
    endpoint: Mapped[str] = mapped_column(String(160), nullable=False)
    key_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    request_fingerprint: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    resource_type: Mapped[str] = mapped_column(String(80), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(100), nullable=False)
    response_status: Mapped[int | None] = mapped_column(Integer)
    response_snapshot: Mapped[dict[str, object] | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )


class WorkerIdentity(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "worker_identities"
    __table_args__ = {"schema": "security"}

    name: Mapped[str] = mapped_column(String(160), nullable=False, unique=True)
    public_prefix: Mapped[str] = mapped_column(
        String(16), nullable=False, unique=True
    )
    last_four: Mapped[str] = mapped_column(String(4), nullable=False)
    token_digest: Mapped[bytes] = mapped_column(
        LargeBinary(32), nullable=False, unique=True
    )
    capabilities: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    max_concurrency: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(
        String(24), nullable=False, default="ACTIVE"
    )
    protocol_version: Mapped[str] = mapped_column(String(40), nullable=False)
    software_version: Mapped[str] = mapped_column(String(80), nullable=False)
    metadata_json: Mapped[dict[str, object]] = mapped_column(
        JSONB, nullable=False, default=dict
    )
    sandbox_profile: Mapped[str | None] = mapped_column(String(80))
    sandbox_attestation_digest: Mapped[str | None] = mapped_column(String(64))
    sandbox_execution_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    sandbox_attested_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    registered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_lost_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    last_recovered_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    last_cleanup_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    cleanup_generation: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class StorageGrant(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "storage_grants"
    __table_args__ = {"schema": "security"}

    organization_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("identity.organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    project_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("control.projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    storage_object_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("control.storage_objects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    lease_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("control.execution_leases.id", ondelete="CASCADE"),
        index=True,
    )
    worker_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("security.worker_identities.id", ondelete="RESTRICT"),
        index=True,
    )
    issued_to_user_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("identity.users.id", ondelete="RESTRICT"),
        index=True,
    )
    operation: Mapped[str] = mapped_column(String(16), nullable=False)
    provider: Mapped[str] = mapped_column(
        String(24), nullable=False, default="S3_PRESIGNED"
    )
    capability_digest: Mapped[bytes] = mapped_column(
        LargeBinary(32), nullable=False, unique=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )


class ExecutionLease(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "execution_leases"
    __table_args__ = (
        UniqueConstraint(
            "work_kind",
            "source_outbox_id",
            "attempt",
            name="uq_execution_leases_source_attempt",
        ),
        {"schema": "control"},
    )

    worker_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("security.worker_identities.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    organization_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("identity.organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    project_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("control.projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    work_kind: Mapped[str] = mapped_column(String(24), nullable=False)
    source_outbox_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), nullable=False, index=True
    )
    source_topic: Mapped[str] = mapped_column(String(120), nullable=False)
    build_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("control.builds.id", ondelete="CASCADE"),
        index=True,
    )
    run_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("control.runs.id", ondelete="CASCADE"),
        index=True,
    )
    lease_token_digest: Mapped[bytes] = mapped_column(
        LargeBinary(32), nullable=False, unique=True
    )
    payload_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    payload_snapshot: Mapped[dict[str, object]] = mapped_column(
        JSONB, nullable=False
    )
    status: Mapped[str] = mapped_column(
        String(24), nullable=False, default="ACTIVE"
    )
    attempt: Mapped[int] = mapped_column(Integer, nullable=False)
    claimed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    deadline_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    last_renewed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    failure_code: Mapped[str | None] = mapped_column(String(80))
    failure_summary: Mapped[str | None] = mapped_column(Text)


class ExecutionArtifact(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "execution_artifacts"
    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "digest_algorithm",
            "digest",
            "kind",
            name="uq_execution_artifacts_digest_kind",
        ),
        {"schema": "control"},
    )

    organization_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("identity.organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    project_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("control.projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    build_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("control.builds.id", ondelete="CASCADE"),
        index=True,
    )
    run_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("control.runs.id", ondelete="CASCADE"),
        index=True,
    )
    lease_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("control.execution_leases.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    created_by_worker_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("security.worker_identities.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    kind: Mapped[str] = mapped_column(String(40), nullable=False)
    digest_algorithm: Mapped[str] = mapped_column(
        String(16), nullable=False, default="sha256"
    )
    digest: Mapped[str] = mapped_column(String(128), nullable=False)
    object_key: Mapped[str] = mapped_column(String(1024), nullable=False)
    media_type: Mapped[str] = mapped_column(String(160), nullable=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    status: Mapped[str] = mapped_column(
        String(24), nullable=False, default="AVAILABLE"
    )
    scan_status: Mapped[str] = mapped_column(
        String(24), nullable=False, default="PENDING"
    )
    provenance: Mapped[dict[str, object]] = mapped_column(
        JSONB, nullable=False, default=dict
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class SecretInjectionGrant(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "secret_injection_grants"
    __table_args__ = (
        UniqueConstraint(
            "lease_id",
            "request_fingerprint",
            name="uq_secret_injection_grants_lease_request",
        ),
        {"schema": "security"},
    )

    worker_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("security.worker_identities.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    lease_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("control.execution_leases.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    organization_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("identity.organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    project_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("control.projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    run_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("control.runs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    request_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    secret_names: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    environment: Mapped[str] = mapped_column(String(24), nullable=False)
    algorithm: Mapped[str] = mapped_column(String(80), nullable=False)
    ephemeral_public_key: Mapped[bytes] = mapped_column(
        LargeBinary(32), nullable=False
    )
    nonce: Mapped[bytes] = mapped_column(LargeBinary(12), nullable=False)
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    worker_public_key_digest: Mapped[str] = mapped_column(
        String(64), nullable=False
    )
    status: Mapped[str] = mapped_column(
        String(24), nullable=False, default="ISSUED"
    )
    issued_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    consumed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
