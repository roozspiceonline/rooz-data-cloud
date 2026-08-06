"""Create Phase 1G secure source ingestion and artifact delivery.

Revision ID: 20260806_0007
Revises: 20260806_0006
Create Date: 2026-08-06
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260806_0007"
down_revision: str | None = "20260806_0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

UUID = postgresql.UUID(as_uuid=True)
JSONB = postgresql.JSONB(astext_type=sa.Text())


def upgrade() -> None:
    op.create_table(
        "storage_objects",
        sa.Column(
            "id", UUID, server_default=sa.text("gen_random_uuid()"), nullable=False
        ),
        sa.Column("organization_id", UUID, nullable=False),
        sa.Column("project_id", UUID, nullable=False),
        sa.Column("agent_id", UUID),
        sa.Column("kind", sa.String(40), nullable=False),
        sa.Column("provider", sa.String(24), server_default="S3", nullable=False),
        sa.Column("bucket", sa.String(160), nullable=False),
        sa.Column("object_key", sa.String(1024), nullable=False),
        sa.Column("file_name", sa.String(255), nullable=False),
        sa.Column("media_type", sa.String(160), nullable=False),
        sa.Column("expected_size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("size_bytes", sa.BigInteger()),
        sa.Column("expected_sha256_digest", sa.String(64), nullable=False),
        sa.Column("sha256_digest", sa.String(64)),
        sa.Column(
            "status", sa.String(24), server_default="PENDING_UPLOAD", nullable=False
        ),
        sa.Column(
            "scan_status", sa.String(24), server_default="PENDING", nullable=False
        ),
        sa.Column("rejection_code", sa.String(80)),
        sa.Column(
            "metadata_json",
            JSONB,
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("created_by_user_id", UUID, nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("uploaded_at", sa.DateTime(timezone=True)),
        sa.Column("available_at", sa.DateTime(timezone=True)),
        sa.Column("rejected_at", sa.DateTime(timezone=True)),
        sa.Column("deleted_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint(
            "kind IN ('AGENT_SOURCE')", name="ck_storage_objects_kind"
        ),
        sa.CheckConstraint(
            "status IN ('PENDING_UPLOAD', 'QUARANTINED', 'AVAILABLE', "
            "'REJECTED', 'DELETED')",
            name="ck_storage_objects_status",
        ),
        sa.CheckConstraint(
            "scan_status IN ('PENDING', 'PASSED', 'FAILED', 'NOT_REQUIRED')",
            name="ck_storage_objects_scan_status",
        ),
        sa.CheckConstraint(
            "expected_size_bytes > 0 AND (size_bytes IS NULL OR size_bytes > 0)",
            name="ck_storage_objects_positive_size",
        ),
        sa.CheckConstraint(
            "expected_sha256_digest ~ '^[0-9a-f]{64}$'",
            name="ck_storage_objects_expected_digest",
        ),
        sa.CheckConstraint(
            "sha256_digest IS NULL OR sha256_digest ~ '^[0-9a-f]{64}$'",
            name="ck_storage_objects_digest",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["identity.organizations.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["project_id"], ["control.projects.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["agent_id"], ["control.agents.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["created_by_user_id"], ["identity.users.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "bucket", "object_key", name="uq_storage_objects_bucket_key"
        ),
        schema="control",
    )
    for name, columns in [
        ("ix_storage_objects_organization_id", ["organization_id"]),
        ("ix_storage_objects_project_id", ["project_id"]),
        ("ix_storage_objects_agent_id", ["agent_id"]),
        ("ix_storage_objects_status", ["status", "created_at"]),
    ]:
        op.create_index(name, "storage_objects", columns, schema="control")

    # Nullable rollout keeps upgrades safe for pre-1G immutable versions/builds.
    # Phase 1G application paths require these fields for every new record.
    op.add_column(
        "agent_versions",
        sa.Column("source_object_id", UUID, nullable=True),
        schema="control",
    )
    op.create_foreign_key(
        "fk_agent_versions_source_object_id",
        "agent_versions",
        "storage_objects",
        ["source_object_id"],
        ["id"],
        source_schema="control",
        referent_schema="control",
        ondelete="RESTRICT",
    )
    op.create_index(
        "ix_agent_versions_source_object_id",
        "agent_versions",
        ["source_object_id"],
        schema="control",
    )
    op.execute(
        """
        CREATE UNIQUE INDEX uq_agent_versions_source_object_id
        ON control.agent_versions (source_object_id)
        WHERE source_object_id IS NOT NULL
        """
    )

    op.add_column(
        "builds",
        sa.Column("source_object_id", UUID, nullable=True),
        schema="control",
    )
    op.create_foreign_key(
        "fk_builds_source_object_id",
        "builds",
        "storage_objects",
        ["source_object_id"],
        ["id"],
        source_schema="control",
        referent_schema="control",
        ondelete="RESTRICT",
    )
    op.create_index(
        "ix_builds_source_object_id",
        "builds",
        ["source_object_id"],
        schema="control",
    )

    op.create_table(
        "storage_grants",
        sa.Column(
            "id", UUID, server_default=sa.text("gen_random_uuid()"), nullable=False
        ),
        sa.Column("organization_id", UUID, nullable=False),
        sa.Column("project_id", UUID, nullable=False),
        sa.Column("storage_object_id", UUID, nullable=False),
        sa.Column("lease_id", UUID),
        sa.Column("worker_id", UUID),
        sa.Column("issued_to_user_id", UUID),
        sa.Column("operation", sa.String(16), nullable=False),
        sa.Column(
            "provider", sa.String(24), server_default="S3_PRESIGNED", nullable=False
        ),
        sa.Column("capability_digest", sa.LargeBinary(32), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint(
            "operation IN ('UPLOAD', 'DOWNLOAD')",
            name="ck_storage_grants_operation",
        ),
        sa.CheckConstraint(
            "expires_at > created_at", name="ck_storage_grants_expiry"
        ),
        sa.CheckConstraint(
            "(issued_to_user_id IS NOT NULL AND worker_id IS NULL AND lease_id IS NULL) "
            "OR (issued_to_user_id IS NULL AND worker_id IS NOT NULL "
            "AND lease_id IS NOT NULL)",
            name="ck_storage_grants_principal",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["identity.organizations.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["project_id"], ["control.projects.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["storage_object_id"],
            ["control.storage_objects.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["lease_id"], ["control.execution_leases.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["worker_id"],
            ["security.worker_identities.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["issued_to_user_id"], ["identity.users.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "capability_digest", name="uq_storage_grants_capability_digest"
        ),
        schema="security",
    )
    for name, columns in [
        ("ix_storage_grants_organization_id", ["organization_id"]),
        ("ix_storage_grants_project_id", ["project_id"]),
        ("ix_storage_grants_storage_object_id", ["storage_object_id"]),
        ("ix_storage_grants_lease_id", ["lease_id"]),
        ("ix_storage_grants_worker_id", ["worker_id"]),
        ("ix_storage_grants_issued_to_user_id", ["issued_to_user_id"]),
        ("ix_storage_grants_expiry", ["expires_at"]),
    ]:
        op.create_index(name, "storage_grants", columns, schema="security")

    op.execute(
        """
        CREATE OR REPLACE FUNCTION security.rdc_storage_object_org(
          target_storage_object uuid
        )
        RETURNS uuid
        LANGUAGE sql
        STABLE
        SECURITY DEFINER
        SET search_path = control, identity, security, pg_temp
        AS $$
          SELECT object.organization_id
          FROM control.storage_objects object
          WHERE object.id = target_storage_object
            AND object.deleted_at IS NULL
            AND security.rdc_has_org_membership(object.organization_id)
        $$
        """
    )

    op.execute(
        """
        CREATE OR REPLACE FUNCTION control.enforce_storage_object_tenancy()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = control, identity, security, pg_temp
        AS $$
        BEGIN
          IF NOT EXISTS (
            SELECT 1 FROM control.projects project
            WHERE project.id = NEW.project_id
              AND project.organization_id = NEW.organization_id
              AND project.deleted_at IS NULL
          ) THEN
            RAISE EXCEPTION 'storage object tenant mismatch';
          END IF;
          IF NEW.agent_id IS NOT NULL AND NOT EXISTS (
            SELECT 1 FROM control.agents agent
            WHERE agent.id = NEW.agent_id
              AND agent.project_id = NEW.project_id
              AND agent.organization_id = NEW.organization_id
              AND agent.deleted_at IS NULL
          ) THEN
            RAISE EXCEPTION 'storage object agent tenant mismatch';
          END IF;
          RETURN NEW;
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER storage_objects_tenancy_guard
        BEFORE INSERT OR UPDATE OF organization_id, project_id, agent_id
        ON control.storage_objects
        FOR EACH ROW
        EXECUTE FUNCTION control.enforce_storage_object_tenancy()
        """
    )

    op.execute(
        """
        CREATE OR REPLACE FUNCTION security.enforce_storage_grant_tenancy()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = control, identity, security, pg_temp
        AS $$
        BEGIN
          IF NOT EXISTS (
            SELECT 1 FROM control.storage_objects object
            WHERE object.id = NEW.storage_object_id
              AND object.organization_id = NEW.organization_id
              AND object.project_id = NEW.project_id
          ) THEN
            RAISE EXCEPTION 'storage grant tenant mismatch';
          END IF;
          IF NEW.lease_id IS NOT NULL AND NOT EXISTS (
            SELECT 1 FROM control.execution_leases lease
            WHERE lease.id = NEW.lease_id
              AND lease.worker_id = NEW.worker_id
              AND lease.organization_id = NEW.organization_id
              AND lease.project_id = NEW.project_id
          ) THEN
            RAISE EXCEPTION 'storage grant lease mismatch';
          END IF;
          RETURN NEW;
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER storage_grants_tenancy_guard
        BEFORE INSERT OR UPDATE OF organization_id, project_id,
          storage_object_id, lease_id, worker_id
        ON security.storage_grants
        FOR EACH ROW
        EXECUTE FUNCTION security.enforce_storage_grant_tenancy()
        """
    )

    op.execute("ALTER TABLE control.storage_objects ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE security.storage_grants ENABLE ROW LEVEL SECURITY")
    op.execute(
        """
        CREATE POLICY storage_objects_tenant
        ON control.storage_objects
        USING (
          organization_id = security.rdc_current_org_id()
          AND security.rdc_has_org_membership(organization_id)
        )
        WITH CHECK (
          organization_id = security.rdc_current_org_id()
          AND security.rdc_has_org_membership(organization_id)
        )
        """
    )
    op.execute(
        """
        CREATE POLICY storage_objects_worker
        ON control.storage_objects
        FOR SELECT
        USING (
          security.rdc_worker_is_active()
          AND status = 'AVAILABLE'
          AND scan_status = 'PASSED'
          AND EXISTS (
            SELECT 1
            FROM control.execution_leases lease
            JOIN control.builds build ON build.id = lease.build_id
            WHERE lease.worker_id = security.rdc_current_worker_id()
              AND lease.status = 'ACTIVE'
              AND lease.work_kind = 'BUILD'
              AND build.source_object_id = storage_objects.id
          )
        )
        """
    )
    op.execute(
        """
        CREATE POLICY storage_grants_tenant
        ON security.storage_grants
        USING (
          organization_id = security.rdc_current_org_id()
          AND security.rdc_has_org_membership(organization_id)
        )
        WITH CHECK (
          organization_id = security.rdc_current_org_id()
          AND security.rdc_has_org_membership(organization_id)
        )
        """
    )
    op.execute(
        """
        CREATE POLICY storage_grants_worker
        ON security.storage_grants
        USING (
          worker_id = security.rdc_current_worker_id()
          AND security.rdc_worker_is_active()
        )
        WITH CHECK (
          worker_id = security.rdc_current_worker_id()
          AND security.rdc_worker_is_active()
          AND operation = 'DOWNLOAD'
        )
        """
    )


def downgrade() -> None:
    op.execute(
        "DROP POLICY IF EXISTS storage_grants_worker ON security.storage_grants"
    )
    op.execute(
        "DROP POLICY IF EXISTS storage_grants_tenant ON security.storage_grants"
    )
    op.execute(
        "DROP POLICY IF EXISTS storage_objects_worker ON control.storage_objects"
    )
    op.execute(
        "DROP POLICY IF EXISTS storage_objects_tenant ON control.storage_objects"
    )
    op.execute(
        "DROP TRIGGER IF EXISTS storage_grants_tenancy_guard "
        "ON security.storage_grants"
    )
    op.execute(
        "DROP TRIGGER IF EXISTS storage_objects_tenancy_guard "
        "ON control.storage_objects"
    )
    op.drop_table("storage_grants", schema="security")
    op.drop_index(
        "ix_builds_source_object_id", table_name="builds", schema="control"
    )
    op.drop_constraint(
        "fk_builds_source_object_id", "builds", schema="control", type_="foreignkey"
    )
    op.drop_column("builds", "source_object_id", schema="control")
    op.execute("DROP INDEX IF EXISTS control.uq_agent_versions_source_object_id")
    op.drop_index(
        "ix_agent_versions_source_object_id",
        table_name="agent_versions",
        schema="control",
    )
    op.drop_constraint(
        "fk_agent_versions_source_object_id",
        "agent_versions",
        schema="control",
        type_="foreignkey",
    )
    op.drop_column("agent_versions", "source_object_id", schema="control")
    op.drop_table("storage_objects", schema="control")
    op.execute("DROP FUNCTION IF EXISTS security.enforce_storage_grant_tenancy()")
    op.execute("DROP FUNCTION IF EXISTS control.enforce_storage_object_tenancy()")
    op.execute("DROP FUNCTION IF EXISTS security.rdc_storage_object_org(uuid)")
