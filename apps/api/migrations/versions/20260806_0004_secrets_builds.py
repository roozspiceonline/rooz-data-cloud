"""Create Phase 1D project secrets and build control-plane tables.

Revision ID: 20260806_0004
Revises: 20260806_0003
Create Date: 2026-08-06
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260806_0004"
down_revision: str | None = "20260806_0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

UUID = postgresql.UUID(as_uuid=True)
JSONB = postgresql.JSONB(astext_type=sa.Text())


def upgrade() -> None:
    op.add_column(
        "idempotency_records",
        sa.Column("response_status", sa.Integer()),
        schema="security",
    )
    op.add_column(
        "idempotency_records",
        sa.Column("response_snapshot", JSONB),
        schema="security",
    )

    op.create_table(
        "project_secrets",
        sa.Column(
            "id",
            UUID,
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("organization_id", UUID, nullable=False),
        sa.Column("project_id", UUID, nullable=False),
        sa.Column("name", sa.String(64), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("environment", sa.String(24), nullable=False),
        sa.Column("encrypted_value", sa.LargeBinary(), nullable=False),
        sa.Column("value_nonce", sa.LargeBinary(12), nullable=False),
        sa.Column("wrapped_data_key", sa.LargeBinary(), nullable=False),
        sa.Column("key_nonce", sa.LargeBinary(12), nullable=False),
        sa.Column(
            "encryption_algorithm",
            sa.String(32),
            server_default="AES-256-GCM",
            nullable=False,
        ),
        sa.Column("master_key_version", sa.String(40), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True)),
        sa.Column("created_by_user_id", UUID, nullable=False),
        sa.Column("updated_by_user_id", UUID, nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column(
            "version",
            sa.BigInteger(),
            server_default="1",
            nullable=False,
        ),
        sa.CheckConstraint(
            "name ~ '^[A-Z][A-Z0-9_]{0,63}$'",
            name="ck_project_secrets_name",
        ),
        sa.CheckConstraint(
            "environment IN ('development', 'test', 'staging', 'production')",
            name="ck_project_secrets_environment",
        ),
        sa.CheckConstraint(
            "octet_length(value_nonce) = 12",
            name="ck_project_secrets_value_nonce",
        ),
        sa.CheckConstraint(
            "octet_length(key_nonce) = 12",
            name="ck_project_secrets_key_nonce",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["identity.organizations.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["project_id"],
            ["control.projects.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["created_by_user_id"],
            ["identity.users.id"],
        ),
        sa.ForeignKeyConstraint(
            ["updated_by_user_id"],
            ["identity.users.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "project_id",
            "name",
            name="uq_project_secrets_project_name",
        ),
        schema="security",
    )
    op.create_index(
        "ix_project_secrets_organization_id",
        "project_secrets",
        ["organization_id"],
        schema="security",
    )
    op.create_index(
        "ix_project_secrets_project_id",
        "project_secrets",
        ["project_id"],
        schema="security",
    )
    op.create_index(
        "ix_project_secrets_project_created",
        "project_secrets",
        ["project_id", sa.text("created_at DESC"), sa.text("id DESC")],
        schema="security",
    )

    op.create_table(
        "builds",
        sa.Column(
            "id",
            UUID,
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("organization_id", UUID, nullable=False),
        sa.Column("project_id", UUID, nullable=False),
        sa.Column("agent_id", UUID, nullable=False),
        sa.Column("agent_version_id", UUID, nullable=False),
        sa.Column("manifest_digest", sa.String(64), nullable=False),
        sa.Column(
            "status",
            sa.String(32),
            server_default="QUEUED",
            nullable=False,
        ),
        sa.Column("requested_by_user_id", UUID, nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("artifact_digest", sa.String(120)),
        sa.Column("error_code", sa.String(80)),
        sa.Column("error_message", sa.Text()),
        sa.Column(
            "version",
            sa.BigInteger(),
            server_default="1",
            nullable=False,
        ),
        sa.CheckConstraint(
            "status IN ('QUEUED', 'STARTING', 'RUNNING', 'SUCCEEDED', "
            "'FAILED', 'CANCELLED', 'TIMED_OUT')",
            name="ck_builds_status",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["identity.organizations.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["project_id"],
            ["control.projects.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["agent_id"],
            ["control.agents.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["agent_version_id"],
            ["control.agent_versions.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["requested_by_user_id"],
            ["identity.users.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
        schema="control",
    )
    op.create_index(
        "ix_builds_organization_id",
        "builds",
        ["organization_id"],
        schema="control",
    )
    op.create_index(
        "ix_builds_project_id",
        "builds",
        ["project_id"],
        schema="control",
    )
    op.create_index(
        "ix_builds_agent_id",
        "builds",
        ["agent_id"],
        schema="control",
    )
    op.create_index(
        "ix_builds_agent_version_id",
        "builds",
        ["agent_version_id"],
        schema="control",
    )
    op.create_index(
        "ix_builds_agent_created",
        "builds",
        ["agent_id", sa.text("created_at DESC"), sa.text("id DESC")],
        schema="control",
    )

    op.create_table(
        "build_dispatch_outbox",
        sa.Column(
            "id",
            UUID,
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("organization_id", UUID, nullable=False),
        sa.Column("project_id", UUID, nullable=False),
        sa.Column("build_id", UUID, nullable=False),
        sa.Column(
            "topic",
            sa.String(120),
            server_default="rdc.build.requested.v1",
            nullable=False,
        ),
        sa.Column("payload", JSONB, nullable=False),
        sa.Column(
            "status",
            sa.String(24),
            server_default="PENDING",
            nullable=False,
        ),
        sa.Column(
            "attempts",
            sa.Integer(),
            server_default="0",
            nullable=False,
        ),
        sa.Column(
            "available_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("claimed_at", sa.DateTime(timezone=True)),
        sa.Column("delivered_at", sa.DateTime(timezone=True)),
        sa.Column("last_error_code", sa.String(80)),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "status IN ('PENDING', 'CLAIMED', 'DELIVERED', 'FAILED')",
            name="ck_build_dispatch_outbox_status",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["identity.organizations.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["project_id"],
            ["control.projects.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["build_id"],
            ["control.builds.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "build_id",
            name="uq_build_dispatch_outbox_build",
        ),
        schema="control",
    )
    op.create_index(
        "ix_build_dispatch_outbox_organization_id",
        "build_dispatch_outbox",
        ["organization_id"],
        schema="control",
    )
    op.create_index(
        "ix_build_dispatch_outbox_project_id",
        "build_dispatch_outbox",
        ["project_id"],
        schema="control",
    )
    op.create_index(
        "ix_build_dispatch_outbox_build_id",
        "build_dispatch_outbox",
        ["build_id"],
        schema="control",
    )
    op.create_index(
        "ix_build_dispatch_outbox_pending",
        "build_dispatch_outbox",
        ["status", "available_at"],
        schema="control",
    )

    op.execute(
        """
        CREATE OR REPLACE FUNCTION security.enforce_project_secret_tenancy()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
          IF NOT EXISTS (
            SELECT 1
            FROM control.projects project
            WHERE project.id = NEW.project_id
              AND project.organization_id = NEW.organization_id
              AND project.deleted_at IS NULL
          ) THEN
            RAISE EXCEPTION 'Project secret tenancy mismatch'
              USING ERRCODE = '23514';
          END IF;
          RETURN NEW;
        END
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER project_secrets_tenancy_guard
        BEFORE INSERT OR UPDATE OF organization_id, project_id
        ON security.project_secrets
        FOR EACH ROW
        EXECUTE FUNCTION security.enforce_project_secret_tenancy()
        """
    )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION control.enforce_build_tenancy()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
          IF NOT EXISTS (
            SELECT 1
            FROM control.agent_versions version
            WHERE version.id = NEW.agent_version_id
              AND version.agent_id = NEW.agent_id
              AND version.project_id = NEW.project_id
              AND version.organization_id = NEW.organization_id
          ) THEN
            RAISE EXCEPTION 'Build tenancy does not match Agent version'
              USING ERRCODE = '23514';
          END IF;
          RETURN NEW;
        END
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER builds_tenancy_guard
        BEFORE INSERT OR UPDATE OF
          organization_id, project_id, agent_id, agent_version_id
        ON control.builds
        FOR EACH ROW
        EXECUTE FUNCTION control.enforce_build_tenancy()
        """
    )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION control.enforce_build_outbox_tenancy()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
          IF NOT EXISTS (
            SELECT 1
            FROM control.builds build
            WHERE build.id = NEW.build_id
              AND build.project_id = NEW.project_id
              AND build.organization_id = NEW.organization_id
          ) THEN
            RAISE EXCEPTION 'Build outbox tenancy mismatch'
              USING ERRCODE = '23514';
          END IF;
          RETURN NEW;
        END
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER build_dispatch_outbox_tenancy_guard
        BEFORE INSERT OR UPDATE OF organization_id, project_id, build_id
        ON control.build_dispatch_outbox
        FOR EACH ROW
        EXECUTE FUNCTION control.enforce_build_outbox_tenancy()
        """
    )

    op.execute(
        """
        CREATE OR REPLACE FUNCTION security.rdc_project_secret_org(
          target_secret uuid
        )
        RETURNS uuid
        LANGUAGE sql
        STABLE
        SECURITY DEFINER
        SET search_path = security, control, identity, pg_temp
        AS $$
          SELECT secret.organization_id
          FROM security.project_secrets secret
          WHERE secret.id = target_secret
            AND security.rdc_has_org_membership(secret.organization_id)
        $$
        """
    )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION security.rdc_build_org(
          target_build uuid
        )
        RETURNS uuid
        LANGUAGE sql
        STABLE
        SECURITY DEFINER
        SET search_path = control, identity, security, pg_temp
        AS $$
          SELECT build.organization_id
          FROM control.builds build
          WHERE build.id = target_build
            AND security.rdc_has_org_membership(build.organization_id)
        $$
        """
    )

    for schema_name, table_name in [
        ("security", "project_secrets"),
        ("control", "builds"),
        ("control", "build_dispatch_outbox"),
    ]:
        op.execute(
            f'ALTER TABLE "{schema_name}"."{table_name}" '
            "ENABLE ROW LEVEL SECURITY"
        )
        op.execute(
            f"""
            CREATE POLICY {table_name}_tenant
            ON {schema_name}.{table_name}
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


def downgrade() -> None:
    op.execute("DROP FUNCTION IF EXISTS security.rdc_build_org(uuid)")
    op.execute("DROP FUNCTION IF EXISTS security.rdc_project_secret_org(uuid)")
    op.drop_table("build_dispatch_outbox", schema="control")
    op.drop_table("builds", schema="control")
    op.drop_table("project_secrets", schema="security")
    op.execute("DROP FUNCTION IF EXISTS control.enforce_build_outbox_tenancy()")
    op.execute("DROP FUNCTION IF EXISTS control.enforce_build_tenancy()")
    op.execute("DROP FUNCTION IF EXISTS security.enforce_project_secret_tenancy()")
    op.drop_column(
        "idempotency_records",
        "response_snapshot",
        schema="security",
    )
    op.drop_column(
        "idempotency_records",
        "response_status",
        schema="security",
    )
