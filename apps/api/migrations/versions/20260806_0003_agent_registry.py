"""Create the Phase 1C Agent registry and immutable versions.

Revision ID: 20260806_0003
Revises: 20260806_0002
Create Date: 2026-08-06
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260806_0003"
down_revision: str | None = "20260806_0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

UUID = postgresql.UUID(as_uuid=True)
JSONB = postgresql.JSONB(astext_type=sa.Text())


def upgrade() -> None:
    op.create_table(
        "agents",
        sa.Column(
            "id",
            UUID,
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("organization_id", UUID, nullable=False),
        sa.Column("project_id", UUID, nullable=False),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("slug", sa.String(80), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column(
            "status",
            sa.String(32),
            server_default="ACTIVE",
            nullable=False,
        ),
        sa.Column("created_by_user_id", UUID, nullable=False),
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
        sa.Column("deleted_at", sa.DateTime(timezone=True)),
        sa.Column(
            "version",
            sa.BigInteger(),
            server_default="1",
            nullable=False,
        ),
        sa.CheckConstraint(
            "status IN ('ACTIVE', 'ARCHIVED')",
            name="ck_agents_status",
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
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "project_id",
            "slug",
            name="uq_agents_project_slug",
        ),
        schema="control",
    )
    op.create_index(
        "ix_agents_organization_id",
        "agents",
        ["organization_id"],
        schema="control",
    )
    op.create_index(
        "ix_agents_project_id",
        "agents",
        ["project_id"],
        schema="control",
    )
    op.create_index(
        "ix_agents_project_created",
        "agents",
        ["project_id", sa.text("created_at DESC"), sa.text("id DESC")],
        schema="control",
    )

    op.create_table(
        "agent_versions",
        sa.Column(
            "id",
            UUID,
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("organization_id", UUID, nullable=False),
        sa.Column("project_id", UUID, nullable=False),
        sa.Column("agent_id", UUID, nullable=False),
        sa.Column("version_number", sa.Integer(), nullable=False),
        sa.Column("protocol", sa.String(40), nullable=False),
        sa.Column("semantic_version", sa.String(80), nullable=False),
        sa.Column(
            "manifest_schema_version",
            sa.String(40),
            nullable=False,
        ),
        sa.Column("manifest_digest", sa.String(64), nullable=False),
        sa.Column("manifest", JSONB, nullable=False),
        sa.Column("release_notes", sa.Text()),
        sa.Column("created_by_user_id", UUID, nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
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
            ["created_by_user_id"],
            ["identity.users.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "agent_id",
            "version_number",
            name="uq_agent_versions_agent_number",
        ),
        sa.UniqueConstraint(
            "agent_id",
            "semantic_version",
            name="uq_agent_versions_agent_semver",
        ),
        schema="control",
    )
    op.create_index(
        "ix_agent_versions_organization_id",
        "agent_versions",
        ["organization_id"],
        schema="control",
    )
    op.create_index(
        "ix_agent_versions_project_id",
        "agent_versions",
        ["project_id"],
        schema="control",
    )
    op.create_index(
        "ix_agent_versions_agent_id",
        "agent_versions",
        ["agent_id"],
        schema="control",
    )
    op.create_index(
        "ix_agent_versions_agent_created",
        "agent_versions",
        ["agent_id", sa.text("created_at DESC"), sa.text("id DESC")],
        schema="control",
    )

    op.execute(
        """
        CREATE OR REPLACE FUNCTION control.enforce_agent_tenancy()
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
            RAISE EXCEPTION 'Agent project and organization do not match'
              USING ERRCODE = '23514';
          END IF;
          RETURN NEW;
        END
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER agents_tenancy_guard
        BEFORE INSERT OR UPDATE OF organization_id, project_id
        ON control.agents
        FOR EACH ROW
        EXECUTE FUNCTION control.enforce_agent_tenancy()
        """
    )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION control.enforce_agent_version_tenancy()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
          IF NOT EXISTS (
            SELECT 1
            FROM control.agents agent
            WHERE agent.id = NEW.agent_id
              AND agent.organization_id = NEW.organization_id
              AND agent.project_id = NEW.project_id
              AND agent.deleted_at IS NULL
          ) THEN
            RAISE EXCEPTION 'Agent version tenancy does not match its Agent'
              USING ERRCODE = '23514';
          END IF;
          RETURN NEW;
        END
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER agent_versions_tenancy_guard
        BEFORE INSERT
        ON control.agent_versions
        FOR EACH ROW
        EXECUTE FUNCTION control.enforce_agent_version_tenancy()
        """
    )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION control.reject_agent_version_mutation()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
          RAISE EXCEPTION 'Agent versions are immutable'
            USING ERRCODE = '55000';
        END
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER agent_versions_immutable
        BEFORE UPDATE OR DELETE
        ON control.agent_versions
        FOR EACH ROW
        EXECUTE FUNCTION control.reject_agent_version_mutation()
        """
    )

    op.execute(
        """
        CREATE OR REPLACE FUNCTION security.rdc_project_org(
          target_project uuid
        )
        RETURNS uuid
        LANGUAGE sql
        STABLE
        SECURITY DEFINER
        SET search_path = control, identity, security, pg_temp
        AS $$
          SELECT project.organization_id
          FROM control.projects project
          WHERE project.id = target_project
            AND project.deleted_at IS NULL
            AND security.rdc_has_org_membership(project.organization_id)
        $$
        """
    )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION security.rdc_agent_org(
          target_agent uuid
        )
        RETURNS uuid
        LANGUAGE sql
        STABLE
        SECURITY DEFINER
        SET search_path = control, identity, security, pg_temp
        AS $$
          SELECT agent.organization_id
          FROM control.agents agent
          WHERE agent.id = target_agent
            AND agent.deleted_at IS NULL
            AND security.rdc_has_org_membership(agent.organization_id)
        $$
        """
    )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION security.rdc_agent_version_org(
          target_version uuid
        )
        RETURNS uuid
        LANGUAGE sql
        STABLE
        SECURITY DEFINER
        SET search_path = control, identity, security, pg_temp
        AS $$
          SELECT version.organization_id
          FROM control.agent_versions version
          WHERE version.id = target_version
            AND security.rdc_has_org_membership(version.organization_id)
        $$
        """
    )

    for table_name in ["agents", "agent_versions"]:
        op.execute(
            f'ALTER TABLE "control"."{table_name}" ENABLE ROW LEVEL SECURITY'
        )
        op.execute(
            f"""
            CREATE POLICY {table_name}_tenant
            ON control.{table_name}
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
    for function_name in [
        "security.rdc_agent_version_org(uuid)",
        "security.rdc_agent_org(uuid)",
        "security.rdc_project_org(uuid)",
    ]:
        op.execute(f"DROP FUNCTION IF EXISTS {function_name}")

    op.execute(
        "DROP TRIGGER IF EXISTS agent_versions_immutable "
        "ON control.agent_versions"
    )
    op.execute(
        "DROP FUNCTION IF EXISTS control.reject_agent_version_mutation()"
    )
    op.execute(
        "DROP TRIGGER IF EXISTS agent_versions_tenancy_guard "
        "ON control.agent_versions"
    )
    op.execute(
        "DROP FUNCTION IF EXISTS control.enforce_agent_version_tenancy()"
    )
    op.execute(
        "DROP TRIGGER IF EXISTS agents_tenancy_guard ON control.agents"
    )
    op.execute("DROP FUNCTION IF EXISTS control.enforce_agent_tenancy()")

    op.drop_index(
        "ix_agent_versions_agent_created",
        table_name="agent_versions",
        schema="control",
    )
    op.drop_index(
        "ix_agent_versions_agent_id",
        table_name="agent_versions",
        schema="control",
    )
    op.drop_index(
        "ix_agent_versions_project_id",
        table_name="agent_versions",
        schema="control",
    )
    op.drop_index(
        "ix_agent_versions_organization_id",
        table_name="agent_versions",
        schema="control",
    )
    op.drop_table("agent_versions", schema="control")

    op.drop_index(
        "ix_agents_project_created",
        table_name="agents",
        schema="control",
    )
    op.drop_index(
        "ix_agents_project_id",
        table_name="agents",
        schema="control",
    )
    op.drop_index(
        "ix_agents_organization_id",
        table_name="agents",
        schema="control",
    )
    op.drop_table("agents", schema="control")
