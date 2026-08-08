'''Add Phase 1O KeyValueStore metadata persistence and tenant RLS.

Revision ID: 20260808_0012
Revises: 20260808_0011
Create Date: 2026-08-08
'''

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260808_0012"
down_revision: str | None = "20260808_0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

UUID = postgresql.UUID(as_uuid=True)


def upgrade() -> None:
    op.create_table(
        "key_value_stores",
        sa.Column("id", UUID, server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("organization_id", UUID, nullable=False),
        sa.Column("project_id", UUID, nullable=False),
        sa.Column("scope", sa.String(16), nullable=False),
        sa.Column("run_id", UUID, nullable=True),
        sa.Column("agent_id", UUID, nullable=True),
        sa.Column("agent_version_id", UUID, nullable=True),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("record_count", sa.BigInteger(), server_default="0", nullable=False),
        sa.Column("total_bytes", sa.BigInteger(), server_default="0", nullable=False),
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
        sa.Column("version", sa.BigInteger(), server_default="1", nullable=False),
        sa.CheckConstraint("scope IN ('PROJECT', 'RUN')", name="ck_key_value_stores_scope"),
        sa.CheckConstraint(
            "name ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'",
            name="ck_key_value_stores_name",
        ),
        sa.CheckConstraint("record_count >= 0", name="ck_key_value_stores_record_count"),
        sa.CheckConstraint("total_bytes >= 0", name="ck_key_value_stores_total_bytes"),
        sa.CheckConstraint("version >= 1", name="ck_key_value_stores_version"),
        sa.CheckConstraint(
            "(scope = 'PROJECT' AND run_id IS NULL AND agent_id IS NULL "
            "AND agent_version_id IS NULL) OR "
            "(scope = 'RUN' AND run_id IS NOT NULL AND agent_id IS NOT NULL "
            "AND agent_version_id IS NOT NULL)",
            name="ck_key_value_stores_scope_lineage",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["identity.organizations.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(["project_id"], ["control.projects.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["run_id"], ["control.runs.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["agent_id"], ["control.agents.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["agent_version_id"],
            ["control.agent_versions.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["identity.users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        schema="control",
    )

    for name, columns in [
        ("ix_key_value_stores_organization_id", ["organization_id"]),
        ("ix_key_value_stores_project_id", ["project_id"]),
        ("ix_key_value_stores_run_id", ["run_id"]),
        ("ix_key_value_stores_agent_id", ["agent_id"]),
        ("ix_key_value_stores_agent_version_id", ["agent_version_id"]),
    ]:
        op.create_index(name, "key_value_stores", columns, schema="control")

    op.create_index(
        "uq_key_value_stores_project_name",
        "key_value_stores",
        ["project_id", "name"],
        unique=True,
        schema="control",
        postgresql_where=sa.text("scope = 'PROJECT'"),
    )
    op.create_index(
        "uq_key_value_stores_run_name",
        "key_value_stores",
        ["run_id", "name"],
        unique=True,
        schema="control",
        postgresql_where=sa.text("scope = 'RUN'"),
    )
    op.create_index(
        "ix_key_value_stores_project_created",
        "key_value_stores",
        ["project_id", sa.text("created_at DESC"), sa.text("id DESC")],
        schema="control",
    )

    op.execute(
        '''
        CREATE OR REPLACE FUNCTION control.enforce_key_value_store_tenancy()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = control, identity, security, pg_temp
        AS $$
        BEGIN
          IF NOT EXISTS (
            SELECT 1
            FROM control.projects project
            WHERE project.id = NEW.project_id
              AND project.organization_id = NEW.organization_id
          ) THEN
            RAISE EXCEPTION 'KV store project tenancy mismatch'
              USING ERRCODE = '23514';
          END IF;

          IF NEW.scope = 'RUN' THEN
            IF NOT EXISTS (
              SELECT 1
              FROM control.runs run
              WHERE run.id = NEW.run_id
                AND run.organization_id = NEW.organization_id
                AND run.project_id = NEW.project_id
                AND run.agent_id = NEW.agent_id
                AND run.agent_version_id = NEW.agent_version_id
            ) THEN
              RAISE EXCEPTION 'KV store Run lineage mismatch'
                USING ERRCODE = '23514';
            END IF;
          ELSIF NEW.scope = 'PROJECT' THEN
            IF NEW.run_id IS NOT NULL
              OR NEW.agent_id IS NOT NULL
              OR NEW.agent_version_id IS NOT NULL
            THEN
              RAISE EXCEPTION 'Project KV store cannot carry Run lineage'
                USING ERRCODE = '23514';
            END IF;
          ELSE
            RAISE EXCEPTION 'KV store scope is invalid'
              USING ERRCODE = '23514';
          END IF;

          IF TG_OP = 'UPDATE' AND (
            OLD.organization_id IS DISTINCT FROM NEW.organization_id
            OR OLD.project_id IS DISTINCT FROM NEW.project_id
            OR OLD.scope IS DISTINCT FROM NEW.scope
            OR OLD.run_id IS DISTINCT FROM NEW.run_id
            OR OLD.agent_id IS DISTINCT FROM NEW.agent_id
            OR OLD.agent_version_id IS DISTINCT FROM NEW.agent_version_id
            OR OLD.name IS DISTINCT FROM NEW.name
            OR OLD.created_by_user_id IS DISTINCT FROM NEW.created_by_user_id
          ) THEN
            RAISE EXCEPTION 'KV store identity fields are immutable'
              USING ERRCODE = '23514';
          END IF;

          RETURN NEW;
        END;
        $$
        '''
    )

    op.execute(
        '''
        CREATE TRIGGER key_value_stores_tenancy_guard
        BEFORE INSERT OR UPDATE OF
          organization_id, project_id, scope, run_id, agent_id,
          agent_version_id, name, created_by_user_id
        ON control.key_value_stores
        FOR EACH ROW
        EXECUTE FUNCTION control.enforce_key_value_store_tenancy()
        '''
    )

    op.execute(
        '''
        CREATE OR REPLACE FUNCTION security.rdc_key_value_store_org(
          target_store uuid
        )
        RETURNS uuid
        LANGUAGE sql
        STABLE
        SECURITY DEFINER
        SET search_path = control, identity, security, pg_temp
        AS $$
          SELECT store.organization_id
          FROM control.key_value_stores store
          WHERE store.id = target_store
            AND security.rdc_has_org_membership(store.organization_id)
        $$
        '''
    )

    op.execute(
        'ALTER TABLE "control"."key_value_stores" ENABLE ROW LEVEL SECURITY'
    )
    op.execute(
        '''
        CREATE POLICY key_value_stores_tenant
        ON control.key_value_stores
        USING (
          organization_id = security.rdc_current_org_id()
          AND security.rdc_has_org_membership(organization_id)
        )
        WITH CHECK (
          organization_id = security.rdc_current_org_id()
          AND security.rdc_has_org_membership(organization_id)
        )
        '''
    )


def downgrade() -> None:
    op.execute(
        "DROP POLICY IF EXISTS key_value_stores_tenant "
        "ON control.key_value_stores"
    )
    op.execute(
        "DROP TRIGGER IF EXISTS key_value_stores_tenancy_guard "
        "ON control.key_value_stores"
    )
    op.execute(
        "DROP FUNCTION IF EXISTS security.rdc_key_value_store_org(uuid)"
    )
    op.execute(
        "DROP FUNCTION IF EXISTS control.enforce_key_value_store_tenancy()"
    )
    op.drop_table("key_value_stores", schema="control")
