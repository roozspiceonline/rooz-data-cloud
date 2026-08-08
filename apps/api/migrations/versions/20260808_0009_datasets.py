"""Add Phase 1N Dataset metadata persistence and tenant RLS.

Revision ID: 20260808_0009
Revises: 20260807_0008
Create Date: 2026-08-08
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260808_0009"
down_revision: str | None = "20260807_0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

UUID = postgresql.UUID(as_uuid=True)
JSONB = postgresql.JSONB(astext_type=sa.Text())


def upgrade() -> None:
    op.create_table(
        "datasets",
        sa.Column(
            "id",
            UUID,
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("organization_id", UUID, nullable=False),
        sa.Column("project_id", UUID, nullable=False),
        sa.Column("run_id", UUID, nullable=False),
        sa.Column("agent_id", UUID, nullable=False),
        sa.Column("agent_version_id", UUID, nullable=False),
        sa.Column(
            "name",
            sa.String(128),
            server_default="default",
            nullable=False,
        ),
        sa.Column(
            "item_count",
            sa.BigInteger(),
            server_default="0",
            nullable=False,
        ),
        sa.Column(
            "total_bytes",
            sa.BigInteger(),
            server_default="0",
            nullable=False,
        ),
        sa.Column(
            "next_sequence",
            sa.BigInteger(),
            server_default="1",
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
        sa.Column(
            "version",
            sa.BigInteger(),
            server_default="1",
            nullable=False,
        ),
        sa.CheckConstraint(
            "char_length(name) BETWEEN 1 AND 128",
            name="ck_datasets_name_length",
        ),
        sa.CheckConstraint(
            "item_count >= 0",
            name="ck_datasets_item_count",
        ),
        sa.CheckConstraint(
            "total_bytes >= 0",
            name="ck_datasets_total_bytes",
        ),
        sa.CheckConstraint(
            "next_sequence >= 1",
            name="ck_datasets_next_sequence",
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
            ["run_id"],
            ["control.runs.id"],
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
            ["created_by_user_id"],
            ["identity.users.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "run_id",
            "name",
            name="uq_datasets_run_name",
        ),
        schema="control",
    )
    for name, columns in [
        ("ix_datasets_organization_id", ["organization_id"]),
        ("ix_datasets_project_id", ["project_id"]),
        ("ix_datasets_run_id", ["run_id"]),
        ("ix_datasets_agent_id", ["agent_id"]),
        ("ix_datasets_agent_version_id", ["agent_version_id"]),
    ]:
        op.create_index(name, "datasets", columns, schema="control")
    op.create_index(
        "ix_datasets_project_created",
        "datasets",
        ["project_id", sa.text("created_at DESC"), sa.text("id DESC")],
        schema="control",
    )

    op.create_table(
        "dataset_items",
        sa.Column(
            "id",
            UUID,
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("organization_id", UUID, nullable=False),
        sa.Column("project_id", UUID, nullable=False),
        sa.Column("dataset_id", UUID, nullable=False),
        sa.Column("run_id", UUID, nullable=False),
        sa.Column("sequence", sa.BigInteger(), nullable=False),
        sa.Column("item_json", JSONB, nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("sha256_digest", sa.String(64), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "sequence >= 1",
            name="ck_dataset_items_sequence",
        ),
        sa.CheckConstraint(
            "size_bytes BETWEEN 1 AND 65536",
            name="ck_dataset_items_size",
        ),
        sa.CheckConstraint(
            "sha256_digest ~ '^[0-9a-f]{64}$'",
            name="ck_dataset_items_digest",
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
            ["dataset_id"],
            ["control.datasets.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["run_id"],
            ["control.runs.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "dataset_id",
            "sequence",
            name="uq_dataset_items_dataset_sequence",
        ),
        schema="control",
    )
    for name, columns in [
        ("ix_dataset_items_organization_id", ["organization_id"]),
        ("ix_dataset_items_project_id", ["project_id"]),
        ("ix_dataset_items_dataset_id", ["dataset_id"]),
        ("ix_dataset_items_run_id", ["run_id"]),
    ]:
        op.create_index(name, "dataset_items", columns, schema="control")
    op.create_index(
        "ix_dataset_items_dataset_sequence",
        "dataset_items",
        ["dataset_id", "sequence"],
        schema="control",
    )

    op.execute(
        """
        CREATE OR REPLACE FUNCTION control.enforce_dataset_tenancy()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = control, identity, security, pg_temp
        AS $$
        BEGIN
          IF NOT EXISTS (
            SELECT 1
            FROM control.runs run
            WHERE run.id = NEW.run_id
              AND run.organization_id = NEW.organization_id
              AND run.project_id = NEW.project_id
              AND run.agent_id = NEW.agent_id
              AND run.agent_version_id = NEW.agent_version_id
          ) THEN
            RAISE EXCEPTION 'Dataset tenancy or Run lineage mismatch'
              USING ERRCODE = '23514';
          END IF;
          RETURN NEW;
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER datasets_tenancy_guard
        BEFORE INSERT OR UPDATE OF
          organization_id, project_id, run_id, agent_id, agent_version_id
        ON control.datasets
        FOR EACH ROW
        EXECUTE FUNCTION control.enforce_dataset_tenancy()
        """
    )

    op.execute(
        """
        CREATE OR REPLACE FUNCTION control.enforce_dataset_item_tenancy()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = control, identity, security, pg_temp
        AS $$
        BEGIN
          IF NOT EXISTS (
            SELECT 1
            FROM control.datasets dataset
            WHERE dataset.id = NEW.dataset_id
              AND dataset.organization_id = NEW.organization_id
              AND dataset.project_id = NEW.project_id
              AND dataset.run_id = NEW.run_id
          ) THEN
            RAISE EXCEPTION 'Dataset item tenancy mismatch'
              USING ERRCODE = '23514';
          END IF;
          RETURN NEW;
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER dataset_items_tenancy_guard
        BEFORE INSERT OR UPDATE OF
          organization_id, project_id, dataset_id, run_id
        ON control.dataset_items
        FOR EACH ROW
        EXECUTE FUNCTION control.enforce_dataset_item_tenancy()
        """
    )

    op.execute(
        """
        CREATE OR REPLACE FUNCTION security.rdc_dataset_org(
          target_dataset uuid
        )
        RETURNS uuid
        LANGUAGE sql
        STABLE
        SECURITY DEFINER
        SET search_path = control, identity, security, pg_temp
        AS $$
          SELECT dataset.organization_id
          FROM control.datasets dataset
          WHERE dataset.id = target_dataset
            AND security.rdc_has_org_membership(dataset.organization_id)
        $$
        """
    )

    for table_name in ["datasets", "dataset_items"]:
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
    op.execute(
        "DROP POLICY IF EXISTS dataset_items_tenant "
        "ON control.dataset_items"
    )
    op.execute(
        "DROP POLICY IF EXISTS datasets_tenant ON control.datasets"
    )
    op.execute(
        "DROP TRIGGER IF EXISTS dataset_items_tenancy_guard "
        "ON control.dataset_items"
    )
    op.execute(
        "DROP TRIGGER IF EXISTS datasets_tenancy_guard "
        "ON control.datasets"
    )
    op.execute("DROP FUNCTION IF EXISTS security.rdc_dataset_org(uuid)")
    op.execute(
        "DROP FUNCTION IF EXISTS control.enforce_dataset_item_tenancy()"
    )
    op.execute(
        "DROP FUNCTION IF EXISTS control.enforce_dataset_tenancy()"
    )
    op.drop_table("dataset_items", schema="control")
    op.drop_table("datasets", schema="control")
