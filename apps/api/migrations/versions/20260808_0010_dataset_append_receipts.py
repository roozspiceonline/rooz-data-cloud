"""Add Phase 1N idempotent Dataset item append receipts and quotas.

Revision ID: 20260808_0010
Revises: 20260808_0009
Create Date: 2026-08-08
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260808_0010"
down_revision: str | None = "20260808_0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

UUID = postgresql.UUID(as_uuid=True)


def upgrade() -> None:
    op.create_table(
        "dataset_append_receipts",
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
        sa.Column(
            "schema_version",
            sa.String(40),
            server_default="rdc.dataset-append/v1",
            nullable=False,
        ),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("request_digest", sa.String(64), nullable=False),
        sa.Column("first_sequence", sa.BigInteger(), nullable=False),
        sa.Column("item_count", sa.Integer(), nullable=False),
        sa.Column("total_bytes", sa.BigInteger(), nullable=False),
        sa.Column("created_by_user_id", UUID, nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "schema_version = 'rdc.dataset-append/v1'",
            name="ck_dataset_append_receipts_schema",
        ),
        sa.CheckConstraint(
            "char_length(idempotency_key) BETWEEN 1 AND 128",
            name="ck_dataset_append_receipts_key_length",
        ),
        sa.CheckConstraint(
            "request_digest ~ '^[0-9a-f]{64}$'",
            name="ck_dataset_append_receipts_digest",
        ),
        sa.CheckConstraint(
            "first_sequence >= 1",
            name="ck_dataset_append_receipts_first_sequence",
        ),
        sa.CheckConstraint(
            "item_count BETWEEN 1 AND 100",
            name="ck_dataset_append_receipts_item_count",
        ),
        sa.CheckConstraint(
            "total_bytes BETWEEN 1 AND 262144",
            name="ck_dataset_append_receipts_total_bytes",
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
        sa.ForeignKeyConstraint(
            ["created_by_user_id"],
            ["identity.users.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "dataset_id",
            "idempotency_key",
            name="uq_dataset_append_receipts_dataset_key",
        ),
        schema="control",
    )
    for name, columns in [
        ("ix_dataset_append_receipts_organization_id", ["organization_id"]),
        ("ix_dataset_append_receipts_project_id", ["project_id"]),
        ("ix_dataset_append_receipts_dataset_id", ["dataset_id"]),
        ("ix_dataset_append_receipts_run_id", ["run_id"]),
    ]:
        op.create_index(
            name,
            "dataset_append_receipts",
            columns,
            schema="control",
        )

    op.create_check_constraint(
        "ck_datasets_item_quota",
        "datasets",
        "item_count <= 100000",
        schema="control",
    )
    op.create_check_constraint(
        "ck_datasets_byte_quota",
        "datasets",
        "total_bytes <= 268435456",
        schema="control",
    )
    op.create_check_constraint(
        "ck_datasets_sequence_counter",
        "datasets",
        "next_sequence = item_count + 1",
        schema="control",
    )

    op.add_column(
        "dataset_items",
        sa.Column("append_receipt_id", UUID, nullable=True),
        schema="control",
    )
    op.create_foreign_key(
        "fk_dataset_items_append_receipt_id",
        "dataset_items",
        "dataset_append_receipts",
        ["append_receipt_id"],
        ["id"],
        source_schema="control",
        referent_schema="control",
        ondelete="RESTRICT",
    )
    op.create_index(
        "ix_dataset_items_append_receipt_id",
        "dataset_items",
        ["append_receipt_id"],
        schema="control",
    )
    op.execute(
        """
        DO $$
        BEGIN
          IF EXISTS (SELECT 1 FROM control.dataset_items) THEN
            RAISE EXCEPTION
              'Phase 1N Increment 3 requires an empty dataset_items table';
          END IF;
        END;
        $$
        """
    )
    op.alter_column(
        "dataset_items",
        "append_receipt_id",
        existing_type=UUID,
        nullable=False,
        schema="control",
    )

    op.execute(
        """
        CREATE OR REPLACE FUNCTION control.enforce_dataset_append_receipt_tenancy()
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
            RAISE EXCEPTION 'Dataset append receipt tenancy mismatch'
              USING ERRCODE = '23514';
          END IF;
          RETURN NEW;
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER dataset_append_receipts_tenancy_guard
        BEFORE INSERT OR UPDATE OF
          organization_id, project_id, dataset_id, run_id
        ON control.dataset_append_receipts
        FOR EACH ROW
        EXECUTE FUNCTION control.enforce_dataset_append_receipt_tenancy()
        """
    )

    op.execute(
        "DROP TRIGGER IF EXISTS dataset_items_tenancy_guard "
        "ON control.dataset_items"
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
            JOIN control.dataset_append_receipts receipt
              ON receipt.id = NEW.append_receipt_id
            WHERE dataset.id = NEW.dataset_id
              AND dataset.organization_id = NEW.organization_id
              AND dataset.project_id = NEW.project_id
              AND dataset.run_id = NEW.run_id
              AND receipt.dataset_id = NEW.dataset_id
              AND receipt.organization_id = NEW.organization_id
              AND receipt.project_id = NEW.project_id
              AND receipt.run_id = NEW.run_id
              AND NEW.sequence >= receipt.first_sequence
              AND NEW.sequence <
                receipt.first_sequence + receipt.item_count
          ) THEN
            RAISE EXCEPTION 'Dataset item receipt or tenancy mismatch'
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
          organization_id, project_id, dataset_id,
          append_receipt_id, run_id, sequence
        ON control.dataset_items
        FOR EACH ROW
        EXECUTE FUNCTION control.enforce_dataset_item_tenancy()
        """
    )

    op.execute(
        """
        CREATE OR REPLACE FUNCTION control.reject_dataset_item_mutation()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
          RAISE EXCEPTION 'Dataset items are append-only'
            USING ERRCODE = '55000';
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER dataset_items_immutable_guard
        BEFORE UPDATE OR DELETE
        ON control.dataset_items
        FOR EACH ROW
        EXECUTE FUNCTION control.reject_dataset_item_mutation()
        """
    )

    op.execute(
        """
        CREATE OR REPLACE FUNCTION control.reject_dataset_append_receipt_mutation()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
          RAISE EXCEPTION 'Dataset append receipts are immutable'
            USING ERRCODE = '55000';
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER dataset_append_receipts_immutable_guard
        BEFORE UPDATE OR DELETE
        ON control.dataset_append_receipts
        FOR EACH ROW
        EXECUTE FUNCTION control.reject_dataset_append_receipt_mutation()
        """
    )

    op.execute(
        'ALTER TABLE "control"."dataset_append_receipts" '
        "ENABLE ROW LEVEL SECURITY"
    )
    op.execute(
        """
        CREATE POLICY dataset_append_receipts_tenant
        ON control.dataset_append_receipts
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
        "DROP POLICY IF EXISTS dataset_append_receipts_tenant "
        "ON control.dataset_append_receipts"
    )
    op.execute(
        "DROP TRIGGER IF EXISTS dataset_append_receipts_immutable_guard "
        "ON control.dataset_append_receipts"
    )
    op.execute(
        "DROP TRIGGER IF EXISTS dataset_items_immutable_guard "
        "ON control.dataset_items"
    )
    op.execute(
        "DROP TRIGGER IF EXISTS dataset_items_tenancy_guard "
        "ON control.dataset_items"
    )
    op.execute(
        "DROP FUNCTION IF EXISTS control.enforce_dataset_item_tenancy()"
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

    op.drop_index(
        "ix_dataset_items_append_receipt_id",
        table_name="dataset_items",
        schema="control",
    )
    op.drop_constraint(
        "fk_dataset_items_append_receipt_id",
        "dataset_items",
        schema="control",
        type_="foreignkey",
    )
    op.drop_column(
        "dataset_items",
        "append_receipt_id",
        schema="control",
    )

    op.execute(
        "DROP TRIGGER IF EXISTS dataset_append_receipts_tenancy_guard "
        "ON control.dataset_append_receipts"
    )
    op.drop_table("dataset_append_receipts", schema="control")
    op.execute(
        "DROP FUNCTION IF EXISTS "
        "control.enforce_dataset_append_receipt_tenancy()"
    )
    op.execute(
        "DROP FUNCTION IF EXISTS "
        "control.reject_dataset_append_receipt_mutation()"
    )
    op.execute(
        "DROP FUNCTION IF EXISTS control.reject_dataset_item_mutation()"
    )

    for name in [
        "ck_datasets_sequence_counter",
        "ck_datasets_byte_quota",
        "ck_datasets_item_quota",
    ]:
        op.drop_constraint(
            name,
            "datasets",
            schema="control",
            type_="check",
        )
