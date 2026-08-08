"""Add Phase 1O versioned KV records and object-backed values.

Revision ID: 20260808_0013
Revises: 20260808_0012
Create Date: 2026-08-08
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260808_0013"
down_revision: str | None = "20260808_0012"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

UUID = postgresql.UUID(as_uuid=True)


def upgrade() -> None:
    op.create_table(
        "key_value_records",
        sa.Column(
            "id",
            UUID,
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("organization_id", UUID, nullable=False),
        sa.Column("project_id", UUID, nullable=False),
        sa.Column("store_id", UUID, nullable=False),
        sa.Column("key", sa.String(256), nullable=False),
        sa.Column(
            "current_version",
            sa.BigInteger(),
            server_default="1",
            nullable=False,
        ),
        sa.Column(
            "deleted",
            sa.Boolean(),
            server_default=sa.false(),
            nullable=False,
        ),
        sa.Column(
            "current_size_bytes",
            sa.BigInteger(),
            server_default="0",
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
            "key ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$'",
            name="ck_key_value_records_key",
        ),
        sa.CheckConstraint(
            "current_version >= 1",
            name="ck_key_value_records_current_version",
        ),
        sa.CheckConstraint(
            "current_size_bytes >= 0",
            name="ck_key_value_records_current_size",
        ),
        sa.CheckConstraint(
            "(deleted = false) OR current_size_bytes = 0",
            name="ck_key_value_records_deleted_size",
        ),
        sa.CheckConstraint(
            "version >= 1",
            name="ck_key_value_records_version",
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
            ["store_id"],
            ["control.key_value_stores.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["created_by_user_id"],
            ["identity.users.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "store_id",
            "key",
            name="uq_key_value_records_store_key",
        ),
        schema="control",
    )

    op.create_table(
        "key_value_record_versions",
        sa.Column(
            "id",
            UUID,
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("organization_id", UUID, nullable=False),
        sa.Column("project_id", UUID, nullable=False),
        sa.Column("store_id", UUID, nullable=False),
        sa.Column("record_id", UUID, nullable=False),
        sa.Column("version", sa.BigInteger(), nullable=False),
        sa.Column("operation", sa.String(8), nullable=False),
        sa.Column(
            "tombstone",
            sa.Boolean(),
            server_default=sa.false(),
            nullable=False,
        ),
        sa.Column("content_type", sa.String(160), nullable=True),
        sa.Column("encoding", sa.String(16), nullable=True),
        sa.Column("object_key", sa.String(1024), nullable=True),
        sa.Column("value_sha256", sa.String(64), nullable=True),
        sa.Column(
            "size_bytes",
            sa.BigInteger(),
            server_default="0",
            nullable=False,
        ),
        sa.Column("created_by_user_id", UUID, nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "version >= 1",
            name="ck_key_value_record_versions_version",
        ),
        sa.CheckConstraint(
            "operation IN ('SET', 'DELETE')",
            name="ck_key_value_record_versions_operation",
        ),
        sa.CheckConstraint(
            "size_bytes >= 0",
            name="ck_key_value_record_versions_size",
        ),
        sa.CheckConstraint(
            """
            (
              operation = 'SET'
              AND tombstone = false
              AND content_type IS NOT NULL
              AND encoding IS NOT NULL
              AND object_key IS NOT NULL
              AND value_sha256 IS NOT NULL
              AND value_sha256 ~ '^[0-9a-f]{64}$'
              AND (
                (content_type = 'application/json' AND encoding = 'json')
                OR (
                  content_type = 'text/plain; charset=utf-8'
                  AND encoding = 'utf8'
                )
                OR (
                  content_type = 'application/octet-stream'
                  AND encoding = 'base64'
                )
              )
            )
            OR
            (
              operation = 'DELETE'
              AND tombstone = true
              AND content_type IS NULL
              AND encoding IS NULL
              AND object_key IS NULL
              AND value_sha256 IS NULL
              AND size_bytes = 0
            )
            """,
            name="ck_key_value_record_versions_value_lineage",
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
            ["store_id"],
            ["control.key_value_stores.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["record_id"],
            ["control.key_value_records.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["created_by_user_id"],
            ["identity.users.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "record_id",
            "version",
            name="uq_key_value_record_versions_record_version",
        ),
        sa.UniqueConstraint(
            "object_key",
            name="uq_key_value_record_versions_object_key",
        ),
        schema="control",
    )

    op.create_table(
        "key_value_mutation_receipts",
        sa.Column(
            "id",
            UUID,
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("organization_id", UUID, nullable=False),
        sa.Column("project_id", UUID, nullable=False),
        sa.Column("store_id", UUID, nullable=False),
        sa.Column("record_id", UUID, nullable=False),
        sa.Column("record_version_id", UUID, nullable=False),
        sa.Column(
            "schema_version",
            sa.String(40),
            server_default="rdc.kv-write/v1",
            nullable=False,
        ),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("request_digest", sa.String(64), nullable=False),
        sa.Column("operation", sa.String(8), nullable=False),
        sa.Column("key", sa.String(256), nullable=False),
        sa.Column("expected_version", sa.BigInteger(), nullable=True),
        sa.Column("result_version", sa.BigInteger(), nullable=False),
        sa.Column("value_sha256", sa.String(64), nullable=True),
        sa.Column(
            "size_bytes",
            sa.BigInteger(),
            server_default="0",
            nullable=False,
        ),
        sa.Column("created_by_user_id", UUID, nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "schema_version = 'rdc.kv-write/v1'",
            name="ck_key_value_mutation_receipts_schema",
        ),
        sa.CheckConstraint(
            """
            idempotency_key
            ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
            """,
            name="ck_key_value_mutation_receipts_idempotency",
        ),
        sa.CheckConstraint(
            "request_digest ~ '^[0-9a-f]{64}$'",
            name="ck_key_value_mutation_receipts_request_digest",
        ),
        sa.CheckConstraint(
            "operation IN ('SET', 'DELETE')",
            name="ck_key_value_mutation_receipts_operation",
        ),
        sa.CheckConstraint(
            "key ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$'",
            name="ck_key_value_mutation_receipts_key",
        ),
        sa.CheckConstraint(
            "expected_version IS NULL OR expected_version >= 0",
            name="ck_key_value_mutation_receipts_expected_version",
        ),
        sa.CheckConstraint(
            "result_version >= 1",
            name="ck_key_value_mutation_receipts_result_version",
        ),
        sa.CheckConstraint(
            "size_bytes >= 0",
            name="ck_key_value_mutation_receipts_size",
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
            ["store_id"],
            ["control.key_value_stores.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["record_id"],
            ["control.key_value_records.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["record_version_id"],
            ["control.key_value_record_versions.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["created_by_user_id"],
            ["identity.users.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "store_id",
            "idempotency_key",
            name="uq_key_value_mutation_receipts_store_key",
        ),
        sa.UniqueConstraint(
            "record_version_id",
            name="uq_key_value_mutation_receipts_record_version",
        ),
        schema="control",
    )

    for table_name, index_name, columns in [
        (
            "key_value_records",
            "ix_key_value_records_organization_id",
            ["organization_id"],
        ),
        (
            "key_value_records",
            "ix_key_value_records_project_id",
            ["project_id"],
        ),
        (
            "key_value_records",
            "ix_key_value_records_store_id",
            ["store_id"],
        ),
        (
            "key_value_record_versions",
            "ix_key_value_record_versions_organization_id",
            ["organization_id"],
        ),
        (
            "key_value_record_versions",
            "ix_key_value_record_versions_project_id",
            ["project_id"],
        ),
        (
            "key_value_record_versions",
            "ix_key_value_record_versions_store_id",
            ["store_id"],
        ),
        (
            "key_value_record_versions",
            "ix_key_value_record_versions_record_id",
            ["record_id"],
        ),
        (
            "key_value_mutation_receipts",
            "ix_key_value_mutation_receipts_organization_id",
            ["organization_id"],
        ),
        (
            "key_value_mutation_receipts",
            "ix_key_value_mutation_receipts_project_id",
            ["project_id"],
        ),
        (
            "key_value_mutation_receipts",
            "ix_key_value_mutation_receipts_store_id",
            ["store_id"],
        ),
        (
            "key_value_mutation_receipts",
            "ix_key_value_mutation_receipts_record_id",
            ["record_id"],
        ),
        (
            "key_value_mutation_receipts",
            "ix_key_value_mutation_receipts_record_version_id",
            ["record_version_id"],
        ),
    ]:
        op.create_index(
            index_name,
            table_name,
            columns,
            schema="control",
        )

    op.create_unique_constraint(
        "uq_key_value_records_id_current_version",
        "key_value_records",
        ["id", "current_version"],
        schema="control",
    )
    op.create_foreign_key(
        "fk_key_value_records_current_version",
        "key_value_records",
        "key_value_record_versions",
        ["id", "current_version"],
        ["record_id", "version"],
        source_schema="control",
        referent_schema="control",
        deferrable=True,
        initially="DEFERRED",
    )

    op.create_check_constraint(
        "ck_key_value_stores_record_quota",
        "key_value_stores",
        "record_count <= 10000",
        schema="control",
    )
    op.create_check_constraint(
        "ck_key_value_stores_byte_quota",
        "key_value_stores",
        "total_bytes <= 268435456",
        schema="control",
    )

    op.execute(
        """
        CREATE OR REPLACE FUNCTION control.enforce_key_value_record_tenancy()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = control, identity, security, pg_temp
        AS $$
        BEGIN
          IF NOT EXISTS (
            SELECT 1
            FROM control.key_value_stores store
            WHERE store.id = NEW.store_id
              AND store.organization_id = NEW.organization_id
              AND store.project_id = NEW.project_id
          ) THEN
            RAISE EXCEPTION 'KV record store tenancy mismatch'
              USING ERRCODE = '23514';
          END IF;

          IF TG_OP = 'UPDATE' THEN
            IF OLD.organization_id IS DISTINCT FROM NEW.organization_id
              OR OLD.project_id IS DISTINCT FROM NEW.project_id
              OR OLD.store_id IS DISTINCT FROM NEW.store_id
              OR OLD.key IS DISTINCT FROM NEW.key
              OR OLD.created_by_user_id IS DISTINCT FROM NEW.created_by_user_id
            THEN
              RAISE EXCEPTION 'KV record identity fields are immutable'
                USING ERRCODE = '23514';
            END IF;

            IF NEW.current_version <> OLD.current_version + 1
              OR NEW.version <> OLD.version + 1
            THEN
              RAISE EXCEPTION 'KV record version must advance exactly once'
                USING ERRCODE = '23514';
            END IF;
          END IF;

          RETURN NEW;
        END;
        $$
        """
    )

    op.execute(
        """
        CREATE TRIGGER key_value_records_tenancy_guard
        BEFORE INSERT OR UPDATE
        ON control.key_value_records
        FOR EACH ROW
        EXECUTE FUNCTION control.enforce_key_value_record_tenancy()
        """
    )

    op.execute(
        """
        CREATE OR REPLACE FUNCTION
          control.enforce_key_value_record_version_lineage()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = control, identity, security, pg_temp
        AS $$
        BEGIN
          IF TG_OP IN ('UPDATE', 'DELETE') THEN
            RAISE EXCEPTION 'KV record version history is immutable'
              USING ERRCODE = '23514';
          END IF;

          IF NOT EXISTS (
            SELECT 1
            FROM control.key_value_records record
            WHERE record.id = NEW.record_id
              AND record.store_id = NEW.store_id
              AND record.organization_id = NEW.organization_id
              AND record.project_id = NEW.project_id
          ) THEN
            RAISE EXCEPTION 'KV record version lineage mismatch'
              USING ERRCODE = '23514';
          END IF;

          RETURN NEW;
        END;
        $$
        """
    )

    op.execute(
        """
        CREATE TRIGGER key_value_record_versions_lineage_guard
        BEFORE INSERT OR UPDATE OR DELETE
        ON control.key_value_record_versions
        FOR EACH ROW
        EXECUTE FUNCTION
          control.enforce_key_value_record_version_lineage()
        """
    )

    op.execute(
        """
        CREATE OR REPLACE FUNCTION
          control.enforce_key_value_mutation_receipt_lineage()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = control, identity, security, pg_temp
        AS $$
        BEGIN
          IF TG_OP IN ('UPDATE', 'DELETE') THEN
            RAISE EXCEPTION 'KV mutation receipts are immutable'
              USING ERRCODE = '23514';
          END IF;

          IF NOT EXISTS (
            SELECT 1
            FROM control.key_value_record_versions version_row
            JOIN control.key_value_records record
              ON record.id = version_row.record_id
            WHERE version_row.id = NEW.record_version_id
              AND version_row.record_id = NEW.record_id
              AND version_row.store_id = NEW.store_id
              AND version_row.organization_id = NEW.organization_id
              AND version_row.project_id = NEW.project_id
              AND version_row.version = NEW.result_version
              AND version_row.operation = NEW.operation
              AND version_row.value_sha256 IS NOT DISTINCT FROM NEW.value_sha256
              AND version_row.size_bytes = NEW.size_bytes
              AND record.key = NEW.key
          ) THEN
            RAISE EXCEPTION 'KV mutation receipt lineage mismatch'
              USING ERRCODE = '23514';
          END IF;

          RETURN NEW;
        END;
        $$
        """
    )

    op.execute(
        """
        CREATE TRIGGER key_value_mutation_receipts_lineage_guard
        BEFORE INSERT OR UPDATE OR DELETE
        ON control.key_value_mutation_receipts
        FOR EACH ROW
        EXECUTE FUNCTION
          control.enforce_key_value_mutation_receipt_lineage()
        """
    )

    op.execute(
        """
        CREATE OR REPLACE FUNCTION
          control.enforce_key_value_record_current_pointer()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = control, identity, security, pg_temp
        AS $$
        BEGIN
          IF NOT EXISTS (
            SELECT 1
            FROM control.key_value_record_versions version_row
            WHERE version_row.record_id = NEW.id
              AND version_row.version = NEW.current_version
              AND version_row.organization_id = NEW.organization_id
              AND version_row.project_id = NEW.project_id
              AND version_row.store_id = NEW.store_id
              AND version_row.tombstone = NEW.deleted
              AND version_row.size_bytes = NEW.current_size_bytes
          ) THEN
            RAISE EXCEPTION 'KV current-version pointer is inconsistent'
              USING ERRCODE = '23514';
          END IF;
          RETURN NEW;
        END;
        $$
        """
    )

    op.execute(
        """
        CREATE CONSTRAINT TRIGGER key_value_records_current_pointer_guard
        AFTER INSERT OR UPDATE
        ON control.key_value_records
        DEFERRABLE INITIALLY DEFERRED
        FOR EACH ROW
        EXECUTE FUNCTION
          control.enforce_key_value_record_current_pointer()
        """
    )

    op.execute(
        """
        CREATE OR REPLACE FUNCTION security.rdc_key_value_record_org(
          target_record uuid
        )
        RETURNS uuid
        LANGUAGE sql
        STABLE
        SECURITY DEFINER
        SET search_path = control, identity, security, pg_temp
        AS $$
          SELECT record.organization_id
          FROM control.key_value_records record
          WHERE record.id = target_record
            AND security.rdc_has_org_membership(record.organization_id)
        $$
        """
    )

    for table_name in [
        "key_value_records",
        "key_value_record_versions",
        "key_value_mutation_receipts",
    ]:
        op.execute(
            f'ALTER TABLE "control"."{table_name}" '
            "ENABLE ROW LEVEL SECURITY"
        )

    for table_name, policy_name in [
        ("key_value_records", "key_value_records_tenant"),
        (
            "key_value_record_versions",
            "key_value_record_versions_tenant",
        ),
        (
            "key_value_mutation_receipts",
            "key_value_mutation_receipts_tenant",
        ),
    ]:
        op.execute(
            f"""
            CREATE POLICY {policy_name}
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
    for table_name, policy_name in [
        (
            "key_value_mutation_receipts",
            "key_value_mutation_receipts_tenant",
        ),
        (
            "key_value_record_versions",
            "key_value_record_versions_tenant",
        ),
        ("key_value_records", "key_value_records_tenant"),
    ]:
        op.execute(
            f"DROP POLICY IF EXISTS {policy_name} "
            f"ON control.{table_name}"
        )

    op.execute(
        "DROP FUNCTION IF EXISTS security.rdc_key_value_record_org(uuid)"
    )
    op.execute(
        """
        DROP TRIGGER IF EXISTS key_value_records_current_pointer_guard
        ON control.key_value_records
        """
    )
    op.execute(
        """
        DROP TRIGGER IF EXISTS key_value_mutation_receipts_lineage_guard
        ON control.key_value_mutation_receipts
        """
    )
    op.execute(
        """
        DROP TRIGGER IF EXISTS key_value_record_versions_lineage_guard
        ON control.key_value_record_versions
        """
    )
    op.execute(
        """
        DROP TRIGGER IF EXISTS key_value_records_tenancy_guard
        ON control.key_value_records
        """
    )

    op.execute(
        """
        DROP FUNCTION IF EXISTS
          control.enforce_key_value_record_current_pointer()
        """
    )
    op.execute(
        """
        DROP FUNCTION IF EXISTS
          control.enforce_key_value_mutation_receipt_lineage()
        """
    )
    op.execute(
        """
        DROP FUNCTION IF EXISTS
          control.enforce_key_value_record_version_lineage()
        """
    )
    op.execute(
        """
        DROP FUNCTION IF EXISTS
          control.enforce_key_value_record_tenancy()
        """
    )

    op.drop_constraint(
        "fk_key_value_records_current_version",
        "key_value_records",
        schema="control",
        type_="foreignkey",
    )
    op.drop_constraint(
        "uq_key_value_records_id_current_version",
        "key_value_records",
        schema="control",
        type_="unique",
    )
    op.drop_constraint(
        "ck_key_value_stores_byte_quota",
        "key_value_stores",
        schema="control",
        type_="check",
    )
    op.drop_constraint(
        "ck_key_value_stores_record_quota",
        "key_value_stores",
        schema="control",
        type_="check",
    )
    op.drop_table("key_value_mutation_receipts", schema="control")
    op.drop_table("key_value_record_versions", schema="control")
    op.drop_table("key_value_records", schema="control")
