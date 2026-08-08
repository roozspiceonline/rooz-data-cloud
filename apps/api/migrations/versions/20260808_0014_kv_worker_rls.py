"""Add Phase 1O lease-scoped worker Key-Value Store RLS policies.

Revision ID: 20260808_0014
Revises: 20260808_0013
Create Date: 2026-08-08
"""

from collections.abc import Sequence

from alembic import op

revision: str = "20260808_0014"
down_revision: str | None = "20260808_0013"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _lease_predicate(table_name: str) -> str:
    return f"""
      security.rdc_worker_is_active()
      AND EXISTS (
        SELECT 1
        FROM control.key_value_stores store
        JOIN control.execution_leases lease
          ON lease.run_id = store.run_id
         AND lease.organization_id = store.organization_id
         AND lease.project_id = store.project_id
        WHERE store.id = {table_name}.store_id
          AND store.scope = 'RUN'
          AND lease.worker_id = security.rdc_current_worker_id()
          AND lease.status = 'ACTIVE'
          AND lease.expires_at > now()
          AND lease.work_kind = 'RUN_START'
      )
    """


def upgrade() -> None:
    store_predicate = """
      security.rdc_worker_is_active()
      AND key_value_stores.scope = 'RUN'
      AND EXISTS (
        SELECT 1
        FROM control.execution_leases lease
        WHERE lease.worker_id = security.rdc_current_worker_id()
          AND lease.status = 'ACTIVE'
          AND lease.expires_at > now()
          AND lease.work_kind = 'RUN_START'
          AND lease.organization_id = key_value_stores.organization_id
          AND lease.project_id = key_value_stores.project_id
          AND lease.run_id = key_value_stores.run_id
      )
    """

    op.execute(
        f"""
        CREATE POLICY key_value_stores_execution_worker_select
        ON control.key_value_stores
        FOR SELECT
        USING ({store_predicate})
        """
    )
    op.execute(
        f"""
        CREATE POLICY key_value_stores_execution_worker_insert
        ON control.key_value_stores
        FOR INSERT
        WITH CHECK ({store_predicate})
        """
    )
    op.execute(
        f"""
        CREATE POLICY key_value_stores_execution_worker_update
        ON control.key_value_stores
        FOR UPDATE
        USING ({store_predicate})
        WITH CHECK ({store_predicate})
        """
    )

    for table_name in (
        "key_value_records",
        "key_value_record_versions",
        "key_value_mutation_receipts",
    ):
        predicate = _lease_predicate(table_name)
        op.execute(
            f"""
            CREATE POLICY {table_name}_execution_worker_select
            ON control.{table_name}
            FOR SELECT
            USING ({predicate})
            """
        )
        op.execute(
            f"""
            CREATE POLICY {table_name}_execution_worker_insert
            ON control.{table_name}
            FOR INSERT
            WITH CHECK ({predicate})
            """
        )

    record_predicate = _lease_predicate("key_value_records")
    op.execute(
        f"""
        CREATE POLICY key_value_records_execution_worker_update
        ON control.key_value_records
        FOR UPDATE
        USING ({record_predicate})
        WITH CHECK ({record_predicate})
        """
    )


def downgrade() -> None:
    policies = [
        ("key_value_records_execution_worker_update", "key_value_records"),
        (
            "key_value_mutation_receipts_execution_worker_insert",
            "key_value_mutation_receipts",
        ),
        (
            "key_value_mutation_receipts_execution_worker_select",
            "key_value_mutation_receipts",
        ),
        (
            "key_value_record_versions_execution_worker_insert",
            "key_value_record_versions",
        ),
        (
            "key_value_record_versions_execution_worker_select",
            "key_value_record_versions",
        ),
        ("key_value_records_execution_worker_insert", "key_value_records"),
        ("key_value_records_execution_worker_select", "key_value_records"),
        ("key_value_stores_execution_worker_update", "key_value_stores"),
        ("key_value_stores_execution_worker_insert", "key_value_stores"),
        ("key_value_stores_execution_worker_select", "key_value_stores"),
    ]
    for policy, table in policies:
        op.execute(
            f"DROP POLICY IF EXISTS {policy} ON control.{table}"
        )
