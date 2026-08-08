"""Add Phase 1N lease-scoped worker Dataset RLS policies.

Revision ID: 20260808_0011
Revises: 20260808_0010
Create Date: 2026-08-08
"""

from collections.abc import Sequence

from alembic import op

revision: str = "20260808_0011"
down_revision: str | None = "20260808_0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        CREATE POLICY datasets_execution_worker_select
        ON control.datasets
        FOR SELECT
        USING (
          security.rdc_worker_is_active()
          AND EXISTS (
            SELECT 1
            FROM control.execution_leases lease
            WHERE lease.worker_id = security.rdc_current_worker_id()
              AND lease.status = 'ACTIVE'
              AND lease.expires_at > now()
              AND lease.work_kind = 'RUN_START'
              AND lease.organization_id = datasets.organization_id
              AND lease.project_id = datasets.project_id
              AND lease.run_id = datasets.run_id
          )
        )
        """
    )
    op.execute(
        """
        CREATE POLICY datasets_execution_worker_insert
        ON control.datasets
        FOR INSERT
        WITH CHECK (
          security.rdc_worker_is_active()
          AND EXISTS (
            SELECT 1
            FROM control.execution_leases lease
            WHERE lease.worker_id = security.rdc_current_worker_id()
              AND lease.status = 'ACTIVE'
              AND lease.expires_at > now()
              AND lease.work_kind = 'RUN_START'
              AND lease.organization_id = datasets.organization_id
              AND lease.project_id = datasets.project_id
              AND lease.run_id = datasets.run_id
          )
        )
        """
    )
    op.execute(
        """
        CREATE POLICY datasets_execution_worker_update
        ON control.datasets
        FOR UPDATE
        USING (
          security.rdc_worker_is_active()
          AND EXISTS (
            SELECT 1
            FROM control.execution_leases lease
            WHERE lease.worker_id = security.rdc_current_worker_id()
              AND lease.status = 'ACTIVE'
              AND lease.expires_at > now()
              AND lease.work_kind = 'RUN_START'
              AND lease.organization_id = datasets.organization_id
              AND lease.project_id = datasets.project_id
              AND lease.run_id = datasets.run_id
          )
        )
        WITH CHECK (
          security.rdc_worker_is_active()
          AND EXISTS (
            SELECT 1
            FROM control.execution_leases lease
            WHERE lease.worker_id = security.rdc_current_worker_id()
              AND lease.status = 'ACTIVE'
              AND lease.expires_at > now()
              AND lease.work_kind = 'RUN_START'
              AND lease.organization_id = datasets.organization_id
              AND lease.project_id = datasets.project_id
              AND lease.run_id = datasets.run_id
          )
        )
        """
    )
    op.execute(
        """
        CREATE POLICY dataset_items_execution_worker_insert
        ON control.dataset_items
        FOR INSERT
        WITH CHECK (
          security.rdc_worker_is_active()
          AND EXISTS (
            SELECT 1
            FROM control.execution_leases lease
            WHERE lease.worker_id = security.rdc_current_worker_id()
              AND lease.status = 'ACTIVE'
              AND lease.expires_at > now()
              AND lease.work_kind = 'RUN_START'
              AND lease.organization_id = dataset_items.organization_id
              AND lease.project_id = dataset_items.project_id
              AND lease.run_id = dataset_items.run_id
          )
        )
        """
    )
    op.execute(
        """
        CREATE POLICY dataset_append_receipts_execution_worker_select
        ON control.dataset_append_receipts
        FOR SELECT
        USING (
          security.rdc_worker_is_active()
          AND EXISTS (
            SELECT 1
            FROM control.execution_leases lease
            WHERE lease.worker_id = security.rdc_current_worker_id()
              AND lease.status = 'ACTIVE'
              AND lease.expires_at > now()
              AND lease.work_kind = 'RUN_START'
              AND lease.organization_id =
                dataset_append_receipts.organization_id
              AND lease.project_id =
                dataset_append_receipts.project_id
              AND lease.run_id = dataset_append_receipts.run_id
          )
        )
        """
    )
    op.execute(
        """
        CREATE POLICY dataset_append_receipts_execution_worker_insert
        ON control.dataset_append_receipts
        FOR INSERT
        WITH CHECK (
          security.rdc_worker_is_active()
          AND EXISTS (
            SELECT 1
            FROM control.execution_leases lease
            WHERE lease.worker_id = security.rdc_current_worker_id()
              AND lease.status = 'ACTIVE'
              AND lease.expires_at > now()
              AND lease.work_kind = 'RUN_START'
              AND lease.organization_id =
                dataset_append_receipts.organization_id
              AND lease.project_id =
                dataset_append_receipts.project_id
              AND lease.run_id = dataset_append_receipts.run_id
          )
        )
        """
    )


def downgrade() -> None:
    for policy, table in [
        (
            "dataset_append_receipts_execution_worker_insert",
            "dataset_append_receipts",
        ),
        (
            "dataset_append_receipts_execution_worker_select",
            "dataset_append_receipts",
        ),
        ("dataset_items_execution_worker_insert", "dataset_items"),
        ("datasets_execution_worker_update", "datasets"),
        ("datasets_execution_worker_insert", "datasets"),
        ("datasets_execution_worker_select", "datasets"),
    ]:
        op.execute(
            f"DROP POLICY IF EXISTS {policy} ON control.{table}"
        )
