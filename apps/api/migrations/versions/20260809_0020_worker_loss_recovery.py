"""Persist worker-loss detection and cleanup recovery evidence.

Revision ID: 20260809_0020
Revises: 20260809_0019
Create Date: 2026-08-09
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260809_0020"
down_revision: str | None = "20260809_0019"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    for name in ("last_lost_at", "last_recovered_at", "last_cleanup_at"):
        op.add_column(
            "worker_identities",
            sa.Column(name, sa.DateTime(timezone=True)),
            schema="security",
        )
    op.add_column(
        "worker_identities",
        sa.Column(
            "cleanup_generation",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
        schema="security",
    )
    op.create_check_constraint(
        "ck_worker_identities_cleanup_generation",
        "worker_identities",
        "cleanup_generation >= 0",
        schema="security",
    )
    op.create_check_constraint(
        "ck_worker_identities_recovery_order",
        "worker_identities",
        "last_recovered_at IS NULL OR (last_lost_at IS NOT NULL "
        "AND last_cleanup_at >= last_recovered_at)",
        schema="security",
    )
    op.create_index(
        "ix_worker_identities_loss_detection",
        "worker_identities",
        ["last_seen_at", "last_lost_at", "last_recovered_at"],
        unique=False,
        schema="security",
        postgresql_where=sa.text(
            "status = 'ACTIVE' AND revoked_at IS NULL"
        ),
    )

    for name, type_ in (
        ("last_workers_lost", sa.Integer()),
        ("last_worker_leases_fenced", sa.Integer()),
        ("total_workers_lost", sa.BigInteger()),
        ("total_worker_leases_fenced", sa.BigInteger()),
    ):
        op.add_column(
            "execution_recovery_state",
            sa.Column(name, type_, nullable=False, server_default="0"),
            schema="control",
        )
    op.create_check_constraint(
        "ck_execution_recovery_state_worker_loss_counts",
        "execution_recovery_state",
        "last_workers_lost >= 0 AND last_worker_leases_fenced >= 0 "
        "AND total_workers_lost >= 0 "
        "AND total_worker_leases_fenced >= 0",
        schema="control",
    )

    op.execute(
        """
        CREATE OR REPLACE FUNCTION security.rdc_worker_is_active()
        RETURNS boolean
        LANGUAGE sql
        STABLE
        SECURITY DEFINER
        SET search_path = security, pg_temp
        AS $$
          SELECT EXISTS (
            SELECT 1
            FROM security.worker_identities worker
            WHERE worker.id = security.rdc_current_worker_id()
              AND worker.status IN ('ACTIVE', 'DRAINING')
              AND worker.revoked_at IS NULL
              AND (worker.expires_at IS NULL OR worker.expires_at > now())
              AND (
                worker.last_lost_at IS NULL
                OR worker.last_recovered_at >= worker.last_lost_at
              )
          )
        $$
        """
    )


def downgrade() -> None:
    op.execute(
        """
        CREATE OR REPLACE FUNCTION security.rdc_worker_is_active()
        RETURNS boolean
        LANGUAGE sql
        STABLE
        SECURITY DEFINER
        SET search_path = security, pg_temp
        AS $$
          SELECT EXISTS (
            SELECT 1
            FROM security.worker_identities worker
            WHERE worker.id = security.rdc_current_worker_id()
              AND worker.status IN ('ACTIVE', 'DRAINING')
              AND worker.revoked_at IS NULL
              AND (worker.expires_at IS NULL OR worker.expires_at > now())
          )
        $$
        """
    )
    op.drop_constraint(
        "ck_execution_recovery_state_worker_loss_counts",
        "execution_recovery_state",
        schema="control",
        type_="check",
    )
    for name in (
        "total_worker_leases_fenced",
        "total_workers_lost",
        "last_worker_leases_fenced",
        "last_workers_lost",
    ):
        op.drop_column("execution_recovery_state", name, schema="control")

    op.drop_index(
        "ix_worker_identities_loss_detection",
        table_name="worker_identities",
        schema="security",
    )
    op.drop_constraint(
        "ck_worker_identities_recovery_order",
        "worker_identities",
        schema="security",
        type_="check",
    )
    op.drop_constraint(
        "ck_worker_identities_cleanup_generation",
        "worker_identities",
        schema="security",
        type_="check",
    )
    for name in (
        "cleanup_generation",
        "last_cleanup_at",
        "last_recovered_at",
        "last_lost_at",
    ):
        op.drop_column("worker_identities", name, schema="security")
