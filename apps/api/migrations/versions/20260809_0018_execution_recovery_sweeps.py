"""Add durable execution recovery sweep health and counters.

Revision ID: 20260809_0018
Revises: 20260809_0017
Create Date: 2026-08-09
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260809_0018"
down_revision: str | None = "20260809_0017"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "execution_recovery_state",
        sa.Column("id", sa.SmallInteger(), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("owner_id", sa.String(length=200)),
        sa.Column("last_started_at", sa.DateTime(timezone=True)),
        sa.Column("last_completed_at", sa.DateTime(timezone=True)),
        sa.Column("last_heartbeat_at", sa.DateTime(timezone=True)),
        sa.Column("last_leases_reaped", sa.Integer(), nullable=False),
        sa.Column("last_cancellations_converged", sa.Integer(), nullable=False),
        sa.Column("total_sweeps", sa.BigInteger(), nullable=False),
        sa.Column("total_failures", sa.BigInteger(), nullable=False),
        sa.Column("last_error_code", sa.String(length=80)),
        sa.Column("last_error_summary", sa.String(length=240)),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.CheckConstraint("id = 1", name="ck_execution_recovery_state_singleton"),
        sa.CheckConstraint(
            "status IN ('NEVER_RUN','HEALTHY','FAILED')",
            name="ck_execution_recovery_state_status",
        ),
        sa.CheckConstraint(
            "last_leases_reaped >= 0 AND last_cancellations_converged >= 0",
            name="ck_execution_recovery_state_last_counts",
        ),
        sa.CheckConstraint(
            "total_sweeps >= 0 AND total_failures >= 0",
            name="ck_execution_recovery_state_total_counts",
        ),
        sa.PrimaryKeyConstraint("id"),
        schema="control",
    )
    op.execute(
        """
        INSERT INTO control.execution_recovery_state (
          id,
          status,
          last_leases_reaped,
          last_cancellations_converged,
          total_sweeps,
          total_failures
        ) VALUES (1, 'NEVER_RUN', 0, 0, 0, 0)
        """
    )


def downgrade() -> None:
    op.drop_table("execution_recovery_state", schema="control")
