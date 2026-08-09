"""Persist and index execution concurrency admission limits.

Revision ID: 20260809_0019
Revises: 20260809_0018
Create Date: 2026-08-09
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260809_0019"
down_revision: str | None = "20260809_0018"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "projects",
        sa.Column(
            "max_active_leases",
            sa.Integer(),
            nullable=False,
            server_default="20",
        ),
        schema="control",
    )
    op.create_check_constraint(
        "ck_projects_max_active_leases",
        "projects",
        "max_active_leases BETWEEN 1 AND 1000",
        schema="control",
    )
    op.execute(
        """
        UPDATE security.worker_identities
        SET max_concurrency = LEAST(max_concurrency, 16)
        WHERE max_concurrency > 16
        """
    )
    op.drop_constraint(
        "ck_worker_identities_max_concurrency",
        "worker_identities",
        schema="security",
        type_="check",
    )
    op.create_check_constraint(
        "ck_worker_identities_max_concurrency",
        "worker_identities",
        "max_concurrency BETWEEN 1 AND 16",
        schema="security",
    )
    op.execute(
        """
        CREATE INDEX ix_execution_leases_active_project_admission
        ON control.execution_leases (
          project_id,
          expires_at,
          deadline_at
        )
        WHERE status = 'ACTIVE'
          AND work_kind IN ('BUILD', 'RUN_START')
        """
    )
    op.execute(
        """
        CREATE INDEX ix_execution_leases_active_worker_admission
        ON control.execution_leases (
          worker_id,
          expires_at,
          deadline_at
        )
        WHERE status = 'ACTIVE'
        """
    )


def downgrade() -> None:
    op.drop_index(
        "ix_execution_leases_active_worker_admission",
        table_name="execution_leases",
        schema="control",
    )
    op.drop_index(
        "ix_execution_leases_active_project_admission",
        table_name="execution_leases",
        schema="control",
    )
    op.drop_constraint(
        "ck_worker_identities_max_concurrency",
        "worker_identities",
        schema="security",
        type_="check",
    )
    op.create_check_constraint(
        "ck_worker_identities_max_concurrency",
        "worker_identities",
        "max_concurrency BETWEEN 1 AND 256",
        schema="security",
    )
    op.drop_constraint(
        "ck_projects_max_active_leases",
        "projects",
        schema="control",
        type_="check",
    )
    op.drop_column("projects", "max_active_leases", schema="control")
