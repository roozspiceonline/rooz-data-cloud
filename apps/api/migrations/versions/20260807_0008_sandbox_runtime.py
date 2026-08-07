"""Add Phase 1H sandbox worker attestation state.

Revision ID: 20260807_0008
Revises: 20260806_0007
Create Date: 2026-08-07
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260807_0008"
down_revision: str | None = "20260806_0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "worker_identities",
        sa.Column("sandbox_profile", sa.String(80)),
        schema="security",
    )
    op.add_column(
        "worker_identities",
        sa.Column("sandbox_attestation_digest", sa.String(64)),
        schema="security",
    )
    op.add_column(
        "worker_identities",
        sa.Column(
            "sandbox_execution_enabled",
            sa.Boolean(),
            server_default=sa.false(),
            nullable=False,
        ),
        schema="security",
    )
    op.add_column(
        "worker_identities",
        sa.Column("sandbox_attested_at", sa.DateTime(timezone=True)),
        schema="security",
    )
    op.create_check_constraint(
        "ck_worker_identities_sandbox_digest",
        "worker_identities",
        "sandbox_attestation_digest IS NULL OR "
        "sandbox_attestation_digest ~ '^[0-9a-f]{64}$'",
        schema="security",
    )
    op.create_check_constraint(
        "ck_worker_identities_sandbox_enabled",
        "worker_identities",
        "NOT sandbox_execution_enabled OR "
        "(sandbox_profile = 'rdc.sandbox/v1' AND "
        "sandbox_attestation_digest IS NOT NULL AND "
        "sandbox_attested_at IS NOT NULL)",
        schema="security",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_worker_identities_sandbox_enabled",
        "worker_identities",
        schema="security",
        type_="check",
    )
    op.drop_constraint(
        "ck_worker_identities_sandbox_digest",
        "worker_identities",
        schema="security",
        type_="check",
    )
    op.drop_column("worker_identities", "sandbox_attested_at", schema="security")
    op.drop_column(
        "worker_identities",
        "sandbox_execution_enabled",
        schema="security",
    )
    op.drop_column(
        "worker_identities",
        "sandbox_attestation_digest",
        schema="security",
    )
    op.drop_column("worker_identities", "sandbox_profile", schema="security")
