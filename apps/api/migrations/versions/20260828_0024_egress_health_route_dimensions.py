"""Add server-derived route dimensions to egress health observations.

Revision ID: 20260828_0024
Revises: 20260828_0023
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260828_0024"
down_revision: str | None = "20260828_0023"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "egress_health_observations",
        sa.Column(
            "provider_key",
            sa.String(64),
            server_default="legacy",
            nullable=False,
        ),
        schema="control",
    )
    op.add_column(
        "egress_health_observations",
        sa.Column(
            "region_key",
            sa.String(64),
            server_default="unknown",
            nullable=False,
        ),
        schema="control",
    )
    op.create_check_constraint(
        "ck_egress_health_observations_provider_key",
        "egress_health_observations",
        "provider_key ~ '^[a-z0-9][a-z0-9._-]{0,63}$'",
        schema="control",
    )
    op.create_check_constraint(
        "ck_egress_health_observations_region_key",
        "egress_health_observations",
        "region_key ~ '^[a-z0-9][a-z0-9._-]{0,63}$'",
        schema="control",
    )
    op.create_index(
        "ix_egress_health_observations_project_route_time",
        "egress_health_observations",
        ["project_id", "provider_key", "region_key", "observed_at"],
        schema="control",
    )


def downgrade() -> None:
    op.drop_index(
        "ix_egress_health_observations_project_route_time",
        table_name="egress_health_observations",
        schema="control",
    )
    op.drop_constraint(
        "ck_egress_health_observations_region_key",
        "egress_health_observations",
        schema="control",
        type_="check",
    )
    op.drop_constraint(
        "ck_egress_health_observations_provider_key",
        "egress_health_observations",
        schema="control",
        type_="check",
    )
    op.drop_column(
        "egress_health_observations", "region_key", schema="control"
    )
    op.drop_column(
        "egress_health_observations", "provider_key", schema="control"
    )
