"""Add tenant-scoped webhook destination metadata.

Revision ID: 20260830_0030
Revises: 20260829_0029
"""
# ruff: noqa: E501

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260830_0030"
down_revision: str | None = "20260829_0029"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None
UUID = postgresql.UUID(as_uuid=True)


def upgrade() -> None:
    op.create_table(
        "webhook_destinations",
        sa.Column("id", UUID, server_default=sa.text("gen_random_uuid()"), primary_key=True),
        sa.Column("organization_id", UUID, nullable=False),
        sa.Column("project_id", UUID, nullable=False),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("endpoint_url", sa.String(2048), nullable=False),
        sa.Column("endpoint_origin", sa.String(512), nullable=False),
        sa.Column("event_types", postgresql.JSONB(), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("signing_secret_id", UUID, nullable=False),
        sa.Column("signing_secret_version", sa.BigInteger(), nullable=False),
        sa.Column("created_by_user_id", UUID, nullable=False),
        sa.Column("updated_by_user_id", UUID, nullable=False),
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
        sa.Column("version", sa.BigInteger(), server_default="1", nullable=False),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["identity.organizations.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(["project_id"], ["control.projects.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["signing_secret_id"], ["security.project_secrets.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["identity.users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["updated_by_user_id"], ["identity.users.id"], ondelete="RESTRICT"),
        sa.UniqueConstraint("project_id", "name", name="uq_webhook_destinations_project_name"),
        sa.CheckConstraint(
            "status IN ('PENDING_VERIFICATION','DISABLED')", name="ck_webhook_destinations_status"
        ),
        sa.CheckConstraint(
            "endpoint_url ~ '^https://[^@#]+$'", name="ck_webhook_destinations_https"
        ),
        sa.CheckConstraint(
            "jsonb_typeof(event_types) = 'array' AND jsonb_array_length(event_types) BETWEEN 1 AND 16",
            name="ck_webhook_destinations_events",
        ),
        sa.CheckConstraint(
            "signing_secret_version >= 1 AND version >= 1", name="ck_webhook_destinations_versions"
        ),
        schema="control",
    )
    op.create_index(
        "ix_webhook_destinations_project_created",
        "webhook_destinations",
        ["project_id", "created_at", "id"],
        schema="control",
    )
    op.execute("ALTER TABLE control.webhook_destinations ENABLE ROW LEVEL SECURITY")
    op.execute("""
        CREATE OR REPLACE FUNCTION control.enforce_webhook_destination_tenancy()
        RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, control, identity, security, pg_temp AS $$
        DECLARE derived_org uuid; secret_row record;
        BEGIN
          SELECT organization_id INTO derived_org FROM control.projects
          WHERE id = NEW.project_id AND deleted_at IS NULL;
          IF NOT FOUND THEN RAISE EXCEPTION 'Webhook Project reference is invalid' USING ERRCODE='23514'; END IF;
          SELECT organization_id, project_id, version INTO secret_row
          FROM security.project_secrets WHERE id = NEW.signing_secret_id;
          IF NOT FOUND OR secret_row.organization_id <> derived_org OR secret_row.project_id <> NEW.project_id THEN
            RAISE EXCEPTION 'Webhook signing secret reference is invalid' USING ERRCODE='23514';
          END IF;
          NEW.organization_id := derived_org;
          NEW.signing_secret_version := secret_row.version;
          RETURN NEW;
        END; $$
    """)
    op.execute(
        "CREATE TRIGGER webhook_destination_tenancy_guard BEFORE INSERT OR UPDATE ON control.webhook_destinations FOR EACH ROW EXECUTE FUNCTION control.enforce_webhook_destination_tenancy()"
    )
    tenant = "organization_id = security.rdc_current_org_id() AND security.rdc_has_org_membership(organization_id)"
    project = "project_id = security.rdc_current_project_id()"
    op.execute(
        f"CREATE POLICY webhook_destinations_select ON control.webhook_destinations FOR SELECT USING ({tenant} AND {project})"
    )
    op.execute(
        f"CREATE POLICY webhook_destinations_insert ON control.webhook_destinations FOR INSERT WITH CHECK ({tenant} AND {project})"
    )
    op.execute(
        f"CREATE POLICY webhook_destinations_update ON control.webhook_destinations FOR UPDATE USING ({tenant} AND {project}) WITH CHECK ({tenant} AND {project})"
    )


def downgrade() -> None:
    op.execute(
        "DROP TRIGGER IF EXISTS webhook_destination_tenancy_guard ON control.webhook_destinations"
    )
    op.drop_table("webhook_destinations", schema="control")
    op.execute("DROP FUNCTION IF EXISTS control.enforce_webhook_destination_tenancy()")
