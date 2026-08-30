"""Add claim-fenced webhook delivery-attempt lifecycle.

Revision ID: 20260830_0031
Revises: 20260830_0030
"""

# ruff: noqa: E501
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260830_0031"
down_revision: str | None = "20260830_0030"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None
UUID = postgresql.UUID(as_uuid=True)


def upgrade() -> None:
    op.create_table(
        "webhook_delivery_attempts",
        sa.Column("id", UUID, server_default=sa.text("gen_random_uuid()"), primary_key=True),
        sa.Column("organization_id", UUID, nullable=False),
        sa.Column("project_id", UUID, nullable=False),
        sa.Column("destination_id", UUID, nullable=False),
        sa.Column("event_id", UUID, nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("attempt_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("max_attempts", sa.Integer(), nullable=False),
        sa.Column("available_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("claim_token", UUID),
        sa.Column("claimed_by", sa.String(128)),
        sa.Column("claim_expires_at", sa.DateTime(timezone=True)),
        sa.Column("last_error_code", sa.String(64)),
        sa.Column("last_http_status", sa.Integer()),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
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
            ["destination_id"], ["control.webhook_destinations.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(["event_id"], ["control.events.id"], ondelete="RESTRICT"),
        sa.UniqueConstraint(
            "destination_id", "event_id", name="uq_webhook_delivery_destination_event"
        ),
        sa.CheckConstraint(
            "status IN ('PENDING','CLAIMED','RETRY_WAIT','SUCCEEDED','DEAD_LETTERED','CANCELLED')",
            name="ck_webhook_delivery_status",
        ),
        sa.CheckConstraint(
            "attempt_count BETWEEN 0 AND max_attempts AND max_attempts BETWEEN 1 AND 8",
            name="ck_webhook_delivery_attempt_bounds",
        ),
        sa.CheckConstraint(
            "(status = 'CLAIMED') = (claim_token IS NOT NULL AND claimed_by IS NOT NULL AND claim_expires_at IS NOT NULL)",
            name="ck_webhook_delivery_claim_shape",
        ),
        sa.CheckConstraint(
            "last_http_status IS NULL OR last_http_status BETWEEN 100 AND 599",
            name="ck_webhook_delivery_http_status",
        ),
        schema="control",
    )
    op.create_index(
        "ix_webhook_delivery_claimable",
        "webhook_delivery_attempts",
        ["status", "available_at", "created_at", "id"],
        schema="control",
    )
    op.create_index(
        "ix_webhook_delivery_project_created",
        "webhook_delivery_attempts",
        ["project_id", "created_at", "id"],
        schema="control",
    )
    op.create_table(
        "webhook_delivery_transitions",
        sa.Column("id", UUID, server_default=sa.text("gen_random_uuid()"), primary_key=True),
        sa.Column("organization_id", UUID, nullable=False),
        sa.Column("project_id", UUID, nullable=False),
        sa.Column("delivery_id", UUID, nullable=False),
        sa.Column("sequence", sa.BigInteger(), nullable=False),
        sa.Column("from_status", sa.String(24)),
        sa.Column("to_status", sa.String(24), nullable=False),
        sa.Column("reason_code", sa.String(64), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("claim_token", UUID),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["identity.organizations.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(["project_id"], ["control.projects.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["delivery_id"], ["control.webhook_delivery_attempts.id"], ondelete="RESTRICT"
        ),
        sa.UniqueConstraint(
            "delivery_id", "sequence", name="uq_webhook_delivery_transition_sequence"
        ),
        schema="control",
    )
    op.execute("ALTER TABLE control.webhook_delivery_attempts ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE control.webhook_delivery_transitions ENABLE ROW LEVEL SECURITY")
    op.execute("""
      CREATE OR REPLACE FUNCTION control.enforce_webhook_delivery_tenancy()
      RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
      SET search_path=pg_catalog,control,identity,security,pg_temp AS $$
      DECLARE destination_row record; event_row record;
      BEGIN
        SELECT organization_id,project_id,status INTO destination_row FROM control.webhook_destinations WHERE id=NEW.destination_id;
        SELECT organization_id,project_id INTO event_row FROM control.events WHERE id=NEW.event_id;
        IF NOT FOUND OR destination_row.organization_id IS NULL OR event_row.organization_id IS NULL OR destination_row.status='DISABLED'
           OR destination_row.organization_id <> event_row.organization_id
           OR destination_row.project_id <> event_row.project_id THEN
          RAISE EXCEPTION 'Webhook delivery lineage is invalid' USING ERRCODE='23514';
        END IF;
        NEW.organization_id := destination_row.organization_id;
        NEW.project_id := destination_row.project_id;
        RETURN NEW;
      END; $$
    """)
    op.execute(
        "CREATE TRIGGER webhook_delivery_tenancy_guard BEFORE INSERT ON control.webhook_delivery_attempts FOR EACH ROW EXECUTE FUNCTION control.enforce_webhook_delivery_tenancy()"
    )
    op.execute("""
      CREATE OR REPLACE FUNCTION control.enforce_webhook_transition()
      RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
      SET search_path=pg_catalog,control,identity,security,pg_temp AS $$
      DECLARE delivery_row record; expected_sequence bigint;
      BEGIN
        SELECT organization_id,project_id,status,attempt_count,claim_token INTO delivery_row FROM control.webhook_delivery_attempts WHERE id=NEW.delivery_id;
        IF NOT FOUND THEN RAISE EXCEPTION 'Webhook delivery reference is invalid' USING ERRCODE='23514'; END IF;
        SELECT COALESCE(MAX(sequence),0)+1 INTO expected_sequence FROM control.webhook_delivery_transitions WHERE delivery_id=NEW.delivery_id;
        IF NEW.sequence <> expected_sequence OR NEW.to_status <> delivery_row.status OR NEW.attempt_count <> delivery_row.attempt_count THEN
          RAISE EXCEPTION 'Webhook transition snapshot is invalid' USING ERRCODE='23514';
        END IF;
        NEW.organization_id:=delivery_row.organization_id; NEW.project_id:=delivery_row.project_id; NEW.created_at:=clock_timestamp();
        RETURN NEW;
      END; $$
    """)
    op.execute(
        "CREATE TRIGGER webhook_transition_guard BEFORE INSERT ON control.webhook_delivery_transitions FOR EACH ROW EXECUTE FUNCTION control.enforce_webhook_transition()"
    )
    op.execute(
        "CREATE OR REPLACE FUNCTION control.webhook_transition_immutable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'Webhook delivery transitions are immutable' USING ERRCODE='23514'; END; $$"
    )
    op.execute(
        "CREATE TRIGGER webhook_transition_immutable BEFORE UPDATE OR DELETE ON control.webhook_delivery_transitions FOR EACH ROW EXECUTE FUNCTION control.webhook_transition_immutable()"
    )
    tenant = "organization_id=security.rdc_current_org_id() AND security.rdc_has_org_membership(organization_id) AND project_id=security.rdc_current_project_id()"
    for table in ("webhook_delivery_attempts", "webhook_delivery_transitions"):
        op.execute(f"CREATE POLICY {table}_select ON control.{table} FOR SELECT USING ({tenant})")
        op.execute(
            f"CREATE POLICY {table}_insert ON control.{table} FOR INSERT WITH CHECK ({tenant})"
        )
    op.execute(
        f"CREATE POLICY webhook_delivery_attempts_update ON control.webhook_delivery_attempts FOR UPDATE USING ({tenant}) WITH CHECK ({tenant})"
    )


def downgrade() -> None:
    op.drop_table("webhook_delivery_transitions", schema="control")
    op.drop_table("webhook_delivery_attempts", schema="control")
    op.execute("DROP FUNCTION IF EXISTS control.webhook_transition_immutable()")
    op.execute("DROP FUNCTION IF EXISTS control.enforce_webhook_transition()")
    op.execute("DROP FUNCTION IF EXISTS control.enforce_webhook_delivery_tenancy()")
