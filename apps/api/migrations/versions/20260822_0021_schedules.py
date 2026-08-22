"""Add tenant-scoped schedules and immutable trigger history."""
# ruff: noqa: E501

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260822_0021"
down_revision: str | None = "20260809_0020"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None
UUID = postgresql.UUID(as_uuid=True)


def upgrade() -> None:
    op.create_table(
        "schedules",
        sa.Column("id", UUID, server_default=sa.text("gen_random_uuid()"), primary_key=True),
        sa.Column("organization_id", UUID, nullable=False),
        sa.Column("project_id", UUID, nullable=False),
        sa.Column("agent_id", UUID, nullable=False),
        sa.Column("agent_version_id", UUID, nullable=False),
        sa.Column("build_id", UUID, nullable=False),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("status", sa.String(16), server_default="ACTIVE", nullable=False),
        sa.Column("cadence_kind", sa.String(16), nullable=False),
        sa.Column("starts_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("interval_seconds", sa.Integer()),
        sa.Column("missed_run_policy", sa.String(16), nullable=False),
        sa.Column("misfire_grace_seconds", sa.Integer(), nullable=False),
        sa.Column("run_payload", postgresql.JSONB(), nullable=False),
        sa.Column("next_fire_at", sa.DateTime(timezone=True)),
        sa.Column("last_triggered_at", sa.DateTime(timezone=True)),
        sa.Column("fired_count", sa.BigInteger(), server_default="0", nullable=False),
        sa.Column("skipped_count", sa.BigInteger(), server_default="0", nullable=False),
        sa.Column("failed_count", sa.BigInteger(), server_default="0", nullable=False),
        sa.Column("created_by_user_id", UUID, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
        sa.Column("version", sa.BigInteger(), server_default="1", nullable=False),
        sa.UniqueConstraint("project_id", "name", name="uq_schedules_project_name"),
        sa.CheckConstraint("name ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'", name="ck_schedules_name"),
        sa.CheckConstraint("status IN ('ACTIVE','PAUSED','COMPLETED')", name="ck_schedules_status"),
        sa.CheckConstraint("cadence_kind IN ('ONCE','INTERVAL')", name="ck_schedules_cadence_kind"),
        sa.CheckConstraint("missed_run_policy IN ('SKIP','FIRE_ONCE')", name="ck_schedules_missed_run_policy"),
        sa.CheckConstraint("misfire_grace_seconds BETWEEN 60 AND 86400", name="ck_schedules_misfire_grace"),
        sa.CheckConstraint("jsonb_typeof(run_payload) = 'object'", name="ck_schedules_run_payload_object"),
        sa.CheckConstraint("fired_count >= 0 AND skipped_count >= 0 AND failed_count >= 0", name="ck_schedules_nonnegative_counts"),
        sa.CheckConstraint("(cadence_kind = 'ONCE' AND interval_seconds IS NULL) OR (cadence_kind = 'INTERVAL' AND interval_seconds BETWEEN 60 AND 31536000)", name="ck_schedules_cadence_fields"),
        sa.CheckConstraint("(status = 'COMPLETED' AND cadence_kind = 'ONCE' AND next_fire_at IS NULL) OR status <> 'COMPLETED'", name="ck_schedules_completed_once"),
        sa.ForeignKeyConstraint(["organization_id"], ["identity.organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["project_id"], ["control.projects.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["agent_id"], ["control.agents.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["agent_version_id"], ["control.agent_versions.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["build_id"], ["control.builds.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["identity.users.id"], ondelete="RESTRICT"),
        schema="control",
    )
    op.create_table(
        "schedule_triggers",
        sa.Column("id", UUID, server_default=sa.text("gen_random_uuid()"), primary_key=True),
        sa.Column("organization_id", UUID, nullable=False),
        sa.Column("project_id", UUID, nullable=False),
        sa.Column("schedule_id", UUID, nullable=False),
        sa.Column("run_id", UUID),
        sa.Column("scheduled_for", sa.DateTime(timezone=True), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("outcome", sa.String(16), nullable=False),
        sa.Column("reason", sa.String(80), nullable=False),
        sa.Column("error_code", sa.String(80)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
        sa.UniqueConstraint("schedule_id", "scheduled_for", name="uq_schedule_triggers_schedule_instant"),
        sa.CheckConstraint("outcome IN ('FIRED','SKIPPED','FAILED')", name="ck_schedule_triggers_outcome"),
        sa.CheckConstraint("(outcome = 'FIRED') = (run_id IS NOT NULL)", name="ck_schedule_triggers_run_outcome"),
        sa.CheckConstraint("(outcome = 'FAILED') = (error_code IS NOT NULL)", name="ck_schedule_triggers_error_outcome"),
        sa.ForeignKeyConstraint(["organization_id"], ["identity.organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["project_id"], ["control.projects.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["schedule_id"], ["control.schedules.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["run_id"], ["control.runs.id"], ondelete="RESTRICT"),
        schema="control",
    )
    for table in ("schedules", "schedule_triggers"):
        op.create_index(f"ix_{table}_organization_id", table, ["organization_id"], schema="control")
        op.create_index(f"ix_{table}_project_id", table, ["project_id"], schema="control")
        op.execute(f"ALTER TABLE control.{table} ENABLE ROW LEVEL SECURITY")
    op.create_index("ix_schedules_agent_id", "schedules", ["agent_id"], schema="control")
    op.create_index("ix_schedules_agent_version_id", "schedules", ["agent_version_id"], schema="control")
    op.create_index("ix_schedules_build_id", "schedules", ["build_id"], schema="control")
    op.create_index("ix_schedule_triggers_schedule_id", "schedule_triggers", ["schedule_id"], schema="control")
    op.create_index("ix_schedule_triggers_run_id", "schedule_triggers", ["run_id"], schema="control")
    op.execute("CREATE INDEX ix_schedules_due ON control.schedules (next_fire_at, id) WHERE status = 'ACTIVE' AND next_fire_at IS NOT NULL")

    tenant = "organization_id = security.rdc_current_org_id() AND security.rdc_has_org_membership(organization_id)"
    dispatcher = "NULLIF(current_setting('rdc.schedule_dispatcher', true), '') = '1'"
    for table in ("schedules", "schedule_triggers"):
        op.execute(f"CREATE POLICY {table}_tenant_select ON control.{table} FOR SELECT USING ({tenant})")
    op.execute(f"CREATE POLICY schedules_tenant_insert ON control.schedules FOR INSERT WITH CHECK ({tenant})")
    op.execute(f"CREATE POLICY schedules_tenant_update ON control.schedules FOR UPDATE USING ({tenant}) WITH CHECK ({tenant})")
    op.execute(f"CREATE POLICY schedules_dispatcher_select ON control.schedules FOR SELECT USING ({dispatcher})")
    op.execute(f"CREATE POLICY schedules_dispatcher_update ON control.schedules FOR UPDATE USING ({dispatcher}) WITH CHECK ({dispatcher})")
    op.execute(f"CREATE POLICY schedule_triggers_dispatcher_insert ON control.schedule_triggers FOR INSERT WITH CHECK ({dispatcher})")

    op.execute(
        """
        CREATE OR REPLACE FUNCTION control.enforce_schedule_tenancy()
        RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = control, identity, security, pg_temp AS $$
        BEGIN
          IF NOT EXISTS (
            SELECT 1 FROM control.projects p
            WHERE p.id = NEW.project_id AND p.organization_id = NEW.organization_id
          ) OR NOT EXISTS (
            SELECT 1 FROM control.agents a
            WHERE a.id = NEW.agent_id AND a.project_id = NEW.project_id
              AND a.organization_id = NEW.organization_id
          ) OR NOT EXISTS (
            SELECT 1 FROM control.agent_versions v
            WHERE v.id = NEW.agent_version_id AND v.agent_id = NEW.agent_id
              AND v.project_id = NEW.project_id AND v.organization_id = NEW.organization_id
          ) OR NOT EXISTS (
            SELECT 1 FROM control.builds b
            WHERE b.id = NEW.build_id AND b.agent_version_id = NEW.agent_version_id
              AND b.agent_id = NEW.agent_id AND b.project_id = NEW.project_id
              AND b.organization_id = NEW.organization_id
          ) THEN
            RAISE EXCEPTION 'Schedule tenancy mismatch' USING ERRCODE = '23514';
          END IF;
          RETURN NEW;
        END; $$
        """
    )
    op.execute("CREATE TRIGGER schedules_tenancy_guard BEFORE INSERT OR UPDATE ON control.schedules FOR EACH ROW EXECUTE FUNCTION control.enforce_schedule_tenancy()")
    op.execute(
        """
        CREATE OR REPLACE FUNCTION control.enforce_schedule_definition_immutable()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF OLD.organization_id IS DISTINCT FROM NEW.organization_id
            OR OLD.project_id IS DISTINCT FROM NEW.project_id
            OR OLD.agent_id IS DISTINCT FROM NEW.agent_id
            OR OLD.agent_version_id IS DISTINCT FROM NEW.agent_version_id
            OR OLD.build_id IS DISTINCT FROM NEW.build_id
            OR OLD.name IS DISTINCT FROM NEW.name
            OR OLD.cadence_kind IS DISTINCT FROM NEW.cadence_kind
            OR OLD.starts_at IS DISTINCT FROM NEW.starts_at
            OR OLD.interval_seconds IS DISTINCT FROM NEW.interval_seconds
            OR OLD.missed_run_policy IS DISTINCT FROM NEW.missed_run_policy
            OR OLD.misfire_grace_seconds IS DISTINCT FROM NEW.misfire_grace_seconds
            OR OLD.run_payload IS DISTINCT FROM NEW.run_payload
            OR OLD.created_by_user_id IS DISTINCT FROM NEW.created_by_user_id
            OR OLD.created_at IS DISTINCT FROM NEW.created_at THEN
            RAISE EXCEPTION 'Schedule definition is immutable' USING ERRCODE = '23514';
          END IF;
          RETURN NEW;
        END; $$
        """
    )
    op.execute("CREATE TRIGGER schedules_definition_immutable BEFORE UPDATE ON control.schedules FOR EACH ROW EXECUTE FUNCTION control.enforce_schedule_definition_immutable()")
    op.execute(
        """
        CREATE OR REPLACE FUNCTION control.enforce_schedule_trigger_tenancy()
        RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = control, identity, security, pg_temp AS $$
        BEGIN
          IF NOT EXISTS (
            SELECT 1 FROM control.schedules s
            WHERE s.id = NEW.schedule_id AND s.project_id = NEW.project_id
              AND s.organization_id = NEW.organization_id
          ) THEN
            RAISE EXCEPTION 'Schedule trigger tenancy mismatch' USING ERRCODE = '23514';
          END IF;
          IF NEW.run_id IS NOT NULL AND NOT EXISTS (
            SELECT 1 FROM control.runs r
            WHERE r.id = NEW.run_id AND r.project_id = NEW.project_id
              AND r.organization_id = NEW.organization_id
          ) THEN
            RAISE EXCEPTION 'Schedule trigger Run tenancy mismatch' USING ERRCODE = '23514';
          END IF;
          RETURN NEW;
        END; $$
        """
    )
    op.execute("CREATE TRIGGER schedule_triggers_tenancy_guard BEFORE INSERT OR UPDATE ON control.schedule_triggers FOR EACH ROW EXECUTE FUNCTION control.enforce_schedule_trigger_tenancy()")
    op.execute(
        """
        CREATE OR REPLACE FUNCTION control.schedule_trigger_immutable()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          RAISE EXCEPTION 'Schedule triggers are immutable' USING ERRCODE = '23514';
        END; $$
        """
    )
    op.execute("CREATE TRIGGER schedule_triggers_immutable BEFORE UPDATE OR DELETE ON control.schedule_triggers FOR EACH ROW EXECUTE FUNCTION control.schedule_trigger_immutable()")
    op.execute(
        """
        CREATE OR REPLACE FUNCTION security.rdc_schedule_org(target_schedule uuid)
        RETURNS uuid LANGUAGE sql STABLE SECURITY DEFINER
        SET search_path = control, identity, security, pg_temp AS $$
          SELECT schedule.organization_id
          FROM control.schedules schedule
          WHERE schedule.id = target_schedule
            AND security.rdc_has_org_membership(schedule.organization_id)
        $$
        """
    )


def downgrade() -> None:
    op.execute("DROP FUNCTION IF EXISTS security.rdc_schedule_org(uuid)")
    op.execute("DROP TRIGGER IF EXISTS schedule_triggers_immutable ON control.schedule_triggers")
    op.execute("DROP TRIGGER IF EXISTS schedule_triggers_tenancy_guard ON control.schedule_triggers")
    op.execute("DROP TRIGGER IF EXISTS schedules_definition_immutable ON control.schedules")
    op.execute("DROP TRIGGER IF EXISTS schedules_tenancy_guard ON control.schedules")
    op.execute("DROP FUNCTION IF EXISTS control.schedule_trigger_immutable()")
    op.execute("DROP FUNCTION IF EXISTS control.enforce_schedule_trigger_tenancy()")
    op.execute("DROP FUNCTION IF EXISTS control.enforce_schedule_definition_immutable()")
    op.execute("DROP FUNCTION IF EXISTS control.enforce_schedule_tenancy()")
    op.drop_table("schedule_triggers", schema="control")
    op.drop_table("schedules", schema="control")
