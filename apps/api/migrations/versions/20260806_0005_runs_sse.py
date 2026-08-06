"""Create Phase 1E Run control-plane and SSE event tables.

Revision ID: 20260806_0005
Revises: 20260806_0004
Create Date: 2026-08-06
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260806_0005"
down_revision: str | None = "20260806_0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

UUID = postgresql.UUID(as_uuid=True)
JSONB = postgresql.JSONB(astext_type=sa.Text())


def upgrade() -> None:
    op.create_table(
        "runs",
        sa.Column(
            "id",
            UUID,
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("organization_id", UUID, nullable=False),
        sa.Column("project_id", UUID, nullable=False),
        sa.Column("agent_id", UUID, nullable=False),
        sa.Column("agent_version_id", UUID, nullable=False),
        sa.Column("build_id", UUID, nullable=False),
        sa.Column(
            "status",
            sa.String(32),
            server_default="QUEUED",
            nullable=False,
        ),
        sa.Column("input_reference", JSONB, nullable=False),
        sa.Column("runtime_configuration", JSONB, nullable=False),
        sa.Column("memory_mb", sa.Integer(), nullable=False),
        sa.Column("cpu_millis", sa.Integer(), nullable=False),
        sa.Column("timeout_seconds", sa.Integer(), nullable=False),
        sa.Column("requested_by_user_id", UUID, nullable=False),
        sa.Column(
            "queued_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.Column("cancel_requested_at", sa.DateTime(timezone=True)),
        sa.Column("failure_code", sa.String(80)),
        sa.Column("failure_summary", sa.Text()),
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
        sa.Column(
            "version",
            sa.BigInteger(),
            server_default="1",
            nullable=False,
        ),
        sa.CheckConstraint(
            "status IN ('DRAFT', 'READY', 'QUEUED', 'STARTING', 'RUNNING', "
            "'PAUSING', 'PAUSED', 'SUCCEEDED', 'PARTIALLY_SUCCEEDED', "
            "'FAILED', 'TIMING_OUT', 'TIMED_OUT', 'ABORTING', 'ABORTED')",
            name="ck_runs_status",
        ),
        sa.CheckConstraint(
            "memory_mb BETWEEN 128 AND 32768",
            name="ck_runs_memory_mb",
        ),
        sa.CheckConstraint(
            "cpu_millis BETWEEN 100 AND 16000",
            name="ck_runs_cpu_millis",
        ),
        sa.CheckConstraint(
            "timeout_seconds BETWEEN 1 AND 86400",
            name="ck_runs_timeout_seconds",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["identity.organizations.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["project_id"],
            ["control.projects.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["agent_id"],
            ["control.agents.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["agent_version_id"],
            ["control.agent_versions.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["build_id"],
            ["control.builds.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["requested_by_user_id"],
            ["identity.users.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
        schema="control",
    )
    for name, columns in [
        ("ix_runs_organization_id", ["organization_id"]),
        ("ix_runs_project_id", ["project_id"]),
        ("ix_runs_agent_id", ["agent_id"]),
        ("ix_runs_agent_version_id", ["agent_version_id"]),
        ("ix_runs_build_id", ["build_id"]),
    ]:
        op.create_index(name, "runs", columns, schema="control")
    op.create_index(
        "ix_runs_project_queued",
        "runs",
        ["project_id", sa.text("queued_at DESC"), sa.text("id DESC")],
        schema="control",
    )
    op.create_index(
        "ix_runs_status_queue",
        "runs",
        ["status", "queued_at"],
        schema="control",
    )

    op.create_table(
        "run_events",
        sa.Column(
            "id",
            UUID,
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("organization_id", UUID, nullable=False),
        sa.Column("project_id", UUID, nullable=False),
        sa.Column("run_id", UUID, nullable=False),
        sa.Column("sequence", sa.BigInteger(), nullable=False),
        sa.Column("event_type", sa.String(40), nullable=False),
        sa.Column("payload", JSONB, nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "sequence >= 1",
            name="ck_run_events_sequence",
        ),
        sa.CheckConstraint(
            "event_type IN ('run.status', 'run.log', 'run.metric', "
            "'run.warning', 'run.completed', 'run.failed')",
            name="ck_run_events_event_type",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["identity.organizations.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["project_id"],
            ["control.projects.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["run_id"],
            ["control.runs.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "run_id",
            "sequence",
            name="uq_run_events_run_sequence",
        ),
        schema="control",
    )
    op.create_index(
        "ix_run_events_organization_id",
        "run_events",
        ["organization_id"],
        schema="control",
    )
    op.create_index(
        "ix_run_events_project_id",
        "run_events",
        ["project_id"],
        schema="control",
    )
    op.create_index(
        "ix_run_events_run_id",
        "run_events",
        ["run_id"],
        schema="control",
    )
    op.create_index(
        "ix_run_events_run_sequence",
        "run_events",
        ["run_id", "sequence"],
        schema="control",
    )

    op.create_table(
        "run_command_outbox",
        sa.Column(
            "id",
            UUID,
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("organization_id", UUID, nullable=False),
        sa.Column("project_id", UUID, nullable=False),
        sa.Column("run_id", UUID, nullable=False),
        sa.Column("command", sa.String(24), nullable=False),
        sa.Column("topic", sa.String(120), nullable=False),
        sa.Column("payload", JSONB, nullable=False),
        sa.Column(
            "status",
            sa.String(24),
            server_default="PENDING",
            nullable=False,
        ),
        sa.Column(
            "attempts",
            sa.Integer(),
            server_default="0",
            nullable=False,
        ),
        sa.Column(
            "available_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("claimed_at", sa.DateTime(timezone=True)),
        sa.Column("delivered_at", sa.DateTime(timezone=True)),
        sa.Column("last_error_code", sa.String(80)),
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
        sa.CheckConstraint(
            "command IN ('START', 'CANCEL')",
            name="ck_run_command_outbox_command",
        ),
        sa.CheckConstraint(
            "status IN ('PENDING', 'CLAIMED', 'DELIVERED', 'FAILED', "
            "'CANCELLED')",
            name="ck_run_command_outbox_status",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["identity.organizations.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["project_id"],
            ["control.projects.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["run_id"],
            ["control.runs.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "run_id",
            "command",
            name="uq_run_command_outbox_run_command",
        ),
        schema="control",
    )
    op.create_index(
        "ix_run_command_outbox_organization_id",
        "run_command_outbox",
        ["organization_id"],
        schema="control",
    )
    op.create_index(
        "ix_run_command_outbox_project_id",
        "run_command_outbox",
        ["project_id"],
        schema="control",
    )
    op.create_index(
        "ix_run_command_outbox_run_id",
        "run_command_outbox",
        ["run_id"],
        schema="control",
    )
    op.create_index(
        "ix_run_command_outbox_pending",
        "run_command_outbox",
        ["status", "available_at"],
        schema="control",
    )

    op.execute(
        """
        CREATE OR REPLACE FUNCTION control.enforce_run_tenancy()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
          IF NOT EXISTS (
            SELECT 1
            FROM control.agent_versions version
            JOIN control.builds build ON build.id = NEW.build_id
            WHERE version.id = NEW.agent_version_id
              AND version.agent_id = NEW.agent_id
              AND version.project_id = NEW.project_id
              AND version.organization_id = NEW.organization_id
              AND build.agent_version_id = version.id
              AND build.agent_id = NEW.agent_id
              AND build.project_id = NEW.project_id
              AND build.organization_id = NEW.organization_id
          ) THEN
            RAISE EXCEPTION 'Run tenancy does not match Build and Agent version'
              USING ERRCODE = '23514';
          END IF;
          RETURN NEW;
        END
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER runs_tenancy_guard
        BEFORE INSERT OR UPDATE OF
          organization_id, project_id, agent_id, agent_version_id, build_id
        ON control.runs
        FOR EACH ROW
        EXECUTE FUNCTION control.enforce_run_tenancy()
        """
    )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION control.enforce_run_child_tenancy()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
          IF NOT EXISTS (
            SELECT 1
            FROM control.runs run
            WHERE run.id = NEW.run_id
              AND run.project_id = NEW.project_id
              AND run.organization_id = NEW.organization_id
          ) THEN
            RAISE EXCEPTION 'Run child tenancy mismatch'
              USING ERRCODE = '23514';
          END IF;
          RETURN NEW;
        END
        $$
        """
    )
    for table_name, trigger_name in [
        ("run_events", "run_events_tenancy_guard"),
        ("run_command_outbox", "run_command_outbox_tenancy_guard"),
    ]:
        op.execute(
            f"""
            CREATE TRIGGER {trigger_name}
            BEFORE INSERT OR UPDATE OF organization_id, project_id, run_id
            ON control.{table_name}
            FOR EACH ROW
            EXECUTE FUNCTION control.enforce_run_child_tenancy()
            """
        )

    op.execute(
        """
        CREATE OR REPLACE FUNCTION security.rdc_run_org(target_run uuid)
        RETURNS uuid
        LANGUAGE sql
        STABLE
        SECURITY DEFINER
        SET search_path = control, identity, security, pg_temp
        AS $$
          SELECT run.organization_id
          FROM control.runs run
          WHERE run.id = target_run
            AND security.rdc_has_org_membership(run.organization_id)
        $$
        """
    )

    for table_name in ["runs", "run_events", "run_command_outbox"]:
        op.execute(
            f'ALTER TABLE "control"."{table_name}" ENABLE ROW LEVEL SECURITY'
        )
        op.execute(
            f"""
            CREATE POLICY {table_name}_tenant
            ON control.{table_name}
            USING (
              organization_id = security.rdc_current_org_id()
              AND security.rdc_has_org_membership(organization_id)
            )
            WITH CHECK (
              organization_id = security.rdc_current_org_id()
              AND security.rdc_has_org_membership(organization_id)
            )
            """
        )


def downgrade() -> None:
    op.execute("DROP FUNCTION IF EXISTS security.rdc_run_org(uuid)")
    op.drop_table("run_command_outbox", schema="control")
    op.drop_table("run_events", schema="control")
    op.drop_table("runs", schema="control")
    op.execute("DROP FUNCTION IF EXISTS control.enforce_run_child_tenancy()")
    op.execute("DROP FUNCTION IF EXISTS control.enforce_run_tenancy()")
