"""Persist bounded Run cancellation convergence state.

Revision ID: 20260809_0017
Revises: 20260809_0016
Create Date: 2026-08-09
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260809_0017"
down_revision: str | None = "20260809_0016"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "runs",
        sa.Column("cancel_deadline_at", sa.DateTime(timezone=True)),
        schema="control",
    )
    op.execute(
        """
        UPDATE control.runs
        SET cancel_deadline_at = cancel_requested_at + INTERVAL '5 minutes'
        WHERE cancel_requested_at IS NOT NULL
          AND cancel_deadline_at IS NULL
        """
    )
    op.execute(
        """
        UPDATE control.run_command_outbox command
        SET payload = jsonb_set(
          command.payload,
          '{cancel_deadline_at}',
          to_jsonb(run.cancel_deadline_at::text),
          true
        )
        FROM control.runs run
        WHERE command.run_id = run.id
          AND command.command = 'CANCEL'
          AND run.cancel_deadline_at IS NOT NULL
        """
    )
    op.create_check_constraint(
        "ck_runs_cancel_deadline",
        "runs",
        "(cancel_requested_at IS NULL AND cancel_deadline_at IS NULL) OR "
        "(cancel_requested_at IS NOT NULL AND cancel_deadline_at IS NOT NULL "
        "AND cancel_deadline_at > cancel_requested_at)",
        schema="control",
    )
    op.create_index(
        "ix_runs_cancellation_deadline",
        "runs",
        ["status", "cancel_deadline_at"],
        schema="control",
    )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION control.enforce_run_cancellation_immutable()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
          IF OLD.cancel_requested_at IS NOT NULL
             AND NEW.cancel_requested_at IS DISTINCT FROM OLD.cancel_requested_at
          THEN
            RAISE EXCEPTION 'Run cancellation request is immutable'
              USING ERRCODE = '23514';
          END IF;
          IF OLD.cancel_deadline_at IS NOT NULL
             AND NEW.cancel_deadline_at IS DISTINCT FROM OLD.cancel_deadline_at
          THEN
            RAISE EXCEPTION 'Run cancellation deadline is immutable'
              USING ERRCODE = '23514';
          END IF;
          RETURN NEW;
        END
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER run_cancellation_immutable
        BEFORE UPDATE OF cancel_requested_at, cancel_deadline_at
        ON control.runs
        FOR EACH ROW
        EXECUTE FUNCTION control.enforce_run_cancellation_immutable()
        """
    )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION security.rdc_worker_has_active_run_lease(
          target_organization uuid,
          target_project uuid
        ) RETURNS boolean
        LANGUAGE sql
        STABLE
        SECURITY DEFINER
        SET search_path = control, identity, security, pg_temp
        AS $$
          SELECT security.rdc_worker_is_active() AND EXISTS (
            SELECT 1
            FROM control.execution_leases lease
            JOIN control.runs run ON run.id = lease.run_id
            WHERE lease.worker_id = security.rdc_current_worker_id()
              AND lease.status = 'ACTIVE'
              AND lease.expires_at > now()
              AND lease.deadline_at > now()
              AND lease.work_kind = 'RUN_START'
              AND lease.organization_id = target_organization
              AND lease.project_id = target_project
              AND run.cancel_requested_at IS NULL
          )
        $$
        """
    )


def downgrade() -> None:
    op.execute(
        """
        CREATE OR REPLACE FUNCTION security.rdc_worker_has_active_run_lease(
          target_organization uuid,
          target_project uuid
        ) RETURNS boolean
        LANGUAGE sql
        STABLE
        SECURITY DEFINER
        SET search_path = control, identity, security, pg_temp
        AS $$
          SELECT security.rdc_worker_is_active() AND EXISTS (
            SELECT 1
            FROM control.execution_leases lease
            WHERE lease.worker_id = security.rdc_current_worker_id()
              AND lease.status = 'ACTIVE'
              AND lease.expires_at > now()
              AND lease.deadline_at > now()
              AND lease.work_kind = 'RUN_START'
              AND lease.organization_id = target_organization
              AND lease.project_id = target_project
          )
        $$
        """
    )
    op.execute(
        """
        UPDATE control.run_command_outbox
        SET payload = payload - 'cancel_deadline_at'
        WHERE command = 'CANCEL'
        """
    )
    op.execute(
        "DROP TRIGGER IF EXISTS run_cancellation_immutable ON control.runs"
    )
    op.execute(
        "DROP FUNCTION IF EXISTS control.enforce_run_cancellation_immutable()"
    )
    op.drop_index(
        "ix_runs_cancellation_deadline",
        table_name="runs",
        schema="control",
    )
    op.drop_constraint(
        "ck_runs_cancel_deadline",
        "runs",
        schema="control",
        type_="check",
    )
    op.drop_column("runs", "cancel_deadline_at", schema="control")
