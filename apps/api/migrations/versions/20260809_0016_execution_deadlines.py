"""Persist and enforce immutable execution deadlines.

Revision ID: 20260809_0016
Revises: 20260809_0015
Create Date: 2026-08-09
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260809_0016"
down_revision: str | None = "20260809_0015"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "execution_leases",
        sa.Column("deadline_at", sa.DateTime(timezone=True), nullable=True),
        schema="control",
    )
    op.execute(
        """
        UPDATE control.execution_leases
        SET deadline_at = expires_at
        WHERE deadline_at IS NULL
        """
    )
    op.alter_column(
        "execution_leases",
        "deadline_at",
        nullable=False,
        schema="control",
    )
    op.create_check_constraint(
        "ck_execution_leases_deadline",
        "execution_leases",
        "deadline_at > claimed_at AND expires_at <= deadline_at",
        schema="control",
    )
    op.create_index(
        "ix_execution_leases_active_deadline",
        "execution_leases",
        ["status", "deadline_at"],
        schema="control",
    )

    op.execute(
        """
        CREATE OR REPLACE FUNCTION control.enforce_execution_deadline_immutable()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
          IF NEW.deadline_at IS DISTINCT FROM OLD.deadline_at THEN
            RAISE EXCEPTION 'Execution deadline is immutable'
              USING ERRCODE = '23514';
          END IF;
          RETURN NEW;
        END
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER execution_lease_deadline_immutable
        BEFORE UPDATE OF deadline_at ON control.execution_leases
        FOR EACH ROW
        EXECUTE FUNCTION control.enforce_execution_deadline_immutable()
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

    for policy, schema, table in [
        ("execution_leases_reaper_select", "control", "execution_leases"),
        ("execution_leases_reaper", "control", "execution_leases"),
        ("builds_execution_reaper_select", "control", "builds"),
        ("builds_execution_reaper", "control", "builds"),
        ("runs_execution_reaper_select", "control", "runs"),
        ("runs_execution_reaper", "control", "runs"),
        ("run_events_execution_reaper", "control", "run_events"),
        (
            "secret_injection_grants_reaper_select",
            "security",
            "secret_injection_grants",
        ),
        (
            "secret_injection_grants_reaper",
            "security",
            "secret_injection_grants",
        ),
    ]:
        op.execute(f"DROP POLICY IF EXISTS {policy} ON {schema}.{table}")

    overdue = "(lease.expires_at <= now() OR lease.deadline_at <= now())"
    op.execute(
        """
        CREATE POLICY execution_leases_reaper_select
        ON control.execution_leases FOR SELECT
        USING (
          security.rdc_worker_is_active()
          AND status = 'ACTIVE'
          AND (expires_at <= now() OR deadline_at <= now())
        )
        """
    )
    op.execute(
        """
        CREATE POLICY execution_leases_reaper
        ON control.execution_leases FOR UPDATE
        USING (
          security.rdc_worker_is_active()
          AND status = 'ACTIVE'
          AND (expires_at <= now() OR deadline_at <= now())
        )
        WITH CHECK (
          security.rdc_worker_is_active()
          AND status IN ('EXPIRED', 'FAILED')
        )
        """
    )
    for target, key in (("builds", "build_id"), ("runs", "run_id")):
        op.execute(
            f"""
            CREATE POLICY {target}_execution_reaper_select
            ON control.{target} FOR SELECT
            USING (
              security.rdc_worker_is_active()
              AND EXISTS (
                SELECT 1 FROM control.execution_leases lease
                WHERE lease.status = 'ACTIVE'
                  AND {overdue}
                  AND lease.{key} = {target}.id
              )
            )
            """
        )
        op.execute(
            f"""
            CREATE POLICY {target}_execution_reaper
            ON control.{target} FOR UPDATE
            USING (
              security.rdc_worker_is_active()
              AND EXISTS (
                SELECT 1 FROM control.execution_leases lease
                WHERE lease.status = 'ACTIVE'
                  AND {overdue}
                  AND lease.{key} = {target}.id
              )
            )
            WITH CHECK (security.rdc_worker_is_active())
            """
        )
    op.execute(
        f"""
        CREATE POLICY run_events_execution_reaper
        ON control.run_events FOR INSERT
        WITH CHECK (
          security.rdc_worker_is_active()
          AND EXISTS (
            SELECT 1 FROM control.execution_leases lease
            WHERE lease.status = 'ACTIVE'
              AND {overdue}
              AND lease.run_id = run_events.run_id
          )
        )
        """
    )
    op.execute(
        f"""
        CREATE POLICY secret_injection_grants_reaper_select
        ON security.secret_injection_grants FOR SELECT
        USING (
          security.rdc_worker_is_active()
          AND status = 'ISSUED'
          AND EXISTS (
            SELECT 1 FROM control.execution_leases lease
            WHERE lease.id = secret_injection_grants.lease_id
              AND lease.status = 'ACTIVE'
              AND {overdue}
          )
        )
        """
    )
    op.execute(
        f"""
        CREATE POLICY secret_injection_grants_reaper
        ON security.secret_injection_grants FOR UPDATE
        USING (
          security.rdc_worker_is_active()
          AND status = 'ISSUED'
          AND EXISTS (
            SELECT 1 FROM control.execution_leases lease
            WHERE lease.id = secret_injection_grants.lease_id
              AND lease.status = 'ACTIVE'
              AND {overdue}
          )
        )
        WITH CHECK (
          security.rdc_worker_is_active()
          AND status = 'EXPIRED'
        )
        """
    )


def downgrade() -> None:
    for policy, schema, table in [
        ("execution_leases_reaper_select", "control", "execution_leases"),
        ("execution_leases_reaper", "control", "execution_leases"),
        ("builds_execution_reaper_select", "control", "builds"),
        ("builds_execution_reaper", "control", "builds"),
        ("runs_execution_reaper_select", "control", "runs"),
        ("runs_execution_reaper", "control", "runs"),
        ("run_events_execution_reaper", "control", "run_events"),
        (
            "secret_injection_grants_reaper_select",
            "security",
            "secret_injection_grants",
        ),
        (
            "secret_injection_grants_reaper",
            "security",
            "secret_injection_grants",
        ),
    ]:
        op.execute(f"DROP POLICY IF EXISTS {policy} ON {schema}.{table}")
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
              AND lease.work_kind = 'RUN_START'
              AND lease.organization_id = target_organization
              AND lease.project_id = target_project
          )
        $$
        """
    )
    op.execute(
        "DROP TRIGGER IF EXISTS execution_lease_deadline_immutable "
        "ON control.execution_leases"
    )
    op.execute(
        "DROP FUNCTION IF EXISTS control.enforce_execution_deadline_immutable()"
    )
    op.drop_index(
        "ix_execution_leases_active_deadline",
        table_name="execution_leases",
        schema="control",
    )
    op.drop_constraint(
        "ck_execution_leases_deadline",
        "execution_leases",
        schema="control",
        type_="check",
    )
    op.drop_column("execution_leases", "deadline_at", schema="control")

    op.execute(
        """
        CREATE POLICY execution_leases_reaper_select
        ON control.execution_leases FOR SELECT
        USING (
          security.rdc_worker_is_active()
          AND status = 'ACTIVE'
          AND expires_at <= now()
        )
        """
    )
    op.execute(
        """
        CREATE POLICY execution_leases_reaper
        ON control.execution_leases FOR UPDATE
        USING (
          security.rdc_worker_is_active()
          AND status = 'ACTIVE'
          AND expires_at <= now()
        )
        WITH CHECK (
          security.rdc_worker_is_active()
          AND status = 'EXPIRED'
        )
        """
    )
    for target, key in (("builds", "build_id"), ("runs", "run_id")):
        op.execute(
            f"""
            CREATE POLICY {target}_execution_reaper_select
            ON control.{target} FOR SELECT
            USING (
              security.rdc_worker_is_active()
              AND EXISTS (
                SELECT 1 FROM control.execution_leases lease
                WHERE lease.status = 'ACTIVE'
                  AND lease.expires_at <= now()
                  AND lease.{key} = {target}.id
              )
            )
            """
        )
        op.execute(
            f"""
            CREATE POLICY {target}_execution_reaper
            ON control.{target} FOR UPDATE
            USING (
              security.rdc_worker_is_active()
              AND EXISTS (
                SELECT 1 FROM control.execution_leases lease
                WHERE lease.status = 'ACTIVE'
                  AND lease.expires_at <= now()
                  AND lease.{key} = {target}.id
              )
            )
            WITH CHECK (security.rdc_worker_is_active())
            """
        )
    op.execute(
        """
        CREATE POLICY run_events_execution_reaper
        ON control.run_events FOR INSERT
        WITH CHECK (
          security.rdc_worker_is_active()
          AND EXISTS (
            SELECT 1 FROM control.execution_leases lease
            WHERE lease.status = 'ACTIVE'
              AND lease.expires_at <= now()
              AND lease.run_id = run_events.run_id
          )
        )
        """
    )
    op.execute(
        """
        CREATE POLICY secret_injection_grants_reaper_select
        ON security.secret_injection_grants FOR SELECT
        USING (
          security.rdc_worker_is_active()
          AND status = 'ISSUED'
          AND EXISTS (
            SELECT 1 FROM control.execution_leases lease
            WHERE lease.id = secret_injection_grants.lease_id
              AND lease.status = 'ACTIVE'
              AND lease.expires_at <= now()
          )
        )
        """
    )
    op.execute(
        """
        CREATE POLICY secret_injection_grants_reaper
        ON security.secret_injection_grants FOR UPDATE
        USING (
          security.rdc_worker_is_active()
          AND status = 'ISSUED'
          AND EXISTS (
            SELECT 1 FROM control.execution_leases lease
            WHERE lease.id = secret_injection_grants.lease_id
              AND lease.status = 'ACTIVE'
              AND lease.expires_at <= now()
          )
        )
        WITH CHECK (
          security.rdc_worker_is_active()
          AND status = 'EXPIRED'
        )
        """
    )
