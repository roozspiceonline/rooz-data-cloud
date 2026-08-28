"""Add immutable lease-scoped egress health observations.

Revision ID: 20260828_0023
Revises: 20260822_0022
"""
# ruff: noqa: E501

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260828_0023"
down_revision: str | None = "20260822_0022"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None
UUID = postgresql.UUID(as_uuid=True)


def upgrade() -> None:
    op.create_table(
        "egress_health_observations",
        sa.Column(
            "id",
            UUID,
            server_default=sa.text("gen_random_uuid()"),
            primary_key=True,
        ),
        sa.Column("organization_id", UUID, nullable=False),
        sa.Column("project_id", UUID, nullable=False),
        sa.Column("run_id", UUID, nullable=False),
        sa.Column("lease_id", UUID, nullable=False),
        sa.Column("worker_id", UUID, nullable=False),
        sa.Column("client_observation_id", UUID, nullable=False),
        sa.Column("evidence", postgresql.JSONB(), nullable=False),
        sa.Column("evidence_digest", sa.String(64), nullable=False),
        sa.Column("outcome", sa.String(32), nullable=False),
        sa.Column("healthy", sa.Boolean(), nullable=False),
        sa.Column("retryable", sa.Boolean(), nullable=False),
        sa.Column(
            "observed_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.UniqueConstraint(
            "lease_id",
            "client_observation_id",
            name="uq_egress_health_observations_lease_client",
        ),
        sa.CheckConstraint(
            "evidence_digest ~ '^[0-9a-f]{64}$'",
            name="ck_egress_health_observations_digest",
        ),
        sa.CheckConstraint(
            "outcome IN ('SUCCESS','HTTP_403','HTTP_429','BOT_CHALLENGE','LOGIN_REQUIRED','EMPTY_RESPONSE','HTTP_ERROR','DNS_FAILURE','TLS_FAILURE','TIMEOUT','PROXY_FAILURE')",
            name="ck_egress_health_observations_outcome",
        ),
        sa.CheckConstraint(
            "jsonb_typeof(evidence) = 'object' AND evidence - ARRAY['transport_failure','http_status','response_bytes','latency_ms','challenge_detected','login_required'] = '{}'::jsonb",
            name="ck_egress_health_observations_evidence_shape",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["identity.organizations.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["project_id"], ["control.projects.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["run_id"], ["control.runs.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["lease_id"], ["control.execution_leases.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["worker_id"],
            ["security.worker_identities.id"],
            ondelete="RESTRICT",
        ),
        schema="control",
    )
    for columns in (
        ["organization_id"],
        ["project_id", "observed_at"],
        ["run_id", "observed_at"],
        ["lease_id", "observed_at"],
        ["worker_id"],
    ):
        suffix = "_".join(columns)
        op.create_index(
            f"ix_egress_health_observations_{suffix}",
            "egress_health_observations",
            columns,
            schema="control",
        )

    op.execute(
        """
        CREATE OR REPLACE FUNCTION control.enforce_egress_health_observation()
        RETURNS trigger
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = control, security, identity, pg_temp
        AS $$
        DECLARE
          transport text := NEW.evidence ->> 'transport_failure';
          status_code integer;
          response_size bigint;
          latency bigint;
          challenge boolean := COALESCE((NEW.evidence ->> 'challenge_detected')::boolean, false);
          login boolean := COALESCE((NEW.evidence ->> 'login_required')::boolean, false);
        BEGIN
          IF NOT EXISTS (
            SELECT 1 FROM control.execution_leases lease
            WHERE lease.id = NEW.lease_id
              AND lease.worker_id = NEW.worker_id
              AND lease.organization_id = NEW.organization_id
              AND lease.project_id = NEW.project_id
              AND lease.run_id = NEW.run_id
              AND lease.work_kind = 'RUN_START'
              AND lease.status = 'ACTIVE'
              AND lease.expires_at > now()
              AND lease.deadline_at > now()
          ) THEN
            RAISE EXCEPTION 'Egress health lease tenancy mismatch'
              USING ERRCODE = '23514';
          END IF;

          IF NOT (NEW.evidence ? 'latency_ms')
             OR jsonb_typeof(NEW.evidence -> 'latency_ms') <> 'number' THEN
            RAISE EXCEPTION 'Egress health evidence is invalid' USING ERRCODE = '23514';
          END IF;
          latency := (NEW.evidence ->> 'latency_ms')::bigint;
          IF latency < 0 OR latency > 300000
             OR ((transport IS NULL) = NOT (NEW.evidence ? 'http_status')) THEN
            RAISE EXCEPTION 'Egress health evidence is invalid' USING ERRCODE = '23514';
          END IF;

          IF transport IS NOT NULL THEN
            IF transport NOT IN ('DNS_FAILURE','TLS_FAILURE','TIMEOUT','PROXY_FAILURE')
               OR NEW.evidence ? 'response_bytes'
               OR challenge OR login THEN
              RAISE EXCEPTION 'Egress health evidence is invalid' USING ERRCODE = '23514';
            END IF;
            NEW.outcome := transport;
            NEW.healthy := false;
            NEW.retryable := true;
            RETURN NEW;
          END IF;

          status_code := (NEW.evidence ->> 'http_status')::integer;
          IF status_code < 100 OR status_code > 599 THEN
            RAISE EXCEPTION 'Egress health evidence is invalid' USING ERRCODE = '23514';
          END IF;
          IF NEW.evidence ? 'response_bytes' THEN
            response_size := (NEW.evidence ->> 'response_bytes')::bigint;
            IF response_size < 0 OR response_size > 16777216 THEN
              RAISE EXCEPTION 'Egress health evidence is invalid' USING ERRCODE = '23514';
            END IF;
          END IF;

          IF challenge THEN
            NEW.outcome := 'BOT_CHALLENGE'; NEW.healthy := false; NEW.retryable := false;
          ELSIF login THEN
            NEW.outcome := 'LOGIN_REQUIRED'; NEW.healthy := false; NEW.retryable := false;
          ELSIF status_code = 403 THEN
            NEW.outcome := 'HTTP_403'; NEW.healthy := false; NEW.retryable := false;
          ELSIF status_code = 429 THEN
            NEW.outcome := 'HTTP_429'; NEW.healthy := false; NEW.retryable := true;
          ELSIF status_code >= 400 THEN
            NEW.outcome := 'HTTP_ERROR'; NEW.healthy := false; NEW.retryable := status_code >= 500;
          ELSIF response_size = 0 THEN
            NEW.outcome := 'EMPTY_RESPONSE'; NEW.healthy := false; NEW.retryable := true;
          ELSE
            NEW.outcome := 'SUCCESS'; NEW.healthy := true; NEW.retryable := false;
          END IF;
          RETURN NEW;
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER egress_health_observations_guard
        BEFORE INSERT ON control.egress_health_observations
        FOR EACH ROW EXECUTE FUNCTION control.enforce_egress_health_observation()
        """
    )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION control.egress_health_observation_immutable()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          RAISE EXCEPTION 'Egress health observations are immutable'
            USING ERRCODE = '23514';
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER egress_health_observations_immutable
        BEFORE UPDATE OR DELETE ON control.egress_health_observations
        FOR EACH ROW EXECUTE FUNCTION control.egress_health_observation_immutable()
        """
    )

    op.execute(
        "ALTER TABLE control.egress_health_observations ENABLE ROW LEVEL SECURITY"
    )
    tenant = (
        "organization_id = security.rdc_current_org_id() "
        "AND security.rdc_has_org_membership(organization_id)"
    )
    op.execute(
        f"CREATE POLICY egress_health_observations_tenant_select "
        f"ON control.egress_health_observations FOR SELECT USING ({tenant})"
    )
    worker = """
      worker_id = security.rdc_current_worker_id()
      AND security.rdc_worker_is_active()
      AND EXISTS (
        SELECT 1 FROM control.execution_leases lease
        WHERE lease.id = egress_health_observations.lease_id
          AND lease.worker_id = security.rdc_current_worker_id()
          AND lease.status = 'ACTIVE'
          AND lease.expires_at > now()
          AND lease.deadline_at > now()
          AND lease.work_kind = 'RUN_START'
          AND lease.organization_id = egress_health_observations.organization_id
          AND lease.project_id = egress_health_observations.project_id
          AND lease.run_id = egress_health_observations.run_id
      )
    """
    op.execute(
        f"CREATE POLICY egress_health_observations_worker_select "
        f"ON control.egress_health_observations FOR SELECT USING ({worker})"
    )
    op.execute(
        f"CREATE POLICY egress_health_observations_worker_insert "
        f"ON control.egress_health_observations FOR INSERT WITH CHECK ({worker})"
    )


def downgrade() -> None:
    op.execute(
        "DROP POLICY IF EXISTS egress_health_observations_worker_insert ON control.egress_health_observations"
    )
    op.execute(
        "DROP POLICY IF EXISTS egress_health_observations_worker_select ON control.egress_health_observations"
    )
    op.execute(
        "DROP POLICY IF EXISTS egress_health_observations_tenant_select ON control.egress_health_observations"
    )
    op.execute(
        "DROP TRIGGER IF EXISTS egress_health_observations_immutable ON control.egress_health_observations"
    )
    op.execute(
        "DROP TRIGGER IF EXISTS egress_health_observations_guard ON control.egress_health_observations"
    )
    op.execute("DROP FUNCTION IF EXISTS control.egress_health_observation_immutable()")
    op.execute("DROP FUNCTION IF EXISTS control.enforce_egress_health_observation()")
    op.drop_table("egress_health_observations", schema="control")
