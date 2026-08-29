"""Compact egress health evidence and remove unused telemetry indexes.

Revision ID: 20260828_0025
Revises: 20260828_0024
"""
# ruff: noqa: E501

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "20260828_0025"
down_revision: str | None = "20260828_0024"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


COMPACT_GUARD = """
CREATE OR REPLACE FUNCTION control.enforce_egress_health_observation()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path = control, security, identity, pg_temp AS $$
DECLARE
  response_size bigint;
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
    RAISE EXCEPTION 'Egress health lease tenancy mismatch' USING ERRCODE = '23514';
  END IF;

  IF NEW.evidence IS NOT NULL THEN
    IF jsonb_typeof(NEW.evidence) <> 'object'
       OR NEW.evidence - ARRAY['transport_failure','http_status','response_bytes','latency_ms','challenge_detected','login_required'] <> '{}'::jsonb THEN
      RAISE EXCEPTION 'Egress health evidence is invalid' USING ERRCODE = '23514';
    END IF;
    NEW.transport_failure := NEW.evidence ->> 'transport_failure';
    NEW.http_status := (NEW.evidence ->> 'http_status')::smallint;
    NEW.response_bytes := (NEW.evidence ->> 'response_bytes')::bigint;
    NEW.latency_ms := (NEW.evidence ->> 'latency_ms')::integer;
    NEW.challenge_detected := COALESCE((NEW.evidence ->> 'challenge_detected')::boolean, false);
    NEW.login_required := COALESCE((NEW.evidence ->> 'login_required')::boolean, false);
    NEW.evidence := NULL;
  END IF;

  IF NEW.latency_ms IS NULL OR NEW.latency_ms < 0 OR NEW.latency_ms > 300000
     OR ((NEW.transport_failure IS NULL) = (NEW.http_status IS NULL)) THEN
    RAISE EXCEPTION 'Egress health evidence is invalid' USING ERRCODE = '23514';
  END IF;
  IF NEW.transport_failure IS NOT NULL THEN
    IF NEW.transport_failure NOT IN ('DNS_FAILURE','TLS_FAILURE','TIMEOUT','PROXY_FAILURE')
       OR NEW.response_bytes IS NOT NULL OR NEW.challenge_detected OR NEW.login_required THEN
      RAISE EXCEPTION 'Egress health evidence is invalid' USING ERRCODE = '23514';
    END IF;
    NEW.outcome := NEW.transport_failure; NEW.healthy := false; NEW.retryable := true;
    RETURN NEW;
  END IF;
  IF NEW.http_status < 100 OR NEW.http_status > 599 THEN
    RAISE EXCEPTION 'Egress health evidence is invalid' USING ERRCODE = '23514';
  END IF;
  response_size := NEW.response_bytes;
  IF response_size IS NOT NULL AND (response_size < 0 OR response_size > 16777216) THEN
    RAISE EXCEPTION 'Egress health evidence is invalid' USING ERRCODE = '23514';
  END IF;
  IF NEW.challenge_detected THEN
    NEW.outcome := 'BOT_CHALLENGE'; NEW.healthy := false; NEW.retryable := false;
  ELSIF NEW.login_required THEN
    NEW.outcome := 'LOGIN_REQUIRED'; NEW.healthy := false; NEW.retryable := false;
  ELSIF NEW.http_status = 403 THEN
    NEW.outcome := 'HTTP_403'; NEW.healthy := false; NEW.retryable := false;
  ELSIF NEW.http_status = 429 THEN
    NEW.outcome := 'HTTP_429'; NEW.healthy := false; NEW.retryable := true;
  ELSIF NEW.http_status >= 400 THEN
    NEW.outcome := 'HTTP_ERROR'; NEW.healthy := false; NEW.retryable := NEW.http_status >= 500;
  ELSIF response_size = 0 THEN
    NEW.outcome := 'EMPTY_RESPONSE'; NEW.healthy := false; NEW.retryable := true;
  ELSE
    NEW.outcome := 'SUCCESS'; NEW.healthy := true; NEW.retryable := false;
  END IF;
  RETURN NEW;
END; $$
"""


def upgrade() -> None:
    op.add_column("egress_health_observations", sa.Column("transport_failure", sa.String(32)), schema="control")
    op.add_column("egress_health_observations", sa.Column("http_status", sa.SmallInteger()), schema="control")
    op.add_column("egress_health_observations", sa.Column("response_bytes", sa.BigInteger()), schema="control")
    op.add_column("egress_health_observations", sa.Column("latency_ms", sa.Integer()), schema="control")
    op.add_column("egress_health_observations", sa.Column("challenge_detected", sa.Boolean(), server_default=sa.text("false"), nullable=False), schema="control")
    op.add_column("egress_health_observations", sa.Column("login_required", sa.Boolean(), server_default=sa.text("false"), nullable=False), schema="control")
    op.execute("ALTER TABLE control.egress_health_observations DISABLE TRIGGER egress_health_observations_immutable")
    op.execute("""
        UPDATE control.egress_health_observations SET
          transport_failure = evidence ->> 'transport_failure',
          http_status = (evidence ->> 'http_status')::smallint,
          response_bytes = (evidence ->> 'response_bytes')::bigint,
          latency_ms = (evidence ->> 'latency_ms')::integer,
          challenge_detected = COALESCE((evidence ->> 'challenge_detected')::boolean, false),
          login_required = COALESCE((evidence ->> 'login_required')::boolean, false)
    """)
    op.alter_column("egress_health_observations", "latency_ms", nullable=False, schema="control")
    op.drop_constraint("ck_egress_health_observations_evidence_shape", "egress_health_observations", schema="control", type_="check")
    op.alter_column("egress_health_observations", "evidence", nullable=True, schema="control")
    op.create_check_constraint(
        "ck_egress_health_observations_compact_evidence",
        "egress_health_observations",
        "latency_ms BETWEEN 0 AND 300000 AND ((transport_failure IS NULL) <> (http_status IS NULL)) AND (http_status IS NULL OR http_status BETWEEN 100 AND 599) AND (response_bytes IS NULL OR response_bytes BETWEEN 0 AND 16777216) AND (transport_failure IS NULL OR (transport_failure IN ('DNS_FAILURE','TLS_FAILURE','TIMEOUT','PROXY_FAILURE') AND response_bytes IS NULL AND NOT challenge_detected AND NOT login_required))",
        schema="control",
    )
    op.execute(COMPACT_GUARD)
    op.execute("UPDATE control.egress_health_observations SET evidence = NULL")
    for name in (
        "ix_egress_health_observations_organization_id",
        "ix_egress_health_observations_run_id_observed_at",
        "ix_egress_health_observations_lease_id_observed_at",
        "ix_egress_health_observations_worker_id",
    ):
        op.drop_index(name, table_name="egress_health_observations", schema="control")
    op.execute("ALTER TABLE control.egress_health_observations ENABLE TRIGGER egress_health_observations_immutable")


def downgrade() -> None:
    op.execute("ALTER TABLE control.egress_health_observations DISABLE TRIGGER egress_health_observations_immutable")
    for name, columns in (
        ("ix_egress_health_observations_organization_id", ["organization_id"]),
        ("ix_egress_health_observations_run_id_observed_at", ["run_id", "observed_at"]),
        ("ix_egress_health_observations_lease_id_observed_at", ["lease_id", "observed_at"]),
        ("ix_egress_health_observations_worker_id", ["worker_id"]),
    ):
        op.create_index(name, "egress_health_observations", columns, schema="control")
    op.execute("""
        UPDATE control.egress_health_observations SET evidence = jsonb_strip_nulls(
          jsonb_build_object(
            'transport_failure', transport_failure,
            'http_status', http_status,
            'response_bytes', response_bytes,
            'latency_ms', latency_ms,
            'challenge_detected', CASE WHEN challenge_detected THEN true ELSE NULL END,
            'login_required', CASE WHEN login_required THEN true ELSE NULL END
          )
        )
    """)
    op.alter_column("egress_health_observations", "evidence", nullable=False, schema="control")
    op.drop_constraint("ck_egress_health_observations_compact_evidence", "egress_health_observations", schema="control", type_="check")
    op.create_check_constraint(
        "ck_egress_health_observations_evidence_shape",
        "egress_health_observations",
        "jsonb_typeof(evidence) = 'object' AND evidence - ARRAY['transport_failure','http_status','response_bytes','latency_ms','challenge_detected','login_required'] = '{}'::jsonb",
        schema="control",
    )
    op.execute("""
        CREATE OR REPLACE FUNCTION control.enforce_egress_health_observation()
        RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = control, security, identity, pg_temp AS $$
        DECLARE
          transport text := NEW.evidence ->> 'transport_failure';
          status_code integer; response_size bigint; latency bigint;
          challenge boolean := COALESCE((NEW.evidence ->> 'challenge_detected')::boolean, false);
          login boolean := COALESCE((NEW.evidence ->> 'login_required')::boolean, false);
        BEGIN
          IF NOT EXISTS (SELECT 1 FROM control.execution_leases lease WHERE lease.id = NEW.lease_id AND lease.worker_id = NEW.worker_id AND lease.organization_id = NEW.organization_id AND lease.project_id = NEW.project_id AND lease.run_id = NEW.run_id AND lease.work_kind = 'RUN_START' AND lease.status = 'ACTIVE' AND lease.expires_at > now() AND lease.deadline_at > now()) THEN RAISE EXCEPTION 'Egress health lease tenancy mismatch' USING ERRCODE = '23514'; END IF;
          IF NOT (NEW.evidence ? 'latency_ms') OR jsonb_typeof(NEW.evidence -> 'latency_ms') <> 'number' THEN RAISE EXCEPTION 'Egress health evidence is invalid' USING ERRCODE = '23514'; END IF;
          latency := (NEW.evidence ->> 'latency_ms')::bigint;
          IF latency < 0 OR latency > 300000 OR ((transport IS NULL) = NOT (NEW.evidence ? 'http_status')) THEN RAISE EXCEPTION 'Egress health evidence is invalid' USING ERRCODE = '23514'; END IF;
          IF transport IS NOT NULL THEN
            IF transport NOT IN ('DNS_FAILURE','TLS_FAILURE','TIMEOUT','PROXY_FAILURE') OR NEW.evidence ? 'response_bytes' OR challenge OR login THEN RAISE EXCEPTION 'Egress health evidence is invalid' USING ERRCODE = '23514'; END IF;
            NEW.outcome := transport; NEW.healthy := false; NEW.retryable := true; RETURN NEW;
          END IF;
          status_code := (NEW.evidence ->> 'http_status')::integer;
          IF status_code < 100 OR status_code > 599 THEN RAISE EXCEPTION 'Egress health evidence is invalid' USING ERRCODE = '23514'; END IF;
          IF NEW.evidence ? 'response_bytes' THEN response_size := (NEW.evidence ->> 'response_bytes')::bigint; IF response_size < 0 OR response_size > 16777216 THEN RAISE EXCEPTION 'Egress health evidence is invalid' USING ERRCODE = '23514'; END IF; END IF;
          IF challenge THEN NEW.outcome := 'BOT_CHALLENGE'; NEW.healthy := false; NEW.retryable := false;
          ELSIF login THEN NEW.outcome := 'LOGIN_REQUIRED'; NEW.healthy := false; NEW.retryable := false;
          ELSIF status_code = 403 THEN NEW.outcome := 'HTTP_403'; NEW.healthy := false; NEW.retryable := false;
          ELSIF status_code = 429 THEN NEW.outcome := 'HTTP_429'; NEW.healthy := false; NEW.retryable := true;
          ELSIF status_code >= 400 THEN NEW.outcome := 'HTTP_ERROR'; NEW.healthy := false; NEW.retryable := status_code >= 500;
          ELSIF response_size = 0 THEN NEW.outcome := 'EMPTY_RESPONSE'; NEW.healthy := false; NEW.retryable := true;
          ELSE NEW.outcome := 'SUCCESS'; NEW.healthy := true; NEW.retryable := false; END IF;
          RETURN NEW;
        END; $$
    """)
    for column in ("login_required", "challenge_detected", "latency_ms", "response_bytes", "http_status", "transport_failure"):
        op.drop_column("egress_health_observations", column, schema="control")
    op.execute("ALTER TABLE control.egress_health_observations ENABLE TRIGGER egress_health_observations_immutable")
