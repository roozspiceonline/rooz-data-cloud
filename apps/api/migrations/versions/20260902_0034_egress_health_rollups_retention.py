"""Add egress-health hourly rollups and bounded retention state.

Revision ID: 20260902_0034
Revises: 20260901_0033
"""

# ruff: noqa: E501
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260902_0034"
down_revision: str | None = "20260901_0033"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None
UUID = postgresql.UUID(as_uuid=True)


def upgrade() -> None:
    op.create_table(
        "egress_health_rollup_buckets",
        sa.Column("organization_id", UUID, nullable=False),
        sa.Column("project_id", UUID, nullable=False),
        sa.Column("bucket_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("provider_key", sa.String(64), nullable=False),
        sa.Column("region_key", sa.String(64), nullable=False),
        sa.Column("outcome", sa.String(32), nullable=False),
        sa.Column("total_count", sa.BigInteger(), nullable=False),
        sa.Column("healthy_count", sa.BigInteger(), nullable=False),
        sa.Column("retryable_count", sa.BigInteger(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["identity.organizations.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["project_id"], ["control.projects.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("project_id", "bucket_start", "provider_key", "region_key", "outcome", name="pk_egress_health_rollup_buckets"),
        sa.CheckConstraint("bucket_start = date_trunc('hour', bucket_start)", name="ck_egress_health_rollup_bucket_hour"),
        sa.CheckConstraint("provider_key ~ '^[a-z0-9][a-z0-9._-]{0,63}$'", name="ck_egress_health_rollup_provider_key"),
        sa.CheckConstraint("region_key ~ '^[a-z0-9][a-z0-9._-]{0,63}$'", name="ck_egress_health_rollup_region_key"),
        sa.CheckConstraint("outcome IN ('SUCCESS','HTTP_403','HTTP_429','BOT_CHALLENGE','LOGIN_REQUIRED','EMPTY_RESPONSE','HTTP_ERROR','DNS_FAILURE','TLS_FAILURE','TIMEOUT','PROXY_FAILURE')", name="ck_egress_health_rollup_outcome"),
        sa.CheckConstraint("total_count > 0 AND healthy_count BETWEEN 0 AND total_count AND retryable_count BETWEEN 0 AND total_count", name="ck_egress_health_rollup_counts"),
        schema="control",
    )
    op.create_index("ix_egress_health_rollup_org_bucket", "egress_health_rollup_buckets", ["organization_id", "bucket_start"], schema="control")
    op.create_table(
        "egress_health_maintenance_state",
        sa.Column("id", sa.SmallInteger(), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("owner_id", sa.String(200)),
        sa.Column("last_started_at", sa.DateTime(timezone=True)),
        sa.Column("last_completed_at", sa.DateTime(timezone=True)),
        sa.Column("last_heartbeat_at", sa.DateTime(timezone=True)),
        sa.Column("last_buckets_rolled", sa.Integer(), nullable=False),
        sa.Column("last_raw_rows_purged", sa.Integer(), nullable=False),
        sa.Column("last_rollup_rows_purged", sa.Integer(), nullable=False),
        sa.Column("total_sweeps", sa.BigInteger(), nullable=False),
        sa.Column("total_failures", sa.BigInteger(), nullable=False),
        sa.Column("total_buckets_rolled", sa.BigInteger(), nullable=False),
        sa.Column("total_raw_rows_purged", sa.BigInteger(), nullable=False),
        sa.Column("total_rollup_rows_purged", sa.BigInteger(), nullable=False),
        sa.Column("last_error_code", sa.String(80)),
        sa.Column("last_error_summary", sa.String(240)),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint("id = 1", name="ck_egress_health_maintenance_singleton"),
        sa.CheckConstraint("status IN ('NEVER_RUN','HEALTHY','FAILED')", name="ck_egress_health_maintenance_status"),
        sa.CheckConstraint("last_buckets_rolled >= 0 AND last_raw_rows_purged >= 0 AND last_rollup_rows_purged >= 0 AND total_sweeps >= 0 AND total_failures >= 0 AND total_buckets_rolled >= 0 AND total_raw_rows_purged >= 0 AND total_rollup_rows_purged >= 0", name="ck_egress_health_maintenance_counts"),
        schema="control",
    )
    op.execute("""INSERT INTO control.egress_health_maintenance_state (id,status,last_buckets_rolled,last_raw_rows_purged,last_rollup_rows_purged,total_sweeps,total_failures,total_buckets_rolled,total_raw_rows_purged,total_rollup_rows_purged) VALUES (1,'NEVER_RUN',0,0,0,0,0,0,0,0)""")
    op.execute("""
      CREATE OR REPLACE FUNCTION control.egress_health_observation_immutable()
      RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,control,pg_temp AS $$
      DECLARE retention_cutoff timestamptz;
      BEGIN
        retention_cutoff:=NULLIF(current_setting('rdc.egress_health_raw_retention_cutoff',true),'')::timestamptz;
        IF TG_OP='DELETE' AND retention_cutoff IS NOT NULL
           AND retention_cutoff<=clock_timestamp()-interval '48 hours'
           AND OLD.observed_at<retention_cutoff THEN RETURN OLD; END IF;
        RAISE EXCEPTION 'Egress health observations are immutable' USING ERRCODE='23514';
      END; $$
    """)
    op.execute("""
      CREATE OR REPLACE FUNCTION control.enforce_egress_health_rollup_bucket()
      RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,control,pg_temp AS $$
      DECLARE retention_cutoff timestamptz;
      BEGIN
        IF TG_OP='INSERT' THEN
          IF NOT EXISTS (SELECT 1 FROM control.projects project WHERE project.id=NEW.project_id AND project.organization_id=NEW.organization_id) THEN
            RAISE EXCEPTION 'Egress health rollup project tenancy mismatch' USING ERRCODE='23514';
          END IF;
          RETURN NEW;
        END IF;
        retention_cutoff:=NULLIF(current_setting('rdc.egress_health_rollup_retention_cutoff',true),'')::timestamptz;
        IF TG_OP='DELETE' AND retention_cutoff IS NOT NULL
           AND retention_cutoff<=date_trunc('hour',clock_timestamp()-interval '7 days')
           AND OLD.bucket_start<retention_cutoff THEN RETURN OLD; END IF;
        RAISE EXCEPTION 'Egress health rollup buckets are immutable' USING ERRCODE='23514';
      END; $$
    """)
    op.execute("CREATE TRIGGER egress_health_rollup_buckets_guard BEFORE INSERT OR UPDATE OR DELETE ON control.egress_health_rollup_buckets FOR EACH ROW EXECUTE FUNCTION control.enforce_egress_health_rollup_bucket()")
    op.execute("""
      CREATE OR REPLACE FUNCTION control.run_egress_health_maintenance(
        p_now timestamptz,p_rollup_batch_size integer,p_purge_batch_size integer,
        p_raw_retention_hours integer,p_rollup_retention_days integer,p_owner_id text
      ) RETURNS TABLE(acquired boolean,buckets_rolled integer,raw_rows_purged integer,rollup_rows_purged integer)
      LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,control,security,pg_temp AS $$
      DECLARE server_now timestamptz; raw_cutoff timestamptz; rollup_cutoff timestamptz;
      BEGIN
        server_now:=clock_timestamp();
        IF p_now IS NULL OR abs(extract(epoch FROM (p_now-server_now)))>5
           OR p_rollup_batch_size NOT BETWEEN 1 AND 168
           OR p_purge_batch_size NOT BETWEEN 1 AND 10000
           OR p_raw_retention_hours NOT BETWEEN 48 AND 168
           OR p_rollup_retention_days NOT BETWEEN 7 AND 90
           OR p_owner_id IS NULL OR length(p_owner_id) NOT BETWEEN 1 AND 200 THEN
          RAISE EXCEPTION 'Egress health maintenance bounds are invalid' USING ERRCODE='22023';
        END IF;
        p_now:=server_now;
        acquired:=pg_try_advisory_xact_lock(hashtextextended('rdc:egress-health-maintenance:v1',0));
        buckets_rolled:=0; raw_rows_purged:=0; rollup_rows_purged:=0;
        IF NOT acquired THEN RETURN NEXT; RETURN; END IF;
        WITH candidate_buckets AS MATERIALIZED (
          SELECT observation.organization_id,observation.project_id,date_trunc('hour',observation.observed_at) AS bucket_start
          FROM control.egress_health_observations observation
          WHERE observation.observed_at<date_trunc('hour',p_now)
            AND NOT EXISTS (SELECT 1 FROM control.egress_health_rollup_buckets rollup WHERE rollup.project_id=observation.project_id AND rollup.bucket_start=date_trunc('hour',observation.observed_at))
          GROUP BY observation.organization_id,observation.project_id,date_trunc('hour',observation.observed_at)
          ORDER BY bucket_start,observation.project_id LIMIT p_rollup_batch_size
        ), inserted AS (
          INSERT INTO control.egress_health_rollup_buckets
            (organization_id,project_id,bucket_start,provider_key,region_key,outcome,total_count,healthy_count,retryable_count,created_at)
          SELECT observation.organization_id,observation.project_id,candidate.bucket_start,observation.provider_key,observation.region_key,observation.outcome,
                 count(*),count(*) FILTER (WHERE observation.healthy),count(*) FILTER (WHERE observation.retryable),p_now
          FROM candidate_buckets candidate JOIN control.egress_health_observations observation
            ON observation.organization_id=candidate.organization_id AND observation.project_id=candidate.project_id
           AND observation.observed_at>=candidate.bucket_start AND observation.observed_at<candidate.bucket_start+interval '1 hour'
          GROUP BY observation.organization_id,observation.project_id,candidate.bucket_start,observation.provider_key,observation.region_key,observation.outcome
          ON CONFLICT DO NOTHING RETURNING project_id,bucket_start
        ) SELECT count(DISTINCT (project_id,bucket_start))::integer INTO buckets_rolled FROM inserted;
        raw_cutoff:=p_now-make_interval(hours=>p_raw_retention_hours);
        PERFORM set_config('rdc.egress_health_raw_retention_cutoff',raw_cutoff::text,true);
        WITH candidates AS MATERIALIZED (
          SELECT observation.ctid FROM control.egress_health_observations observation
          WHERE observation.observed_at<raw_cutoff AND EXISTS (
            SELECT 1 FROM control.egress_health_rollup_buckets rollup
            WHERE rollup.project_id=observation.project_id AND rollup.bucket_start=date_trunc('hour',observation.observed_at)
          ) ORDER BY observation.observed_at,observation.id LIMIT p_purge_batch_size
        ), deleted AS (
          DELETE FROM control.egress_health_observations observation USING candidates
          WHERE observation.ctid=candidates.ctid RETURNING observation.id
        ) SELECT count(*)::integer INTO raw_rows_purged FROM deleted;
        rollup_cutoff:=date_trunc('hour',p_now-make_interval(days=>p_rollup_retention_days));
        PERFORM set_config('rdc.egress_health_rollup_retention_cutoff',rollup_cutoff::text,true);
        WITH candidates AS MATERIALIZED (
          SELECT rollup.ctid FROM control.egress_health_rollup_buckets rollup
          WHERE rollup.bucket_start<rollup_cutoff
          ORDER BY rollup.bucket_start,rollup.project_id,rollup.provider_key,rollup.region_key,rollup.outcome LIMIT p_purge_batch_size
        ), deleted AS (
          DELETE FROM control.egress_health_rollup_buckets rollup USING candidates
          WHERE rollup.ctid=candidates.ctid RETURNING rollup.project_id
        ) SELECT count(*)::integer INTO rollup_rows_purged FROM deleted;
        UPDATE control.egress_health_maintenance_state SET status='HEALTHY',owner_id=left(p_owner_id,200),last_started_at=p_now,
          last_completed_at=p_now,last_heartbeat_at=p_now,last_buckets_rolled=buckets_rolled,last_raw_rows_purged=raw_rows_purged,
          last_rollup_rows_purged=rollup_rows_purged,total_sweeps=total_sweeps+1,total_buckets_rolled=total_buckets_rolled+buckets_rolled,
          total_raw_rows_purged=total_raw_rows_purged+raw_rows_purged,total_rollup_rows_purged=total_rollup_rows_purged+rollup_rows_purged,
          last_error_code=NULL,last_error_summary=NULL,updated_at=p_now WHERE id=1;
        IF NOT FOUND THEN RAISE EXCEPTION 'Egress health maintenance state is not initialized'; END IF;
        RETURN NEXT;
      END; $$
    """)
    op.execute("REVOKE ALL ON FUNCTION control.run_egress_health_maintenance(timestamptz,integer,integer,integer,integer,text) FROM PUBLIC")
    op.execute("ALTER TABLE control.egress_health_rollup_buckets ENABLE ROW LEVEL SECURITY")
    tenant = "organization_id = security.rdc_current_org_id() AND security.rdc_has_org_membership(organization_id)"
    op.execute(f"CREATE POLICY egress_health_rollup_buckets_tenant_select ON control.egress_health_rollup_buckets FOR SELECT USING ({tenant})")


def downgrade() -> None:
    op.execute("DROP FUNCTION IF EXISTS control.run_egress_health_maintenance(timestamptz,integer,integer,integer,integer,text)")
    op.execute("DROP POLICY IF EXISTS egress_health_rollup_buckets_tenant_select ON control.egress_health_rollup_buckets")
    op.execute("DROP TRIGGER IF EXISTS egress_health_rollup_buckets_guard ON control.egress_health_rollup_buckets")
    op.execute("DROP FUNCTION IF EXISTS control.enforce_egress_health_rollup_bucket()")
    op.execute("""CREATE OR REPLACE FUNCTION control.egress_health_observation_immutable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'Egress health observations are immutable' USING ERRCODE='23514'; END; $$""")
    op.drop_table("egress_health_maintenance_state", schema="control")
    op.drop_table("egress_health_rollup_buckets", schema="control")
