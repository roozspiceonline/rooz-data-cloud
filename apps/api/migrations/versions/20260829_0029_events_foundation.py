"""Add immutable tenant-isolated RDC lifecycle events.

Revision ID: 20260829_0029
Revises: 20260829_0028
"""
# ruff: noqa: E501

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260829_0029"
down_revision: str | None = "20260829_0028"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

UUID = postgresql.UUID(as_uuid=True)


def upgrade() -> None:
    op.execute("""
        CREATE OR REPLACE FUNCTION security.rdc_current_project_id()
        RETURNS uuid LANGUAGE sql STABLE AS $$
          SELECT NULLIF(current_setting('rdc.current_project_id', true), '')::uuid
        $$
    """)
    op.execute("""
        CREATE OR REPLACE FUNCTION control.event_payload_is_safe(
          p_value jsonb, p_depth integer DEFAULT 0
        ) RETURNS boolean LANGUAGE plpgsql IMMUTABLE
        SET search_path = pg_catalog, control, pg_temp AS $$
        DECLARE
          pair record;
          item jsonb;
          normalized_key text;
          kind text;
        BEGIN
          IF p_depth > 8 THEN RETURN FALSE; END IF;
          kind := jsonb_typeof(p_value);
          IF kind = 'object' THEN
            IF (SELECT count(*) FROM jsonb_each(p_value)) > 64 THEN RETURN FALSE; END IF;
            FOR pair IN SELECT * FROM jsonb_each(p_value) LOOP
              IF octet_length(convert_to(pair.key, 'UTF8')) NOT BETWEEN 1 AND 64 THEN
                RETURN FALSE;
              END IF;
              normalized_key := lower(regexp_replace(pair.key, '[^a-z0-9]', '', 'g'));
              IF normalized_key ~ '(authorization|password|secret|credential|token|cookie|databaseurl|redisurl|s3accesskey|s3secretkey|objectstoragecredential)' THEN
                RETURN FALSE;
              END IF;
              IF NOT control.event_payload_is_safe(pair.value, p_depth + 1) THEN
                RETURN FALSE;
              END IF;
            END LOOP;
            RETURN TRUE;
          ELSIF kind = 'array' THEN
            IF jsonb_array_length(p_value) > 100 THEN RETURN FALSE; END IF;
            FOR item IN SELECT * FROM jsonb_array_elements(p_value) LOOP
              IF NOT control.event_payload_is_safe(item, p_depth + 1) THEN
                RETURN FALSE;
              END IF;
            END LOOP;
            RETURN TRUE;
          ELSIF kind = 'string' THEN
            RETURN octet_length(convert_to(p_value #>> '{}', 'UTF8')) <= 2048;
          ELSIF kind = 'number' THEN
            RETURN length(p_value::text) <= 128;
          END IF;
          RETURN kind IN ('boolean', 'null');
        END; $$
    """)

    op.create_table(
        "events",
        sa.Column(
            "id",
            UUID,
            server_default=sa.text("gen_random_uuid()"),
            primary_key=True,
        ),
        sa.Column("organization_id", UUID, nullable=False),
        sa.Column("project_id", UUID, nullable=False),
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column("schema_version", sa.String(32), nullable=False),
        sa.Column("subject_type", sa.String(32), nullable=False),
        sa.Column("subject_id", UUID, nullable=False),
        sa.Column("payload", postgresql.JSONB(), nullable=False),
        sa.Column("payload_digest", sa.String(64), nullable=False),
        sa.Column("emitter", sa.String(32), nullable=False),
        sa.Column("request_id", sa.String(100), nullable=False),
        sa.Column(
            "occurred_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["identity.organizations.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["project_id"],
            ["control.projects.id"],
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint(
            "project_id",
            "event_type",
            "subject_type",
            "subject_id",
            name="uq_events_project_type_subject",
        ),
        sa.CheckConstraint(
            "event_type IN ('build.created','run.created')",
            name="ck_events_type",
        ),
        sa.CheckConstraint(
            "schema_version = 'rdc.event/v1'",
            name="ck_events_schema_version",
        ),
        sa.CheckConstraint(
            "(event_type = 'build.created' AND subject_type = 'build') OR "
            "(event_type = 'run.created' AND subject_type = 'run')",
            name="ck_events_subject_type",
        ),
        sa.CheckConstraint(
            "jsonb_typeof(payload) = 'object' "
            "AND octet_length(convert_to(payload::text, 'UTF8')) <= 16384 "
            "AND control.event_payload_is_safe(payload, 0)",
            name="ck_events_payload",
        ),
        sa.CheckConstraint(
            "payload_digest ~ '^[0-9a-f]{64}$'",
            name="ck_events_payload_digest",
        ),
        sa.CheckConstraint(
            "emitter = 'control-plane'",
            name="ck_events_emitter",
        ),
        sa.CheckConstraint(
            "request_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$'",
            name="ck_events_request_id",
        ),
        schema="control",
    )
    op.create_index(
        "ix_events_organization_id",
        "events",
        ["organization_id"],
        schema="control",
    )
    op.create_index(
        "ix_events_project_occurred",
        "events",
        ["project_id", "occurred_at", "id"],
        schema="control",
    )
    op.execute("ALTER TABLE control.events ENABLE ROW LEVEL SECURITY")

    op.execute("""
        CREATE OR REPLACE FUNCTION control.enforce_event_envelope()
        RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, control, identity, security, pg_temp AS $$
        DECLARE
          derived_organization_id uuid;
          subject_record record;
          server_now timestamptz;
        BEGIN
          SELECT project.organization_id INTO derived_organization_id
          FROM control.projects project
          WHERE project.id = NEW.project_id AND project.deleted_at IS NULL;
          IF NOT FOUND THEN
            RAISE EXCEPTION 'Event project reference is invalid' USING ERRCODE = '23514';
          END IF;
          NEW.organization_id := derived_organization_id;

          IF NEW.event_type = 'run.created' AND NEW.subject_type = 'run' THEN
            SELECT run.agent_id, run.agent_version_id, run.build_id, run.status
            INTO subject_record FROM control.runs run
            WHERE run.id = NEW.subject_id
              AND run.organization_id = derived_organization_id
              AND run.project_id = NEW.project_id;
            IF NOT FOUND
               OR NEW.payload->>'agent_id' <> subject_record.agent_id::text
               OR NEW.payload->>'agent_version_id' <> subject_record.agent_version_id::text
               OR NEW.payload->>'build_id' <> subject_record.build_id::text
               OR NEW.payload->>'status' <> subject_record.status THEN
              RAISE EXCEPTION 'Event Run reference is invalid' USING ERRCODE = '23514';
            END IF;
          ELSIF NEW.event_type = 'build.created' AND NEW.subject_type = 'build' THEN
            SELECT build.agent_id, build.agent_version_id, build.status
            INTO subject_record FROM control.builds build
            WHERE build.id = NEW.subject_id
              AND build.organization_id = derived_organization_id
              AND build.project_id = NEW.project_id;
            IF NOT FOUND
               OR NEW.payload->>'agent_id' <> subject_record.agent_id::text
               OR NEW.payload->>'agent_version_id' <> subject_record.agent_version_id::text
               OR NEW.payload->>'status' <> subject_record.status THEN
              RAISE EXCEPTION 'Event Build reference is invalid' USING ERRCODE = '23514';
            END IF;
          ELSE
            RAISE EXCEPTION 'Event type is not allowlisted' USING ERRCODE = '23514';
          END IF;

          server_now := clock_timestamp();
          NEW.schema_version := 'rdc.event/v1';
          NEW.payload_digest := encode(
            public.digest(convert_to(NEW.payload::text, 'UTF8'), 'sha256'), 'hex'
          );
          NEW.emitter := 'control-plane';
          NEW.occurred_at := server_now;
          NEW.created_at := server_now;
          RETURN NEW;
        END; $$
    """)
    op.execute("""
        CREATE TRIGGER events_envelope_guard
        BEFORE INSERT ON control.events
        FOR EACH ROW EXECUTE FUNCTION control.enforce_event_envelope()
    """)
    op.execute("""
        CREATE OR REPLACE FUNCTION control.event_immutable()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          RAISE EXCEPTION 'RDC events are immutable' USING ERRCODE = '23514';
        END; $$
    """)
    op.execute("""
        CREATE TRIGGER events_immutable
        BEFORE UPDATE OR DELETE ON control.events
        FOR EACH ROW EXECUTE FUNCTION control.event_immutable()
    """)

    tenant = (
        "organization_id = security.rdc_current_org_id() "
        "AND security.rdc_has_org_membership(organization_id)"
    )
    project = "project_id = security.rdc_current_project_id()"
    op.execute(
        "CREATE POLICY events_tenant_project_select ON control.events "
        f"FOR SELECT USING ({tenant} AND {project})"
    )
    op.execute(
        "CREATE POLICY events_tenant_project_insert ON control.events "
        f"FOR INSERT WITH CHECK ({tenant} AND {project})"
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS events_immutable ON control.events")
    op.execute("DROP TRIGGER IF EXISTS events_envelope_guard ON control.events")
    op.drop_table("events", schema="control")
    op.execute("DROP FUNCTION IF EXISTS control.event_immutable()")
    op.execute("DROP FUNCTION IF EXISTS control.enforce_event_envelope()")
    op.execute("DROP FUNCTION IF EXISTS control.event_payload_is_safe(jsonb,integer)")
    op.execute("DROP FUNCTION IF EXISTS security.rdc_current_project_id()")
