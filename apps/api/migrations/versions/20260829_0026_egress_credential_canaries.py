"""Add race-safe credential-rotation canary attempts and history.

Revision ID: 20260829_0026
Revises: 20260828_0025
"""
# ruff: noqa: E501

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260829_0026"
down_revision: str | None = "20260828_0025"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None
UUID = postgresql.UUID(as_uuid=True)


def upgrade() -> None:
    op.create_table(
        "egress_credential_canary_attempts",
        sa.Column("id", UUID, server_default=sa.text("gen_random_uuid()"), primary_key=True),
        sa.Column("organization_id", UUID, nullable=False),
        sa.Column("project_id", UUID, nullable=False),
        sa.Column("policy_id", UUID, nullable=False),
        sa.Column("policy_revision_id", UUID, nullable=False),
        sa.Column("credential_secret_id", UUID, nullable=False),
        sa.Column("secret_version", sa.BigInteger(), nullable=False),
        sa.Column("target_digest", sa.String(64), nullable=False),
        sa.Column("provider_key", sa.String(64), nullable=False),
        sa.Column("region_key", sa.String(64), nullable=False),
        sa.Column("status", sa.String(16), server_default="PENDING", nullable=False),
        sa.Column("attempt_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("claim_token", UUID),
        sa.Column("claim_expires_at", sa.DateTime(timezone=True)),
        sa.Column("scheduled_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
        sa.Column("claimed_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("outcome", sa.String(32)),
        sa.Column("healthy", sa.Boolean()),
        sa.Column("retryable", sa.Boolean()),
        sa.Column("version", sa.BigInteger(), server_default="1", nullable=False),
        sa.UniqueConstraint("policy_revision_id", "secret_version", "target_digest", name="uq_egress_credential_canary_binding"),
        sa.CheckConstraint("secret_version >= 1", name="ck_egress_credential_canary_secret_version"),
        sa.CheckConstraint("target_digest ~ '^[0-9a-f]{64}$'", name="ck_egress_credential_canary_target_digest"),
        sa.CheckConstraint("provider_key ~ '^[a-z0-9][a-z0-9._-]{0,63}$'", name="ck_egress_credential_canary_provider_key"),
        sa.CheckConstraint("region_key ~ '^[a-z0-9][a-z0-9._-]{0,63}$'", name="ck_egress_credential_canary_region_key"),
        sa.CheckConstraint("status IN ('PENDING','CLAIMED','SUCCEEDED','FAILED','SUPERSEDED')", name="ck_egress_credential_canary_status"),
        sa.CheckConstraint("attempt_count BETWEEN 0 AND 5", name="ck_egress_credential_canary_attempt_count"),
        sa.CheckConstraint("version >= 1", name="ck_egress_credential_canary_version"),
        sa.CheckConstraint("claim_expires_at IS NULL OR (claimed_at IS NOT NULL AND claim_expires_at BETWEEN claimed_at + INTERVAL '15 seconds' AND claimed_at + INTERVAL '5 minutes')", name="ck_egress_credential_canary_claim_window"),
        sa.CheckConstraint("completed_at IS NULL OR (claimed_at IS NOT NULL AND completed_at >= claimed_at)", name="ck_egress_credential_canary_completion_time"),
        sa.CheckConstraint("(status = 'PENDING' AND claim_token IS NULL AND claim_expires_at IS NULL AND claimed_at IS NULL AND completed_at IS NULL AND outcome IS NULL AND healthy IS NULL AND retryable IS NULL) OR (status = 'CLAIMED' AND claim_token IS NOT NULL AND claim_expires_at IS NOT NULL AND claimed_at IS NOT NULL AND completed_at IS NULL AND outcome IS NULL AND healthy IS NULL AND retryable IS NULL) OR (status IN ('SUCCEEDED','FAILED','SUPERSEDED') AND claim_token IS NOT NULL AND claim_expires_at IS NOT NULL AND claimed_at IS NOT NULL AND completed_at IS NOT NULL AND outcome IS NOT NULL AND healthy IS NOT NULL AND retryable IS NOT NULL)", name="ck_egress_credential_canary_lifecycle"),
        sa.CheckConstraint("outcome IS NULL OR outcome IN ('SUCCESS','AUTH_REJECTED','TARGET_ERROR','TIMEOUT','TLS_FAILURE','DNS_FAILURE','CONFIGURATION_ERROR','SECRET_VERSION_SUPERSEDED','MAX_ATTEMPTS_EXCEEDED')", name="ck_egress_credential_canary_outcome"),
        sa.ForeignKeyConstraint(["organization_id"], ["identity.organizations.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["project_id"], ["control.projects.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["policy_id"], ["control.egress_policies.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["policy_revision_id"], ["control.egress_policy_revisions.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["credential_secret_id"], ["security.project_secrets.id"], ondelete="RESTRICT"),
        schema="control",
    )
    op.create_table(
        "egress_credential_canary_transitions",
        sa.Column("id", UUID, server_default=sa.text("gen_random_uuid()"), primary_key=True),
        sa.Column("organization_id", UUID, nullable=False),
        sa.Column("project_id", UUID, nullable=False),
        sa.Column("attempt_id", UUID, nullable=False),
        sa.Column("attempt_version", sa.BigInteger(), nullable=False),
        sa.Column("from_status", sa.String(16)),
        sa.Column("to_status", sa.String(16), nullable=False),
        sa.Column("event", sa.String(24), nullable=False),
        sa.Column("outcome", sa.String(32)),
        sa.Column("healthy", sa.Boolean()),
        sa.Column("retryable", sa.Boolean()),
        sa.Column("observed_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
        sa.UniqueConstraint("attempt_id", "attempt_version", name="uq_egress_credential_canary_transition_version"),
        sa.CheckConstraint("attempt_version >= 1", name="ck_egress_credential_canary_transition_version"),
        sa.CheckConstraint("from_status IS NULL OR from_status IN ('PENDING','CLAIMED')", name="ck_egress_credential_canary_transition_from_status"),
        sa.CheckConstraint("to_status IN ('PENDING','CLAIMED','SUCCEEDED','FAILED','SUPERSEDED')", name="ck_egress_credential_canary_transition_to_status"),
        sa.CheckConstraint("event IN ('ENQUEUED','CLAIMED','RECLAIMED','SUCCEEDED','FAILED','SUPERSEDED')", name="ck_egress_credential_canary_transition_event"),
        sa.CheckConstraint("outcome IS NULL OR outcome IN ('SUCCESS','AUTH_REJECTED','TARGET_ERROR','TIMEOUT','TLS_FAILURE','DNS_FAILURE','CONFIGURATION_ERROR','SECRET_VERSION_SUPERSEDED','MAX_ATTEMPTS_EXCEEDED')", name="ck_egress_credential_canary_transition_outcome"),
        sa.CheckConstraint("(event = 'ENQUEUED' AND from_status IS NULL AND to_status = 'PENDING' AND outcome IS NULL AND healthy IS NULL AND retryable IS NULL) OR (event = 'CLAIMED' AND from_status = 'PENDING' AND to_status = 'CLAIMED' AND outcome IS NULL AND healthy IS NULL AND retryable IS NULL) OR (event = 'RECLAIMED' AND from_status = 'CLAIMED' AND to_status = 'PENDING' AND outcome IS NULL AND healthy IS NULL AND retryable IS NULL) OR (event = to_status AND from_status = 'CLAIMED' AND to_status IN ('SUCCEEDED','FAILED','SUPERSEDED') AND outcome IS NOT NULL AND healthy IS NOT NULL AND retryable IS NOT NULL)", name="ck_egress_credential_canary_transition_shape"),
        sa.ForeignKeyConstraint(["organization_id"], ["identity.organizations.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["project_id"], ["control.projects.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["attempt_id"], ["control.egress_credential_canary_attempts.id"], ondelete="RESTRICT"),
        schema="control",
    )
    for name, table, columns in (
        ("ix_ecc_attempts_organization", "egress_credential_canary_attempts", ["organization_id"]),
        ("ix_ecc_attempts_project_scheduled", "egress_credential_canary_attempts", ["project_id", "scheduled_at"]),
        ("ix_ecc_attempts_status_scheduled", "egress_credential_canary_attempts", ["status", "scheduled_at"]),
        ("ix_ecc_attempts_secret_version", "egress_credential_canary_attempts", ["credential_secret_id", "secret_version"]),
        ("ix_ecc_transitions_organization", "egress_credential_canary_transitions", ["organization_id"]),
        ("ix_ecc_transitions_project_observed", "egress_credential_canary_transitions", ["project_id", "observed_at"]),
    ):
        op.create_index(name, table, columns, schema="control")

    op.execute("""
        CREATE OR REPLACE FUNCTION control.enforce_egress_credential_canary_insert()
        RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = control, security, identity, pg_temp AS $$
        DECLARE revision_record record;
        BEGIN
          SELECT revision.organization_id, revision.project_id, revision.policy_id,
                 revision.credential_secret_id, secret.version AS secret_version
          INTO revision_record
          FROM control.egress_policy_revisions revision
          JOIN control.egress_policies policy ON policy.id = revision.policy_id
          JOIN security.project_secrets secret ON secret.id = revision.credential_secret_id
          WHERE revision.id = NEW.policy_revision_id
            AND policy.id = revision.policy_id
            AND policy.organization_id = revision.organization_id
            AND policy.project_id = revision.project_id
            AND policy.status = 'ACTIVE'
            AND policy.active_revision_id = revision.id
            AND secret.organization_id = revision.organization_id
            AND secret.project_id = revision.project_id;
          IF NOT FOUND THEN
            RAISE EXCEPTION 'Egress credential canary binding is ineligible' USING ERRCODE = '23514';
          END IF;
          NEW.organization_id := revision_record.organization_id;
          NEW.project_id := revision_record.project_id;
          NEW.policy_id := revision_record.policy_id;
          NEW.credential_secret_id := revision_record.credential_secret_id;
          NEW.secret_version := revision_record.secret_version;
          NEW.status := 'PENDING'; NEW.attempt_count := 0; NEW.claim_token := NULL;
          NEW.claim_expires_at := NULL; NEW.claimed_at := NULL; NEW.completed_at := NULL;
          NEW.outcome := NULL; NEW.healthy := NULL; NEW.retryable := NULL; NEW.version := 1;
          RETURN NEW;
        END; $$
    """)
    op.execute("CREATE TRIGGER egress_credential_canary_insert_guard BEFORE INSERT ON control.egress_credential_canary_attempts FOR EACH ROW EXECUTE FUNCTION control.enforce_egress_credential_canary_insert()")
    op.execute("""
        CREATE OR REPLACE FUNCTION control.enforce_egress_credential_canary_transition()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF ROW(NEW.organization_id, NEW.project_id, NEW.policy_id, NEW.policy_revision_id,
                 NEW.credential_secret_id, NEW.secret_version, NEW.target_digest,
                 NEW.provider_key, NEW.region_key, NEW.scheduled_at)
             IS DISTINCT FROM
             ROW(OLD.organization_id, OLD.project_id, OLD.policy_id, OLD.policy_revision_id,
                 OLD.credential_secret_id, OLD.secret_version, OLD.target_digest,
                 OLD.provider_key, OLD.region_key, OLD.scheduled_at) THEN
            RAISE EXCEPTION 'Egress credential canary lineage is immutable' USING ERRCODE = '23514';
          END IF;
          IF OLD.status IN ('SUCCEEDED','FAILED','SUPERSEDED') OR NEW.version <> OLD.version + 1 THEN
            RAISE EXCEPTION 'Egress credential canary transition is invalid' USING ERRCODE = '23514';
          END IF;
          IF OLD.status = 'PENDING' AND NEW.status = 'CLAIMED' THEN
            IF NEW.attempt_count <> OLD.attempt_count + 1 OR NEW.claim_token IS NULL
               OR NEW.claimed_at IS NULL OR NEW.claim_expires_at <= NEW.claimed_at THEN
              RAISE EXCEPTION 'Egress credential canary claim is invalid' USING ERRCODE = '23514';
            END IF;
          ELSIF OLD.status = 'CLAIMED' AND NEW.status = 'PENDING' THEN
            IF NEW.attempt_count <> OLD.attempt_count OR NEW.claim_token IS NOT NULL
               OR NEW.claim_expires_at IS NOT NULL OR NEW.claimed_at IS NOT NULL OR NEW.completed_at IS NOT NULL
               OR NEW.outcome IS NOT NULL OR NEW.healthy IS NOT NULL OR NEW.retryable IS NOT NULL THEN
              RAISE EXCEPTION 'Egress credential canary reclaim is invalid' USING ERRCODE = '23514';
            END IF;
          ELSIF OLD.status = 'CLAIMED' AND NEW.status IN ('SUCCEEDED','FAILED','SUPERSEDED') THEN
            IF NEW.attempt_count <> OLD.attempt_count OR NEW.claim_token <> OLD.claim_token
               OR NEW.claimed_at <> OLD.claimed_at OR NEW.claim_expires_at <> OLD.claim_expires_at
               OR NEW.completed_at IS NULL OR NEW.outcome IS NULL
               OR NEW.healthy IS NULL OR NEW.retryable IS NULL THEN
              RAISE EXCEPTION 'Egress credential canary completion is invalid' USING ERRCODE = '23514';
            END IF;
            IF (NEW.status = 'SUCCEEDED' AND (NEW.outcome <> 'SUCCESS' OR NOT NEW.healthy OR NEW.retryable))
               OR (NEW.status = 'SUPERSEDED' AND (NEW.outcome <> 'SECRET_VERSION_SUPERSEDED' OR NEW.healthy OR NEW.retryable))
               OR (NEW.status = 'FAILED' AND (NEW.outcome IN ('SUCCESS','SECRET_VERSION_SUPERSEDED') OR NEW.healthy)) THEN
              RAISE EXCEPTION 'Egress credential canary result is invalid' USING ERRCODE = '23514';
            END IF;
          ELSE
            RAISE EXCEPTION 'Egress credential canary transition is invalid' USING ERRCODE = '23514';
          END IF;
          RETURN NEW;
        END; $$
    """)
    op.execute("CREATE TRIGGER egress_credential_canary_transition_guard BEFORE UPDATE ON control.egress_credential_canary_attempts FOR EACH ROW EXECUTE FUNCTION control.enforce_egress_credential_canary_transition()")
    op.execute("""
        CREATE OR REPLACE FUNCTION control.record_egress_credential_canary_transition()
        RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = control, pg_temp AS $$
        DECLARE event_name text;
        BEGIN
          event_name := CASE
            WHEN TG_OP = 'INSERT' THEN 'ENQUEUED'
            WHEN NEW.status = 'CLAIMED' THEN 'CLAIMED'
            WHEN NEW.status = 'PENDING' THEN 'RECLAIMED'
            ELSE NEW.status
          END;
          INSERT INTO control.egress_credential_canary_transitions
            (organization_id, project_id, attempt_id, attempt_version, from_status, to_status, event, outcome, healthy, retryable, observed_at)
          VALUES
            (NEW.organization_id, NEW.project_id, NEW.id, NEW.version,
             CASE WHEN TG_OP = 'INSERT' THEN NULL ELSE OLD.status END,
             NEW.status, event_name, NEW.outcome, NEW.healthy, NEW.retryable, CURRENT_TIMESTAMP);
          RETURN NEW;
        END; $$
    """)
    op.execute("CREATE TRIGGER egress_credential_canary_history AFTER INSERT OR UPDATE ON control.egress_credential_canary_attempts FOR EACH ROW EXECUTE FUNCTION control.record_egress_credential_canary_transition()")
    op.execute("""
        CREATE OR REPLACE FUNCTION control.reject_egress_credential_canary_mutation()
        RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
          RAISE EXCEPTION 'Egress credential canary history is immutable' USING ERRCODE = '23514';
        END; $$
    """)
    op.execute("CREATE TRIGGER egress_credential_canary_attempt_delete_guard BEFORE DELETE ON control.egress_credential_canary_attempts FOR EACH ROW EXECUTE FUNCTION control.reject_egress_credential_canary_mutation()")
    op.execute("CREATE TRIGGER egress_credential_canary_transitions_immutable BEFORE UPDATE OR DELETE ON control.egress_credential_canary_transitions FOR EACH ROW EXECUTE FUNCTION control.reject_egress_credential_canary_mutation()")

    for table in ("egress_credential_canary_attempts", "egress_credential_canary_transitions"):
        op.execute(f"ALTER TABLE control.{table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"CREATE POLICY {table}_tenant_select ON control.{table} FOR SELECT USING (organization_id = security.rdc_current_org_id() AND security.rdc_has_org_membership(organization_id))")
    scheduler = "NULLIF(current_setting('rdc.egress_canary_scheduler', true), '') = '1'"
    op.execute(f"CREATE POLICY egress_credential_canary_attempts_scheduler_select ON control.egress_credential_canary_attempts FOR SELECT USING ({scheduler})")
    op.execute(f"CREATE POLICY egress_credential_canary_attempts_scheduler_insert ON control.egress_credential_canary_attempts FOR INSERT WITH CHECK ({scheduler})")
    op.execute(f"CREATE POLICY egress_credential_canary_attempts_scheduler_update ON control.egress_credential_canary_attempts FOR UPDATE USING ({scheduler}) WITH CHECK ({scheduler})")


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS egress_credential_canary_transitions_immutable ON control.egress_credential_canary_transitions")
    op.execute("DROP TRIGGER IF EXISTS egress_credential_canary_attempt_delete_guard ON control.egress_credential_canary_attempts")
    op.execute("DROP TRIGGER IF EXISTS egress_credential_canary_history ON control.egress_credential_canary_attempts")
    op.execute("DROP TRIGGER IF EXISTS egress_credential_canary_transition_guard ON control.egress_credential_canary_attempts")
    op.execute("DROP TRIGGER IF EXISTS egress_credential_canary_insert_guard ON control.egress_credential_canary_attempts")
    op.execute("DROP FUNCTION IF EXISTS control.reject_egress_credential_canary_mutation()")
    op.execute("DROP FUNCTION IF EXISTS control.record_egress_credential_canary_transition()")
    op.execute("DROP FUNCTION IF EXISTS control.enforce_egress_credential_canary_transition()")
    op.execute("DROP FUNCTION IF EXISTS control.enforce_egress_credential_canary_insert()")
    op.drop_table("egress_credential_canary_transitions", schema="control")
    op.drop_table("egress_credential_canary_attempts", schema="control")
