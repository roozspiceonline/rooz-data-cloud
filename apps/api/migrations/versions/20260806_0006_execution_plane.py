"""Create Phase 1F isolated execution-plane foundation.

Revision ID: 20260806_0006
Revises: 20260806_0005
Create Date: 2026-08-06
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260806_0006"
down_revision: str | None = "20260806_0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

UUID = postgresql.UUID(as_uuid=True)
JSONB = postgresql.JSONB(astext_type=sa.Text())


def upgrade() -> None:
    op.create_table(
        "worker_identities",
        sa.Column(
            "id",
            UUID,
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("public_prefix", sa.String(16), nullable=False),
        sa.Column("last_four", sa.String(4), nullable=False),
        sa.Column("token_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("capabilities", JSONB, nullable=False),
        sa.Column("max_concurrency", sa.Integer(), nullable=False),
        sa.Column(
            "status",
            sa.String(24),
            server_default="ACTIVE",
            nullable=False,
        ),
        sa.Column("protocol_version", sa.String(40), nullable=False),
        sa.Column("software_version", sa.String(80), nullable=False),
        sa.Column(
            "metadata_json",
            JSONB,
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "registered_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("last_seen_at", sa.DateTime(timezone=True)),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint(
            "status IN ('ACTIVE', 'DRAINING', 'REVOKED')",
            name="ck_worker_identities_status",
        ),
        sa.CheckConstraint(
            "max_concurrency BETWEEN 1 AND 256",
            name="ck_worker_identities_max_concurrency",
        ),
        sa.CheckConstraint(
            "jsonb_typeof(capabilities) = 'array'",
            name="ck_worker_identities_capabilities_array",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name", name="uq_worker_identities_name"),
        sa.UniqueConstraint(
            "public_prefix",
            name="uq_worker_identities_public_prefix",
        ),
        sa.UniqueConstraint(
            "token_digest",
            name="uq_worker_identities_token_digest",
        ),
        schema="security",
    )

    op.create_table(
        "execution_leases",
        sa.Column(
            "id",
            UUID,
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("worker_id", UUID, nullable=False),
        sa.Column("organization_id", UUID, nullable=False),
        sa.Column("project_id", UUID, nullable=False),
        sa.Column("work_kind", sa.String(24), nullable=False),
        sa.Column("source_outbox_id", UUID, nullable=False),
        sa.Column("source_topic", sa.String(120), nullable=False),
        sa.Column("build_id", UUID),
        sa.Column("run_id", UUID),
        sa.Column("lease_token_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("payload_digest", sa.String(64), nullable=False),
        sa.Column("payload_snapshot", JSONB, nullable=False),
        sa.Column(
            "status",
            sa.String(24),
            server_default="ACTIVE",
            nullable=False,
        ),
        sa.Column("attempt", sa.Integer(), nullable=False),
        sa.Column(
            "claimed_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_renewed_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
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
        sa.CheckConstraint(
            "work_kind IN ('BUILD', 'RUN_START', 'RUN_CANCEL')",
            name="ck_execution_leases_work_kind",
        ),
        sa.CheckConstraint(
            "status IN ('ACTIVE', 'COMPLETED', 'FAILED', 'EXPIRED', "
            "'CANCELLED')",
            name="ck_execution_leases_status",
        ),
        sa.CheckConstraint(
            "attempt BETWEEN 1 AND 20",
            name="ck_execution_leases_attempt",
        ),
        sa.CheckConstraint(
            "expires_at > claimed_at",
            name="ck_execution_leases_expiry",
        ),
        sa.CheckConstraint(
            "(work_kind = 'BUILD' AND build_id IS NOT NULL AND run_id IS NULL) "
            "OR (work_kind IN ('RUN_START', 'RUN_CANCEL') "
            "AND build_id IS NULL AND run_id IS NOT NULL)",
            name="ck_execution_leases_target",
        ),
        sa.ForeignKeyConstraint(
            ["worker_id"],
            ["security.worker_identities.id"],
            ondelete="RESTRICT",
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
            ["build_id"],
            ["control.builds.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["run_id"],
            ["control.runs.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "lease_token_digest",
            name="uq_execution_leases_token_digest",
        ),
        sa.UniqueConstraint(
            "work_kind",
            "source_outbox_id",
            "attempt",
            name="uq_execution_leases_source_attempt",
        ),
        schema="control",
    )
    for name, columns in [
        ("ix_execution_leases_worker_id", ["worker_id"]),
        ("ix_execution_leases_organization_id", ["organization_id"]),
        ("ix_execution_leases_project_id", ["project_id"]),
        ("ix_execution_leases_source_outbox_id", ["source_outbox_id"]),
        ("ix_execution_leases_build_id", ["build_id"]),
        ("ix_execution_leases_run_id", ["run_id"]),
    ]:
        op.create_index(name, "execution_leases", columns, schema="control")
    op.create_index(
        "ix_execution_leases_active_expiry",
        "execution_leases",
        ["status", "expires_at"],
        schema="control",
    )
    op.execute(
        """
        CREATE UNIQUE INDEX uq_execution_leases_active_source
        ON control.execution_leases (work_kind, source_outbox_id)
        WHERE status = 'ACTIVE'
        """
    )

    op.create_table(
        "execution_artifacts",
        sa.Column(
            "id",
            UUID,
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("organization_id", UUID, nullable=False),
        sa.Column("project_id", UUID, nullable=False),
        sa.Column("build_id", UUID),
        sa.Column("run_id", UUID),
        sa.Column("lease_id", UUID, nullable=False),
        sa.Column("created_by_worker_id", UUID, nullable=False),
        sa.Column("kind", sa.String(40), nullable=False),
        sa.Column(
            "digest_algorithm",
            sa.String(16),
            server_default="sha256",
            nullable=False,
        ),
        sa.Column("digest", sa.String(128), nullable=False),
        sa.Column("object_key", sa.String(1024), nullable=False),
        sa.Column("media_type", sa.String(160), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column(
            "status",
            sa.String(24),
            server_default="AVAILABLE",
            nullable=False,
        ),
        sa.Column(
            "scan_status",
            sa.String(24),
            server_default="PENDING",
            nullable=False,
        ),
        sa.Column(
            "provenance",
            JSONB,
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "kind IN ('CONTAINER_IMAGE', 'SBOM', 'PROVENANCE', "
            "'RUN_OUTPUT', 'LOG_BUNDLE')",
            name="ck_execution_artifacts_kind",
        ),
        sa.CheckConstraint(
            "status IN ('AVAILABLE', 'QUARANTINED', 'REJECTED', 'DELETED')",
            name="ck_execution_artifacts_status",
        ),
        sa.CheckConstraint(
            "scan_status IN ('PENDING', 'PASSED', 'FAILED', 'NOT_REQUIRED')",
            name="ck_execution_artifacts_scan_status",
        ),
        sa.CheckConstraint(
            "digest_algorithm = 'sha256' AND digest ~ '^[0-9a-f]{64}$'",
            name="ck_execution_artifacts_digest",
        ),
        sa.CheckConstraint(
            "size_bytes BETWEEN 0 AND 1099511627776",
            name="ck_execution_artifacts_size",
        ),
        sa.CheckConstraint(
            "object_key NOT LIKE '/%' AND object_key NOT LIKE '%..%'",
            name="ck_execution_artifacts_object_key",
        ),
        sa.CheckConstraint(
            "(build_id IS NOT NULL AND run_id IS NULL) "
            "OR (build_id IS NULL AND run_id IS NOT NULL)",
            name="ck_execution_artifacts_target",
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
            ["build_id"],
            ["control.builds.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["run_id"],
            ["control.runs.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["lease_id"],
            ["control.execution_leases.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["created_by_worker_id"],
            ["security.worker_identities.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "organization_id",
            "digest_algorithm",
            "digest",
            "kind",
            name="uq_execution_artifacts_digest_kind",
        ),
        schema="control",
    )
    for name, columns in [
        ("ix_execution_artifacts_organization_id", ["organization_id"]),
        ("ix_execution_artifacts_project_id", ["project_id"]),
        ("ix_execution_artifacts_build_id", ["build_id"]),
        ("ix_execution_artifacts_run_id", ["run_id"]),
        ("ix_execution_artifacts_lease_id", ["lease_id"]),
        (
            "ix_execution_artifacts_created_by_worker_id",
            ["created_by_worker_id"],
        ),
    ]:
        op.create_index(name, "execution_artifacts", columns, schema="control")
    op.create_index(
        "ix_execution_artifacts_project_created",
        "execution_artifacts",
        ["project_id", sa.text("created_at DESC"), sa.text("id DESC")],
        schema="control",
    )

    op.create_table(
        "secret_injection_grants",
        sa.Column(
            "id",
            UUID,
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("worker_id", UUID, nullable=False),
        sa.Column("lease_id", UUID, nullable=False),
        sa.Column("organization_id", UUID, nullable=False),
        sa.Column("project_id", UUID, nullable=False),
        sa.Column("run_id", UUID, nullable=False),
        sa.Column("request_fingerprint", sa.String(64), nullable=False),
        sa.Column("secret_names", JSONB, nullable=False),
        sa.Column("environment", sa.String(24), nullable=False),
        sa.Column("algorithm", sa.String(80), nullable=False),
        sa.Column("ephemeral_public_key", sa.LargeBinary(32), nullable=False),
        sa.Column("nonce", sa.LargeBinary(12), nullable=False),
        sa.Column("ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("worker_public_key_digest", sa.String(64), nullable=False),
        sa.Column(
            "status",
            sa.String(24),
            server_default="ISSUED",
            nullable=False,
        ),
        sa.Column(
            "issued_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint(
            "environment IN ('development', 'test', 'staging', 'production')",
            name="ck_secret_injection_grants_environment",
        ),
        sa.CheckConstraint(
            "status IN ('ISSUED', 'CONSUMED', 'EXPIRED', 'REVOKED')",
            name="ck_secret_injection_grants_status",
        ),
        sa.CheckConstraint(
            "expires_at > issued_at",
            name="ck_secret_injection_grants_expiry",
        ),
        sa.CheckConstraint(
            "jsonb_typeof(secret_names) = 'array'",
            name="ck_secret_injection_grants_names_array",
        ),
        sa.ForeignKeyConstraint(
            ["worker_id"],
            ["security.worker_identities.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["lease_id"],
            ["control.execution_leases.id"],
            ondelete="CASCADE",
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
            "lease_id",
            "request_fingerprint",
            name="uq_secret_injection_grants_lease_request",
        ),
        schema="security",
    )
    for name, columns in [
        ("ix_secret_injection_grants_worker_id", ["worker_id"]),
        ("ix_secret_injection_grants_lease_id", ["lease_id"]),
        ("ix_secret_injection_grants_organization_id", ["organization_id"]),
        ("ix_secret_injection_grants_project_id", ["project_id"]),
        ("ix_secret_injection_grants_run_id", ["run_id"]),
    ]:
        op.create_index(
            name,
            "secret_injection_grants",
            columns,
            schema="security",
        )

    op.execute(
        """
        CREATE OR REPLACE FUNCTION security.rdc_current_worker_id()
        RETURNS uuid
        LANGUAGE sql
        STABLE
        AS $$
          SELECT NULLIF(current_setting('rdc.current_worker_id', true), '')::uuid
        $$
        """
    )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION security.rdc_worker_is_active()
        RETURNS boolean
        LANGUAGE sql
        STABLE
        SECURITY DEFINER
        SET search_path = security, pg_temp
        AS $$
          SELECT EXISTS (
            SELECT 1
            FROM security.worker_identities worker
            WHERE worker.id = security.rdc_current_worker_id()
              AND worker.status IN ('ACTIVE', 'DRAINING')
              AND worker.revoked_at IS NULL
              AND (worker.expires_at IS NULL OR worker.expires_at > now())
          )
        $$
        """
    )

    op.execute(
        """
        CREATE OR REPLACE FUNCTION control.enforce_execution_lease_tenancy()
        RETURNS trigger
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = control, security, pg_temp
        AS $$
        BEGIN
          IF NEW.work_kind = 'BUILD' THEN
            IF NOT EXISTS (
              SELECT 1 FROM control.builds build
              WHERE build.id = NEW.build_id
                AND build.organization_id = NEW.organization_id
                AND build.project_id = NEW.project_id
            ) THEN
              RAISE EXCEPTION 'Execution lease Build tenancy mismatch'
                USING ERRCODE = '23514';
            END IF;
          ELSE
            IF NOT EXISTS (
              SELECT 1 FROM control.runs run
              WHERE run.id = NEW.run_id
                AND run.organization_id = NEW.organization_id
                AND run.project_id = NEW.project_id
            ) THEN
              RAISE EXCEPTION 'Execution lease Run tenancy mismatch'
                USING ERRCODE = '23514';
            END IF;
          END IF;
          RETURN NEW;
        END
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER execution_leases_tenancy_guard
        BEFORE INSERT OR UPDATE OF
          organization_id, project_id, work_kind, build_id, run_id
        ON control.execution_leases
        FOR EACH ROW
        EXECUTE FUNCTION control.enforce_execution_lease_tenancy()
        """
    )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION control.enforce_execution_artifact_tenancy()
        RETURNS trigger
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = control, security, pg_temp
        AS $$
        BEGIN
          IF NOT EXISTS (
            SELECT 1
            FROM control.execution_leases lease
            WHERE lease.id = NEW.lease_id
              AND lease.worker_id = NEW.created_by_worker_id
              AND lease.organization_id = NEW.organization_id
              AND lease.project_id = NEW.project_id
              AND (
                (NEW.build_id IS NOT NULL AND lease.build_id = NEW.build_id)
                OR (NEW.run_id IS NOT NULL AND lease.run_id = NEW.run_id)
              )
          ) THEN
            RAISE EXCEPTION 'Execution artifact tenancy mismatch'
              USING ERRCODE = '23514';
          END IF;
          RETURN NEW;
        END
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER execution_artifacts_tenancy_guard
        BEFORE INSERT OR UPDATE OF
          organization_id, project_id, build_id, run_id, lease_id,
          created_by_worker_id
        ON control.execution_artifacts
        FOR EACH ROW
        EXECUTE FUNCTION control.enforce_execution_artifact_tenancy()
        """
    )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION security.enforce_secret_grant_tenancy()
        RETURNS trigger
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = control, security, pg_temp
        AS $$
        BEGIN
          IF NOT EXISTS (
            SELECT 1
            FROM control.execution_leases lease
            WHERE lease.id = NEW.lease_id
              AND lease.worker_id = NEW.worker_id
              AND lease.organization_id = NEW.organization_id
              AND lease.project_id = NEW.project_id
              AND lease.run_id = NEW.run_id
              AND lease.work_kind = 'RUN_START'
          ) THEN
            RAISE EXCEPTION 'Secret injection grant tenancy mismatch'
              USING ERRCODE = '23514';
          END IF;
          RETURN NEW;
        END
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER secret_injection_grants_tenancy_guard
        BEFORE INSERT OR UPDATE OF
          worker_id, lease_id, organization_id, project_id, run_id
        ON security.secret_injection_grants
        FOR EACH ROW
        EXECUTE FUNCTION security.enforce_secret_grant_tenancy()
        """
    )

    for schema, table in [
        ("control", "execution_leases"),
        ("control", "execution_artifacts"),
        ("security", "secret_injection_grants"),
    ]:
        op.execute(
            f'ALTER TABLE "{schema}"."{table}" ENABLE ROW LEVEL SECURITY'
        )

    op.execute(
        """
        CREATE POLICY execution_leases_tenant
        ON control.execution_leases
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
    op.execute(
        """
        CREATE POLICY execution_leases_worker
        ON control.execution_leases
        USING (
          worker_id = security.rdc_current_worker_id()
          AND security.rdc_worker_is_active()
        )
        WITH CHECK (
          worker_id = security.rdc_current_worker_id()
          AND security.rdc_worker_is_active()
        )
        """
    )
    op.execute(
        """
        CREATE POLICY execution_leases_reaper_select
        ON control.execution_leases
        FOR SELECT
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
        ON control.execution_leases
        FOR UPDATE
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

    op.execute(
        """
        CREATE POLICY execution_artifacts_tenant
        ON control.execution_artifacts
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
    op.execute(
        """
        CREATE POLICY execution_artifacts_worker
        ON control.execution_artifacts
        USING (
          security.rdc_worker_is_active()
          AND (
            created_by_worker_id = security.rdc_current_worker_id()
            OR EXISTS (
              SELECT 1
              FROM control.execution_leases lease
              JOIN control.runs run ON run.id = lease.run_id
              WHERE lease.worker_id = security.rdc_current_worker_id()
                AND lease.status = 'ACTIVE'
                AND run.build_id = execution_artifacts.build_id
            )
          )
        )
        WITH CHECK (
          created_by_worker_id = security.rdc_current_worker_id()
          AND security.rdc_worker_is_active()
        )
        """
    )
    op.execute(
        """
        CREATE POLICY secret_injection_grants_worker
        ON security.secret_injection_grants
        USING (
          worker_id = security.rdc_current_worker_id()
          AND security.rdc_worker_is_active()
        )
        WITH CHECK (
          worker_id = security.rdc_current_worker_id()
          AND security.rdc_worker_is_active()
        )
        """
    )

    op.execute(
        """
        CREATE POLICY build_dispatch_outbox_execution_worker
        ON control.build_dispatch_outbox
        USING (security.rdc_worker_is_active())
        WITH CHECK (security.rdc_worker_is_active())
        """
    )
    op.execute(
        """
        CREATE POLICY run_command_outbox_execution_worker
        ON control.run_command_outbox
        USING (security.rdc_worker_is_active())
        WITH CHECK (security.rdc_worker_is_active())
        """
    )
    op.execute(
        """
        CREATE POLICY builds_execution_worker
        ON control.builds
        USING (
          security.rdc_worker_is_active()
          AND EXISTS (
            SELECT 1
            FROM control.execution_leases lease
            WHERE lease.worker_id = security.rdc_current_worker_id()
              AND lease.status = 'ACTIVE'
              AND lease.build_id = builds.id
          )
        )
        WITH CHECK (
          security.rdc_worker_is_active()
          AND EXISTS (
            SELECT 1
            FROM control.execution_leases lease
            WHERE lease.worker_id = security.rdc_current_worker_id()
              AND lease.status = 'ACTIVE'
              AND lease.build_id = builds.id
          )
        )
        """
    )
    op.execute(
        """
        CREATE POLICY builds_execution_reaper_select
        ON control.builds
        FOR SELECT
        USING (
          security.rdc_worker_is_active()
          AND EXISTS (
            SELECT 1
            FROM control.execution_leases lease
            WHERE lease.status = 'ACTIVE'
              AND lease.expires_at <= now()
              AND lease.build_id = builds.id
          )
        )
        """
    )
    op.execute(
        """
        CREATE POLICY builds_execution_reaper
        ON control.builds
        FOR UPDATE
        USING (
          security.rdc_worker_is_active()
          AND EXISTS (
            SELECT 1
            FROM control.execution_leases lease
            WHERE lease.status = 'ACTIVE'
              AND lease.expires_at <= now()
              AND lease.build_id = builds.id
          )
        )
        WITH CHECK (security.rdc_worker_is_active())
        """
    )

    op.execute(
        """
        CREATE POLICY runs_execution_worker
        ON control.runs
        USING (
          security.rdc_worker_is_active()
          AND EXISTS (
            SELECT 1
            FROM control.execution_leases lease
            WHERE lease.worker_id = security.rdc_current_worker_id()
              AND lease.status = 'ACTIVE'
              AND lease.run_id = runs.id
          )
        )
        WITH CHECK (
          security.rdc_worker_is_active()
          AND EXISTS (
            SELECT 1
            FROM control.execution_leases lease
            WHERE lease.worker_id = security.rdc_current_worker_id()
              AND lease.status = 'ACTIVE'
              AND lease.run_id = runs.id
          )
        )
        """
    )
    op.execute(
        """
        CREATE POLICY runs_execution_reaper_select
        ON control.runs
        FOR SELECT
        USING (
          security.rdc_worker_is_active()
          AND EXISTS (
            SELECT 1
            FROM control.execution_leases lease
            WHERE lease.status = 'ACTIVE'
              AND lease.expires_at <= now()
              AND lease.run_id = runs.id
          )
        )
        """
    )
    op.execute(
        """
        CREATE POLICY runs_execution_reaper
        ON control.runs
        FOR UPDATE
        USING (
          security.rdc_worker_is_active()
          AND EXISTS (
            SELECT 1
            FROM control.execution_leases lease
            WHERE lease.status = 'ACTIVE'
              AND lease.expires_at <= now()
              AND lease.run_id = runs.id
          )
        )
        WITH CHECK (security.rdc_worker_is_active())
        """
    )

    op.execute(
        """
        CREATE POLICY agent_versions_execution_worker
        ON control.agent_versions
        FOR SELECT
        USING (
          security.rdc_worker_is_active()
          AND EXISTS (
            SELECT 1
            FROM control.execution_leases lease
            LEFT JOIN control.builds build ON build.id = lease.build_id
            LEFT JOIN control.runs run ON run.id = lease.run_id
            WHERE lease.worker_id = security.rdc_current_worker_id()
              AND lease.status = 'ACTIVE'
              AND (
                build.agent_version_id = agent_versions.id
                OR run.agent_version_id = agent_versions.id
              )
          )
        )
        """
    )
    op.execute(
        """
        CREATE POLICY run_events_execution_worker
        ON control.run_events
        USING (
          security.rdc_worker_is_active()
          AND EXISTS (
            SELECT 1
            FROM control.execution_leases lease
            WHERE lease.worker_id = security.rdc_current_worker_id()
              AND lease.status = 'ACTIVE'
              AND lease.run_id = run_events.run_id
          )
        )
        WITH CHECK (
          security.rdc_worker_is_active()
          AND EXISTS (
            SELECT 1
            FROM control.execution_leases lease
            WHERE lease.worker_id = security.rdc_current_worker_id()
              AND lease.status = 'ACTIVE'
              AND lease.run_id = run_events.run_id
          )
        )
        """
    )
    op.execute(
        """
        CREATE POLICY run_events_execution_reaper
        ON control.run_events
        FOR INSERT
        WITH CHECK (
          security.rdc_worker_is_active()
          AND EXISTS (
            SELECT 1
            FROM control.execution_leases lease
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
        ON security.secret_injection_grants
        FOR SELECT
        USING (
          security.rdc_worker_is_active()
          AND status = 'ISSUED'
          AND EXISTS (
            SELECT 1
            FROM control.execution_leases lease
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
        ON security.secret_injection_grants
        FOR UPDATE
        USING (
          security.rdc_worker_is_active()
          AND status = 'ISSUED'
          AND EXISTS (
            SELECT 1
            FROM control.execution_leases lease
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

    op.execute(
        """
        CREATE POLICY project_secrets_execution_worker
        ON security.project_secrets
        FOR SELECT
        USING (
          security.rdc_worker_is_active()
          AND EXISTS (
            SELECT 1
            FROM control.execution_leases lease
            WHERE lease.worker_id = security.rdc_current_worker_id()
              AND lease.status = 'ACTIVE'
              AND lease.work_kind = 'RUN_START'
              AND lease.project_id = project_secrets.project_id
          )
        )
        """
    )
    op.execute(
        """
        CREATE POLICY audit_execution_worker_insert
        ON security.audit_events
        FOR INSERT
        WITH CHECK (
          (
            actor_type = 'worker'
            AND actor_id = security.rdc_current_worker_id()::text
            AND security.rdc_worker_is_active()
          )
          OR (
            actor_type = 'system'
            AND action LIKE 'execution.%'
            AND security.rdc_worker_is_active()
          )
          OR (
            actor_type = 'system'
            AND actor_id = 'worker-bootstrap'
            AND current_setting(
              'rdc.worker_bootstrap_authenticated',
              true
            ) = 'true'
          )
        )
        """
    )


def downgrade() -> None:
    for policy, schema, table in [
        ("audit_execution_worker_insert", "security", "audit_events"),
        ("run_events_execution_reaper", "control", "run_events"),
        ("runs_execution_reaper", "control", "runs"),
        ("runs_execution_reaper_select", "control", "runs"),
        ("builds_execution_reaper", "control", "builds"),
        ("builds_execution_reaper_select", "control", "builds"),
        ("project_secrets_execution_worker", "security", "project_secrets"),
        ("run_events_execution_worker", "control", "run_events"),
        ("agent_versions_execution_worker", "control", "agent_versions"),
        ("runs_execution_worker", "control", "runs"),
        ("builds_execution_worker", "control", "builds"),
        (
            "run_command_outbox_execution_worker",
            "control",
            "run_command_outbox",
        ),
        (
            "build_dispatch_outbox_execution_worker",
            "control",
            "build_dispatch_outbox",
        ),
    ]:
        op.execute(f"DROP POLICY IF EXISTS {policy} ON {schema}.{table}")

    op.execute(
        "DROP TRIGGER IF EXISTS secret_injection_grants_tenancy_guard "
        "ON security.secret_injection_grants"
    )
    op.execute(
        "DROP TRIGGER IF EXISTS execution_artifacts_tenancy_guard "
        "ON control.execution_artifacts"
    )
    op.execute(
        "DROP TRIGGER IF EXISTS execution_leases_tenancy_guard "
        "ON control.execution_leases"
    )

    op.drop_table("secret_injection_grants", schema="security")
    op.drop_table("execution_artifacts", schema="control")
    op.drop_table("execution_leases", schema="control")
    op.drop_table("worker_identities", schema="security")

    op.execute("DROP FUNCTION IF EXISTS security.enforce_secret_grant_tenancy()")
    op.execute(
        "DROP FUNCTION IF EXISTS control.enforce_execution_artifact_tenancy()"
    )
    op.execute(
        "DROP FUNCTION IF EXISTS control.enforce_execution_lease_tenancy()"
    )
    op.execute("DROP FUNCTION IF EXISTS security.rdc_worker_is_active()")
    op.execute("DROP FUNCTION IF EXISTS security.rdc_current_worker_id()")
