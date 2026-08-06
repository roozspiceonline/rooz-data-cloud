"""Create the Phase 1B identity and tenancy foundation.

Revision ID: 20260806_0002
Revises: 20260806_0001
Create Date: 2026-08-06
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260806_0002"
down_revision: str | None = "20260806_0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


UUID = postgresql.UUID(as_uuid=True)
JSONB = postgresql.JSONB(astext_type=sa.Text())


def upgrade() -> None:
    op.execute("CREATE SCHEMA IF NOT EXISTS identity")
    op.execute("CREATE SCHEMA IF NOT EXISTS control")
    op.execute("CREATE SCHEMA IF NOT EXISTS security")

    op.create_table(
        "users",
        sa.Column(
            "id",
            UUID,
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("email_normalized", sa.String(320), nullable=False),
        sa.Column("email_display", sa.String(320), nullable=False),
        sa.Column("password_hash", sa.Text(), nullable=False),
        sa.Column("password_algorithm", sa.String(32), nullable=False),
        sa.Column("display_name", sa.String(160), nullable=False),
        sa.Column("email_verified_at", sa.DateTime(timezone=True)),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column(
            "failed_login_count",
            sa.Integer(),
            server_default="0",
            nullable=False,
        ),
        sa.Column("locked_until", sa.DateTime(timezone=True)),
        sa.Column("password_changed_at", sa.DateTime(timezone=True)),
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
        sa.Column("deactivated_at", sa.DateTime(timezone=True)),
        sa.Column(
            "version",
            sa.BigInteger(),
            server_default="1",
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("email_normalized"),
        schema="identity",
    )

    op.create_table(
        "sessions",
        sa.Column(
            "id",
            UUID,
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("user_id", UUID, nullable=False),
        sa.Column("token_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("csrf_token_digest", sa.LargeBinary(32), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column(
            "last_seen_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column(
            "idle_expires_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column(
            "absolute_expires_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("revoke_reason", sa.String(100)),
        sa.Column("user_agent_hash", sa.String(64)),
        sa.Column("ip_prefix_hash", sa.String(64)),
        sa.Column(
            "version",
            sa.BigInteger(),
            server_default="1",
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["identity.users.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_digest"),
        schema="identity",
    )
    op.create_index(
        "ix_sessions_user_active",
        "sessions",
        ["user_id", "revoked_at"],
        schema="identity",
    )
    op.create_index(
        "ix_sessions_expiry",
        "sessions",
        ["idle_expires_at", "absolute_expires_at"],
        schema="identity",
    )

    op.create_table(
        "organizations",
        sa.Column(
            "id",
            UUID,
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("slug", sa.String(80), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("created_by_user_id", UUID, nullable=False),
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
        sa.Column("deleted_at", sa.DateTime(timezone=True)),
        sa.Column(
            "version",
            sa.BigInteger(),
            server_default="1",
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["created_by_user_id"],
            ["identity.users.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("slug"),
        schema="identity",
    )

    op.create_table(
        "organization_memberships",
        sa.Column(
            "id",
            UUID,
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("organization_id", UUID, nullable=False),
        sa.Column("user_id", UUID, nullable=False),
        sa.Column("role", sa.String(32), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column(
            "joined_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column("created_by_user_id", UUID),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column(
            "version",
            sa.BigInteger(),
            server_default="1",
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["created_by_user_id"],
            ["identity.users.id"],
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["identity.organizations.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["identity.users.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "organization_id",
            "user_id",
            name="uq_organization_memberships_organization_user",
        ),
        schema="identity",
    )
    op.create_index(
        "ix_memberships_user",
        "organization_memberships",
        ["user_id", "status"],
        schema="identity",
    )
    op.create_index(
        "ix_memberships_org",
        "organization_memberships",
        ["organization_id", "status"],
        schema="identity",
    )

    op.create_table(
        "projects",
        sa.Column(
            "id",
            UUID,
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("organization_id", UUID, nullable=False),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("slug", sa.String(80), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("created_by_user_id", UUID, nullable=False),
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
        sa.Column("deleted_at", sa.DateTime(timezone=True)),
        sa.Column(
            "version",
            sa.BigInteger(),
            server_default="1",
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["created_by_user_id"],
            ["identity.users.id"],
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["identity.organizations.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "organization_id",
            "slug",
            name="uq_projects_organization_slug",
        ),
        schema="control",
    )

    op.create_table(
        "api_keys",
        sa.Column(
            "id",
            UUID,
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("organization_id", UUID, nullable=False),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("public_prefix", sa.String(24), nullable=False),
        sa.Column("last_four", sa.String(4), nullable=False),
        sa.Column("token_digest", sa.LargeBinary(32), nullable=False),
        sa.Column("scopes", JSONB, nullable=False),
        sa.Column("environment", sa.String(16), nullable=False),
        sa.Column("created_by_user_id", UUID, nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("revoke_reason", sa.String(100)),
        sa.Column("last_used_at", sa.DateTime(timezone=True)),
        sa.ForeignKeyConstraint(
            ["created_by_user_id"],
            ["identity.users.id"],
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["identity.organizations.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "organization_id",
            "public_prefix",
            name="uq_api_keys_organization_prefix",
        ),
        sa.UniqueConstraint("token_digest"),
        schema="security",
    )

    op.create_table(
        "audit_events",
        sa.Column(
            "id",
            UUID,
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("organization_id", UUID),
        sa.Column("project_id", UUID),
        sa.Column("actor_type", sa.String(32), nullable=False),
        sa.Column("actor_id", sa.String(100), nullable=False),
        sa.Column("action", sa.String(120), nullable=False),
        sa.Column("resource_type", sa.String(80), nullable=False),
        sa.Column("resource_id", sa.String(100)),
        sa.Column("request_id", sa.String(100), nullable=False),
        sa.Column("details", JSONB, nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["identity.organizations.id"],
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["project_id"],
            ["control.projects.id"],
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id"),
        schema="security",
    )

    op.create_table(
        "idempotency_records",
        sa.Column(
            "id",
            UUID,
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("organization_id", UUID, nullable=False),
        sa.Column("principal_id", sa.String(100), nullable=False),
        sa.Column("endpoint", sa.String(160), nullable=False),
        sa.Column("key_digest", sa.String(64), nullable=False),
        sa.Column(
            "request_fingerprint",
            sa.String(64),
            nullable=False,
        ),
        sa.Column("resource_type", sa.String(80), nullable=False),
        sa.Column("resource_id", sa.String(100), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column(
            "expires_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["identity.organizations.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "organization_id",
            "principal_id",
            "endpoint",
            "key_digest",
            name="uq_idempotency_scope",
        ),
        schema="security",
    )

    op.execute(
        """
        CREATE OR REPLACE FUNCTION security.rdc_current_user_id()
        RETURNS uuid
        LANGUAGE sql
        STABLE
        AS $$
          SELECT NULLIF(
            current_setting('rdc.current_user_id', true),
            ''
          )::uuid
        $$
        """
    )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION security.rdc_current_org_id()
        RETURNS uuid
        LANGUAGE sql
        STABLE
        AS $$
          SELECT NULLIF(
            current_setting('rdc.current_organization_id', true),
            ''
          )::uuid
        $$
        """
    )

    op.execute(
        """
        CREATE OR REPLACE FUNCTION security.rdc_is_org_creator(
          target_org uuid
        )
        RETURNS boolean
        LANGUAGE sql
        STABLE
        SECURITY DEFINER
        SET search_path = identity, pg_temp
        AS $$
          SELECT EXISTS (
            SELECT 1
            FROM identity.organizations organization
            WHERE organization.id = target_org
              AND organization.created_by_user_id =
                security.rdc_current_user_id()
          )
        $$
        """
    )

    op.execute(
        """
        CREATE OR REPLACE FUNCTION security.rdc_has_org_membership(
          target_org uuid
        )
        RETURNS boolean
        LANGUAGE sql
        STABLE
        SECURITY DEFINER
        SET search_path = identity, pg_temp
        AS $$
          SELECT EXISTS (
            SELECT 1
            FROM identity.organization_memberships membership
            WHERE membership.organization_id = target_org
              AND membership.user_id = security.rdc_current_user_id()
              AND membership.status = 'ACTIVE'
          )
        $$
        """
    )

    for schema_name, table_name in [
        ("identity", "organizations"),
        ("identity", "organization_memberships"),
        ("control", "projects"),
        ("security", "api_keys"),
        ("security", "audit_events"),
        ("security", "idempotency_records"),
    ]:
        op.execute(
            f'ALTER TABLE "{schema_name}"."{table_name}" '
            "ENABLE ROW LEVEL SECURITY"
        )

    op.execute(
        """
        CREATE POLICY organizations_select
        ON identity.organizations
        FOR SELECT
        USING (security.rdc_has_org_membership(id))
        """
    )
    op.execute(
        """
        CREATE POLICY organizations_insert
        ON identity.organizations
        FOR INSERT
        WITH CHECK (
          created_by_user_id = security.rdc_current_user_id()
        )
        """
    )
    op.execute(
        """
        CREATE POLICY memberships_select
        ON identity.organization_memberships
        FOR SELECT
        USING (
          security.rdc_has_org_membership(organization_id)
        )
        """
    )
    op.execute(
        """
        CREATE POLICY memberships_insert
        ON identity.organization_memberships
        FOR INSERT
        WITH CHECK (
          security.rdc_has_org_membership(organization_id)
          OR (
            user_id = security.rdc_current_user_id()
            AND role = 'owner'
            AND security.rdc_is_org_creator(organization_id)
          )
        )
        """
    )
    op.execute(
        """
        CREATE POLICY memberships_modify
        ON identity.organization_memberships
        FOR UPDATE
        USING (
          security.rdc_has_org_membership(organization_id)
        )
        WITH CHECK (
          security.rdc_has_org_membership(organization_id)
        )
        """
    )

    for qualified, policy in [
        ("control.projects", "projects_tenant"),
        ("security.api_keys", "api_keys_tenant"),
        ("security.audit_events", "audit_events_tenant"),
        ("security.idempotency_records", "idempotency_tenant"),
    ]:
        op.execute(
            f"""
            CREATE POLICY {policy}
            ON {qualified}
            USING (
              organization_id = security.rdc_current_org_id()
              AND security.rdc_has_org_membership(
                organization_id
              )
            )
            WITH CHECK (
              organization_id = security.rdc_current_org_id()
              AND security.rdc_has_org_membership(
                organization_id
              )
            )
            """
        )

    op.execute(
        """
        CREATE POLICY api_keys_auth_lookup
        ON security.api_keys
        FOR SELECT
        USING (
          encode(token_digest, 'hex') = NULLIF(
            current_setting(
              'rdc.current_api_key_digest',
              true
            ),
            ''
          )
        )
        """
    )

    op.execute(
        """
        CREATE POLICY audit_global_auth_insert
        ON security.audit_events
        FOR INSERT
        WITH CHECK (
          organization_id IS NULL
          AND actor_type = 'user'
          AND actor_id = security.rdc_current_user_id()::text
        )
        """
    )


def downgrade() -> None:
    for schema_name, table_name in [
        ("security", "idempotency_records"),
        ("security", "audit_events"),
        ("security", "api_keys"),
        ("control", "projects"),
        ("identity", "organization_memberships"),
        ("identity", "organizations"),
        ("identity", "sessions"),
        ("identity", "users"),
    ]:
        op.drop_table(table_name, schema=schema_name)

    op.execute(
        "DROP FUNCTION IF EXISTS "
        "security.rdc_has_org_membership(uuid)"
    )
    op.execute(
        "DROP FUNCTION IF EXISTS "
        "security.rdc_is_org_creator(uuid)"
    )
    op.execute(
        "DROP FUNCTION IF EXISTS security.rdc_current_org_id()"
    )
    op.execute(
        "DROP FUNCTION IF EXISTS security.rdc_current_user_id()"
    )
    op.execute("DROP SCHEMA IF EXISTS security")
    op.execute("DROP SCHEMA IF EXISTS control")
    op.execute("DROP SCHEMA IF EXISTS identity")
