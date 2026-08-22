"""Add tenant-scoped immutable egress-policy revisions."""
# ruff: noqa: E501

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260822_0022"
down_revision: str | None = "20260822_0021"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None
UUID = postgresql.UUID(as_uuid=True)


def _tenant_predicate() -> str:
    return "organization_id = security.rdc_current_org_id() AND security.rdc_has_org_membership(organization_id)"


def upgrade() -> None:
    op.create_table(
        "egress_policies",
        sa.Column("id", UUID, server_default=sa.text("gen_random_uuid()"), primary_key=True),
        sa.Column("organization_id", UUID, nullable=False),
        sa.Column("project_id", UUID, nullable=False),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("status", sa.String(16), server_default="DRAFT", nullable=False),
        sa.Column("active_revision_id", UUID),
        sa.Column("activated_at", sa.DateTime(timezone=True)),
        sa.Column("disabled_at", sa.DateTime(timezone=True)),
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
        sa.Column("version", sa.BigInteger(), server_default="1", nullable=False),
        sa.UniqueConstraint("project_id", "name", name="uq_egress_policies_project_name"),
        sa.CheckConstraint(
            "name ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'", name="ck_egress_policies_name"
        ),
        sa.CheckConstraint(
            "status IN ('DRAFT','ACTIVE','DISABLED')", name="ck_egress_policies_status"
        ),
        sa.CheckConstraint("version >= 1", name="ck_egress_policies_version"),
        sa.CheckConstraint(
            "(status <> 'ACTIVE') OR (active_revision_id IS NOT NULL AND activated_at IS NOT NULL)",
            name="ck_egress_policies_active_revision",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"], ["identity.organizations.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["project_id"], ["control.projects.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["identity.users.id"], ondelete="RESTRICT"),
        schema="control",
    )
    op.create_table(
        "egress_policy_revisions",
        sa.Column("id", UUID, server_default=sa.text("gen_random_uuid()"), primary_key=True),
        sa.Column("organization_id", UUID, nullable=False),
        sa.Column("project_id", UUID, nullable=False),
        sa.Column("policy_id", UUID, nullable=False),
        sa.Column("revision_number", sa.BigInteger(), nullable=False),
        sa.Column("allowed_hosts", postgresql.JSONB(), nullable=False),
        sa.Column("allowed_methods", postgresql.JSONB(), nullable=False),
        sa.Column("max_requests", sa.Integer(), nullable=False),
        sa.Column("max_response_bytes", sa.BigInteger(), nullable=False),
        sa.Column("max_total_bytes", sa.BigInteger(), nullable=False),
        sa.Column("max_redirects", sa.Integer(), nullable=False),
        sa.Column("connect_timeout_seconds", sa.Integer(), nullable=False),
        sa.Column("request_timeout_seconds", sa.Integer(), nullable=False),
        sa.Column("credential_secret_id", UUID),
        sa.Column("policy_digest", sa.String(64), nullable=False),
        sa.Column("created_by_user_id", UUID, nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.UniqueConstraint(
            "policy_id", "revision_number", name="uq_egress_policy_revision_number"
        ),
        sa.CheckConstraint("revision_number >= 1", name="ck_egress_policy_revisions_number"),
        sa.CheckConstraint(
            "jsonb_typeof(allowed_hosts) = 'array' AND jsonb_array_length(allowed_hosts) BETWEEN 1 AND 64",
            name="ck_egress_policy_revisions_hosts",
        ),
        sa.CheckConstraint(
            "jsonb_typeof(allowed_methods) = 'array' AND jsonb_array_length(allowed_methods) BETWEEN 1 AND 2",
            name="ck_egress_policy_revisions_methods",
        ),
        sa.CheckConstraint(
            "max_requests BETWEEN 1 AND 64", name="ck_egress_policy_revisions_requests"
        ),
        sa.CheckConstraint(
            "max_response_bytes BETWEEN 65536 AND 8388608",
            name="ck_egress_policy_revisions_response_bytes",
        ),
        sa.CheckConstraint(
            "max_total_bytes BETWEEN max_response_bytes AND 33554432",
            name="ck_egress_policy_revisions_total_bytes",
        ),
        sa.CheckConstraint(
            "max_redirects BETWEEN 0 AND 5", name="ck_egress_policy_revisions_redirects"
        ),
        sa.CheckConstraint(
            "connect_timeout_seconds BETWEEN 1 AND 10",
            name="ck_egress_policy_revisions_connect_timeout",
        ),
        sa.CheckConstraint(
            "request_timeout_seconds BETWEEN 1 AND 30",
            name="ck_egress_policy_revisions_request_timeout",
        ),
        sa.CheckConstraint(
            "policy_digest ~ '^[0-9a-f]{64}$'", name="ck_egress_policy_revisions_digest"
        ),
        sa.ForeignKeyConstraint(["policy_id"], ["control.egress_policies.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["credential_secret_id"], ["security.project_secrets.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["identity.users.id"], ondelete="RESTRICT"),
        schema="control",
    )
    op.create_foreign_key(
        "fk_egress_policies_active_revision",
        "egress_policies",
        "egress_policy_revisions",
        ["active_revision_id"],
        ["id"],
        source_schema="control",
        referent_schema="control",
        ondelete="RESTRICT",
    )
    for table in ("egress_policies", "egress_policy_revisions"):
        op.create_index(f"ix_{table}_organization_id", table, ["organization_id"], schema="control")
        op.execute(f"ALTER TABLE control.{table} ENABLE ROW LEVEL SECURITY")
    predicate = _tenant_predicate()
    op.execute(f"CREATE POLICY egress_policies_tenant_select ON control.egress_policies FOR SELECT USING ({predicate})")
    op.execute(f"CREATE POLICY egress_policies_tenant_insert ON control.egress_policies FOR INSERT WITH CHECK ({predicate})")
    op.execute(
        f"CREATE POLICY egress_policies_tenant_update ON control.egress_policies FOR UPDATE USING ({predicate}) WITH CHECK ({predicate})"
    )
    op.execute(f"CREATE POLICY egress_policy_revisions_tenant_select ON control.egress_policy_revisions FOR SELECT USING ({predicate})")
    op.execute(f"CREATE POLICY egress_policy_revisions_tenant_insert ON control.egress_policy_revisions FOR INSERT WITH CHECK ({predicate})")
    op.create_index(
        "ix_egress_policies_project_created",
        "egress_policies",
        ["project_id", "created_at", "id"],
        schema="control",
    )
    op.create_index(
        "ix_egress_policy_revisions_policy_number",
        "egress_policy_revisions",
        ["policy_id", "revision_number"],
        schema="control",
    )
    op.execute(
        """CREATE OR REPLACE FUNCTION control.enforce_egress_policy_owner() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = control, identity, security, pg_temp AS $$ BEGIN IF NOT EXISTS (SELECT 1 FROM control.projects p WHERE p.id = NEW.project_id AND p.organization_id = NEW.organization_id AND p.deleted_at IS NULL) THEN RAISE EXCEPTION 'Egress policy project tenancy mismatch' USING ERRCODE = '23514'; END IF; IF TG_OP = 'UPDATE' AND (OLD.organization_id IS DISTINCT FROM NEW.organization_id OR OLD.project_id IS DISTINCT FROM NEW.project_id OR OLD.name IS DISTINCT FROM NEW.name OR OLD.created_by_user_id IS DISTINCT FROM NEW.created_by_user_id OR OLD.created_at IS DISTINCT FROM NEW.created_at) THEN RAISE EXCEPTION 'Egress policy ownership is immutable' USING ERRCODE = '23514'; END IF; RETURN NEW; END; $$"""
    )
    op.execute(
        "CREATE TRIGGER egress_policies_owner_guard BEFORE INSERT OR UPDATE ON control.egress_policies FOR EACH ROW EXECUTE FUNCTION control.enforce_egress_policy_owner()"
    )
    op.execute(
        """CREATE OR REPLACE FUNCTION control.enforce_egress_policy_revision_tenancy() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = control, identity, security, pg_temp AS $$ BEGIN IF NOT EXISTS (SELECT 1 FROM control.egress_policies p WHERE p.id = NEW.policy_id AND p.organization_id = NEW.organization_id AND p.project_id = NEW.project_id) THEN RAISE EXCEPTION 'Egress policy revision tenancy mismatch' USING ERRCODE = '23514'; END IF; IF NEW.credential_secret_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM security.project_secrets s WHERE s.id = NEW.credential_secret_id AND s.organization_id = NEW.organization_id AND s.project_id = NEW.project_id) THEN RAISE EXCEPTION 'Egress policy credential tenancy mismatch' USING ERRCODE = '23514'; END IF; RETURN NEW; END; $$"""
    )
    op.execute(
        "CREATE TRIGGER egress_policy_revisions_tenancy_guard BEFORE INSERT ON control.egress_policy_revisions FOR EACH ROW EXECUTE FUNCTION control.enforce_egress_policy_revision_tenancy()"
    )
    op.execute(
        """CREATE OR REPLACE FUNCTION control.enforce_egress_policy_revision_values() RETURNS trigger LANGUAGE plpgsql AS $$ DECLARE host text; BEGIN IF NEW.allowed_methods NOT IN ('[\"GET\"]'::jsonb, '[\"HEAD\"]'::jsonb, '[\"GET\",\"HEAD\"]'::jsonb) THEN RAISE EXCEPTION 'Egress policy methods are not canonical' USING ERRCODE = '23514'; END IF; IF EXISTS (SELECT 1 FROM jsonb_array_elements(NEW.allowed_hosts) item WHERE jsonb_typeof(item) <> 'string') OR (SELECT count(*) FROM jsonb_array_elements_text(NEW.allowed_hosts)) <> (SELECT count(DISTINCT item) FROM jsonb_array_elements_text(NEW.allowed_hosts) item) THEN RAISE EXCEPTION 'Egress policy hosts are not canonical' USING ERRCODE = '23514'; END IF; FOR host IN SELECT value FROM jsonb_array_elements_text(NEW.allowed_hosts) LOOP IF host <> lower(host) OR length(host) > 253 OR host !~ '^[a-z0-9][a-z0-9.-]*[a-z0-9]$' OR position('.' IN host) = 0 OR host LIKE '%..%' OR host LIKE '%*%' OR host LIKE '%/%' OR host LIKE '%@%' OR host LIKE '%:%' OR EXISTS (SELECT 1 FROM unnest(string_to_array(host, '.')) label WHERE length(label) > 63 OR label !~ '^[a-z0-9]([a-z0-9-]*[a-z0-9])?$') OR host ~ '(^|\\.)[0-9]+(\\.[0-9]+){3}$' OR host ~ '\\.(local|localhost|internal|invalid|test|example)$' THEN RAISE EXCEPTION 'Egress policy host is not canonical' USING ERRCODE = '23514'; END IF; END LOOP; RETURN NEW; END; $$"""
    )
    op.execute(
        "CREATE TRIGGER egress_policy_revisions_value_guard BEFORE INSERT ON control.egress_policy_revisions FOR EACH ROW EXECUTE FUNCTION control.enforce_egress_policy_revision_values()"
    )
    op.execute(
        """CREATE OR REPLACE FUNCTION control.enforce_egress_policy_active_revision() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = control, identity, security, pg_temp AS $$ BEGIN IF NEW.active_revision_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM control.egress_policy_revisions r WHERE r.id = NEW.active_revision_id AND r.policy_id = NEW.id AND r.organization_id = NEW.organization_id AND r.project_id = NEW.project_id) THEN RAISE EXCEPTION 'Egress policy active revision mismatch' USING ERRCODE = '23514'; END IF; RETURN NEW; END; $$"""
    )
    op.execute(
        "CREATE TRIGGER egress_policies_active_revision_guard BEFORE INSERT OR UPDATE ON control.egress_policies FOR EACH ROW EXECUTE FUNCTION control.enforce_egress_policy_active_revision()"
    )
    op.execute(
        """CREATE OR REPLACE FUNCTION control.egress_policy_revision_immutable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'Egress policy revisions are immutable' USING ERRCODE = '23514'; END; $$"""
    )
    op.execute(
        "CREATE TRIGGER egress_policy_revisions_immutable BEFORE UPDATE OR DELETE ON control.egress_policy_revisions FOR EACH ROW EXECUTE FUNCTION control.egress_policy_revision_immutable()"
    )
    op.execute(
        """CREATE OR REPLACE FUNCTION security.rdc_egress_policy_org(target_policy uuid) RETURNS uuid LANGUAGE sql STABLE SECURITY DEFINER SET search_path = control, identity, security, pg_temp AS $$ SELECT p.organization_id FROM control.egress_policies p WHERE p.id = target_policy AND security.rdc_has_org_membership(p.organization_id) $$"""
    )


def downgrade() -> None:
    op.execute("DROP FUNCTION IF EXISTS security.rdc_egress_policy_org(uuid)")
    op.execute(
        "DROP TRIGGER IF EXISTS egress_policy_revisions_immutable ON control.egress_policy_revisions"
    )
    op.execute(
        "DROP TRIGGER IF EXISTS egress_policies_active_revision_guard ON control.egress_policies"
    )
    op.execute(
        "DROP TRIGGER IF EXISTS egress_policy_revisions_tenancy_guard ON control.egress_policy_revisions"
    )
    op.execute(
        "DROP TRIGGER IF EXISTS egress_policy_revisions_value_guard ON control.egress_policy_revisions"
    )
    op.execute("DROP TRIGGER IF EXISTS egress_policies_owner_guard ON control.egress_policies")
    op.execute("DROP FUNCTION IF EXISTS control.egress_policy_revision_immutable()")
    op.execute("DROP FUNCTION IF EXISTS control.enforce_egress_policy_active_revision()")
    op.execute("DROP FUNCTION IF EXISTS control.enforce_egress_policy_revision_tenancy()")
    op.execute("DROP FUNCTION IF EXISTS control.enforce_egress_policy_revision_values()")
    op.execute("DROP FUNCTION IF EXISTS control.enforce_egress_policy_owner()")
    op.execute("DROP POLICY IF EXISTS egress_policies_tenant_update ON control.egress_policies")
    for table in ("egress_policy_revisions", "egress_policies"):
        op.execute(f"DROP POLICY IF EXISTS {table}_tenant_insert ON control.{table}")
        op.execute(f"DROP POLICY IF EXISTS {table}_tenant_select ON control.{table}")
    op.drop_constraint(
        "fk_egress_policies_active_revision",
        "egress_policies",
        schema="control",
        type_="foreignkey",
    )
    op.drop_table("egress_policy_revisions", schema="control")
    op.drop_table("egress_policies", schema="control")
