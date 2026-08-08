'''Add Phase 1P tenant-scoped request queue persistence.'''
# ruff: noqa: E501

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260809_0015"
down_revision: str | None = "20260808_0014"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None
UUID = postgresql.UUID(as_uuid=True)


def _tenant_predicate() -> str:
    return "organization_id = security.rdc_current_org_id() AND security.rdc_has_org_membership(organization_id)"


def _worker_lease_predicate(table_name: str) -> str:
    return f"""
      security.rdc_worker_is_active()
      AND EXISTS (
        SELECT 1
        FROM control.execution_leases lease
        WHERE lease.worker_id = security.rdc_current_worker_id()
          AND lease.status = 'ACTIVE'
          AND lease.expires_at > now()
          AND lease.work_kind = 'RUN_START'
          AND lease.organization_id = {table_name}.organization_id
          AND lease.project_id = {table_name}.project_id
      )
    """


def upgrade() -> None:
    op.create_table("request_queues", sa.Column("id", UUID, server_default=sa.text("gen_random_uuid()"), primary_key=True), sa.Column("organization_id", UUID, nullable=False), sa.Column("project_id", UUID, nullable=False), sa.Column("name", sa.String(128), nullable=False), sa.Column("pending_count", sa.BigInteger(), server_default="0", nullable=False), sa.Column("claimed_count", sa.BigInteger(), server_default="0", nullable=False), sa.Column("handled_count", sa.BigInteger(), server_default="0", nullable=False), sa.Column("failed_count", sa.BigInteger(), server_default="0", nullable=False), sa.Column("created_by_user_id", UUID, nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False), sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False), sa.Column("version", sa.BigInteger(), server_default="1", nullable=False), sa.UniqueConstraint("project_id", "name", name="uq_request_queues_project_name"), sa.CheckConstraint("name ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'", name="ck_request_queues_name"), sa.ForeignKeyConstraint(["organization_id"], ["identity.organizations.id"], ondelete="CASCADE"), sa.ForeignKeyConstraint(["project_id"], ["control.projects.id"], ondelete="CASCADE"), sa.ForeignKeyConstraint(["created_by_user_id"], ["identity.users.id"], ondelete="RESTRICT"), schema="control")
    op.create_table("request_queue_requests", sa.Column("id", UUID, server_default=sa.text("gen_random_uuid()"), primary_key=True), sa.Column("organization_id", UUID, nullable=False), sa.Column("project_id", UUID, nullable=False), sa.Column("queue_id", UUID, nullable=False), sa.Column("request_url", sa.Text(), nullable=False), sa.Column("unique_key", sa.String(256)), sa.Column("identity_digest", sa.String(64), nullable=False), sa.Column("user_data", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False), sa.Column("status", sa.String(16), server_default="PENDING", nullable=False), sa.Column("attempt_count", sa.Integer(), server_default="0", nullable=False), sa.Column("max_attempts", sa.Integer(), server_default="3", nullable=False), sa.Column("available_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False), sa.Column("claimed_by", sa.String(128)), sa.Column("claim_token", UUID), sa.Column("claim_expires_at", sa.DateTime(timezone=True)), sa.Column("handled_at", sa.DateTime(timezone=True)), sa.Column("failure_code", sa.String(80)), sa.Column("failure_summary", sa.Text()), sa.Column("created_by_user_id", UUID, nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False), sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False), sa.Column("version", sa.BigInteger(), server_default="1", nullable=False), sa.UniqueConstraint("queue_id", "identity_digest", name="uq_request_queue_requests_identity"), sa.CheckConstraint("status IN ('PENDING','CLAIMED','HANDLED','FAILED')", name="ck_request_queue_requests_status"), sa.CheckConstraint("attempt_count >= 0 AND max_attempts >= 1", name="ck_request_queue_requests_attempts"), sa.ForeignKeyConstraint(["queue_id"], ["control.request_queues.id"], ondelete="CASCADE"), sa.ForeignKeyConstraint(["created_by_user_id"], ["identity.users.id"], ondelete="RESTRICT"), schema="control")
    op.create_table("request_queue_transitions", sa.Column("id", UUID, server_default=sa.text("gen_random_uuid()"), primary_key=True), sa.Column("organization_id", UUID, nullable=False), sa.Column("project_id", UUID, nullable=False), sa.Column("queue_id", UUID, nullable=False), sa.Column("request_id", UUID, nullable=False), sa.Column("from_status", sa.String(16)), sa.Column("to_status", sa.String(16), nullable=False), sa.Column("reason", sa.String(80), nullable=False), sa.Column("attempt_count", sa.Integer(), nullable=False), sa.Column("details", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False), sa.ForeignKeyConstraint(["queue_id"], ["control.request_queues.id"], ondelete="RESTRICT"), sa.ForeignKeyConstraint(["request_id"], ["control.request_queue_requests.id"], ondelete="RESTRICT"), schema="control")
    op.create_table("request_queue_enqueue_receipts", sa.Column("id", UUID, server_default=sa.text("gen_random_uuid()"), primary_key=True), sa.Column("organization_id", UUID, nullable=False), sa.Column("project_id", UUID, nullable=False), sa.Column("queue_id", UUID, nullable=False), sa.Column("request_id", UUID, nullable=False), sa.Column("idempotency_key", sa.String(256), nullable=False), sa.Column("request_digest", sa.String(64), nullable=False), sa.Column("identity_digest", sa.String(64), nullable=False), sa.Column("created_by_user_id", UUID, nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False), sa.UniqueConstraint("queue_id", "idempotency_key", name="uq_request_queue_enqueue_idempotency"), sa.ForeignKeyConstraint(["queue_id"], ["control.request_queues.id"], ondelete="CASCADE"), sa.ForeignKeyConstraint(["request_id"], ["control.request_queue_requests.id"], ondelete="CASCADE"), sa.ForeignKeyConstraint(["created_by_user_id"], ["identity.users.id"], ondelete="RESTRICT"), schema="control")
    op.create_check_constraint("ck_request_queues_nonnegative_counts", "request_queues", "pending_count >= 0 AND claimed_count >= 0 AND handled_count >= 0 AND failed_count >= 0", schema="control")
    for table in ("request_queues", "request_queue_requests", "request_queue_transitions", "request_queue_enqueue_receipts"):
        op.create_index(f"ix_{table}_organization_id", table, ["organization_id"], schema="control")
        op.execute(f'ALTER TABLE control.{table} ENABLE ROW LEVEL SECURITY')
        tenant_predicate = _tenant_predicate()
        op.execute(f'''CREATE POLICY {table}_tenant_select ON control.{table} FOR SELECT USING ({tenant_predicate})''')
        op.execute(f'''CREATE POLICY {table}_tenant_insert ON control.{table} FOR INSERT WITH CHECK ({tenant_predicate})''')
    tenant_predicate = _tenant_predicate()
    op.execute(f'''CREATE POLICY request_queues_tenant_update ON control.request_queues FOR UPDATE USING ({tenant_predicate}) WITH CHECK ({tenant_predicate})''')
    for table in ("request_queues", "request_queue_requests"):
        worker_predicate = _worker_lease_predicate(table)
        op.execute(f'''CREATE POLICY {table}_execution_worker_select ON control.{table} FOR SELECT USING ({worker_predicate})''')
        op.execute(f'''CREATE POLICY {table}_execution_worker_update ON control.{table} FOR UPDATE USING ({worker_predicate}) WITH CHECK ({worker_predicate})''')
    transition_worker_predicate = _worker_lease_predicate("request_queue_transitions")
    op.execute(f'''CREATE POLICY request_queue_transitions_execution_worker_insert ON control.request_queue_transitions FOR INSERT WITH CHECK ({transition_worker_predicate})''')
    op.create_index("ix_request_queue_requests_claim", "request_queue_requests", ["queue_id", "status", "available_at"], schema="control")
    op.execute('''CREATE OR REPLACE FUNCTION control.enforce_request_queue_owner() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = control, identity, security, pg_temp AS $$ BEGIN IF NOT EXISTS (SELECT 1 FROM control.projects p WHERE p.id = NEW.project_id AND p.organization_id = NEW.organization_id) THEN RAISE EXCEPTION 'Request Queue project tenancy mismatch' USING ERRCODE = '23514'; END IF; IF TG_OP = 'UPDATE' AND (OLD.organization_id IS DISTINCT FROM NEW.organization_id OR OLD.project_id IS DISTINCT FROM NEW.project_id OR OLD.name IS DISTINCT FROM NEW.name OR OLD.created_by_user_id IS DISTINCT FROM NEW.created_by_user_id OR OLD.created_at IS DISTINCT FROM NEW.created_at) THEN RAISE EXCEPTION 'Request Queue ownership is immutable' USING ERRCODE = '23514'; END IF; RETURN NEW; END; $$''')
    op.execute('CREATE TRIGGER request_queues_tenancy_guard BEFORE INSERT OR UPDATE ON control.request_queues FOR EACH ROW EXECUTE FUNCTION control.enforce_request_queue_owner()')
    op.execute('''CREATE OR REPLACE FUNCTION control.enforce_request_queue_tenancy() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = control, identity, security, pg_temp AS $$ BEGIN IF NOT EXISTS (SELECT 1 FROM control.request_queues q WHERE q.id = NEW.queue_id AND q.organization_id = NEW.organization_id AND q.project_id = NEW.project_id) THEN RAISE EXCEPTION 'Request Queue tenancy mismatch' USING ERRCODE = '23514'; END IF; IF TG_TABLE_NAME = 'request_queue_requests' AND TG_OP = 'UPDATE' AND (OLD.organization_id IS DISTINCT FROM NEW.organization_id OR OLD.project_id IS DISTINCT FROM NEW.project_id OR OLD.queue_id IS DISTINCT FROM NEW.queue_id OR OLD.request_url IS DISTINCT FROM NEW.request_url OR OLD.unique_key IS DISTINCT FROM NEW.unique_key OR OLD.identity_digest IS DISTINCT FROM NEW.identity_digest OR OLD.user_data IS DISTINCT FROM NEW.user_data OR OLD.max_attempts IS DISTINCT FROM NEW.max_attempts OR OLD.created_by_user_id IS DISTINCT FROM NEW.created_by_user_id OR OLD.created_at IS DISTINCT FROM NEW.created_at) THEN RAISE EXCEPTION 'Request Queue request identity is immutable' USING ERRCODE = '23514'; END IF; RETURN NEW; END; $$''')
    for table in ("request_queue_requests", "request_queue_transitions", "request_queue_enqueue_receipts"):
        op.execute(f'CREATE TRIGGER {table}_tenancy_guard BEFORE INSERT OR UPDATE ON control.{table} FOR EACH ROW EXECUTE FUNCTION control.enforce_request_queue_tenancy()')
    op.execute('''CREATE OR REPLACE FUNCTION control.enforce_request_queue_request_reference() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = control, identity, security, pg_temp AS $$ BEGIN IF NOT EXISTS (SELECT 1 FROM control.request_queue_requests r WHERE r.id = NEW.request_id AND r.queue_id = NEW.queue_id AND r.organization_id = NEW.organization_id AND r.project_id = NEW.project_id) THEN RAISE EXCEPTION 'Request Queue request tenancy mismatch' USING ERRCODE = '23514'; END IF; RETURN NEW; END; $$''')
    for table in ("request_queue_transitions", "request_queue_enqueue_receipts"):
        op.execute(f'CREATE TRIGGER {table}_request_guard BEFORE INSERT OR UPDATE ON control.{table} FOR EACH ROW EXECUTE FUNCTION control.enforce_request_queue_request_reference()')
    op.execute('''CREATE OR REPLACE FUNCTION control.request_queue_transition_immutable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'Request Queue transitions are immutable' USING ERRCODE = '23514'; END; $$''')
    op.execute('CREATE TRIGGER request_queue_transitions_immutable BEFORE UPDATE OR DELETE ON control.request_queue_transitions FOR EACH ROW EXECUTE FUNCTION control.request_queue_transition_immutable()')
    op.execute('''CREATE OR REPLACE FUNCTION control.request_queue_enqueue_receipt_immutable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'Request Queue enqueue receipts are immutable' USING ERRCODE = '23514'; END; $$''')
    op.execute('CREATE TRIGGER request_queue_enqueue_receipts_immutable BEFORE UPDATE OR DELETE ON control.request_queue_enqueue_receipts FOR EACH ROW EXECUTE FUNCTION control.request_queue_enqueue_receipt_immutable()')
    op.execute('''CREATE OR REPLACE FUNCTION security.enforce_audit_event_tenancy() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = control, identity, security, pg_temp AS $$ BEGIN IF NEW.project_id IS NOT NULL AND (NEW.organization_id IS NULL OR NOT EXISTS (SELECT 1 FROM control.projects p WHERE p.id = NEW.project_id AND p.organization_id = NEW.organization_id)) THEN RAISE EXCEPTION 'Audit event project tenancy mismatch' USING ERRCODE = '23514'; END IF; RETURN NEW; END; $$''')
    op.execute('CREATE TRIGGER audit_events_tenancy_guard BEFORE INSERT ON security.audit_events FOR EACH ROW EXECUTE FUNCTION security.enforce_audit_event_tenancy()')
    op.execute('''CREATE OR REPLACE FUNCTION security.audit_event_immutable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'Audit events are immutable' USING ERRCODE = '23514'; END; $$''')
    op.execute('CREATE TRIGGER audit_events_immutable BEFORE UPDATE OR DELETE ON security.audit_events FOR EACH ROW EXECUTE FUNCTION security.audit_event_immutable()')
    op.execute('''CREATE OR REPLACE FUNCTION security.rdc_request_queue_org(target_queue uuid) RETURNS uuid LANGUAGE sql STABLE SECURITY DEFINER SET search_path = control, identity, security, pg_temp AS $$ SELECT q.organization_id FROM control.request_queues q WHERE q.id = target_queue AND security.rdc_has_org_membership(q.organization_id) $$''')


def downgrade() -> None:
    op.execute('DROP TRIGGER IF EXISTS audit_events_immutable ON security.audit_events')
    op.execute('DROP TRIGGER IF EXISTS audit_events_tenancy_guard ON security.audit_events')
    op.execute('DROP FUNCTION IF EXISTS security.audit_event_immutable()')
    op.execute('DROP FUNCTION IF EXISTS security.enforce_audit_event_tenancy()')
    op.execute('DROP TRIGGER IF EXISTS request_queue_enqueue_receipts_immutable ON control.request_queue_enqueue_receipts')
    op.execute('DROP FUNCTION IF EXISTS control.request_queue_enqueue_receipt_immutable()')
    policies = [
        ("request_queue_transitions_execution_worker_insert", "request_queue_transitions"),
        ("request_queue_requests_execution_worker_update", "request_queue_requests"),
        ("request_queue_requests_execution_worker_select", "request_queue_requests"),
        ("request_queues_execution_worker_update", "request_queues"),
        ("request_queues_execution_worker_select", "request_queues"),
        ("request_queues_tenant_update", "request_queues"),
    ]
    for table in ("request_queue_enqueue_receipts", "request_queue_transitions", "request_queue_requests", "request_queues"):
        policies.extend(((f"{table}_tenant_insert", table), (f"{table}_tenant_select", table)))
    for policy, table in policies:
        op.execute(f'DROP POLICY IF EXISTS {policy} ON control.{table}')
    op.execute('DROP FUNCTION IF EXISTS security.rdc_request_queue_org(uuid)')
    op.drop_table("request_queue_enqueue_receipts", schema="control")
    op.drop_table("request_queue_transitions", schema="control")
    op.drop_table("request_queue_requests", schema="control")
    op.drop_table("request_queues", schema="control")
    op.execute('DROP FUNCTION IF EXISTS control.request_queue_transition_immutable()')
    op.execute('DROP FUNCTION IF EXISTS control.enforce_request_queue_request_reference()')
    op.execute('DROP FUNCTION IF EXISTS control.enforce_request_queue_tenancy()')
    op.execute('DROP FUNCTION IF EXISTS control.enforce_request_queue_owner()')
