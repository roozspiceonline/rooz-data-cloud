"""Add webhook replay history and automatic failure controls.

Revision ID: 20260901_0033
Revises: 20260831_0032
"""

# ruff: noqa: E501
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "20260901_0033"
down_revision: str | None = "20260831_0032"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None
UUID = postgresql.UUID(as_uuid=True)


def _install_claim_and_load(*, active: bool) -> None:
    allowed = "IN ('PENDING_VERIFICATION','ACTIVE')" if active else "='PENDING_VERIFICATION'"
    expiry_control = """
          IF next_status='DEAD_LETTERED' THEN
            UPDATE control.webhook_destinations destination
            SET consecutive_failure_count=LEAST(destination.failure_threshold,destination.consecutive_failure_count+1),
                status=CASE WHEN destination.consecutive_failure_count+1>=destination.failure_threshold THEN 'DISABLED' ELSE destination.status END,
                disabled_reason=CASE WHEN destination.consecutive_failure_count+1>=destination.failure_threshold THEN 'AUTO_FAILURE_THRESHOLD' ELSE destination.disabled_reason END,
                updated_at=p_now,version=destination.version+1
            WHERE destination.id=candidate.destination_id AND destination.status IN ('PENDING_VERIFICATION','ACTIVE');
          END IF;
    """ if active else ""
    op.execute(f"""
      CREATE OR REPLACE FUNCTION control.claim_webhook_delivery_canary(
        p_now timestamptz,p_batch_size integer,p_claim_seconds integer,p_worker_id text
      ) RETURNS TABLE(
        delivery_id uuid,organization_id uuid,project_id uuid,destination_id uuid,
        event_id uuid,attempt_count integer,claim_token text,claim_expires_at timestamptz
      ) LANGUAGE plpgsql SECURITY DEFINER
      SET search_path=pg_catalog,control,public,pg_temp AS $$
      DECLARE candidate record; raw_token text; previous_status text; next_status text;
              server_now timestamptz;
      BEGIN
        server_now:=clock_timestamp();
        IF p_now IS NULL OR abs(extract(epoch FROM (p_now-server_now)))>5 THEN
          RAISE EXCEPTION 'Webhook claim clock is invalid' USING ERRCODE='22023';
        END IF;
        p_now:=server_now;
        IF p_batch_size NOT BETWEEN 1 AND 20 OR p_claim_seconds NOT BETWEEN 15 AND 120
           OR p_worker_id !~ '^[a-z0-9][a-z0-9._-]{{0,63}}$' THEN
          RAISE EXCEPTION 'Webhook claim bounds are invalid' USING ERRCODE='22023';
        END IF;
        FOR candidate IN
          SELECT delivery.* FROM control.webhook_delivery_attempts delivery
          WHERE delivery.status='CLAIMED' AND delivery.claim_expires_at<=p_now
          ORDER BY delivery.claim_expires_at,delivery.id LIMIT p_batch_size
          FOR UPDATE SKIP LOCKED
        LOOP
          next_status:=CASE WHEN candidate.attempt_count>=candidate.max_attempts THEN 'DEAD_LETTERED' ELSE 'RETRY_WAIT' END;
          UPDATE control.webhook_delivery_attempts delivery
          SET status=next_status,available_at=p_now,claim_token=NULL,claim_token_digest=NULL,
              claimed_by=NULL,claim_expires_at=NULL,last_error_code='CLAIM_EXPIRED',
              completed_at=CASE WHEN next_status='DEAD_LETTERED' THEN p_now ELSE NULL END,
              updated_at=p_now,version=delivery.version+1 WHERE delivery.id=candidate.id;
          INSERT INTO control.webhook_delivery_transitions
            (organization_id,project_id,delivery_id,sequence,from_status,to_status,reason_code,attempt_count,claim_token)
          SELECT candidate.organization_id,candidate.project_id,candidate.id,
                 COALESCE(MAX(t.sequence),0)+1,'CLAIMED',next_status,'CLAIM_EXPIRED',candidate.attempt_count,NULL
          FROM control.webhook_delivery_transitions t WHERE t.delivery_id=candidate.id;
          {expiry_control}
        END LOOP;
        FOR candidate IN
          SELECT delivery.* FROM control.webhook_delivery_attempts delivery
          JOIN control.webhook_destinations destination ON destination.id=delivery.destination_id
          WHERE delivery.status IN ('PENDING','RETRY_WAIT') AND delivery.available_at<=p_now
            AND destination.status {allowed}
          ORDER BY delivery.available_at,delivery.created_at,delivery.id LIMIT p_batch_size
          FOR UPDATE OF delivery SKIP LOCKED
        LOOP
          raw_token:=encode(public.gen_random_bytes(32),'hex');
          UPDATE control.webhook_delivery_attempts delivery
          SET status='CLAIMED',attempt_count=delivery.attempt_count+1,claim_token=NULL,
              claim_token_digest=encode(public.digest(raw_token,'sha256'),'hex'),
              claimed_by=p_worker_id,claim_expires_at=p_now+make_interval(secs=>p_claim_seconds),
              updated_at=p_now,version=delivery.version+1 WHERE delivery.id=candidate.id;
          INSERT INTO control.webhook_delivery_transitions
            (organization_id,project_id,delivery_id,sequence,from_status,to_status,reason_code,attempt_count,claim_token)
          SELECT candidate.organization_id,candidate.project_id,candidate.id,
                 COALESCE(MAX(t.sequence),0)+1,candidate.status,'CLAIMED','CLAIMED',candidate.attempt_count+1,NULL
          FROM control.webhook_delivery_transitions t WHERE t.delivery_id=candidate.id;
          delivery_id:=candidate.id; organization_id:=candidate.organization_id;
          project_id:=candidate.project_id; destination_id:=candidate.destination_id;
          event_id:=candidate.event_id; attempt_count:=candidate.attempt_count+1;
          claim_token:=raw_token; claim_expires_at:=p_now+make_interval(secs=>p_claim_seconds);
          RETURN NEXT;
        END LOOP;
      END; $$
    """)
    op.execute("REVOKE ALL ON FUNCTION control.claim_webhook_delivery_canary(timestamptz,integer,integer,text) FROM PUBLIC")
    op.execute(f"""
      CREATE OR REPLACE FUNCTION control.load_webhook_delivery_claim(
        p_delivery_id uuid,p_claim_token_digest text
      ) RETURNS TABLE(
        organization_id uuid,project_id uuid,destination_id uuid,event_id uuid,
        endpoint_url varchar,event_type varchar,event_occurred_at timestamptz,event_payload jsonb,
        signing_secret_id uuid,secret_name varchar,secret_version bigint,
        encrypted_value bytea,value_nonce bytea,wrapped_data_key bytea,key_nonce bytea,
        encryption_algorithm varchar,master_key_version varchar
      ) LANGUAGE sql STABLE SECURITY DEFINER
      SET search_path=pg_catalog,control,security,pg_temp AS $$
        SELECT delivery.organization_id,delivery.project_id,delivery.destination_id,delivery.event_id,
               delivery.endpoint_url,event.event_type,event.occurred_at,event.payload,
               secret.id,secret.name,secret.version,secret.encrypted_value,secret.value_nonce,
               secret.wrapped_data_key,secret.key_nonce,secret.encryption_algorithm,secret.master_key_version
        FROM control.webhook_delivery_attempts delivery
        JOIN control.webhook_destinations destination
          ON destination.id=delivery.destination_id AND destination.organization_id=delivery.organization_id
         AND destination.project_id=delivery.project_id AND destination.status {allowed}
         AND destination.endpoint_url=delivery.endpoint_url
         AND destination.signing_secret_id=delivery.signing_secret_id
         AND destination.signing_secret_version=delivery.signing_secret_version
        JOIN control.events event
          ON event.id=delivery.event_id AND event.organization_id=delivery.organization_id
         AND event.project_id=delivery.project_id
        JOIN security.project_secrets secret
          ON secret.id=delivery.signing_secret_id AND secret.organization_id=delivery.organization_id
         AND secret.project_id=delivery.project_id AND secret.version=delivery.signing_secret_version
        WHERE delivery.id=p_delivery_id AND p_claim_token_digest~'^[0-9a-f]{{64}}$'
          AND delivery.status='CLAIMED' AND delivery.claim_token_digest=p_claim_token_digest
          AND delivery.claim_expires_at>CURRENT_TIMESTAMP LIMIT 1
      $$
    """)
    op.execute("REVOKE ALL ON FUNCTION control.load_webhook_delivery_claim(uuid,text) FROM PUBLIC")


def _install_completion_v33() -> None:
    op.execute("""
      CREATE OR REPLACE FUNCTION control.complete_webhook_delivery_canary(
        p_delivery_id uuid,p_claim_token_digest text,p_outcome text,p_http_status integer,p_now timestamptz
      ) RETURNS TABLE(delivery_id uuid,status varchar,outcome text,retry_scheduled boolean,available_at timestamptz)
      LANGUAGE plpgsql SECURITY DEFINER
      SET search_path=pg_catalog,control,security,pg_temp AS $$
      DECLARE secret_row record; delivery_row record; destination_row record;
              next_status text; final_outcome text; retryable boolean; next_available timestamptz;
              server_now timestamptz; next_failure_count integer;
      BEGIN
        server_now:=clock_timestamp();
        IF p_now IS NULL OR abs(extract(epoch FROM (p_now-server_now)))>5 THEN
          RAISE EXCEPTION 'Webhook completion clock is invalid' USING ERRCODE='22023';
        END IF;
        p_now:=server_now;
        IF p_claim_token_digest!~'^[0-9a-f]{64}$' THEN RETURN; END IF;
        IF p_outcome NOT IN ('DELIVERED','HTTP_RETRY','HTTP_PERMANENT','AUTH_REJECTED','DNS_FAILURE','TLS_FAILURE','TIMEOUT','CONFIGURATION_ERROR')
           OR (p_http_status IS NOT NULL AND p_http_status NOT BETWEEN 100 AND 599) THEN
          RAISE EXCEPTION 'Webhook delivery result is invalid' USING ERRCODE='22023';
        END IF;
        SELECT delivery.* INTO delivery_row FROM control.webhook_delivery_attempts delivery
        WHERE delivery.id=p_delivery_id FOR UPDATE;
        IF NOT FOUND THEN RETURN; END IF;
        IF delivery_row.status<>'CLAIMED' OR delivery_row.claim_token_digest<>p_claim_token_digest
           OR delivery_row.claim_expires_at IS NULL OR delivery_row.claim_expires_at<=p_now THEN RETURN; END IF;
        SELECT destination.status,destination.endpoint_url,destination.signing_secret_id,
               destination.signing_secret_version,destination.failure_threshold,
               destination.consecutive_failure_count INTO destination_row
        FROM control.webhook_destinations destination
        WHERE destination.id=delivery_row.destination_id FOR UPDATE;
        IF NOT FOUND THEN RETURN; END IF;
        SELECT secret.id,secret.version INTO secret_row FROM security.project_secrets secret
        WHERE secret.id=delivery_row.signing_secret_id
          AND secret.organization_id=delivery_row.organization_id
          AND secret.project_id=delivery_row.project_id FOR UPDATE;
        IF NOT FOUND THEN RETURN; END IF;
        final_outcome:=p_outcome;
        IF secret_row.version<>delivery_row.signing_secret_version
           OR destination_row.status NOT IN ('PENDING_VERIFICATION','ACTIVE')
           OR destination_row.endpoint_url<>delivery_row.endpoint_url
           OR destination_row.signing_secret_id<>delivery_row.signing_secret_id
           OR destination_row.signing_secret_version<>delivery_row.signing_secret_version THEN
          final_outcome:='CONFIGURATION_ERROR';
        END IF;
        retryable:=final_outcome IN ('HTTP_RETRY','DNS_FAILURE','TIMEOUT');
        IF final_outcome='DELIVERED' THEN next_status:='SUCCEEDED'; next_available:=delivery_row.available_at;
        ELSIF retryable AND delivery_row.attempt_count<delivery_row.max_attempts THEN
          next_status:='RETRY_WAIT';
          next_available:=p_now+make_interval(secs=>LEAST(3600,(2^LEAST(delivery_row.attempt_count,10))*5)::integer);
        ELSE next_status:='DEAD_LETTERED'; next_available:=delivery_row.available_at; END IF;
        UPDATE control.webhook_delivery_attempts delivery
        SET status=next_status,available_at=next_available,claim_token=NULL,claim_token_digest=NULL,
            claimed_by=NULL,claim_expires_at=NULL,last_error_code=CASE WHEN final_outcome='DELIVERED' THEN NULL ELSE final_outcome END,
            last_http_status=p_http_status,completed_at=CASE WHEN next_status IN ('SUCCEEDED','DEAD_LETTERED') THEN p_now ELSE NULL END,
            updated_at=p_now,version=delivery.version+1 WHERE delivery.id=p_delivery_id;
        INSERT INTO control.webhook_delivery_transitions
          (organization_id,project_id,delivery_id,sequence,from_status,to_status,reason_code,attempt_count,claim_token)
        SELECT delivery_row.organization_id,delivery_row.project_id,p_delivery_id,
               COALESCE(MAX(t.sequence),0)+1,'CLAIMED',next_status,final_outcome,delivery_row.attempt_count,NULL
        FROM control.webhook_delivery_transitions t WHERE t.delivery_id=p_delivery_id;
        IF final_outcome='DELIVERED' THEN
          UPDATE control.webhook_destinations destination
          SET status='ACTIVE',verified_at=COALESCE(destination.verified_at,p_now),
              consecutive_failure_count=0,disabled_reason=NULL,updated_at=p_now,
              version=destination.version+1
          WHERE destination.id=delivery_row.destination_id;
        ELSIF next_status='DEAD_LETTERED' AND destination_row.status IN ('PENDING_VERIFICATION','ACTIVE') THEN
          next_failure_count:=LEAST(destination_row.failure_threshold,destination_row.consecutive_failure_count+1);
          UPDATE control.webhook_destinations destination
          SET consecutive_failure_count=next_failure_count,
              status=CASE WHEN next_failure_count>=destination.failure_threshold THEN 'DISABLED' ELSE destination.status END,
              disabled_reason=CASE WHEN next_failure_count>=destination.failure_threshold THEN 'AUTO_FAILURE_THRESHOLD' ELSE destination.disabled_reason END,
              updated_at=p_now,version=destination.version+1
          WHERE destination.id=delivery_row.destination_id;
        END IF;
        delivery_id:=p_delivery_id; status:=next_status; outcome:=final_outcome;
        retry_scheduled:=next_status='RETRY_WAIT'; available_at:=next_available; RETURN NEXT;
      END; $$
    """)
    op.execute("REVOKE ALL ON FUNCTION control.complete_webhook_delivery_canary(uuid,text,text,integer,timestamptz) FROM PUBLIC")


def _install_completion_v32() -> None:
    op.execute("""
      CREATE OR REPLACE FUNCTION control.complete_webhook_delivery_canary(
        p_delivery_id uuid,p_claim_token_digest text,p_outcome text,p_http_status integer,p_now timestamptz
      ) RETURNS TABLE(delivery_id uuid,status varchar,outcome text,retry_scheduled boolean,available_at timestamptz)
      LANGUAGE plpgsql SECURITY DEFINER
      SET search_path=pg_catalog,control,security,pg_temp AS $$
      DECLARE lineage record; secret_row record; delivery_row record; destination_row record;
              next_status text; final_outcome text; retryable boolean; next_available timestamptz;
              server_now timestamptz;
      BEGIN
        server_now:=clock_timestamp();
        IF p_now IS NULL OR abs(extract(epoch FROM (p_now-server_now)))>5 THEN
          RAISE EXCEPTION 'Webhook completion clock is invalid' USING ERRCODE='22023';
        END IF;
        p_now:=server_now;
        IF p_claim_token_digest!~'^[0-9a-f]{64}$' THEN RETURN; END IF;
        IF p_outcome NOT IN ('DELIVERED','HTTP_RETRY','HTTP_PERMANENT','AUTH_REJECTED','DNS_FAILURE','TLS_FAILURE','TIMEOUT','CONFIGURATION_ERROR')
           OR (p_http_status IS NOT NULL AND p_http_status NOT BETWEEN 100 AND 599) THEN
          RAISE EXCEPTION 'Webhook delivery result is invalid' USING ERRCODE='22023';
        END IF;
        SELECT delivery.signing_secret_id,delivery.signing_secret_version,delivery.organization_id,
               delivery.project_id,delivery.destination_id INTO lineage
        FROM control.webhook_delivery_attempts delivery WHERE delivery.id=p_delivery_id;
        IF NOT FOUND THEN RETURN; END IF;
        SELECT secret.id,secret.version INTO secret_row FROM security.project_secrets secret
        WHERE secret.id=lineage.signing_secret_id AND secret.organization_id=lineage.organization_id
          AND secret.project_id=lineage.project_id FOR UPDATE;
        IF NOT FOUND THEN RETURN; END IF;
        SELECT delivery.* INTO delivery_row FROM control.webhook_delivery_attempts delivery
        WHERE delivery.id=p_delivery_id FOR UPDATE;
        IF delivery_row.status<>'CLAIMED' OR delivery_row.claim_token_digest<>p_claim_token_digest
           OR delivery_row.claim_expires_at IS NULL OR delivery_row.claim_expires_at<=p_now THEN RETURN; END IF;
        SELECT destination.status,destination.endpoint_url,destination.signing_secret_id,
               destination.signing_secret_version INTO destination_row
        FROM control.webhook_destinations destination
        WHERE destination.id=delivery_row.destination_id;
        final_outcome:=p_outcome;
        IF secret_row.version<>delivery_row.signing_secret_version
           OR destination_row.status<>'PENDING_VERIFICATION'
           OR destination_row.endpoint_url<>delivery_row.endpoint_url
           OR destination_row.signing_secret_id<>delivery_row.signing_secret_id
           OR destination_row.signing_secret_version<>delivery_row.signing_secret_version THEN
          final_outcome:='CONFIGURATION_ERROR';
        END IF;
        retryable:=final_outcome IN ('HTTP_RETRY','DNS_FAILURE','TIMEOUT');
        IF final_outcome='DELIVERED' THEN next_status:='SUCCEEDED'; next_available:=delivery_row.available_at;
        ELSIF retryable AND delivery_row.attempt_count<delivery_row.max_attempts THEN
          next_status:='RETRY_WAIT';
          next_available:=p_now+make_interval(secs=>LEAST(3600,(2^LEAST(delivery_row.attempt_count,10))*5)::integer);
        ELSE next_status:='DEAD_LETTERED'; next_available:=delivery_row.available_at; END IF;
        UPDATE control.webhook_delivery_attempts delivery
        SET status=next_status,available_at=next_available,claim_token=NULL,claim_token_digest=NULL,
            claimed_by=NULL,claim_expires_at=NULL,last_error_code=CASE WHEN final_outcome='DELIVERED' THEN NULL ELSE final_outcome END,
            last_http_status=p_http_status,completed_at=CASE WHEN next_status IN ('SUCCEEDED','DEAD_LETTERED') THEN p_now ELSE NULL END,
            updated_at=p_now,version=delivery.version+1 WHERE delivery.id=p_delivery_id;
        INSERT INTO control.webhook_delivery_transitions
          (organization_id,project_id,delivery_id,sequence,from_status,to_status,reason_code,attempt_count,claim_token)
        SELECT delivery_row.organization_id,delivery_row.project_id,p_delivery_id,
               COALESCE(MAX(t.sequence),0)+1,'CLAIMED',next_status,final_outcome,delivery_row.attempt_count,NULL
        FROM control.webhook_delivery_transitions t WHERE t.delivery_id=p_delivery_id;
        delivery_id:=p_delivery_id; status:=next_status; outcome:=final_outcome;
        retry_scheduled:=next_status='RETRY_WAIT'; available_at:=next_available; RETURN NEXT;
      END; $$
    """)
    op.execute("REVOKE ALL ON FUNCTION control.complete_webhook_delivery_canary(uuid,text,text,integer,timestamptz) FROM PUBLIC")


def upgrade() -> None:
    op.add_column("webhook_destinations", sa.Column("verified_at", sa.DateTime(timezone=True)), schema="control")
    op.add_column("webhook_destinations", sa.Column("consecutive_failure_count", sa.Integer(), server_default="0", nullable=False), schema="control")
    op.add_column("webhook_destinations", sa.Column("failure_threshold", sa.Integer(), server_default="3", nullable=False), schema="control")
    op.add_column("webhook_destinations", sa.Column("disabled_reason", sa.String(64)), schema="control")
    op.execute("UPDATE control.webhook_destinations SET disabled_reason='OPERATOR_DISABLED' WHERE status='DISABLED'")
    op.drop_constraint("ck_webhook_destinations_status", "webhook_destinations", schema="control", type_="check")
    op.create_check_constraint("ck_webhook_destinations_status", "webhook_destinations", "status IN ('PENDING_VERIFICATION','ACTIVE','DISABLED')", schema="control")
    op.create_check_constraint("ck_webhook_destinations_failure_bounds", "webhook_destinations", "failure_threshold BETWEEN 1 AND 8 AND consecutive_failure_count BETWEEN 0 AND failure_threshold", schema="control")
    op.create_check_constraint("ck_webhook_destinations_activation", "webhook_destinations", "status <> 'ACTIVE' OR verified_at IS NOT NULL", schema="control")
    op.create_check_constraint("ck_webhook_destinations_disabled_reason", "webhook_destinations", "(status = 'DISABLED') = (disabled_reason IS NOT NULL)", schema="control")
    op.add_column("webhook_delivery_attempts", sa.Column("replay_count", sa.Integer(), server_default="0", nullable=False), schema="control")
    op.add_column("webhook_delivery_attempts", sa.Column("last_replayed_at", sa.DateTime(timezone=True)), schema="control")
    op.add_column("webhook_delivery_attempts", sa.Column("last_replay_key_digest", sa.String(64)), schema="control")
    op.add_column("webhook_delivery_attempts", sa.Column("replay_requested_by_user_id", UUID), schema="control")
    op.create_foreign_key("fk_webhook_delivery_replay_user", "webhook_delivery_attempts", "users", ["replay_requested_by_user_id"], ["id"], source_schema="control", referent_schema="identity", ondelete="RESTRICT")
    op.create_check_constraint("ck_webhook_delivery_replay", "webhook_delivery_attempts", "replay_count >= 0 AND ((replay_count = 0 AND last_replayed_at IS NULL AND last_replay_key_digest IS NULL AND replay_requested_by_user_id IS NULL) OR (replay_count > 0 AND last_replayed_at IS NOT NULL AND last_replay_key_digest ~ '^[0-9a-f]{64}$' AND replay_requested_by_user_id IS NOT NULL))", schema="control")
    _install_claim_and_load(active=True)
    _install_completion_v33()


def downgrade() -> None:
    # Downgrades are only supported after all active deliveries have converged.
    for constraint in (
        "ck_webhook_destinations_disabled_reason",
        "ck_webhook_destinations_activation",
        "ck_webhook_destinations_failure_bounds",
    ):
        op.drop_constraint(
            constraint, "webhook_destinations", schema="control", type_="check"
        )
    op.execute("UPDATE control.webhook_destinations SET status='PENDING_VERIFICATION',verified_at=NULL,disabled_reason=NULL,consecutive_failure_count=0 WHERE status='ACTIVE'")
    op.execute("UPDATE control.webhook_destinations SET disabled_reason=NULL,consecutive_failure_count=0 WHERE status='DISABLED'")
    _install_claim_and_load(active=False)
    _install_completion_v32()
    op.drop_constraint("ck_webhook_delivery_replay", "webhook_delivery_attempts", schema="control", type_="check")
    op.drop_constraint("fk_webhook_delivery_replay_user", "webhook_delivery_attempts", schema="control", type_="foreignkey")
    for column in ("replay_requested_by_user_id", "last_replay_key_digest", "last_replayed_at", "replay_count"):
        op.drop_column("webhook_delivery_attempts", column, schema="control")
    op.drop_constraint("ck_webhook_destinations_status", "webhook_destinations", schema="control", type_="check")
    op.create_check_constraint("ck_webhook_destinations_status", "webhook_destinations", "status IN ('PENDING_VERIFICATION','DISABLED')", schema="control")
    for column in ("disabled_reason", "failure_threshold", "consecutive_failure_count", "verified_at"):
        op.drop_column("webhook_destinations", column, schema="control")
