"""Harden credential-canary scheduler capabilities and claim fencing.

Revision ID: 20260829_0027
Revises: 20260829_0026
"""
# ruff: noqa: E501

from collections.abc import Sequence

from alembic import op

revision: str = "20260829_0027"
down_revision: str | None = "20260829_0026"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _create_digest_guards() -> None:
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
          NEW.status := 'PENDING'; NEW.attempt_count := 0; NEW.claim_token_digest := NULL;
          NEW.claim_expires_at := NULL; NEW.claimed_at := NULL; NEW.completed_at := NULL;
          NEW.outcome := NULL; NEW.healthy := NULL; NEW.retryable := NULL; NEW.version := 1;
          RETURN NEW;
        END; $$
    """)
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
            IF NEW.attempt_count <> OLD.attempt_count + 1 OR NEW.claim_token_digest IS NULL
               OR NEW.claimed_at IS NULL OR NEW.claim_expires_at <= NEW.claimed_at THEN
              RAISE EXCEPTION 'Egress credential canary claim is invalid' USING ERRCODE = '23514';
            END IF;
          ELSIF OLD.status = 'CLAIMED' AND NEW.status = 'PENDING' THEN
            IF NEW.attempt_count <> OLD.attempt_count OR NEW.claim_token_digest IS NOT NULL
               OR NEW.claim_expires_at IS NOT NULL OR NEW.claimed_at IS NOT NULL OR NEW.completed_at IS NOT NULL
               OR NEW.outcome IS NOT NULL OR NEW.healthy IS NOT NULL OR NEW.retryable IS NOT NULL THEN
              RAISE EXCEPTION 'Egress credential canary reclaim is invalid' USING ERRCODE = '23514';
            END IF;
          ELSIF OLD.status = 'CLAIMED' AND NEW.status IN ('SUCCEEDED','FAILED','SUPERSEDED') THEN
            IF NEW.attempt_count <> OLD.attempt_count OR NEW.claim_token_digest <> OLD.claim_token_digest
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


def _create_scoped_capabilities() -> None:
    op.execute("""
        CREATE FUNCTION control.enqueue_egress_credential_canaries_for_secret(
          p_secret_id uuid, p_target_digest text, p_provider_key text, p_region_key text
        ) RETURNS TABLE(attempt_id uuid, policy_id uuid, policy_revision_id uuid)
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, control, security, identity, pg_temp AS $$
        BEGIN
          IF p_target_digest !~ '^[0-9a-f]{64}$'
             OR p_provider_key !~ '^[a-z0-9][a-z0-9._-]{0,63}$'
             OR p_region_key !~ '^[a-z0-9][a-z0-9._-]{0,63}$' THEN
            RAISE EXCEPTION 'Credential canary configuration is invalid' USING ERRCODE = '22023';
          END IF;
          RETURN QUERY
          INSERT INTO control.egress_credential_canary_attempts
            (organization_id, project_id, policy_id, policy_revision_id,
             credential_secret_id, secret_version, target_digest, provider_key, region_key)
          SELECT secret.organization_id, secret.project_id, policy.id, revision.id,
                 secret.id, secret.version, p_target_digest, p_provider_key, p_region_key
          FROM security.project_secrets secret
          JOIN control.egress_policy_revisions revision
            ON revision.credential_secret_id = secret.id
           AND revision.organization_id = secret.organization_id
           AND revision.project_id = secret.project_id
          JOIN control.egress_policies policy
            ON policy.id = revision.policy_id
           AND policy.organization_id = secret.organization_id
           AND policy.project_id = secret.project_id
           AND policy.status = 'ACTIVE'
           AND policy.active_revision_id = revision.id
          WHERE secret.id = p_secret_id
            AND secret.organization_id = security.rdc_current_org_id()
            AND security.rdc_has_org_membership(secret.organization_id)
          ORDER BY revision.id
          ON CONFLICT ON CONSTRAINT uq_egress_credential_canary_binding DO NOTHING
          RETURNING egress_credential_canary_attempts.id,
                    egress_credential_canary_attempts.policy_id,
                    egress_credential_canary_attempts.policy_revision_id;
        END; $$
    """)
    op.execute("REVOKE ALL ON FUNCTION control.enqueue_egress_credential_canaries_for_secret(uuid,text,text,text) FROM PUBLIC")

    op.execute("""
        CREATE FUNCTION control.claim_egress_credential_canaries(
          p_now timestamptz, p_batch_size integer, p_claim_seconds integer,
          p_max_attempts integer
        ) RETURNS TABLE(
          attempt_id uuid, organization_id uuid, project_id uuid, policy_id uuid,
          policy_revision_id uuid, credential_secret_id uuid, secret_version bigint,
          target_digest varchar, provider_key varchar, region_key varchar,
          attempt_count integer, claim_token text, claim_expires_at timestamptz
        ) LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, control, pg_temp AS $$
        BEGIN
          IF p_batch_size NOT BETWEEN 1 AND 100
             OR p_claim_seconds NOT BETWEEN 15 AND 300
             OR p_max_attempts NOT BETWEEN 1 AND 5 THEN
            RAISE EXCEPTION 'Credential canary claim bounds are invalid' USING ERRCODE = '22023';
          END IF;

          WITH expired AS (
            SELECT candidate.id
            FROM control.egress_credential_canary_attempts candidate
            WHERE candidate.status = 'CLAIMED' AND candidate.claim_expires_at <= p_now
            ORDER BY candidate.claim_expires_at, candidate.id
            LIMIT p_batch_size FOR UPDATE SKIP LOCKED
          )
          UPDATE control.egress_credential_canary_attempts candidate
          SET status = CASE WHEN candidate.attempt_count >= p_max_attempts THEN 'FAILED' ELSE 'PENDING' END,
              claim_token_digest = CASE WHEN candidate.attempt_count >= p_max_attempts THEN candidate.claim_token_digest ELSE NULL END,
              claim_expires_at = CASE WHEN candidate.attempt_count >= p_max_attempts THEN candidate.claim_expires_at ELSE NULL END,
              claimed_at = CASE WHEN candidate.attempt_count >= p_max_attempts THEN candidate.claimed_at ELSE NULL END,
              completed_at = CASE WHEN candidate.attempt_count >= p_max_attempts THEN p_now ELSE NULL END,
              outcome = CASE WHEN candidate.attempt_count >= p_max_attempts THEN 'MAX_ATTEMPTS_EXCEEDED' ELSE NULL END,
              healthy = CASE WHEN candidate.attempt_count >= p_max_attempts THEN FALSE ELSE NULL END,
              retryable = CASE WHEN candidate.attempt_count >= p_max_attempts THEN FALSE ELSE NULL END,
              version = candidate.version + 1
          FROM expired WHERE candidate.id = expired.id;

          RETURN QUERY
          WITH pending AS (
            SELECT candidate.id
            FROM control.egress_credential_canary_attempts candidate
            WHERE candidate.status = 'PENDING'
            ORDER BY candidate.scheduled_at, candidate.id
            LIMIT p_batch_size FOR UPDATE SKIP LOCKED
          ), tokens AS (
            SELECT pending.id, encode(public.gen_random_bytes(32), 'hex') AS raw_token
            FROM pending
          )
          UPDATE control.egress_credential_canary_attempts candidate
          SET status = 'CLAIMED', attempt_count = candidate.attempt_count + 1,
              claim_token_digest = encode(public.digest(tokens.raw_token, 'sha256'), 'hex'),
              claimed_at = p_now,
              claim_expires_at = p_now + make_interval(secs => p_claim_seconds),
              version = candidate.version + 1
          FROM tokens WHERE candidate.id = tokens.id
          RETURNING candidate.id, candidate.organization_id, candidate.project_id,
                    candidate.policy_id, candidate.policy_revision_id,
                    candidate.credential_secret_id, candidate.secret_version,
                    candidate.target_digest, candidate.provider_key, candidate.region_key,
                    candidate.attempt_count, tokens.raw_token, candidate.claim_expires_at;
        END; $$
    """)
    op.execute("REVOKE ALL ON FUNCTION control.claim_egress_credential_canaries(timestamptz,integer,integer,integer) FROM PUBLIC")

    op.execute("""
        CREATE FUNCTION control.complete_egress_credential_canary(
          p_attempt_id uuid, p_claim_token_digest text, p_outcome text,
          p_target_digest text, p_now timestamptz
        ) RETURNS TABLE(
          attempt_id uuid, status varchar, outcome varchar, healthy boolean,
          retryable boolean, completed_at timestamptz, version bigint
        ) LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, control, security, pg_temp AS $$
        DECLARE
          lineage record;
          secret_record record;
          attempt_record record;
          next_status text;
          next_outcome text;
          next_healthy boolean;
          next_retryable boolean;
        BEGIN
          IF p_claim_token_digest !~ '^[0-9a-f]{64}$' OR p_target_digest !~ '^[0-9a-f]{64}$' THEN
            RETURN;
          END IF;
          IF p_outcome NOT IN ('SUCCESS','AUTH_REJECTED','TARGET_ERROR','TIMEOUT','TLS_FAILURE','DNS_FAILURE') THEN
            RAISE EXCEPTION 'Credential canary outcome is invalid' USING ERRCODE = '22023';
          END IF;

          SELECT candidate.credential_secret_id, candidate.organization_id, candidate.project_id
          INTO lineage
          FROM control.egress_credential_canary_attempts candidate
          WHERE candidate.id = p_attempt_id;
          IF NOT FOUND THEN RETURN; END IF;

          -- Global lock order is ProjectSecret first, then canary attempt. Secret
          -- replacement already holds this same ProjectSecret lock before enqueue.
          SELECT secret.id, secret.version INTO secret_record
          FROM security.project_secrets secret
          WHERE secret.id = lineage.credential_secret_id
            AND secret.organization_id = lineage.organization_id
            AND secret.project_id = lineage.project_id
          FOR UPDATE;
          IF NOT FOUND THEN RETURN; END IF;

          SELECT candidate.* INTO attempt_record
          FROM control.egress_credential_canary_attempts candidate
          WHERE candidate.id = p_attempt_id FOR UPDATE;
          IF attempt_record.status <> 'CLAIMED'
             OR attempt_record.claim_token_digest <> p_claim_token_digest
             OR attempt_record.claim_expires_at IS NULL
             OR attempt_record.claim_expires_at <= p_now THEN
            RETURN;
          END IF;

          IF attempt_record.target_digest <> p_target_digest THEN
            next_status := 'FAILED'; next_outcome := 'CONFIGURATION_ERROR';
            next_healthy := FALSE; next_retryable := FALSE;
          ELSIF secret_record.version <> attempt_record.secret_version THEN
            next_status := 'SUPERSEDED'; next_outcome := 'SECRET_VERSION_SUPERSEDED';
            next_healthy := FALSE; next_retryable := FALSE;
          ELSIF p_outcome = 'SUCCESS' THEN
            next_status := 'SUCCEEDED'; next_outcome := p_outcome;
            next_healthy := TRUE; next_retryable := FALSE;
          ELSE
            next_status := 'FAILED'; next_outcome := p_outcome;
            next_healthy := FALSE;
            next_retryable := p_outcome IN ('TARGET_ERROR','TIMEOUT','DNS_FAILURE');
          END IF;

          RETURN QUERY
          UPDATE control.egress_credential_canary_attempts candidate
          SET status = next_status, outcome = next_outcome, healthy = next_healthy,
              retryable = next_retryable, completed_at = p_now,
              version = candidate.version + 1
          WHERE candidate.id = p_attempt_id
          RETURNING candidate.id, candidate.status, candidate.outcome,
                    candidate.healthy, candidate.retryable, candidate.completed_at,
                    candidate.version;
        END; $$
    """)
    op.execute("REVOKE ALL ON FUNCTION control.complete_egress_credential_canary(uuid,text,text,text,timestamptz) FROM PUBLIC")


def upgrade() -> None:
    for policy in (
        "egress_credential_canary_attempts_scheduler_select",
        "egress_credential_canary_attempts_scheduler_insert",
        "egress_credential_canary_attempts_scheduler_update",
    ):
        op.execute(f"DROP POLICY IF EXISTS {policy} ON control.egress_credential_canary_attempts")

    op.execute("DROP TRIGGER egress_credential_canary_insert_guard ON control.egress_credential_canary_attempts")
    op.execute("DROP TRIGGER egress_credential_canary_transition_guard ON control.egress_credential_canary_attempts")
    op.execute("DROP TRIGGER egress_credential_canary_history ON control.egress_credential_canary_attempts")
    op.drop_constraint("ck_egress_credential_canary_lifecycle", "egress_credential_canary_attempts", schema="control", type_="check")
    op.execute("ALTER TABLE control.egress_credential_canary_attempts ADD COLUMN claim_token_digest varchar(64)")
    op.execute("UPDATE control.egress_credential_canary_attempts SET claim_token_digest = encode(digest(claim_token::text, 'sha256'), 'hex') WHERE claim_token IS NOT NULL")
    op.drop_column("egress_credential_canary_attempts", "claim_token", schema="control")
    op.execute("ALTER TABLE control.egress_credential_canary_attempts ADD CONSTRAINT ck_egress_credential_canary_claim_token_digest CHECK (claim_token_digest IS NULL OR claim_token_digest ~ '^[0-9a-f]{64}$')")
    op.execute("""
        ALTER TABLE control.egress_credential_canary_attempts
        ADD CONSTRAINT ck_egress_credential_canary_lifecycle CHECK (
          (status = 'PENDING' AND claim_token_digest IS NULL AND claim_expires_at IS NULL AND claimed_at IS NULL AND completed_at IS NULL AND outcome IS NULL AND healthy IS NULL AND retryable IS NULL)
          OR (status = 'CLAIMED' AND claim_token_digest IS NOT NULL AND claim_expires_at IS NOT NULL AND claimed_at IS NOT NULL AND completed_at IS NULL AND outcome IS NULL AND healthy IS NULL AND retryable IS NULL)
          OR (status IN ('SUCCEEDED','FAILED','SUPERSEDED') AND claim_token_digest IS NOT NULL AND claim_expires_at IS NOT NULL AND claimed_at IS NOT NULL AND completed_at IS NOT NULL AND outcome IS NOT NULL AND healthy IS NOT NULL AND retryable IS NOT NULL)
        )
    """)
    _create_digest_guards()
    op.execute("CREATE TRIGGER egress_credential_canary_insert_guard BEFORE INSERT ON control.egress_credential_canary_attempts FOR EACH ROW EXECUTE FUNCTION control.enforce_egress_credential_canary_insert()")
    op.execute("CREATE TRIGGER egress_credential_canary_transition_guard BEFORE UPDATE ON control.egress_credential_canary_attempts FOR EACH ROW EXECUTE FUNCTION control.enforce_egress_credential_canary_transition()")
    op.execute("CREATE TRIGGER egress_credential_canary_history AFTER INSERT OR UPDATE ON control.egress_credential_canary_attempts FOR EACH ROW EXECUTE FUNCTION control.record_egress_credential_canary_transition()")
    _create_scoped_capabilities()


def _create_raw_token_guards() -> None:
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
            AND policy.status = 'ACTIVE' AND policy.active_revision_id = revision.id
            AND secret.organization_id = revision.organization_id
            AND secret.project_id = revision.project_id;
          IF NOT FOUND THEN RAISE EXCEPTION 'Egress credential canary binding is ineligible' USING ERRCODE = '23514'; END IF;
          NEW.organization_id := revision_record.organization_id; NEW.project_id := revision_record.project_id;
          NEW.policy_id := revision_record.policy_id; NEW.credential_secret_id := revision_record.credential_secret_id;
          NEW.secret_version := revision_record.secret_version; NEW.status := 'PENDING'; NEW.attempt_count := 0;
          NEW.claim_token := NULL; NEW.claim_expires_at := NULL; NEW.claimed_at := NULL; NEW.completed_at := NULL;
          NEW.outcome := NULL; NEW.healthy := NULL; NEW.retryable := NULL; NEW.version := 1;
          RETURN NEW;
        END; $$
    """)
    op.execute("""
        CREATE OR REPLACE FUNCTION control.enforce_egress_credential_canary_transition()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF ROW(NEW.organization_id, NEW.project_id, NEW.policy_id, NEW.policy_revision_id, NEW.credential_secret_id, NEW.secret_version, NEW.target_digest, NEW.provider_key, NEW.region_key, NEW.scheduled_at)
             IS DISTINCT FROM ROW(OLD.organization_id, OLD.project_id, OLD.policy_id, OLD.policy_revision_id, OLD.credential_secret_id, OLD.secret_version, OLD.target_digest, OLD.provider_key, OLD.region_key, OLD.scheduled_at) THEN
            RAISE EXCEPTION 'Egress credential canary lineage is immutable' USING ERRCODE = '23514';
          END IF;
          IF OLD.status IN ('SUCCEEDED','FAILED','SUPERSEDED') OR NEW.version <> OLD.version + 1 THEN
            RAISE EXCEPTION 'Egress credential canary transition is invalid' USING ERRCODE = '23514';
          END IF;
          IF OLD.status = 'PENDING' AND NEW.status = 'CLAIMED' THEN
            IF NEW.attempt_count <> OLD.attempt_count + 1 OR NEW.claim_token IS NULL OR NEW.claimed_at IS NULL OR NEW.claim_expires_at <= NEW.claimed_at THEN
              RAISE EXCEPTION 'Egress credential canary claim is invalid' USING ERRCODE = '23514'; END IF;
          ELSIF OLD.status = 'CLAIMED' AND NEW.status = 'PENDING' THEN
            IF NEW.attempt_count <> OLD.attempt_count OR NEW.claim_token IS NOT NULL OR NEW.claim_expires_at IS NOT NULL OR NEW.claimed_at IS NOT NULL OR NEW.completed_at IS NOT NULL OR NEW.outcome IS NOT NULL OR NEW.healthy IS NOT NULL OR NEW.retryable IS NOT NULL THEN
              RAISE EXCEPTION 'Egress credential canary reclaim is invalid' USING ERRCODE = '23514'; END IF;
          ELSIF OLD.status = 'CLAIMED' AND NEW.status IN ('SUCCEEDED','FAILED','SUPERSEDED') THEN
            IF NEW.attempt_count <> OLD.attempt_count OR NEW.claim_token <> OLD.claim_token OR NEW.claimed_at <> OLD.claimed_at OR NEW.claim_expires_at <> OLD.claim_expires_at OR NEW.completed_at IS NULL OR NEW.outcome IS NULL OR NEW.healthy IS NULL OR NEW.retryable IS NULL THEN
              RAISE EXCEPTION 'Egress credential canary completion is invalid' USING ERRCODE = '23514'; END IF;
            IF (NEW.status = 'SUCCEEDED' AND (NEW.outcome <> 'SUCCESS' OR NOT NEW.healthy OR NEW.retryable)) OR (NEW.status = 'SUPERSEDED' AND (NEW.outcome <> 'SECRET_VERSION_SUPERSEDED' OR NEW.healthy OR NEW.retryable)) OR (NEW.status = 'FAILED' AND (NEW.outcome IN ('SUCCESS','SECRET_VERSION_SUPERSEDED') OR NEW.healthy)) THEN
              RAISE EXCEPTION 'Egress credential canary result is invalid' USING ERRCODE = '23514'; END IF;
          ELSE RAISE EXCEPTION 'Egress credential canary transition is invalid' USING ERRCODE = '23514'; END IF;
          RETURN NEW;
        END; $$
    """)


def downgrade() -> None:
    op.execute("DROP FUNCTION IF EXISTS control.complete_egress_credential_canary(uuid,text,text,text,timestamptz)")
    op.execute("DROP FUNCTION IF EXISTS control.claim_egress_credential_canaries(timestamptz,integer,integer,integer)")
    op.execute("DROP FUNCTION IF EXISTS control.enqueue_egress_credential_canaries_for_secret(uuid,text,text,text)")
    op.execute("DROP TRIGGER egress_credential_canary_insert_guard ON control.egress_credential_canary_attempts")
    op.execute("DROP TRIGGER egress_credential_canary_transition_guard ON control.egress_credential_canary_attempts")
    op.execute("DROP TRIGGER egress_credential_canary_history ON control.egress_credential_canary_attempts")
    op.drop_constraint("ck_egress_credential_canary_lifecycle", "egress_credential_canary_attempts", schema="control", type_="check")
    op.drop_constraint("ck_egress_credential_canary_claim_token_digest", "egress_credential_canary_attempts", schema="control", type_="check")
    op.execute("ALTER TABLE control.egress_credential_canary_attempts ADD COLUMN claim_token uuid")
    op.execute("UPDATE control.egress_credential_canary_attempts SET claim_token = gen_random_uuid() WHERE claim_token_digest IS NOT NULL")
    op.drop_column("egress_credential_canary_attempts", "claim_token_digest", schema="control")
    op.execute("""
        ALTER TABLE control.egress_credential_canary_attempts
        ADD CONSTRAINT ck_egress_credential_canary_lifecycle CHECK (
          (status = 'PENDING' AND claim_token IS NULL AND claim_expires_at IS NULL AND claimed_at IS NULL AND completed_at IS NULL AND outcome IS NULL AND healthy IS NULL AND retryable IS NULL)
          OR (status = 'CLAIMED' AND claim_token IS NOT NULL AND claim_expires_at IS NOT NULL AND claimed_at IS NOT NULL AND completed_at IS NULL AND outcome IS NULL AND healthy IS NULL AND retryable IS NULL)
          OR (status IN ('SUCCEEDED','FAILED','SUPERSEDED') AND claim_token IS NOT NULL AND claim_expires_at IS NOT NULL AND claimed_at IS NOT NULL AND completed_at IS NOT NULL AND outcome IS NOT NULL AND healthy IS NOT NULL AND retryable IS NOT NULL)
        )
    """)
    _create_raw_token_guards()
    op.execute("CREATE TRIGGER egress_credential_canary_insert_guard BEFORE INSERT ON control.egress_credential_canary_attempts FOR EACH ROW EXECUTE FUNCTION control.enforce_egress_credential_canary_insert()")
    op.execute("CREATE TRIGGER egress_credential_canary_transition_guard BEFORE UPDATE ON control.egress_credential_canary_attempts FOR EACH ROW EXECUTE FUNCTION control.enforce_egress_credential_canary_transition()")
    op.execute("CREATE TRIGGER egress_credential_canary_history AFTER INSERT OR UPDATE ON control.egress_credential_canary_attempts FOR EACH ROW EXECUTE FUNCTION control.record_egress_credential_canary_transition()")
    scheduler = "NULLIF(current_setting('rdc.egress_canary_scheduler', true), '') = '1'"
    op.execute(f"CREATE POLICY egress_credential_canary_attempts_scheduler_select ON control.egress_credential_canary_attempts FOR SELECT USING ({scheduler})")
    op.execute(f"CREATE POLICY egress_credential_canary_attempts_scheduler_insert ON control.egress_credential_canary_attempts FOR INSERT WITH CHECK ({scheduler})")
    op.execute(f"CREATE POLICY egress_credential_canary_attempts_scheduler_update ON control.egress_credential_canary_attempts FOR UPDATE USING ({scheduler}) WITH CHECK ({scheduler})")
