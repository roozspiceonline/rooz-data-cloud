"""Add a claim-fenced secret loader for the live credential-canary runner.

Revision ID: 20260829_0028
Revises: 20260829_0027
"""
# ruff: noqa: E501

from collections.abc import Sequence

from alembic import op

revision: str = "20260829_0028"
down_revision: str | None = "20260829_0027"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("""
        CREATE FUNCTION control.load_egress_credential_canary_secret(
          p_attempt_id uuid, p_claim_token_digest text
        ) RETURNS TABLE(
          organization_id uuid,
          project_id uuid,
          credential_secret_id uuid,
          secret_name varchar,
          secret_version bigint,
          encrypted_value bytea,
          value_nonce bytea,
          wrapped_data_key bytea,
          key_nonce bytea,
          encryption_algorithm varchar,
          master_key_version varchar,
          target_digest varchar
        ) LANGUAGE sql STABLE SECURITY DEFINER
        SET search_path = pg_catalog, control, security, pg_temp AS $$
          SELECT secret.organization_id,
                 secret.project_id,
                 secret.id,
                 secret.name,
                 secret.version,
                 secret.encrypted_value,
                 secret.value_nonce,
                 secret.wrapped_data_key,
                 secret.key_nonce,
                 secret.encryption_algorithm,
                 secret.master_key_version,
                 attempt.target_digest
          FROM control.egress_credential_canary_attempts attempt
          JOIN security.project_secrets secret
            ON secret.id = attempt.credential_secret_id
           AND secret.organization_id = attempt.organization_id
           AND secret.project_id = attempt.project_id
           AND secret.version = attempt.secret_version
          WHERE attempt.id = p_attempt_id
            AND p_claim_token_digest ~ '^[0-9a-f]{64}$'
            AND attempt.status = 'CLAIMED'
            AND attempt.claim_token_digest = p_claim_token_digest
            AND attempt.claim_expires_at IS NOT NULL
            AND attempt.claim_expires_at > CURRENT_TIMESTAMP
          LIMIT 1
        $$
    """)
    op.execute(
        "REVOKE ALL ON FUNCTION "
        "control.load_egress_credential_canary_secret(uuid,text) "
        "FROM PUBLIC"
    )


def downgrade() -> None:
    op.execute(
        "DROP FUNCTION IF EXISTS "
        "control.load_egress_credential_canary_secret(uuid,text)"
    )
