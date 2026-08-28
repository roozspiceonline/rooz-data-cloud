#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def need(path: str, *markers: str) -> None:
    source = (ROOT / path).read_text(encoding="utf-8")
    missing = [marker for marker in markers if marker not in source]
    if missing:
        raise SystemExit(f"{path} missing: {', '.join(missing)}")


need("apps/api/app/egress_policy_protocol.py", "IP literals are not allowed", "FORBIDDEN_SUFFIXES", "canonical_fingerprint")
need("apps/api/app/models.py", "class EgressPolicy", "class EgressPolicyRevision", "credential_secret_id")
need("apps/api/app/services/egress_policies.py", "acquire_idempotency_lock", "with_for_update()", "credential_configured", 'action="egress_policy.activated"')
need("apps/api/app/api/routes/egress_policies.py", 'require_project_permission("egress.create")', 'require_egress_policy_permission("egress.update")', 'Header(alias="Idempotency-Key")')
need("apps/api/migrations/versions/20260822_0022_egress_policies.py", "ENABLE ROW LEVEL SECURITY", "egress_policy_revisions_immutable", "credential tenancy mismatch", "methods are not canonical", "host is not canonical", "active revision mismatch", "security.rdc_egress_policy_org")
need("apps/api/tests/test_egress_policy_contracts.py", "test_policy_rejects_unsafe_or_ambiguous_hosts", "credential_secret_id")
need("apps/api/app/run_schemas.py", "EgressPolicyBindingInput", "rdc.run-egress-policy/v1")
need("apps/api/app/services/runs.py", "_resolve_run_egress_policy", "with_for_update()", "EGRESS_POLICY_EXCEEDS_CANARY_CEILING", '"credential_configured": revision.credential_secret_id is not None')
need("apps/api/app/services/execution_plane.py", "_bound_egress_policy", "project_egress_policy_binding_digest")
need("apps/api/app/services/execution_plane.py", "_bound_run_egress_policy_is_current", "EGRESS_POLICY_BINDING_REVOKED", "run.egress_policy_binding_revoked")
need("apps/api/app/services/execution_plane.py", "issue_egress_credential_envelope", "worker_egress_credential_aad", "EGRESS_CREDENTIAL_BINDING_REVOKED", "execution.egress_credential_envelope.issued")
need("apps/api/app/services/worker_request_queue.py", "rdc.request-queue-worker-capability/v6", "project_egress_policy_binding_digest")
need("workers/sandbox-runtime/worker.py", "_effective_worker_egress_policy", "Project policy-revision digest mismatch")
need("workers/sandbox-runtime/worker.py", "decrypt_egress_credential_envelope", "Credential-bound egress is unavailable to browser execution", "authorization=egress_authorization")
need("workers/sandbox-runtime/egress_broker.py", 'request_headers["Authorization"] = authorization')
need("apps/api/tests/test_egress_policy_runtime_binding.py", "test_create_run_persists_server_resolved_policy_snapshot", "test_worker_independently_reconstructs_and_enforces_ceiling", "test_queue_capability_binds_same_project_revision_receipt")
need("apps/api/tests/test_egress_policy_runtime_binding.py", "test_execution_admission_converges_disabled_or_rotated_binding", "test_execution_admission_rejects_incomplete_bound_snapshot")
need("apps/api/tests/test_egress_policy_runtime_binding.py", "test_egress_credential_envelope_is_lease_and_binding_scoped", "Bearer private-value")
need("apps/api/tests/test_phase1f_contracts.py", "test_egress_credential_envelope_is_bound_to_policy_and_lease")
need("apps/api/tests/test_egress_policy_postgres.py", "test_rls_and_resolver_hide_other_tenant", "test_service_idempotency_rotation_and_optimistic_lifecycle", "test_bound_run_admission_serializes_with_policy_disable")
need("apps/api/app/main.py", '"egress_policy_live_binding_enabled": True', '"egress_policy_worker_credential_envelopes_enabled": True', '"egress_policy_plaintext_credentials_exposed": False')
for path in ("docs/proxy-egress/README.md", "docs/proxy-egress/THREAT_MODEL.md", "docs/proxy-egress/RUNBOOK.md"):
    need(path, "Proxy/Egress")

print("Proxy/Egress verification passed")
