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
need("apps/api/tests/test_egress_policy_postgres.py", "test_rls_and_resolver_hide_other_tenant", "test_service_idempotency_rotation_and_optimistic_lifecycle")
need("apps/api/app/main.py", '"egress_policy_live_binding_enabled": False', '"egress_policy_plaintext_credentials_exposed": False')
for path in ("docs/proxy-egress/README.md", "docs/proxy-egress/THREAT_MODEL.md", "docs/proxy-egress/RUNBOOK.md"):
    need(path, "Proxy/Egress")

print("Proxy/Egress verification passed")
