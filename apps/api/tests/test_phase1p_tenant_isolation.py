from pathlib import Path


def test_request_queue_tenant_resolver_and_rls_are_not_client_selected() -> None:
    root = Path(__file__).parents[1]
    deps = (root / "app/api/agent_dependencies.py").read_text()
    migration = (root / "migrations/versions/20260809_0015_request_queues.py").read_text()
    assert '"rdc_request_queue_org"' in deps
    assert "security.rdc_current_org_id()" in migration
    assert "security.rdc_has_org_membership(organization_id)" in migration
