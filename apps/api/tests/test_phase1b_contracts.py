from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_migration_contains_rls_and_tenant_context() -> None:
    migration = (
        ROOT
        / "api/migrations/versions/20260806_0002_identity_tenancy.py"
    ).read_text(encoding="utf-8")
    assert "ENABLE ROW LEVEL SECURITY" in migration
    assert "rdc.current_user_id" in migration
    assert "rdc.current_organization_id" in migration
    assert "rdc_has_org_membership" in migration


def test_api_does_not_store_browser_tokens() -> None:
    source = (
        ROOT.parent / "packages/api-client/src/index.ts"
    ).read_text(encoding="utf-8")
    assert "localStorage" not in source
    assert "sessionStorage" not in source
    assert 'credentials: "include"' in source


def test_public_api_version_is_preserved() -> None:
    source = (ROOT / "api/app/main.py").read_text(
        encoding="utf-8"
    )
    assert 'APIRouter(prefix="/api/v1")' in source
