from pathlib import Path
from uuid import uuid4

import pytest

from app.core.pagination import (
    decode_egress_policy_list_cursor,
    decode_egress_policy_revision_cursor,
    encode_egress_policy_list_cursor,
    encode_egress_policy_revision_cursor,
)
from app.core.permissions import role_has_permission
from app.egress_policy_protocol import (
    EgressPolicyProtocolError,
    normalize_hostname,
    validate_egress_policy,
)
from app.egress_policy_schemas import EgressPolicyRevisionSummary
from app.main import app


def _validated(**overrides: object):
    values = {
        "allowed_hosts": ["API.Example.COM."],
        "allowed_methods": ["GET", "HEAD"],
        "max_requests": 16,
        "max_response_bytes": 1_048_576,
        "max_total_bytes": 4_194_304,
        "max_redirects": 0,
        "connect_timeout_seconds": 5,
        "request_timeout_seconds": 15,
    }
    values.update(overrides)
    return validate_egress_policy(**values)  # type: ignore[arg-type]


def test_policy_normalization_and_digest_are_canonical() -> None:
    first = _validated()
    second = _validated(allowed_hosts=["api.example.com"], allowed_methods=["HEAD", "GET"])
    assert first.allowed_hosts == ["api.example.com"]
    assert first.allowed_methods == ["GET", "HEAD"]
    assert first.policy_digest == second.policy_digest
    assert len(first.policy_digest) == 64


@pytest.mark.parametrize(
    "host",
    [
        "*",
        "*.example.com",
        "https://example.com",
        "127.0.0.1",
        "[::1]",
        "localhost",
        "metadata.internal",
        "service.local",
        "single-label",
        "user@example.com",
    ],
)
def test_policy_rejects_unsafe_or_ambiguous_hosts(host: str) -> None:
    with pytest.raises(EgressPolicyProtocolError):
        normalize_hostname(host)


def test_policy_rejects_duplicate_hosts_methods_and_unbounded_totals() -> None:
    with pytest.raises(EgressPolicyProtocolError, match="unique"):
        _validated(allowed_hosts=["a.example.com", "A.EXAMPLE.COM"])
    with pytest.raises(EgressPolicyProtocolError, match="unique GET or HEAD"):
        _validated(allowed_methods=["GET", "GET"])
    with pytest.raises(EgressPolicyProtocolError, match="at least"):
        _validated(max_response_bytes=2_000_000, max_total_bytes=1_000_000)


def test_signed_policy_cursor_is_bound_to_project_and_filter() -> None:
    project_id = uuid4()
    from datetime import UTC, datetime

    cursor = encode_egress_policy_list_cursor(
        project_id=project_id,
        status="ACTIVE",
        created_at=datetime.now(UTC),
        resource_id=uuid4(),
    )
    assert (
        decode_egress_policy_list_cursor(cursor, project_id=project_id, status="ACTIVE") is not None
    )
    with pytest.raises(Exception, match="cursor"):
        decode_egress_policy_list_cursor(cursor, project_id=uuid4(), status="ACTIVE")
    with pytest.raises(Exception, match="cursor"):
        decode_egress_policy_list_cursor(cursor, project_id=project_id, status="DISABLED")


def test_signed_revision_cursor_is_bound_to_policy() -> None:
    policy_id = uuid4()
    cursor = encode_egress_policy_revision_cursor(
        policy_id=policy_id, revision_number=7
    )
    position = decode_egress_policy_revision_cursor(cursor, policy_id=policy_id)
    assert position is not None and position.revision_number == 7
    with pytest.raises(Exception, match="cursor"):
        decode_egress_policy_revision_cursor(cursor, policy_id=uuid4())


def test_permissions_and_openapi_expose_only_authenticated_metadata_routes() -> None:
    assert role_has_permission("developer", "egress.create")
    assert role_has_permission("developer", "egress.update")
    assert role_has_permission("viewer", "egress.read")
    assert not role_has_permission("viewer", "egress.update")
    paths = app.openapi()["paths"]
    assert "/api/v1/projects/{project_id}/egress-policies" in paths
    assert "/api/v1/egress-policies/{policy_id}/activate" in paths
    assert "/api/v1/egress-policies/{policy_id}/disable" in paths
    schema = EgressPolicyRevisionSummary.model_json_schema()
    properties = schema["properties"]
    assert "credential_configured" in properties
    assert "credential_secret_id" not in properties
    assert "encrypted_value" not in str(app.openapi())


def test_migration_has_rls_immutable_revisions_and_reference_guards() -> None:
    root = Path(__file__).resolve().parents[1]
    migration = (root / "migrations/versions/20260822_0022_egress_policies.py").read_text()
    for required in (
        "ENABLE ROW LEVEL SECURITY",
        "egress_policies_tenant_select",
        "egress_policy_revisions_tenant_select",
        "egress_policy_revisions_immutable",
        "enforce_egress_policy_revision_tenancy",
        "credential_secret_id",
        "enforce_egress_policy_active_revision",
        "security.rdc_egress_policy_org",
    ):
        assert required in migration
