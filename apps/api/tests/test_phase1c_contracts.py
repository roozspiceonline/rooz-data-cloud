from pathlib import Path
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.agent_schemas import (
    AgentManifest,
    CreateAgentVersionRequest,
    UpdateAgentRequest,
)
from app.api.routes.agents import agent_etag, parse_agent_if_match
from app.core.errors import ApiError
from app.core.pagination import decode_cursor, encode_cursor
from app.core.permissions import role_has_permission, validate_scopes
from app.services.agents import canonical_manifest, manifest_digest


def valid_manifest() -> dict[str, object]:
    return {
        "protocol": "rooz.agent/v1",
        "name": "catalog-agent",
        "version": "1.0.0",
        "runtime": {
            "kind": "container",
            "entrypoint": ["python", "-m", "agent"],
        },
        "schemas": {
            "input": "schemas/input.json",
            "output": "schemas/output.json",
        },
        "capabilities": {
            "network": "none",
            "browser": False,
            "dataset": False,
            "keyValueStore": False,
            "requestQueue": False,
        },
        "resources": {
            "memoryMb": 512,
            "cpuUnits": 500,
            "timeoutSeconds": 300,
            "maxProcesses": 16,
            "ephemeralDiskMb": 512,
        },
        "extensions": {},
    }


def test_agent_permissions_follow_role_contract() -> None:
    assert role_has_permission("developer", "agent.create")
    assert role_has_permission("developer", "agent.version_create")
    assert role_has_permission("viewer", "agent.read")
    assert not role_has_permission("viewer", "agent.update")
    assert validate_scopes(["agent.read", "agent.version_create"]) == [
        "agent.read",
        "agent.version_create",
    ]


def test_manifest_accepts_protocol_schema_and_aliases() -> None:
    manifest = AgentManifest.model_validate(valid_manifest())
    dumped = manifest.model_dump(mode="json", by_alias=True)
    assert dumped["protocol"] == "rooz.agent/v1"
    assert dumped["capabilities"]["keyValueStore"] is False
    assert dumped["resources"]["memoryMb"] == 512


def test_manifest_rejects_path_traversal_and_unknown_fields() -> None:
    invalid = valid_manifest()
    invalid["schemas"] = {
        "input": "../private.json",
        "output": "schemas/output.json",
    }
    with pytest.raises(ValidationError):
        AgentManifest.model_validate(invalid)

    unknown = valid_manifest()
    unknown["execute_now"] = True
    with pytest.raises(ValidationError):
        AgentManifest.model_validate(unknown)


def test_manifest_digest_is_canonical() -> None:
    payload = CreateAgentVersionRequest.model_validate(
        {"manifest": valid_manifest(), "release_notes": "Initial"}
    )
    first = canonical_manifest(payload)
    second = canonical_manifest(payload)
    assert first == second
    assert manifest_digest(first) == manifest_digest(second)
    assert len(manifest_digest(first)) == 64


def test_agent_updates_require_at_least_one_field() -> None:
    with pytest.raises(ValidationError):
        UpdateAgentRequest.model_validate({})


def test_cursor_round_trip_and_tamper_rejection() -> None:
    from datetime import UTC, datetime

    resource_id = uuid4()
    cursor = encode_cursor(
        created_at=datetime(2026, 8, 6, 2, 0, tzinfo=UTC),
        resource_id=resource_id,
    )
    decoded = decode_cursor(cursor)
    assert decoded is not None
    assert decoded.resource_id == resource_id
    with pytest.raises(ApiError):
        decode_cursor(cursor[:-1] + ("A" if cursor[-1] != "A" else "B"))


def test_agent_etag_contract() -> None:
    agent_id = uuid4()
    etag = agent_etag(agent_id, 7)
    assert parse_agent_if_match(etag, agent_id=agent_id) == 7


def test_phase1c_migration_has_rls_and_immutability() -> None:
    migration = Path(
        "migrations/versions/20260806_0003_agent_registry.py"
    ).read_text(encoding="utf-8")
    assert "ENABLE ROW LEVEL SECURITY" in migration
    assert "agent_versions_immutable" in migration
    assert "rdc_agent_version_org" in migration
    assert "reject_agent_version_mutation" in migration
    assert "BuildKit" not in migration


def test_phase1c_routes_match_approved_inventory() -> None:
    from app.main import app

    paths = app.openapi()["paths"]
    assert "/api/v1/projects/{project_id}/agents" in paths
    assert "/api/v1/agents/{agent_id}" in paths
    assert "/api/v1/agents/{agent_id}/versions" in paths
    assert "/api/v1/agent-versions/{version_id}" in paths
    assert "/api/v1/builds/{build_id}" in paths
    assert "/api/v1/runs/{run_id}" not in paths
