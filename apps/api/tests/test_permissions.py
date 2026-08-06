from app.core.permissions import role_has_permission, validate_scopes


def test_owner_has_foundation_permissions() -> None:
    assert role_has_permission("owner", "membership.update_role")
    assert role_has_permission("owner", "api_key.revoke")


def test_viewer_cannot_create_projects() -> None:
    assert not role_has_permission("viewer", "project.create")
    assert role_has_permission("viewer", "project.read")


def test_unknown_scope_is_rejected() -> None:
    try:
        validate_scopes(["project.read", "root.shell"])
    except ValueError as exc:
        assert "root.shell" in str(exc)
    else:
        raise AssertionError("Unknown scope should be rejected")
