from collections.abc import Collection

PERMISSIONS = frozenset(
    {
        "organization.read", "organization.update", "membership.read",
        "membership.invite", "membership.update_role", "membership.remove",
        "project.create", "project.read", "project.update", "project.delete",
        "agent.create", "agent.read", "agent.update", "agent.version_create",
        "build.create", "build.read", "run.create", "run.read", "run.cancel",
        "execution.read", "storage.read", "storage.upload", "storage.download",
        "dataset.create", "dataset.read", "dataset.write", "dataset.export",
        "kv.create", "kv.read", "kv.write", "kv.delete",
        "queue.create", "queue.read", "queue.enqueue",
        "secret.read_metadata", "secret.create", "secret.replace", "secret.delete",
        "api_key.create", "api_key.read_metadata", "api_key.revoke", "audit.read",
    }
)

ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "owner": PERMISSIONS,
    "administrator": frozenset(PERMISSIONS - {"organization.delete"}),
    "developer": frozenset(
        {
            "organization.read", "membership.read", "project.create",
            "project.read", "project.update", "agent.create", "agent.read",
            "agent.update", "agent.version_create", "build.create", "build.read",
            "run.create", "run.read", "run.cancel", "execution.read",
            "storage.read", "storage.upload", "storage.download",
            "dataset.create", "dataset.read", "dataset.write", "dataset.export",
            "kv.create", "kv.read", "kv.write", "kv.delete",
            "queue.create", "queue.read", "queue.enqueue",
            "secret.read_metadata", "secret.create", "secret.replace",
            "secret.delete", "api_key.create", "api_key.read_metadata",
            "api_key.revoke",
        }
    ),
    "analyst": frozenset(
        {
            "organization.read", "membership.read", "project.read", "agent.read",
            "build.read", "run.read", "execution.read", "storage.read",
            "storage.download", "dataset.read", "dataset.export", "kv.read", "queue.read",
            "api_key.read_metadata",
        }
    ),
    "operator": frozenset(
        {
            "organization.read", "membership.read", "project.read", "agent.read",
            "build.read", "run.create", "run.read", "run.cancel",
            "execution.read", "storage.read", "storage.download", "dataset.read",
            "dataset.export", "kv.read", "queue.read",
        }
    ),
    "viewer": frozenset(
        {
            "organization.read", "project.read", "agent.read", "build.read",
            "run.read", "execution.read", "storage.read", "storage.download",
            "dataset.read", "dataset.export", "kv.read", "queue.read",
        }
    ),
    "billing_manager": frozenset({"organization.read"}),
}


def role_has_permission(role: str, permission: str) -> bool:
    return permission in ROLE_PERMISSIONS.get(role, frozenset())


def validate_scopes(scopes: Collection[str]) -> list[str]:
    normalized = sorted(set(scopes))
    invalid = [scope for scope in normalized if scope not in PERMISSIONS]
    if invalid:
        raise ValueError("Unknown API-key scopes: " + ", ".join(invalid))
    return normalized
