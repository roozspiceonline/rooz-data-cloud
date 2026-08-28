from pathlib import Path

ROOT = Path(__file__).parents[1]


def need(path: str, *markers: str) -> None:
    source = (ROOT / path).read_text(encoding="utf-8")
    missing = [marker for marker in markers if marker not in source]
    if missing:
        raise SystemExit(f"{path} is missing: {', '.join(missing)}")


need(
    "apps/api/app/egress_health_protocol.py",
    "EgressHealthEvidence",
    "EgressHealthObservationRequest",
    "classify_egress_health",
    "BOT_CHALLENGE",
    "PROXY_FAILURE",
)
need(
    "apps/api/app/services/egress_health.py",
    "record_egress_health_observation",
    "EGRESS_HEALTH_REPLAY_CONFLICT",
    "classify_egress_health(payload.evidence)",
    "summarize_egress_health",
    "summarize_egress_health_routes",
    "MAX_ROUTE_DIMENSIONS",
)
need(
    "apps/api/migrations/versions/20260828_0023_egress_health_observations.py",
    "ENABLE ROW LEVEL SECURITY",
    "egress_health_observations_worker_insert",
    "egress_health_observations_immutable",
    "uq_egress_health_observations_lease_client",
)
need(
    "apps/api/migrations/versions/20260828_0024_egress_health_route_dimensions.py",
    "provider_key",
    "region_key",
    "ix_egress_health_observations_project_route_time",
)
need(
    "apps/api/app/core/config.py",
    "egress_route_provider_key",
    "egress_route_region_key",
    "egress_health_min_route_samples",
)
need(
    "apps/api/app/api/routes/egress_policies.py",
    '"/projects/{project_id}/egress-health/routes"',
    "summarize_egress_health_routes",
    'require_project_permission("egress.read")',
)
need(
    "apps/api/tests/test_egress_health_protocol.py",
    "test_ambiguous_unbounded_or_target_bearing_evidence_is_rejected",
)
need(
    "apps/api/tests/test_egress_health_persistence_contracts.py",
    "test_persistence_migration_enforces_immutability_rls_and_exact_lease",
    "test_route_dimension_migration_is_bounded_and_reversible",
)
need("docker-compose.yml", "postgres:18-alpine", "postgres_data:/var/lib/postgresql")
need("docs/proxy-egress/THREAT_MODEL.md", "immutable observation", "minimum sample")
print("Egress health persistence verification passed")
