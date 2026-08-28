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
)
need(
    "apps/api/migrations/versions/20260828_0023_egress_health_observations.py",
    "ENABLE ROW LEVEL SECURITY",
    "egress_health_observations_worker_insert",
    "egress_health_observations_immutable",
    "uq_egress_health_observations_lease_client",
)
need(
    "apps/api/tests/test_egress_health_protocol.py",
    "test_ambiguous_unbounded_or_target_bearing_evidence_is_rejected",
)
need(
    "apps/api/tests/test_egress_health_persistence_contracts.py",
    "test_persistence_migration_enforces_immutability_rls_and_exact_lease",
)
need("docker-compose.yml", "postgres:18-alpine", "postgres_data:/var/lib/postgresql")
need("docs/proxy-egress/THREAT_MODEL.md", "immutable observation")
print("Egress health persistence verification passed")
