from pathlib import Path

ROOT = Path(__file__).parents[1]


def need(path: str, *markers: str) -> None:
    source = (ROOT / path).read_text(encoding="utf-8")
    missing = [marker for marker in markers if marker not in source]
    if missing:
        raise SystemExit(f"{path} is missing: {', '.join(missing)}")


need("apps/api/app/egress_health_protocol.py", "EgressHealthEvidence", "classify_egress_health", "BOT_CHALLENGE", "PROXY_FAILURE")
need("apps/api/tests/test_egress_health_protocol.py", "test_ambiguous_unbounded_or_target_bearing_evidence_is_rejected")
need("docs/proxy-egress/THREAT_MODEL.md", "provider-health evidence")
print("Egress health classification verification passed")
