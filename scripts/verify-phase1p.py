#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def need(path: str, *markers: str) -> None:
    text = (ROOT / path).read_text()
    missing = [marker for marker in markers if marker not in text]
    if missing:
        raise SystemExit(f"{path} missing: {', '.join(missing)}")


need("apps/api/migrations/versions/20260809_0015_request_queues.py", "ENABLE ROW LEVEL SECURITY", "rdc_request_queue_org", "request_queue_transition_immutable")
need("apps/api/app/services/request_queues.py", "with_for_update()", "IDEMPOTENCY_KEY_REUSED", "RequestQueueTransition")
need("docs/phase1p/THREAT_MODEL.md", "RLS", "Idempotency")
need("docs/phase1p/RUNBOOK.md", "20260809_0015", "Do not expose claim")
print("Phase 1P verification passed")
