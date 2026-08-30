from pathlib import Path

ROOT = Path(__file__).parents[1]


def need(path: str, *markers: str) -> None:
    source = (ROOT / path).read_text(encoding="utf-8")
    missing = [marker for marker in markers if marker not in source]
    if missing:
        raise SystemExit(f"{path} is missing: {', '.join(missing)}")


need(
    "apps/api/migrations/versions/20260829_0029_events_foundation.py",
    "ENABLE ROW LEVEL SECURITY",
    "events_tenant_project_select",
    "security.rdc_current_project_id()",
    "control.event_payload_is_safe",
    "RDC events are immutable",
    "Event Run reference is invalid",
    "Event Build reference is invalid",
    "uq_events_project_type_subject",
)
need(
    "apps/api/app/event_protocol.py",
    'EVENT_SCHEMA_VERSION = "rdc.event/v1"',
    "EVENT_DEFINITIONS",
    "MAX_EVENT_PAYLOAD_BYTES = 16_384",
    "Sensitive event payload keys are prohibited",
)
need(
    "apps/api/app/services/events.py",
    "emit_event",
    "EVENT_REPLAY_CONFLICT",
    "set_project_context",
    "limit + 1",
)
need(
    "apps/api/app/api/routes/events.py",
    'require_project_permission("event.read")',
    "decode_event_cursor",
    "Query(ge=1, le=100)",
)
need(
    "apps/api/tests/test_events_postgres.py",
    "test_event_persistence_is_immutable_replay_safe_and_server_owned",
    "test_event_rls_denies_cross_org_and_cross_project_reads",
    "test_event_history_order_and_pagination_are_stable",
)
need("docs/events-webhooks/THREAT_MODEL.md", "Agent", "Chromium", "RLS")
print("Events persistence verification passed")
