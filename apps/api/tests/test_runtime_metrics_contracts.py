from __future__ import annotations

from pathlib import Path

import pytest

from app.api.routes.health import runtime_metrics_payload
from app.main import app
from app.services.runtime_metrics import RuntimeMetrics, read_runtime_metrics

ROOT = Path(__file__).resolve().parents[3]


def _metrics() -> RuntimeMetrics:
    return RuntimeMetrics(
        active_execution_leases=2,
        active_workers=3,
        build_dispatch_ready=5,
        run_commands_ready=7,
        schedules_due=11,
        request_queue_ready=13,
        credential_canaries_ready=17,
        credential_canaries_claimed=19,
        webhook_deliveries_ready=23,
        webhook_deliveries_claimed=29,
    )


def test_runtime_metrics_are_fixed_scalar_global_aggregates() -> None:
    payload = runtime_metrics_payload(_metrics())
    assert payload.splitlines() == [
        "rdc_runtime_metrics_healthy 1",
        "rdc_runtime_execution_active_leases 2",
        "rdc_runtime_workers_active 3",
        "rdc_runtime_build_dispatch_ready 5",
        "rdc_runtime_run_commands_ready 7",
        "rdc_runtime_schedules_due 11",
        "rdc_runtime_request_queue_ready 13",
        "rdc_runtime_credential_canaries_ready 17",
        "rdc_runtime_credential_canaries_claimed 19",
        "rdc_runtime_webhook_deliveries_ready 23",
        "rdc_runtime_webhook_deliveries_claimed 29",
    ]
    for prohibited in (
        "organization",
        "project",
        "worker_id",
        "lease_id",
        "run_id",
        "destination",
        "policy",
        "url",
        "payload",
        "token",
        "claim_token",
        "secret",
        "error",
        "{",
    ):
        assert prohibited not in payload


def test_runtime_metrics_query_is_one_fixed_snapshot_without_dimensions() -> None:
    source = (
        ROOT / "apps/api/app/services/runtime_metrics.py"
    ).read_text(encoding="utf-8")
    assert source.count("await session.execute(") == 1
    assert "RUNTIME_METRICS_QUERY_TIMEOUT_SECONDS = 2.0" in source
    assert "asyncio.timeout(RUNTIME_METRICS_QUERY_TIMEOUT_SECONDS)" in source
    assert "CURRENT_TIMESTAMP" in source
    assert ":worker_fresh_after_seconds" in source
    for prohibited in (
        "organization_id",
        "project_id",
        "lease_id",
        "run_id",
        "policy_id",
        "endpoint_url",
        "payload",
        "token_digest",
        "failure_summary",
    ):
        assert prohibited not in source


@pytest.mark.asyncio
@pytest.mark.parametrize("value", [14, 301])
async def test_runtime_metrics_reject_unbounded_worker_freshness(value: int) -> None:
    with pytest.raises(ValueError, match="Worker freshness"):
        await read_runtime_metrics(
            object(),  # type: ignore[arg-type]
            worker_fresh_after_seconds=value,
        )


def test_runtime_metrics_endpoint_is_hidden_and_fails_closed() -> None:
    source = (ROOT / "apps/api/app/api/routes/health.py").read_text(encoding="utf-8")
    assert '@router.get("/metrics/runtime", include_in_schema=False)' in source
    runtime = source[source.index("async def runtime_metrics(") :]
    assert '"rdc_runtime_metrics_healthy 0\\n"' in runtime
    assert "status_code=503" in runtime
    assert "PROMETHEUS_CONTENT_TYPE" in runtime
    assert "/metrics/runtime" not in app.openapi()["paths"]


def test_runtime_metrics_unavailable_alert_covers_failed_scrapes() -> None:
    rules = (
        ROOT / "infrastructure/monitoring/rdc-runtime.rules.yml"
    ).read_text(encoding="utf-8")
    assert (
        "absent(rdc_runtime_metrics_healthy) or "
        "rdc_runtime_metrics_healthy != 1"
    ) in rules
