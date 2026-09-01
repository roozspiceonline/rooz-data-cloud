from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def need(value: bool, message: str) -> None:
    if not value:
        raise SystemExit(message)


observability = (ROOT / "apps/api/app/core/observability.py").read_text()
main = (ROOT / "apps/api/app/main.py").read_text()
tests = (ROOT / "apps/api/tests/test_observability_contracts.py").read_text()
runner_paths = [
    "apps/api/app/recovery_scheduler.py",
    "apps/api/app/schedule_dispatcher.py",
    "apps/api/app/egress_health_maintenance_runner.py",
    "apps/api/app/egress_credential_canary_runner.py",
    "apps/api/app/webhook_delivery_runner.py",
]
worker = (ROOT / "workers/sandbox-runtime/worker.py").read_text()
worker_logging = (ROOT / "workers/sandbox-runtime/worker_observability.py").read_text()
sandbox_client = (ROOT / "workers/sandbox-runtime/rdc_worker_client.py").read_text()
execution_client = (ROOT / "workers/execution-plane/rdc_worker_client.py").read_text()
health_routes = (ROOT / "apps/api/app/api/routes/health.py").read_text()
runtime_metrics = (ROOT / "apps/api/app/services/runtime_metrics.py").read_text()
runtime_tests = (ROOT / "apps/api/tests/test_runtime_metrics_contracts.py").read_text()
runtime_alerts = (ROOT / "infrastructure/monitoring/rdc-runtime.rules.yml").read_text()

for marker in [
    'LOG_SCHEMA_VERSION: Final = "rdc.log/v1"',
    '"authorization"',
    '"credential"',
    '"payload"',
    '"secret"',
    '"token"',
    '"url"',
    "ContextVar",
    "RdcJsonFormatter",
    "configure_structured_logging",
    "log_event",
]:
    need(marker in observability, f"observability contract missing {marker}")

for marker in [
    '"http.request.completed"',
    'request.scope.get("route")',
    "route_template",
    "duration_ms",
    "bind_log_context(request_id=request.state.request_id)",
]:
    need(marker in main, f"HTTP correlation logging missing {marker}")
need("request.url" not in main, "HTTP logging must not read raw request URLs")
need("request.query_params" not in main, "HTTP logging must not read query strings")

for relative_path in runner_paths:
    source = (ROOT / relative_path).read_text()
    need(
        "configure_structured_logging(" in source and "log_event(" in source,
        f"trusted runner lacks structured logging: {relative_path}",
    )
    need("logging.basicConfig" not in source, f"legacy logging remains: {relative_path}")
    need("logger.exception" not in source, f"traceback logging remains: {relative_path}")

for marker in [
    "test_structured_log_rejects_secret_bearing_field_classes",
    "test_structured_log_rejects_nested_or_unbounded_values",
    "test_http_completion_uses_route_template_and_omits_query_string",
]:
    need(marker in tests, f"observability adversarial test missing {marker}")

for marker in [
    'LOG_SCHEMA_VERSION = "rdc.log/v1"',
    '"worker.started"',
    '"worker.lease.claimed"',
    '"worker.lease.completed"',
    '"worker.failed"',
    '"worker.stopped"',
    "lease_id",
    "run_id",
    "worker_id",
]:
    need(
        marker in worker_logging or marker in worker,
        f"worker observability contract missing {marker}",
    )
need(
    "tenant-authorized `LOG_BUNDLE`" in (ROOT / "docs/observability/README.md").read_text(),
    "Agent log boundary documentation is missing",
)
for source in (sandbox_client, execution_client):
    need(
        '"X-Request-ID": request_correlation_id(path)' in source,
        "worker client correlation header is missing",
    )
    need('return f"lease_{lease_id.hex}"' in source, "lease correlation is missing")
build_source = worker[worker.index("def _build(") : worker.index("def _run(")]
run_source = worker[worker.index("def _run(") : worker.index("def main(")]
need(
    "request_egress_credential_envelope" not in build_source,
    "Build path must not resolve Run egress credentials",
)
need(
    "request_egress_credential_envelope" in run_source
    and "authorization=egress_authorization" in run_source,
    "Run path must resolve and consume credential-bound egress authorization",
)

for marker in [
    '@router.get("/metrics/runtime", include_in_schema=False)',
    '"rdc_runtime_metrics_healthy 0\\n"',
    "read_runtime_metrics(",
]:
    need(marker in health_routes, f"runtime metrics route missing {marker}")
for marker in [
    "class RuntimeMetrics",
    "await session.execute(",
    "control.execution_leases",
    "control.schedules",
    "control.request_queue_requests",
    "control.egress_credential_canary_attempts",
    "control.webhook_delivery_attempts",
]:
    need(marker in runtime_metrics, f"runtime metrics snapshot missing {marker}")
need(
    runtime_metrics.count("await session.execute(") == 1,
    "runtime metrics must use one database snapshot query",
)
for marker in [
    "test_runtime_metrics_are_fixed_scalar_global_aggregates",
    "test_runtime_metrics_query_is_one_fixed_snapshot_without_dimensions",
    "test_runtime_metrics_endpoint_is_hidden_and_fails_closed",
]:
    need(marker in runtime_tests, f"runtime metrics test missing {marker}")
for marker in [
    "RDCRuntimeMetricsUnavailable",
    "absent(rdc_runtime_metrics_healthy)",
    "RDCExecutionDispatchBacklogWithoutWorkers",
    "RDCWebhookDeliveryBacklog",
]:
    need(marker in runtime_alerts, f"runtime metrics alert missing {marker}")

print("Structured observability foundation verification passed")
