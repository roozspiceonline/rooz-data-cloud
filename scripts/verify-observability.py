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

print("Structured observability foundation verification passed")
