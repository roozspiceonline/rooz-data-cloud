import logging
import time
from collections.abc import Awaitable, Callable
from uuid import uuid4

from fastapi import APIRouter, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.responses import Response

from .api.routes.agents import router as agents_router
from .api.routes.builds_secrets import router as builds_secrets_router
from .api.routes.datasets import router as datasets_router
from .api.routes.egress_policies import router as egress_policies_router
from .api.routes.events import router as events_router
from .api.routes.execution import router as execution_router
from .api.routes.health import router as health_router
from .api.routes.identity_tenancy import router as identity_router
from .api.routes.internal_execution import router as internal_execution_router
from .api.routes.key_value_stores import router as key_value_stores_router
from .api.routes.request_queues import router as request_queues_router
from .api.routes.runs import router as runs_router
from .api.routes.schedules import router as schedules_router
from .api.routes.storage import router as storage_router
from .api.routes.webhook_deliveries import router as webhook_deliveries_router
from .api.routes.webhook_destinations import router as webhook_destinations_router
from .core.config import get_settings
from .core.errors import (
    ApiError,
    api_error_handler,
    error_payload,
    validation_error_handler,
)
from .core.observability import (
    bind_log_context,
    configure_structured_logging,
    log_event,
    reset_log_context,
)

settings = get_settings()
configure_structured_logging(
    service="api",
    environment=settings.env,
    deployment_id=settings.deployment_id,
)
logger = logging.getLogger("rdc.api")

app = FastAPI(
    title="Rooz Data Cloud API",
    version="0.15.0-phase1o",
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
    redoc_url=None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=[
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "OPTIONS",
    ],
    allow_headers=[
        "Authorization",
        "Content-Type",
        "Idempotency-Key",
        "If-Match",
        "Last-Event-ID",
        "X-RDC-CSRF",
        "X-RDC-Lease-Token",
        "X-Request-ID",
    ],
)


@app.middleware("http")
async def request_context(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
) -> Response:
    incoming = request.headers.get("X-Request-ID", "")
    valid = 1 <= len(incoming) <= 100 and all(
        character.isalnum() or character in "._-" for character in incoming
    )
    request.state.request_id = incoming if valid else f"req_{uuid4().hex}"
    token = bind_log_context(request_id=request.state.request_id)
    started = time.monotonic()
    response: Response | None = None
    try:
        response = await call_next(request)
        response.headers["X-Request-ID"] = request.state.request_id
        response.headers.setdefault("Cache-Control", "no-store")
        return response
    finally:
        route = request.scope.get("route")
        route_template = getattr(route, "path", "unmatched")
        status_code = response.status_code if response is not None else 500
        log_event(
            logger,
            logging.ERROR if status_code >= 500 else logging.INFO,
            "http.request.completed",
            method=request.method,
            route=route_template,
            status_code=status_code,
            duration_ms=max(0, round((time.monotonic() - started) * 1000)),
        )
        reset_log_context(token)


async def handle_api_error(
    request: Request,
    exc: Exception,
) -> JSONResponse:
    if not isinstance(exc, ApiError):
        raise exc
    return await api_error_handler(request, exc)


async def handle_validation_error(
    request: Request,
    exc: Exception,
) -> JSONResponse:
    if not isinstance(exc, RequestValidationError):
        raise exc
    return await validation_error_handler(request, exc)


app.add_exception_handler(ApiError, handle_api_error)
app.add_exception_handler(
    RequestValidationError,
    handle_validation_error,
)


@app.exception_handler(Exception)
async def unexpected_error(
    request: Request,
    exc: Exception,
) -> JSONResponse:
    token = bind_log_context(request_id=request.state.request_id)
    try:
        log_event(
            logger,
            logging.ERROR,
            "http.request.unexpected_error",
            error_type=type(exc).__name__,
        )
    finally:
        reset_log_context(token)
    return JSONResponse(
        status_code=500,
        content=error_payload(
            request,
            code="INTERNAL_ERROR",
            message="An unexpected error occurred.",
        ),
    )


app.include_router(health_router)
app.include_router(internal_execution_router)

v1_router = APIRouter(prefix="/api/v1")
v1_router.include_router(identity_router)
v1_router.include_router(agents_router)
v1_router.include_router(builds_secrets_router)
v1_router.include_router(datasets_router)
v1_router.include_router(egress_policies_router)
v1_router.include_router(events_router)
v1_router.include_router(webhook_destinations_router)
v1_router.include_router(webhook_deliveries_router)
v1_router.include_router(key_value_stores_router)
v1_router.include_router(request_queues_router)
v1_router.include_router(runs_router)
v1_router.include_router(schedules_router)
v1_router.include_router(execution_router)
v1_router.include_router(storage_router)


def _browser_live_navigation_canary_enabled() -> bool:
    return (
        settings.sandbox_execution_enabled
        and settings.sandbox_activation_mode == "canary"
        and settings.sandbox_canary_web_egress_enabled
        and settings.sandbox_canary_browser_enabled
        and settings.sandbox_canary_browser_live_navigation_enabled
        and bool(settings.sandbox_canary_web_egress_allowed_hosts)
        and bool(settings.sandbox_canary_agent_version_id.strip())
        and bool(settings.sandbox_canary_worker_name.strip())
    )


def _dataset_worker_canary_enabled() -> bool:
    return (
        settings.sandbox_execution_enabled
        and settings.sandbox_activation_mode == "canary"
        and settings.sandbox_canary_dataset_writes_enabled
        and bool(settings.sandbox_canary_agent_version_id.strip())
        and bool(settings.sandbox_canary_worker_name.strip())
    )


def _key_value_store_worker_canary_enabled() -> bool:
    return (
        settings.sandbox_execution_enabled
        and settings.sandbox_activation_mode == "canary"
        and settings.sandbox_canary_key_value_store_enabled
        and bool(settings.sandbox_canary_agent_version_id.strip())
        and bool(settings.sandbox_canary_worker_name.strip())
    )


@v1_router.get("/system/foundation", tags=["system"])
async def foundation_status() -> dict[str, object]:
    return {
        "arbitrary_code_in_api": False,
        "phase": "1O",
        "service": "rdc-api",
        "status": "tenant-key-value-store-versioned-state",
        "write_only_project_secrets": True,
        "write_only_secrets_required": True,
        "envelope_encryption_required": True,
        "durable_build_dispatch_outbox": True,
        "build_execution_isolated": True,
        "tenant_rls_required": True,
        "tenant_rls_enabled": True,
        "schedule_persistence_enabled": True,
        "schedule_trigger_history_immutable": True,
        "schedule_dispatch_enabled": settings.schedule_dispatch_enabled,
        "schedule_dispatch_singleton_lock": "postgresql-advisory-xact",
        "schedule_missed_run_policies": ["SKIP", "FIRE_ONCE"],
        "egress_policy_metadata_persistence_enabled": True,
        "egress_policy_revisions_immutable": True,
        "egress_policy_rls_enabled": True,
        "egress_policy_live_binding_enabled": True,
        "egress_policy_binding_receipt": "rdc.run-egress-policy-receipt/v1",
        "egress_policy_worker_credential_envelopes_enabled": True,
        "egress_policy_plaintext_credentials_exposed": False,
        "egress_credential_canary_persistence_enabled": True,
        "egress_credential_canary_history_immutable": True,
        "egress_credential_canary_scheduling_enabled": (settings.egress_credential_canary_enabled),
        "egress_credential_canary_live_executor_enabled": (
            settings.egress_credential_canary_live_executor_enabled
        ),
        "egress_adaptive_routing_enabled": False,
        "event_persistence_enabled": True,
        "event_history_project_rls_enabled": True,
        "webhook_delivery_enabled": False,
        "webhook_destination_persistence_enabled": True,
        "webhook_destination_activation_enabled": True,
        "webhook_delivery_lifecycle_persistence_enabled": True,
        "webhook_delivery_claim_fencing_enabled": True,
        "webhook_delivery_canary_enabled": settings.webhook_delivery_canary_enabled,
        "webhook_delivery_network_policy_available": True,
        "webhook_delivery_digest_only_claims_enabled": True,
        "webhook_delivery_claim_scoped_secret_loader_enabled": True,
        "webhook_delivery_direct_tls_transport_available": True,
        "webhook_delivery_history_enabled": True,
        "webhook_delivery_replay_enabled": True,
        "webhook_automatic_failure_disablement_enabled": True,
        "webhook_active_event_enqueue_enabled": True,
        "opaque_server_sessions": True,
        "write_only_api_keys": True,
        "agent_versions_immutable": True,
        "build_execution_enabled": settings.sandbox_execution_enabled,
        "run_control_plane_enabled": True,
        "run_dispatch_outbox_enabled": True,
        "run_sse_monitoring_enabled": True,
        "run_execution_enabled": settings.sandbox_execution_enabled,
        "internal_execution_protocol_enabled": True,
        "worker_leasing_enabled": True,
        "execution_retry_policy_server_owned": True,
        "execution_retry_base_seconds": settings.worker_retry_base_seconds,
        "execution_retry_max_seconds": settings.worker_retry_max_seconds,
        "execution_retry_requires_durable_source": True,
        "execution_deadline_server_derived": True,
        "execution_deadline_immutable": True,
        "lease_renewal_deadline_clamped": True,
        "run_cancellation_dispatch_idempotent": True,
        "run_cancellation_convergence_seconds": (settings.worker_cancel_convergence_seconds),
        "run_cancellation_lease_fencing": True,
        "execution_recovery_scheduler_enabled": (settings.execution_recovery_sweep_enabled),
        "execution_recovery_sweep_interval_seconds": (
            settings.execution_recovery_sweep_interval_seconds
        ),
        "execution_recovery_sweep_batch_size": (settings.execution_recovery_sweep_batch_size),
        "execution_recovery_singleton_lock": "postgresql-advisory-xact",
        "execution_project_concurrency_admission": True,
        "execution_worker_concurrency_admission": True,
        "execution_project_default_max_active_leases": (
            settings.execution_project_default_max_active_leases
        ),
        "worker_registration_max_concurrency": (settings.worker_registration_max_concurrency),
        "worker_loss_detection": True,
        "worker_lost_after_seconds": settings.worker_lost_after_seconds,
        "worker_restart_cleanup_required": True,
        "managed_runtime_forced_cleanup": True,
        "production_environment_identity_guard": True,
        "production_supervisor_contract": "systemd-control-group",
        "database_restore_rollback_drill": True,
        "object_version_recovery_drill": True,
        "execution_recovery_slo_metrics": True,
        "run_cancel_project_slot_exempt": True,
        "artifact_metadata_enabled": True,
        "lease_scoped_secret_envelopes_enabled": True,
        "secure_source_ingestion_enabled": True,
        "artifact_object_delivery_enabled": True,
        "sandbox_execution_enabled": settings.sandbox_execution_enabled,
        "sandbox_attestation_required": True,
        "sandbox_default_network_policy": "deny-all",
        "sandbox_activation_mode": settings.sandbox_activation_mode,
        "sandbox_container_network_policy": "deny-all",
        "sandbox_canary_web_egress_enabled": (settings.sandbox_canary_web_egress_enabled),
        "web_fetch_request_contract": "rdc.web-fetch/v1",
        "web_fetch_result_contract": "rdc.web-fetch-result/v1",
        "versioned_web_fetch_contract_available": True,
        "web_fetch_activation_scope": "phase1j-single-canary",
        "browser_request_contract": "rdc.browser/v1",
        "browser_navigation_request_contract": "rdc.browser/v2",
        "browser_navigation_receipt_contract": ("rdc.browser-navigation-receipt/v1"),
        "browser_navigation_intent_contract_available": True,
        "browser_navigation_dispatch_enabled": _browser_live_navigation_canary_enabled(),
        "browser_egress_policy_contract": "rdc.browser-egress-policy/v1",
        "browser_egress_policy_available": True,
        "browser_egress_transport_wired": True,
        "browser_egress_subresource_revalidation": True,
        "browser_gateway_transport_contract": ("rdc.browser-gateway-transport-self-test/v1"),
        "browser_gateway_transport_mode": "unix-domain-socket",
        "browser_gateway_transport_self_test_available": True,
        "browser_gateway_live_forwarding_enabled": _browser_live_navigation_canary_enabled(),
        "browser_gateway_live_forwarding_contract_available": True,
        "browser_gateway_request_contract": "rdc.browser-gateway-request/v1",
        "browser_gateway_response_contract": "rdc.browser-gateway-response/v1",
        "browser_navigation_result_contract": "rdc.browser-navigation-result/v1",
        "browser_navigation_live_code_available": True,
        "browser_navigation_live_worker_wired": True,
        "browser_live_navigation_gate_enabled": (
            settings.sandbox_canary_browser_live_navigation_enabled
        ),
        "browser_live_navigation_canary_enabled": (_browser_live_navigation_canary_enabled()),
        "browser_policy_contract": "rdc.browser-policy/v1",
        "browser_runtime_self_test_contract": ("rdc.browser-runtime-self-test/v1"),
        "browser_runtime_self_test_available": True,
        "browser_execution_enabled": _browser_live_navigation_canary_enabled(),
        "browser_public_navigation_enabled": _browser_live_navigation_canary_enabled(),
        "browser_canary_activation_enabled": (
            settings.sandbox_execution_enabled
            and settings.sandbox_activation_mode == "canary"
            and settings.sandbox_canary_web_egress_enabled
            and settings.sandbox_canary_browser_enabled
            and bool(settings.sandbox_canary_web_egress_allowed_hosts)
            and bool(settings.sandbox_canary_agent_version_id.strip())
            and bool(settings.sandbox_canary_worker_name.strip())
        ),
        "brokered_web_egress_enabled": (
            settings.sandbox_execution_enabled
            and settings.sandbox_activation_mode == "canary"
            and settings.sandbox_canary_web_egress_enabled
            and bool(settings.sandbox_canary_web_egress_allowed_hosts)
            and bool(settings.sandbox_canary_agent_version_id.strip())
            and bool(settings.sandbox_canary_worker_name.strip())
        ),
        "controlled_canary_execution_enabled": (
            settings.sandbox_execution_enabled
            and settings.sandbox_activation_mode == "canary"
            and bool(settings.sandbox_canary_agent_version_id.strip())
            and bool(settings.sandbox_canary_worker_name.strip())
        ),
        "dataset_append_contract": "rdc.dataset-append/v1",
        "dataset_metadata_persistence_enabled": True,
        "dataset_item_append_enabled": True,
        "dataset_item_read_enabled": True,
        "dataset_item_cursor_signed": True,
        "dataset_bounded_export_enabled": True,
        "dataset_export_format": "jsonl",
        "dataset_export_max_items": 10_000,
        "dataset_export_max_bytes": 16_777_216,
        "dataset_export_requires_authentication": True,
        "dataset_public_export_enabled": False,
        "dataset_worker_capability_contract": "rdc.dataset-worker-capability/v1",
        "dataset_worker_write_gate_enabled": (settings.sandbox_canary_dataset_writes_enabled),
        "dataset_worker_append_canary_enabled": _dataset_worker_canary_enabled(),
        "dataset_rls_enabled": True,
        "dataset_items_immutable": True,
        "key_value_store_contract": "rdc.kv-write/v1",
        "key_value_store_metadata_persistence_enabled": True,
        "key_value_store_record_mutation_enabled": True,
        "key_value_store_record_read_enabled": True,
        "key_value_store_record_listing_enabled": True,
        "key_value_store_record_cursor_signed": True,
        "key_value_store_worker_capability_contract": "rdc.kv-worker-capability/v1",
        "key_value_store_worker_gate_enabled": settings.sandbox_canary_key_value_store_enabled,
        "request_queue_key_value_store_composition_gate_enabled": (
            settings.sandbox_canary_request_queue_key_value_store_enabled
        ),
        "request_queue_key_value_store_receipt_contract": (
            "rdc.request-queue-key-value-store-receipt/v1"
        ),
        "request_queue_key_value_store_queue_capability_contract": (
            "rdc.request-queue-worker-capability/v5"
        ),
        "request_queue_key_value_store_kv_capability_contract": ("rdc.kv-worker-capability/v2"),
        "key_value_store_worker_canary_enabled": _key_value_store_worker_canary_enabled(),
        "key_value_store_rls_enabled": True,
        "key_value_store_public_access_enabled": False,
        "untrusted_agent_execution_enabled": False,
    }


app.include_router(v1_router)
