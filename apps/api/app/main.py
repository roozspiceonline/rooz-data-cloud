from collections.abc import Awaitable, Callable
from uuid import uuid4

from fastapi import APIRouter, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.responses import Response

from .api.routes.agents import router as agents_router
from .api.routes.builds_secrets import router as builds_secrets_router
from .api.routes.health import router as health_router
from .api.routes.identity_tenancy import router as identity_router
from .core.config import get_settings
from .core.errors import (
    ApiError,
    api_error_handler,
    error_payload,
    validation_error_handler,
)

settings = get_settings()

app = FastAPI(
    title="Rooz Data Cloud API",
    version="0.4.0-phase1d",
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
        "X-RDC-CSRF",
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
        character.isalnum() or character in "._-"
        for character in incoming
    )
    request.state.request_id = incoming if valid else f"req_{uuid4().hex}"
    response = await call_next(request)
    response.headers["X-Request-ID"] = request.state.request_id
    response.headers["Cache-Control"] = "no-store"
    return response


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
    _: Exception,
) -> JSONResponse:
    return JSONResponse(
        status_code=500,
        content=error_payload(
            request,
            code="INTERNAL_ERROR",
            message="An unexpected error occurred.",
        ),
    )


app.include_router(health_router)

v1_router = APIRouter(prefix="/api/v1")
v1_router.include_router(identity_router)
v1_router.include_router(agents_router)
v1_router.include_router(builds_secrets_router)


@v1_router.get("/system/foundation", tags=["system"])
async def foundation_status() -> dict[str, object]:
    return {
        "arbitrary_code_in_api": False,
        "phase": "1D",
        "service": "rdc-api",
        "status": "project-secrets-build-control-plane",
        "write_only_project_secrets": True,
        "envelope_encryption_required": True,
        "durable_build_dispatch_outbox": True,
        "build_execution_isolated": True,
        "tenant_rls_required": True,
        "write_only_secrets_required": True,
        "tenant_rls_enabled": True,
        "opaque_server_sessions": True,
        "write_only_api_keys": True,
        "agent_versions_immutable": True,
        "build_execution_enabled": False,
        "run_execution_enabled": False,
    }


app.include_router(v1_router)
