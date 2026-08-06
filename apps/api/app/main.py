from fastapi import APIRouter, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .api.routes.health import router as health_router

app = FastAPI(
    title="Rooz Data Cloud API",
    version="0.1.0-phase1a",
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
    redoc_url=None,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Idempotency-Key", "If-Match", "X-RDC-CSRF"],
)
app.include_router(health_router)

v1_router = APIRouter(prefix="/api/v1")


@v1_router.get("/system/foundation", tags=["system"])
async def foundation_status() -> dict[str, object]:
    return {
        "arbitrary_code_in_api": False,
        "phase": "1A",
        "service": "rdc-api",
        "status": "foundation-ready",
        "tenant_rls_required": True,
        "write_only_secrets_required": True,
    }


app.include_router(v1_router)
