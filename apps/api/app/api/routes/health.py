from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from ...core.database import check_database
from ...core.redis_client import check_redis

router = APIRouter(tags=["health"])


@router.get("/health/live")
async def liveness() -> dict[str, str]:
    return {"service": "rdc-api", "status": "ok", "timestamp": datetime.now(UTC).isoformat()}


async def dependency_status() -> dict[str, str]:
    results: dict[str, str] = {}
    try:
        await check_database()
        results["postgres"] = "ready"
    except Exception:
        results["postgres"] = "unavailable"
    try:
        await check_redis()
        results["redis"] = "ready"
    except Exception:
        results["redis"] = "unavailable"
    return results


@router.get("/health/ready")
async def readiness() -> JSONResponse:
    dependencies = await dependency_status()
    ready = all(value == "ready" for value in dependencies.values())
    body: dict[str, Any] = {
        "dependencies": dependencies,
        "service": "rdc-api",
        "status": "ready" if ready else "degraded",
    }
    return JSONResponse(status_code=200 if ready else 503, content=body)
