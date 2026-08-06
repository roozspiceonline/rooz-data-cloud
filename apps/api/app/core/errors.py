from collections.abc import Mapping, Sequence
from typing import Any

from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse


class ApiError(Exception):
    def __init__(
        self,
        *,
        status_code: int,
        code: str,
        message: str,
        field_errors: Sequence[Mapping[str, str]] | None = None,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.field_errors = list(field_errors or [])
        self.details = dict(details or {})


def request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", "req_unknown"))


def error_payload(
    request: Request,
    *,
    code: str,
    message: str,
    field_errors: Sequence[Mapping[str, str]] | None = None,
    details: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "error": {
            "code": code,
            "message": message,
            "request_id": request_id(request),
            "field_errors": list(field_errors or []),
            "details": dict(details or {}),
        }
    }


async def api_error_handler(request: Request, exc: ApiError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content=error_payload(
            request,
            code=exc.code,
            message=exc.message,
            field_errors=exc.field_errors,
            details=exc.details,
        ),
    )


async def validation_error_handler(
    request: Request,
    exc: RequestValidationError,
) -> JSONResponse:
    field_errors = []
    for item in exc.errors():
        location = ".".join(str(part) for part in item.get("loc", []) if part != "body")
        field_errors.append(
            {
                "field": location or "request",
                "code": str(item.get("type", "INVALID")),
                "message": str(item.get("msg", "Invalid value.")),
            }
        )
    return JSONResponse(
        status_code=422,
        content=error_payload(
            request,
            code="VALIDATION_FAILED",
            message="One or more fields are invalid.",
            field_errors=field_errors,
        ),
    )


def success_payload(request: Request, data: Any) -> dict[str, Any]:
    return {"data": data, "meta": {"request_id": request_id(request)}}
