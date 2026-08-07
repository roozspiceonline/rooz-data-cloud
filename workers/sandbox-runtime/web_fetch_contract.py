from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

_SCHEMA_VERSION = "rdc.web-fetch/v1"
_REQUEST_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_ALLOWED_METHODS = {"GET", "HEAD"}
_MAX_REQUESTS = 32
_MAX_URL_LENGTH = 8192


class WebFetchContractError(ValueError):
    pass


@dataclass(frozen=True)
class WebFetchRequest:
    request_id: str
    method: str
    url: str

    def as_broker_request(self) -> dict[str, str]:
        return {"id": self.request_id, "method": self.method, "url": self.url}


@dataclass(frozen=True)
class WebFetchEnvelope:
    requests: tuple[WebFetchRequest, ...]

    @property
    def schema_version(self) -> str:
        return _SCHEMA_VERSION

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "requests": [request.as_broker_request() for request in self.requests],
        }

    @property
    def digest(self) -> str:
        encoded = json.dumps(
            self.as_dict(),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def as_phase1j_broker_input(self) -> dict[str, object]:
        return {
            "_rdc_web_requests": [
                request.as_broker_request() for request in self.requests
            ]
        }


def _normalize_request(raw: object) -> WebFetchRequest:
    if not isinstance(raw, dict) or set(raw) != {"id", "method", "url"}:
        raise WebFetchContractError(
            "Web-fetch requests require exactly id, method, and url."
        )

    request_id = raw.get("id")
    if not isinstance(request_id, str) or _REQUEST_ID.fullmatch(request_id) is None:
        raise WebFetchContractError("Web-fetch request id is invalid.")

    method = raw.get("method")
    if not isinstance(method, str):
        raise WebFetchContractError("Web-fetch method must be a string.")
    method = method.upper()
    if method not in _ALLOWED_METHODS:
        raise WebFetchContractError("Web-fetch method must be GET or HEAD.")

    url = raw.get("url")
    if not isinstance(url, str) or not url or len(url) > _MAX_URL_LENGTH:
        raise WebFetchContractError("Web-fetch URL is invalid.")

    try:
        parsed = urlsplit(url)
    except ValueError as exc:
        raise WebFetchContractError("Web-fetch URL is malformed.") from exc

    if parsed.scheme.casefold() != "https":
        raise WebFetchContractError("Web-fetch URL must use HTTPS.")
    if not parsed.hostname:
        raise WebFetchContractError("Web-fetch URL requires a hostname.")
    if parsed.username is not None or parsed.password is not None:
        raise WebFetchContractError("Web-fetch URL credentials are not allowed.")

    return WebFetchRequest(request_id=request_id, method=method, url=url)


def parse_web_fetch_envelope(raw: object) -> WebFetchEnvelope:
    if not isinstance(raw, dict) or set(raw) != {"schema_version", "requests"}:
        raise WebFetchContractError(
            "Web-fetch envelope requires exactly schema_version and requests."
        )
    if raw.get("schema_version") != _SCHEMA_VERSION:
        raise WebFetchContractError("Unsupported web-fetch schema version.")

    requests = raw.get("requests")
    if not isinstance(requests, list) or not 1 <= len(requests) <= _MAX_REQUESTS:
        raise WebFetchContractError(
            "Web-fetch request count is outside the safe range."
        )

    normalized = tuple(_normalize_request(item) for item in requests)
    ids = [request.request_id for request in normalized]
    if len(ids) != len(set(ids)):
        raise WebFetchContractError("Web-fetch request ids must be unique.")

    return WebFetchEnvelope(requests=normalized)


def canonical_web_fetch_digest(raw: object) -> str:
    return parse_web_fetch_envelope(raw).digest


def phase1j_broker_adapter(raw: object) -> dict[str, object]:
    return parse_web_fetch_envelope(raw).as_phase1j_broker_input()
