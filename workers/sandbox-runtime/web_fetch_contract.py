from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

_SCHEMA_VERSION = "rdc.web-fetch/v1"
_RESULT_SCHEMA_VERSION = "rdc.web-fetch-result/v1"
_REQUEST_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ALLOWED_METHODS = {"GET", "HEAD"}
_SAFE_HEADERS = {
    "content-type",
    "content-length",
    "etag",
    "last-modified",
    "cache-control",
}
_MAX_REQUESTS = 32
_MAX_URL_LENGTH = 8192
_MAX_ENVELOPE_BYTES = 65_536


class WebFetchContractError(ValueError):
    pass


@dataclass(frozen=True)
class WebFetchRequest:
    request_id: str
    method: str
    url: str

    def as_broker_request(self) -> dict[str, str]:
        return {
            "id": self.request_id,
            "method": self.method,
            "url": self.url,
        }


@dataclass(frozen=True)
class WebFetchEnvelope:
    requests: tuple[WebFetchRequest, ...]

    @property
    def schema_version(self) -> str:
        return _SCHEMA_VERSION

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "requests": [
                request.as_broker_request()
                for request in self.requests
            ],
        }

    @property
    def digest(self) -> str:
        return hashlib.sha256(_canonical_bytes(self.as_dict())).hexdigest()

    def as_phase1j_broker_input(self) -> dict[str, object]:
        return {
            "_rdc_web_requests": [
                request.as_broker_request()
                for request in self.requests
            ]
        }


def _canonical_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise WebFetchContractError(
            "Web-fetch value must contain valid JSON."
        ) from exc


def _normalize_request(raw: object) -> WebFetchRequest:
    if not isinstance(raw, dict) or set(raw) != {"id", "method", "url"}:
        raise WebFetchContractError(
            "Web-fetch requests require exactly id, method, and url."
        )

    request_id = raw.get("id")
    if (
        not isinstance(request_id, str)
        or _REQUEST_ID.fullmatch(request_id) is None
    ):
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
    if not url.startswith("https://"):
        raise WebFetchContractError(
            "Web-fetch URL must use lowercase https://."
        )

    try:
        parsed = urlsplit(url)
    except ValueError as exc:
        raise WebFetchContractError("Web-fetch URL is malformed.") from exc

    if not parsed.hostname:
        raise WebFetchContractError("Web-fetch URL requires a hostname.")
    if parsed.username is not None or parsed.password is not None:
        raise WebFetchContractError(
            "Web-fetch URL credentials are not allowed."
        )

    return WebFetchRequest(
        request_id=request_id,
        method=method,
        url=url,
    )


def parse_web_fetch_envelope(raw: object) -> WebFetchEnvelope:
    if not isinstance(raw, dict) or set(raw) != {"schema_version", "requests"}:
        raise WebFetchContractError(
            "Web-fetch envelope requires exactly schema_version and requests."
        )
    if raw.get("schema_version") != _SCHEMA_VERSION:
        raise WebFetchContractError("Unsupported web-fetch schema version.")

    requests = raw.get("requests")
    if not isinstance(requests, list):
        raise WebFetchContractError("Web-fetch requests must be a list.")
    if not 1 <= len(requests) <= _MAX_REQUESTS:
        raise WebFetchContractError(
            "Web-fetch request count is outside the safe range."
        )

    normalized = tuple(_normalize_request(item) for item in requests)
    ids = [request.request_id for request in normalized]
    if len(ids) != len(set(ids)):
        raise WebFetchContractError("Web-fetch request ids must be unique.")

    envelope = WebFetchEnvelope(requests=normalized)
    if len(_canonical_bytes(envelope.as_dict())) > _MAX_ENVELOPE_BYTES:
        raise WebFetchContractError(
            "Web-fetch envelope cannot exceed 64 KiB."
        )
    return envelope


def canonical_web_fetch_digest(raw: object) -> str:
    return parse_web_fetch_envelope(raw).digest


def phase1j_broker_adapter(raw: object) -> dict[str, object]:
    return parse_web_fetch_envelope(raw).as_phase1j_broker_input()


def _result_body(raw: dict[str, object]) -> dict[str, object]:
    size = raw.get("size_bytes")
    digest = raw.get("body_sha256")
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        raise WebFetchContractError("Broker result size is invalid.")
    if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
        raise WebFetchContractError("Broker result body digest is invalid.")

    text = raw.get("body_text")
    encoded = raw.get("body_base64")
    if text is not None and encoded is not None:
        raise WebFetchContractError(
            "Broker result cannot contain text and base64 bodies together."
        )
    if text is not None:
        if not isinstance(text, str):
            raise WebFetchContractError("Broker text body is invalid.")
        encoding = "text"
        value: str | None = text
    elif encoded is not None:
        if not isinstance(encoded, str):
            raise WebFetchContractError("Broker base64 body is invalid.")
        encoding = "base64"
        value = encoded
    else:
        encoding = "none"
        value = None

    return {
        "encoding": encoding,
        "value": value,
        "size_bytes": size,
        "sha256": digest,
    }


def phase1j_broker_result_adapter(
    request_envelope: object,
    broker_output: object,
) -> dict[str, object]:
    envelope = parse_web_fetch_envelope(request_envelope)
    if not isinstance(broker_output, dict):
        raise WebFetchContractError("Broker output must be an object.")

    raw_results = broker_output.get("_rdc_web_results")
    raw_budget = broker_output.get("_rdc_web_budget")
    if not isinstance(raw_results, list) or not isinstance(raw_budget, dict):
        raise WebFetchContractError(
            "Broker output is missing result or budget metadata."
        )
    if len(raw_results) != len(envelope.requests):
        raise WebFetchContractError(
            "Broker result count does not match the request envelope."
        )

    results: list[dict[str, object]] = []
    for request, raw in zip(envelope.requests, raw_results, strict=True):
        if not isinstance(raw, dict):
            raise WebFetchContractError("Broker result must be an object.")
        if raw.get("id") != request.request_id:
            raise WebFetchContractError("Broker result id mismatch.")
        if raw.get("method") != request.method:
            raise WebFetchContractError("Broker result method mismatch.")

        url = raw.get("url")
        status = raw.get("status")
        headers = raw.get("headers")
        if not isinstance(url, str) or not url.startswith("https://"):
            raise WebFetchContractError("Broker final URL is invalid.")
        if (
            not isinstance(status, int)
            or isinstance(status, bool)
            or not 100 <= status <= 599
        ):
            raise WebFetchContractError("Broker HTTP status is invalid.")
        if not isinstance(headers, dict):
            raise WebFetchContractError("Broker headers are invalid.")

        safe_headers: dict[str, str] = {}
        for key, value in headers.items():
            if (
                not isinstance(key, str)
                or not isinstance(value, str)
                or key.casefold() not in _SAFE_HEADERS
            ):
                raise WebFetchContractError(
                    "Broker returned an unsupported response header."
                )
            safe_headers[key.casefold()] = value[:2048]

        results.append(
            {
                "id": request.request_id,
                "method": request.method,
                "url": url,
                "status": status,
                "headers": safe_headers,
                "body": _result_body(raw),
            }
        )

    budget_keys = {
        "requests_used",
        "bytes_received",
        "max_requests",
        "max_total_bytes",
    }
    if set(raw_budget) != budget_keys:
        raise WebFetchContractError("Broker budget metadata is invalid.")
    budget: dict[str, int] = {}
    for key in sorted(budget_keys):
        value = raw_budget.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise WebFetchContractError("Broker budget value is invalid.")
        budget[key] = value

    return {
        "schema_version": _RESULT_SCHEMA_VERSION,
        "request_digest": envelope.digest,
        "results": results,
        "budget": budget,
    }
