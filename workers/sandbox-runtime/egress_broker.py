from __future__ import annotations

import base64
import hashlib
import http.client
import re
import socket
import ssl
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urljoin, urlsplit

from egress_policy import EgressPolicy, EgressPolicyError, ValidatedTarget

_REQUEST_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_REDIRECT_STATUSES = {301, 302, 303, 307, 308}
_TEXTUAL_TYPES = (
    "text/",
    "application/json",
    "application/xml",
    "application/xhtml+xml",
    "application/javascript",
)


@dataclass(frozen=True)
class BrokerResponse:
    request_id: str
    method: str
    url: str
    status: int
    headers: dict[str, str]
    body_text: str | None
    body_base64: str | None
    size_bytes: int
    body_sha256: str

    def as_dict(self) -> dict[str, object]:
        return {
            "id": self.request_id,
            "method": self.method,
            "url": self.url,
            "status": self.status,
            "headers": self.headers,
            "body_text": self.body_text,
            "body_base64": self.body_base64,
            "size_bytes": self.size_bytes,
            "body_sha256": self.body_sha256,
        }


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(
        self,
        *,
        hostname: str,
        address: str,
        connect_timeout: int,
        request_timeout: int,
    ) -> None:
        super().__init__(
            hostname,
            port=443,
            timeout=request_timeout,
            context=ssl.create_default_context(),
        )
        self._rdc_address = address
        self._rdc_connect_timeout = connect_timeout

    def connect(self) -> None:
        raw = socket.create_connection(
            (self._rdc_address, 443),
            timeout=self._rdc_connect_timeout,
        )
        raw.settimeout(self.timeout)
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)


ConnectionFactory = Callable[
    [ValidatedTarget, EgressPolicy],
    http.client.HTTPSConnection,
]


def _default_connection(
    target: ValidatedTarget,
    policy: EgressPolicy,
) -> http.client.HTTPSConnection:
    return _PinnedHTTPSConnection(
        hostname=target.hostname,
        address=target.addresses[0],
        connect_timeout=policy.connect_timeout_seconds,
        request_timeout=policy.request_timeout_seconds,
    )


def _safe_headers(response: http.client.HTTPResponse) -> dict[str, str]:
    allowed = {
        "content-type",
        "content-length",
        "etag",
        "last-modified",
        "cache-control",
    }
    result: dict[str, str] = {}
    for key, value in response.getheaders():
        normalized = key.casefold()
        if normalized in allowed:
            result[normalized] = value[:2048]
    return result


def _decode_body(
    body: bytes,
    content_type: str,
) -> tuple[str | None, str | None]:
    lowered = content_type.casefold()
    if any(lowered.startswith(prefix) for prefix in _TEXTUAL_TYPES):
        charset = "utf-8"
        for item in content_type.split(";")[1:]:
            name, separator, value = item.strip().partition("=")
            if (
                separator
                and name.casefold() == "charset"
                and value.strip()
            ):
                charset = value.strip().strip('"').strip("'")
                break
        try:
            text = body.decode(charset, errors="replace")
        except LookupError as exc:
            raise EgressPolicyError(
                "Response declared an unsupported charset."
            ) from exc
        return text, None
    return None, base64.b64encode(body).decode("ascii")


def _request_once(
    *,
    target: ValidatedTarget,
    method: str,
    policy: EgressPolicy,
    connection_factory: ConnectionFactory,
) -> tuple[int, dict[str, str], bytes, str | None]:
    parsed = urlsplit(target.url)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    connection = connection_factory(target, policy)
    try:
        connection.request(
            method,
            path,
            headers={
                "Host": target.hostname,
                "User-Agent": "RDC-Phase1J-Canary/1.0",
                "Accept": (
                    "text/html,application/json,text/plain,application/xml,"
                    "application/xhtml+xml;q=0.9,*/*;q=0.1"
                ),
                "Accept-Encoding": "identity",
                "Connection": "close",
            },
        )
        response = connection.getresponse()
        headers = _safe_headers(response)
        content_encoding = (
            response.getheader("Content-Encoding") or "identity"
        ).casefold()
        if content_encoding not in {"", "identity"}:
            raise EgressPolicyError(
                "Compressed web-egress responses are not accepted in Phase 1J."
            )
        location = response.getheader("Location")
        if response.status in _REDIRECT_STATUSES:
            return response.status, headers, b"", location
        if method == "HEAD":
            return response.status, headers, b"", None
        body = response.read(policy.max_response_bytes + 1)
        if len(body) > policy.max_response_bytes:
            raise EgressPolicyError(
                "Web-egress response exceeded the per-response byte limit."
            )
        return response.status, headers, body, None
    except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
        raise EgressPolicyError("Brokered HTTPS request failed.") from exc
    finally:
        connection.close()


def broker_validated_resource_once(
    *,
    target: ValidatedTarget,
    method: str,
    policy: EgressPolicy,
    connection_factory: ConnectionFactory = _default_connection,
) -> tuple[int, dict[str, str], bytes, str | None]:
    normalized_method = method.strip().upper()
    if normalized_method not in {"GET", "HEAD"}:
        raise EgressPolicyError(
            "Validated broker request permits GET and HEAD only."
        )
    return _request_once(
        target=target,
        method=normalized_method,
        policy=policy,
        connection_factory=connection_factory,
    )


def _fetch(
    *,
    request_id: str,
    method: str,
    url: str,
    policy: EgressPolicy,
    resolver,
    connection_factory: ConnectionFactory,
    budget: dict[str, int],
) -> BrokerResponse:
    current_url = url
    redirect_count = 0

    while True:
        if budget["requests"] >= policy.max_requests:
            raise EgressPolicyError("Web-egress request budget was exceeded.")
        target = policy.validate_target(current_url, resolver=resolver)
        budget["requests"] += 1

        status, headers, body, location = _request_once(
            target=target,
            method=method,
            policy=policy,
            connection_factory=connection_factory,
        )

        if status in _REDIRECT_STATUSES:
            if not location:
                raise EgressPolicyError(
                    "Redirect response did not include Location."
                )
            if redirect_count >= policy.max_redirects:
                raise EgressPolicyError(
                    "Web-egress redirect budget was exceeded."
                )
            redirect_count += 1
            current_url = urljoin(target.url, location)
            continue

        budget["bytes"] += len(body)
        if budget["bytes"] > policy.max_total_bytes:
            raise EgressPolicyError(
                "Web-egress total byte budget was exceeded."
            )

        content_type = headers.get("content-type", "")
        body_text, body_base64 = _decode_body(body, content_type)
        return BrokerResponse(
            request_id=request_id,
            method=method,
            url=target.url,
            status=status,
            headers=headers,
            body_text=body_text,
            body_base64=body_base64,
            size_bytes=len(body),
            body_sha256=hashlib.sha256(body).hexdigest(),
        )


def broker_web_requests(
    input_value: dict[str, object],
    *,
    policy: EgressPolicy,
    resolver=socket.getaddrinfo,
    connection_factory: ConnectionFactory = _default_connection,
) -> dict[str, object]:
    result = dict(input_value)
    raw_requests = result.pop("_rdc_web_requests", [])
    if not isinstance(raw_requests, list):
        raise EgressPolicyError("_rdc_web_requests must be a list.")
    if len(raw_requests) > policy.max_requests:
        raise EgressPolicyError(
            "Requested web fetches exceed the request budget."
        )

    budget = {"requests": 0, "bytes": 0}
    responses: list[dict[str, object]] = []
    seen_ids: set[str] = set()

    for raw in raw_requests:
        if not isinstance(raw, dict):
            raise EgressPolicyError("Each web request must be an object.")
        request_id = str(raw.get("id", ""))
        if _REQUEST_ID.fullmatch(request_id) is None:
            raise EgressPolicyError("Web request id is invalid.")
        if request_id in seen_ids:
            raise EgressPolicyError("Web request ids must be unique.")
        seen_ids.add(request_id)

        method = str(raw.get("method", "GET")).upper()
        if method not in {"GET", "HEAD"}:
            raise EgressPolicyError("Phase 1J permits GET and HEAD only.")
        url = str(raw.get("url", ""))
        if not url:
            raise EgressPolicyError("Web request URL cannot be blank.")

        response = _fetch(
            request_id=request_id,
            method=method,
            url=url,
            policy=policy,
            resolver=resolver,
            connection_factory=connection_factory,
            budget=budget,
        )
        responses.append(response.as_dict())

    result["_rdc_web_results"] = responses
    result["_rdc_web_budget"] = {
        "requests_used": budget["requests"],
        "bytes_received": budget["bytes"],
        "max_requests": policy.max_requests,
        "max_total_bytes": policy.max_total_bytes,
    }
    return result
