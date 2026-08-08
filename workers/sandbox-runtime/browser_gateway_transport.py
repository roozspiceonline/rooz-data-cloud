from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import socket
import threading
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urljoin

from browser_egress_policy import BrowserEgressPolicy, BrowserEgressPolicyError
from egress_broker import ConnectionFactory, _default_connection, _request_once
from egress_policy import EgressPolicyError, Resolver

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_NONCE = re.compile(r"^[0-9a-f]{32}$")
_REQUEST_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_MAX_SELF_TEST_MESSAGE_BYTES = 4_096
_MAX_LIVE_REQUEST_BYTES = 16_384
_MAX_LIVE_RESPONSE_BYTES = 11_300_000
_REDIRECT_STATUSES = {301, 302, 303, 307, 308}


class BrowserGatewayTransportError(RuntimeError):
    pass


def _decode_message(raw: bytes, *, maximum: int) -> dict[str, object]:
    if not raw or len(raw) > maximum:
        raise BrowserGatewayTransportError(
            "Browser gateway transport message is outside the safe size limit."
        )
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BrowserGatewayTransportError(
            "Browser gateway transport message is invalid JSON."
        ) from exc
    if not isinstance(value, dict):
        raise BrowserGatewayTransportError(
            "Browser gateway transport message must be an object."
        )
    return {str(key): item for key, item in value.items()}


def _encode_message(value: dict[str, object], *, maximum: int) -> bytes:
    encoded = (
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
        + b"\n"
    )
    if len(encoded) > maximum:
        raise BrowserGatewayTransportError(
            "Browser gateway transport response exceeded the safe size limit."
        )
    return encoded


def _read_line(connection: socket.socket, *, maximum: int) -> bytes:
    raw = bytearray()
    while b"\n" not in raw:
        chunk = connection.recv(min(65_536, maximum + 1))
        if not chunk:
            break
        raw.extend(chunk)
        if len(raw) > maximum:
            raise BrowserGatewayTransportError(
                "Browser gateway transport message exceeded the safe size limit."
            )
    return bytes(raw).split(b"\n", 1)[0]


def validate_gateway_ping(
    value: object,
    *,
    gateway_policy_digest: str,
) -> dict[str, object]:
    if _DIGEST.fullmatch(gateway_policy_digest) is None:
        raise BrowserGatewayTransportError("Browser gateway policy digest is invalid.")
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "nonce",
        "gateway_policy_digest",
    }:
        raise BrowserGatewayTransportError("Browser gateway ping fields are invalid.")
    if value.get("schema_version") != "rdc.browser-gateway-ping/v1":
        raise BrowserGatewayTransportError("Browser gateway ping version is unsupported.")
    nonce = value.get("nonce")
    if not isinstance(nonce, str) or _NONCE.fullmatch(nonce) is None:
        raise BrowserGatewayTransportError("Browser gateway ping nonce is invalid.")
    if value.get("gateway_policy_digest") != gateway_policy_digest:
        raise BrowserGatewayTransportError(
            "Browser gateway ping policy digest does not match the Run receipt."
        )
    return {
        "schema_version": "rdc.browser-gateway-pong/v1",
        "nonce": nonce,
        "gateway_policy_digest": gateway_policy_digest,
        "transport": "unix",
        "policy_enforced": True,
        "external_request": False,
        "live_forwarding": False,
    }


def _validate_live_request(
    value: object,
    *,
    gateway_policy_digest: str,
) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "request_id",
        "gateway_policy_digest",
        "resource_type",
        "method",
        "url",
    }:
        raise BrowserGatewayTransportError("Browser gateway request fields are invalid.")
    if value.get("schema_version") != "rdc.browser-gateway-request/v1":
        raise BrowserGatewayTransportError("Browser gateway request version is unsupported.")
    request_id = value.get("request_id")
    if not isinstance(request_id, str) or _REQUEST_ID.fullmatch(request_id) is None:
        raise BrowserGatewayTransportError("Browser gateway request id is invalid.")
    if value.get("gateway_policy_digest") != gateway_policy_digest:
        raise BrowserGatewayTransportError(
            "Browser gateway request policy digest does not match the Run."
        )
    resource_type = value.get("resource_type")
    method = value.get("method")
    url = value.get("url")
    if not all(isinstance(item, str) for item in (resource_type, method, url)):
        raise BrowserGatewayTransportError(
            "Browser gateway request fields must be strings."
        )
    if len(url) > 8192:
        raise BrowserGatewayTransportError("Browser gateway request URL is too long.")
    return {
        "request_id": request_id,
        "resource_type": resource_type,
        "method": method,
        "url": url,
    }


@dataclass
class BrowserGatewayBudget:
    requests_used: int = 0
    bytes_received: int = 0
    redirects_used: int = 0

    def as_dict(self, *, policy: BrowserEgressPolicy) -> dict[str, int]:
        return {
            "requests_used": self.requests_used,
            "bytes_received": self.bytes_received,
            "redirects_used": self.redirects_used,
            "max_requests": policy.base.max_requests,
            "max_total_bytes": policy.base.max_total_bytes,
            "max_redirects": policy.base.max_redirects,
        }


class BrowserGatewayBroker:
    def __init__(
        self,
        *,
        policy: BrowserEgressPolicy,
        gateway_policy_digest: str,
        live_forwarding_enabled: bool,
        resolver: Resolver | None = None,
        connection_factory: ConnectionFactory = _default_connection,
    ) -> None:
        if _DIGEST.fullmatch(gateway_policy_digest) is None:
            raise BrowserGatewayTransportError("Browser gateway policy digest is invalid.")
        if gateway_policy_digest != policy.digest:
            raise BrowserGatewayTransportError(
                "Browser gateway policy digest does not match policy."
            )
        self.policy = policy
        self.gateway_policy_digest = gateway_policy_digest
        self.live_forwarding_enabled = live_forwarding_enabled
        self.resolver = resolver
        self.connection_factory = connection_factory
        self.budget = BrowserGatewayBudget()

    def handle_request(self, value: object) -> dict[str, object]:
        if not self.live_forwarding_enabled:
            raise BrowserGatewayTransportError(
                "Browser gateway live forwarding is disabled."
            )
        request = _validate_live_request(
            value,
            gateway_policy_digest=self.gateway_policy_digest,
        )
        if self.budget.requests_used >= self.policy.base.max_requests:
            raise BrowserGatewayTransportError(
                "Browser gateway request budget was exceeded."
            )
        try:
            if self.resolver is None:
                validated = self.policy.validate_resource(
                    resource_type=request["resource_type"],
                    method=request["method"],
                    url=request["url"],
                )
            else:
                validated = self.policy.validate_resource(
                    resource_type=request["resource_type"],
                    method=request["method"],
                    url=request["url"],
                    resolver=self.resolver,
                )
        except BrowserEgressPolicyError as exc:
            raise BrowserGatewayTransportError(
                "Browser gateway request was denied by policy."
            ) from exc

        self.budget.requests_used += 1
        try:
            status, headers, body, location = _request_once(
                target=validated.target,
                method=validated.method,
                policy=self.policy.base,
                connection_factory=self.connection_factory,
            )
        except EgressPolicyError as exc:
            raise BrowserGatewayTransportError(
                "Browser gateway HTTPS request failed within policy."
            ) from exc

        safe_headers = {
            key: item
            for key, item in headers.items()
            if key not in {"content-length", "set-cookie", "location"}
        }

        redirect_url: str | None = None
        if status in _REDIRECT_STATUSES:
            if not location:
                raise BrowserGatewayTransportError(
                    "Browser gateway redirect lacks Location."
                )
            if self.budget.redirects_used >= self.policy.base.max_redirects:
                raise BrowserGatewayTransportError(
                    "Browser gateway redirect budget was exceeded."
                )
            candidate = urljoin(validated.target.url, location)
            try:
                if self.resolver is None:
                    redirect = self.policy.validate_redirect(
                        resource_type=validated.resource_type,
                        method=validated.method,
                        url=candidate,
                    )
                else:
                    redirect = self.policy.validate_redirect(
                        resource_type=validated.resource_type,
                        method=validated.method,
                        url=candidate,
                        resolver=self.resolver,
                    )
            except BrowserEgressPolicyError as exc:
                raise BrowserGatewayTransportError(
                    "Browser gateway redirect target was denied."
                ) from exc
            self.budget.redirects_used += 1
            redirect_url = redirect.target.url
            body = b""
        else:
            self.budget.bytes_received += len(body)
            if self.budget.bytes_received > self.policy.base.max_total_bytes:
                raise BrowserGatewayTransportError(
                    "Browser gateway total byte budget was exceeded."
                )

        return {
            "schema_version": "rdc.browser-gateway-response/v1",
            "request_id": request["request_id"],
            "gateway_policy_digest": self.gateway_policy_digest,
            "status": status,
            "headers": safe_headers,
            "redirect_url": redirect_url,
            "body_base64": base64.b64encode(body).decode("ascii"),
            "size_bytes": len(body),
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "budget": self.budget.as_dict(policy=self.policy),
        }


class BrowserGatewaySelfTestServer:
    def __init__(self, *, socket_path: Path, gateway_policy_digest: str) -> None:
        if _DIGEST.fullmatch(gateway_policy_digest) is None:
            raise BrowserGatewayTransportError("Browser gateway policy digest is invalid.")
        self.socket_path = socket_path
        self.gateway_policy_digest = gateway_policy_digest
        self._server: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._error: BaseException | None = None

    def start(self) -> None:
        if self._server is not None:
            raise BrowserGatewayTransportError(
                "Browser gateway self-test server is already started."
            )
        parent = self.socket_path.parent
        parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        os.chmod(parent, 0o755)
        if self.socket_path.exists():
            raise BrowserGatewayTransportError("Browser gateway IPC socket already exists.")
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            server.settimeout(5.0)
            server.bind(str(self.socket_path))
            os.chmod(self.socket_path, 0o666)
            server.listen(1)
        except BaseException:
            server.close()
            self.socket_path.unlink(missing_ok=True)
            raise
        self._server = server
        self._thread = threading.Thread(
            target=self._serve_once,
            name="rdc-browser-gateway-self-test",
            daemon=True,
        )
        self._thread.start()

    def _serve_once(self) -> None:
        server = self._server
        if server is None:
            self._error = BrowserGatewayTransportError(
                "Browser gateway self-test server is unavailable."
            )
            return
        try:
            connection, _ = server.accept()
            with connection:
                connection.settimeout(3.0)
                request = _decode_message(
                    _read_line(connection, maximum=_MAX_SELF_TEST_MESSAGE_BYTES),
                    maximum=_MAX_SELF_TEST_MESSAGE_BYTES,
                )
                response = validate_gateway_ping(
                    request,
                    gateway_policy_digest=self.gateway_policy_digest,
                )
                connection.sendall(
                    _encode_message(
                        response,
                        maximum=_MAX_SELF_TEST_MESSAGE_BYTES,
                    )
                )
        except BaseException as exc:
            self._error = exc
        finally:
            server.close()
            self._server = None
            self.socket_path.unlink(missing_ok=True)

    def wait(self, *, timeout_seconds: float = 6.0) -> None:
        thread = self._thread
        if thread is None:
            raise BrowserGatewayTransportError(
                "Browser gateway self-test server was not started."
            )
        thread.join(timeout_seconds)
        if thread.is_alive():
            self.close()
            raise BrowserGatewayTransportError(
                "Browser gateway self-test transport timed out."
            )
        if self._error is not None:
            error = self._error
            self._error = None
            if isinstance(error, BrowserGatewayTransportError):
                raise error
            raise BrowserGatewayTransportError(
                "Browser gateway self-test transport failed."
            ) from error

    def close(self) -> None:
        server = self._server
        self._server = None
        if server is not None:
            try:
                server.close()
            except OSError:
                pass
        self.socket_path.unlink(missing_ok=True)

    def __enter__(self) -> "BrowserGatewaySelfTestServer":
        self.start()
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()


class BrowserGatewayLiveServer:
    def __init__(self, *, socket_path: Path, broker: BrowserGatewayBroker) -> None:
        if not broker.live_forwarding_enabled:
            raise BrowserGatewayTransportError(
                "Live server requires explicit forwarding enablement."
            )
        self.socket_path = socket_path
        self.broker = broker
        self._server: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._error: BaseException | None = None
        self._connections = 0
        self._max_connections = broker.policy.base.max_requests + 4

    def start(self) -> None:
        if self._server is not None:
            raise BrowserGatewayTransportError(
                "Browser gateway live server is already started."
            )
        parent = self.socket_path.parent
        parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        os.chmod(parent, 0o755)
        if self.socket_path.exists():
            raise BrowserGatewayTransportError("Browser gateway IPC socket already exists.")
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            server.settimeout(0.25)
            server.bind(str(self.socket_path))
            os.chmod(self.socket_path, 0o666)
            server.listen(4)
        except BaseException:
            server.close()
            self.socket_path.unlink(missing_ok=True)
            raise
        self._server = server
        self._thread = threading.Thread(
            target=self._serve_loop,
            name="rdc-browser-gateway-live",
            daemon=True,
        )
        self._thread.start()

    def _error_payload(self, *, request_id: str | None) -> dict[str, object]:
        return {
            "schema_version": "rdc.browser-gateway-error/v1",
            "request_id": request_id,
            "gateway_policy_digest": self.broker.gateway_policy_digest,
            "error_code": "BROWSER_GATEWAY_POLICY_DENIED",
        }

    def _serve_connection(self, connection: socket.socket) -> None:
        request_id: str | None = None
        try:
            request = _decode_message(
                _read_line(connection, maximum=_MAX_LIVE_REQUEST_BYTES),
                maximum=_MAX_LIVE_REQUEST_BYTES,
            )
            raw_id = request.get("request_id")
            if isinstance(raw_id, str):
                request_id = raw_id[:64]
            response = self.broker.handle_request(request)
        except BrowserGatewayTransportError:
            response = self._error_payload(request_id=request_id)
        connection.sendall(
            _encode_message(response, maximum=_MAX_LIVE_RESPONSE_BYTES)
        )

    def _serve_loop(self) -> None:
        server = self._server
        if server is None:
            self._error = BrowserGatewayTransportError(
                "Browser gateway live server is unavailable."
            )
            return
        try:
            while not self._stop.is_set():
                try:
                    connection, _ = server.accept()
                except TimeoutError:
                    continue
                except OSError:
                    if self._stop.is_set():
                        break
                    raise
                self._connections += 1
                if self._connections > self._max_connections:
                    connection.close()
                    raise BrowserGatewayTransportError(
                        "Browser gateway connection budget was exceeded."
                    )
                with connection:
                    connection.settimeout(
                        self.broker.policy.base.request_timeout_seconds
                    )
                    self._serve_connection(connection)
        except BaseException as exc:
            self._error = exc
        finally:
            try:
                server.close()
            except OSError:
                pass
            self._server = None
            self.socket_path.unlink(missing_ok=True)

    def stop(self) -> None:
        self._stop.set()
        server = self._server
        if server is not None:
            try:
                server.close()
            except OSError:
                pass
        thread = self._thread
        if thread is not None:
            thread.join(2.0)
        self.socket_path.unlink(missing_ok=True)

    def raise_if_failed(self) -> None:
        if self._error is None:
            return
        error = self._error
        self._error = None
        if isinstance(error, BrowserGatewayTransportError):
            raise error
        raise BrowserGatewayTransportError("Browser gateway live server failed.") from error

    def __enter__(self) -> "BrowserGatewayLiveServer":
        self.start()
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.stop()
