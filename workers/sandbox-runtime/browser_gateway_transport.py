from __future__ import annotations

import json
import os
import re
import socket
import threading
from pathlib import Path

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_NONCE = re.compile(r"^[0-9a-f]{32}$")
_MAX_MESSAGE_BYTES = 4_096


class BrowserGatewayTransportError(RuntimeError):
    pass


def _decode_message(raw: bytes) -> dict[str, object]:
    if not raw or len(raw) > _MAX_MESSAGE_BYTES:
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


def validate_gateway_ping(
    value: object,
    *,
    gateway_policy_digest: str,
) -> dict[str, object]:
    if _DIGEST.fullmatch(gateway_policy_digest) is None:
        raise BrowserGatewayTransportError(
            "Browser gateway policy digest is invalid."
        )
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "nonce",
        "gateway_policy_digest",
    }:
        raise BrowserGatewayTransportError(
            "Browser gateway ping fields are invalid."
        )
    if value.get("schema_version") != "rdc.browser-gateway-ping/v1":
        raise BrowserGatewayTransportError(
            "Browser gateway ping version is unsupported."
        )
    nonce = value.get("nonce")
    if not isinstance(nonce, str) or _NONCE.fullmatch(nonce) is None:
        raise BrowserGatewayTransportError(
            "Browser gateway ping nonce is invalid."
        )
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


class BrowserGatewaySelfTestServer:
    def __init__(
        self,
        *,
        socket_path: Path,
        gateway_policy_digest: str,
    ) -> None:
        if _DIGEST.fullmatch(gateway_policy_digest) is None:
            raise BrowserGatewayTransportError(
                "Browser gateway policy digest is invalid."
            )
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
        try:
            os.chmod(parent, 0o755)
        except OSError as exc:
            raise BrowserGatewayTransportError(
                "Browser gateway IPC directory permissions could not be set."
            ) from exc
        if self.socket_path.exists():
            raise BrowserGatewayTransportError(
                "Browser gateway IPC socket already exists."
            )

        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            server.settimeout(5.0)
            server.bind(str(self.socket_path))
            os.chmod(self.socket_path, 0o666)
            server.listen(1)
        except BaseException:
            server.close()
            try:
                self.socket_path.unlink(missing_ok=True)
            except OSError:
                pass
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
                raw = bytearray()
                while b"\n" not in raw:
                    chunk = connection.recv(1024)
                    if not chunk:
                        break
                    raw.extend(chunk)
                    if len(raw) > _MAX_MESSAGE_BYTES:
                        raise BrowserGatewayTransportError(
                            "Browser gateway ping exceeded the safe size limit."
                        )
                line = bytes(raw).split(b"\n", 1)[0]
                request = _decode_message(line)
                response = validate_gateway_ping(
                    request,
                    gateway_policy_digest=self.gateway_policy_digest,
                )
                encoded = (
                    json.dumps(
                        response,
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode("utf-8")
                    + b"\n"
                )
                connection.sendall(encoded)
        except BaseException as exc:
            self._error = exc
        finally:
            server.close()
            self._server = None
            try:
                self.socket_path.unlink(missing_ok=True)
            except OSError:
                pass

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
        try:
            self.socket_path.unlink(missing_ok=True)
        except OSError:
            pass

    def __enter__(self) -> "BrowserGatewaySelfTestServer":
        self.start()
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()
