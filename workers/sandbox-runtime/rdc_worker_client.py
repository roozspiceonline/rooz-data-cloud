"""Reference client for the RDC internal worker protocol.

This module implements authenticated protocol calls and secret-envelope
cryptography only. It does not execute Agent code, invoke containers, or claim
work automatically.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


@dataclass(frozen=True)
class WorkerKeyPair:
    private_key: X25519PrivateKey

    @property
    def public_key_b64(self) -> str:
        value = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return base64.b64encode(value).decode("ascii")


class WorkerProtocolError(RuntimeError):
    """An internal worker-protocol request failed."""


class RdcWorkerClient:
    def __init__(self, *, base_url: str, worker_token: str) -> None:
        self._base_url = base_url.rstrip("/")
        self._worker_token = worker_token

    def _request(
        self,
        method: str,
        path: str,
        payload: dict[str, object] | None = None,
        *,
        lease_token: str | None = None,
    ) -> dict[str, Any] | None:
        data = None if payload is None else json.dumps(payload).encode()
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer " + self._worker_token,
            "User-Agent": "rdc-reference-worker/0.1",
        }
        if data is not None:
            headers["Content-Type"] = "application/json"
        if lease_token is not None:
            headers["X-RDC-Lease-Token"] = lease_token
        request = Request(
            self._base_url + path,
            data=data,
            headers=headers,
            method=method,
        )
        try:
            with urlopen(request, timeout=30) as response:
                if response.status == 204:
                    return None
                body = response.read().decode("utf-8")
                return json.loads(body)
        except HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise WorkerProtocolError(
                f"Worker protocol returned HTTP {exc.code}: {body}"
            ) from exc

    def worker(self) -> dict[str, Any]:
        response = self._request("GET", "/internal/v1/workers/me")
        if response is None:
            raise WorkerProtocolError("Worker metadata response was empty.")
        return response

    def heartbeat(
        self,
        *,
        software_version: str,
        active_lease_count: int,
        draining: bool = False,
        sandbox: dict[str, object] | None = None,
        recovery: dict[str, object] | None = None,
    ) -> dict[str, Any]:
        response = self._request(
            "POST",
            "/internal/v1/workers/me/heartbeat",
            {
                "status": "DRAINING" if draining else "ACTIVE",
                "software_version": software_version,
                "active_lease_count": active_lease_count,
                "sandbox": sandbox,
                "recovery": recovery,
                "metadata": {"reference_client": True},
            },
        )
        if response is None:
            raise WorkerProtocolError("Heartbeat response was empty.")
        return response

    def claim(
        self,
        kinds: list[str],
    ) -> dict[str, Any] | None:
        return self._request(
            "POST",
            "/internal/v1/leases/claim",
            {"kinds": kinds},
        )

    def renew(
        self,
        lease_id: str,
        lease_token: str,
        *,
        extend_seconds: int = 60,
    ) -> dict[str, Any]:
        response = self._request(
            "POST",
            f"/internal/v1/leases/{lease_id}/renew",
            {"extend_seconds": extend_seconds},
            lease_token=lease_token,
        )
        if response is None:
            raise WorkerProtocolError("Lease renewal response was empty.")
        return response

    def source_download(
        self,
        lease_id: str,
        lease_token: str,
    ) -> dict[str, Any]:
        response = self._request(
            "POST",
            f"/internal/v1/leases/{lease_id}/source-download",
            lease_token=lease_token,
        )
        if response is None:
            raise WorkerProtocolError("Source-download response was empty.")
        return response

    def status(
        self,
        lease_id: str,
        lease_token: str,
        *,
        status: str,
        message: str | None = None,
    ) -> dict[str, Any]:
        response = self._request(
            "POST",
            f"/internal/v1/leases/{lease_id}/status",
            {"status": status, "message": message},
            lease_token=lease_token,
        )
        if response is None:
            raise WorkerProtocolError("Lease status response was empty.")
        return response

    def events(
        self,
        lease_id: str,
        lease_token: str,
        events: list[dict[str, object]],
    ) -> dict[str, Any]:
        response = self._request(
            "POST",
            f"/internal/v1/leases/{lease_id}/events",
            {"events": events},
            lease_token=lease_token,
        )
        if response is None:
            raise WorkerProtocolError("Event response was empty.")
        return response

    def artifact_upload(
        self,
        lease_id: str,
        lease_token: str,
        artifact: dict[str, object],
    ) -> dict[str, Any]:
        response = self._request(
            "POST",
            f"/internal/v1/leases/{lease_id}/artifact-upload",
            artifact,
            lease_token=lease_token,
        )
        if response is None:
            raise WorkerProtocolError("Artifact-upload response was empty.")
        return response

    def artifact_download(
        self,
        lease_id: str,
        lease_token: str,
    ) -> dict[str, Any]:
        response = self._request(
            "POST",
            f"/internal/v1/leases/{lease_id}/artifact-download",
            lease_token=lease_token,
        )
        if response is None:
            raise WorkerProtocolError("Artifact-download response was empty.")
        return response


    def dataset_append(
        self,
        lease_id: str,
        lease_token: str,
        payload: dict[str, object],
    ) -> dict[str, Any]:
        response = self._request(
            "POST",
            f"/internal/v1/leases/{lease_id}/dataset-append",
            payload,
            lease_token=lease_token,
        )
        if response is None:
            raise WorkerProtocolError("Dataset-append response was empty.")
        return response

    def kv_read(
        self,
        lease_id: str,
        lease_token: str,
        payload: dict[str, object],
    ) -> dict[str, Any]:
        response = self._request(
            "POST",
            f"/internal/v1/leases/{lease_id}/kv-read",
            payload,
            lease_token=lease_token,
        )
        if response is None:
            raise WorkerProtocolError("KV-read response was empty.")
        return response

    def kv_mutate(
        self,
        lease_id: str,
        lease_token: str,
        payload: dict[str, object],
    ) -> dict[str, Any]:
        response = self._request(
            "POST",
            f"/internal/v1/leases/{lease_id}/kv-mutate",
            payload,
            lease_token=lease_token,
        )
        if response is None:
            raise WorkerProtocolError("KV-mutate response was empty.")
        return response

    def queue_claim(
        self,
        lease_id: str,
        lease_token: str,
        *,
        queue_id: str,
    ) -> dict[str, Any] | None:
        return self._request(
            "POST",
            f"/internal/v1/leases/{lease_id}/queue-claim",
            {"queue_id": queue_id},
            lease_token=lease_token,
        )

    def queue_complete(
        self,
        lease_id: str,
        lease_token: str,
        payload: dict[str, object],
    ) -> dict[str, Any]:
        response = self._request(
            "POST",
            f"/internal/v1/leases/{lease_id}/queue-complete",
            payload,
            lease_token=lease_token,
        )
        if response is None:
            raise WorkerProtocolError("Queue-complete response was empty.")
        return response

    def complete(
        self,
        lease_id: str,
        lease_token: str,
        payload: dict[str, object],
    ) -> dict[str, Any]:
        response = self._request(
            "POST",
            f"/internal/v1/leases/{lease_id}/complete",
            payload,
            lease_token=lease_token,
        )
        if response is None:
            raise WorkerProtocolError("Lease completion response was empty.")
        return response

    def request_secret_envelope(
        self,
        lease_id: str,
        lease_token: str,
        *,
        names: list[str],
        environment: str,
        key_pair: WorkerKeyPair,
    ) -> dict[str, Any]:
        response = self._request(
            "POST",
            f"/internal/v1/leases/{lease_id}/secret-envelope",
            {
                "names": names,
                "environment": environment,
                "worker_public_key_b64": key_pair.public_key_b64,
            },
            lease_token=lease_token,
        )
        if response is None:
            raise WorkerProtocolError("Secret-envelope response was empty.")
        return response

    def request_egress_credential_envelope(
        self,
        lease_id: str,
        lease_token: str,
        *,
        policy_binding_digest: str,
        key_pair: WorkerKeyPair,
    ) -> dict[str, Any]:
        response = self._request(
            "POST",
            f"/internal/v1/leases/{lease_id}/egress-credential-envelope",
            {
                "policy_binding_digest": policy_binding_digest,
                "worker_public_key_b64": key_pair.public_key_b64,
            },
            lease_token=lease_token,
        )
        if response is None:
            raise WorkerProtocolError("Egress credential-envelope response was empty.")
        return response


def generate_worker_key_pair() -> WorkerKeyPair:
    return WorkerKeyPair(private_key=X25519PrivateKey.generate())


def decrypt_secret_envelope(
    envelope: dict[str, Any],
    *,
    key_pair: WorkerKeyPair,
    lease_id: str,
    worker_id: str,
    run_id: str,
) -> dict[str, object]:
    data = envelope["data"]
    if data["algorithm"] != "X25519-HKDF-SHA256-AES-256-GCM":
        raise WorkerProtocolError("Unsupported secret-envelope algorithm.")
    peer = X25519PublicKey.from_public_bytes(
        base64.b64decode(data["ephemeral_public_key_b64"], validate=True)
    )
    shared_secret = key_pair.private_key.exchange(peer)
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"rdc/execution-secret-envelope/v1",
    ).derive(shared_secret)
    aad = (
        f"rdc/worker-secret-envelope/v1:{lease_id}:{worker_id}:{run_id}"
    ).encode()
    plaintext = AESGCM(key).decrypt(
        base64.b64decode(data["nonce_b64"], validate=True),
        base64.b64decode(data["ciphertext_b64"], validate=True),
        aad,
    )
    try:
        result = json.loads(plaintext)
    finally:
        mutable = bytearray(plaintext)
        for index in range(len(mutable)):
            mutable[index] = 0
    if not isinstance(result, dict):
        raise WorkerProtocolError("Secret-envelope payload was invalid.")
    return result


def decrypt_egress_credential_envelope(
    envelope: dict[str, Any],
    *,
    key_pair: WorkerKeyPair,
    lease_id: str,
    worker_id: str,
    run_id: str,
    policy_binding_digest: str,
) -> str:
    data = envelope["data"]
    if (
        data["algorithm"] != "X25519-HKDF-SHA256-AES-256-GCM"
        or data.get("policy_binding_digest") != policy_binding_digest
    ):
        raise WorkerProtocolError("Egress credential-envelope binding is invalid.")
    peer = X25519PublicKey.from_public_bytes(
        base64.b64decode(data["ephemeral_public_key_b64"], validate=True)
    )
    shared_secret = key_pair.private_key.exchange(peer)
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"rdc/execution-secret-envelope/v1",
    ).derive(shared_secret)
    aad = (
        "rdc/worker-egress-credential-envelope/v1:"
        f"{lease_id}:{worker_id}:{run_id}:{policy_binding_digest}"
    ).encode()
    plaintext = AESGCM(key).decrypt(
        base64.b64decode(data["nonce_b64"], validate=True),
        base64.b64decode(data["ciphertext_b64"], validate=True),
        aad,
    )
    try:
        result = json.loads(plaintext)
    finally:
        mutable = bytearray(plaintext)
        for index in range(len(mutable)):
            mutable[index] = 0
    expected = {
        "schema_version": "rdc.egress-credential/v1",
        "lease_id": lease_id,
        "run_id": run_id,
        "policy_binding_digest": policy_binding_digest,
    }
    if (
        not isinstance(result, dict)
        or any(result.get(key) != value for key, value in expected.items())
        or set(result) != {*expected, "authorization", "expires_at"}
        or not isinstance(result.get("authorization"), str)
        or not result["authorization"]
        or len(result["authorization"]) > 8192
        or "\r" in result["authorization"]
        or "\n" in result["authorization"]
    ):
        raise WorkerProtocolError("Egress credential-envelope payload was invalid.")
    try:
        envelope_expiry = datetime.fromisoformat(str(result["expires_at"]))
        response_expiry = datetime.fromisoformat(str(data["expires_at"]))
    except (KeyError, ValueError) as exc:
        raise WorkerProtocolError(
            "Egress credential-envelope expiry was invalid."
        ) from exc
    if (
        envelope_expiry.tzinfo is None
        or envelope_expiry != response_expiry
        or envelope_expiry <= datetime.now(UTC)
    ):
        raise WorkerProtocolError("Egress credential-envelope expired.")
    return str(result["authorization"])
