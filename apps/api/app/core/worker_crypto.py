import base64
import hashlib
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


@dataclass(frozen=True)
class WorkerSecretEnvelope:
    algorithm: str
    ephemeral_public_key: bytes
    nonce: bytes
    ciphertext: bytes
    worker_public_key_digest: str


def decode_worker_public_key(value: str) -> bytes:
    try:
        raw = base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise ValueError("Worker public key must be valid base64.") from exc
    if len(raw) != 32:
        raise ValueError("Worker public key must decode to 32 bytes.")
    return raw


def worker_secret_aad(*, lease_id: str, worker_id: str, run_id: str) -> bytes:
    return f"rdc/worker-secret-envelope/v1:{lease_id}:{worker_id}:{run_id}".encode()


def encrypt_secret_payload_for_worker(
    plaintext: bytes,
    *,
    worker_public_key: bytes,
    aad: bytes,
) -> WorkerSecretEnvelope:
    peer = X25519PublicKey.from_public_bytes(worker_public_key)
    ephemeral_private = X25519PrivateKey.generate()
    shared_secret = ephemeral_private.exchange(peer)
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"rdc/execution-secret-envelope/v1",
    ).derive(shared_secret)
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
    ephemeral_public_key = ephemeral_private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return WorkerSecretEnvelope(
        algorithm="X25519-HKDF-SHA256-AES-256-GCM",
        ephemeral_public_key=ephemeral_public_key,
        nonce=nonce,
        ciphertext=ciphertext,
        worker_public_key_digest=hashlib.sha256(worker_public_key).hexdigest(),
    )
