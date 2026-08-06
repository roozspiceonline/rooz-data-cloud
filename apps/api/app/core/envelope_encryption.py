import base64
import os
from dataclasses import dataclass
from uuid import UUID

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .config import get_settings


@dataclass(frozen=True)
class EncryptedSecretValue:
    ciphertext: bytes
    value_nonce: bytes
    wrapped_data_key: bytes
    key_nonce: bytes
    algorithm: str
    master_key_version: str


def _master_key() -> bytes:
    value = get_settings().project_secret_master_key_b64
    return base64.b64decode(value, validate=True)


def secret_aad(
    *,
    organization_id: UUID,
    project_id: UUID,
    secret_id: UUID,
    name: str,
    version: int,
) -> bytes:
    return (
        "rdc/project-secret/v1:"
        f"{organization_id}:{project_id}:{secret_id}:{name}:{version}"
    ).encode()


def encrypt_project_secret(
    plaintext: str,
    *,
    organization_id: UUID,
    project_id: UUID,
    secret_id: UUID,
    name: str,
    version: int,
) -> EncryptedSecretValue:
    settings = get_settings()
    data_key = AESGCM.generate_key(bit_length=256)
    value_nonce = os.urandom(12)
    key_nonce = os.urandom(12)
    aad = secret_aad(
        organization_id=organization_id,
        project_id=project_id,
        secret_id=secret_id,
        name=name,
        version=version,
    )
    ciphertext = AESGCM(data_key).encrypt(
        value_nonce,
        plaintext.encode(),
        aad,
    )
    wrapped_data_key = AESGCM(_master_key()).encrypt(
        key_nonce,
        data_key,
        aad,
    )
    return EncryptedSecretValue(
        ciphertext=ciphertext,
        value_nonce=value_nonce,
        wrapped_data_key=wrapped_data_key,
        key_nonce=key_nonce,
        algorithm="AES-256-GCM",
        master_key_version=settings.project_secret_master_key_version,
    )


def decrypt_project_secret(
    *,
    ciphertext: bytes,
    value_nonce: bytes,
    wrapped_data_key: bytes,
    key_nonce: bytes,
    organization_id: UUID,
    project_id: UUID,
    secret_id: UUID,
    name: str,
    version: int,
) -> bytes:
    aad = secret_aad(
        organization_id=organization_id,
        project_id=project_id,
        secret_id=secret_id,
        name=name,
        version=version,
    )
    data_key = AESGCM(_master_key()).decrypt(
        key_nonce,
        wrapped_data_key,
        aad,
    )
    return AESGCM(data_key).decrypt(value_nonce, ciphertext, aad)
