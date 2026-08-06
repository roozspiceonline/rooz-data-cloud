import base64
import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerifyMismatchError

_PASSWORD_HASHER = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16,
    type=Type.ID,
)


def hash_password(password: str) -> str:
    return _PASSWORD_HASHER.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _PASSWORD_HASHER.verify(password_hash, password)
    except (VerifyMismatchError, InvalidHashError):
        return False


def needs_password_rehash(password_hash: str) -> bool:
    try:
        return _PASSWORD_HASHER.check_needs_rehash(password_hash)
    except InvalidHashError:
        return True


def secret_digest(value: str, pepper: str) -> bytes:
    return hmac.new(
        pepper.encode(),
        value.encode(),
        hashlib.sha256,
    ).digest()


def new_session_token() -> str:
    return secrets.token_urlsafe(32)


def derive_csrf_token(
    *,
    session_id: UUID,
    session_token_digest: bytes,
    pepper: str,
) -> str:
    material = session_id.bytes + session_token_digest
    digest = hmac.new(
        pepper.encode(),
        material,
        hashlib.sha256,
    ).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def verify_csrf_token(
    *,
    supplied_token: str,
    session_id: UUID,
    session_token_digest: bytes,
    expected_digest: bytes,
    pepper: str,
) -> bool:
    expected_token = derive_csrf_token(
        session_id=session_id,
        session_token_digest=session_token_digest,
        pepper=pepper,
    )
    if not hmac.compare_digest(supplied_token, expected_token):
        return False
    return hmac.compare_digest(
        secret_digest(supplied_token, pepper),
        expected_digest,
    )


def canonical_fingerprint(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class IssuedApiKey:
    raw_token: str
    public_prefix: str
    last_four: str


def derive_api_key(
    *,
    environment: str,
    organization_id: UUID,
    principal_id: UUID,
    idempotency_key: str,
    issuance_secret: str,
) -> IssuedApiKey:
    scope = (
        f"{environment}:{organization_id}:{principal_id}:{idempotency_key}"
    ).encode()
    prefix_digest = hmac.new(
        issuance_secret.encode(),
        b"prefix:" + scope,
        hashlib.sha256,
    ).digest()
    secret_digest_bytes = hmac.new(
        issuance_secret.encode(),
        b"secret:" + scope,
        hashlib.sha256,
    ).digest()
    public_prefix = (
        base64.b32encode(prefix_digest[:5]).decode("ascii").lower().rstrip("=")
    )
    secret_part = (
        base64.urlsafe_b64encode(secret_digest_bytes)
        .decode("ascii")
        .rstrip("=")
    )
    raw_token = f"rdc_{environment}_{public_prefix}_{secret_part}"
    return IssuedApiKey(
        raw_token=raw_token,
        public_prefix=public_prefix,
        last_four=secret_part[-4:],
    )


def is_expired(value: datetime | None, *, now: datetime) -> bool:
    return value is not None and value <= now
