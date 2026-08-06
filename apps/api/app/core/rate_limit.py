import hashlib
import hmac

from redis.asyncio import Redis

from .config import get_settings
from .errors import ApiError

settings = get_settings()
redis_client = Redis.from_url(settings.redis_url, decode_responses=True)


def privacy_preserving_rate_key(kind: str, value: str) -> str:
    digest = hmac.new(
        settings.rate_limit_key.encode("utf-8"),
        value.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"rdc:auth-rate:{kind}:{digest}"


async def enforce_auth_rate_limit(kind: str, value: str) -> None:
    key = privacy_preserving_rate_key(kind, value)
    try:
        count = await redis_client.incr(key)
        if count == 1:
            await redis_client.expire(
                key,
                settings.auth_rate_limit_window_seconds,
            )
    except Exception as exc:
        if settings.env in {"staging", "production"}:
            raise ApiError(
                status_code=503,
                code="SERVICE_UNAVAILABLE",
                message="Authentication is temporarily unavailable.",
            ) from exc
        return

    if int(count) > settings.auth_rate_limit_requests:
        raise ApiError(
            status_code=429,
            code="RATE_LIMITED",
            message="Too many authentication attempts. Try again later.",
        )
