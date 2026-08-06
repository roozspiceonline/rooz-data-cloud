from redis.asyncio import Redis

from .config import get_settings

redis_client = Redis.from_url(get_settings().redis_url, decode_responses=True)


async def check_redis() -> None:
    response = await redis_client.ping()
    if response is not True:
        raise RuntimeError("Redis ping did not return PONG")
