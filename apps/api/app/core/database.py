from collections.abc import AsyncIterator
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from .config import get_settings

engine: AsyncEngine = create_async_engine(
    get_settings().database_url,
    pool_pre_ping=True,
)
session_factory = async_sessionmaker(
    engine,
    expire_on_commit=False,
    class_=AsyncSession,
)


async def get_db() -> AsyncIterator[AsyncSession]:
    async with session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def set_identity_context(session: AsyncSession, user_id: UUID) -> None:
    await session.execute(
        text("SELECT set_config('rdc.current_user_id', :value, true)"),
        {"value": str(user_id)},
    )


async def set_tenant_context(
    session: AsyncSession,
    *,
    user_id: UUID,
    organization_id: UUID,
) -> None:
    await set_identity_context(session, user_id)
    await session.execute(
        text("SELECT set_config('rdc.current_organization_id', :value, true)"),
        {"value": str(organization_id)},
    )


async def set_worker_context(session: AsyncSession, worker_id: UUID) -> None:
    await session.execute(
        text("SELECT set_config('rdc.current_worker_id', :value, true)"),
        {"value": str(worker_id)},
    )


async def set_api_key_lookup_context(
    session: AsyncSession,
    token_digest_hex: str,
) -> None:
    await session.execute(
        text(
            "SELECT set_config("
            "'rdc.current_api_key_digest', :value, true"
            ")"
        ),
        {"value": token_digest_hex},
    )


async def check_database() -> None:
    async with engine.connect() as connection:
        await connection.exec_driver_sql("SELECT 1")
