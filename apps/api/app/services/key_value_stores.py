from uuid import UUID

from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.errors import ApiError
from ..core.pagination import CursorPosition
from ..kv_schemas import CreateKeyValueStoreRequest, KeyValueStoreSummary
from ..models import KeyValueStore, Project, Run
from .identity_tenancy import append_audit_event


def key_value_store_summary(record: KeyValueStore) -> KeyValueStoreSummary:
    return KeyValueStoreSummary.model_validate(record)


async def _ensure_store_name_available(
    session: AsyncSession,
    *,
    scope: str,
    project_id: UUID,
    run_id: UUID | None,
    name: str,
) -> None:
    statement = select(KeyValueStore).where(
        KeyValueStore.scope == scope,
        KeyValueStore.name == name,
    )
    if scope == "PROJECT":
        statement = statement.where(KeyValueStore.project_id == project_id)
    else:
        statement = statement.where(KeyValueStore.run_id == run_id)

    if await session.scalar(statement) is not None:
        raise ApiError(
            status_code=409,
            code="KEY_VALUE_STORE_ALREADY_EXISTS",
            message="A Key-Value Store with that name already exists.",
        )


async def create_project_key_value_store(
    session: AsyncSession,
    *,
    project: Project,
    user_id: UUID,
    actor_type: str,
    actor_id: str,
    request_id: str,
    payload: CreateKeyValueStoreRequest,
) -> KeyValueStore:
    await _ensure_store_name_available(
        session,
        scope="PROJECT",
        project_id=project.id,
        run_id=None,
        name=payload.name,
    )
    record = KeyValueStore(
        organization_id=project.organization_id,
        project_id=project.id,
        scope="PROJECT",
        run_id=None,
        agent_id=None,
        agent_version_id=None,
        name=payload.name,
        record_count=0,
        total_bytes=0,
        created_by_user_id=user_id,
        version=1,
    )
    session.add(record)
    await session.flush()

    await append_audit_event(
        session,
        organization_id=project.organization_id,
        project_id=project.id,
        actor_type=actor_type,
        actor_id=actor_id,
        action="kv_store.created",
        resource_type="key_value_store",
        resource_id=str(record.id),
        request_id=request_id,
        details={"scope": "PROJECT", "name": record.name},
    )
    return record


async def create_run_key_value_store(
    session: AsyncSession,
    *,
    run: Run,
    user_id: UUID,
    actor_type: str,
    actor_id: str,
    request_id: str,
    payload: CreateKeyValueStoreRequest,
) -> KeyValueStore:
    await _ensure_store_name_available(
        session,
        scope="RUN",
        project_id=run.project_id,
        run_id=run.id,
        name=payload.name,
    )
    record = KeyValueStore(
        organization_id=run.organization_id,
        project_id=run.project_id,
        scope="RUN",
        run_id=run.id,
        agent_id=run.agent_id,
        agent_version_id=run.agent_version_id,
        name=payload.name,
        record_count=0,
        total_bytes=0,
        created_by_user_id=user_id,
        version=1,
    )
    session.add(record)
    await session.flush()

    await append_audit_event(
        session,
        organization_id=run.organization_id,
        project_id=run.project_id,
        actor_type=actor_type,
        actor_id=actor_id,
        action="kv_store.created",
        resource_type="key_value_store",
        resource_id=str(record.id),
        request_id=request_id,
        details={
            "scope": "RUN",
            "run_id": str(run.id),
            "agent_id": str(run.agent_id),
            "agent_version_id": str(run.agent_version_id),
            "name": record.name,
        },
    )
    return record


async def list_key_value_stores(
    session: AsyncSession,
    *,
    project_id: UUID,
    cursor: CursorPosition | None,
    limit: int,
) -> tuple[list[KeyValueStore], bool]:
    statement = select(KeyValueStore).where(
        KeyValueStore.project_id == project_id
    )
    if cursor is not None:
        statement = statement.where(
            or_(
                KeyValueStore.created_at < cursor.created_at,
                and_(
                    KeyValueStore.created_at == cursor.created_at,
                    KeyValueStore.id < cursor.resource_id,
                ),
            )
        )
    rows = list(
        (
            await session.scalars(
                statement.order_by(
                    KeyValueStore.created_at.desc(),
                    KeyValueStore.id.desc(),
                ).limit(limit + 1)
            )
        ).all()
    )
    return rows[:limit], len(rows) > limit
