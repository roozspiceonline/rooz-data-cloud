from uuid import UUID

from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.errors import ApiError
from ..core.pagination import CursorPosition
from ..dataset_schemas import CreateDatasetRequest, DatasetSummary
from ..models import Dataset, Run
from .identity_tenancy import append_audit_event


def dataset_summary(record: Dataset) -> DatasetSummary:
    return DatasetSummary.model_validate(record)


async def create_dataset(
    session: AsyncSession,
    *,
    run: Run,
    user_id: UUID,
    actor_type: str,
    actor_id: str,
    request_id: str,
    payload: CreateDatasetRequest,
) -> Dataset:
    existing = await session.scalar(
        select(Dataset).where(
            Dataset.run_id == run.id,
            Dataset.name == payload.name,
        )
    )
    if existing is not None:
        raise ApiError(
            status_code=409,
            code="DATASET_ALREADY_EXISTS",
            message="A Dataset with that name already exists for this Run.",
        )

    record = Dataset(
        organization_id=run.organization_id,
        project_id=run.project_id,
        run_id=run.id,
        agent_id=run.agent_id,
        agent_version_id=run.agent_version_id,
        name=payload.name,
        item_count=0,
        total_bytes=0,
        next_sequence=1,
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
        action="dataset.created",
        resource_type="dataset",
        resource_id=str(record.id),
        request_id=request_id,
        details={
            "run_id": str(run.id),
            "agent_id": str(run.agent_id),
            "agent_version_id": str(run.agent_version_id),
            "name": record.name,
        },
    )
    return record


async def list_datasets(
    session: AsyncSession,
    *,
    project_id: UUID,
    cursor: CursorPosition | None,
    limit: int,
) -> tuple[list[Dataset], bool]:
    statement = select(Dataset).where(Dataset.project_id == project_id)
    if cursor is not None:
        statement = statement.where(
            or_(
                Dataset.created_at < cursor.created_at,
                and_(
                    Dataset.created_at == cursor.created_at,
                    Dataset.id < cursor.resource_id,
                ),
            )
        )
    rows = list(
        (
            await session.scalars(
                statement.order_by(
                    Dataset.created_at.desc(),
                    Dataset.id.desc(),
                ).limit(limit + 1)
            )
        ).all()
    )
    return rows[:limit], len(rows) > limit
