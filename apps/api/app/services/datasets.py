import hashlib
from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.errors import ApiError
from ..core.pagination import CursorPosition
from ..dataset_append_protocol import (
    canonical_json_bytes,
    validate_dataset_append,
)
from ..dataset_schemas import (
    CreateDatasetRequest,
    DatasetAppendReceiptSummary,
    DatasetSummary,
)
from ..models import Dataset, DatasetAppendReceipt, DatasetItem, Run
from .identity_tenancy import append_audit_event

MAX_DATASET_ITEMS = 100_000
MAX_DATASET_BYTES = 268_435_456


@dataclass(frozen=True)
class DatasetAppendOutcome:
    receipt: DatasetAppendReceipt
    replayed: bool


def dataset_summary(record: Dataset) -> DatasetSummary:
    return DatasetSummary.model_validate(record)


def dataset_append_receipt_summary(
    record: DatasetAppendReceipt,
) -> DatasetAppendReceiptSummary:
    return DatasetAppendReceiptSummary.model_validate(record)


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


async def append_dataset_items(
    session: AsyncSession,
    *,
    dataset: Dataset,
    user_id: UUID,
    actor_type: str,
    actor_id: str,
    request_id: str,
    payload: object,
) -> DatasetAppendOutcome:
    validation = validate_dataset_append(payload)

    locked = await session.scalar(
        select(Dataset)
        .where(
            Dataset.id == dataset.id,
            Dataset.organization_id == dataset.organization_id,
            Dataset.project_id == dataset.project_id,
        )
        .with_for_update()
    )
    if locked is None:
        raise ApiError(
            status_code=404,
            code="RESOURCE_NOT_FOUND",
            message="The requested resource was not found.",
        )

    existing = await session.scalar(
        select(DatasetAppendReceipt).where(
            DatasetAppendReceipt.dataset_id == locked.id,
            DatasetAppendReceipt.idempotency_key
            == validation.idempotency_key,
        )
    )
    if existing is not None:
        if existing.request_digest != validation.request_digest:
            raise ApiError(
                status_code=409,
                code="DATASET_IDEMPOTENCY_CONFLICT",
                message=(
                    "The idempotency key was already used for a "
                    "different Dataset append request."
                ),
            )
        return DatasetAppendOutcome(receipt=existing, replayed=True)

    item_payloads = [
        canonical_json_bytes(item)
        for item in validation.items
    ]
    item_bytes = sum(len(encoded) for encoded in item_payloads)

    if locked.item_count + validation.item_count > MAX_DATASET_ITEMS:
        raise ApiError(
            status_code=413,
            code="DATASET_ITEM_QUOTA_EXCEEDED",
            message="The Dataset item quota would be exceeded.",
        )
    if locked.total_bytes + item_bytes > MAX_DATASET_BYTES:
        raise ApiError(
            status_code=413,
            code="DATASET_BYTE_QUOTA_EXCEEDED",
            message="The Dataset byte quota would be exceeded.",
        )

    first_sequence = locked.next_sequence
    receipt = DatasetAppendReceipt(
        organization_id=locked.organization_id,
        project_id=locked.project_id,
        dataset_id=locked.id,
        run_id=locked.run_id,
        schema_version=validation.schema_version,
        idempotency_key=validation.idempotency_key,
        request_digest=validation.request_digest,
        first_sequence=first_sequence,
        item_count=validation.item_count,
        total_bytes=item_bytes,
        created_by_user_id=user_id,
    )
    session.add(receipt)
    await session.flush()

    for offset, (item, encoded) in enumerate(
        zip(validation.items, item_payloads, strict=True)
    ):
        session.add(
            DatasetItem(
                organization_id=locked.organization_id,
                project_id=locked.project_id,
                dataset_id=locked.id,
                append_receipt_id=receipt.id,
                run_id=locked.run_id,
                sequence=first_sequence + offset,
                item_json=item,
                size_bytes=len(encoded),
                sha256_digest=hashlib.sha256(encoded).hexdigest(),
            )
        )

    locked.item_count += validation.item_count
    locked.total_bytes += item_bytes
    locked.next_sequence += validation.item_count
    locked.version += 1
    await session.flush()

    await append_audit_event(
        session,
        organization_id=locked.organization_id,
        project_id=locked.project_id,
        actor_type=actor_type,
        actor_id=actor_id,
        action="dataset.items_appended",
        resource_type="dataset",
        resource_id=str(locked.id),
        request_id=request_id,
        details={
            "append_receipt_id": str(receipt.id),
            "request_digest": receipt.request_digest,
            "first_sequence": receipt.first_sequence,
            "item_count": receipt.item_count,
            "total_bytes": receipt.total_bytes,
        },
    )
    return DatasetAppendOutcome(receipt=receipt, replayed=False)


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
