import base64
import hashlib
import json
from contextlib import suppress
from dataclasses import dataclass
from uuid import UUID, uuid4

from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.errors import ApiError
from ..core.pagination import CursorPosition
from ..core.s3_storage import StorageBackendError, object_storage
from ..kv_mutation_protocol import (
    KVProtocolError,
    ValidatedKVMutation,
    validate_kv_mutation,
)
from ..kv_schemas import (
    CreateKeyValueStoreRequest,
    KeyValueMutationReceiptSummary,
    KeyValueRecordSummary,
    KeyValueStoreSummary,
)
from ..models import (
    KeyValueMutationReceipt,
    KeyValueRecord,
    KeyValueRecordVersion,
    KeyValueStore,
    Project,
    Run,
)
from .identity_tenancy import append_audit_event

MAX_KV_RECORDS = 10_000
MAX_KV_STORE_BYTES = 268_435_456


@dataclass(frozen=True)
class KeyValueMutationOutcome:
    receipt: KeyValueMutationReceipt
    replayed: bool


def key_value_store_summary(record: KeyValueStore) -> KeyValueStoreSummary:
    return KeyValueStoreSummary.model_validate(record)


def key_value_mutation_receipt_summary(
    outcome: KeyValueMutationOutcome,
) -> KeyValueMutationReceiptSummary:
    record = outcome.receipt
    return KeyValueMutationReceiptSummary.model_validate(
        {
            "id": record.id,
            "store_id": record.store_id,
            "record_id": record.record_id,
            "record_version_id": record.record_version_id,
            "schema_version": record.schema_version,
            "idempotency_key": record.idempotency_key,
            "request_digest": record.request_digest,
            "operation": record.operation,
            "key": record.key,
            "expected_version": record.expected_version,
            "result_version": record.result_version,
            "value_sha256": record.value_sha256,
            "size_bytes": record.size_bytes,
            "replayed": outcome.replayed,
            "created_at": record.created_at,
        }
    )


async def key_value_record_summary(
    record: KeyValueRecord,
    session: AsyncSession,
) -> KeyValueRecordSummary:
    version = await session.scalar(
        select(KeyValueRecordVersion).where(
            KeyValueRecordVersion.record_id == record.id,
            KeyValueRecordVersion.version == record.current_version,
            KeyValueRecordVersion.tombstone.is_(False),
        )
    )
    if (
        version is None
        or version.object_key is None
        or version.content_type is None
        or version.encoding is None
        or version.value_sha256 is None
    ):
        raise ApiError(
            status_code=500,
            code="KV_STORAGE_LINEAGE_INVALID",
            message="The Key-Value record storage lineage is invalid.",
        )
    try:
        raw = await object_storage.read_object(
            object_key=version.object_key,
            max_bytes=version.size_bytes,
        )
    except StorageBackendError as exc:
        raise ApiError(status_code=503, code=exc.code, message=exc.message) from exc
    if len(raw) != version.size_bytes or hashlib.sha256(raw).hexdigest() != version.value_sha256:
        raise ApiError(
            status_code=500,
            code="KV_STORAGE_INTEGRITY_FAILED",
            message="The Key-Value record failed storage integrity verification.",
        )
    try:
        if version.encoding == "json":
            value: object = json.loads(raw.decode("utf-8"))
        elif version.encoding == "utf8":
            value = raw.decode("utf-8")
        elif version.encoding == "base64":
            value = base64.b64encode(raw).decode("ascii")
        else:
            raise ValueError("unsupported encoding")
    except (UnicodeError, ValueError) as exc:
        raise ApiError(
            status_code=500,
            code="KV_STORAGE_DECODE_FAILED",
            message="The Key-Value record could not be safely decoded.",
        ) from exc
    return KeyValueRecordSummary(
        key=record.key,
        version=record.current_version,
        content_type=version.content_type,
        encoding=version.encoding,
        value_sha256=version.value_sha256,
        size_bytes=version.size_bytes,
        value=value,
    )


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


def _version_conflict(
    *,
    expected_version: int,
    current_version: int | None,
) -> ApiError:
    return ApiError(
        status_code=409,
        code="KV_VERSION_CONFLICT",
        message=(
            "The Key-Value record version precondition failed. "
            f"Expected {expected_version}; current version is "
            f"{current_version if current_version is not None else 'absent'}."
        ),
    )


def _enforce_expected_version(
    validation: ValidatedKVMutation,
    record: KeyValueRecord | None,
) -> None:
    expected = validation.expected_version
    if expected is None:
        return
    current = record.current_version if record is not None else None
    if expected == 0:
        if record is not None:
            raise _version_conflict(
                expected_version=expected,
                current_version=current,
            )
        return
    if record is None or record.current_version != expected:
        raise _version_conflict(
            expected_version=expected,
            current_version=current,
        )


def _server_object_key(
    *,
    organization_id: UUID,
    store_id: UUID,
    record_id: UUID,
    version_id: UUID,
) -> str:
    return (
        "kv/"
        f"{organization_id.hex}/"
        f"{store_id.hex}/"
        f"{record_id.hex}/"
        f"{version_id.hex}"
    )


async def mutate_key_value_record(
    session: AsyncSession,
    *,
    store: KeyValueStore,
    user_id: UUID,
    actor_type: str,
    actor_id: str,
    request_id: str,
    payload: object,
    required_operation: str,
) -> KeyValueMutationOutcome:
    try:
        validation = validate_kv_mutation(payload)
    except KVProtocolError as exc:
        raise ApiError(
            status_code=422,
            code="KV_MUTATION_INVALID",
            message=str(exc),
        ) from exc

    if validation.operation != required_operation:
        raise ApiError(
            status_code=422,
            code="KV_OPERATION_MISMATCH",
            message="The mutation operation does not match this endpoint.",
        )

    locked_store = await session.scalar(
        select(KeyValueStore)
        .where(
            KeyValueStore.id == store.id,
            KeyValueStore.organization_id == store.organization_id,
            KeyValueStore.project_id == store.project_id,
        )
        .with_for_update()
    )
    if locked_store is None:
        raise ApiError(
            status_code=404,
            code="RESOURCE_NOT_FOUND",
            message="The requested resource was not found.",
        )

    existing_receipt = await session.scalar(
        select(KeyValueMutationReceipt).where(
            KeyValueMutationReceipt.store_id == locked_store.id,
            KeyValueMutationReceipt.idempotency_key
            == validation.idempotency_key,
        )
    )
    if existing_receipt is not None:
        if existing_receipt.request_digest != validation.request_digest:
            raise ApiError(
                status_code=409,
                code="KV_IDEMPOTENCY_CONFLICT",
                message=(
                    "The idempotency key was already used for a "
                    "different Key-Value mutation."
                ),
            )
        return KeyValueMutationOutcome(
            receipt=existing_receipt,
            replayed=True,
        )

    current = await session.scalar(
        select(KeyValueRecord)
        .where(
            KeyValueRecord.store_id == locked_store.id,
            KeyValueRecord.key == validation.key,
        )
        .with_for_update()
    )
    _enforce_expected_version(validation, current)

    if validation.operation == "delete":
        if current is None:
            raise ApiError(
                status_code=404,
                code="KV_RECORD_NOT_FOUND",
                message="The Key-Value record does not exist.",
            )
        if current.deleted:
            raise ApiError(
                status_code=409,
                code="KV_RECORD_ALREADY_DELETED",
                message="The Key-Value record is already deleted.",
            )

    record_id = current.id if current is not None else uuid4()
    next_version = 1 if current is None else current.current_version + 1
    version_id = uuid4()

    if validation.operation == "set":
        if (
            validation.value_bytes is None
            or validation.content_type is None
            or validation.encoding is None
            or validation.value_sha256 is None
        ):
            raise RuntimeError("Validated SET mutation is missing value lineage.")

        if current is not None and not current.deleted:
            was_live = True
            previous_size = current.current_size_bytes
        else:
            was_live = False
            previous_size = 0
        projected_count = (
            locked_store.record_count
            if was_live
            else locked_store.record_count + 1
        )
        projected_bytes = (
            locked_store.total_bytes
            - previous_size
            + validation.decoded_bytes
        )
        if projected_count > MAX_KV_RECORDS:
            raise ApiError(
                status_code=413,
                code="KV_RECORD_QUOTA_EXCEEDED",
                message="The Key-Value Store record quota would be exceeded.",
            )
        if projected_bytes > MAX_KV_STORE_BYTES:
            raise ApiError(
                status_code=413,
                code="KV_BYTE_QUOTA_EXCEEDED",
                message="The Key-Value Store byte quota would be exceeded.",
            )
        object_key = _server_object_key(
            organization_id=locked_store.organization_id,
            store_id=locked_store.id,
            record_id=record_id,
            version_id=version_id,
        )
        object_bytes = validation.value_bytes
        tombstone = False
        new_size = validation.decoded_bytes
    else:
        if current is None:
            raise RuntimeError("DELETE mutation lost its locked record.")
        projected_count = locked_store.record_count - 1
        projected_bytes = (
            locked_store.total_bytes - current.current_size_bytes
        )
        object_key = None
        object_bytes = None
        tombstone = True
        new_size = 0

    uploaded_key: str | None = None
    try:
        if object_key is not None and object_bytes is not None:
            try:
                await object_storage.write_object(
                    object_key=object_key,
                    content=object_bytes,
                    content_type=validation.content_type
                    or "application/octet-stream",
                    sha256_digest=validation.value_sha256 or "",
                    metadata={
                        "rdc-kv-store-id": str(locked_store.id),
                        "rdc-kv-record-id": str(record_id),
                        "rdc-kv-version-id": str(version_id),
                    },
                )
            except StorageBackendError as exc:
                raise ApiError(
                    status_code=503,
                    code=exc.code,
                    message=exc.message,
                ) from exc
            uploaded_key = object_key

        if current is None:
            current = KeyValueRecord(
                id=record_id,
                organization_id=locked_store.organization_id,
                project_id=locked_store.project_id,
                store_id=locked_store.id,
                key=validation.key,
                current_version=next_version,
                deleted=tombstone,
                current_size_bytes=new_size,
                created_by_user_id=user_id,
                version=1,
            )
            session.add(current)
        else:
            current.current_version = next_version
            current.deleted = tombstone
            current.current_size_bytes = new_size
            current.version += 1

        record_version = KeyValueRecordVersion(
            id=version_id,
            organization_id=locked_store.organization_id,
            project_id=locked_store.project_id,
            store_id=locked_store.id,
            record_id=record_id,
            version=next_version,
            operation=validation.operation.upper(),
            tombstone=tombstone,
            content_type=validation.content_type,
            encoding=validation.encoding,
            object_key=object_key,
            value_sha256=validation.value_sha256,
            size_bytes=new_size,
            created_by_user_id=user_id,
        )
        session.add(record_version)

        receipt = KeyValueMutationReceipt(
            organization_id=locked_store.organization_id,
            project_id=locked_store.project_id,
            store_id=locked_store.id,
            record_id=record_id,
            record_version_id=version_id,
            schema_version=validation.schema_version,
            idempotency_key=validation.idempotency_key,
            request_digest=validation.request_digest,
            operation=validation.operation.upper(),
            key=validation.key,
            expected_version=validation.expected_version,
            result_version=next_version,
            value_sha256=validation.value_sha256,
            size_bytes=new_size,
            created_by_user_id=user_id,
        )
        session.add(receipt)

        locked_store.record_count = projected_count
        locked_store.total_bytes = projected_bytes
        locked_store.version += 1
        await session.flush()

        await append_audit_event(
            session,
            organization_id=locked_store.organization_id,
            project_id=locked_store.project_id,
            actor_type=actor_type,
            actor_id=actor_id,
            action=(
                "kv_record.set"
                if validation.operation == "set"
                else "kv_record.deleted"
            ),
            resource_type="key_value_record",
            resource_id=str(record_id),
            request_id=request_id,
            details={
                "store_id": str(locked_store.id),
                "record_version_id": str(version_id),
                "result_version": next_version,
                "request_digest": validation.request_digest,
                "value_sha256": validation.value_sha256,
                "size_bytes": new_size,
            },
        )
        return KeyValueMutationOutcome(receipt=receipt, replayed=False)
    except Exception:
        if uploaded_key is not None:
            with suppress(StorageBackendError):
                await object_storage.delete_object(object_key=uploaded_key)
        raise


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


async def list_key_value_records(
    session: AsyncSession,
    *,
    store_id: UUID,
    prefix: str | None,
    after_key: str | None,
    limit: int,
) -> tuple[list[KeyValueRecord], bool]:
    statement = select(KeyValueRecord).where(
        KeyValueRecord.store_id == store_id,
        KeyValueRecord.deleted.is_(False),
    )
    if prefix is not None:
        statement = statement.where(KeyValueRecord.key.startswith(prefix))
    if after_key is not None:
        statement = statement.where(KeyValueRecord.key > after_key)
    rows = list(
        (await session.scalars(statement.order_by(KeyValueRecord.key).limit(limit + 1))).all()
    )
    return rows[:limit], len(rows) > limit


async def get_key_value_record(
    session: AsyncSession, *, store_id: UUID, key: str
) -> KeyValueRecord:
    record = await session.scalar(
        select(KeyValueRecord).where(
            KeyValueRecord.store_id == store_id,
            KeyValueRecord.key == key,
            KeyValueRecord.deleted.is_(False),
        )
    )
    if record is None:
        raise ApiError(
            status_code=404,
            code="KV_RECORD_NOT_FOUND",
            message="The Key-Value record does not exist.",
        )
    return record
