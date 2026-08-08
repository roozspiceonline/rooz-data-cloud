from __future__ import annotations

import base64
import hashlib
import json
from typing import cast

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.config import get_settings
from ..core.errors import ApiError
from ..core.s3_storage import StorageBackendError, object_storage
from ..kv_mutation_protocol import (
    MAX_VALUE_BYTES,
    KVProtocolError,
    validate_kv_mutation,
)
from ..kv_schemas import (
    CreateKeyValueStoreRequest,
    KeyValueMutationReceiptSummary,
)
from ..kv_worker_protocol import (
    MAX_WORKER_READ_TOTAL_BYTES,
    KVWorkerProtocolError,
    ValidatedKVReadRequest,
    validate_kv_read_request,
)
from ..models import (
    ExecutionLease,
    KeyValueRecord,
    KeyValueRecordVersion,
    KeyValueStore,
    Run,
    WorkerIdentity,
)
from .key_value_stores import (
    create_run_key_value_store,
    key_value_mutation_receipt_summary,
    mutate_key_value_record,
)

settings = get_settings()


def key_value_store_capability(
    worker: WorkerIdentity,
    payload: dict[str, object],
    *,
    key_value_store_enabled: bool,
) -> dict[str, object] | None:
    if (
        not key_value_store_enabled
        or not settings.sandbox_canary_key_value_store_enabled
        or str(payload.get("work_kind", "")) != "RUN_START"
        or worker.name != settings.sandbox_canary_worker_name.strip()
        or "KV_ACCESS" not in worker.capabilities
        or str(payload.get("agent_version_id", ""))
        != settings.sandbox_canary_agent_version_id.strip()
    ):
        return None

    manifest = payload.get("manifest")
    if not isinstance(manifest, dict):
        return None
    capabilities = manifest.get("capabilities")
    if not isinstance(capabilities, dict):
        return None
    if (
        capabilities.get("keyValueStore") is not True
        or capabilities.get("dataset") is not False
        or capabilities.get("browser") is not False
        or capabilities.get("requestQueue") is not False
    ):
        return None

    run_id = payload.get("run_id")
    input_reference = payload.get("input_reference")
    if (
        not isinstance(run_id, str)
        or not run_id
        or not isinstance(input_reference, dict)
    ):
        return None
    input_value = input_reference.get("value")
    if not isinstance(input_value, dict) or "_rdc_kv" in input_value:
        return None

    read_request = input_value.get("_rdc_kv_read")
    read_request_digest: str | None = None
    if read_request is not None:
        try:
            read_request_digest = validate_kv_read_request(
                read_request
            ).request_digest
        except KVWorkerProtocolError:
            return None

    return {
        "schema_version": "rdc.kv-worker-capability/v1",
        "write_schema_version": "rdc.kv-write/v1",
        "read_schema_version": "rdc.kv-worker-read/v1",
        "output_schema_version": "rdc.kv-worker-output/v1",
        "run_id": run_id,
        "agent_version_id": str(payload["agent_version_id"]),
        "worker_name": worker.name,
        "store_name": "default",
        "read_request_digest": read_request_digest,
        "max_read_keys": 16,
        "max_read_total_bytes": MAX_WORKER_READ_TOTAL_BYTES,
        "max_mutations": 4,
        "max_value_bytes": MAX_VALUE_BYTES,
        "post_run_mutations_only": True,
        "direct_database_access": False,
        "direct_object_storage_access": False,
        "enabled": True,
    }


async def _worker_run_context(
    session: AsyncSession,
    *,
    lease: ExecutionLease,
    worker: WorkerIdentity,
) -> tuple[Run, dict[str, object]]:
    if not settings.sandbox_canary_key_value_store_enabled:
        raise ApiError(
            status_code=403,
            code="KV_WORKER_ACCESS_DISABLED",
            message="Worker Key-Value Store access is disabled.",
        )
    if (
        lease.work_kind != "RUN_START"
        or lease.run_id is None
        or "KV_ACCESS" not in worker.capabilities
    ):
        raise ApiError(
            status_code=403,
            code="KV_WORKER_CAPABILITY_DENIED",
            message="The worker cannot access Key-Value Store state.",
        )

    snapshot = dict(lease.payload_snapshot)
    activation = snapshot.get("activation")
    kv_enabled = (
        isinstance(activation, dict)
        and activation.get("key_value_store_enabled") is True
    )
    expected = key_value_store_capability(
        worker,
        snapshot,
        key_value_store_enabled=kv_enabled,
    )
    if (
        expected is None
        or snapshot.get("key_value_store_capability") != expected
        or str(snapshot.get("run_id", "")) != str(lease.run_id)
    ):
        raise ApiError(
            status_code=403,
            code="KV_WORKER_CAPABILITY_INVALID",
            message="The worker Key-Value Store capability receipt is invalid.",
        )

    run = await session.scalar(
        select(Run).where(
            Run.id == lease.run_id,
            Run.organization_id == lease.organization_id,
            Run.project_id == lease.project_id,
        )
    )
    if (
        run is None
        or str(run.agent_version_id)
        != settings.sandbox_canary_agent_version_id.strip()
        or str(snapshot.get("agent_version_id", ""))
        != str(run.agent_version_id)
    ):
        raise ApiError(
            status_code=404,
            code="RESOURCE_NOT_FOUND",
            message="The requested resource was not found.",
        )
    return run, expected


async def _run_default_store(
    session: AsyncSession,
    *,
    run: Run,
) -> KeyValueStore | None:
    return cast(
        KeyValueStore | None,
        await session.scalar(
            select(KeyValueStore).where(
                KeyValueStore.organization_id == run.organization_id,
                KeyValueStore.project_id == run.project_id,
                KeyValueStore.scope == "RUN",
                KeyValueStore.run_id == run.id,
                KeyValueStore.name == "default",
            )
        ),
    )


def _missing_record(key: str) -> dict[str, object]:
    return {
        "key": key,
        "found": False,
        "version": None,
        "content_type": None,
        "encoding": None,
        "value_sha256": None,
        "size_bytes": None,
        "value": None,
    }


async def _read_records(
    session: AsyncSession,
    *,
    store: KeyValueStore,
    validation: ValidatedKVReadRequest,
) -> dict[str, object]:
    records: list[dict[str, object]] = []
    total_bytes = 0

    for key in validation.keys:
        current = await session.scalar(
            select(KeyValueRecord).where(
                KeyValueRecord.store_id == store.id,
                KeyValueRecord.key == key,
                KeyValueRecord.deleted.is_(False),
            )
        )
        if current is None:
            records.append(_missing_record(key))
            continue

        version = await session.scalar(
            select(KeyValueRecordVersion).where(
                KeyValueRecordVersion.record_id == current.id,
                KeyValueRecordVersion.version == current.current_version,
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

        if version.size_bytes > MAX_VALUE_BYTES:
            raise ApiError(
                status_code=500,
                code="KV_STORAGE_LINEAGE_INVALID",
                message="The Key-Value record exceeds the protocol limit.",
            )
        if total_bytes + version.size_bytes > MAX_WORKER_READ_TOTAL_BYTES:
            raise ApiError(
                status_code=413,
                code="KV_WORKER_READ_TOO_LARGE",
                message=(
                    "The requested Key-Value read exceeds "
                    "the worker byte limit."
                ),
            )

        try:
            raw = await object_storage.read_object(
                object_key=version.object_key,
                max_bytes=MAX_VALUE_BYTES,
            )
        except StorageBackendError as exc:
            raise ApiError(
                status_code=503,
                code=exc.code,
                message=exc.message,
            ) from exc

        if (
            len(raw) != version.size_bytes
            or hashlib.sha256(raw).hexdigest() != version.value_sha256
        ):
            raise ApiError(
                status_code=500,
                code="KV_STORAGE_INTEGRITY_FAILED",
                message=(
                    "The Key-Value record failed storage "
                    "integrity verification."
                ),
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

        total_bytes += len(raw)
        records.append(
            {
                "key": key,
                "found": True,
                "version": current.current_version,
                "content_type": version.content_type,
                "encoding": version.encoding,
                "value_sha256": version.value_sha256,
                "size_bytes": version.size_bytes,
                "value": value,
            }
        )

    return {
        "schema_version": "rdc.kv-worker-read-result/v1",
        "store_name": "default",
        "records": records,
    }


async def read_worker_key_value_records(
    session: AsyncSession,
    *,
    lease: ExecutionLease,
    worker: WorkerIdentity,
    payload: object,
) -> dict[str, object]:
    run, capability = await _worker_run_context(
        session,
        lease=lease,
        worker=worker,
    )
    try:
        validation = validate_kv_read_request(payload)
    except KVWorkerProtocolError as exc:
        raise ApiError(
            status_code=422,
            code="KV_WORKER_READ_INVALID",
            message=str(exc),
        ) from exc

    if capability.get("read_request_digest") != validation.request_digest:
        raise ApiError(
            status_code=403,
            code="KV_WORKER_READ_INTENT_MISMATCH",
            message=(
                "The KV read request does not match "
                "the immutable Run intent."
            ),
        )

    store = await _run_default_store(session, run=run)
    if store is None:
        return {
            "schema_version": "rdc.kv-worker-read-result/v1",
            "store_name": "default",
            "records": [_missing_record(key) for key in validation.keys],
        }
    return await _read_records(
        session,
        store=store,
        validation=validation,
    )


async def mutate_worker_key_value_record(
    session: AsyncSession,
    *,
    lease: ExecutionLease,
    worker: WorkerIdentity,
    payload: object,
    request_id: str,
) -> KeyValueMutationReceiptSummary:
    run, _ = await _worker_run_context(
        session,
        lease=lease,
        worker=worker,
    )
    try:
        validation = validate_kv_mutation(payload)
    except KVProtocolError as exc:
        raise ApiError(
            status_code=422,
            code="KV_MUTATION_INVALID",
            message=str(exc),
        ) from exc

    store = await _run_default_store(session, run=run)
    if store is None:
        if validation.operation != "set":
            raise ApiError(
                status_code=404,
                code="KV_RECORD_NOT_FOUND",
                message="The Key-Value record does not exist.",
            )
        store = await create_run_key_value_store(
            session,
            run=run,
            user_id=run.requested_by_user_id,
            actor_type="worker",
            actor_id=str(worker.id),
            request_id=request_id,
            payload=CreateKeyValueStoreRequest(name="default"),
        )

    outcome = await mutate_key_value_record(
        session,
        store=store,
        user_id=run.requested_by_user_id,
        actor_type="worker",
        actor_id=str(worker.id),
        request_id=request_id,
        payload=validation.request,
        required_operation=validation.operation,
    )
    return key_value_mutation_receipt_summary(outcome)
