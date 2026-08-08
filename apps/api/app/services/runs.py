import hashlib
import json
import re
from datetime import UTC, datetime, timedelta
from typing import cast
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from sqlalchemy import and_, func, or_, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.config import get_settings
from ..core.errors import ApiError
from ..core.pagination import CursorPosition
from ..core.security import canonical_fingerprint
from ..models import (
    AgentVersion,
    Build,
    IdempotencyRecord,
    Run,
    RunCommandOutbox,
    RunEvent,
)
from ..run_schemas import CreateRunRequest, RunEventType
from .builds_secrets import acquire_idempotency_lock, validate_idempotency_key
from .identity_tenancy import append_audit_event

RUN_TERMINAL_STATUSES = frozenset(
    {
        "SUCCEEDED",
        "PARTIALLY_SUCCEEDED",
        "FAILED",
        "TIMED_OUT",
        "ABORTED",
    }
)
RUN_CANCELLABLE_ACTIVE_STATUSES = frozenset(
    {
        "STARTING",
        "RUNNING",
        "PAUSING",
        "PAUSED",
        "TIMING_OUT",
    }
)
PERSISTED_EVENT_TYPES = frozenset(
    {
        "run.status",
        "run.log",
        "run.metric",
        "run.warning",
        "run.completed",
        "run.failed",
    }
)
ANSI_ESCAPE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
SENSITIVE_KEY_PARTS = (
    "authorization",
    "cookie",
    "credential",
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
)
MAX_EVENT_PAYLOAD_BYTES = 65_536
MAX_EVENT_STRING_LENGTH = 16_384


def run_metadata(record: Run) -> dict[str, object]:
    return {
        "id": record.id,
        "organization_id": record.organization_id,
        "project_id": record.project_id,
        "agent_id": record.agent_id,
        "agent_version_id": record.agent_version_id,
        "build_id": record.build_id,
        "status": record.status,
        "input_reference": record.input_reference,
        "runtime_configuration": record.runtime_configuration,
        "memory_mb": record.memory_mb,
        "cpu_millis": record.cpu_millis,
        "timeout_seconds": record.timeout_seconds,
        "queued_at": record.queued_at,
        "started_at": record.started_at,
        "finished_at": record.finished_at,
        "cancel_requested_at": record.cancel_requested_at,
        "failure_code": record.failure_code,
        "failure_summary": record.failure_summary,
        "created_at": record.created_at,
        "updated_at": record.updated_at,
        "version": record.version,
        "status_url": f"/api/v1/runs/{record.id}",
        "events_url": f"/api/v1/runs/{record.id}/events",
        "cancel_url": f"/api/v1/runs/{record.id}/cancel",
    }


def json_run_snapshot(record: Run) -> dict[str, object]:
    snapshot = run_metadata(record)
    return {
        **snapshot,
        "id": str(record.id),
        "organization_id": str(record.organization_id),
        "project_id": str(record.project_id),
        "agent_id": str(record.agent_id),
        "agent_version_id": str(record.agent_version_id),
        "build_id": str(record.build_id),
        "queued_at": record.queued_at.isoformat(),
        "started_at": record.started_at.isoformat() if record.started_at else None,
        "finished_at": record.finished_at.isoformat() if record.finished_at else None,
        "cancel_requested_at": (
            record.cancel_requested_at.isoformat()
            if record.cancel_requested_at
            else None
        ),
        "created_at": record.created_at.isoformat(),
        "updated_at": record.updated_at.isoformat(),
    }


def run_event_metadata(record: RunEvent) -> dict[str, object]:
    return {
        "id": record.id,
        "run_id": record.run_id,
        "sequence": record.sequence,
        "event_type": record.event_type,
        "timestamp": record.created_at,
        "payload": record.payload,
    }


def _manifest_network(version: AgentVersion) -> str:
    capabilities = version.manifest.get("capabilities")
    if not isinstance(capabilities, dict):
        raise ApiError(
            status_code=409,
            code="AGENT_MANIFEST_INVALID",
            message="The immutable Agent version has invalid capabilities.",
        )
    network = capabilities.get("network")
    if network not in {"none", "web-egress"}:
        raise ApiError(
            status_code=409,
            code="AGENT_MANIFEST_INVALID",
            message="The immutable Agent version has invalid network capability.",
        )
    return str(network)


def _manifest_browser(version: AgentVersion) -> bool:
    capabilities = version.manifest.get("capabilities")
    if not isinstance(capabilities, dict):
        raise ApiError(
            status_code=409,
            code="AGENT_MANIFEST_INVALID",
            message="The immutable Agent version has invalid capabilities.",
        )
    browser = capabilities.get("browser")
    if not isinstance(browser, bool):
        raise ApiError(
            status_code=409,
            code="AGENT_MANIFEST_INVALID",
            message="The immutable Agent version has invalid browser capability.",
        )
    return browser


def _browser_policy_payload() -> dict[str, object]:
    settings = get_settings()
    return {
        "schema_version": "rdc.browser-policy/v1",
        "enabled": settings.sandbox_canary_browser_enabled,
        "allowed_hosts": sorted(settings.sandbox_canary_web_egress_allowed_hosts),
        "max_pages": settings.sandbox_canary_browser_max_pages,
        "max_actions": settings.sandbox_canary_browser_max_actions,
        "navigation_timeout_seconds": settings.sandbox_canary_browser_navigation_timeout_seconds,
        "max_dom_bytes": settings.sandbox_canary_browser_max_dom_bytes,
        "max_screenshot_bytes": settings.sandbox_canary_browser_max_screenshot_bytes,
        "agent_container_network": "none",
        "project_secrets_available": False,
        "persistent_profile": False,
        "downloads_enabled": False,
        "uploads_enabled": False,
        "remote_cdp_enabled": False,
    }


def _normalize_browser_navigation_hostname(value: str) -> str:
    import ipaddress

    candidate = value.strip().rstrip(".").casefold()
    if not candidate or "*" in candidate:
        raise ApiError(
            status_code=422,
            code="BROWSER_NAVIGATION_HOST_REJECTED",
            message="Browser navigation requires an exact hostname.",
        )
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        pass
    else:
        raise ApiError(
            status_code=422,
            code="BROWSER_NAVIGATION_HOST_REJECTED",
            message="Browser navigation cannot target an IP literal.",
        )
    try:
        normalized = candidate.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ApiError(
            status_code=422,
            code="BROWSER_NAVIGATION_HOST_REJECTED",
            message="Browser navigation hostname is invalid.",
        ) from exc
    labels = normalized.split(".")
    if (
        len(labels) < 2
        or normalized.endswith(".local")
        or any(
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or not all(
                character.isalnum() or character == "-"
                for character in label
            )
            for label in labels
        )
    ):
        raise ApiError(
            status_code=422,
            code="BROWSER_NAVIGATION_HOST_REJECTED",
            message="Browser navigation hostname is unsafe.",
        )
    return normalized


def _browser_navigation_receipt(
    browser_navigation: dict[str, object],
    *,
    browser_policy: dict[str, object],
    browser_policy_digest: str,
) -> dict[str, object]:
    allowed_hosts_raw = browser_policy.get("allowed_hosts")
    if not isinstance(allowed_hosts_raw, list) or not allowed_hosts_raw:
        raise ApiError(
            status_code=409,
            code="BROWSER_NAVIGATION_POLICY_UNAVAILABLE",
            message=(
                "Browser navigation intent requires an operator hostname "
                "allowlist."
            ),
        )
    allowed_hosts = {
        _normalize_browser_navigation_hostname(str(host))
        for host in allowed_hosts_raw
    }
    def require_policy_int(name: str) -> int:
        value = browser_policy.get(name)
        if isinstance(value, bool) or not isinstance(value, int):
            raise ApiError(
                status_code=409,
                code="BROWSER_NAVIGATION_POLICY_UNAVAILABLE",
                message=(
                    "Browser navigation policy field is not a valid integer: "
                    + name
                ),
            )
        return value

    max_pages = require_policy_int("max_pages")
    max_actions = require_policy_int("max_actions")
    navigation_timeout_seconds = require_policy_int(
        "navigation_timeout_seconds"
    )
    max_dom_bytes = require_policy_int("max_dom_bytes")
    navigation_timeout_ms = navigation_timeout_seconds * 1000

    steps = browser_navigation.get("steps")
    if not isinstance(steps, list) or not 1 <= len(steps) <= max_actions:
        raise ApiError(
            status_code=422,
            code="BROWSER_NAVIGATION_POLICY_REJECTED",
            message="Browser navigation step count exceeds operator policy.",
        )

    goto_count = 0
    for step in steps:
        if not isinstance(step, dict):
            raise ApiError(
                status_code=422,
                code="BROWSER_NAVIGATION_POLICY_REJECTED",
                message="Browser navigation step is malformed.",
            )
        step_type = step.get("type")
        if step_type == "goto":
            goto_count += 1
            url = step.get("url")
            if not isinstance(url, str):
                raise ApiError(
                    status_code=422,
                    code="BROWSER_NAVIGATION_POLICY_REJECTED",
                    message="Browser goto URL is malformed.",
                )
            parsed = urlsplit(url)
            if not parsed.hostname:
                raise ApiError(
                    status_code=422,
                    code="BROWSER_NAVIGATION_POLICY_REJECTED",
                    message="Browser goto URL requires a hostname.",
                )
            hostname = _normalize_browser_navigation_hostname(
                parsed.hostname
            )
            if hostname not in allowed_hosts:
                raise ApiError(
                    status_code=422,
                    code="BROWSER_NAVIGATION_HOST_NOT_ALLOWED",
                    message=(
                        "Browser navigation hostname is not "
                        "operator-allowlisted."
                    ),
                )
        elif step_type == "wait_for_selector":
            timeout_ms = step.get("timeout_ms")
            if (
                isinstance(timeout_ms, bool)
                or not isinstance(timeout_ms, int)
                or timeout_ms > navigation_timeout_ms
            ):
                raise ApiError(
                    status_code=422,
                    code="BROWSER_NAVIGATION_POLICY_REJECTED",
                    message=(
                        "Browser selector wait exceeds operator policy."
                    ),
                )
        elif step_type == "extract_html":
            max_bytes = step.get("max_bytes")
            if (
                isinstance(max_bytes, bool)
                or not isinstance(max_bytes, int)
                or max_bytes > max_dom_bytes
            ):
                raise ApiError(
                    status_code=422,
                    code="BROWSER_NAVIGATION_POLICY_REJECTED",
                    message=(
                        "Browser HTML extraction exceeds operator policy."
                    ),
                )

    if not 1 <= goto_count <= max_pages:
        raise ApiError(
            status_code=422,
            code="BROWSER_NAVIGATION_POLICY_REJECTED",
            message="Browser navigation page count exceeds operator policy.",
        )

    return {
        "schema_version": "rdc.browser-navigation-receipt/v1",
        "request_schema_version": "rdc.browser/v2",
        "request_digest": canonical_fingerprint(browser_navigation),
        "browser_policy_digest": browser_policy_digest,
        "execution_enabled": False,
        "dispatch_enabled": False,
        "browser_network": "none",
        "browser_egress_gateway_required": True,
    }



def _manifest_resource(version: AgentVersion, key: str) -> int:
    resources = version.manifest.get("resources")
    if not isinstance(resources, dict):
        raise ApiError(
            status_code=409,
            code="AGENT_MANIFEST_INVALID",
            message="The immutable Agent version has invalid resource limits.",
        )
    value = resources.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ApiError(
            status_code=409,
            code="AGENT_MANIFEST_INVALID",
            message="The immutable Agent version has invalid resource limits.",
        )
    return value


def _runtime_configuration(
    version: AgentVersion,
    payload: CreateRunRequest,
) -> dict[str, int]:
    maximums = {
        "memory_mb": _manifest_resource(version, "memoryMb"),
        "cpu_millis": _manifest_resource(version, "cpuUnits"),
        "timeout_seconds": _manifest_resource(version, "timeoutSeconds"),
    }
    requested = {
        "memory_mb": payload.runtime.memory_mb,
        "cpu_millis": payload.runtime.cpu_millis,
        "timeout_seconds": payload.runtime.timeout_seconds,
    }
    effective: dict[str, int] = {}
    for key, maximum in maximums.items():
        supplied = requested[key]
        value = maximum if supplied is None else supplied
        if value > maximum:
            raise ApiError(
                status_code=422,
                code="RUNTIME_LIMIT_EXCEEDED",
                message=(
                    f"Requested {key} exceeds the immutable Agent version limit."
                ),
            )
        effective[key] = value
    return effective


def _sanitize_value(value: object, *, key_hint: str = "") -> object:
    lowered = key_hint.casefold()
    if any(part in lowered for part in SENSITIVE_KEY_PARTS):
        return "[REDACTED]"
    if isinstance(value, str):
        clean = ANSI_ESCAPE.sub("", value)
        clean = "".join(
            character
            for character in clean
            if character in "\n\r\t" or ord(character) >= 32
        )
        return clean[:MAX_EVENT_STRING_LENGTH]
    if isinstance(value, dict):
        return {
            str(key)[:128]: _sanitize_value(item, key_hint=str(key))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_sanitize_value(item) for item in value[:1000]]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)[:MAX_EVENT_STRING_LENGTH]


def sanitize_event_payload(payload: dict[str, object]) -> dict[str, object]:
    sanitized = cast(dict[str, object], _sanitize_value(payload))
    try:
        encoded = json.dumps(
            sanitized,
            allow_nan=False,
            separators=(",", ":"),
        ).encode()
    except (TypeError, ValueError) as exc:
        raise ApiError(
            status_code=422,
            code="RUN_EVENT_INVALID",
            message="Run event payload must contain valid JSON values.",
        ) from exc
    if len(encoded) > MAX_EVENT_PAYLOAD_BYTES:
        raise ApiError(
            status_code=413,
            code="RUN_EVENT_TOO_LARGE",
            message="Run event payload cannot exceed 64 KiB.",
        )
    return sanitized


async def append_run_event(
    session: AsyncSession,
    *,
    run: Run,
    event_type: RunEventType | str,
    payload: dict[str, object],
) -> RunEvent:
    if event_type not in PERSISTED_EVENT_TYPES:
        raise ApiError(
            status_code=422,
            code="RUN_EVENT_INVALID",
            message="The Run event type is not supported.",
        )
    lock_material = hashlib.sha256(f"run-event:{run.id}".encode()).digest()[:8]
    lock_key = int.from_bytes(lock_material, byteorder="big", signed=True)
    await session.execute(
        text("SELECT pg_advisory_xact_lock(:lock_key)"),
        {"lock_key": lock_key},
    )
    current = await session.scalar(
        select(func.max(RunEvent.sequence)).where(RunEvent.run_id == run.id)
    )
    sequence = int(current or 0) + 1
    record = RunEvent(
        organization_id=run.organization_id,
        project_id=run.project_id,
        run_id=run.id,
        sequence=sequence,
        event_type=str(event_type),
        payload=sanitize_event_payload(payload),
        created_at=datetime.now(UTC),
    )
    session.add(record)
    await session.flush()
    return record


async def create_run(
    session: AsyncSession,
    *,
    version: AgentVersion,
    user_id: UUID,
    idempotency_key: str,
    payload: CreateRunRequest,
    request_id: str,
) -> dict[str, object]:
    validate_idempotency_key(idempotency_key)
    build = await session.scalar(
        select(Build).where(
            Build.id == payload.build_id,
            Build.organization_id == version.organization_id,
            Build.project_id == version.project_id,
            Build.agent_id == version.agent_id,
            Build.agent_version_id == version.id,
        )
    )
    if build is None:
        raise ApiError(
            status_code=404,
            code="RESOURCE_NOT_FOUND",
            message="The requested resource was not found.",
        )
    if build.status != "SUCCEEDED" or build.artifact_digest is None:
        raise ApiError(
            status_code=409,
            code="BUILD_NOT_READY",
            message="A successful Build artifact is required before creating a Run.",
        )

    runtime = _runtime_configuration(version, payload)
    web_fetch = (
        payload.web_fetch.model_dump(mode="json")
        if payload.web_fetch is not None
        else None
    )
    browser = (
        payload.browser.model_dump(mode="json")
        if payload.browser is not None
        else None
    )
    browser_navigation = (
        payload.browser_navigation.model_dump(mode="json")
        if payload.browser_navigation is not None
        else None
    )
    if web_fetch is not None and _manifest_network(version) != "web-egress":
        raise ApiError(
            status_code=422,
            code="WEB_FETCH_CAPABILITY_REQUIRED",
            message=(
                "This immutable Agent version does not declare "
                "network=web-egress."
            ),
        )

    browser_policy: dict[str, object] | None = None
    browser_policy_digest: str | None = None
    browser_navigation_receipt: dict[str, object] | None = None
    if browser is not None or browser_navigation is not None:
        if _manifest_network(version) != "web-egress":
            raise ApiError(
                status_code=422,
                code="BROWSER_NETWORK_CAPABILITY_REQUIRED",
                message="Browser Runs require immutable network=web-egress.",
            )
        if not _manifest_browser(version):
            raise ApiError(
                status_code=422,
                code="BROWSER_CAPABILITY_REQUIRED",
                message="This immutable Agent version does not declare browser=true.",
            )
        browser_policy = _browser_policy_payload()
        browser_policy_digest = canonical_fingerprint(browser_policy)
        if browser_navigation is not None:
            browser_navigation_receipt = _browser_navigation_receipt(
                browser_navigation,
                browser_policy=browser_policy,
                browser_policy_digest=browser_policy_digest,
            )

    fingerprint = canonical_fingerprint(
        {
            "agent_version_id": str(version.id),
            "build_id": str(build.id),
            "input": payload.input,
            "web_fetch": web_fetch,
            "browser": browser,
            "browser_navigation": browser_navigation,
            "browser_navigation_receipt": browser_navigation_receipt,
            "browser_policy_digest": browser_policy_digest,
            "runtime": runtime,
        }
    )
    key_digest = hashlib.sha256(idempotency_key.encode()).hexdigest()
    endpoint = "POST:/api/v1/agent-versions/{version_id}/runs"
    await acquire_idempotency_lock(
        session,
        organization_id=version.organization_id,
        principal_id=str(user_id),
        endpoint=endpoint,
        key_digest=key_digest,
    )
    existing = await session.scalar(
        select(IdempotencyRecord).where(
            IdempotencyRecord.organization_id == version.organization_id,
            IdempotencyRecord.principal_id == str(user_id),
            IdempotencyRecord.endpoint == endpoint,
            IdempotencyRecord.key_digest == key_digest,
        )
    )
    if existing is not None:
        if existing.request_fingerprint != fingerprint:
            raise ApiError(
                status_code=409,
                code="IDEMPOTENCY_CONFLICT",
                message="This idempotency key was used for a different request.",
            )
        if existing.response_snapshot is None:
            raise ApiError(
                status_code=409,
                code="RESOURCE_CONFLICT",
                message="The original idempotent result is unavailable.",
            )
        return dict(existing.response_snapshot)

    now = datetime.now(UTC)
    input_reference: dict[str, object] = {
        "kind": "inline",
        "value": payload.input,
    }
    if web_fetch is not None:
        input_reference["web_fetch"] = web_fetch
    if browser is not None:
        input_reference["browser"] = browser
        input_reference["browser_policy"] = browser_policy
        input_reference["browser_policy_digest"] = browser_policy_digest
    if browser_navigation is not None:
        input_reference["browser_navigation"] = browser_navigation
        input_reference["browser_navigation_receipt"] = (
            browser_navigation_receipt
        )
        input_reference["browser_policy"] = browser_policy
        input_reference["browser_policy_digest"] = browser_policy_digest

    navigation_receipt_only = browser_navigation is not None
    initial_status = "DRAFT" if navigation_receipt_only else "QUEUED"

    record = Run(
        id=uuid4(),
        organization_id=version.organization_id,
        project_id=version.project_id,
        agent_id=version.agent_id,
        agent_version_id=version.id,
        build_id=build.id,
        status=initial_status,
        input_reference=input_reference,
        runtime_configuration=runtime,
        memory_mb=runtime["memory_mb"],
        cpu_millis=runtime["cpu_millis"],
        timeout_seconds=runtime["timeout_seconds"],
        requested_by_user_id=user_id,
        queued_at=now,
        created_at=now,
        updated_at=now,
        version=1,
    )
    session.add(record)
    await session.flush()
    if not navigation_receipt_only:
        session.add(
            RunCommandOutbox(
                organization_id=record.organization_id,
                project_id=record.project_id,
                run_id=record.id,
                command="START",
                topic="rdc.run.requested.v1",
                payload={
                    "schema_version": "1",
                    "run_id": str(record.id),
                    "organization_id": str(record.organization_id),
                    "project_id": str(record.project_id),
                    "agent_id": str(record.agent_id),
                    "agent_version_id": str(record.agent_version_id),
                    "build_id": str(record.build_id),
                    "runtime": runtime,
                },
                status="PENDING",
                attempts=0,
                available_at=now,
            )
        )
    await append_run_event(
        session,
        run=record,
        event_type="run.status",
        payload={"previous_status": None, "status": initial_status},
    )
    snapshot = json_run_snapshot(record)
    session.add(
        IdempotencyRecord(
            organization_id=record.organization_id,
            principal_id=str(user_id),
            endpoint=endpoint,
            key_digest=key_digest,
            request_fingerprint=fingerprint,
            resource_type="run",
            resource_id=str(record.id),
            response_status=202,
            response_snapshot=snapshot,
            created_at=now,
            expires_at=now + timedelta(hours=24),
        )
    )
    await append_audit_event(
        session,
        organization_id=record.organization_id,
        project_id=record.project_id,
        actor_type="user",
        actor_id=str(user_id),
        action=(
            "run.browser_navigation_intent_recorded"
            if navigation_receipt_only
            else "run.queued"
        ),
        resource_type="run",
        resource_id=str(record.id),
        request_id=request_id,
        details={
            "agent_id": str(record.agent_id),
            "agent_version_id": str(record.agent_version_id),
            "build_id": str(record.build_id),
            "memory_mb": record.memory_mb,
            "cpu_millis": record.cpu_millis,
            "timeout_seconds": record.timeout_seconds,
            "browser_navigation_request_digest": (
                browser_navigation_receipt["request_digest"]
                if browser_navigation_receipt is not None
                else None
            ),
            "browser_navigation_dispatch_enabled": False,
        },
    )
    return snapshot


async def cancel_run(
    session: AsyncSession,
    *,
    record: Run,
    user_id: UUID,
    idempotency_key: str,
    request_id: str,
) -> dict[str, object]:
    validate_idempotency_key(idempotency_key)
    fingerprint = canonical_fingerprint({"run_id": str(record.id)})
    key_digest = hashlib.sha256(idempotency_key.encode()).hexdigest()
    endpoint = "POST:/api/v1/runs/{run_id}/cancel"
    await acquire_idempotency_lock(
        session,
        organization_id=record.organization_id,
        principal_id=str(user_id),
        endpoint=endpoint,
        key_digest=key_digest,
    )
    existing = await session.scalar(
        select(IdempotencyRecord).where(
            IdempotencyRecord.organization_id == record.organization_id,
            IdempotencyRecord.principal_id == str(user_id),
            IdempotencyRecord.endpoint == endpoint,
            IdempotencyRecord.key_digest == key_digest,
        )
    )
    if existing is not None:
        if existing.request_fingerprint != fingerprint:
            raise ApiError(
                status_code=409,
                code="IDEMPOTENCY_CONFLICT",
                message="This idempotency key was used for a different request.",
            )
        if existing.response_snapshot is None:
            raise ApiError(
                status_code=409,
                code="RESOURCE_CONFLICT",
                message="The original idempotent result is unavailable.",
            )
        return dict(existing.response_snapshot)

    now = datetime.now(UTC)
    previous_status = record.status
    if record.status in RUN_TERMINAL_STATUSES:
        pass
    elif record.status in {"DRAFT", "READY", "QUEUED"}:
        record.cancel_requested_at = now
        record.status = "ABORTED"
        record.finished_at = now
        record.version += 1
        record.updated_at = now
        start_command = await session.scalar(
            select(RunCommandOutbox).where(
                RunCommandOutbox.run_id == record.id,
                RunCommandOutbox.command == "START",
            )
        )
        if start_command is not None and start_command.status == "PENDING":
            start_command.status = "CANCELLED"
            start_command.updated_at = now
        await append_run_event(
            session,
            run=record,
            event_type="run.status",
            payload={
                "previous_status": previous_status,
                "status": "ABORTED",
            },
        )
        await append_run_event(
            session,
            run=record,
            event_type="run.completed",
            payload={"status": "ABORTED"},
        )
    elif record.status in RUN_CANCELLABLE_ACTIVE_STATUSES:
        record.cancel_requested_at = now
        record.status = "ABORTING"
        record.version += 1
        record.updated_at = now
        session.add(
            RunCommandOutbox(
                organization_id=record.organization_id,
                project_id=record.project_id,
                run_id=record.id,
                command="CANCEL",
                topic="rdc.run.cancel.requested.v1",
                payload={
                    "schema_version": "1",
                    "run_id": str(record.id),
                    "organization_id": str(record.organization_id),
                    "project_id": str(record.project_id),
                },
                status="PENDING",
                attempts=0,
                available_at=now,
            )
        )
        await append_run_event(
            session,
            run=record,
            event_type="run.status",
            payload={
                "previous_status": previous_status,
                "status": "ABORTING",
            },
        )
    elif record.status != "ABORTING":
        raise ApiError(
            status_code=409,
            code="RUN_STATE_CONFLICT",
            message="The Run cannot be cancelled from its current state.",
        )

    snapshot = json_run_snapshot(record)
    session.add(
        IdempotencyRecord(
            organization_id=record.organization_id,
            principal_id=str(user_id),
            endpoint=endpoint,
            key_digest=key_digest,
            request_fingerprint=fingerprint,
            resource_type="run",
            resource_id=str(record.id),
            response_status=202,
            response_snapshot=snapshot,
            created_at=now,
            expires_at=now + timedelta(hours=24),
        )
    )
    await append_audit_event(
        session,
        organization_id=record.organization_id,
        project_id=record.project_id,
        actor_type="user",
        actor_id=str(user_id),
        action="run.cancel_requested",
        resource_type="run",
        resource_id=str(record.id),
        request_id=request_id,
        details={
            "previous_status": previous_status,
            "resulting_status": record.status,
        },
    )
    return snapshot


async def list_project_runs(
    session: AsyncSession,
    *,
    project_id: UUID,
    cursor: CursorPosition | None,
    limit: int,
    status: str | None = None,
) -> tuple[list[Run], bool]:
    statement = select(Run).where(Run.project_id == project_id)
    if status is not None:
        statement = statement.where(Run.status == status)
    if cursor is not None:
        statement = statement.where(
            or_(
                Run.queued_at < cursor.created_at,
                and_(
                    Run.queued_at == cursor.created_at,
                    Run.id < cursor.resource_id,
                ),
            )
        )
    rows = list(
        (
            await session.scalars(
                statement.order_by(
                    Run.queued_at.desc(),
                    Run.id.desc(),
                ).limit(limit + 1)
            )
        ).all()
    )
    return rows[:limit], len(rows) > limit


async def list_run_events(
    session: AsyncSession,
    *,
    run_id: UUID,
    after_sequence: int,
    limit: int = 500,
) -> list[RunEvent]:
    return list(
        (
            await session.scalars(
                select(RunEvent)
                .where(
                    RunEvent.run_id == run_id,
                    RunEvent.sequence > after_sequence,
                )
                .order_by(RunEvent.sequence.asc())
                .limit(limit)
            )
        ).all()
    )


async def minimum_run_event_sequence(
    session: AsyncSession,
    *,
    run_id: UUID,
) -> int | None:
    value = await session.scalar(
        select(func.min(RunEvent.sequence)).where(RunEvent.run_id == run_id)
    )
    return int(value) if value is not None else None
