#!/usr/bin/env python3
"""Credential-safe PostgreSQL backup, restore, and migration rollback drill."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import BinaryIO
from urllib.parse import parse_qs, quote, unquote, urlsplit
from uuid import uuid4

ARCHIVE_SUFFIX = ".dump"
MANIFEST_SUFFIX = ".manifest.json"
MAX_ARCHIVE_BYTES = 1_099_511_627_776
REVISION_PATTERN = re.compile(r"^[A-Za-z0-9_]{1,64}$")
DEPLOYMENT_PATTERN = re.compile(
    r"^(?P<environment>staging|production)-[a-z0-9][a-z0-9-]{2,62}$"
)


class RecoveryDrillError(RuntimeError):
    """A production recovery drill failed without exposing command output."""


@dataclass(frozen=True)
class PostgresConnection:
    host: str
    port: int
    user: str
    password: str | None
    database: str
    sslmode: str | None


def parse_database_url(raw: str) -> PostgresConnection:
    try:
        parsed = urlsplit(raw)
        port = parsed.port or 5432
        query = parse_qs(parsed.query, strict_parsing=True)
    except ValueError as exc:
        raise RecoveryDrillError("PostgreSQL recovery URL is invalid.") from exc
    if parsed.scheme not in {"postgres", "postgresql", "postgresql+asyncpg"}:
        raise RecoveryDrillError("Recovery URL must use PostgreSQL.")
    database = unquote(parsed.path.removeprefix("/"))
    if (
        parsed.hostname is None
        or not parsed.username
        or not database
        or "/" in database
        or not 1 <= port <= 65535
    ):
        raise RecoveryDrillError("PostgreSQL recovery URL is incomplete.")
    if set(query) - {"sslmode"} or any(len(values) != 1 for values in query.values()):
        raise RecoveryDrillError("PostgreSQL recovery URL query is unsupported.")
    sslmode = query.get("sslmode", [None])[0]
    if sslmode not in {None, "disable", "prefer", "require", "verify-ca", "verify-full"}:
        raise RecoveryDrillError("PostgreSQL recovery SSL mode is invalid.")
    return PostgresConnection(
        host=parsed.hostname,
        port=port,
        user=unquote(parsed.username),
        password=(unquote(parsed.password) if parsed.password is not None else None),
        database=database,
        sslmode=sslmode,
    )


def postgres_environment(
    connection: PostgresConnection,
    *,
    database: str | None = None,
) -> dict[str, str]:
    environment = dict(os.environ)
    for name in (
        "RDC_BACKUP_DATABASE_URL",
        "RDC_RESTORE_DATABASE_URL",
        "RDC_DATABASE_URL",
        "PGPASSWORD",
        "PGSERVICE",
        "PGSERVICEFILE",
    ):
        environment.pop(name, None)
    environment.update(
        {
            "PGAPPNAME": "rdc-production-recovery-drill",
            "PGCONNECT_TIMEOUT": "10",
            "PGDATABASE": database or connection.database,
            "PGHOST": connection.host,
            "PGPORT": str(connection.port),
            "PGUSER": connection.user,
        }
    )
    if connection.password is not None:
        environment["PGPASSWORD"] = connection.password
    if connection.sslmode is not None:
        environment["PGSSLMODE"] = connection.sslmode
    return environment


def _run(
    arguments: list[str],
    *,
    environment: dict[str, str],
    timeout_seconds: int,
    stdout: BinaryIO | int | None = None,
    capture_stdout: bool = False,
    cwd: Path | None = None,
) -> str:
    try:
        completed = subprocess.run(
            arguments,
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=(subprocess.PIPE if capture_stdout else stdout or subprocess.DEVNULL),
            stderr=subprocess.DEVNULL,
            timeout=timeout_seconds,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        command = Path(arguments[0]).name
        raise RecoveryDrillError(
            f"Recovery drill {command} command could not complete."
        ) from exc
    if completed.returncode != 0:
        command = Path(arguments[0]).name
        raise RecoveryDrillError(f"Recovery drill {command} command failed.")
    if not capture_stdout:
        return ""
    output = completed.stdout
    if not isinstance(output, bytes) or len(output) > 4096:
        raise RecoveryDrillError("Recovery drill command output is invalid.")
    try:
        return output.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise RecoveryDrillError("Recovery drill command output is invalid.") from exc


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_deployment(environment: str, deployment_id: str) -> None:
    matched = DEPLOYMENT_PATTERN.fullmatch(deployment_id)
    if matched is None or matched.group("environment") != environment:
        raise RecoveryDrillError("Deployment identity does not match the environment.")


def _archive_paths(value: Path) -> tuple[Path, Path]:
    if value.suffix != ARCHIVE_SUFFIX or value.is_symlink():
        raise RecoveryDrillError("Backup archive path is invalid.")
    parent = value.parent
    if not parent.is_dir() or parent.is_symlink():
        raise RecoveryDrillError("Backup archive directory is invalid.")
    archive = parent.resolve() / value.name
    manifest = archive.with_name(archive.name + MANIFEST_SUFFIX)
    if archive.exists() or manifest.exists():
        raise RecoveryDrillError("Backup output already exists.")
    return archive, manifest


def new_backup_archive_path(directory: Path, deployment_id: str) -> Path:
    if not directory.is_dir() or directory.is_symlink():
        raise RecoveryDrillError("Backup archive directory is invalid.")
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return directory / f"{deployment_id}-{timestamp}-{uuid4().hex[:12]}.dump"


def _database_revision(
    connection: PostgresConnection,
    *,
    database: str,
    timeout_seconds: int,
) -> str:
    revision = _run(
        [
            "psql",
            "--no-psqlrc",
            "--tuples-only",
            "--no-align",
            "--command",
            "SELECT version_num FROM alembic_version",
        ],
        environment=postgres_environment(connection, database=database),
        timeout_seconds=timeout_seconds,
        capture_stdout=True,
    )
    if REVISION_PATTERN.fullmatch(revision) is None:
        raise RecoveryDrillError("Database migration revision is invalid.")
    return revision


def run_backup(
    *,
    connection: PostgresConnection,
    archive_path: Path,
    environment: str,
    deployment_id: str,
    timeout_seconds: int,
) -> dict[str, object]:
    _validate_deployment(environment, deployment_id)
    archive, manifest_path = _archive_paths(archive_path)
    revision = _database_revision(
        connection,
        database=connection.database,
        timeout_seconds=timeout_seconds,
    )
    partial = archive.with_name(f".{archive.name}.partial-{uuid4().hex}")
    try:
        with partial.open("xb") as output:
            os.chmod(partial, 0o600)
            _run(
                ["pg_dump", "--format=custom", "--no-owner", "--no-privileges"],
                environment=postgres_environment(connection),
                timeout_seconds=timeout_seconds,
                stdout=output,
            )
            output.flush()
            os.fsync(output.fileno())
        size = partial.stat().st_size
        if not 1 <= size <= MAX_ARCHIVE_BYTES:
            raise RecoveryDrillError("Backup archive size is invalid.")
        partial.replace(archive)
        checksum = _sha256(archive)
        manifest: dict[str, object] = {
            "schema_version": "rdc.production-backup/v1",
            "created_at": datetime.now(UTC).isoformat(),
            "environment": environment,
            "deployment_id": deployment_id,
            "archive_file": archive.name,
            "size_bytes": size,
            "sha256": checksum,
            "alembic_revision": revision,
        }
        with manifest_path.open("x", encoding="utf-8") as destination:
            os.chmod(manifest_path, 0o600)
            json.dump(manifest, destination, sort_keys=True, separators=(",", ":"))
            destination.write("\n")
            destination.flush()
            os.fsync(destination.fileno())
        return manifest
    except Exception:
        partial.unlink(missing_ok=True)
        if not manifest_path.exists():
            archive.unlink(missing_ok=True)
        raise


def _load_manifest(
    archive: Path,
    *,
    environment: str,
    deployment_id: str,
) -> dict[str, object]:
    manifest_path = archive.with_name(archive.name + MANIFEST_SUFFIX)
    if (
        archive.suffix != ARCHIVE_SUFFIX
        or archive.is_symlink()
        or manifest_path.is_symlink()
        or not archive.is_file()
        or not manifest_path.is_file()
    ):
        raise RecoveryDrillError("Backup archive or manifest is unavailable.")
    if not 1 <= archive.stat().st_size <= MAX_ARCHIVE_BYTES:
        raise RecoveryDrillError("Backup archive size is invalid.")
    try:
        decoded = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RecoveryDrillError("Backup manifest is invalid.") from exc
    required = {
        "schema_version",
        "created_at",
        "environment",
        "deployment_id",
        "archive_file",
        "size_bytes",
        "sha256",
        "alembic_revision",
    }
    if not isinstance(decoded, dict) or set(decoded) != required:
        raise RecoveryDrillError("Backup manifest is invalid.")
    if (
        decoded["schema_version"] != "rdc.production-backup/v1"
        or decoded["environment"] != environment
        or decoded["deployment_id"] != deployment_id
        or decoded["archive_file"] != archive.name
        or decoded["size_bytes"] != archive.stat().st_size
        or decoded["sha256"] != _sha256(archive)
        or not isinstance(decoded["alembic_revision"], str)
        or REVISION_PATTERN.fullmatch(decoded["alembic_revision"]) is None
    ):
        raise RecoveryDrillError("Backup manifest verification failed.")
    return {str(key): value for key, value in decoded.items()}


def _async_database_url(connection: PostgresConnection, database: str) -> str:
    credentials = quote(connection.user, safe="")
    if connection.password is not None:
        credentials += ":" + quote(connection.password, safe="")
    host = connection.host
    if ":" in host:
        host = f"[{host}]"
    value = (
        f"postgresql+asyncpg://{credentials}@{host}:{connection.port}/"
        + quote(database, safe="")
    )
    if connection.sslmode is not None:
        value += "?ssl=" + quote(connection.sslmode, safe="")
    return value


def run_restore_drill(
    *,
    connection: PostgresConnection,
    archive_path: Path,
    environment: str,
    deployment_id: str,
    api_root: Path,
    timeout_seconds: int,
) -> dict[str, object]:
    _validate_deployment(environment, deployment_id)
    if archive_path.is_symlink():
        raise RecoveryDrillError("Backup archive path is invalid.")
    archive = archive_path.resolve(strict=True)
    manifest = _load_manifest(
        archive,
        environment=environment,
        deployment_id=deployment_id,
    )
    alembic = api_root.resolve() / ".venv/bin/alembic"
    if not alembic.is_file() or not os.access(alembic, os.X_OK):
        raise RecoveryDrillError("Alembic executable is unavailable.")
    drill_database = "rdc_restore_drill_" + uuid4().hex[:16]
    created = False
    failure: Exception | None = None
    try:
        _run(
            ["createdb", "--maintenance-db=postgres", drill_database],
            environment=postgres_environment(connection, database="postgres"),
            timeout_seconds=timeout_seconds,
        )
        created = True
        _run(
            [
                "pg_restore",
                "--exit-on-error",
                "--single-transaction",
                "--no-owner",
                "--no-privileges",
                "--dbname",
                drill_database,
                str(archive),
            ],
            environment=postgres_environment(connection, database=drill_database),
            timeout_seconds=timeout_seconds,
        )
        restored_revision = _database_revision(
            connection,
            database=drill_database,
            timeout_seconds=timeout_seconds,
        )
        if restored_revision != manifest["alembic_revision"]:
            raise RecoveryDrillError("Restored migration revision does not match backup.")
        alembic_environment = postgres_environment(
            connection,
            database=drill_database,
        )
        # The disposable drill only needs the database URL. Running Alembic with
        # RDC_ENV=production would also require the API's unrelated runtime
        # secrets, which the least-privileged backup unit intentionally lacks.
        alembic_environment["RDC_ENV"] = "test"
        alembic_environment["RDC_DATABASE_URL"] = _async_database_url(
            connection,
            drill_database,
        )
        head_output = _run(
            [str(alembic), "heads"],
            environment=alembic_environment,
            timeout_seconds=timeout_seconds,
            capture_stdout=True,
            cwd=api_root.resolve(),
        )
        head_revision = head_output.split(maxsplit=1)[0]
        if REVISION_PATTERN.fullmatch(head_revision) is None:
            raise RecoveryDrillError("Alembic head revision is invalid.")
        _run(
            [str(alembic), "downgrade", "-1"],
            environment=alembic_environment,
            timeout_seconds=timeout_seconds,
            cwd=api_root.resolve(),
        )
        _run(
            [str(alembic), "upgrade", "head"],
            environment=alembic_environment,
            timeout_seconds=timeout_seconds,
            cwd=api_root.resolve(),
        )
        final_revision = _database_revision(
            connection,
            database=drill_database,
            timeout_seconds=timeout_seconds,
        )
        if final_revision != head_revision:
            raise RecoveryDrillError("Migration rollback drill did not restore revision.")
    except RecoveryDrillError as exc:
        failure = exc
    finally:
        if created:
            try:
                _run(
                    ["dropdb", "--maintenance-db=postgres", drill_database],
                    environment=postgres_environment(connection, database="postgres"),
                    timeout_seconds=timeout_seconds,
                )
            except RecoveryDrillError:
                if failure is not None:
                    raise RecoveryDrillError(
                        "Recovery drill and disposable database cleanup failed."
                    ) from failure
                raise
    if failure is not None:
        raise failure
    return {
        "schema_version": "rdc.production-recovery-drill/v1",
        "environment": environment,
        "deployment_id": deployment_id,
        "backup_revision": manifest["alembic_revision"],
        "restore_verified": True,
        "migration_rollback_verified": True,
        "disposable_database_removed": True,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("backup", "restore-drill"))
    output = parser.add_mutually_exclusive_group(required=True)
    output.add_argument("--archive", type=Path)
    output.add_argument("--archive-dir", type=Path)
    parser.add_argument(
        "--api-root",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "apps/api",
    )
    parser.add_argument("--timeout-seconds", type=int, default=600)
    arguments = parser.parse_args()
    if not 30 <= arguments.timeout_seconds <= 3600:
        raise SystemExit("Timeout must be between 30 and 3600 seconds.")
    environment = os.environ.get("RDC_ENV", "")
    deployment_id = os.environ.get("RDC_DEPLOYMENT_ID", "")
    database_url_variable = (
        "RDC_BACKUP_DATABASE_URL"
        if arguments.command == "backup"
        else "RDC_RESTORE_DATABASE_URL"
    )
    raw_database_url = os.environ.get(database_url_variable, "")
    try:
        connection = parse_database_url(raw_database_url)
        if arguments.command == "backup":
            archive_path = arguments.archive
            if archive_path is None:
                archive_path = new_backup_archive_path(
                    arguments.archive_dir,
                    deployment_id,
                )
            result = run_backup(
                connection=connection,
                archive_path=archive_path,
                environment=environment,
                deployment_id=deployment_id,
                timeout_seconds=arguments.timeout_seconds,
            )
        else:
            if arguments.archive is None:
                raise RecoveryDrillError(
                    "Restore drill requires one explicit backup archive."
                )
            result = run_restore_drill(
                connection=connection,
                archive_path=arguments.archive,
                environment=environment,
                deployment_id=deployment_id,
                api_root=arguments.api_root,
                timeout_seconds=arguments.timeout_seconds,
            )
    except RecoveryDrillError as exc:
        raise SystemExit(str(exc)) from exc
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
