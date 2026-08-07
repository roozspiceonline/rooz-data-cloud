import io
import json
import re
import stat
import zipfile
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import cast

from pydantic import ValidationError

from ..agent_schemas import AgentManifest

_DRIVE_PREFIX = re.compile(r"^[A-Za-z]:")
_NESTED_ARCHIVE_SUFFIXES = (
    ".7z",
    ".bz2",
    ".gz",
    ".rar",
    ".tar",
    ".tgz",
    ".xz",
    ".zip",
)


class SourceArchiveError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class SourceArchiveInspection:
    manifest: dict[str, object]
    manifest_digest: str
    file_count: int
    expanded_size_bytes: int
    compressed_size_bytes: int
    paths: tuple[str, ...]


def canonical_manifest_digest(manifest: dict[str, object]) -> str:
    import hashlib

    encoded = json.dumps(
        manifest,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _safe_archive_path(name: str) -> PurePosixPath:
    if not name or "\x00" in name or "\\" in name:
        raise SourceArchiveError(
            "SOURCE_ARCHIVE_PATH_INVALID",
            "Archive paths must be non-empty POSIX relative paths.",
        )
    if name.startswith("/") or _DRIVE_PREFIX.match(name):
        raise SourceArchiveError(
            "SOURCE_ARCHIVE_PATH_INVALID",
            "Archive paths cannot be absolute or drive-qualified.",
        )
    path = PurePosixPath(name)
    if any(part in {"", ".", ".."} for part in path.parts):
        raise SourceArchiveError(
            "SOURCE_ARCHIVE_PATH_INVALID",
            "Archive paths cannot contain empty, current, or parent segments.",
        )
    return path


def inspect_source_archive(
    content: bytes,
    *,
    expected_agent_slug: str,
    max_archive_bytes: int,
    max_expanded_bytes: int,
    max_files: int,
    max_single_file_bytes: int,
    max_compression_ratio: float,
    max_path_depth: int = 16,
) -> SourceArchiveInspection:
    if not content:
        raise SourceArchiveError(
            "SOURCE_ARCHIVE_EMPTY",
            "The source archive is empty.",
        )
    if len(content) > max_archive_bytes:
        raise SourceArchiveError(
            "SOURCE_ARCHIVE_TOO_LARGE",
            "The compressed source archive exceeds the configured limit.",
        )

    try:
        archive = zipfile.ZipFile(io.BytesIO(content))
    except zipfile.BadZipFile as exc:
        raise SourceArchiveError(
            "SOURCE_ARCHIVE_INVALID",
            "The uploaded source must be a valid ZIP archive.",
        ) from exc

    with archive:
        entries = archive.infolist()
        if not entries:
            raise SourceArchiveError(
                "SOURCE_ARCHIVE_EMPTY",
                "The source archive does not contain any files.",
            )
        if len(entries) > max_files:
            raise SourceArchiveError(
                "SOURCE_ARCHIVE_FILE_LIMIT",
                "The source archive contains too many entries.",
            )

        normalized_paths: set[str] = set()
        normalized_casefold_paths: set[str] = set()
        file_paths: list[str] = []
        expanded_size = 0
        compressed_size = 0

        for entry in entries:
            path = _safe_archive_path(entry.filename)
            normalized = path.as_posix().rstrip("/")
            if len(path.parts) > max_path_depth:
                raise SourceArchiveError(
                    "SOURCE_ARCHIVE_DEPTH_LIMIT",
                    "The source archive exceeds the maximum path depth.",
                )
            if (
                normalized in normalized_paths
                or normalized.casefold() in normalized_casefold_paths
            ):
                raise SourceArchiveError(
                    "SOURCE_ARCHIVE_DUPLICATE_PATH",
                    "The source archive contains duplicate normalized paths.",
                )
            normalized_paths.add(normalized)
            normalized_casefold_paths.add(normalized.casefold())

            mode = entry.external_attr >> 16
            if mode and (
                stat.S_ISLNK(mode)
                or stat.S_ISCHR(mode)
                or stat.S_ISBLK(mode)
                or stat.S_ISFIFO(mode)
                or stat.S_ISSOCK(mode)
            ):
                raise SourceArchiveError(
                    "SOURCE_ARCHIVE_SPECIAL_FILE",
                    "Links, devices, sockets, and special files are prohibited.",
                )
            if entry.flag_bits & 0x1:
                raise SourceArchiveError(
                    "SOURCE_ARCHIVE_ENCRYPTED",
                    "Encrypted ZIP entries are prohibited.",
                )
            if entry.is_dir():
                continue
            if entry.file_size > max_single_file_bytes:
                raise SourceArchiveError(
                    "SOURCE_ARCHIVE_FILE_TOO_LARGE",
                    "A source file exceeds the configured per-file limit.",
                )
            if normalized.casefold().endswith(_NESTED_ARCHIVE_SUFFIXES):
                raise SourceArchiveError(
                    "SOURCE_ARCHIVE_NESTED_ARCHIVE",
                    "Nested archives are prohibited in Agent source uploads.",
                )

            expanded_size += entry.file_size
            compressed_size += entry.compress_size
            if expanded_size > max_expanded_bytes:
                raise SourceArchiveError(
                    "SOURCE_ARCHIVE_EXPANDED_LIMIT",
                    "The expanded source archive exceeds the configured limit.",
                )
            file_paths.append(normalized)

        ratio = expanded_size / max(compressed_size, 1)
        if ratio > max_compression_ratio:
            raise SourceArchiveError(
                "SOURCE_ARCHIVE_COMPRESSION_RATIO",
                "The source archive compression ratio exceeds the safe limit.",
            )

        verified_expanded_size = 0
        for entry in entries:
            if entry.is_dir():
                continue
            entry_size = 0
            try:
                with archive.open(entry, "r") as source:
                    while True:
                        chunk = source.read(1024 * 1024)
                        if not chunk:
                            break
                        entry_size += len(chunk)
                        verified_expanded_size += len(chunk)
                        if entry_size > max_single_file_bytes:
                            raise SourceArchiveError(
                                "SOURCE_ARCHIVE_FILE_TOO_LARGE",
                                "A source file exceeds the configured per-file limit.",
                            )
                        if verified_expanded_size > max_expanded_bytes:
                            raise SourceArchiveError(
                                "SOURCE_ARCHIVE_EXPANDED_LIMIT",
                                "The expanded source archive exceeds the configured limit.",
                            )
            except SourceArchiveError:
                raise
            except (EOFError, NotImplementedError, RuntimeError, zipfile.BadZipFile) as exc:
                raise SourceArchiveError(
                    "SOURCE_ARCHIVE_CORRUPT",
                    "A ZIP entry failed integrity verification.",
                ) from exc
            if entry_size != entry.file_size:
                raise SourceArchiveError(
                    "SOURCE_ARCHIVE_CORRUPT",
                    "A ZIP entry size does not match its directory metadata.",
                )
        if verified_expanded_size != expanded_size:
            raise SourceArchiveError(
                "SOURCE_ARCHIVE_CORRUPT",
                "The ZIP expanded size does not match its directory metadata.",
            )

        if "agent.json" not in normalized_paths:
            raise SourceArchiveError(
                "SOURCE_MANIFEST_MISSING",
                "The archive root must contain agent.json.",
            )

        try:
            manifest_bytes = archive.read("agent.json")
        except (KeyError, NotImplementedError, RuntimeError) as exc:
            raise SourceArchiveError(
                "SOURCE_MANIFEST_MISSING",
                "The archive root must contain a readable agent.json.",
            ) from exc
        if len(manifest_bytes) > 262_144:
            raise SourceArchiveError(
                "SOURCE_MANIFEST_TOO_LARGE",
                "agent.json cannot exceed 256 KiB.",
            )
        try:
            raw_manifest = json.loads(manifest_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SourceArchiveError(
                "SOURCE_MANIFEST_INVALID",
                "agent.json must contain valid UTF-8 JSON.",
            ) from exc
        if not isinstance(raw_manifest, dict):
            raise SourceArchiveError(
                "SOURCE_MANIFEST_INVALID",
                "agent.json must contain a JSON object.",
            )
        try:
            validated = AgentManifest.model_validate(raw_manifest)
        except ValidationError as exc:
            raise SourceArchiveError(
                "SOURCE_MANIFEST_INVALID",
                "agent.json does not satisfy the Rooz Agent manifest schema.",
            ) from exc
        if validated.name != expected_agent_slug:
            raise SourceArchiveError(
                "SOURCE_MANIFEST_AGENT_MISMATCH",
                "agent.json name must match the target Agent slug.",
            )

        manifest = cast(
            dict[str, object],
            validated.model_dump(mode="json", by_alias=True),
        )
        schema_paths = [
            validated.schemas.input,
            validated.schemas.output,
            validated.schemas.dataset,
        ]
        for schema_path in schema_paths:
            if schema_path is not None and schema_path not in file_paths:
                raise SourceArchiveError(
                    "SOURCE_SCHEMA_MISSING",
                    f"The manifest references missing schema path: {schema_path}",
                )

        return SourceArchiveInspection(
            manifest=manifest,
            manifest_digest=canonical_manifest_digest(manifest),
            file_count=len(file_paths),
            expanded_size_bytes=expanded_size,
            compressed_size_bytes=compressed_size,
            paths=tuple(sorted(file_paths)),
        )
