import hashlib
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, cast

import anyio
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from .config import get_settings


class StorageBackendError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class StoredObjectHead:
    size_bytes: int
    content_type: str
    metadata: dict[str, str]
    etag: str | None


def _client(endpoint_url: str) -> Any:
    settings = get_settings()
    return boto3.client(
        "s3",
        endpoint_url=endpoint_url,
        aws_access_key_id=settings.s3_access_key,
        aws_secret_access_key=settings.s3_secret_key,
        region_name=settings.s3_region,
        config=Config(
            signature_version="s3v4",
            s3={"addressing_style": "path"},
            connect_timeout=5,
            read_timeout=30,
            retries={"max_attempts": 3, "mode": "standard"},
        ),
    )


@lru_cache
def internal_s3_client() -> Any:
    return _client(get_settings().s3_endpoint)


@lru_cache
def public_s3_client() -> Any:
    return _client(get_settings().s3_public_endpoint)


class S3ObjectStorage:
    def __init__(self) -> None:
        self.settings = get_settings()
        self.bucket = self.settings.s3_bucket

    async def ensure_bucket(self) -> None:
        def operation() -> None:
            client = internal_s3_client()
            try:
                client.head_bucket(Bucket=self.bucket)
                return
            except ClientError as exc:
                status = int(
                    exc.response.get("ResponseMetadata", {}).get(
                        "HTTPStatusCode", 0
                    )
                )
                if status not in {403, 404}:
                    raise StorageBackendError(
                        "STORAGE_UNAVAILABLE",
                        "Object storage could not be verified.",
                    ) from exc
            try:
                if self.settings.s3_region == "us-east-1":
                    client.create_bucket(Bucket=self.bucket)
                else:
                    client.create_bucket(
                        Bucket=self.bucket,
                        CreateBucketConfiguration={
                            "LocationConstraint": self.settings.s3_region
                        },
                    )
            except ClientError as exc:
                code = str(exc.response.get("Error", {}).get("Code", ""))
                if code not in {
                    "BucketAlreadyExists",
                    "BucketAlreadyOwnedByYou",
                }:
                    raise StorageBackendError(
                        "STORAGE_UNAVAILABLE",
                        "Object storage bucket creation failed.",
                    ) from exc

        await anyio.to_thread.run_sync(operation)

    async def create_presigned_upload(
        self,
        *,
        object_key: str,
        object_id: str,
        content_type: str,
        sha256_digest: str,
        size_bytes: int,
        expires_seconds: int,
    ) -> dict[str, object]:
        await self.ensure_bucket()

        def operation() -> dict[str, object]:
            client = public_s3_client()
            fields = {
                "Content-Type": content_type,
                "x-amz-meta-rdc-object-id": object_id,
                "x-amz-meta-sha256": sha256_digest,
            }
            conditions: list[object] = [
                {"Content-Type": content_type},
                {"x-amz-meta-rdc-object-id": object_id},
                {"x-amz-meta-sha256": sha256_digest},
                ["content-length-range", size_bytes, size_bytes],
            ]
            result = client.generate_presigned_post(
                Bucket=self.bucket,
                Key=object_key,
                Fields=fields,
                Conditions=conditions,
                ExpiresIn=expires_seconds,
            )
            return {
                "url": str(result["url"]),
                "fields": {
                    str(key): str(value)
                    for key, value in dict(result["fields"]).items()
                },
            }

        return await anyio.to_thread.run_sync(operation)

    async def create_presigned_download(
        self,
        *,
        object_key: str,
        file_name: str,
        expires_seconds: int,
    ) -> str:
        await self.ensure_bucket()

        def operation() -> str:
            result = public_s3_client().generate_presigned_url(
                "get_object",
                Params={
                    "Bucket": self.bucket,
                    "Key": object_key,
                    "ResponseContentDisposition": (
                        'attachment; filename="' + file_name.replace('"', "") + '"'
                    ),
                },
                ExpiresIn=expires_seconds,
            )
            return str(result)

        return await anyio.to_thread.run_sync(operation)

    async def head_object(self, *, object_key: str) -> StoredObjectHead:
        await self.ensure_bucket()

        def operation() -> StoredObjectHead:
            try:
                result = internal_s3_client().head_object(
                    Bucket=self.bucket,
                    Key=object_key,
                )
            except ClientError as exc:
                status = int(
                    exc.response.get("ResponseMetadata", {}).get(
                        "HTTPStatusCode", 0
                    )
                )
                if status == 404:
                    raise StorageBackendError(
                        "STORAGE_OBJECT_NOT_UPLOADED",
                        "The expected object has not been uploaded.",
                    ) from exc
                raise StorageBackendError(
                    "STORAGE_UNAVAILABLE",
                    "Object storage metadata could not be read.",
                ) from exc
            metadata = {
                str(key).casefold(): str(value)
                for key, value in dict(result.get("Metadata", {})).items()
            }
            etag_value = result.get("ETag")
            return StoredObjectHead(
                size_bytes=int(result["ContentLength"]),
                content_type=str(
                    result.get("ContentType") or "application/octet-stream"
                ),
                metadata=metadata,
                etag=str(etag_value).strip('"') if etag_value else None,
            )

        return await anyio.to_thread.run_sync(operation)

    async def read_object(
        self,
        *,
        object_key: str,
        max_bytes: int,
    ) -> bytes:
        await self.ensure_bucket()

        def operation() -> bytes:
            try:
                response = internal_s3_client().get_object(
                    Bucket=self.bucket,
                    Key=object_key,
                )
            except ClientError as exc:
                raise StorageBackendError(
                    "STORAGE_UNAVAILABLE",
                    "Object storage content could not be read.",
                ) from exc
            body = response["Body"]
            chunks: list[bytes] = []
            total = 0
            try:
                while True:
                    chunk = body.read(1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_bytes:
                        raise StorageBackendError(
                            "STORAGE_OBJECT_TOO_LARGE",
                            "The stored object exceeds the configured limit.",
                        )
                    chunks.append(bytes(chunk))
            finally:
                body.close()
            return b"".join(chunks)

        return await anyio.to_thread.run_sync(operation)

    async def delete_object(self, *, object_key: str) -> None:
        await self.ensure_bucket()

        def operation() -> None:
            try:
                internal_s3_client().delete_object(
                    Bucket=self.bucket,
                    Key=object_key,
                )
            except ClientError as exc:
                raise StorageBackendError(
                    "STORAGE_UNAVAILABLE",
                    "The rejected object could not be removed.",
                ) from exc

        await anyio.to_thread.run_sync(operation)


def capability_digest(value: object) -> bytes:
    import json

    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).digest()


def public_upload_payload(value: dict[str, object]) -> tuple[str, dict[str, str]]:
    return (
        cast(str, value["url"]),
        cast(dict[str, str], value["fields"]),
    )


object_storage = S3ObjectStorage()
