#!/usr/bin/env python3
"""Verify versioned object recovery using one bounded operator-owned canary key."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from typing import Protocol
from urllib.parse import urlsplit
from uuid import uuid4

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

DEPLOYMENT_PATTERN = re.compile(
    r"^(?P<environment>staging|production)-[a-z0-9][a-z0-9-]{2,62}$"
)
MAX_VERSION_RECORDS = 32


class ObjectRecoveryDrillError(RuntimeError):
    pass


class ObjectStorageClient(Protocol):
    def get_bucket_versioning(self, *, Bucket: str) -> dict[str, object]: ...

    def put_object(self, **kwargs: object) -> dict[str, object]: ...

    def delete_object(self, *, Bucket: str, Key: str) -> dict[str, object]: ...

    def get_object(self, **kwargs: object) -> dict[str, object]: ...

    def list_object_versions(self, **kwargs: object) -> dict[str, object]: ...

    def delete_objects(self, **kwargs: object) -> dict[str, object]: ...


def validate_configuration(
    *,
    environment: str,
    deployment_id: str,
    endpoint: str,
    bucket: str,
) -> None:
    matched = DEPLOYMENT_PATTERN.fullmatch(deployment_id)
    parsed = urlsplit(endpoint)
    if matched is None or matched.group("environment") != environment:
        raise ObjectRecoveryDrillError(
            "Deployment identity does not match the environment."
        )
    if (
        parsed.scheme != "https"
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ObjectRecoveryDrillError(
            "Object-storage recovery endpoint must be credential-free HTTPS."
        )
    if bucket != f"rdc-{environment}-{deployment_id.removeprefix(environment + '-')}":
        raise ObjectRecoveryDrillError(
            "Object-storage bucket does not match the deployment identity."
        )


def _cleanup_canary(
    client: ObjectStorageClient,
    *,
    bucket: str,
    key: str,
    expected_version_ids: set[str],
) -> int:
    response = client.list_object_versions(
        Bucket=bucket,
        Prefix=key,
        MaxKeys=MAX_VERSION_RECORDS,
    )
    if response.get("IsTruncated") is True:
        raise ObjectRecoveryDrillError("Canary cleanup exceeded its bound.")
    targets: list[dict[str, str]] = []
    observed_version_ids: set[str] = set()
    for collection in ("Versions", "DeleteMarkers"):
        records = response.get(collection, [])
        if not isinstance(records, list):
            raise ObjectRecoveryDrillError("Canary version listing is invalid.")
        for record in records:
            if (
                not isinstance(record, dict)
                or record.get("Key") != key
                or not isinstance(record.get("VersionId"), str)
            ):
                raise ObjectRecoveryDrillError("Canary version identity is invalid.")
            targets.append({"Key": key, "VersionId": record["VersionId"]})
            observed_version_ids.add(record["VersionId"])
    if len(targets) > MAX_VERSION_RECORDS:
        raise ObjectRecoveryDrillError("Canary cleanup exceeded its bound.")
    if not expected_version_ids.issubset(observed_version_ids):
        raise ObjectRecoveryDrillError("Canary versions were not completely listed.")
    if targets:
        result = client.delete_objects(
            Bucket=bucket,
            Delete={"Objects": targets, "Quiet": True},
        )
        if result.get("Errors"):
            raise ObjectRecoveryDrillError("Canary cleanup failed.")
    return len(targets)


def run_object_recovery_drill(
    client: ObjectStorageClient,
    *,
    environment: str,
    deployment_id: str,
    endpoint: str,
    bucket: str,
    kms_key_id: str | None,
) -> dict[str, object]:
    validate_configuration(
        environment=environment,
        deployment_id=deployment_id,
        endpoint=endpoint,
        bucket=bucket,
    )
    try:
        versioning = client.get_bucket_versioning(Bucket=bucket)
    except (BotoCoreError, ClientError, OSError) as exc:
        raise ObjectRecoveryDrillError(
            "Object-storage versioning could not be verified."
        ) from exc
    if versioning.get("Status") != "Enabled":
        raise ObjectRecoveryDrillError("Object-storage versioning is not enabled.")

    key = f"recovery-drill/{deployment_id}/{uuid4().hex}.json"
    original = json.dumps(
        {
            "schema_version": "rdc.object-recovery-canary/v1",
            "nonce": uuid4().hex,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    replacement = b'{"schema_version":"rdc.object-recovery-canary/v2"}'
    encryption: dict[str, object] = (
        {"ServerSideEncryption": "aws:kms", "SSEKMSKeyId": kms_key_id}
        if kms_key_id
        else {"ServerSideEncryption": "AES256"}
    )
    failure: ObjectRecoveryDrillError | None = None
    cleaned_versions = 0
    expected_version_ids: set[str] = set()
    try:
        first = client.put_object(
            Bucket=bucket,
            Key=key,
            Body=original,
            ContentType="application/json",
            Metadata={"rdc-recovery-drill": "true"},
            **encryption,
        )
        first_version = first.get("VersionId")
        if not isinstance(first_version, str) or not first_version:
            raise ObjectRecoveryDrillError("Canary version identity is unavailable.")
        expected_version_ids.add(first_version)
        second = client.put_object(
            Bucket=bucket,
            Key=key,
            Body=replacement,
            ContentType="application/json",
            Metadata={"rdc-recovery-drill": "true"},
            **encryption,
        )
        second_version = second.get("VersionId")
        if not isinstance(second_version, str) or not second_version:
            raise ObjectRecoveryDrillError("Canary version identity is unavailable.")
        expected_version_ids.add(second_version)
        deleted = client.delete_object(Bucket=bucket, Key=key)
        delete_marker_version = deleted.get("VersionId")
        if not isinstance(delete_marker_version, str) or not delete_marker_version:
            raise ObjectRecoveryDrillError("Delete-marker identity is unavailable.")
        expected_version_ids.add(delete_marker_version)
        restored = client.get_object(
            Bucket=bucket,
            Key=key,
            VersionId=first_version,
        )
        body = restored.get("Body")
        if not hasattr(body, "read"):
            raise ObjectRecoveryDrillError("Restored canary body is invalid.")
        recovered = body.read(len(original) + 1)
        close = getattr(body, "close", None)
        if callable(close):
            close()
        if recovered != original:
            raise ObjectRecoveryDrillError("Versioned object recovery did not match.")
    except (BotoCoreError, ClientError, OSError, ObjectRecoveryDrillError) as exc:
        failure = (
            exc
            if isinstance(exc, ObjectRecoveryDrillError)
            else ObjectRecoveryDrillError("Object-storage recovery drill failed.")
        )
    finally:
        try:
            cleaned_versions = _cleanup_canary(
                client,
                bucket=bucket,
                key=key,
                expected_version_ids=expected_version_ids,
            )
        except (BotoCoreError, ClientError, OSError, ObjectRecoveryDrillError) as exc:
            if failure is not None:
                raise ObjectRecoveryDrillError(
                    "Object recovery and canary cleanup failed."
                ) from failure
            raise ObjectRecoveryDrillError("Object canary cleanup failed.") from exc
    if failure is not None:
        raise failure
    if cleaned_versions < 3:
        raise ObjectRecoveryDrillError(
            "Object canary versions were not completely observed and removed."
        )
    return {
        "schema_version": "rdc.object-recovery-drill/v1",
        "environment": environment,
        "deployment_id": deployment_id,
        "bucket_versioning": "Enabled",
        "restored_sha256": hashlib.sha256(original).hexdigest(),
        "canary_versions_removed": cleaned_versions,
        "restore_verified": True,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--kms-key-id")
    arguments = parser.parse_args()
    environment = os.environ.get("RDC_ENV", "")
    deployment_id = os.environ.get("RDC_DEPLOYMENT_ID", "")
    endpoint = os.environ.get("RDC_S3_ENDPOINT", "")
    bucket = os.environ.get("RDC_S3_BUCKET", "")
    access_key = os.environ.get("RDC_S3_ACCESS_KEY", "")
    secret_key = os.environ.get("RDC_S3_SECRET_KEY", "")
    if not access_key or not secret_key:
        raise SystemExit("Object-storage recovery credentials are required.")
    try:
        client = boto3.client(
            "s3",
            endpoint_url=endpoint,
            region_name=os.environ.get("RDC_S3_REGION", "us-east-1"),
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            config=Config(
                connect_timeout=5,
                read_timeout=15,
                retries={"max_attempts": 2, "mode": "standard"},
                s3={"addressing_style": "path"},
            ),
        )
        result = run_object_recovery_drill(
            client,
            environment=environment,
            deployment_id=deployment_id,
            endpoint=endpoint,
            bucket=bucket,
            kms_key_id=arguments.kms_key_id,
        )
    except ObjectRecoveryDrillError as exc:
        raise SystemExit(str(exc)) from exc
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
