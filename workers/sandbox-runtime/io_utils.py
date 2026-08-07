from __future__ import annotations

import hashlib
import http.client
import json
import os
import shutil
import tempfile
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


class SandboxIoError(RuntimeError):
    pass


def sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            digest.update(chunk)
    return digest.hexdigest(), total


def download_file(url: str, destination: Path, *, max_bytes: int) -> None:
    request = Request(url, headers={"User-Agent": "rdc-sandbox-worker/0.1"})
    total = 0
    with urlopen(request, timeout=60) as response, destination.open("wb") as output:
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise SandboxIoError("Downloaded object exceeds the configured limit.")
            output.write(chunk)


def upload_file(url: str, headers: dict[str, str], path: Path) -> None:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise SandboxIoError("Artifact upload URL is invalid.")
    connection_cls = (
        http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
    )
    connection = connection_cls(parsed.hostname, parsed.port, timeout=60)
    target = parsed.path + ("?" + parsed.query if parsed.query else "")
    size = path.stat().st_size
    request_headers = {**headers, "Content-Length": str(size)}
    connection.putrequest("PUT", target)
    for key, value in request_headers.items():
        connection.putheader(key, value)
    connection.endheaders()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            connection.send(chunk)
    response = connection.getresponse()
    response.read()
    connection.close()
    if response.status < 200 or response.status >= 300:
        raise SandboxIoError(f"Artifact upload failed with HTTP {response.status}.")


def private_temp_dir(root: Path, prefix: str) -> Path:
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    value = Path(tempfile.mkdtemp(prefix=prefix, dir=root))
    os.chmod(value, 0o700)
    return value


def write_private_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, separators=(",", ":")), encoding="utf-8")
    os.chmod(path, 0o600)


def cleanup_tree(path: Path) -> None:
    shutil.rmtree(path, ignore_errors=True)
