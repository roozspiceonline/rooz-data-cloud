#!/usr/bin/env python3
"""Static release-gate checks for RDC Phase 1B."""

import compileall
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

REQUIRED = [
    "apps/api/app/core/security.py",
    "apps/api/app/core/permissions.py",
    "apps/api/app/api/dependencies.py",
    "apps/api/app/api/routes/identity_tenancy.py",
    "apps/api/app/models.py",
    "apps/api/app/schemas.py",
    "apps/api/migrations/versions/20260806_0002_identity_tenancy.py",
    "packages/api-client/src/index.ts",
    "apps/console/src/components/login-form.tsx",
    "apps/console/src/components/organization-selector.tsx",
    "docs/phase1b/README.md",
]

SECRET_PATTERNS = [
    re.compile(r"ghp_[A-Za-z0-9]{20,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"AIza[A-Za-z0-9_-]{20,}"),
    re.compile(r"sk-[A-Za-z0-9_-]{20,}"),
]


def fail(message: str) -> None:
    print("ERROR:", message, file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    missing = [path for path in REQUIRED if not (ROOT / path).exists()]
    if missing:
        fail("Missing Phase 1B files: " + ", ".join(missing))

    if not compileall.compile_dir(
        str(ROOT / "apps/api/app"),
        quiet=1,
        force=True,
    ):
        fail("API package compilation failed")

    if not compileall.compile_dir(
        str(ROOT / "apps/api/migrations"),
        quiet=1,
        force=True,
    ):
        fail("Migration compilation failed")

    scanned = 0
    for path in ROOT.rglob("*"):
        if not path.is_file() or path.suffix in {".pyc", ".zip"}:
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        scanned += 1
        for pattern in SECRET_PATTERNS:
            if pattern.search(content):
                fail(
                    "Potential credential detected in {}".format(
                        path.relative_to(ROOT)
                    )
                )

    security = (
        ROOT / "apps/api/app/core/security.py"
    ).read_text(encoding="utf-8")
    if "Type.ID" not in security or "PasswordHasher" not in security:
        fail("Argon2id password hashing is missing")

    migration = (
        ROOT
        / "apps/api/migrations/versions/"
        "20260806_0002_identity_tenancy.py"
    ).read_text(encoding="utf-8")
    for required in (
        "ENABLE ROW LEVEL SECURITY",
        "rdc.current_user_id",
        "rdc.current_organization_id",
        "rdc_has_org_membership",
        "api_keys",
        "audit_events",
    ):
        if required not in migration:
            fail("Migration contract is missing {}".format(required))

    client = (
        ROOT / "packages/api-client/src/index.ts"
    ).read_text(encoding="utf-8")
    if 'credentials: "include"' not in client:
        fail("Browser requests must include session cookies")
    if "localStorage" in client or "sessionStorage" in client:
        fail("Browser credential storage is prohibited")
    if "X-RDC-CSRF" not in client:
        fail("CSRF header behavior is missing")

    routes = (
        ROOT
        / "apps/api/app/api/routes/identity_tenancy.py"
    ).read_text(encoding="utf-8")
    for route in (
        "/auth/login",
        "/auth/session",
        "/organizations",
        "/projects",
        "/api-keys",
    ):
        if route not in routes:
            fail("Expected API route is missing: {}".format(route))

    print("RDC_PHASE1B_FOUNDATION_OK")
    print("Required files:", len(REQUIRED))
    print("Text files scanned:", scanned)


if __name__ == "__main__":
    main()
