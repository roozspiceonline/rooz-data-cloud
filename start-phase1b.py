#!/usr/bin/env python3
"""Create RDC Phase 1B Bridge tasks, GitHub Issues, branch, and draft PR.

Compatible with Python 3.9+ and requires no third-party packages.
"""

import base64
import json
import os
import sys
from pathlib import Path
from typing import Dict, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent
BRIDGE_DIR = Path.home() / "Downloads" / "rdc-team-bridge"
ENV_FILE = BRIDGE_DIR / ".env"
BRIDGE_URL = os.environ.get(
    "RDC_BRIDGE_URL",
    "http://127.0.0.1:8765",
).rstrip("/")
BRANCH = "feat/phase-1b-identity-tenancy"
EXCLUDED = {
    ".git",
    ".next",
    ".venv",
    "__pycache__",
    "node_modules",
}

TASKS = [
    {
        "task_id": "RDC-P1B-CHAT-001",
        "title": "Identity, sessions, tenancy, API keys, and RLS",
        "description": (
            "Implement Phase 1B identity and tenancy: Argon2id users, "
            "opaque server-side sessions, CSRF, organizations, memberships, "
            "projects, scoped one-time API keys, audit events, explicit tenant "
            "predicates, PostgreSQL RLS, migration verification, and contract "
            "tests. Do not implement Agents, Builds, Runs, billing, or workers."
        ),
        "phase": "Phase 1B",
        "owner": "chatgpt",
        "status": "IN_PROGRESS",
        "priority": "CRITICAL",
        "deliverables": [
            "Identity and tenancy database migration",
            "Authentication and session APIs",
            "Organization, membership, and project APIs",
            "API-key issuance and revocation APIs",
            "RLS policies and audit events",
            "Backend and contract tests",
        ],
        "acceptance_criteria": [
            "Passwords use Argon2id",
            "Raw session and API-key tokens are never stored",
            "Cookie mutations require session-bound CSRF",
            "Tenant queries use explicit organization predicates and RLS",
            "API keys are scoped, revocable, and shown once",
            "CI applies migrations to PostgreSQL and passes all checks",
        ],
    },
    {
        "task_id": "RDC-P1B-GEM-001",
        "title": "Review authentication and organization-selection UX",
        "description": (
            "Review the Phase 1B login, session recovery, organization "
            "selection, error states, accessibility, responsive behavior, and "
            "credential-handling UX. Propose precise file-level corrections "
            "only. Do not introduce browser token storage, frontend "
            "authorization authority, secret reveal behavior, or changes to "
            "backend contracts."
        ),
        "phase": "Phase 1B",
        "owner": "gemini",
        "status": "WAITING_FOR_GEMINI",
        "priority": "HIGH",
        "deliverables": [
            "Authentication UX review",
            "Organization-selection accessibility review",
            "Loading, error, and empty-state corrections",
            "Targeted frontend patch proposals",
        ],
        "acceptance_criteria": [
            "No localStorage or sessionStorage credentials",
            "Errors remain generic where enumeration is possible",
            "Keyboard and screen-reader behavior is defined",
            "Organization navigation uses server-authorized results only",
        ],
    },
    {
        "task_id": "RDC-P1B-INT-001",
        "title": "Reconcile Phase 1B identity and tenancy",
        "description": (
            "Reconcile the backend implementation, Gemini UX review, "
            "migration behavior, RLS tests, API contracts, and GitHub CI. "
            "Keep blocked until both upstream tasks are in review."
        ),
        "phase": "Phase 1B",
        "owner": "chatgpt",
        "status": "BLOCKED",
        "priority": "HIGH",
        "deliverables": [
            "Integrated Phase 1B patch set",
            "Security and tenancy verification",
            "Bablu approval request",
        ],
        "acceptance_criteria": [
            "Frontend and backend authentication contracts align",
            "RLS and explicit scoping remain intact",
            "CI passes",
            "No later product domain is represented as complete",
        ],
    },
]


def load_env(path: Path) -> Dict[str, str]:
    if not path.exists():
        raise RuntimeError("Bridge .env was not found: {}".format(path))

    values: Dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        value = value.strip()
        if (
            len(value) >= 2
            and value[0] == value[-1]
            and value[0] in {"'", '"'}
        ):
            value = value[1:-1]

        values[key.strip()] = value

    return values


def request_json(
    method: str,
    url: str,
    payload: Optional[dict] = None,
    headers: Optional[dict] = None,
    allow_404: bool = False,
):
    data = None
    final_headers = dict(headers or {})

    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        final_headers.setdefault("Content-Type", "application/json")

    request = Request(
        url,
        data=data,
        headers=final_headers,
        method=method,
    )

    try:
        with urlopen(request, timeout=300) as response:
            body = response.read().decode("utf-8")
            return (
                response.status,
                json.loads(body) if body else {},
            )
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        if allow_404 and exc.code == 404:
            return 404, {}

        try:
            parsed = json.loads(body)
            detail = (
                parsed.get("detail")
                or parsed.get("message")
                or body
            )
        except json.JSONDecodeError:
            detail = body

        raise RuntimeError(
            "{} {} failed with HTTP {}: {}".format(
                method,
                url,
                exc.code,
                detail,
            )
        ) from exc
    except URLError as exc:
        raise RuntimeError(
            "Could not reach {}: {}".format(url, exc)
        ) from exc


def bridge(
    method: str,
    path: str,
    payload: Optional[dict] = None,
):
    return request_json(
        method,
        BRIDGE_URL + path,
        payload,
    )[1]


def github_headers(token: str) -> dict:
    return {
        "Authorization": "Bearer {}".format(token),
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "rdc-phase1b-kickoff/1.0",
    }


def github(
    method: str,
    url: str,
    token: str,
    payload: Optional[dict] = None,
    allow_404: bool = False,
):
    return request_json(
        method,
        url,
        payload,
        github_headers(token),
        allow_404,
    )


def create_or_get_task(task: dict) -> dict:
    try:
        created = bridge("POST", "/api/tasks", task)
        print("Created Bridge task:", task["task_id"])
        return created
    except RuntimeError as exc:
        if "HTTP 409" not in str(exc):
            raise

        existing = bridge(
            "GET",
            "/api/tasks/{}".format(task["task_id"]),
        )
        print("Bridge task already exists:", task["task_id"])
        return existing


def ensure_issue(task: dict) -> Optional[int]:
    issue_url = task.get("github_issue_url")
    if issue_url:
        try:
            return int(issue_url.rstrip("/").split("/")[-1])
        except (TypeError, ValueError):
            return None

    result = bridge(
        "POST",
        "/api/tasks/{}/github-issue".format(task["task_id"]),
    )
    print(
        "Created GitHub Issue #{} for {}".format(
            result["issue_number"],
            task["task_id"],
        )
    )
    return int(result["issue_number"])


def ensure_branch(
    api_root: str,
    token: str,
    base: str,
) -> None:
    encoded = quote("heads/{}".format(BRANCH), safe="")
    status, _ = github(
        "GET",
        "{}/git/ref/{}".format(api_root, encoded),
        token,
        allow_404=True,
    )

    if status == 200:
        print("GitHub branch already exists:", BRANCH)
        return

    base_encoded = quote("heads/{}".format(base), safe="")
    _, base_ref = github(
        "GET",
        "{}/git/ref/{}".format(api_root, base_encoded),
        token,
    )
    github(
        "POST",
        "{}/git/refs".format(api_root),
        token,
        {
            "ref": "refs/heads/{}".format(BRANCH),
            "sha": base_ref["object"]["sha"],
        },
    )
    print("Created GitHub branch:", BRANCH)


def repository_files():
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file():
            continue
        if any(part in EXCLUDED for part in path.parts):
            continue
        if path.name in {
            "start-phase1b.py",
            "RDC-P1B-GEM-001-result.md",
            "MANIFEST.json",
        }:
            continue

        yield path.relative_to(ROOT), path


def sync_file(
    api_root: str,
    token: str,
    relative: Path,
    local: Path,
) -> str:
    repo_path = relative.as_posix()
    encoded = quote(repo_path, safe="/")
    query = urlencode({"ref": BRANCH})

    status, remote = github(
        "GET",
        "{}/contents/{}?{}".format(
            api_root,
            encoded,
            query,
        ),
        token,
        allow_404=True,
    )

    content = local.read_bytes()

    if status == 200:
        remote_bytes = base64.b64decode(
            str(remote.get("content", "")).replace("\n", "")
        )

        if remote_bytes == content:
            return "unchanged"

        github(
            "PUT",
            "{}/contents/{}".format(api_root, encoded),
            token,
            {
                "branch": BRANCH,
                "content": base64.b64encode(content).decode("ascii"),
                "message": "feat(phase1b): update {}".format(
                    repo_path
                ),
                "sha": remote["sha"],
            },
        )
        return "updated"

    github(
        "PUT",
        "{}/contents/{}".format(api_root, encoded),
        token,
        {
            "branch": BRANCH,
            "content": base64.b64encode(content).decode("ascii"),
            "message": "feat(phase1b): add {}".format(repo_path),
        },
    )
    return "created"


def ensure_pr(
    api_root: str,
    token: str,
    owner: str,
    base: str,
    issues: Dict[str, int],
) -> Tuple[int, str]:
    query = urlencode(
        {
            "state": "open",
            "head": "{}:{}".format(owner, BRANCH),
            "base": base,
        }
    )
    _, pulls = github(
        "GET",
        "{}/pulls?{}".format(api_root, query),
        token,
    )

    if pulls:
        return int(pulls[0]["number"]), str(pulls[0]["html_url"])

    issue_lines = [
        "- Relates to #{} ({})".format(
            issues[task_id],
            task_id,
        )
        for task_id in sorted(issues)
    ]

    body = """## Purpose

Implement the Rooz Data Cloud Phase 1B identity and tenancy foundation.

## Included

- Argon2id users
- Opaque server-side sessions and CSRF
- Organizations, memberships, and projects
- Scoped one-time API keys
- Audit events and idempotency records
- PostgreSQL RLS
- Login and organization-selection console flows
- Migration and contract CI

## Explicit exclusions

- No Agents, Builds, Runs, workers, billing, or arbitrary code execution
- No browser credential storage
- No plaintext password, session, CSRF, or API-key storage

## Bridge tasks

{}

Keep this pull request in draft until Gemini review, integration reconciliation, CI, and Bablu approval are complete.
""".format("\n".join(issue_lines))

    _, pr = github(
        "POST",
        "{}/pulls".format(api_root),
        token,
        {
            "base": base,
            "body": body,
            "draft": True,
            "head": BRANCH,
            "title": "[RDC-P1B] Identity and tenancy foundation",
        },
    )
    return int(pr["number"]), str(pr["html_url"])


def frontend_review_context(pr_url: str) -> str:
    paths = [
        "apps/console/src/components/login-form.tsx",
        "apps/console/src/components/organization-selector.tsx",
        "apps/console/src/app/login/page.tsx",
        "apps/console/src/app/console/select-org/page.tsx",
        "packages/api-client/src/index.ts",
        "packages/shared-types/src/index.ts",
    ]
    sections = [
        "Review draft PR: {}".format(pr_url),
        "Return precise file-level corrections and rationale.",
        (
            "Do not change the approved authentication, CSRF, tenancy, "
            "RLS, or secret contracts."
        ),
    ]

    for path in paths:
        content = (ROOT / path).read_text(encoding="utf-8")
        sections.append(
            "\nFILE: {}\n```text\n{}\n```".format(path, content)
        )

    return "\n".join(sections)[:19_500]


def main() -> None:
    health = bridge("GET", "/health")
    print(
        "Connected to {} v{}".format(
            health.get("service", "rdc-team-bridge"),
            health.get("version", "unknown"),
        )
    )

    env = load_env(ENV_FILE)
    token = env.get("GITHUB_TOKEN", "").strip()
    repository = (
        env.get("GITHUB_REPOSITORY", "")
        .strip()
        .strip("/")
    )

    if not token:
        raise RuntimeError(
            "GITHUB_TOKEN is missing from {}".format(ENV_FILE)
        )
    if repository.count("/") != 1:
        raise RuntimeError(
            "GITHUB_REPOSITORY must use owner/repository format"
        )

    issues: Dict[str, int] = {}
    for task_data in TASKS:
        task = create_or_get_task(task_data)
        issue_number = ensure_issue(task)
        if issue_number is not None:
            issues[task_data["task_id"]] = issue_number

    owner, _ = repository.split("/", 1)
    api_root = "https://api.github.com/repos/{}".format(
        repository
    )
    _, repo = github("GET", api_root, token)
    base = repo["default_branch"]

    ensure_branch(api_root, token, base)

    counts = {
        "created": 0,
        "updated": 0,
        "unchanged": 0,
    }

    for relative, local in repository_files():
        result = sync_file(
            api_root,
            token,
            relative,
            local,
        )
        counts[result] += 1
        print(
            "{}: {}".format(
                result.capitalize(),
                relative.as_posix(),
            )
        )

    pr_number, pr_url = ensure_pr(
        api_root,
        token,
        owner,
        base,
        issues,
    )
    print("Draft PR #{}: {}".format(pr_number, pr_url))

    chat_result = """RDC-P1B-CHAT-001 — Implementation Result

Completed:
- Added Argon2id user credentials and opaque server-side sessions.
- Added session-bound CSRF and HttpOnly cookie handling.
- Added Redis-backed authentication rate limiting.
- Added organizations, memberships, projects, API keys, audit events, and idempotency records.
- Added explicit tenant predicates and PostgreSQL RLS policies.
- Added idempotent API-key issuance without plaintext token storage.
- Added login and organization-selection console flows with no browser credential storage.
- Added PostgreSQL migration execution to CI.
- Uploaded implementation to draft PR #{pr_number}: {pr_url}.

Security boundaries:
- Raw passwords, session tokens, CSRF tokens, and API keys are never stored.
- API keys are scoped, revocable, and organization-bound.
- Cross-tenant access is hidden through safe 404 behavior.
- Frontend controls are not authorization controls.
- No arbitrary code execution was added to the API.

Blockers:
- Gemini frontend review
- GitHub CI
- Final integration review
- Bablu approval

Recommended next status: IN_REVIEW
""".format(
        pr_number=pr_number,
        pr_url=pr_url,
    )

    bridge(
        "POST",
        "/api/tasks/RDC-P1B-CHAT-001/import-result",
        {
            "agent": "chatgpt",
            "content": chat_result,
        },
    )

    gemini_task = bridge(
        "GET",
        "/api/tasks/RDC-P1B-GEM-001",
    )

    if gemini_task["status"] not in {
        "IN_REVIEW",
        "APPROVED",
        "COMPLETED",
    }:
        print(
            "Dispatching authentication UX review to Gemini..."
        )
        result = bridge(
            "POST",
            "/api/tasks/RDC-P1B-GEM-001/dispatch-gemini",
            {
                "extra_instruction": frontend_review_context(
                    pr_url
                )
            },
        )
        result_path = (
            Path.home()
            / "Downloads"
            / "RDC-P1B-GEM-001-result.md"
        )
        result_path.write_text(
            result.get("content", ""),
            encoding="utf-8",
        )
        print("Gemini review saved to:", result_path)
    else:
        print(
            "Gemini dispatch skipped; task status:",
            gemini_task["status"],
        )

    bridge(
        "PATCH",
        "/api/tasks/RDC-P1B-INT-001",
        {"status": "BLOCKED"},
    )

    print()
    print("RDC_PHASE1B_KICKOFF_COMPLETE")
    print("Created files:", counts["created"])
    print("Updated files:", counts["updated"])
    print("Unchanged files:", counts["unchanged"])
    print("Draft PR:", pr_url)
    print()
    print("NEXT ACTION:")
    print(
        "Upload ~/Downloads/RDC-P1B-GEM-001-result.md "
        "to ChatGPT."
    )


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("ERROR:", exc, file=sys.stderr)
        sys.exit(1)
