#!/usr/bin/env python3
"""Start RDC Phase 1A through the local Bridge and GitHub."""

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
BRIDGE_URL = os.environ.get("RDC_BRIDGE_URL", "http://127.0.0.1:8765").rstrip("/")
BRANCH = "feat/phase-1a-engineering-foundation"
TIMEOUT = 300
EXCLUDED = {".git", ".next", ".pnpm-store", ".turbo", ".venv", "__pycache__", "node_modules"}

TASKS = [
    {
        "task_id": "RDC-P1A-CHAT-001",
        "title": "Monorepo, API, infrastructure, and CI foundation",
        "description": (
            "Implement the approved Phase 1A engineering foundation: pnpm/Turborepo monorepo, "
            "FastAPI composition root, dependency-aware health endpoints, PostgreSQL/Redis/MinIO "
            "local topology, Alembic migration foundation, shared packages, Docker Compose, and CI. "
            "Do not implement authentication, organization/project domains, Agent execution, Builds, "
            "Runs, billing, or arbitrary code execution."
        ),
        "phase": "Phase 1A",
        "owner": "chatgpt",
        "status": "IN_PROGRESS",
        "priority": "CRITICAL",
        "deliverables": [
            "Runnable monorepo scaffold",
            "FastAPI API shell",
            "Docker Compose topology",
            "PostgreSQL migration foundation",
            "Shared packages",
            "GitHub Actions CI",
        ],
        "acceptance_criteria": [
            "Public API root remains /api/v1",
            "API liveness and dependency-aware readiness are implemented",
            "API process contains no arbitrary Agent or build execution",
            "PostgreSQL, Redis, and object storage start through Compose",
            "Console and API run as non-root containers",
            "CI checks frontend, backend, scaffold, and Compose configuration",
        ],
    },
    {
        "task_id": "RDC-P1A-GEM-001",
        "title": "Review and refine the accessible console shell",
        "description": (
            "Review the Phase 1A Next.js console shell and shared UI foundation. Verify the explicit "
            "Organization to Project route hierarchy, navigation clarity, responsive behavior, "
            "WCAG 2.1 AA foundations, loading/error/permission patterns, design-token consistency, "
            "and bundle boundaries. Return targeted patch proposals only; do not change API, "
            "authentication, tenant, secret, or execution-plane contracts."
        ),
        "phase": "Phase 1A",
        "owner": "gemini",
        "status": "WAITING_FOR_GEMINI",
        "priority": "HIGH",
        "deliverables": [
            "Frontend architecture review",
            "Accessible console-shell corrections",
            "Shared UI correction proposals",
            "Testing and bundle-risk review",
        ],
        "acceptance_criteria": [
            "Approved route root is preserved",
            "Frontend guards remain UX-only",
            "No browser credential storage is introduced",
            "Secret reveal UI is prohibited",
            "Future routes remain clearly disabled",
            "Suggested changes are implementable as file-level patches",
        ],
    },
    {
        "task_id": "RDC-P1A-INT-001",
        "title": "Reconcile Phase 1A implementation and review",
        "description": (
            "Reconcile the Phase 1A implementation with Gemini's frontend review, GitHub PR checks, "
            "Phase 0 contracts, and security merge gates. Resolve only genuine contract, accessibility, "
            "quality, or integration defects. Keep blocked until both upstream tasks are in review."
        ),
        "phase": "Phase 1A",
        "owner": "chatgpt",
        "status": "BLOCKED",
        "priority": "HIGH",
        "deliverables": ["Integrated Phase 1A patch set", "CI and security review", "Bablu approval request"],
        "acceptance_criteria": [
            "Frontend and backend contracts remain aligned",
            "CI passes",
            "No secrets are committed",
            "No Phase 1B domain is falsely represented as implemented",
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
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        values[key.strip()] = value
    return values


def request_json(method: str, url: str, payload: Optional[dict] = None, headers: Optional[dict] = None, allow_404: bool = False):
    data = None
    final_headers = dict(headers or {})
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        final_headers.setdefault("Content-Type", "application/json")
    request = Request(url, data=data, headers=final_headers, method=method)
    try:
        with urlopen(request, timeout=TIMEOUT) as response:
            body = response.read().decode("utf-8")
            return response.status, json.loads(body) if body else {}
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        if allow_404 and exc.code == 404:
            return 404, {}
        try:
            decoded = json.loads(body)
            detail = decoded.get("detail") or decoded.get("message") or body
        except json.JSONDecodeError:
            detail = body
        raise RuntimeError("{} {} failed with HTTP {}: {}".format(method, url, exc.code, detail)) from exc
    except URLError as exc:
        raise RuntimeError("Could not reach {}: {}".format(url, exc)) from exc


def bridge(method: str, path: str, payload: Optional[dict] = None):
    return request_json(method, BRIDGE_URL + path, payload)[1]


def create_or_get_task(task: dict) -> dict:
    try:
        created = bridge("POST", "/api/tasks", task)
        print("Created Bridge task:", task["task_id"])
        return created
    except RuntimeError as exc:
        if "HTTP 409" not in str(exc):
            raise
        existing = bridge("GET", "/api/tasks/{}".format(task["task_id"]))
        print("Bridge task already exists:", task["task_id"])
        return existing


def ensure_issue(task: dict) -> Optional[int]:
    if task.get("github_issue_url"):
        try:
            return int(task["github_issue_url"].rstrip("/").split("/")[-1])
        except (TypeError, ValueError):
            return None
    result = bridge("POST", "/api/tasks/{}/github-issue".format(task["task_id"]))
    print("Created GitHub Issue #{} for {}".format(result["issue_number"], task["task_id"]))
    return int(result["issue_number"])


def github_headers(token: str) -> dict:
    return {
        "Authorization": "Bearer {}".format(token),
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "rdc-phase1a-kickoff/1.0",
    }


def github(method: str, url: str, token: str, payload: Optional[dict] = None, allow_404: bool = False):
    return request_json(method, url, payload, github_headers(token), allow_404)


def ensure_branch(api_root: str, token: str, base: str) -> None:
    encoded = quote("heads/{}".format(BRANCH), safe="")
    status, _ = github("GET", "{}/git/ref/{}".format(api_root, encoded), token, allow_404=True)
    if status == 200:
        print("GitHub branch already exists:", BRANCH)
        return
    base_encoded = quote("heads/{}".format(base), safe="")
    _, base_ref = github("GET", "{}/git/ref/{}".format(api_root, base_encoded), token)
    github("POST", "{}/git/refs".format(api_root), token, {"ref": "refs/heads/{}".format(BRANCH), "sha": base_ref["object"]["sha"]})
    print("Created GitHub branch:", BRANCH)


def repository_files():
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file() or any(part in EXCLUDED for part in path.parts):
            continue
        if path.name in {"start-phase1a.py", "RDC-P1A-GEM-001-result.md", "MANIFEST.json"}:
            continue
        yield path.relative_to(ROOT), path


def sync_file(api_root: str, token: str, relative: Path, local: Path) -> str:
    repo_path = relative.as_posix()
    encoded = quote(repo_path, safe="/")
    status, remote = github("GET", "{}/contents/{}?{}".format(api_root, encoded, urlencode({"ref": BRANCH})), token, allow_404=True)
    content = local.read_bytes()
    if status == 200:
        remote_bytes = base64.b64decode(str(remote.get("content", "")).replace("\n", ""))
        if remote_bytes == content:
            return "unchanged"
        github("PUT", "{}/contents/{}".format(api_root, encoded), token, {
            "branch": BRANCH,
            "content": base64.b64encode(content).decode("ascii"),
            "message": "feat(phase1a): update {}".format(repo_path),
            "sha": remote["sha"],
        })
        return "updated"
    github("PUT", "{}/contents/{}".format(api_root, encoded), token, {
        "branch": BRANCH,
        "content": base64.b64encode(content).decode("ascii"),
        "message": "feat(phase1a): add {}".format(repo_path),
    })
    return "created"


def ensure_pr(api_root: str, token: str, owner: str, base: str, issues: Dict[str, int]) -> Tuple[int, str]:
    query = urlencode({"state": "open", "head": "{}:{}".format(owner, BRANCH), "base": base})
    _, pulls = github("GET", "{}/pulls?{}".format(api_root, query), token)
    if pulls:
        return int(pulls[0]["number"]), str(pulls[0]["html_url"])
    issue_lines = ["- Relates to #{} ({})".format(issues[task_id], task_id) for task_id in sorted(issues)]
    body = """## Purpose

Implement the Rooz Data Cloud Phase 1A engineering foundation.

## Included

- pnpm/Turborepo monorepo
- Next.js console shell
- FastAPI API composition root
- PostgreSQL, Redis, and local S3-compatible storage
- Docker Compose topology
- Shared packages and API client
- Alembic migration foundation
- CI and static verification

## Explicit exclusions

- No production authentication
- No Agent, Build, or Run domain implementation
- No build/runtime worker
- No arbitrary code execution in the API
- No committed secrets

## Bridge tasks

{}

Keep this PR in draft until Gemini review, ChatGPT integration review, CI, and Bablu approval are complete.
""".format("\n".join(issue_lines))
    _, pr = github("POST", "{}/pulls".format(api_root), token, {
        "base": base,
        "body": body,
        "draft": True,
        "head": BRANCH,
        "title": "[RDC-P1A] Engineering foundation",
    })
    return int(pr["number"]), str(pr["html_url"])


def add_message(task_id: str, sender: str, recipient: str, message_type: str, content: str) -> None:
    bridge("POST", "/api/tasks/{}/messages".format(task_id), {
        "sender": sender,
        "recipient": recipient,
        "message_type": message_type,
        "content": content,
    })


def frontend_review_context(pr_url: str) -> str:
    paths = [
        "apps/console/src/app/globals.css",
        "apps/console/src/components/project-shell.tsx",
        "apps/console/src/lib/navigation.ts",
        "apps/console/src/app/console/organizations/[orgId]/projects/[projectId]/dashboard/page.tsx",
        "packages/ui/src/card.tsx",
        "packages/ui/src/status-badge.tsx",
        "packages/api-client/src/index.ts",
    ]
    sections = [
        "Review draft PR: {}".format(pr_url),
        "Return precise file-level corrections and rationale. Do not claim to have edited GitHub.",
    ]
    for path in paths:
        content = (ROOT / path).read_text(encoding="utf-8")
        sections.append("\nFILE: {}\n```text\n{}\n```".format(path, content))
    return "\n".join(sections)[:19_500]


def main() -> None:
    health = bridge("GET", "/health")
    print("Connected to {} v{}".format(health.get("service", "rdc-team-bridge"), health.get("version", "unknown")))

    env = load_env(ENV_FILE)
    token = env.get("GITHUB_TOKEN", "").strip()
    repository = env.get("GITHUB_REPOSITORY", "").strip().strip("/")
    if not token:
        raise RuntimeError("GITHUB_TOKEN is missing from {}".format(ENV_FILE))
    if repository.count("/") != 1:
        raise RuntimeError("GITHUB_REPOSITORY must use owner/repository format")

    issues: Dict[str, int] = {}
    for task_data in TASKS:
        task = create_or_get_task(task_data)
        issue = ensure_issue(task)
        if issue is not None:
            issues[task_data["task_id"]] = issue

    owner, _ = repository.split("/", 1)
    api_root = "https://api.github.com/repos/{}".format(repository)
    _, repo = github("GET", api_root, token)
    base = repo["default_branch"]
    ensure_branch(api_root, token, base)

    counts = {"created": 0, "updated": 0, "unchanged": 0}
    for relative, local in repository_files():
        result = sync_file(api_root, token, relative, local)
        counts[result] += 1
        print("{}: {}".format(result.capitalize(), relative.as_posix()))

    pr_number, pr_url = ensure_pr(api_root, token, owner, base, issues)
    print("Draft PR #{}: {}".format(pr_number, pr_url))

    chat_result = """RDC-P1A-CHAT-001 — Implementation Result

Completed:
- Created the Phase 1A pnpm/Turborepo monorepo.
- Added the Next.js console foundation and approved route hierarchy.
- Added FastAPI liveness, readiness, and /api/v1 foundation endpoints.
- Added PostgreSQL, Redis, and local S3-compatible storage through Docker Compose.
- Added shared UI, types, and cookie/CSRF-aware API client packages.
- Added Alembic foundation migration.
- Added GitHub Actions CI and static verification.
- Uploaded the implementation to draft PR #{number}: {url}.

Security boundaries:
- No browser token storage.
- No arbitrary code execution in the API.
- No secret reveal behavior.
- No Phase 1B product domain represented as complete.
- Infrastructure ports bind to localhost for local development.

Blockers:
- Gemini frontend review
- GitHub CI
- Final integration review
- Bablu approval

Recommended next status: IN_REVIEW
""".format(number=pr_number, url=pr_url)
    bridge("POST", "/api/tasks/RDC-P1A-CHAT-001/import-result", {"agent": "chatgpt", "content": chat_result})
    add_message("RDC-P1A-CHAT-001", "system", "bablu", "status_update", "Implementation uploaded to draft PR #{}: {}".format(pr_number, pr_url))

    gemini_task = bridge("GET", "/api/tasks/RDC-P1A-GEM-001")
    if gemini_task["status"] not in {"IN_REVIEW", "APPROVED", "COMPLETED"}:
        print("Dispatching console review to Gemini...")
        result = bridge("POST", "/api/tasks/RDC-P1A-GEM-001/dispatch-gemini", {"extra_instruction": frontend_review_context(pr_url)})
        result_path = Path.home() / "Downloads" / "RDC-P1A-GEM-001-result.md"
        result_path.write_text(result.get("content", ""), encoding="utf-8")
        print("Gemini review saved to:", result_path)
    else:
        print("Gemini task already {}; dispatch skipped.".format(gemini_task["status"]))

    bridge("PATCH", "/api/tasks/RDC-P1A-INT-001", {"status": "BLOCKED"})
    add_message("RDC-P1A-INT-001", "system", "chatgpt", "status_update", "Integration remains blocked until Gemini review and GitHub checks are available.")

    print()
    print("RDC_PHASE1A_KICKOFF_COMPLETE")
    print("Created files:", counts["created"])
    print("Updated files:", counts["updated"])
    print("Unchanged files:", counts["unchanged"])
    print("Draft PR:", pr_url)
    print()
    print("NEXT ACTION:")
    print("Upload ~/Downloads/RDC-P1A-GEM-001-result.md to ChatGPT.")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("ERROR:", exc, file=sys.stderr)
        sys.exit(1)
