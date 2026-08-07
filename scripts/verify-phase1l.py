from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit("Phase 1L verification failed: " + message)


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def main() -> None:
    path = ROOT / "workers" / "sandbox-runtime" / "browser_policy.py"
    spec = importlib.util.spec_from_file_location("rdc_phase1l_browser_policy", path)
    require(spec is not None and spec.loader is not None, "cannot load browser policy")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)

    disabled = module.BrowserPolicy(
        enabled=False,
        allowed_hosts=("example.com",),
        max_pages=1,
        max_actions=8,
        navigation_timeout_seconds=15,
        max_dom_bytes=2097152,
        max_screenshot_bytes=2097152,
    )
    plan = {
        "schema_version": "rdc.browser/v1",
        "start_url": "https://example.com/",
        "wait_until": "domcontentloaded",
        "actions": [{"id": "page", "type": "snapshot", "include_html": True}],
    }
    try:
        module.validate_browser_plan(plan, policy=disabled)
    except module.BrowserPolicyError:
        pass
    else:
        require(False, "disabled browser accepted a plan")

    enabled = module.BrowserPolicy(
        enabled=True,
        allowed_hosts=("example.com",),
        max_pages=1,
        max_actions=8,
        navigation_timeout_seconds=15,
        max_dom_bytes=2097152,
        max_screenshot_bytes=2097152,
    )
    normalized = module.validate_browser_plan(plan, policy=enabled)
    require(normalized["hostname"] == "example.com", "hostname normalization changed")
    require(len(enabled.digest) == 64, "browser policy digest is not SHA-256")

    schema = json.loads(
        read("packages/agent-protocol/schemas/browser-session.schema.json")
    )
    require(schema.get("additionalProperties") is False, "browser schema is not strict")
    require(
        schema["properties"]["schema_version"]["const"] == "rdc.browser/v1",
        "browser protocol version changed",
    )

    env = read(".env.example")
    require(
        "RDC_SANDBOX_CANARY_BROWSER_ENABLED=false" in env,
        "browser gate does not default false",
    )

    config = read("apps/api/app/core/config.py")
    for marker in [
        "sandbox_canary_browser_enabled: bool = False",
        "Browser execution requires the sandbox master gate and canary mode.",
        "Browser execution requires the Phase 1J web-egress gate.",
        "Browser execution requires an operator web-egress allowlist.",
    ]:
        require(marker in config, "browser config guard missing: " + marker)

    executor = read("workers/sandbox-runtime/run_executor.py")
    require(
        '"--network"' in executor and '"none"' in executor,
        "Agent container network boundary changed",
    )
    require(
        "playwright" not in executor.casefold() and "chromium" not in executor.casefold(),
        "Agent executor unexpectedly gained browser runtime",
    )

    runtime_dockerfile = read("workers/browser-runtime/Dockerfile")
    runtime_requirements = read(
        "workers/browser-runtime/requirements.txt"
    )
    runtime_source = read(
        "workers/browser-runtime/browser_runtime.py"
    )
    runtime_readme = read("workers/browser-runtime/README.md")

    require(
        runtime_requirements.strip() == "playwright==1.61.0",
        "browser runtime Playwright version is not exactly pinned",
    )
    require(
        runtime_dockerfile.startswith(
            "FROM mcr.microsoft.com/playwright/python:v1.61.0-noble"
        ),
        "browser runtime image is not exactly pinned",
    )
    require(
        "USER pwuser" in runtime_dockerfile,
        "browser runtime does not end as the non-root pwuser",
    )
    for forbidden in [
        "--no-sandbox",
        "EXPOSE ",
        "--remote-debugging-port",
    ]:
        require(
            forbidden not in runtime_dockerfile,
            "browser Dockerfile contains forbidden surface: " + forbidden,
        )

    for marker in [
        '"--self-test"',
        'page.goto("about:blank"',
        "accept_downloads=False",
        'service_workers="block"',
        '"external_navigation": False',
        '"remote_cdp": False',
    ]:
        require(
            marker in runtime_source,
            "browser runtime self-test guard missing: " + marker,
        )

    for forbidden in [
        "connect_over_cdp",
        "launch_server",
        "websocket_endpoint",
        "http://",
        "https://",
        "--no-sandbox",
    ]:
        require(
            forbidden not in runtime_source,
            "browser runtime exposes forbidden live behavior: " + forbidden,
        )

    require(
        "not connected" in runtime_readme.casefold(),
        "browser runtime README does not state inert integration",
    )
    require(
        "General untrusted browser execution remains release-blocked."
        in runtime_readme,
        "browser runtime release boundary is missing",
    )

    sandbox_worker = read("workers/sandbox-runtime/worker.py")
    require(
        "browser_runtime" not in sandbox_worker
        and "playwright" not in sandbox_worker.casefold()
        and "chromium" not in sandbox_worker.casefold(),
        "sandbox worker unexpectedly wires the browser runtime",
    )

    run_schemas = read("apps/api/app/run_schemas.py")
    for marker in [
        "class BrowserSnapshotActionInput",
        "class BrowserSessionInput",
        'browser: BrowserSessionInput | None = None',
        "Phase 1L does not allow web_fetch and browser in one Run.",
    ]:
        require(marker in run_schemas, "Run browser contract missing: " + marker)

    runs_service = read("apps/api/app/services/runs.py")
    for marker in [
        "def _manifest_browser",
        "def _browser_policy_payload",
        '"schema_version": "rdc.browser-policy/v1"',
        '"BROWSER_NETWORK_CAPABILITY_REQUIRED"',
        '"BROWSER_CAPABILITY_REQUIRED"',
        'input_reference["browser"] = browser',
        'input_reference["browser_policy"] = browser_policy',
        'input_reference["browser_policy_digest"] = browser_policy_digest',
    ]:
        require(marker in runs_service, "Run browser receipt missing: " + marker)

    worker_config = read("workers/sandbox-runtime/config.py")
    for marker in [
        "browser_enabled: bool",
        "browser_max_pages: int",
        "browser_max_actions: int",
        "browser_navigation_timeout_seconds: int",
        "browser_max_dom_bytes: int",
        "browser_max_screenshot_bytes: int",
        '"RDC_SANDBOX_CANARY_BROWSER_ENABLED"',
    ]:
        require(marker in worker_config, "worker browser config missing: " + marker)

    browser_policy_source = read("workers/sandbox-runtime/browser_policy.py")
    for marker in [
        "def create(",
        "normalized_hosts",
        "Enabled browser policy requires an operator allowlist.",
        '"agent_container_network": "none"',
        '"project_secrets_available": False',
        '"persistent_profile": False',
        '"downloads_enabled": False',
        '"uploads_enabled": False',
        '"remote_cdp_enabled": False',
    ]:
        require(marker in browser_policy_source, "browser policy guard missing: " + marker)

    run_contract_test = read("apps/api/tests/test_phase1l_run_contract.py")
    require(
        "test_phase1l_browser_and_web_fetch_are_mutually_exclusive" in run_contract_test,
        "Phase 1L browser Run regression tests are missing",
    )

    runbook = read("docs/phase1l/RUNBOOK.md")
    require(
        "Do not enable browser execution during the Phase 1L foundation." in runbook,
        "runbook no longer preserves disabled browser foundation",
    )
    require(
        "General untrusted browser execution remains release-blocked." in runbook,
        "browser release boundary is missing",
    )

    print("Phase 1L foundation verification: PASS")
    print("  browser gate default FALSE: PASS")
    print("  rdc.browser/v1 snapshot contract: PASS")
    print("  deterministic browser policy digest: PASS")
    print("  Agent container --network none: PASS")
    print("  isolated Playwright/Chromium skeleton: PASS")
    print("  Run browser contract + immutable policy receipt: PASS")
    print("  worker browser policy reconstruction config: PASS")
    print("  browser runtime live navigation wiring: NOT IMPLEMENTED")
    print("  general untrusted browser execution: BLOCKED")


if __name__ == "__main__":
    main()
