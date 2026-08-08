from __future__ import annotations

import ast
import importlib.util
import json
import re
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
    require(
        "RDC_SANDBOX_CANARY_BROWSER_LIVE_NAVIGATION_ENABLED=false" in env,
        "live-navigation upgrade gate does not default false",
    )

    main_source = read("apps/api/app/main.py")
    for marker in [
        'version="0.13.0-phase1m"',
        '"phase": "1M"',
        '"status": "controlled-browser-navigation-canary"',
        '"browser_request_contract": "rdc.browser/v1"',
        '"browser_policy_contract": "rdc.browser-policy/v1"',
        '"browser_runtime_self_test_available": True',
        '"browser_public_navigation_enabled": '
        "_browser_live_navigation_canary_enabled()",
        '"browser_canary_activation_enabled"',
        '"browser_live_navigation_gate_enabled"',
    ]:
        require(
            marker in main_source,
            "Phase 1L compatibility status missing: " + marker,
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
        "--no-sandbox",
    ]:
        require(
            forbidden not in runtime_source,
            "browser runtime exposes forbidden Phase 1L surface: " + forbidden,
        )
    for marker in [
        "def _self_test()",
        'page.goto("about:blank"',
        "if args.self_test:",
        "Phase 1L self-test cannot accept live arguments.",
    ]:
        require(
            marker in runtime_source,
            "Phase 1L self-test isolation guard missing: " + marker,
        )

    for marker in [
        "`controlled-browser` canary activation",
        "opens only `about:blank`",
        "accepts no URL",
        "rdc.local/browser-runtime@sha256:<64-hex>",
        "`--pull never`",
        "`--network none`",
        "public URL navigation",
    ]:
        require(
            marker in runtime_readme,
            "browser runtime README bridge boundary missing: " + marker,
        )
    require(
        "General untrusted browser execution remains release-blocked."
        in runtime_readme,
        "browser runtime release boundary is missing",
    )

    sandbox_worker = read("workers/sandbox-runtime/worker.py")
    require(
        "run_browser_self_test" in sandbox_worker,
        "sandbox worker does not bridge the isolated browser self-test",
    )
    require(
        '"BROWSER_RUNTIME_FAILED"' in sandbox_worker,
        "sandbox worker lacks bounded browser self-test failure code",
    )
    require(
        '"BROWSER_RUNTIME_NOT_WIRED"' not in sandbox_worker,
        "obsolete browser-runtime block is still present",
    )
    require(
        "playwright" not in sandbox_worker.casefold()
        and "chromium" not in sandbox_worker.casefold(),
        "sandbox worker directly embeds browser implementation",
    )

    run_schemas = read("apps/api/app/run_schemas.py")
    for marker in [
        "class BrowserSnapshotActionInput",
        "class BrowserSessionInput",
        'browser: BrowserSessionInput | None = None',
        "external_surfaces = sum(",
        "A Run may use only one external web/browser intent surface.",
    ]:
        require(marker in run_schemas, "Run browser contract missing: " + marker)
    require(
        "self.web_fetch," in run_schemas
        and "self.browser," in run_schemas,
        "Phase 1L web_fetch/browser mutual exclusion disappeared",
    )

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
        "browser_runtime_image_ref: str",
        "browser_seccomp_profile: Path",
        "browser_runtime_timeout_seconds: int",
        '"RDC_SANDBOX_CANARY_BROWSER_ENABLED"',
        "RDC_BROWSER_RUNTIME_TIMEOUT_SECONDS must be between 1 and 30.",
    ]:
        require(
            marker in worker_config,
            "worker browser config missing: " + marker,
        )

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

    execution_schemas = read("apps/api/app/execution_schemas.py")
    for marker in [
        '"controlled-browser"',
        "browser_policy_digest: str | None",
        "Controlled browser requires an egress-policy digest.",
        "Controlled browser requires a browser-policy digest.",
    ]:
        require(
            marker in execution_schemas,
            "browser activation schema missing: " + marker,
        )

    execution_plane = read("apps/api/app/services/execution_plane.py")
    for marker in [
        "_browser_policy_payload",
        'capability_profile = "controlled-browser"',
        "browser_policy_digest=browser_policy_digest",
        "canonical_fingerprint(stored_policy)",
        "settings.sandbox_canary_browser_enabled",
    ]:
        require(
            marker in execution_plane,
            "control-plane browser activation guard missing: " + marker,
        )

    worker_source = read("workers/sandbox-runtime/worker.py")
    for marker in [
        "def _worker_browser_policy",
        'profile == "controlled-browser"',
        "browser_digest != browser_policy.digest",
        "validate_browser_plan(browser_plan, policy=browser_policy)",
        "run_browser_self_test",
        '"BROWSER_RUNTIME_FAILED"',
    ]:
        require(
            marker in worker_source,
            "worker browser activation verification missing: " + marker,
        )

    activation_tests = read(
        "apps/api/tests/test_phase1l_activation_receipt.py"
    )
    require(
        "test_phase1l_controlled_browser_requires_both_policy_digests"
        in activation_tests,
        "controlled-browser activation schema tests are missing",
    )

    browser_executor = read("workers/sandbox-runtime/browser_executor.py")
    executor_tree = ast.parse(browser_executor)
    image_ref_pattern: str | None = None
    for node in executor_tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if not any(
            isinstance(target, ast.Name) and target.id == "_IMAGE_REF"
            for target in node.targets
        ):
            continue
        if (
            isinstance(node.value, ast.Call)
            and node.value.args
            and isinstance(node.value.args[0], ast.Constant)
            and isinstance(node.value.args[0].value, str)
        ):
            image_ref_pattern = node.value.args[0].value
            break

    require(
        image_ref_pattern is not None,
        "browser executor immutable-image regex is missing",
    )
    valid_image_ref = "rdc.local/browser-runtime@sha256:" + ("a" * 64)
    invalid_image_refs = [
        "rdcXlocal/browser-runtime@sha256:" + ("a" * 64),
        "rdc\\Xlocal/browser-runtime@sha256:" + ("a" * 64),
        "rdc.local/browser-runtime:latest",
        "docker.io/rdc/browser-runtime@sha256:" + ("a" * 64),
        "rdc.local/browser-runtime@sha256:" + ("A" * 64),
    ]
    require(
        re.fullmatch(image_ref_pattern, valid_image_ref) is not None,
        "browser executor rejects the intended immutable local image reference",
    )
    for invalid_image_ref in invalid_image_refs:
        require(
            re.fullmatch(image_ref_pattern, invalid_image_ref) is None,
            "browser executor accepts invalid image reference: "
            + invalid_image_ref,
        )

    for marker in [
        '"--pull"',
        '"never"',
        '"--user"',
        '"pwuser"',
        '"--read-only"',
        '"no-new-privileges"',
        '"--cap-drop"',
        '"ALL"',
        '"--network"',
        '"none"',
        '"--self-test"',
        '"about:blank"',
        '"external_navigation": False',
    ]:
        require(marker in browser_executor, "browser executor guard missing: " + marker)
    for hardening_marker in [
        "def _cleanup_browser_container(",
        '"rm"',
        '"-f"',
        "finally:",
        "_cleanup_browser_container(config, name)",
        "stdout=subprocess.PIPE",
        "stderr=subprocess.DEVNULL",
        "Browser runtime timeout is outside the safe range.",
    ]:
        require(
            hardening_marker in browser_executor,
            "browser runtime hardening missing: " + hardening_marker,
        )
    require(
        "stderr=subprocess.STDOUT" not in browser_executor,
        "browser stderr is still merged into the JSON result channel",
    )

    for forbidden in [
        "--privileged",
        '"host"',
        "--no-sandbox",
        "--remote-debugging-port",
    ]:
        require(
            forbidden not in browser_executor,
            "browser executor contains forbidden surface: " + forbidden,
        )

    browser_seccomp = json.loads(
        read("infrastructure/sandbox/seccomp-rdc-browser.json")
    )
    denied = {
        name
        for rule in browser_seccomp.get("syscalls", [])
        if rule.get("action") == "SCMP_ACT_ERRNO"
        for name in rule.get("names", [])
    }
    for required_denial in ["bpf", "mount", "ptrace", "userfaultfd"]:
        require(
            required_denial in denied,
            "browser seccomp lost denial: " + required_denial,
        )
    for browser_namespace_call in ["clone3", "setns", "unshare"]:
        require(
            browser_namespace_call not in denied,
            "browser seccomp blocks Chromium namespace syscall: "
            + browser_namespace_call,
        )

    phase1l_readme = read("docs/phase1l/README.md")
    runbook = read("docs/phase1l/RUNBOOK.md")
    changelog = read("CHANGELOG.md")

    for stale in [
        "BROWSER_RUNTIME_NOT_WIRED",
        "does **not** install or execute Playwright/Chromium",
        "not imported or launched by",
    ]:
        require(
            stale not in phase1l_readme,
            "Phase 1L README contains stale pre-bridge state: " + stale,
        )
    require(
        "BROWSER_RUNTIME_NOT_WIRED" not in runbook,
        "Phase 1L runbook contains stale pre-bridge state",
    )
    for marker in [
        "force-cleaned after every launch attempt",
        "Browser stderr is not merged",
        "Phase 1M owns controlled navigation",
        "General untrusted browser execution remains release-blocked.",
    ]:
        require(
            marker in runbook,
            "Phase 1L final runbook guard missing: " + marker,
        )
    require(
        "## 0.12.0-phase1l — 2026-08-08" in changelog,
        "Phase 1L changelog entry is missing",
    )

    print("Phase 1L final verification: PASS")
    print("  browser gate default FALSE: PASS")
    print("  rdc.browser/v1 snapshot contract: PASS")
    print("  deterministic browser policy digest: PASS")
    print("  Agent container --network none: PASS")
    print("  isolated Playwright/Chromium skeleton: PASS")
    print("  Run browser contract + immutable policy receipt: PASS")
    print("  worker browser policy reconstruction config: PASS")
    print("  controlled-browser activation receipt: PASS")
    print("  worker independent browser-policy verification: PASS")
    print("  isolated about:blank browser-runtime bridge: PASS")
    print("  runtime timeout + forced container cleanup: PASS")
    print("  browser stdout/stderr isolation: PASS")
    print("  API foundation status Phase 1L: PASS")
    print("  browser runtime public navigation wiring: NOT IMPLEMENTED")
    print("  general untrusted browser execution: BLOCKED")


if __name__ == "__main__":
    main()
