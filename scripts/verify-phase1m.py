from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit("Phase 1M verification failed: " + message)


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def load_module(relative: str, name: str):
    path = ROOT / relative
    spec = importlib.util.spec_from_file_location(name, path)
    require(
        spec is not None and spec.loader is not None,
        "cannot load " + relative,
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def expect_error(module, call, message: str) -> None:
    try:
        call()
    except module.BrowserNavigationContractError:
        return
    raise SystemExit("Phase 1M verification failed: " + message)


def main() -> None:
    policy_module = load_module(
        "workers/sandbox-runtime/browser_policy.py",
        "rdc_phase1m_browser_policy",
    )
    sys.modules["browser_policy"] = policy_module
    module = load_module(
        "workers/sandbox-runtime/browser_navigation_contract.py",
        "rdc_phase1m_navigation",
    )

    policy = policy_module.BrowserPolicy.create(
        enabled=True,
        allowed_hosts=("example.com", "www.example.com"),
        max_pages=2,
        max_actions=8,
        navigation_timeout_seconds=15,
        max_dom_bytes=2_097_152,
        max_screenshot_bytes=2_097_152,
    )

    plan = {
        "schema_version": "rdc.browser/v2",
        "steps": [
            {
                "id": "open",
                "type": "goto",
                "url": "https://example.com/",
                "wait_until": "domcontentloaded",
            },
            {
                "id": "wait",
                "type": "wait_for_selector",
                "selector": "main",
                "state": "visible",
                "timeout_ms": 5000,
            },
            {
                "id": "title",
                "type": "extract_text",
                "selector": "h1",
                "max_chars": 8192,
            },
            {
                "id": "body",
                "type": "extract_html",
                "selector": "main",
                "max_bytes": 262144,
            },
            {
                "id": "shot",
                "type": "screenshot",
                "full_page": False,
            },
        ],
    }
    normalized = module.validate_browser_navigation_plan(
        plan,
        policy=policy,
    )
    require(
        normalized["schema_version"] == "rdc.browser/v2",
        "v2 protocol version changed",
    )
    require(
        normalized["hostnames"] == ["example.com"],
        "navigation hostname normalization changed",
    )
    require(
        normalized["execution_enabled"] is False,
        "v2 foundation unexpectedly enables execution",
    )
    require(
        normalized["browser_network"] == "none",
        "v2 foundation unexpectedly enables browser networking",
    )
    require(
        len(str(normalized["request_digest"])) == 64,
        "navigation request digest is not SHA-256 sized",
    )

    cases = [
        (
            {
                "schema_version": "rdc.browser/v2",
                "steps": [
                    {
                        "id": "open",
                        "type": "goto",
                        "url": "http://example.com/",
                        "wait_until": "load",
                    }
                ],
            },
            "HTTP navigation was accepted",
        ),
        (
            {
                "schema_version": "rdc.browser/v2",
                "steps": [
                    {
                        "id": "open",
                        "type": "goto",
                        "url": "https://127.0.0.1/",
                        "wait_until": "load",
                    }
                ],
            },
            "IP-literal navigation was accepted",
        ),
        (
            {
                "schema_version": "rdc.browser/v2",
                "steps": [
                    {
                        "id": "open",
                        "type": "goto",
                        "url": "https://not-allowed.example/",
                        "wait_until": "load",
                    }
                ],
            },
            "non-allowlisted hostname was accepted",
        ),
        (
            {
                "schema_version": "rdc.browser/v2",
                "steps": [
                    {
                        "id": "click",
                        "type": "click",
                        "selector": "button",
                    }
                ],
            },
            "click action was accepted",
        ),
        (
            {
                "schema_version": "rdc.browser/v2",
                "steps": [
                    {
                        "id": "open",
                        "type": "goto",
                        "url": "https://example.com/",
                        "wait_until": "load",
                    },
                    {
                        "id": "shot",
                        "type": "screenshot",
                        "full_page": True,
                    },
                ],
            },
            "full-page screenshot was accepted",
        ),
    ]
    for value, message in cases:
        expect_error(
            module,
            lambda value=value: module.validate_browser_navigation_plan(
                value,
                policy=policy,
            ),
            message,
        )

    schema = json.loads(
        read(
            "packages/agent-protocol/schemas/"
            "browser-navigation.schema.json"
        )
    )
    require(
        schema.get("additionalProperties") is False,
        "v2 schema is not strict",
    )
    require(
        schema["properties"]["schema_version"]["const"]
        == "rdc.browser/v2",
        "v2 schema version changed",
    )

    v1_schema = json.loads(
        read(
            "packages/agent-protocol/schemas/"
            "browser-session.schema.json"
        )
    )
    require(
        v1_schema["properties"]["schema_version"]["const"]
        == "rdc.browser/v1",
        "Phase 1L browser v1 contract was mutated",
    )

    runtime = read("workers/browser-runtime/browser_runtime.py")
    require(
        'page.goto("about:blank"' in runtime,
        "Phase 1L runtime no longer stays on about:blank",
    )
    for forbidden in [
        "connect_over_cdp",
        "launch_server",
        "--remote-debugging-port",
    ]:
        require(
            forbidden not in runtime,
            "browser runtime gained forbidden live surface: " + forbidden,
        )

    executor = read("workers/sandbox-runtime/browser_executor.py")
    require(
        '"--network"' in executor and '"none"' in executor,
        "browser self-test runtime lost network-none",
    )
    require(
        '"--self-test"' in executor,
        "browser executor no longer self-test only",
    )

    run_schemas = read("apps/api/app/run_schemas.py")
    require(
        'Literal["rdc.browser/v1"]' in run_schemas,
        "Phase 1L API contract disappeared",
    )
    for marker in [
        'Literal["rdc.browser/v2"]',
        "browser_navigation: BrowserNavigationInput | None = None",
        "A Run may use only one external web/browser intent surface.",
    ]:
        require(marker in run_schemas, "v2 Run intent schema missing: " + marker)

    runs_service = read("apps/api/app/services/runs.py")
    for marker in [
        '"rdc.browser-navigation-receipt/v1"',
        '"request_digest": canonical_fingerprint(browser_navigation)',
        '"execution_enabled": False',
        '"dispatch_enabled": False',
        '"browser_network": "none"',
        '"browser_egress_gateway_required": True',
        'initial_status = "DRAFT" if navigation_receipt_only else "QUEUED"',
        "if not navigation_receipt_only:",
        '"run.browser_navigation_intent_recorded"',
    ]:
        require(
            marker in runs_service,
            "v2 Run receipt guard missing: " + marker,
        )

    plane = read("apps/api/app/services/execution_plane.py")
    require(
        plane.count('if "browser_navigation" in input_reference:') >= 2,
        "control plane does not explicitly deny v2 activation",
    )

    worker_source = read("workers/sandbox-runtime/worker.py")
    for marker in [
        "validate_browser_navigation_plan",
        '"rdc.browser-navigation-receipt/v1"',
        "Phase 1M browser navigation execution is not enabled.",
    ]:
        require(
            marker in worker_source,
            "worker v2 receipt guard missing: " + marker,
        )

    main_source = read("apps/api/app/main.py")
    for marker in [
        '"browser_navigation_request_contract": "rdc.browser/v2"',
        '"rdc.browser-navigation-receipt/v1"',
        '"browser_navigation_intent_contract_available": True',
        '"browser_navigation_dispatch_enabled": False',
        '"browser_public_navigation_enabled": False',
    ]:
        require(
            marker in main_source,
            "API v2 status guard missing: " + marker,
        )

    test_source = read("apps/api/tests/test_phase1m_contracts.py")
    require(
        "test_phase1m_run_request_allows_only_one_external_surface"
        in test_source,
        "Phase 1M API contract tests are missing",
    )

    root_readme = read("README.md")
    require(
        "Phase 1M in progress" in root_readme,
        "root README does not reflect current program state",
    )

    docs = read("docs/phase1m/README.md")
    for marker in [
        "rdc.browser/v2",
        "Chromium remains offline",
        "browser-egress gateway",
        "Phase 1L remains authoritative",
    ]:
        require(marker in docs, "Phase 1M docs missing: " + marker)

    print("Phase 1M receipt-only Run intent verification: PASS")
    print("  rdc.browser/v1 compatibility: PASS")
    print("  rdc.browser/v2 strict protocol: PASS")
    print("  bounded goto/wait/extract/screenshot validation: PASS")
    print("  exact HTTPS allowlist policy: PASS")
    print("  v2 Run intent + immutable receipt: PASS")
    print("  v2 initial status: DRAFT")
    print("  v2 START dispatch: BLOCKED")
    print("  control-plane v2 activation: BLOCKED")
    print("  worker independent v2 receipt validation: PASS")
    print("  browser runtime external navigation: NOT ENABLED")
    print("  browser runtime network: NONE")


if __name__ == "__main__":
    main()
