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

    egress_module = load_module(
        "workers/sandbox-runtime/egress_policy.py",
        "rdc_phase1m_egress_policy",
    )
    sys.modules["egress_policy"] = egress_module
    browser_egress_module = load_module(
        "workers/sandbox-runtime/browser_egress_policy.py",
        "rdc_phase1m_browser_egress_policy",
    )
    base_egress = egress_module.EgressPolicy.create(
        ("example.com", "www.example.com"),
        max_requests=8,
        max_response_bytes=1_048_576,
        max_total_bytes=4_194_304,
        max_redirects=3,
        connect_timeout_seconds=5,
        request_timeout_seconds=15,
    )
    browser_egress = browser_egress_module.BrowserEgressPolicy.create(
        base_egress
    )

    def public_resolver(*args, **kwargs):
        return [
            (
                None,
                None,
                None,
                None,
                ("93.184.216.34", 443),
            )
        ]

    def private_resolver(*args, **kwargs):
        return [
            (
                None,
                None,
                None,
                None,
                ("127.0.0.1", 443),
            )
        ]

    validated_resource = browser_egress.validate_resource(
        resource_type="document",
        method="GET",
        url="https://example.com/",
        resolver=public_resolver,
    )
    require(
        validated_resource.target.hostname == "example.com",
        "browser gateway hostname validation changed",
    )
    require(
        validated_resource.target.addresses == ("93.184.216.34",),
        "browser gateway address pin set changed",
    )
    require(
        len(browser_egress.digest) == 64,
        "browser gateway digest is not SHA-256 sized",
    )
    gateway_payload = browser_egress.as_dict()
    for marker, expected in [
        ("deny_ip_literals", True),
        ("require_global_dns", True),
        ("pin_validated_address", True),
        ("revalidate_redirects", True),
        ("revalidate_subresources", True),
        ("service_workers_enabled", False),
        ("websockets_enabled", False),
        ("webrtc_enabled", False),
        ("proxy_override_enabled", False),
        ("persistent_cookies_enabled", False),
        ("transport_wired", False),
        ("browser_network", "none"),
    ]:
        require(
            gateway_payload.get(marker) == expected,
            "browser gateway invariant changed: " + marker,
        )

    gateway_rejections = [
        (
            lambda: browser_egress.validate_resource(
                resource_type="websocket",
                method="GET",
                url="https://example.com/",
                resolver=public_resolver,
            ),
            "WebSocket resource type was accepted",
        ),
        (
            lambda: browser_egress.validate_resource(
                resource_type="document",
                method="POST",
                url="https://example.com/",
                resolver=public_resolver,
            ),
            "POST browser gateway request was accepted",
        ),
        (
            lambda: browser_egress.validate_resource(
                resource_type="document",
                method="GET",
                url="http://example.com/",
                resolver=public_resolver,
            ),
            "HTTP browser gateway target was accepted",
        ),
        (
            lambda: browser_egress.validate_resource(
                resource_type="image",
                method="GET",
                url="https://not-allowed.example/image.png",
                resolver=public_resolver,
            ),
            "non-allowlisted browser subresource was accepted",
        ),
        (
            lambda: browser_egress.validate_resource(
                resource_type="fetch",
                method="GET",
                url="https://example.com/api",
                resolver=private_resolver,
            ),
            "private DNS result was accepted",
        ),
    ]
    for call, message in gateway_rejections:
        try:
            call()
        except browser_egress_module.BrowserEgressPolicyError:
            pass
        else:
            raise SystemExit(
                "Phase 1M verification failed: " + message
            )

    gateway_schema = json.loads(
        read(
            "packages/agent-protocol/schemas/"
            "browser-egress-policy.schema.json"
        )
    )
    require(
        gateway_schema.get("additionalProperties") is False,
        "browser gateway schema is not strict",
    )
    require(
        gateway_schema["properties"]["schema_version"]["const"]
        == "rdc.browser-egress-policy/v1",
        "browser gateway schema version changed",
    )

    gateway_transport_module = load_module(
        "workers/sandbox-runtime/browser_gateway_transport.py",
        "rdc_phase1m_browser_gateway_transport",
    )
    transport_digest = "a" * 64
    valid_ping = {
        "schema_version": "rdc.browser-gateway-ping/v1",
        "nonce": "b" * 32,
        "gateway_policy_digest": transport_digest,
    }
    pong = gateway_transport_module.validate_gateway_ping(
        valid_ping,
        gateway_policy_digest=transport_digest,
    )
    require(
        pong["transport"] == "unix"
        and pong["external_request"] is False
        and pong["live_forwarding"] is False,
        "browser gateway Unix handshake contract changed",
    )
    for invalid_ping in [
        {**valid_ping, "gateway_policy_digest": "c" * 64},
        {**valid_ping, "nonce": "not-a-safe-nonce"},
        {**valid_ping, "unknown": True},
    ]:
        try:
            gateway_transport_module.validate_gateway_ping(
                invalid_ping,
                gateway_policy_digest=transport_digest,
            )
        except gateway_transport_module.BrowserGatewayTransportError:
            pass
        else:
            raise SystemExit(
                "Phase 1M verification failed: "
                "unsafe gateway Unix handshake was accepted"
            )

    transport_schema = json.loads(
        read(
            "packages/agent-protocol/schemas/"
            "browser-gateway-transport-self-test.schema.json"
        )
    )
    require(
        transport_schema.get("additionalProperties") is False,
        "browser gateway transport schema is not strict",
    )
    require(
        transport_schema["properties"]["schema_version"]["const"]
        == "rdc.browser-gateway-transport-self-test/v1",
        "browser gateway transport schema version changed",
    )

    gateway_transport_source = read(
        "workers/sandbox-runtime/browser_gateway_transport.py"
    )
    for forbidden in [
        "AF_INET",
        "getaddrinfo",
        "http.client",
        "urllib.request",
        "ssl.",
    ]:
        require(
            forbidden not in gateway_transport_source,
            "gateway transport self-test gained live network surface: "
            + forbidden,
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

    for marker in [
        "socket.AF_UNIX",
        '"/rdc-ipc/gateway.sock"',
        '"rdc.browser-gateway-ping/v1"',
        '"rdc.browser-gateway-transport-self-test/v1"',
        '"browser_network": "none"',
    ]:
        require(
            marker in runtime,
            "browser runtime Unix transport guard missing: " + marker,
        )
    require(
        "--url" not in runtime,
        "browser runtime gained a direct public URL argument",
    )

    for marker in [
        "run_browser_transport_self_test",
        '"--transport-self-test"',
        '":/rdc-ipc:ro"',
        '"/rdc-ipc/gateway.sock"',
        '"--gateway-policy-digest"',
    ]:
        require(
            marker in executor,
            "browser executor Unix transport guard missing: " + marker,
        )
    for forbidden in [
        '"--network",\n        "host"',
        '"--publish"',
        "containerd.sock:/",
        "docker.sock:/",
    ]:
        require(
            forbidden not in executor,
            "browser executor gained forbidden network/socket surface: "
            + forbidden,
        )

    main_source = read("apps/api/app/main.py")
    for marker in [
        '"rdc.browser-gateway-transport-self-test/v1"',
        '"browser_gateway_transport_mode": "unix-domain-socket"',
        '"browser_gateway_transport_self_test_available": True',
        '"browser_gateway_live_forwarding_enabled": False',
    ]:
        require(
            marker in main_source,
            "API Unix gateway transport guard missing: " + marker,
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
        '"rdc.browser-egress-policy/v1"',
        '"browser_egress_policy_digest": browser_egress_policy_digest',
        '"browser_egress_transport_wired": False',
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
        "BrowserEgressPolicy.create",
        "Phase 1M browser navigation execution is not enabled.",
    ]:
        require(
            marker in worker_source,
            "worker v2 receipt guard missing: " + marker,
        )

    for marker in [
        '"browser_navigation_request_contract": "rdc.browser/v2"',
        '"rdc.browser-navigation-receipt/v1"',
        '"browser_navigation_intent_contract_available": True',
        '"browser_navigation_dispatch_enabled": False',
        '"browser_egress_policy_contract": "rdc.browser-egress-policy/v1"',
        '"browser_egress_transport_wired": False',
        '"browser_egress_subresource_revalidation": True',
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

    print("  Unix browser->gateway transport self-test: PASS")
    print("  Chromium network: NONE")
    print("  gateway external request: FALSE")
    print("  gateway live forwarding: FALSE")
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
    print("  browser egress gateway policy + digest: PASS")
    print("  global DNS/address pinning contract: PASS")
    print("  redirect/subresource revalidation contract: PASS")
    print("  browser egress transport: NOT WIRED")
    print("  browser runtime external navigation: NOT ENABLED")
    print("  browser runtime network: NONE")


if __name__ == "__main__":
    main()
