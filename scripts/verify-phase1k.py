from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).parents[1]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit("Phase 1K verification failed: " + message)


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def load_contract() -> ModuleType:
    path = ROOT / "workers" / "sandbox-runtime" / "web_fetch_contract.py"
    require(path.is_file(), "web-fetch contract module is missing")
    spec = importlib.util.spec_from_file_location(
        "rdc_phase1k_web_fetch_contract",
        path,
    )
    require(
        spec is not None and spec.loader is not None,
        "cannot load web-fetch contract",
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def expect_error(module: ModuleType, call, message: str) -> None:
    try:
        call()
    except module.WebFetchContractError:
        return
    raise SystemExit("Phase 1K verification failed: " + message)


def main() -> None:
    module = load_contract()

    request = {
        "schema_version": "rdc.web-fetch/v1",
        "requests": [
            {
                "id": "homepage",
                "method": "get",
                "url": "https://example.com/",
            },
            {
                "id": "head",
                "method": "HEAD",
                "url": "https://example.com/robots.txt",
            },
        ],
    }
    envelope = module.parse_web_fetch_envelope(request)
    require(envelope.requests[0].method == "GET", "method normalization changed")
    require(len(envelope.digest) == 64, "request digest is not sha256-sized")
    require(
        envelope.digest == module.canonical_web_fetch_digest(request),
        "canonical request digest is not deterministic",
    )

    broker_input = module.phase1j_broker_adapter(request)
    require(
        set(broker_input) == {"_rdc_web_requests"},
        "adapter exposes unexpected Phase 1J fields",
    )

    empty_digest = hashlib.sha256(b"").hexdigest()
    broker_output = {
        "_rdc_web_results": [
            {
                "id": "homepage",
                "method": "GET",
                "url": "https://example.com/",
                "status": 200,
                "headers": {"content-type": "text/plain"},
                "body_text": "hello",
                "body_base64": None,
                "size_bytes": 5,
                "body_sha256": hashlib.sha256(b"hello").hexdigest(),
            },
            {
                "id": "head",
                "method": "HEAD",
                "url": "https://example.com/robots.txt",
                "status": 204,
                "headers": {},
                "body_text": None,
                "body_base64": None,
                "size_bytes": 0,
                "body_sha256": empty_digest,
            },
        ],
        "_rdc_web_budget": {
            "requests_used": 2,
            "bytes_received": 5,
            "max_requests": 8,
            "max_total_bytes": 4194304,
        },
    }
    result = module.phase1j_broker_result_adapter(request, broker_output)
    require(
        result["schema_version"] == "rdc.web-fetch-result/v1",
        "result schema version changed",
    )
    require(
        result["request_digest"] == envelope.digest,
        "result does not bind request digest",
    )
    results = result["results"]
    require(isinstance(results, list), "result list is missing")
    first = results[0]
    second = results[1]
    require(
        first["body"]["sha256"]
        == hashlib.sha256(b"hello").hexdigest(),
        "response body lineage digest changed",
    )
    require(
        second["body"]["encoding"] == "none",
        "HEAD result body representation changed",
    )

    expect_error(
        module,
        lambda: module.parse_web_fetch_envelope(
            {
                "schema_version": "rdc.web-fetch/v1",
                "requests": [
                    {
                        "id": "write",
                        "method": "POST",
                        "url": "https://example.com/",
                    }
                ],
            }
        ),
        "POST was accepted",
    )
    expect_error(
        module,
        lambda: module.parse_web_fetch_envelope(
            {
                "schema_version": "rdc.web-fetch/v1",
                "requests": [
                    {
                        "id": "plain",
                        "method": "GET",
                        "url": "http://example.com/",
                    }
                ],
            }
        ),
        "HTTP URL was accepted",
    )

    request_schema = json.loads(
        read(
            "packages/agent-protocol/schemas/"
            "web-fetch-envelope.schema.json"
        )
    )
    result_schema = json.loads(
        read(
            "packages/agent-protocol/schemas/"
            "web-fetch-result.schema.json"
        )
    )
    require(
        request_schema.get("additionalProperties") is False,
        "request schema is not strict",
    )
    require(
        result_schema.get("additionalProperties") is False,
        "result schema is not strict",
    )
    require(
        result_schema["properties"]["schema_version"]["const"]
        == "rdc.web-fetch-result/v1",
        "result protocol version changed",
    )

    run_schemas = read("apps/api/app/run_schemas.py")
    for marker in [
        "class WebFetchRequestInput",
        "class WebFetchEnvelopeInput",
        "web_fetch: WebFetchEnvelopeInput | None = None",
        "Web-fetch envelope cannot exceed 64 KiB.",
    ]:
        require(marker in run_schemas, "Run contract missing: " + marker)

    runs_service = read("apps/api/app/services/runs.py")
    for marker in [
        '"WEB_FETCH_CAPABILITY_REQUIRED"',
        '"web_fetch": web_fetch',
        'input_reference["web_fetch"] = web_fetch',
    ]:
        require(marker in runs_service, "Run integration missing: " + marker)

    egress_broker = read("workers/sandbox-runtime/egress_broker.py")
    for marker in [
        "body_sha256",
        "hashlib.sha256(body).hexdigest()",
        'method not in {"GET", "HEAD"}',
        '"Accept-Encoding": "identity"',
    ]:
        require(marker in egress_broker, "broker lineage guard missing: " + marker)

    worker = read("workers/sandbox-runtime/worker.py")
    for marker in [
        'web_fetch = input_ref.get("web_fetch")',
        "phase1j_broker_adapter",
        "phase1j_broker_result_adapter",
        '"_rdc_web_fetch_result"',
        '"WEB_FETCH_CONTRACT_INVALID"',
        '"WEB_FETCH_POLICY_DENIED"',
        '"_rdc_web_requests" in input_value',
    ]:
        require(marker in worker, "worker integration missing: " + marker)

    run_executor = read("workers/sandbox-runtime/run_executor.py")
    require(
        '"--network"' in run_executor and '"none"' in run_executor,
        "Agent container no-network boundary changed",
    )

    main_api = read("apps/api/app/main.py")
    for marker in [
        '"web_fetch_request_contract": "rdc.web-fetch/v1"',
        '"web_fetch_result_contract": "rdc.web-fetch-result/v1"',
        '"versioned_web_fetch_contract_available": True',
        '"web_fetch_activation_scope": "phase1j-single-canary"',
        '"browser_execution_enabled": _browser_live_navigation_canary_enabled()',
        '"untrusted_agent_execution_enabled": False',
    ]:
        require(
            marker in main_api,
            "Phase 1K web-fetch foundation compatibility missing: " + marker,
        )

    env_example = read(".env.example")
    require(
        "RDC_SANDBOX_CANARY_WEB_EGRESS_ENABLED=false" in env_example,
        "web-egress gate no longer defaults false",
    )
    require(
        "RDC_SANDBOX_CANARY_WEB_EGRESS_ALLOWED_HOSTS=[]" in env_example,
        "web-egress allowlist no longer defaults empty",
    )
    require(
        "RDC_SANDBOX_CANARY_BROWSER_LIVE_NAVIGATION_ENABLED=false"
        in env_example,
        "live browser navigation no longer defaults false",
    )

    canary_manifest = json.loads(
        read("examples/web-egress-canary/agent.json")
    )
    capabilities = canary_manifest["capabilities"]
    require(
        capabilities["network"] == "web-egress",
        "legacy canary network declaration changed",
    )
    for capability in [
        "browser",
        "dataset",
        "keyValueStore",
        "requestQueue",
    ]:
        require(
            capabilities[capability] is False,
            "legacy canary capability broadened: " + capability,
        )
    require(
        canary_manifest.get("secrets") == [],
        "legacy canary now declares secrets",
    )

    console = read(
        "apps/console/src/components/execution-plane-overview.tsx"
    )
    for marker in [
        "Phase 1K",
        "Phase 1J",
        "Versioned web fetch",
        "top-level web_fetch",
        "rdc.web-fetch/v1",
        "_rdc_web_fetch_result",
        "rdc.web-fetch-result/v1",
        "SHA-256 lineage",
        "Agent container stays --network none",
        "web-egress gate defaults off",
        "General untrusted execution remains release-blocked",
    ]:
        require(marker in console, "console evidence missing: " + marker)

    phase1k_console_test = read(
        "apps/console/tests/phase1k-contract.test.mjs"
    )
    require(
        "Phase 1K console exposes versioned web-fetch safety evidence"
        in phase1k_console_test,
        "Phase 1K console regression test is missing",
    )
    phase1j_console_test = read(
        "apps/console/tests/phase1j-contract.test.mjs"
    )
    require(
        "Phase 1J console explains brokered web-egress boundary"
        in phase1j_console_test,
        "Phase 1J console compatibility test is missing",
    )

    readme = read("docs/phase1k/README.md")
    runbook = read("docs/phase1k/RUNBOOK.md")
    for marker in [
        "top-level `web_fetch`",
        "`_rdc_web_fetch_result`",
        "Phase 1J legacy compatibility",
        "--network none",
    ]:
        require(marker in readme, "README integration missing: " + marker)
    require(
        "WEB_FETCH_CONTRACT_INVALID" in runbook
        and "WEB_FETCH_POLICY_DENIED" in runbook,
        "runbook failure codes are missing",
    )
    require(
        "General untrusted Agent execution remains release-blocked."
        in runbook,
        "release boundary is missing",
    )

    print("Phase 1K final verification: PASS")
    print("  Phase 1K web-fetch foundation compatibility: PASS")
    print("  console/operator evidence: PASS")
    print("  Phase 1J compatibility regression: PASS")
    print("  versioned Run web_fetch contract: PASS")
    print("  API + worker independent validation: PASS")
    print("  Phase 1J broker compatibility: PASS")
    print("  versioned Agent result injection: PASS")
    print("  response SHA-256 lineage: PASS")
    print("  bounded failure codes: PASS")
    print("  Agent container --network none: PASS")
    print("  activation broadening: NOT ENABLED")
    print("  general untrusted execution: BLOCKED")


if __name__ == "__main__":
    main()
