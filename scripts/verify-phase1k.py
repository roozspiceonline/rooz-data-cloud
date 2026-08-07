from __future__ import annotations

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
    require(spec is not None and spec.loader is not None, "cannot load contract")
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
    raw = {
        "schema_version": "rdc.web-fetch/v1",
        "requests": [
            {"id": "homepage", "method": "get", "url": "https://example.com/"},
            {"id": "head", "method": "HEAD", "url": "https://example.com/robots.txt"},
        ],
    }
    envelope = module.parse_web_fetch_envelope(raw)
    require(envelope.requests[0].method == "GET", "method normalization changed")
    require(len(envelope.digest) == 64, "digest is not sha256-sized")
    require(
        envelope.digest == module.canonical_web_fetch_digest(raw),
        "canonical digest is not deterministic",
    )
    broker_input = module.phase1j_broker_adapter(raw)
    require(
        set(broker_input) == {"_rdc_web_requests"},
        "adapter exposes unexpected transport fields",
    )

    expect_error(
        module,
        lambda: module.parse_web_fetch_envelope(
            {
                "schema_version": "rdc.web-fetch/v1",
                "requests": [
                    {"id": "write", "method": "POST", "url": "https://example.com/"}
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
                    {"id": "plain", "method": "GET", "url": "http://example.com/"}
                ],
            }
        ),
        "HTTP URL was accepted",
    )

    schema = json.loads(
        read("packages/agent-protocol/schemas/web-fetch-envelope.schema.json")
    )
    require(schema.get("additionalProperties") is False, "schema is not strict")
    require(
        schema["properties"]["schema_version"].get("const") == "rdc.web-fetch/v1",
        "schema version changed",
    )

    broker = read("workers/sandbox-runtime/egress_broker.py")
    require("_rdc_web_requests" in broker, "Phase 1J broker transport is missing")
    require(
        'method not in {"GET", "HEAD"}' in broker,
        "Phase 1J method boundary changed",
    )

    run_executor = read("workers/sandbox-runtime/run_executor.py")
    require(
        '"--network"' in run_executor and '"none"' in run_executor,
        "Agent container no-network boundary changed",
    )

    readme = read("docs/phase1k/README.md")
    runbook = read("docs/phase1k/RUNBOOK.md")
    for marker in [
        "rdc.web-fetch/v1",
        "does **not** activate or broaden runtime web access",
        "--network none",
        "operator-owned policy",
    ]:
        require(marker in readme, "README missing: " + marker)
    require(
        "General untrusted Agent execution remains release-blocked." in runbook,
        "release boundary is missing",
    )

    print("Phase 1K foundation verification: PASS")
    print("  rdc.web-fetch/v1 strict contract: PASS")
    print("  GET/HEAD + HTTPS boundary: PASS")
    print("  canonical request digest: PASS")
    print("  Phase 1J broker adapter: PASS")
    print("  Agent container --network none: PASS")
    print("  runtime activation broadening: NOT ENABLED")
    print("  general untrusted execution: BLOCKED")


if __name__ == "__main__":
    main()
