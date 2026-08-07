from __future__ import annotations

import importlib.util
import json
import socket
import sys
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).parents[1]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit("Phase 1J verification failed: " + message)


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def load_policy_module() -> ModuleType:
    worker_dir = ROOT / "workers" / "sandbox-runtime"
    path = worker_dir / "egress_policy.py"
    require(path.is_file(), "worker egress policy module is missing")
    sys.path.insert(0, str(worker_dir))
    spec = importlib.util.spec_from_file_location(
        "rdc_phase1j_egress_policy",
        path,
    )
    require(
        spec is not None and spec.loader is not None,
        "cannot load egress policy",
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def public_resolver(
    host: str,
    port: int,
    *,
    family: int,
    type: int,
) -> list[tuple[object, ...]]:
    del host, family, type
    return [
        (
            socket.AF_INET,
            socket.SOCK_STREAM,
            6,
            "",
            ("93.184.216.34", port),
        )
    ]


def private_resolver(
    host: str,
    port: int,
    *,
    family: int,
    type: int,
) -> list[tuple[object, ...]]:
    del host, family, type
    return [
        (
            socket.AF_INET,
            socket.SOCK_STREAM,
            6,
            "",
            ("169.254.169.254", port),
        )
    ]


def expect_policy_error(module: ModuleType, call, message: str) -> None:
    try:
        call()
    except module.EgressPolicyError:
        return
    raise SystemExit("Phase 1J verification failed: " + message)


def main() -> None:
    module = load_policy_module()
    policy = module.EgressPolicy.create(["Example.COM."])
    require(
        policy.allowed_hosts == ("example.com",),
        "hostname normalization changed",
    )
    require(len(policy.digest) == 64, "egress policy digest is invalid")
    require(
        policy.digest == module.EgressPolicy.create(["example.com"]).digest,
        "canonical policy digest is not deterministic",
    )
    target = policy.validate_target(
        "https://EXAMPLE.com/path?q=1#fragment",
        resolver=public_resolver,
    )
    require(
        target.url == "https://example.com/path?q=1",
        "URL normalization changed",
    )
    require(
        target.addresses == ("93.184.216.34",),
        "validated public DNS address is not pinned",
    )

    expect_policy_error(
        module,
        lambda: policy.validate_url(
            "http://example.com/",
            resolver=public_resolver,
        ),
        "HTTP URL was accepted",
    )
    expect_policy_error(
        module,
        lambda: module.EgressPolicy.create(["*.example.com"]),
        "wildcard allowlist was accepted",
    )
    expect_policy_error(
        module,
        lambda: module.EgressPolicy.create(["127.0.0.1"]),
        "IP-literal allowlist was accepted",
    )
    expect_policy_error(
        module,
        lambda: policy.validate_url(
            "https://example.com/",
            resolver=private_resolver,
        ),
        "private DNS answer was accepted",
    )

    activation_schema = json.loads(
        read("packages/agent-protocol/schemas/sandbox-activation.schema.json")
    )
    profiles = activation_schema["properties"]["capability_profile"]["enum"]
    require(
        "offline-minimal" in profiles and "brokered-web-egress" in profiles,
        "activation schema is missing Phase 1J profile",
    )
    require(
        "egress_policy_digest" in activation_schema["required"],
        "activation schema does not bind egress policy",
    )

    broker = read("workers/sandbox-runtime/egress_broker.py")
    compile(broker, "egress_broker.py", "exec")
    for marker in [
        "socket.create_connection(",
        "server_hostname=self.host",
        '"Accept-Encoding": "identity"',
        "_rdc_web_requests",
        "_rdc_web_results",
        'method not in {"GET", "HEAD"}',
        "policy.validate_target(",
    ]:
        require(marker in broker, "broker marker missing: " + marker)

    run_executor = read("workers/sandbox-runtime/run_executor.py")
    require('"--network"' in run_executor, "runtime network flag is missing")
    require('"none"' in run_executor, "runtime no-network boundary is missing")

    api_config = read("apps/api/app/core/config.py")
    for marker in [
        "sandbox_canary_web_egress_enabled: bool = False",
        "sandbox_canary_web_egress_allowed_hosts",
        "sandbox_canary_web_egress_max_requests",
    ]:
        require(marker in api_config, "API egress config missing: " + marker)

    execution_schema = read("apps/api/app/execution_schemas.py")
    for marker in [
        "brokered-web-egress",
        "egress_policy_digest",
        "validate_capability_receipt",
    ]:
        require(marker in execution_schema, "activation contract missing: " + marker)

    service = read("apps/api/app/services/execution_plane.py")
    for marker in [
        "_egress_policy_payload",
        "sandbox_canary_web_egress_enabled",
        "canonical_fingerprint(_egress_policy_payload())",
        '"brokered_web_egress": network == "web-egress"',
    ]:
        require(marker in service, "control-plane guard missing: " + marker)

    worker = read("workers/sandbox-runtime/worker.py")
    for marker in [
        "broker_web_requests",
        "_worker_egress_policy",
        "egress_policy.digest",
        "brokered-web-egress",
    ]:
        require(marker in worker, "worker guard missing: " + marker)

    env_example = read(".env.example")
    require(
        "RDC_SANDBOX_CANARY_WEB_EGRESS_ENABLED=false" in env_example,
        "egress gate does not default false",
    )
    require(
        "RDC_SANDBOX_CANARY_WEB_EGRESS_ALLOWED_HOSTS=[]" in env_example,
        "egress allowlist does not default empty",
    )

    workflow = read(".github/workflows/ci.yml")
    require(
        'RDC_SANDBOX_CANARY_WEB_EGRESS_ENABLED: "false"' in workflow,
        "CI egress gate is not explicitly false",
    )

    main_api = read("apps/api/app/main.py")
    require('"phase": "1J"' in main_api, "foundation phase is not 1J")
    require(
        '"brokered_web_egress_enabled"' in main_api,
        "Phase 1J status signal is missing",
    )
    require(
        '"untrusted_agent_execution_enabled": False' in main_api,
        "general untrusted execution was enabled",
    )

    readme = read("docs/phase1j/README.md")
    runbook = read("docs/phase1j/RUNBOOK.md")
    require(
        "Agent container remains network-isolated" in readme,
        "README container boundary is missing",
    )
    require(
        "General untrusted Agent execution must remain disabled." in runbook,
        "runbook release boundary is missing",
    )

    print("Phase 1J broker integration verification: PASS")
    print("  exact-host HTTPS allowlisting: PASS")
    print("  private-network rejection: PASS")
    print("  DNS address pinning: PASS")
    print("  egress-policy digest binding: PASS")
    print("  worker-side broker contract: PASS")
    print("  Agent container --network none boundary: PASS")
    print("  web-egress gate default false: PASS")
    print("  general untrusted execution: BLOCKED")


if __name__ == "__main__":
    main()
