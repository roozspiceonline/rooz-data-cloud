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


def load_policy_module() -> ModuleType:
    path = ROOT / "workers" / "sandbox-runtime" / "egress_policy.py"
    require(path.is_file(), "worker egress policy module is missing")
    spec = importlib.util.spec_from_file_location("rdc_phase1j_egress_policy", path)
    require(spec is not None and spec.loader is not None, "cannot load egress policy")
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
    require(policy.allowed_hosts == ("example.com",), "hostname normalization changed")
    require(len(policy.digest) == 64, "egress policy digest is not sha256 sized")
    require(
        policy.digest == module.EgressPolicy.create(["example.com"]).digest,
        "canonical policy digest is not deterministic",
    )

    normalized = policy.validate_url(
        "https://EXAMPLE.com/path?q=1#fragment",
        resolver=public_resolver,
    )
    require(
        normalized == "https://example.com/path?q=1",
        "URL normalization or fragment stripping changed",
    )
    require(
        policy.validate_redirect(
            "https://example.com/next",
            resolver=public_resolver,
        )
        == "https://example.com/next",
        "redirect validation changed",
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
            "https://93.184.216.34/",
            resolver=public_resolver,
        ),
        "IP-literal URL was accepted",
    )
    expect_policy_error(
        module,
        lambda: policy.validate_url(
            "https://user:pass@example.com/",
            resolver=public_resolver,
        ),
        "URL credentials were accepted",
    )
    expect_policy_error(
        module,
        lambda: policy.validate_url(
            "https://example.com:444/",
            resolver=public_resolver,
        ),
        "non-443 HTTPS port was accepted",
    )
    expect_policy_error(
        module,
        lambda: policy.validate_url(
            "https://example.com/",
            resolver=private_resolver,
        ),
        "metadata/private DNS answer was accepted",
    )
    expect_policy_error(
        module,
        lambda: policy.validate_redirect(
            "https://example.com/",
            resolver=private_resolver,
        ),
        "redirect DNS revalidation was bypassed",
    )

    schema_path = (
        ROOT
        / "packages"
        / "agent-protocol"
        / "schemas"
        / "web-egress-policy.schema.json"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    require(schema.get("additionalProperties") is False, "egress schema is not strict")
    require(
        schema["properties"]["container_network"].get("const") == "none",
        "protocol schema no longer requires container network none",
    )

    run_executor = (
        ROOT / "workers" / "sandbox-runtime" / "run_executor.py"
    ).read_text(encoding="utf-8")
    require('"--network"' in run_executor, "runtime network flag is missing")
    require('"none"' in run_executor, "runtime no-network boundary is missing")

    readme = (ROOT / "docs" / "phase1j" / "README.md").read_text(encoding="utf-8")
    runbook = (ROOT / "docs" / "phase1j" / "RUNBOOK.md").read_text(encoding="utf-8")
    require(
        "not enable any new runtime capability" in readme,
        "foundation safety boundary is undocumented",
    )
    require(
        "General untrusted Agent execution must remain disabled." in runbook,
        "runbook release boundary is missing",
    )

    print("Phase 1J foundation verification: PASS")
    print("  exact-host HTTPS allowlisting: PASS")
    print("  IP-literal rejection: PASS")
    print("  public-DNS-only enforcement: PASS")
    print("  redirect revalidation primitive: PASS")
    print("  canonical policy digest: PASS")
    print("  Agent container --network none boundary: PASS")
    print("  runtime egress activation: NOT ENABLED (expected)")


if __name__ == "__main__":
    main()
