from __future__ import annotations

import importlib.util
import json
import re
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


def foundation_phase_at_least(
    source: str,
    *,
    minimum_major: int,
    minimum_letter: str,
) -> bool:
    marker = re.search(r'"phase": "(\d+)([A-Z])"', source)
    if marker is None:
        return False
    current = (int(marker.group(1)), ord(marker.group(2)))
    minimum = (minimum_major, ord(minimum_letter))
    return current >= minimum


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
    sys.modules["egress_policy"] = module
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



class _FakeResponse:
    def __init__(
        self,
        status: int,
        *,
        body: bytes = b"",
        headers: dict[str, str] | None = None,
    ) -> None:
        self.status = status
        self._body = body
        self._headers = dict(headers or {})

    def getheaders(self) -> list[tuple[str, str]]:
        return list(self._headers.items())

    def getheader(self, name: str) -> str | None:
        for key, value in self._headers.items():
            if key.casefold() == name.casefold():
                return value
        return None

    def read(self, amount: int | None = None) -> bytes:
        return self._body if amount is None else self._body[:amount]


class _FakeConnection:
    def __init__(self, response: _FakeResponse) -> None:
        self.response = response
        self.request_call = None

    def request(self, method: str, path: str, *, headers: dict[str, str]) -> None:
        self.request_call = (method, path, headers)

    def getresponse(self) -> _FakeResponse:
        return self.response

    def close(self) -> None:
        return None


class _FakeFactory:
    def __init__(self, responses: list[_FakeResponse]) -> None:
        self.responses = list(responses)
        self.connections: list[_FakeConnection] = []

    def __call__(self, target, policy):
        del target, policy
        if not self.responses:
            raise AssertionError("No fake response remains.")
        connection = _FakeConnection(self.responses.pop(0))
        self.connections.append(connection)
        return connection


def verify_broker_behavior(module: ModuleType) -> None:
    import importlib

    broker = importlib.import_module("egress_broker")
    policy = module.EgressPolicy.create(
        ["example.com", "redirect.example.com"]
    )

    success_factory = _FakeFactory(
        [
            _FakeResponse(
                200,
                body=b'{"ok":true}',
                headers={"Content-Type": "application/json"},
            )
        ]
    )
    result = broker.broker_web_requests(
        {
            "_rdc_web_requests": [
                {
                    "id": "homepage",
                    "method": "GET",
                    "url": "https://example.com/data",
                }
            ]
        },
        policy=policy,
        resolver=public_resolver,
        connection_factory=success_factory,
    )
    responses = result["_rdc_web_results"]
    require(len(responses) == 1, "broker result count changed")
    require(responses[0]["status"] == 200, "broker GET status changed")
    require(
        responses[0]["body_text"] == '{"ok":true}',
        "broker body decoding changed",
    )
    require(
        "_rdc_web_requests" not in result,
        "raw request contract leaked into Agent input",
    )

    redirect_factory = _FakeFactory(
        [
            _FakeResponse(
                302,
                headers={"Location": "https://redirect.example.com/final"},
            ),
            _FakeResponse(
                204,
                headers={"Content-Type": "text/plain"},
            ),
        ]
    )
    redirected = broker.broker_web_requests(
        {
            "_rdc_web_requests": [
                {
                    "id": "redirect",
                    "method": "HEAD",
                    "url": "https://example.com/start",
                }
            ]
        },
        policy=policy,
        resolver=public_resolver,
        connection_factory=redirect_factory,
    )
    require(
        redirected["_rdc_web_results"][0]["url"]
        == "https://redirect.example.com/final",
        "redirect target was not revalidated",
    )
    require(
        redirected["_rdc_web_budget"]["requests_used"] == 2,
        "redirect did not consume request budget",
    )

    expect_policy_error(
        module,
        lambda: broker.broker_web_requests(
            {
                "_rdc_web_requests": [
                    {
                        "id": "write",
                        "method": "POST",
                        "url": "https://example.com/",
                    }
                ]
            },
            policy=policy,
            resolver=public_resolver,
            connection_factory=_FakeFactory([]),
        ),
        "broker accepted POST",
    )


def verify_phase1j_fixture() -> None:
    fixture = ROOT / "examples" / "web-egress-canary"
    for relative in [
        "Dockerfile",
        "agent.json",
        "main.py",
        "schemas/input.json",
        "schemas/output.json",
    ]:
        require(
            (fixture / relative).is_file(),
            "web-egress canary fixture missing: " + relative,
        )

    manifest = json.loads(
        (fixture / "agent.json").read_text(encoding="utf-8")
    )
    caps = manifest["capabilities"]
    require(caps["network"] == "web-egress", "canary network capability changed")
    for name in ["browser", "dataset", "keyValueStore", "requestQueue"]:
        require(caps[name] is False, "forbidden canary capability: " + name)
    require(manifest.get("secrets") == [], "web-egress canary declares secrets")

    resources = manifest["resources"]
    require(resources["memoryMb"] <= 256, "canary memory too broad")
    require(resources["cpuUnits"] <= 500, "canary CPU too broad")
    require(resources["maxProcesses"] <= 64, "canary PID limit too broad")
    require(resources["ephemeralDiskMb"] <= 256, "canary disk too broad")
    require(resources["timeoutSeconds"] <= 120, "canary timeout too broad")

    source = (fixture / "main.py").read_text(encoding="utf-8")
    compile(source, "web-egress-canary/main.py", "exec")
    for prohibited in [
        "socket",
        "urllib",
        "requests",
        "http.client",
        "subprocess",
    ]:
        require(
            prohibited not in source,
            "canary contains direct network/runtime primitive: " + prohibited,
        )
    require(
        "_rdc_web_results" in source,
        "canary does not consume brokered results",
    )


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

    verify_broker_behavior(module)
    verify_phase1j_fixture()

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
    require(
        foundation_phase_at_least(
            main_api,
            minimum_major=1,
            minimum_letter="J",
        ),
        "foundation status is earlier than Phase 1J",
    )
    require(
        '"brokered_web_egress_enabled"' in main_api,
        "Phase 1J status signal is missing",
    )
    require(
        '"untrusted_agent_execution_enabled": False' in main_api,
        "general untrusted execution was enabled",
    )

    console = read(
        "apps/console/src/components/execution-plane-overview.tsx"
    )
    for marker in [
        "Phase 1J",
        "Brokered HTTPS canary",
        "Agent container stays --network none",
        "operator allowlist",
        "GET/HEAD",
        "defaults off",
        "General untrusted execution remains release-blocked",
    ]:
        require(marker in console, "console evidence missing: " + marker)

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

    print("Phase 1J final verification: PASS")
    print("  broker behavioral tests: PASS")
    print("  web-egress canary fixture: PASS")
    print("  console/operator evidence: PASS")
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
