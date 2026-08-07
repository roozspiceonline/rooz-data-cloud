from config import SandboxWorkerConfig
from policy import verify_host


def main() -> None:
    probe = verify_host(SandboxWorkerConfig.from_env())
    print("RDC_PHASE1H_SANDBOX_PREFLIGHT_PASSED")
    print(probe.attestation)


if __name__ == "__main__":
    main()
