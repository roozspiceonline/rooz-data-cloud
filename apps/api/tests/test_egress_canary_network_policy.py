import ssl

import pytest

from app.egress_canary_network_policy import (
    BoundedResponse,
    CanaryNetworkLimits,
    CanaryNetworkPolicyError,
    environment_without_proxies,
    normalize_canary_hostname,
    reject_redirect,
    tls_client_context,
    validate_connected_peer,
    validate_dns_resolution,
    validate_global_address,
)


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.0.1",
        "169.254.169.254",
        "0.0.0.0",
        "224.0.0.1",
        "240.0.0.1",
        "::1",
        "fe80::1",
        "fc00::1",
        "ff02::1",
        "::ffff:127.0.0.1",
        "::ffff:10.0.0.1",
        "2001:db8::1",
    ],
)
def test_non_global_and_mapped_private_addresses_are_rejected(address: str) -> None:
    with pytest.raises(CanaryNetworkPolicyError):
        validate_global_address(address)


@pytest.mark.parametrize(
    "hostname",
    [
        "localhost",
        "localhost.localdomain",
        "metadata.google.internal",
        "service.internal",
        "service.local",
        "single-label",
        "127.0.0.1",
        "[::1]",
        "*.example.com",
    ],
)
def test_internal_special_use_and_ambiguous_hosts_are_rejected(hostname: str) -> None:
    with pytest.raises(CanaryNetworkPolicyError):
        normalize_canary_hostname(hostname)


def test_dns_rebinding_is_rejected_against_the_actual_connected_peer() -> None:
    target = validate_dns_resolution("canary.example.com", ["93.184.216.34"])
    assert validate_connected_peer(target, "93.184.216.34") == "93.184.216.34"
    with pytest.raises(CanaryNetworkPolicyError, match="non-global"):
        validate_connected_peer(target, "169.254.169.254")
    with pytest.raises(CanaryNetworkPolicyError, match="validated DNS set"):
        validate_connected_peer(target, "1.1.1.1")


def test_redirects_are_disabled_and_credentials_cannot_change_origin() -> None:
    reject_redirect(200, None)
    with pytest.raises(CanaryNetworkPolicyError, match="redirects are disabled"):
        reject_redirect(302, "https://other.example.com/")
    with pytest.raises(CanaryNetworkPolicyError, match="unexpected redirect"):
        reject_redirect(200, "https://other.example.com/")


def test_tls_context_requires_hostname_and_certificate_verification() -> None:
    context = tls_client_context()
    assert context.check_hostname is True
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.minimum_version >= ssl.TLSVersion.TLSv1_2


def test_proxy_environment_is_removed_case_insensitively() -> None:
    cleaned = environment_without_proxies(
        {
            "PATH": "/bin",
            "HTTP_PROXY": "http://attacker",
            "https_proxy": "http://attacker",
            "All_Proxy": "socks5://attacker",
            "NO_PROXY": "metadata.google.internal",
        }
    )
    assert cleaned == {"PATH": "/bin"}


def test_network_limits_and_response_bytes_are_bounded() -> None:
    limits = CanaryNetworkLimits(
        connect_timeout_seconds=2,
        total_timeout_seconds=5,
        max_response_bytes=8,
    )
    response = BoundedResponse(limits.max_response_bytes)
    response.accept(b"1234")
    response.accept(b"5678")
    with pytest.raises(CanaryNetworkPolicyError, match="exceeded"):
        response.accept(b"9")
    with pytest.raises(CanaryNetworkPolicyError, match="redirects"):
        CanaryNetworkLimits(2, 5, 8, max_redirects=1)
    with pytest.raises(CanaryNetworkPolicyError, match="timeout"):
        CanaryNetworkLimits(2, 31, 8)
