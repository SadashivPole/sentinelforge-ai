"""Tests for IOC validation and canonicalization (sentinelforge.threat_intel.validator).

Scenarios:
1. IPv4 valid and invalid inputs
2. IPv6 valid and invalid inputs
3. Domain valid and invalid inputs (conservative normalization)
4. URL valid and invalid inputs
5. SHA256 valid and invalid inputs
6. Unknown indicator type rejection
7. Non-string input rejection
"""

from __future__ import annotations

import pytest

from sentinelforge.threat_intel.validator import (
    ValidationError,
    validate_domain,
    validate_indicator,
    validate_ipv4,
    validate_ipv6,
    validate_sha256,
    validate_url,
)


# --------------------------------------------------------------------------- #
# IPv4
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "value,expected",
    [
        ("192.168.1.1", "192.168.1.1"),
        ("  10.0.0.1  ", "10.0.0.1"),
        ("0.0.0.0", "0.0.0.0"),
        ("255.255.255.255", "255.255.255.255"),
    ],
)
def test_validate_ipv4_valid(value: str, expected: str) -> None:
    assert validate_ipv4(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "256.1.1.1",
        "1.2.3",
        "1.2.3.4.5",
        "abc.def.ghi.jkl",
        "",
        "192.168.1.1 extra",
        "192.168.1",
    ],
)
def test_validate_ipv4_invalid(value: object) -> None:
    with pytest.raises(ValidationError):
        validate_ipv4(value)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# IPv6
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "value,expected",
    [
        ("2001:db8::1", "2001:db8::1"),
        ("::1", "::1"),
        ("fe80::1%25eth0", "fe80::1%25eth0"),
        ("2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1"),
    ],
)
def test_validate_ipv6_valid(value: str, expected: str) -> None:
    assert validate_ipv6(value) == expected


@pytest.mark.parametrize(
    "value",
    ["2001:db8::1::2", "zzzz::1", "", "not-an-ipv6", "192.168.1.1"],
)
def test_validate_ipv6_invalid(value: object) -> None:
    with pytest.raises(ValidationError):
        validate_ipv6(value)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# Domain
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "value,expected",
    [
        ("example.com", "example.com"),
        ("Example.COM.", "example.com"),
        ("  sub.domain.org  ", "sub.domain.org"),
        ("internal-host.local", "internal-host.local"),
    ],
)
def test_validate_domain_valid(value: str, expected: str) -> None:
    assert validate_domain(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "",
        "   ",
        "-example.com",
        "example-.com",
        "example..com",
        "a" * 64 + ".com",  # label over 63 chars
        "not a domain",
        "http://example.com",
        "example",
    ],
)
def test_validate_domain_invalid(value: object) -> None:
    with pytest.raises(ValidationError):
        validate_domain(value)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# URL
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "value,expected",
    [
        ("https://example.com/path", "https://example.com/path"),
        ("HTTP://Example.COM/", "http://example.com/"),
        ("http://example.com:8080/q?x=1", "http://example.com:8080/q?x=1"),
    ],
)
def test_validate_url_valid(value: str, expected: str) -> None:
    assert validate_url(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "",
        "not a url",
        "example.com",
        "http://",
    ],
)
def test_validate_url_invalid(value: object) -> None:
    with pytest.raises(ValidationError):
        validate_url(value)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# SHA256
# --------------------------------------------------------------------------- #
SHA256 = "a" * 64


def test_validate_sha256_valid() -> None:
    assert validate_sha256(SHA256) == SHA256
    assert validate_sha256("A" * 64) == ("a" * 64)  # canonicalized to lowercase


@pytest.mark.parametrize(
    "value",
    ["", "notahash", "g" * 64, "a" * 63, "a" * 65, "0x" + "a" * 64],
)
def test_validate_sha256_invalid(value: object) -> None:
    with pytest.raises(ValidationError):
        validate_sha256(value)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# Dispatcher + unknown types + non-strings
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "indicator_type",
    ["md5", "sha1", "email", "ipv9", "", None],
)
def test_validate_unknown_type(indicator_type: object) -> None:
    with pytest.raises(ValidationError):
        validate_indicator(indicator_type, "1.2.3.4")  # type: ignore[arg-type]


def test_validate_indicator_dispatches() -> None:
    assert validate_indicator("ipv4", "1.2.3.4") == "1.2.3.4"
    assert validate_indicator("ipv6", "::1") == "::1"
    assert validate_indicator("domain", "Example.COM") == "example.com"
    assert validate_indicator("url", "HTTPS://Example.COM/") == "https://example.com/"
    assert validate_indicator("sha256", "A" * 64) == "a" * 64


@pytest.mark.parametrize("value", [None, 123, ["a"], {"a": 1}])
def test_validate_rejects_non_string(value: object) -> None:
    with pytest.raises(ValidationError):
        validate_ipv4(value)  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        validate_domain(value)  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        validate_url(value)  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        validate_sha256(value)  # type: ignore[arg-type]
