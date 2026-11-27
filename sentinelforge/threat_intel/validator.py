"""IOC validation and canonicalization.

Validators are deterministic, side-effect free and never perform network
lookups, never consult reputation services, and never invent confidence or
attribution. A value is either accepted (and canonicalized) or rejected
with a clear reason.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse, urlunparse

_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")

# A DNS label: 1-63 chars, alphanumeric or internal hyphen, not leading/
# trailing hyphen.
_LABEL_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")


class ValidationError(ValueError):
    """Raised when an IOC value fails validation."""


def validate_ipv4(value: str) -> str:
    """Validate and canonicalize an IPv4 address."""
    if not isinstance(value, str):
        raise ValidationError("IPv4 address must be a string")
    try:
        addr = ipaddress.IPv4Address(value.strip())
    except ValueError as exc:
        raise ValidationError(f"Invalid IPv4 address: {value!r}") from exc
    return str(addr)


def validate_ipv6(value: str) -> str:
    """Validate and canonicalize an IPv6 address."""
    if not isinstance(value, str):
        raise ValidationError("IPv6 address must be a string")
    try:
        addr = ipaddress.IPv6Address(value.strip())
    except ValueError as exc:
        raise ValidationError(f"Invalid IPv6 address: {value!r}") from exc
    return str(addr)


def validate_domain(value: str) -> str:
    """Validate and canonicalize a domain name.

    Conservative normalization: lowercase, strip trailing dot, reject empty
    labels and labels over 63 characters. No TLD requirement (internal
    names are valid), but the value must look like a structured domain,
    not a free-text string.
    """
    if not isinstance(value, str):
        raise ValidationError("Domain must be a string")
    candidate = value.strip().lower().rstrip(".")
    if not candidate:
        raise ValidationError(f"Invalid domain: {value!r}")
    if len(candidate) > 253:
        raise ValidationError(f"Domain too long: {value!r}")
    labels = candidate.split(".")
    if len(labels) < 2:
        raise ValidationError(f"Invalid domain: {value!r}")
    if any(not _LABEL_RE.match(label) for label in labels):
        raise ValidationError(f"Invalid domain: {value!r}")
    return candidate


def validate_url(value: str) -> str:
    """Validate and canonicalize a URL.

    Requires a scheme and a host. Normalizes scheme/hostname to lowercase.
    Does not fetch, resolve, or otherwise network-touch the URL.
    """
    if not isinstance(value, str):
        raise ValidationError("URL must be a string")
    candidate = value.strip()
    try:
        parsed = urlparse(candidate)
    except ValueError as exc:
        raise ValidationError(f"Invalid URL: {value!r}") from exc
    if not parsed.scheme or not parsed.netloc:
        raise ValidationError(f"Invalid URL: {value!r}")
    netloc = (parsed.hostname or "").lower()
    if parsed.port is not None:
        netloc = f"{netloc}:{parsed.port}"
    path = parsed.path or "/"
    return urlunparse(
        (
            parsed.scheme.lower(),
            netloc,
            path,
            parsed.params,
            parsed.query,
            parsed.fragment,
        )
    )


def validate_sha256(value: str) -> str:
    """Validate and canonicalize a SHA256 hash (lowercase hex)."""
    if not isinstance(value, str):
        raise ValidationError("SHA256 hash must be a string")
    candidate = value.strip().lower()
    if not _SHA256_RE.match(candidate):
        raise ValidationError(f"Invalid SHA256 hash: {value!r}")
    return candidate


_VALIDATORS = {
    "ipv4": validate_ipv4,
    "ipv6": validate_ipv6,
    "domain": validate_domain,
    "url": validate_url,
    "sha256": validate_sha256,
}


def validate_indicator(indicator_type: str, value: str) -> str:
    """Validate and canonicalize an IOC value for the given type.

    Returns the canonicalized value, or raises :class:`ValidationError`.
    """
    if indicator_type not in _VALIDATORS:
        raise ValidationError(f"Unknown indicator type: {indicator_type!r}")
    return _VALIDATORS[indicator_type](value)
