"""Local threat intelligence for SentinelForge AI.

Provides a bounded IOC inventory and retrospective hunting capability:

* ``validator`` — deterministic syntax validation and canonicalization for
  IPv4, IPv6, domain, URL and SHA256 indicators.
* ``imports`` — bounded local CSV/JSON import with rejection reporting.
* ``matcher`` — explicit-field IOC matching against stored events.
* ``retro_hunt`` — retrospective hunting that records historical matches
  without modifying original alerts.

No network requests are made and no data is uploaded to external services.
"""

from __future__ import annotations

from sentinelforge.threat_intel.imports import (
    ImportedIOC,
    ImportResult,
    RejectedRecord,
    import_iocs,
)
from sentinelforge.threat_intel.matcher import match_iocs
from sentinelforge.threat_intel.retro_hunt import RetroHuntResult, run_retro_hunt
from sentinelforge.threat_intel.validator import (
    ValidationError,
    validate_domain,
    validate_indicator,
    validate_ipv4,
    validate_ipv6,
    validate_sha256,
    validate_url,
)

__all__ = [
    "ImportResult",
    "ImportedIOC",
    "RejectedRecord",
    "RetroHuntResult",
    "ValidationError",
    "import_iocs",
    "match_iocs",
    "run_retro_hunt",
    "validate_domain",
    "validate_indicator",
    "validate_ipv4",
    "validate_ipv6",
    "validate_sha256",
    "validate_url",
]
