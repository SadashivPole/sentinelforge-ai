"""Public API for the telemetry source adapters package."""

from __future__ import annotations

from sentinelforge.ingestion.adapters.auditd import AuditdAdapter
from sentinelforge.ingestion.adapters.base import (
    Adapter,
    adapt_event,
    adapters,
    register,
)
from sentinelforge.ingestion.adapters.linux_auth import LinuxAuthAdapter
from sentinelforge.ingestion.adapters.win_security import WinSecurityAdapter

__all__ = [
    "Adapter",
    "AuditdAdapter",
    "LinuxAuthAdapter",
    "WinSecurityAdapter",
    "adapt_event",
    "adapters",
    "register",
]
