"""Modular telemetry source adapters.

Each adapter parses a vendor-specific telemetry payload (already parsed from
JSON) into a :class:`~sentinelforge.ingestion.normalizer.NormalizedEvent`,
preserving the original raw payload and recording validation warnings.

Adapters are deliberately narrow: an adapter returns ``None`` when it cannot
confidently handle a payload, never invents fields, and never drops data
silently — missing fields are represented as ``None`` and recorded as
warnings. A connector is only considered implemented once its complete
input-to-storage path is tested.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from sentinelforge.ingestion.normalizer import NormalizedEvent


class Adapter(ABC):
    """Base class for telemetry source adapters."""

    source: str

    def __init__(self) -> None:
        self.warnings: list[str] = []

    @abstractmethod
    def can_handle(self, raw: dict[str, Any]) -> bool:
        """Return True if this adapter can parse ``raw``."""

    @abstractmethod
    def adapt(self, raw: dict[str, Any]) -> NormalizedEvent | None:
        """Parse ``raw`` into a normalized event, or None if not applicable."""


_ADAPTERS: list[Adapter] = []


def register(adapter: Adapter) -> None:
    """Register an adapter in the global dispatcher."""
    _ADAPTERS.append(adapter)


def adapters() -> list[Adapter]:
    """Return all registered adapters, in registration order."""
    return list(_ADAPTERS)


def adapt_event(
    raw: dict[str, Any], source: str | None = None
) -> NormalizedEvent | None:
    """Adapt a parsed telemetry payload into a normalized event.

    If ``source`` is given, only the matching adapter is tried. Otherwise every
    registered adapter is tried in registration order; the first that both
    ``can_handle`` and returns a non-None event wins.

    Returns ``None`` when no adapter can handle the payload. Callers should
    treat a ``None`` result as "unsupported source" rather than an empty event.
    """
    candidates = [a for a in _ADAPTERS if source is None or a.source == source]
    for adapter in candidates:
        if adapter.can_handle(raw):
            event = adapter.adapt(raw)
            if event is not None:
                return event
    return None
