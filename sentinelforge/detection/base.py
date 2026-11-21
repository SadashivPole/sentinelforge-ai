"""Detection engine foundation.

Defines the DetectionRule interface, DetectionResult, Evidence, Severity and a
RuleRegistry. Every detection retains traceable evidence from the original log
events; no detection evidence is ever invented.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
import uuid

from sentinelforge.ingestion.normalizer import NormalizedEvent


class Severity(Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class Evidence:
    """A single piece of evidence traced back to an original log event.

    ``raw`` is the verbatim original log payload so a SOC analyst can always
    inspect the exact evidence that produced a detection.
    """

    event_id: str
    timestamp: str
    source: str
    event_type: Optional[str] = None
    user: Optional[str] = None
    host: Optional[str] = None
    source_address: Optional[str] = None
    raw: dict = field(default_factory=dict)


@dataclass
class DetectionResult:
    """The output of a detection rule evaluation."""

    rule_id: str
    rule_name: str
    severity: Severity
    description: str
    evidence: list[Evidence]
    triggered_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    metadata: dict[str, Any] = field(default_factory=dict)
    detection_id: str = field(default_factory=lambda: f"det-{uuid.uuid4().hex[:16]}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "detection_id": self.detection_id,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity.value,
            "description": self.description,
            "evidence": [asdict(e) for e in self.evidence],
            "triggered_at": self.triggered_at,
            "metadata": self.metadata,
        }


class DetectionRule(ABC):
    """Base interface for all detection rules.

    Subclasses must implement :meth:`evaluate`. A rule receives normalized
    events and returns zero or more :class:`DetectionResult` objects, each
    backed by evidence from the original logs.
    """

    rule_id: str
    name: str
    description: str
    severity: Severity
    metadata: dict[str, Any]

    def __init__(
        self,
        rule_id: str,
        name: str,
        description: str,
        severity: Severity,
        metadata: Optional[dict[str, Any]] = None,
    ) -> None:
        self.rule_id = rule_id
        self.name = name
        self.description = description
        self.severity = severity
        self.metadata = metadata or {}

    @abstractmethod
    def evaluate(self, events: list[NormalizedEvent]) -> list[DetectionResult]:
        """Evaluate the rule against normalized events.

        Returns a list of detection results, each with traceable evidence.
        """

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"{self.__class__.__name__}(rule_id={self.rule_id!r})"


class RuleRegistry:
    """Registry of detection rules.

    Rules are keyed by ``rule_id``. The registry can evaluate every registered
    rule against a set of events and aggregate the results.
    """

    def __init__(self) -> None:
        self._rules: dict[str, DetectionRule] = {}

    def register(self, rule: DetectionRule) -> None:
        """Register a detection rule."""
        self._rules[rule.rule_id] = rule

    def get(self, rule_id: str) -> Optional[DetectionRule]:
        """Return a registered rule by id, or None if not registered."""
        return self._rules.get(rule_id)

    def all(self) -> list[DetectionRule]:
        """Return all registered rules."""
        return list(self._rules.values())

    def evaluate_all(self, events: list[NormalizedEvent]) -> list[DetectionResult]:
        """Evaluate every registered rule against ``events``."""
        results: list[DetectionResult] = []
        for rule in self._rules.values():
            results.extend(rule.evaluate(events))
        return results
