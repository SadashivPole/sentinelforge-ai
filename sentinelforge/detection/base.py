"""Detection engine foundation.

Defines the DetectionRule interface, DetectionResult, Evidence, Severity and a
RuleRegistry. Every detection retains traceable evidence from the original log
events; no detection evidence is ever invented.
"""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

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
    event_type: str | None = None
    user: str | None = None
    host: str | None = None
    source_address: str | None = None
    raw: dict = field(default_factory=dict)


@dataclass
class DetectionResult:
    """The output of a detection rule evaluation."""

    rule_id: str
    rule_name: str
    severity: Severity
    description: str
    evidence: list[Evidence]
    triggered_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
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
        metadata: dict[str, Any] | None = None,
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
        self.catalog: DetectionCatalog = DetectionCatalog()

    def register(self, rule: DetectionRule) -> None:
        """Register a detection rule."""
        self._rules[rule.rule_id] = rule

    def register_catalog_entry(self, entry: RuleCatalogEntry) -> None:
        """Register a structured catalog entry for a detection rule."""
        self.catalog.register(entry)

    def get(self, rule_id: str) -> DetectionRule | None:
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


@dataclass(frozen=True)
class RuleCatalogEntry:
    """Structured metadata for a single detection rule.

    Fields are intentionally flat and static so the catalog can be inspected
    without executing any rule logic. Every field is evidence-backed: nothing
    here is aspirational or imported from an unverified external source.
    """

    rule_id: str
    name: str
    version: str
    objective: str
    category: str
    severity: Severity
    attack_tactic: str | None = None
    attack_tactic_id: str | None = None
    attack_technique: str | None = None
    attack_technique_id: str | None = None
    required_data_source: str | None = None
    required_fields: list[str] = field(default_factory=list)
    threshold: str | None = None
    time_window_seconds: str | None = None
    false_positive_conditions: list[str] = field(default_factory=list)
    investigation_instructions: list[str] = field(default_factory=list)
    external_references: list[str] = field(default_factory=list)
    test_references: list[str] = field(default_factory=list)
    execution_status: str = "working"
    validation_status: str = "unvalidated"


class DetectionCatalog:
    """Read-only catalog of structured detection-rule metadata.

    Entries are keyed by ``rule_id``. The catalog supports listing, lookup, and
    validation (duplicate rule IDs, ATT&CK identifier format) without executing
    any detection logic.
    """

    def __init__(self) -> None:
        self._entries: dict[str, RuleCatalogEntry] = {}

    def register(self, entry: RuleCatalogEntry) -> None:
        """Register a catalog entry. Later entries with the same rule_id win."""
        self._entries[entry.rule_id] = entry

    def get(self, rule_id: str) -> RuleCatalogEntry | None:
        """Return the catalog entry for ``rule_id``, or None if absent."""
        return self._entries.get(rule_id)

    def entries(self) -> list[RuleCatalogEntry]:
        """Return all registered catalog entries, sorted by rule_id."""
        return sorted(self._entries.values(), key=lambda e: e.rule_id)

    def validate(self) -> dict[str, list[str]]:
        """Validate every entry, returning {rule_id: [error messages]}.

        An empty dict means every entry is structurally valid.
        """
        errors: dict[str, list[str]] = {}
        seen_ids: set[str] = set()
        for entry in self._entries.values():
            entry_errors: list[str] = []
            if entry.rule_id in seen_ids:
                entry_errors.append(f"duplicate rule_id: {entry.rule_id}")
            seen_ids.add(entry.rule_id)

            if entry.attack_technique and not entry.attack_technique.startswith("T"):
                entry_errors.append(
                    f"invalid ATT&CK technique identifier: {entry.attack_technique}"
                )
            if entry.attack_technique_id and "." not in entry.attack_technique_id:
                entry_errors.append(
                    f"attack_technique_id should be a sub-technique (e.g. T1110.001), "
                    f"got: {entry.attack_technique_id}"
                )
            if not entry.required_fields:
                entry_errors.append("no required_fields declared")
            if entry_errors:
                errors[entry.rule_id] = entry_errors
        return errors

    def validation_report(self) -> dict[str, Any]:
        """Return a machine-readable validation summary."""
        entry_errors = self.validate()
        return {
            "total_entries": len(self._entries),
            "invalid_entries": len(entry_errors),
            "errors": entry_errors,
            "all_valid": len(entry_errors) == 0,
        }
