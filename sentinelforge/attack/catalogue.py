"""ATT&CK technique catalogue loader and validator.

Loads technique entries from the JSON manifest and provides queryable
access. Catalogue definitions are stored separately from detection records.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class TechniqueEntry:
    """A single MITRE ATT&CK technique or sub-technique catalogue entry."""

    technique_id: str
    technique_name: str
    technique_description: str
    tactic_ids: list[str]
    tactic_names: list[str]
    subtechnique_parent_id: str | None
    platforms: list[str]
    attack_version: str
    source_url: str
    applicable_log_sources: list[str]
    required_telemetry: list[str]
    available_telemetry: list[str]
    evidence_fields: list[str]
    associated_detection_rule_ids: list[str]
    detection_status: str
    mapping_confidence: str
    mapping_rationale: str
    investigation_recommendations: list[str]
    validation_status: str
    last_reviewed: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TechniqueEntry":
        return cls(
            technique_id=data["technique_id"],
            technique_name=data["technique_name"],
            technique_description=data.get("technique_description", ""),
            tactic_ids=data.get("tactic_ids", []),
            tactic_names=data.get("tactic_names", []),
            subtechnique_parent_id=data.get("subtechnique_parent_id"),
            platforms=data.get("platforms", []),
            attack_version=data.get("attack_version", "v20.1"),
            source_url=data.get("source_url", ""),
            applicable_log_sources=data.get("applicable_log_sources", []),
            required_telemetry=data.get("required_telemetry", []),
            available_telemetry=data.get("available_telemetry", []),
            evidence_fields=data.get("evidence_fields", []),
            associated_detection_rule_ids=data.get(
                "associated_detection_rule_ids", []
            ),
            detection_status=data.get("detection_status", ""),
            mapping_confidence=data.get("mapping_confidence", ""),
            mapping_rationale=data.get("mapping_rationale", ""),
            investigation_recommendations=data.get(
                "investigation_recommendations", []
            ),
            validation_status=data.get("validation_status", ""),
            last_reviewed=data.get("last_reviewed", ""),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "technique_description": self.technique_description,
            "tactic_ids": self.tactic_ids,
            "tactic_names": self.tactic_names,
            "subtechnique_parent_id": self.subtechnique_parent_id,
            "platforms": self.platforms,
            "attack_version": self.attack_version,
            "source_url": self.source_url,
            "applicable_log_sources": self.applicable_log_sources,
            "required_telemetry": self.required_telemetry,
            "available_telemetry": self.available_telemetry,
            "evidence_fields": self.evidence_fields,
            "associated_detection_rule_ids": self.associated_detection_rule_ids,
            "detection_status": self.detection_status,
            "mapping_confidence": self.mapping_confidence,
            "mapping_rationale": self.mapping_rationale,
            "investigation_recommendations": self.investigation_recommendations,
            "validation_status": self.validation_status,
            "last_reviewed": self.last_reviewed,
        }


# Valid detection statuses per approved design.
VALID_STATUSES = {
    "IMPLEMENTED_AND_TESTED",
    "IMPLEMENTED_NEEDS_VALIDATION",
    "TELEMETRY_AVAILABLE_NO_DETECTION",
    "PLANNED_REQUIRES_TELEMETRY",
    "UNSUPPORTED_BY_CURRENT_TELEMETRY",
}

# Valid confidence levels.
VALID_CONFIDENCE_LEVELS = {"high", "medium", "low", "none"}

# ATT&CK ID pattern: T#### or T####.###
TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")

# Tactic ID pattern: TA####
TACTIC_ID_RE = re.compile(r"^TA\d{4}$")


class ATTACKCatalogue:
    """In-memory registry of MITRE ATT&CK technique catalogue entries.

    Entries are loaded from a JSON manifest. The catalogue is a reference
    inventory only — catalogue membership is never treated as implemented
    detection coverage.
    """

    def __init__(self, entries: list[TechniqueEntry]) -> None:
        self._by_id: dict[str, TechniqueEntry] = {}
        self._by_tactic: dict[str, list[TechniqueEntry]] = {}
        self._by_status: dict[str, list[TechniqueEntry]] = {}
        self._by_rule: dict[str, list[TechniqueEntry]] = {}
        for entry in entries:
            self._by_id[entry.technique_id] = entry
            for tactic_id in entry.tactic_ids:
                self._by_tactic.setdefault(tactic_id, []).append(entry)
            self._by_status.setdefault(entry.detection_status, []).append(entry)
            for rule_id in entry.associated_detection_rule_ids:
                self._by_rule.setdefault(rule_id, []).append(entry)

    @classmethod
    def from_json(cls, path: str | Path) -> "ATTACKCatalogue":
        """Load a catalogue from a JSON manifest file."""
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        entries = [TechniqueEntry.from_dict(item) for item in data.get("entries", [])]
        return cls(entries)

    def get(self, technique_id: str) -> TechniqueEntry | None:
        """Return a technique entry by ID, or None if not found."""
        return self._by_id.get(technique_id)

    def all(self) -> list[TechniqueEntry]:
        """Return all catalogue entries."""
        return list(self._by_id.values())

    def by_tactic(self, tactic_id: str) -> list[TechniqueEntry]:
        """Return entries associated with a tactic."""
        return list(self._by_tactic.get(tactic_id, []))

    def by_status(self, status: str) -> list[TechniqueEntry]:
        """Return entries with a given detection status."""
        return list(self._by_status.get(status, []))

    def by_rule(self, rule_id: str) -> list[TechniqueEntry]:
        """Return entries associated with a detection rule."""
        return list(self._by_rule.get(rule_id, []))

    def implemented_and_tested(self) -> list[TechniqueEntry]:
        """Return entries with IMPLEMENTED_AND_TESTED status."""
        return self.by_status("IMPLEMENTED_AND_TESTED")

    def count(self) -> int:
        """Return the total number of catalogue entries."""
        return len(self._by_id)

    def count_by_status(self) -> dict[str, int]:
        """Return entry counts grouped by detection status."""
        return {status: len(entries) for status, entries in self._by_status.items()}

    def count_by_tactic(self) -> dict[str, int]:
        """Return entry counts grouped by tactic ID."""
        return {tactic: len(entries) for tactic, entries in self._by_tactic.items()}

    def validate(self) -> list[str]:
        """Validate the catalogue and return a list of error messages.

        Checks:
        - Every technique_id matches the pattern ``^T\\\\d{4}(\\\\.\\\\d{3})?$``
        - Every tactic_id matches the pattern ``^TA\\\\d{4}$``
        - Every sub-technique references an existing parent technique
        - No duplicate technique_id entries
        - detection_status is one of the valid statuses
        - mapping_confidence is one of high/medium/low/none
        - IMPLEMENTED_AND_TESTED entries have associated detection rules
        - mapping_rationale is non-empty for mapped entries
        """
        errors: list[str] = []
        ids: set[str] = set()

        for entry in self.all():
            # Unique IDs
            if entry.technique_id in ids:
                errors.append(f"Duplicate technique_id: {entry.technique_id}")
            ids.add(entry.technique_id)

            # Valid ID format
            if not TECHNIQUE_ID_RE.match(entry.technique_id):
                errors.append(
                    f"Invalid technique_id format: {entry.technique_id}"
                )

            # Valid tactic IDs
            for tactic_id in entry.tactic_ids:
                if not TACTIC_ID_RE.match(tactic_id):
                    errors.append(
                        f"Invalid tactic_id format: {tactic_id} "
                        f"(in {entry.technique_id})"
                    )

            # Sub-technique parent references
            if entry.subtechnique_parent_id is not None:
                if entry.subtechnique_parent_id not in ids:
                    errors.append(
                        f"Sub-technique {entry.technique_id} references "
                        f"nonexistent parent {entry.subtechnique_parent_id}"
                    )

            # Valid status
            if entry.detection_status not in VALID_STATUSES:
                errors.append(
                    f"Invalid detection_status '{entry.detection_status}' "
                    f"for {entry.technique_id}"
                )

            # Valid confidence
            if entry.mapping_confidence not in VALID_CONFIDENCE_LEVELS:
                errors.append(
                    f"Invalid mapping_confidence '{entry.mapping_confidence}' "
                    f"for {entry.technique_id}"
                )

            # Implemented entries must have detection rules
            if (
                entry.detection_status == "IMPLEMENTED_AND_TESTED"
                and not entry.associated_detection_rule_ids
            ):
                errors.append(
                    f"IMPLEMENTED_AND_TESTED entry {entry.technique_id} "
                    f"has no associated detection rules"
                )

            # Mapped entries need rationale
            if entry.detection_status in (
                "IMPLEMENTED_AND_TESTED",
                "IMPLEMENTED_NEEDS_VALIDATION",
                "TELEMETRY_AVAILABLE_NO_DETECTION",
            ) and not entry.mapping_rationale.strip():
                errors.append(
                    f"Entry {entry.technique_id} has empty mapping_rationale"
                )

        return errors
