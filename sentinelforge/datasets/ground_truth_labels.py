"""Per-event ground truth labels for synthetic SOC datasets.

Builds an independent ground-truth record for every generated event,
separate from raw log files. Each event is classified as benign,
suspicious, or unlabeled. Unknown events are never silently classified
as benign.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class EventGroundTruth:
    """Ground-truth label for a single event."""

    event_id: str
    classification: str  # "benign" | "suspicious" | "unlabeled"
    scenario_id: str | None
    expected_detection_categories: tuple[str, ...]
    expected_severity: str | None
    explanation: str
    event_type: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "classification": self.classification,
            "scenario_id": self.scenario_id,
            "expected_detection_categories": list(
                self.expected_detection_categories
            ),
            "expected_severity": self.expected_severity,
            "explanation": self.explanation,
            "event_type": self.event_type,
        }


@dataclass
class EventGroundTruthManifest:
    """Collection of per-event ground-truth labels."""

    dataset_id: str
    entries: dict[str, EventGroundTruth] = field(default_factory=dict)

    def add_entry(self, entry: EventGroundTruth) -> None:
        self.entries[entry.event_id] = entry

    def get_entry(self, event_id: str) -> EventGroundTruth | None:
        return self.entries.get(event_id)

    def by_classification(self, classification: str) -> list[EventGroundTruth]:
        return [
            e for e in self.entries.values()
            if e.classification == classification
        ]

    def counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for entry in self.entries.values():
            counts[entry.classification] = counts.get(entry.classification, 0) + 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "dataset_id": self.dataset_id,
            "total_events": len(self.entries),
            "classification_counts": self.counts(),
            "entries": [e.to_dict() for e in self.entries.values()],
        }

    def write_json(self, path: str | Path) -> None:
        """Write the manifest to a JSON file (separate from raw events)."""
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh, indent=2)

    @classmethod
    def load_json(cls, path: str | Path) -> "EventGroundTruthManifest":
        """Load the manifest from a JSON file."""
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        manifest = cls(dataset_id=data["dataset_id"])
        for entry_data in data.get("entries", []):
            entry = EventGroundTruth(
                event_id=entry_data["event_id"],
                classification=entry_data["classification"],
                scenario_id=entry_data.get("scenario_id"),
                expected_detection_categories=tuple(
                    entry_data.get("expected_detection_categories", [])
                ),
                expected_severity=entry_data.get("expected_severity"),
                explanation=entry_data.get("explanation", ""),
            )
            manifest.add_entry(entry)
        return manifest


def build_event_ground_truth(
    dataset_id: str,
    all_events: list[dict],
    scenario_entries: list[dict],
) -> EventGroundTruthManifest:
    """Build per-event ground-truth labels from generated events and scenario metadata.

    Scenario events inherit their scenario's classification and metadata.
    All other events are marked "unlabeled" — never silently classified
    as benign without evidence.
    """
    manifest = EventGroundTruthManifest(dataset_id=dataset_id)

    # Build a lookup from event_id to scenario metadata.
    scenario_event_map: dict[str, dict] = {}
    for entry in scenario_entries:
        for eid in entry.get("event_ids", []):
            scenario_event_map[eid] = {
                "scenario_id": entry.get("scenario_id", ""),
                "classification": entry.get("classification", "unlabeled"),
                "expected_detection_category": entry.get(
                    "expected_detection_category", ""
                ),
                "expected_severity_range": entry.get(
                    "expected_severity_range", ""
                ),
                "explanation": entry.get("explanation", ""),
            }

    for event in all_events:
        event_id = event.get("event_id", "")
        if not event_id:
            continue

        scenario_info = scenario_event_map.get(event_id)
        if scenario_info is not None:
            # This event is part of a known scenario.
            classification = scenario_info["classification"]
            det_cat = scenario_info.get("expected_detection_category", "")
            categories = tuple(
                c.strip() for c in det_cat.split(",") if c.strip()
            ) if det_cat else ()
            severity = scenario_info.get("expected_severity_range", "")
            explanation = scenario_info.get("explanation", "")
            scenario_id = scenario_info.get("scenario_id", "")

            # Override: a successful login in a brute-force scenario is
            # contextual/corroborating evidence, not a detection-bearing
            # failed_login_burst event. It supports the attack narrative
            # but should not be counted as a failed_login_burst detection
            # target for rule-specific event recall.
            if (
                classification == "suspicious"
                and event.get("event_type") == "auth.login.success"
                and "failed_login_burst" in categories
            ):
                categories = ()
        else:
            # Not part of any known scenario — unlabeled, not benign.
            classification = "unlabeled"
            categories = ()
            severity = None
            explanation = "Not part of any labelled scenario; ground truth unknown."
            scenario_id = None

        manifest.add_entry(EventGroundTruth(
            event_id=event_id,
            classification=classification,
            scenario_id=scenario_id,
            expected_detection_categories=categories,
            expected_severity=severity,
            explanation=explanation,
            event_type=event.get("event_type"),
        ))

    return manifest
