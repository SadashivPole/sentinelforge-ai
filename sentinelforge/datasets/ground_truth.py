"""Ground-truth manifest for synthetic SOC datasets.

Labels are stored separately from raw events to prevent data leakage. The
manifest records expected behaviour per scenario so detection results can be
evaluated against ground truth without ever embedding labels in raw log files.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class GroundTruthEntry:
    """A single ground-truth label for one or more events."""

    dataset_id: str
    scenario_id: str
    event_ids: tuple[str, ...]
    expected_behaviour: str
    classification: str  # "benign" | "suspicious"
    expected_detection_category: str
    expected_severity_range: str  # e.g. "medium-high"
    att_ck_candidate_mappings: tuple[str, ...] = field(default_factory=tuple)
    scenario_start_timestamp: str = ""
    scenario_end_timestamp: str = ""
    explanation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "dataset_id": self.dataset_id,
            "scenario_id": self.scenario_id,
            "event_ids": list(self.event_ids),
            "expected_behaviour": self.expected_behaviour,
            "classification": self.classification,
            "expected_detection_category": self.expected_detection_category,
            "expected_severity_range": self.expected_severity_range,
            "att_ck_candidate_mappings": list(self.att_ck_candidate_mappings),
            "scenario_start_timestamp": self.scenario_start_timestamp,
            "scenario_end_timestamp": self.scenario_end_timestamp,
            "explanation": self.explanation,
        }


@dataclass
class GroundTruthManifest:
    """Collection of ground-truth entries for a dataset."""

    dataset_id: str
    entries: list[GroundTruthEntry] = field(default_factory=list)

    def add_entry(self, entry: GroundTruthEntry) -> None:
        self.entries.append(entry)

    def get_entry(self, scenario_id: str) -> GroundTruthEntry | None:
        for entry in self.entries:
            if entry.scenario_id == scenario_id:
                return entry
        return None

    def event_ids(self) -> set[str]:
        """Return the set of all labelled event IDs."""
        ids: set[str] = set()
        for entry in self.entries:
            ids.update(entry.event_ids)
        return ids

    def to_dict(self) -> dict[str, Any]:
        return {
            "dataset_id": self.dataset_id,
            "entry_count": len(self.entries),
            "entries": [e.to_dict() for e in self.entries],
        }
