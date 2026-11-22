"""Synthetic enterprise SOC dataset generator for SentinelForge AI.

Produces reproducible synthetic security events across multiple log sources
(Windows Sysmon, Linux authentication, Firewall, DNS, Network) plus correlated
attack scenarios. Ground-truth labels are stored separately from raw events to
prevent data leakage.

All generation uses a fixed random seed for reproducibility.
"""

from sentinelforge.datasets.evaluation import (
    AlertLevelMetrics,
    EvaluationResults,
    EventLevelMetrics,
    F1Result,
    RuleAlertMetrics,
    RuleEventMetrics,
    evaluate_detections,
)
from sentinelforge.datasets.generator import DatasetGenerator
from sentinelforge.datasets.ground_truth import (
    GroundTruthEntry,
    GroundTruthManifest,
)
from sentinelforge.datasets.ground_truth_labels import (
    EventGroundTruth,
    EventGroundTruthManifest,
    build_event_ground_truth,
)
from sentinelforge.datasets.native_sysmon import (
    generate_native_sysmon_events,
    write_native_sysmon_jsonl,
)
from sentinelforge.datasets.scenarios import Scenario, ScenarioLibrary
from sentinelforge.datasets.validators import validate_dataset

__all__ = [
    "AlertLevelMetrics",
    "DatasetGenerator",
    "EvaluationResults",
    "EventGroundTruth",
    "EventGroundTruthManifest",
    "EventLevelMetrics",
    "F1Result",
    "GroundTruthEntry",
    "GroundTruthManifest",
    "RuleAlertMetrics",
    "RuleEventMetrics",
    "Scenario",
    "ScenarioLibrary",
    "build_event_ground_truth",
    "evaluate_detections",
    "generate_native_sysmon_events",
    "validate_dataset",
    "write_native_sysmon_jsonl",
]
