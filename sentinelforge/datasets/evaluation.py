"""Detection evaluation metrics for synthetic SOC datasets.

Provides two independent evaluation models:

A. **Alert-level evaluation** — treats each detection alert as a unit.
   TP/FP/FN are counted per alert. Precision = TP / (TP + FP).
   Recall and F1 are not defined at alert level alone (no population of
   "expected alerts").

B. **Event-level evaluation** — treats each labeled event as a unit.
   TP = suspicious events with at least one matching detection.
   FN = suspicious events with no matching detection.
   Recall = TP / (TP + FN).
   Precision is not defined at event level alone.

F1 is calculated only when precision and recall use the same evaluation
unit and the same population.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class AlertLevelMetrics:
    """Metrics for alert-level evaluation.

    Attribution errors (correct detection, wrong technique/category) are
    tracked separately from true false positives (alert on benign evidence).
    Precision is computed over assessed alerts only: TP / assessed.
    """

    total_alerts: int
    true_positive_alerts: int
    false_positive_alerts: int  # alerts on benign evidence
    attribution_error_alerts: int  # alerts on suspicious evidence, wrong category
    unassessed_alerts: int  # alerts on unlabeled evidence only
    assessed_alerts: int  # TP + FP + attribution_errors = total - unassessed
    precision: float  # TP / assessed
    assessment_coverage: float  # assessed / total

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class EventLevelMetrics:
    """Metrics for event-level evaluation."""

    total_suspicious_events: int
    detected_suspicious_events: int
    undetected_suspicious_events: int
    recall: float  # TP / (TP + FN)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class RuleAlertMetrics:
    """Alert-level metrics for a single detection rule.

    Attribution errors (correct detection, wrong technique/category) are
    tracked separately from true false positives (alert on benign evidence).
    """

    rule_id: str
    rule_name: str
    total_alerts: int
    true_positive_alerts: int
    false_positive_alerts: int  # alerts on benign evidence
    attribution_error_alerts: int  # alerts on suspicious evidence, wrong category
    unassessed_alerts: int
    assessed_alerts: int  # TP + FP + attribution_errors
    precision: float  # TP / assessed

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class RuleEventMetrics:
    """Event-level metrics for a single detection rule."""

    rule_id: str
    rule_name: str
    expected_events: int  # suspicious events expecting this rule
    detected_events: int  # expected events with at least one matching alert
    missed_events: int  # expected events with no matching alert
    recall: float  # detected / expected

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class F1Result:
    """F1 score calculated only when precision and recall share the same unit."""

    evaluation_unit: str  # "alert" or "event"
    precision: float
    recall: float
    f1_score: float
    formula: str  # e.g. "2 * P * R / (P + R)"
    valid: bool  # True only when unit and population match

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class EvaluationResults:
    """Complete evaluation results with separate alert and event models."""

    dataset_id: str
    total_events: int
    labeled_events: int
    benign_events: int
    suspicious_events: int
    unlabeled_events: int

    # Alert-level evaluation
    alert_level: AlertLevelMetrics
    rule_alert_metrics: list[RuleAlertMetrics]

    # Event-level evaluation
    event_level: EventLevelMetrics
    rule_event_metrics: list[RuleEventMetrics]

    # F1 — only valid when unit and population match
    f1_alert: F1Result
    f1_event: F1Result

    # Per-classification breakdown of alerts
    per_classification_breakdown: dict[str, dict[str, int]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "dataset_id": self.dataset_id,
            "total_events": self.total_events,
            "labeled_events": self.labeled_events,
            "benign_events": self.benign_events,
            "suspicious_events": self.suspicious_events,
            "unlabeled_events": self.unlabeled_events,
            "alert_level": self.alert_level.to_dict(),
            "rule_alert_metrics": [m.to_dict() for m in self.rule_alert_metrics],
            "event_level": self.event_level.to_dict(),
            "rule_event_metrics": [m.to_dict() for m in self.rule_event_metrics],
            "f1_alert": self.f1_alert.to_dict(),
            "f1_event": self.f1_event.to_dict(),
            "per_classification_breakdown": self.per_classification_breakdown,
        }

    def write_json(self, path: str | Path) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh, indent=2)


def _safe_divide(numerator: float, denominator: float) -> float:
    """Safe division returning 0.0 when denominator is 0."""
    if denominator == 0:
        return 0.0
    return numerator / denominator


def evaluate_detections(
    dataset_id: str,
    detection_results: list[Any],
    event_ground_truth: dict[str, Any],
) -> EvaluationResults:
    """Evaluate detection results against per-event ground truth.

    Two independent evaluation models are produced:

    1. Alert-level — each alert is a unit; TP/FP counted per alert.
    2. Event-level — each labeled suspicious event is a unit;
       detected if at least one matching alert covers it.

    F1 is reported separately for each model, but only marked valid
    when precision and recall share the same unit and population.
    """
    # Mapping from rule IDs / MITRE techniques to short category names
    # used in scenario expected_detection_categories.
    # Each short name maps to exactly ONE primary rule to avoid double counting.
    CATEGORY_ALIASES: dict[str, set[str]] = {
        "sentinelforge.detection.suspicious_powershell": {
            "powershell",
            "t1059.001",
        },
        "sentinelforge.detection.failed_login_burst": {
            "failed_login_burst",
            "t1110",
            "t1110.001",
        },
        "sentinelforge.detection.password_spray": {
            "password_spray",
            "t1110.003",
        },
        "sentinelforge.detection.suspicious_processtree": {
            "suspicious_processtree",
            "t1204.002",
            "t1204",
        },
        "sentinelforge.detection.c2_beacon": {
            "c2_beacon",
            "t1071",
        },
    }

    # Reverse mapping: short category name -> set of rule IDs that produce it.
    RULES_BY_CATEGORY: dict[str, set[str]] = {}
    for rule_id, aliases in CATEGORY_ALIASES.items():
        for alias in aliases:
            RULES_BY_CATEGORY.setdefault(alias, set()).add(rule_id)

    # Build event_id -> ground truth entry lookup.
    gt_entries = event_ground_truth.get("entries", [])
    gt_by_event: dict[str, dict[str, Any]] = {}
    for entry in gt_entries:
        gt_by_event[entry["event_id"]] = entry

    # Count events by classification.
    benign_count = sum(1 for e in gt_entries if e["classification"] == "benign")
    suspicious_count = sum(1 for e in gt_entries if e["classification"] == "suspicious")
    unlabeled_count = sum(1 for e in gt_entries if e["classification"] == "unlabeled")
    labeled_count = benign_count + suspicious_count
    total_events = len(gt_entries)

    # ------------------------------------------------------------------
    # Match alerts to ground truth
    # ------------------------------------------------------------------
    alerts_by_rule: dict[str, list[dict[str, Any]]] = {}

    for result in detection_results:
        rule_id = getattr(result, "rule_id", "unknown")
        rule_name = getattr(result, "rule_name", "unknown")
        evidence_event_ids = [ev.event_id for ev in getattr(result, "evidence", [])]
        metadata = getattr(result, "metadata", {}) or {}
        mitre_technique = metadata.get("mitre_attack_technique", "")

        alert_categories: set[str] = set()
        if mitre_technique:
            alert_categories.add(mitre_technique.lower())
        alert_categories.update(CATEGORY_ALIASES.get(rule_id, set()))
        alert_categories.add(rule_id)

        alert_info = {
            "rule_id": rule_id,
            "rule_name": rule_name,
            "evidence_event_ids": evidence_event_ids,
            "detection_category": mitre_technique or rule_id,
            "alert_categories": alert_categories,
            "severity": str(getattr(result, "severity", "unknown")),
        }
        alerts_by_rule.setdefault(rule_id, []).append(alert_info)

    # ------------------------------------------------------------------
    # Alert-level TP/FP/Attribution Error
    # ------------------------------------------------------------------
    rule_alert_true_positives: dict[str, int] = {}
    rule_alert_false_positives: dict[str, int] = {}
    rule_alert_attribution_errors: dict[str, int] = {}
    rule_alert_unassessed: dict[str, int] = {}
    rule_alert_total: dict[str, int] = {}

    # Track which suspicious events were detected (for event-level FN).
    detected_suspicious_event_ids: set[str] = set()

    for rule_id, alerts in alerts_by_rule.items():
        tp = 0
        fp = 0
        attribution_error = 0
        unassessed = 0
        for alert in alerts:
            is_tp = False
            alert_cats = alert["alert_categories"]
            has_benign_evidence = False
            has_suspicious_evidence = False
            has_unlabeled_evidence = False
            for eid in alert["evidence_event_ids"]:
                gt_entry = gt_by_event.get(eid)
                if gt_entry is None:
                    continue
                if gt_entry["classification"] == "suspicious":
                    has_suspicious_evidence = True
                    expected_cats = gt_entry.get(
                        "expected_detection_categories",
                        gt_entry.get("expected_detection_category", ""),
                    )
                    if isinstance(expected_cats, str):
                        expected_cats = [
                            c.strip().lower()
                            for c in expected_cats.split(",")
                            if c.strip()
                        ]
                    else:
                        expected_cats = [c.strip().lower() for c in expected_cats]
                    if alert_cats & set(expected_cats) or not expected_cats:
                        is_tp = True
                        detected_suspicious_event_ids.add(eid)
                elif gt_entry["classification"] == "benign":
                    has_benign_evidence = True
                elif gt_entry["classification"] == "unlabeled":
                    has_unlabeled_evidence = True
            if is_tp:
                tp += 1
            elif has_benign_evidence:
                # Alert on benign evidence — true false positive.
                fp += 1
            elif has_suspicious_evidence:
                # Alert on suspicious evidence with wrong category —
                # attribution error, not an ordinary false positive.
                attribution_error += 1
            elif has_unlabeled_evidence:
                # Alert on unlabeled evidence only — unassessed.
                unassessed += 1
            else:
                # No evidence events matched any GT entry — unassessed.
                unassessed += 1
        rule_alert_true_positives[rule_id] = tp
        rule_alert_false_positives[rule_id] = fp
        rule_alert_attribution_errors[rule_id] = attribution_error
        rule_alert_unassessed[rule_id] = unassessed
        rule_alert_total[rule_id] = len(alerts)

    # ------------------------------------------------------------------
    # Event-level FN
    # ------------------------------------------------------------------
    rule_event_expected: dict[str, int] = {}
    rule_event_detected: dict[str, int] = {}

    for entry in gt_entries:
        if entry["classification"] != "suspicious":
            continue
        expected_cats = entry.get(
            "expected_detection_categories",
            entry.get("expected_detection_category", ""),
        )
        if isinstance(expected_cats, str):
            expected_cats = [
                c.strip().lower() for c in expected_cats.split(",") if c.strip()
            ]
        else:
            expected_cats = [c.strip().lower() for c in expected_cats]
        for cat in expected_cats:
            matching_rules = RULES_BY_CATEGORY.get(cat, set())
            for rule_id in matching_rules:
                rule_event_expected[rule_id] = rule_event_expected.get(rule_id, 0) + 1

    # Count detected events per rule (event is detected if any alert on it
    # matches the rule's category).
    for rule_id, alerts in alerts_by_rule.items():
        detected_for_rule: set[str] = set()
        for alert in alerts:
            for eid in alert["evidence_event_ids"]:
                gt_entry = gt_by_event.get(eid)
                if gt_entry is None:
                    continue
                if gt_entry["classification"] != "suspicious":
                    continue
                expected_cats = gt_entry.get(
                    "expected_detection_categories",
                    gt_entry.get("expected_detection_category", ""),
                )
                if isinstance(expected_cats, str):
                    expected_cats = [
                        c.strip().lower() for c in expected_cats.split(",") if c.strip()
                    ]
                else:
                    expected_cats = [c.strip().lower() for c in expected_cats]
                alert_cats = alert["alert_categories"]
                if alert_cats & set(expected_cats) or not expected_cats:
                    detected_for_rule.add(eid)
        rule_event_detected[rule_id] = len(detected_for_rule)

    # ------------------------------------------------------------------
    # Build per-rule alert metrics
    # ------------------------------------------------------------------
    all_alert_rule_ids = set(alerts_by_rule.keys())
    rule_alert_metrics: list[RuleAlertMetrics] = []
    total_alert_tp = 0
    total_alert_fp = 0
    total_alert_attribution_errors = 0
    total_alert_unassessed = 0
    total_alerts = 0

    for rule_id in sorted(all_alert_rule_ids):
        tp = rule_alert_true_positives.get(rule_id, 0)
        fp = rule_alert_false_positives.get(rule_id, 0)
        attribution_errors = rule_alert_attribution_errors.get(rule_id, 0)
        unassessed = rule_alert_unassessed.get(rule_id, 0)
        total = rule_alert_total.get(rule_id, 0)
        assessed = tp + fp + attribution_errors
        precision = _safe_divide(tp, assessed)

        rule_name = "unknown"
        for alerts in alerts_by_rule.values():
            for a in alerts:
                if a["rule_id"] == rule_id:
                    rule_name = a["rule_name"]
                    break

        rule_alert_metrics.append(
            RuleAlertMetrics(
                rule_id=rule_id,
                rule_name=rule_name,
                total_alerts=total,
                true_positive_alerts=tp,
                false_positive_alerts=fp,
                attribution_error_alerts=attribution_errors,
                unassessed_alerts=unassessed,
                assessed_alerts=assessed,
                precision=round(precision, 4),
            )
        )

        total_alert_tp += tp
        total_alert_fp += fp
        total_alert_attribution_errors += attribution_errors
        total_alert_unassessed += unassessed
        total_alerts += total

    total_assessed = total_alert_tp + total_alert_fp + total_alert_attribution_errors
    alert_precision = _safe_divide(total_alert_tp, total_assessed)
    assessment_coverage = _safe_divide(total_assessed, total_alerts)

    # ------------------------------------------------------------------
    # Build per-rule event metrics
    # ------------------------------------------------------------------
    all_event_rule_ids = set(rule_event_expected.keys()) | set(
        rule_event_detected.keys()
    )
    rule_event_metrics: list[RuleEventMetrics] = []
    total_event_expected = 0
    total_event_detected = 0

    for rule_id in sorted(all_event_rule_ids):
        expected = rule_event_expected.get(rule_id, 0)
        detected = rule_event_detected.get(rule_id, 0)
        missed = max(0, expected - detected)
        recall = _safe_divide(detected, expected)

        rule_name = "unknown"
        for alerts in alerts_by_rule.values():
            for a in alerts:
                if a["rule_id"] == rule_id:
                    rule_name = a["rule_name"]
                    break

        rule_event_metrics.append(
            RuleEventMetrics(
                rule_id=rule_id,
                rule_name=rule_name,
                expected_events=expected,
                detected_events=detected,
                missed_events=missed,
                recall=round(recall, 4),
            )
        )

        total_event_expected += expected
        total_event_detected += detected

    event_recall = _safe_divide(len(detected_suspicious_event_ids), suspicious_count)

    # ------------------------------------------------------------------
    # Per-classification breakdown of alerts
    # ------------------------------------------------------------------
    breakdown: dict[str, dict[str, int]] = {
        "benign": {"alerts": 0},
        "suspicious": {
            "alerts": 0,
            "detected": len(detected_suspicious_event_ids),
        },
        "unlabeled": {"alerts": 0},
    }
    for rule_id, alerts in alerts_by_rule.items():
        for alert in alerts:
            classifications = set()
            for eid in alert["evidence_event_ids"]:
                gt_entry = gt_by_event.get(eid)
                if gt_entry:
                    classifications.add(gt_entry["classification"])
            if "suspicious" in classifications:
                breakdown["suspicious"]["alerts"] += 1
            elif "benign" in classifications:
                breakdown["benign"]["alerts"] += 1
            elif "unlabeled" in classifications or not classifications:
                breakdown["unlabeled"]["alerts"] += 1

    # ------------------------------------------------------------------
    # F1 results — valid only when unit and population match
    # ------------------------------------------------------------------
    f1_alert = F1Result(
        evaluation_unit="alert",
        precision=round(alert_precision, 4),
        recall=0.0,  # alert-level recall not defined
        f1_score=0.0,
        formula="Alert-level F1 not defined (no alert population for recall).",
        valid=False,
    )
    f1_event = F1Result(
        evaluation_unit="event",
        precision=0.0,  # event-level precision not defined
        recall=round(event_recall, 4),
        f1_score=0.0,
        formula="Event-level F1 not defined (no event-level precision).",
        valid=False,
    )

    return EvaluationResults(
        dataset_id=dataset_id,
        total_events=total_events,
        labeled_events=labeled_count,
        benign_events=benign_count,
        suspicious_events=suspicious_count,
        unlabeled_events=unlabeled_count,
        alert_level=AlertLevelMetrics(
            total_alerts=total_alerts,
            true_positive_alerts=total_alert_tp,
            false_positive_alerts=total_alert_fp,
            attribution_error_alerts=total_alert_attribution_errors,
            unassessed_alerts=total_alert_unassessed,
            assessed_alerts=total_assessed,
            precision=round(alert_precision, 4),
            assessment_coverage=round(assessment_coverage, 4),
        ),
        rule_alert_metrics=rule_alert_metrics,
        event_level=EventLevelMetrics(
            total_suspicious_events=suspicious_count,
            detected_suspicious_events=len(detected_suspicious_event_ids),
            undetected_suspicious_events=suspicious_count
            - len(detected_suspicious_event_ids),
            recall=round(event_recall, 4),
        ),
        rule_event_metrics=rule_event_metrics,
        f1_alert=f1_alert,
        f1_event=f1_event,
        per_classification_breakdown=breakdown,
    )
