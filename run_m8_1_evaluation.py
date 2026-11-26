"""Comprehensive M8.1 dataset quality and detection evaluation.

Runs the full SentinelForge pipeline against the generated synthetic dataset
and evaluates detection performance against per-event ground truth.

Produces:
- Event-level ground truth coverage report
- Detection metrics (TP/FP/FN, precision, recall, F1) per rule and overall
- Confusion matrix
- PowerShell alert investigation
- Password spraying results
- Sysmon format validation
- Pipeline performance metrics
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import time
from pathlib import Path

sys.path.insert(0, ".")

from sentinelforge.datasets.evaluation import (
    CATEGORY_ALIASES,
    alert_categories_match,
    evaluate_detections,
)
from sentinelforge.datasets.generator import DatasetGenerator
from sentinelforge.datasets.ground_truth_labels import EventGroundTruthManifest
from sentinelforge.datasets.validators import validate_dataset
from sentinelforge.ingestion.reader import reader_for
from sentinelforge.ingestion.normalizer import normalize
from sentinelforge.detection.base import RuleRegistry
from sentinelforge.detection.beacon import C2BeaconRule
from sentinelforge.detection.failed_logins import FailedLoginBurstRule
from sentinelforge.detection.password_spray import PasswordSprayRule
from sentinelforge.detection.powershell import SuspiciousPowerShellRule
from sentinelforge.detection.processtree import SuspiciousProcessTreeRule
from sentinelforge.risk.correlator import DetectionCorrelator
from sentinelforge.risk.scorer import RiskScorer
from sentinelforge.storage.database import Database
from sentinelforge.storage.repositories import (
    DetectionRepository,
    EventRepository,
    RiskAssessmentRepository,
)


def load_event_ground_truth(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def run_pipeline(data_dir: Path) -> tuple:
    """Run the full pipeline and return (detection_results, normalized_events, timing)."""
    # Step 1: Ingest
    all_raw_events = []
    cat_counts = {}
    for cat_file in sorted(data_dir.glob("*.jsonl")):
        cat = cat_file.stem
        reader = reader_for(cat_file)
        events = list(reader.read(str(cat_file)))
        all_raw_events.extend(events)
        cat_counts[cat] = len(events)

    # Step 2: Normalize
    start = time.perf_counter()
    normalized = []
    norm_errors = 0
    for raw in all_raw_events:
        source = raw.get("source", "json")
        try:
            nev = normalize(raw, source=source)
            normalized.append(nev)
        except Exception:
            norm_errors += 1
    norm_time = time.perf_counter() - start

    # Step 3: Detection (including PasswordSprayRule)
    registry = RuleRegistry()
    registry.register(FailedLoginBurstRule())
    registry.register(SuspiciousPowerShellRule())
    registry.register(SuspiciousProcessTreeRule())
    registry.register(C2BeaconRule())
    registry.register(PasswordSprayRule())

    start = time.perf_counter()
    detection_results = registry.evaluate_all(normalized)
    det_time = time.perf_counter() - start

    # Step 4: Risk scoring
    start = time.perf_counter()
    scorer = RiskScorer(correlation_window_seconds=3600)
    assessments = scorer.score(detection_results)
    risk_time = time.perf_counter() - start

    # Step 5: Persist
    db_path = data_dir / "sentinelforge_eval.db"
    if os.path.exists(db_path):
        os.unlink(db_path)
    db = Database(db_path)
    db.initialize()

    event_repo = EventRepository(db)
    event_repo.insert_events(normalized)

    det_repo = DetectionRepository(db)
    det_repo.insert_detections(detection_results)

    risk_repo = RiskAssessmentRepository(db)
    for a in assessments:
        risk_repo.insert_risk_assessment(a)

    # Verification
    conn = sqlite3.connect(db_path)
    integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
    fk_check = conn.execute("PRAGMA foreign_key_check").fetchall()
    evt_count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    det_count = conn.execute("SELECT COUNT(*) FROM detections").fetchone()[0]
    risk_count = conn.execute("SELECT COUNT(*) FROM risk_assessments").fetchone()[0]
    conn.close()

    timing = {
        "normalization": norm_time,
        "detection": det_time,
        "risk_scoring": risk_time,
        "total": norm_time + det_time + risk_time,
    }

    return (
        detection_results,
        normalized,
        cat_counts,
        norm_errors,
        timing,
        {
            "integrity": integrity,
            "fk_violations": len(fk_check),
            "events_in_db": evt_count,
            "detections_in_db": det_count,
            "risk_in_db": risk_count,
        },
    )


def investigate_powershell_alerts(
    detection_results: list,
    event_gt: dict,
) -> dict:
    """Investigate PowerShell alert volume (TASK 3)."""
    gt_entries = event_gt.get("entries", [])
    gt_by_event = {e["event_id"]: e for e in gt_entries}

    ps_alerts = []
    ps_true_positives = 0
    ps_false_positives = 0
    ps_unlabeled = 0
    indicator_breakdown: dict[str, int] = {}

    for result in detection_results:
        if result.rule_id != "sentinelforge.detection.suspicious_powershell":
            continue
        metadata = result.metadata or {}
        indicators = metadata.get("indicators", [])
        for ind in indicators:
            indicator_breakdown[ind] = indicator_breakdown.get(ind, 0) + 1

        evidence_ids = [ev.event_id for ev in result.evidence]
        is_tp = False
        for eid in evidence_ids:
            gt_entry = gt_by_event.get(eid)
            if gt_entry and gt_entry["classification"] == "suspicious":
                is_tp = True
                break

        alert_info = {
            "rule_id": result.rule_id,
            "evidence_event_ids": evidence_ids,
            "indicators": indicators,
            "total_weight": metadata.get("total_weight", 0),
            "host": metadata.get("host"),
            "is_true_positive": is_tp,
        }
        ps_alerts.append(alert_info)

        if is_tp:
            ps_true_positives += 1
        else:
            # Check if evidence events are labeled benign or unlabeled
            has_benign = False
            has_unlabeled = False
            for eid in evidence_ids:
                gt_entry = gt_by_event.get(eid)
                if gt_entry:
                    if gt_entry["classification"] == "benign":
                        has_benign = True
                    elif gt_entry["classification"] == "unlabeled":
                        has_unlabeled = True
            if has_benign:
                ps_false_positives += 1
            elif has_unlabeled:
                ps_unlabeled += 1
            else:
                ps_false_positives += 1

    return {
        "total_powershell_alerts": len(ps_alerts),
        "true_positives": ps_true_positives,
        "false_positives": ps_false_positives,
        "unlabeled_evidence": ps_unlabeled,
        "indicator_breakdown": indicator_breakdown,
        "sample_alerts": ps_alerts[:5],
    }


def generate_confusion_matrix(
    detection_results: list,
    event_gt: dict,
) -> dict:
    """Generate a confusion matrix for detection vs ground truth."""
    gt_entries = event_gt.get("entries", [])
    gt_by_event = {e["event_id"]: e for e in gt_entries}

    # For each suspicious event, check if any detection covers it.
    suspicious_event_ids = {
        e["event_id"] for e in gt_entries if e["classification"] == "suspicious"
    }

    detected_suspicious_ids: set = set()
    alerts_on_benign = 0
    alerts_on_unlabeled = 0
    alerts_on_suspicious = 0

    for result in detection_results:
        evidence_ids = [ev.event_id for ev in result.evidence]
        classifications = set()

        # Build this alert's categories using the same alias table as
        # evaluate_detections() so both event-level paths agree on what
        # counts as a detected suspicious event.
        rule_id = getattr(result, "rule_id", "unknown")
        metadata = getattr(result, "metadata", {}) or {}
        mitre_technique = metadata.get("mitre_attack_technique", "")
        alert_categories: set[str] = set()
        if mitre_technique:
            alert_categories.add(mitre_technique.lower())
        alert_categories.update(CATEGORY_ALIASES.get(rule_id, set()))
        alert_categories.add(rule_id)

        for eid in evidence_ids:
            gt_entry = gt_by_event.get(eid)
            if gt_entry:
                classifications.add(gt_entry["classification"])
                if gt_entry["classification"] == "suspicious":
                    expected_cats_raw = gt_entry.get(
                        "expected_detection_categories",
                        gt_entry.get("expected_detection_category", ""),
                    )
                    # Count the event as detected only when at least one
                    # alert matches its expected detection category. Alerts
                    # on suspicious evidence with the wrong category are
                    # attribution errors, not true detections — consistent
                    # with evaluate_detections().
                    if alert_categories_match(alert_categories, expected_cats_raw):
                        detected_suspicious_ids.add(eid)

        if "suspicious" in classifications:
            alerts_on_suspicious += 1
        elif "benign" in classifications:
            alerts_on_benign += 1
        elif "unlabeled" in classifications or not classifications:
            alerts_on_unlabeled += 1

    true_positives = len(detected_suspicious_ids)
    false_negatives = len(suspicious_event_ids) - true_positives

    return {
        "suspicious_events_total": len(suspicious_event_ids),
        "suspicious_events_detected": true_positives,
        "suspicious_events_missed": false_negatives,
        "alerts_on_suspicious_evidence": alerts_on_suspicious,
        "alerts_on_benign_evidence": alerts_on_benign,
        "alerts_on_unlabeled_evidence": alerts_on_unlabeled,
    }


def validate_sysmon_format(data_dir: Path) -> dict:
    """Validate whether Sysmon records use native EVTX format (TASK 5)."""
    sysmon_path = data_dir / "windows_sysmon.jsonl"
    if not sysmon_path.exists():
        return {"error": "windows_sysmon.jsonl not found"}

    with open(sysmon_path, "r", encoding="utf-8") as fh:
        first_line = fh.readline().strip()

    if not first_line:
        return {"error": "empty file"}

    record = json.loads(first_line)

    # Check for native Sysmon EVTX structure
    has_native_structure = (
        "Event" in record
        and isinstance(record.get("Event"), dict)
        and "System" in record["Event"]
        and "EventData" in record["Event"]
    )

    # Check for generic normalized structure
    has_generic_structure = (
        "event_id" in record
        and "timestamp" in record
        and "event_type" in record
        and "process" in record
    )

    return {
        "file": "windows_sysmon.jsonl",
        "native_sysmon_structure": has_native_structure,
        "generic_normalized_structure": has_generic_structure,
        "format_label": (
            "native Sysmon EVTX" if has_native_structure else "generic JSONL (not native Sysmon)"
        ),
        "sample_keys": list(record.keys()),
    }


def main() -> None:
    data_dir = Path("data/generated")

    # Regenerate dataset to ensure fresh state
    gen = DatasetGenerator(seed=42)
    manifest = gen.generate(total_events=10000)
    print(f"Generated {manifest['total_events']} events")

    # Load per-event ground truth
    event_gt_path = data_dir / "event_ground_truth.json"
    event_gt = load_event_ground_truth(str(event_gt_path))
    print(f"Loaded ground truth for {event_gt['total_events']} events")
    print(f"Classification counts: {event_gt['classification_counts']}")

    # Run pipeline
    (
        detection_results,
        normalized,
        cat_counts,
        norm_errors,
        timing,
        db_verification,
    ) = run_pipeline(data_dir)

    print(f"\nPipeline: {len(detection_results)} detections, timing: {timing}")

    # Evaluate detections against ground truth
    eval_results = evaluate_detections(
        dataset_id=manifest["dataset_id"],
        detection_results=detection_results,
        event_ground_truth=event_gt,
    )

    # TASK 3: PowerShell investigation
    ps_investigation = investigate_powershell_alerts(detection_results, event_gt)

    # Confusion matrix
    confusion = generate_confusion_matrix(detection_results, event_gt)

    # TASK 5: Sysmon format validation
    sysmon_validation = validate_sysmon_format(data_dir)

    # Dataset validation
    dataset_validation = validate_dataset(str(data_dir))

    # Build final report
    report = {
        "dataset_id": manifest["dataset_id"],
        "seed": manifest["seed"],
        "generation_manifest": manifest,
        "dataset_validation": dataset_validation,
        "pipeline_timing": timing,
        "db_verification": db_verification,
        "event_ground_truth": {
            "total": event_gt["total_events"],
            "classification_counts": event_gt["classification_counts"],
        },
        "detection_evaluation": eval_results.to_dict(),
        "powershell_investigation": ps_investigation,
        "confusion_matrix": confusion,
        "sysmon_format_validation": sysmon_validation,
    }

    report_path = data_dir / "m8_1_evaluation_report.json"
    with open(report_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)

    # Print summary
    print("\n" + "=" * 60)
    print("M8.1 EVALUATION REPORT SUMMARY")
    print("=" * 60)
    print(f"\nDataset: {manifest['total_events']} events")
    print(f"Categories: {manifest['events_by_category']}")
    print(f"\nGround truth: {event_gt['classification_counts']}")
    print(f"\\nDetections: {len(detection_results)} total")
    print(f"\\n--- ALERT-LEVEL EVALUATION ---")
    print(f"Total alerts: {eval_results.alert_level.total_alerts}")
    print(f"True positive alerts: {eval_results.alert_level.true_positive_alerts}")
    print(f"False positive alerts: {eval_results.alert_level.false_positive_alerts}")
    print(f"Unassessed alerts: {eval_results.alert_level.unassessed_alerts}")
    print(f"Precision: {eval_results.alert_level.precision}")
    print(f"F1 alert-level valid: {eval_results.f1_alert.valid} (alert-level recall not defined)")
    print(f"\\nPer-rule alert metrics:")
    for m in eval_results.rule_alert_metrics:
        print(f"  {m.rule_id}: alerts={m.total_alerts}, TP={m.true_positive_alerts}, "
              f"FP={m.false_positive_alerts}, unassessed={m.unassessed_alerts}, "
              f"precision={m.precision}")
    print(f"\\n--- EVENT-LEVEL EVALUATION ---")
    print(f"Total suspicious events: {eval_results.event_level.total_suspicious_events}")
    print(f"Detected suspicious events: {eval_results.event_level.detected_suspicious_events}")
    print(f"Undetected suspicious events: {eval_results.event_level.undetected_suspicious_events}")
    print(f"Recall: {eval_results.event_level.recall}")
    print(f"F1 event-level valid: {eval_results.f1_event.valid} (event-level precision not defined)")
    print(f"\\nPer-rule event metrics:")
    for m in eval_results.rule_event_metrics:
        print(f"  {m.rule_id}: expected={m.expected_events}, detected={m.detected_events}, "
              f"missed={m.missed_events}, recall={m.recall}")
    print(f"\nPowerShell investigation:")
    print(f"  Total PowerShell alerts: {ps_investigation['total_powershell_alerts']}")
    print(f"  True positives: {ps_investigation['true_positives']}")
    print(f"  False positives: {ps_investigation['false_positives']}")
    print(f"  Unlabeled evidence: {ps_investigation['unlabeled_evidence']}")
    print(f"  Indicators: {ps_investigation['indicator_breakdown']}")
    print(f"\nConfusion matrix:")
    for k, v in confusion.items():
        print(f"  {k}: {v}")
    print(f"\nSysmon format: {sysmon_validation['format_label']}")
    print(f"  Native structure: {sysmon_validation['native_sysmon_structure']}")
    print(f"\nDataset validation: {'PASSED' if dataset_validation['valid'] else 'FAILED'}")
    print(f"\nReport written to {report_path}")


if __name__ == "__main__":
    main()
