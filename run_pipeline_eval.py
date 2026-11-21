"""End-to-end pipeline test: ingest generated dataset through detection,
risk scoring, and SQLite persistence. Produces an evaluation report."""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import time
from pathlib import Path

sys.path.insert(0, ".")

from sentinelforge.ingestion.reader import reader_for
from sentinelforge.ingestion.normalizer import normalize
from sentinelforge.detection.base import RuleRegistry
from sentinelforge.detection.failed_logins import FailedLoginBurstRule
from sentinelforge.detection.powershell import SuspiciousPowerShellRule
from sentinelforge.detection.processtree import SuspiciousProcessTreeRule
from sentinelforge.detection.beacon import C2BeaconRule
from sentinelforge.risk.correlator import DetectionCorrelator
from sentinelforge.risk.scorer import RiskScorer
from sentinelforge.storage.database import Database
from sentinelforge.storage.repositories import (
    EventRepository,
    DetectionRepository,
    RiskAssessmentRepository,
)


def main() -> None:
    data_dir = Path("data/generated")

    # ---- Step 1: Ingest ----
    all_raw_events = []
    cat_counts = {}
    for cat_file in sorted(data_dir.glob("*.jsonl")):
        cat = cat_file.stem
        reader = reader_for(cat_file)
        events = list(reader.read(str(cat_file)))
        all_raw_events.extend(events)
        cat_counts[cat] = len(events)
        print(f"Ingested {cat}: {len(events)} events")

    print(f"\nTotal raw events: {len(all_raw_events)}")

    # ---- Step 2: Normalize ----
    start = time.perf_counter()
    normalized = []
    norm_errors = 0
    for raw in all_raw_events:
        source = raw.get("source", "json")
        try:
            nev = normalize(raw, source=source)
            normalized.append(nev)
        except Exception as e:
            norm_errors += 1
            if norm_errors <= 3:
                print(f"Normalization error for {raw.get('event_id', 'unknown')}: {e}")
    norm_time = time.perf_counter() - start
    print(f"\nNormalized {len(normalized)} events in {norm_time:.3f}s "
          f"({len(normalized)/max(norm_time,0.001):,.0f} events/sec)")
    if norm_errors:
        print(f"  Normalization errors: {norm_errors}")

    # ---- Step 3: Detection ----
    registry = RuleRegistry()
    registry.register(FailedLoginBurstRule())
    registry.register(SuspiciousPowerShellRule())
    registry.register(SuspiciousProcessTreeRule())
    registry.register(C2BeaconRule())

    start = time.perf_counter()
    detection_results = registry.evaluate_all(normalized)
    det_time = time.perf_counter() - start
    print(f"\nDetection: {len(detection_results)} results in {det_time:.3f}s")

    det_categories: dict[str, int] = {}
    for r in detection_results:
        cat = r.metadata.get("mitre_attack_technique", r.rule_id)
        det_categories[cat] = det_categories.get(cat, 0) + 1
    print("Detections by category:")
    for cat, count in sorted(det_categories.items()):
        print(f"  {cat}: {count}")

    # ---- Step 4: Risk scoring ----
    start = time.perf_counter()
    scorer = RiskScorer(correlation_window_seconds=3600)
    assessments = scorer.score(detection_results)
    risk_time = time.perf_counter() - start
    print(f"\nRisk scoring: {len(assessments)} assessments in {risk_time:.3f}s")
    for a in assessments:
        print(f"  {a.affected_host}: score={a.risk_score} ({a.risk_classification}), "
              f"detections={len(a.contributing_detection_ids)}")

    # ---- Step 5: SQLite persistence ----
    db_path = "data/generated/sentinelforge_eval.db"
    if os.path.exists(db_path):
        os.unlink(db_path)

    db = Database(db_path)
    db.initialize()

    start = time.perf_counter()
    event_repo = EventRepository(db)
    event_ids = event_repo.insert_events(normalized)
    event_persist_time = time.perf_counter() - start
    print(f"\nPersisted {len(event_ids)} events in {event_persist_time:.3f}s "
          f"({len(event_ids)/max(event_persist_time,0.001):,.0f} events/sec)")

    start = time.perf_counter()
    det_repo = DetectionRepository(db)
    det_ids = det_repo.insert_detections(detection_results)
    det_persist_time = time.perf_counter() - start
    print(f"Persisted {len(det_ids)} detections in {det_persist_time:.3f}s")

    start = time.perf_counter()
    risk_repo = RiskAssessmentRepository(db)
    risk_ids = [risk_repo.insert_risk_assessment(a) for a in assessments]
    risk_persist_time = time.perf_counter() - start
    print(f"Persisted {len(risk_ids)} risk assessments in {risk_persist_time:.3f}s")

    # ---- Step 6: Verification ----
    conn = sqlite3.connect(db_path)
    integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
    fk_check = conn.execute("PRAGMA foreign_key_check").fetchall()
    evt_count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    det_count = conn.execute("SELECT COUNT(*) FROM detections").fetchone()[0]
    risk_count = conn.execute("SELECT COUNT(*) FROM risk_assessments").fetchone()[0]
    conn.close()

    print(f"\nVerification:")
    print(f"  integrity_check: {integrity}")
    print(f"  foreign_key_check: {'OK' if not fk_check else len(fk_check) + ' violations'}")
    print(f"  events in DB: {evt_count}")
    print(f"  detections in DB: {det_count}")
    print(f"  risk assessments in DB: {risk_count}")

    # ---- Summary ----
    total_time = (norm_time + det_time + risk_time + event_persist_time
                  + det_persist_time + risk_persist_time)
    print(f"\nTotal pipeline time: {total_time:.3f}s")
    print(f"Events per second (end-to-end): {len(normalized)/max(total_time,0.001):,.0f}")

    # Write evaluation report
    report = {
        "dataset_id": "sentinelforge-ds-001",
        "total_raw_events": len(all_raw_events),
        "events_by_category": cat_counts,
        "normalized_events": len(normalized),
        "normalization_errors": norm_errors,
        "detection_results": len(detection_results),
        "detection_categories": det_categories,
        "risk_assessments": len(assessments),
        "pipeline_timing_seconds": {
            "normalization": round(norm_time, 4),
            "detection": round(det_time, 4),
            "risk_scoring": round(risk_time, 4),
            "event_persistence": round(event_persist_time, 4),
            "detection_persistence": round(det_persist_time, 4),
            "risk_persistence": round(risk_persist_time, 4),
            "total": round(total_time, 4),
        },
        "events_per_second": round(len(normalized) / max(total_time, 0.001), 0),
        "integrity_check": integrity,
        "foreign_key_violations": len(fk_check),
        "events_in_db": evt_count,
        "detections_in_db": det_count,
        "risk_assessments_in_db": risk_count,
    }

    report_path = data_dir / "pipeline_evaluation.json"
    with open(report_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    print(f"\nEvaluation report written to {report_path}")


if __name__ == "__main__":
    main()
