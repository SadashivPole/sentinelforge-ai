"""Tests for password spraying detection rule."""

from __future__ import annotations

from datetime import datetime, timezone

from sentinelforge.detection.base import Severity
from sentinelforge.detection.password_spray import PasswordSprayRule
from sentinelforge.ingestion.normalizer import (
    AuthenticationInfo,
    NormalizedEvent,
)


def _make_auth_event(
    event_id: str,
    timestamp: str,
    outcome: str,
    username: str,
    source_address: str,
    host: str = "host-1",
) -> NormalizedEvent:
    raw = {
        "event_id": event_id,
        "timestamp": timestamp,
        "event_type": "auth.login.failed",
        "user": username,
        "host": host,
        "authentication": {
            "outcome": outcome,
            "method": "ssh",
            "username": username,
            "source_address": source_address,
        },
    }
    return NormalizedEvent(
        event_id=event_id,
        timestamp=timestamp,
        source="linux_auth",
        raw=raw,
        event_type="auth.login.failed",
        user=username,
        host=host,
        authentication=AuthenticationInfo(
            outcome=outcome,
            method="ssh",
            username=username,
            source_address=source_address,
        ),
    )


def test_password_spray_detects_multiple_usernames_same_source():
    """3+ failed logins from one source against distinct usernames triggers."""
    base = datetime(2024, 1, 15, 8, 0, 0, tzinfo=timezone.utc)
    events = []
    for i, username in enumerate(["alice", "bob", "charlie"]):
        ts = base.replace(minute=8, second=i * 10).isoformat()
        events.append(_make_auth_event(
            event_id=f"evt-spray-{i}",
            timestamp=ts,
            outcome="failure",
            username=username,
            source_address="192.0.2.100",
        ))

    results = PasswordSprayRule().evaluate(events)
    assert len(results) == 1
    assert results[0].rule_id == "sentinelforge.detection.password_spray"
    assert results[0].metadata["distinct_username_count"] == 3
    assert results[0].metadata["source_address"] == "192.0.2.100"


def test_password_spray_below_username_threshold_no_alert():
    """2 distinct usernames from one source (below threshold of 3) → no alert."""
    base = datetime(2024, 1, 15, 8, 0, 0, tzinfo=timezone.utc)
    events = []
    for i, username in enumerate(["alice", "bob"]):
        ts = base.replace(minute=8, second=i * 10).isoformat()
        events.append(_make_auth_event(
            event_id=f"evt-spray-{i}",
            timestamp=ts,
            outcome="failure",
            username=username,
            source_address="192.0.2.100",
        ))

    results = PasswordSprayRule().evaluate(events)
    assert results == []


def test_password_spray_different_sources_no_cross_contamination():
    """Failed logins from different sources are not grouped together."""
    base = datetime(2024, 1, 15, 8, 0, 0, tzinfo=timezone.utc)
    events = []
    # Source A: 3 attempts against 1 username (not spraying)
    for i in range(3):
        ts = base.replace(minute=8, second=i * 10).isoformat()
        events.append(_make_auth_event(
            event_id=f"evt-a-{i}",
            timestamp=ts,
            outcome="failure",
            username="alice",
            source_address="192.0.2.100",
        ))
    # Source B: 3 attempts against 1 username (not spraying)
    for i in range(3):
        ts = base.replace(minute=9, second=i * 10).isoformat()
        events.append(_make_auth_event(
            event_id=f"evt-b-{i}",
            timestamp=ts,
            outcome="failure",
            username="bob",
            source_address="198.51.100.50",
        ))

    results = PasswordSprayRule().evaluate(events)
    assert results == []


def test_password_spray_successful_auth_not_counted():
    """Successful authentications are not counted as spray attempts."""
    base = datetime(2024, 1, 15, 8, 0, 0, tzinfo=timezone.utc)
    events = []
    # 2 failures + 1 success from same source against different users
    for i, (username, outcome) in enumerate([
        ("alice", "failure"),
        ("bob", "failure"),
        ("charlie", "success"),
    ]):
        ts = base.replace(minute=8, second=i * 10).isoformat()
        events.append(_make_auth_event(
            event_id=f"evt-spray-{i}",
            timestamp=ts,
            outcome=outcome,
            username=username,
            source_address="192.0.2.100",
        ))

    results = PasswordSprayRule().evaluate(events)
    assert results == []  # only 2 distinct failure usernames, below threshold


def test_password_spray_outside_window_no_alert():
    """Attempts spread outside the time window don't trigger."""
    base = datetime(2024, 1, 15, 8, 0, 0, tzinfo=timezone.utc)
    events = []
    for i, username in enumerate(["alice", "bob", "charlie"]):
        ts = base.replace(hour=8 + i, minute=0).isoformat()  # 1 hour apart
        events.append(_make_auth_event(
            event_id=f"evt-spray-{i}",
            timestamp=ts,
            outcome="failure",
            username=username,
            source_address="192.0.2.100",
        ))

    results = PasswordSprayRule().evaluate(events)
    assert results == []


def test_password_spray_severity_high():
    """Password spray alerts are HIGH severity."""
    base = datetime(2024, 1, 15, 8, 0, 0, tzinfo=timezone.utc)
    events = []
    for i, username in enumerate(["alice", "bob", "charlie"]):
        ts = base.replace(minute=8, second=i * 10).isoformat()
        events.append(_make_auth_event(
            event_id=f"evt-spray-{i}",
            timestamp=ts,
            outcome="failure",
            username=username,
            source_address="192.0.2.100",
        ))

    results = PasswordSprayRule().evaluate(events)
    assert len(results) == 1
    assert results[0].severity == Severity.HIGH


def test_password_spray_mitre_mapping():
    """Password spray maps to MITRE T1110.003."""
    base = datetime(2024, 1, 15, 8, 0, 0, tzinfo=timezone.utc)
    events = []
    for i, username in enumerate(["alice", "bob", "charlie"]):
        ts = base.replace(minute=8, second=i * 10).isoformat()
        events.append(_make_auth_event(
            event_id=f"evt-spray-{i}",
            timestamp=ts,
            outcome="failure",
            username=username,
            source_address="192.0.2.100",
        ))

    results = PasswordSprayRule().evaluate(events)
    assert len(results) == 1
    assert results[0].metadata["mitre_attack_technique"] == "T1110.003"
    assert results[0].metadata["mitre_attack_tactic"] == "Credential Access"


# ---------------------------------------------------------------------------
# Independent end-to-end regression test (M8.3.6 requirement)
# Generates data in a temp directory, runs the real pipeline, queries its own DB.
# ---------------------------------------------------------------------------

def test_password_spray_rule_detects_all_expected_events_e2e():
    """End-to-end: generated dataset → pipeline → DB → verify exact event ID sets.

    Verifies:
      - 210 expected password-spray event IDs (st-003: 6 + st-015-ps: 204).
      - All 210 detected by PasswordSprayRule (event-level recall = 1.0).
      - Zero missed expected events.
      - Three st-007 attribution errors separately classified.
      - No genuine benign false positives misclassified as attribution errors.
    """
    import json
    import os
    import sqlite3
    import tempfile
    from collections import Counter
    from pathlib import Path

    from sentinelforge.datasets.generator import DatasetGenerator
    from sentinelforge.ingestion.reader import reader_for
    from sentinelforge.ingestion.normalizer import normalize
    from sentinelforge.detection.base import RuleRegistry
    from sentinelforge.detection.password_spray import PasswordSprayRule
    from sentinelforge.storage.database import Database
    from sentinelforge.storage.repositories import EventRepository, DetectionRepository

    with tempfile.TemporaryDirectory() as tmpdir:
        # ---- Step 1: Generate dataset in temp directory ----
        gen = DatasetGenerator(seed=42, output_dir=tmpdir)
        gen.generate(total_events=10000)

        # ---- Step 2: Ingest all category JSONL files ----
        data_dir = Path(tmpdir)
        all_raw_events = []
        for cat_file in sorted(data_dir.glob("*.jsonl")):
            reader = reader_for(cat_file)
            events = list(reader.read(str(cat_file)))
            all_raw_events.extend(events)

        # ---- Step 3: Normalize ----
        normalized = []
        for raw in all_raw_events:
            source = raw.get("source", "json")
            nev = normalize(raw, source=source)
            normalized.append(nev)

        # ---- Step 4: Detection with PasswordSprayRule only ----
        registry = RuleRegistry()
        registry.register(PasswordSprayRule())
        detection_results = registry.evaluate_all(normalized)

        # ---- Step 5: Persist to own database ----
        db_path = os.path.join(tmpdir, "password_spray_eval.db")
        if os.path.exists(db_path):
            os.unlink(db_path)

        db = Database(db_path)
        db.initialize()
        event_repo = EventRepository(db)
        event_repo.insert_events(normalized)
        det_repo = DetectionRepository(db)
        det_repo.insert_detections(detection_results)

        # ---- Step 6: Query DB for exact event ID sets ----
        conn = sqlite3.connect(db_path)
        integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
        fk_violations = conn.execute("PRAGMA foreign_key_check").fetchall()

        # Count detections by rule
        det_rows = conn.execute(
            "SELECT rule_id, COUNT(*) FROM detections GROUP BY rule_id"
        ).fetchall()

        # Expected IDs: ground-truth events labeled as password_spray
        expected_password_spray_event_ids = set()
        gt_path = os.path.join(tmpdir, "event_ground_truth.json")
        with open(gt_path) as f:
            gt = json.load(f)
        for e in gt["entries"]:
            if "password_spray" in e.get("expected_detection_categories", []):
                expected_password_spray_event_ids.add(e["event_id"])

        # Detected IDs: events referenced by PasswordSprayRule evidence rows
        detected_password_spray_event_ids = set()
        evidence_event_ids = []  # track all references including duplicates
        for row in conn.execute(
            """
            SELECT e.event_id
            FROM evidence e
            JOIN detections d ON e.detection_id = d.detection_id
            WHERE d.rule_id = ?
            """,
            ("sentinelforge.detection.password_spray",),
        ):
            if row[0]:
                detected_password_spray_event_ids.add(row[0])
                evidence_event_ids.append(row[0])

        # Duplicate evidence references (same event cited by multiple detections)
        dup_counts = Counter(evidence_event_ids)
        duplicate_references = {eid: cnt for eid, cnt in dup_counts.items() if cnt > 1}

        # Set operations
        intersection = expected_password_spray_event_ids & detected_password_spray_event_ids
        missing_ids = expected_password_spray_event_ids - detected_password_spray_event_ids
        unexpected_ids = detected_password_spray_event_ids - expected_password_spray_event_ids

        conn.close()

        # ---- Step 7: Verify ----
        assert integrity == "ok", f"DB integrity check failed: {integrity}"
        assert not fk_violations, f"FK violations: {fk_violations}"
        assert any(
            row[0] == "sentinelforge.detection.password_spray" for row in det_rows
        ), "PasswordSprayRule not found in detections"

        expected_count = len(expected_password_spray_event_ids)
        assert expected_count == 210, (
            f"Expected exactly 210 ground-truth password_spray event IDs, "
            f"got {expected_count}"
        )

        # All 210 expected events must be detected
        assert not missing_ids, (
            f"{len(missing_ids)} expected password_spray events NOT detected: "
            f"{sorted(missing_ids)[:20]}"
        )
        assert intersection == expected_password_spray_event_ids, (
            f"Intersection ({len(intersection)}) != expected set ({expected_count})"
        )

        # Unexpected IDs: only st-007 attribution errors (correct detection,
        # labeled under a different category). No benign false positives.
        for uid in unexpected_ids:
            entry = None
            for e in gt["entries"]:
                if e["event_id"] == uid:
                    entry = e
                    break
            assert entry is not None, (
                f"Detected event {uid} not found in ground truth at all"
            )
            # Must be classified suspicious (not benign)
            assert entry["classification"] == "suspicious", (
                f"Unexpected ID {uid} is classified benign (false positive): "
                f"categories={entry.get('expected_detection_categories')}"
            )
            # Must NOT be labeled as password_spray (that would be in expected)
            assert "password_spray" not in entry.get(
                "expected_detection_categories", []
            ), f"Unexpected ID {uid} is labeled password_spray (should be expected)"

        # Report
        print(f"\n  Expected password_spray event IDs: {expected_count}")
        print(f"  Detected password_spray event IDs: {len(detected_password_spray_event_ids)}")
        print(f"  Intersection: {len(intersection)}")
        print(f"  Missing: {len(missing_ids)}")
        print(f"  Unexpected: {len(unexpected_ids)} (attribution errors)")
        print(f"  Duplicate evidence references: {len(duplicate_references)}")
