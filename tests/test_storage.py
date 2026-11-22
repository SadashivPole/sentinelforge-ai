"""Tests for the SQLite storage engine (Milestone 7).

Scenarios:
1. Database creation
2. Event insertion
3. Event retrieval
4. Bulk event ingestion
5. Duplicate handling
6. Detection persistence
7. Evidence preservation
8. Risk assessment persistence
9. Foreign-key constraints
10. Transaction rollback
11. Query filtering
12. Search functionality
13. Unicode and special-character handling
14. Database schema versioning
15. Persistence across application restarts
"""

from __future__ import annotations

import os
import sqlite3
import tempfile

import pytest

from sentinelforge.detection.base import DetectionResult, Evidence, Severity
from sentinelforge.ingestion.normalizer import (
    AuthenticationInfo,
    NetworkInfo,
    NormalizedEvent,
    ProcessInfo,
)
from sentinelforge.risk.scorer import RiskAssessment, ScoringFactor
from sentinelforge.storage.database import Database
from sentinelforge.storage.repositories import (
    DetectionRepository,
    DuplicateIdCollisionError,
    EventRepository,
    RiskAssessmentRepository,
)
from sentinelforge.storage.schema import SCHEMA_VERSION, get_schema_version

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _tmp_db_path() -> str:
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    os.unlink(path)  # let SQLite create it fresh
    return path


def _make_event(
    event_id: str = "evt-1",
    host: str = "host-1",
    source: str = "jsonl",
    event_type: str = "network.connection",
    raw_extra: dict | None = None,
) -> NormalizedEvent:
    raw = {
        "event_id": event_id,
        "timestamp": "2024-01-01T00:00:00Z",
        "event_type": event_type,
        "user": "user-1",
        "host": host,
    }
    if raw_extra:
        raw.update(raw_extra)
    return NormalizedEvent(
        event_id=event_id,
        timestamp="2024-01-01T00:00:00+00:00",
        source=source,
        raw=raw,
        event_type=event_type,
        user="user-1",
        host=host,
        process=ProcessInfo(
            name="powershell.exe",
            command_line="powershell.exe -EncodedCommand ABC",
            pid=1234,
            ppid=100,
            user="user-1",
        ),
        network=NetworkInfo(
            direction="outbound",
            remote_address="203.0.113.45",
            remote_port=4433,
            protocol="https",
        ),
        authentication=AuthenticationInfo(
            outcome="failure",
            method="password",
            username="admin",
            source_address="10.0.0.1",
        ),
    )


def _make_detection(
    rule_id: str = "sentinelforge.detection.test",
    host: str = "host-1",
    severity: Severity = Severity.HIGH,
    description: str = "A test detection",
    detection_id: str | None = None,
) -> DetectionResult:
    return DetectionResult(
        rule_id=rule_id,
        rule_name="Test Detection",
        severity=severity,
        description=description,
        evidence=[
            Evidence(
                event_id="evt-1",
                timestamp="2024-01-01T00:00:00+00:00",
                source="jsonl",
                event_type="network.connection",
                user="user-1",
                host=host,
                source_address="10.0.0.1",
                raw={"event_id": "evt-1", "data": "preserved"},
            )
        ],
        metadata={"host": host, "custom_field": "custom_value"},
        triggered_at="2024-01-01T00:00:00+00:00",
        detection_id=detection_id or rule_id,
    )


def _make_assessment(
    assessment_id: str = "assess-1",
    host: str = "host-1",
    risk_score: int = 75,
    contributing_detection_ids: list[str] | None = None,
) -> RiskAssessment:
    return RiskAssessment(
        assessment_id=assessment_id,
        affected_host=host,
        risk_score=risk_score,
        risk_classification="high",
        contributing_detection_ids=contributing_detection_ids or ["rule-a", "rule-b"],
        scoring_factors=[
            ScoringFactor(
                name="severity",
                weight=0.3,
                raw_score=80.0,
                weighted_score=24.0,
                description="High severity",
            )
        ],
        score_breakdown={"severity": 24.0, "total": 75.0},
        supporting_evidence_count=3,
        explanation="Test explanation",
        recommended_investigation_priorities=["Investigate first"],
        evidence_confidence="high",
        detection_severity=Severity.HIGH,
        asset_criticality_provided=True,
    )


# ---------------------------------------------------------------------------
# Database creation
# ---------------------------------------------------------------------------


def test_database_creates_tables():
    path = _tmp_db_path()
    try:
        db = Database(path)
        version = db.initialize()
        assert version == SCHEMA_VERSION
        assert db.schema_version() == SCHEMA_VERSION

        # Verify all expected tables exist.
        with db.connection() as conn:
            tables = {
                row["name"]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
        expected = {
            "events",
            "detections",
            "evidence",
            "risk_assessments",
            "risk_assessment_detections",
            "schema_metadata",
        }
        assert expected.issubset(tables), f"Missing: {expected - tables}"
    finally:
        os.unlink(path)


def test_schema_versioning():
    path = _tmp_db_path()
    try:
        db = Database(path)
        assert db.schema_version() is None  # not initialized yet
        version = db.initialize()
        assert version == SCHEMA_VERSION
        assert get_schema_version(path) == SCHEMA_VERSION
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# Event insertion and retrieval
# ---------------------------------------------------------------------------


def test_event_insertion_and_retrieval():
    path = _tmp_db_path()
    try:
        db = Database(path)
        db.initialize()
        repo = EventRepository(db)

        event = _make_event()
        eid = repo.insert_event(event)
        assert eid == "evt-1"

        retrieved = repo.get_event("evt-1")
        assert retrieved is not None
        assert retrieved.event_id == "evt-1"
        assert retrieved.host == "host-1"
        assert retrieved.user == "user-1"
        assert retrieved.event_type == "network.connection"
        assert retrieved.process is not None
        assert retrieved.process.name == "powershell.exe"
        assert retrieved.process.command_line == "powershell.exe -EncodedCommand ABC"
        assert retrieved.network is not None
        assert retrieved.network.remote_address == "203.0.113.45"
        assert retrieved.network.remote_port == 4433
        assert retrieved.network.protocol == "https"
        assert retrieved.authentication is not None
        assert retrieved.authentication.outcome == "failure"
        # Raw log preserved verbatim.
        assert retrieved.raw["user"] == "user-1"
        assert retrieved.raw["host"] == "host-1"
    finally:
        os.unlink(path)


def test_event_retrieval_not_found():
    path = _tmp_db_path()
    try:
        db = Database(path)
        db.initialize()
        repo = EventRepository(db)
        assert repo.get_event("nonexistent") is None
    finally:
        os.unlink(path)


def test_bulk_event_ingestion():
    path = _tmp_db_path()
    try:
        db = Database(path)
        db.initialize()
        repo = EventRepository(db)

        events = [
            _make_event(event_id=f"evt-{i}", host=f"host-{i % 3}") for i in range(50)
        ]
        ids = repo.insert_events(events)
        assert len(ids) == 50
        assert repo.count_events() == 50
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# Duplicate handling
# ---------------------------------------------------------------------------


def test_duplicate_event_handling():
    path = _tmp_db_path()
    try:
        db = Database(path)
        db.initialize()
        repo = EventRepository(db)

        event = _make_event(event_id="evt-dup")
        repo.insert_event(event)
        repo.insert_event(event)  # same id again
        assert repo.count_events() == 1  # idempotent, not duplicated
    finally:
        os.unlink(path)


def test_duplicate_detection_handling():
    path = _tmp_db_path()
    try:
        db = Database(path)
        db.initialize()
        repo = DetectionRepository(db)

        det = _make_detection(rule_id="rule-dup")
        repo.insert_detection(det)
        repo.insert_detection(det)  # same rule_id again
        retrieved = repo.get_detection("rule-dup")
        assert retrieved is not None
        assert len(retrieved.evidence) == 1  # evidence not duplicated
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# Detection persistence and evidence preservation
# ---------------------------------------------------------------------------


def test_detection_persistence():
    path = _tmp_db_path()
    try:
        db = Database(path)
        db.initialize()
        repo = DetectionRepository(db)

        det = _make_detection()
        did = repo.insert_detection(det)
        assert did == "sentinelforge.detection.test"

        retrieved = repo.get_detection("sentinelforge.detection.test")
        assert retrieved is not None
        assert retrieved.rule_id == "sentinelforge.detection.test"
        assert retrieved.rule_name == "Test Detection"
        assert retrieved.severity == Severity.HIGH
        assert retrieved.description == "A test detection"
        assert retrieved.metadata["host"] == "host-1"
        assert retrieved.metadata["custom_field"] == "custom_value"
    finally:
        os.unlink(path)


def test_evidence_preservation():
    path = _tmp_db_path()
    try:
        db = Database(path)
        db.initialize()
        repo = DetectionRepository(db)

        det = _make_detection()
        repo.insert_detection(det)

        retrieved = repo.get_detection("sentinelforge.detection.test")
        assert len(retrieved.evidence) == 1
        ev = retrieved.evidence[0]
        assert ev.event_id == "evt-1"
        assert ev.user == "user-1"
        assert ev.host == "host-1"
        assert ev.source_address == "10.0.0.1"
        # Raw evidence preserved verbatim.
        assert ev.raw["data"] == "preserved"
        assert ev.raw["event_id"] == "evt-1"
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# Risk assessment persistence
# ---------------------------------------------------------------------------


def test_risk_assessment_persistence():
    path = _tmp_db_path()
    try:
        db = Database(path)
        db.initialize()
        det_repo = DetectionRepository(db)
        repo = RiskAssessmentRepository(db)

        # Insert parent detections first (FK enforcement).
        det_repo.insert_detection(_make_detection(rule_id="rule-a"))
        det_repo.insert_detection(_make_detection(rule_id="rule-b"))

        assessment = _make_assessment()
        aid = repo.insert_risk_assessment(assessment)
        assert aid == "assess-1"

        retrieved = repo.get_risk_assessment("assess-1")
        assert retrieved is not None
        assert retrieved.affected_host == "host-1"
        assert retrieved.risk_score == 75
        assert retrieved.risk_classification == "high"
        assert retrieved.contributing_detection_ids == ["rule-a", "rule-b"]
        assert retrieved.evidence_confidence == "high"
        assert retrieved.detection_severity == Severity.HIGH
        assert retrieved.asset_criticality_provided is True
        assert retrieved.supporting_evidence_count == 3
        assert len(retrieved.scoring_factors) == 1
        assert retrieved.scoring_factors[0].name == "severity"
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# Foreign-key constraints
# ---------------------------------------------------------------------------


def test_foreign_key_constraints():
    path = _tmp_db_path()
    try:
        db = Database(path)
        db.initialize()

        # Insert evidence with a non-existent detection_id should fail.
        with db.transaction() as conn, pytest.raises(Exception):  # noqa: B017 - intentional: any exception indicates FK constraint enforced
            conn.execute(
                "INSERT INTO evidence (evidence_id, detection_id, event_id, raw) "
                "VALUES (?, ?, ?, ?)",
                ("ev-bad", "nonexistent-detection", "evt-1", "{}"),
            )
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# Transaction rollback
# ---------------------------------------------------------------------------


def test_transaction_rollback_on_fk_violation():
    """Genuine foreign-key violation rollback test.

    A valid operation starts, then an invalid FK operation occurs within the
    same transaction. An exception is raised, all operations in that
    transaction are rolled back, but previously committed data remains intact.
    """
    path = _tmp_db_path()
    try:
        db = Database(path)
        db.initialize()
        event_repo = EventRepository(db)
        det_repo = DetectionRepository(db)

        # Previously committed data: an event and a detection.
        event_repo.insert_event(_make_event(event_id="evt-valid"))
        det_repo.insert_detection(_make_detection(rule_id="rule-valid"))
        assert event_repo.count_events() == 1

        # Begin a transaction: valid op followed by invalid FK op.
        try:
            with db.transaction() as conn:
                # Valid: insert evidence referencing an existing detection.
                conn.execute(
                    "INSERT INTO evidence (evidence_id, detection_id, event_id, raw) "
                    "VALUES (?, ?, ?, ?)",
                    ("ev-good", "rule-valid", "evt-valid", "{}"),
                )
                # Invalid: evidence referencing a nonexistent detection.
                conn.execute(
                    "INSERT INTO evidence (evidence_id, detection_id, event_id, raw) "
                    "VALUES (?, ?, ?, ?)",
                    ("ev-bad", "nonexistent-detection", "evt-valid", "{}"),
                )
        except sqlite3.IntegrityError:
            pass

        # All operations in the failed transaction are rolled back:
        # the valid evidence from the same transaction is NOT persisted.
        with db.connection() as conn:
            retrieved_evidence = conn.execute(
                "SELECT * FROM evidence WHERE evidence_id = ?", ("ev-good",)
            ).fetchall()
        assert len(retrieved_evidence) == 0

        # Previously committed data remains intact.
        assert event_repo.count_events() == 1
        assert event_repo.get_event("evt-valid") is not None
        assert det_repo.get_detection("rule-valid") is not None
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# Query filtering
# ---------------------------------------------------------------------------


def test_event_query_filtering():
    path = _tmp_db_path()
    try:
        db = Database(path)
        db.initialize()
        repo = EventRepository(db)

        events = [
            _make_event(
                event_id=f"evt-{i}",
                host=f"host-{i % 2}",
                source="json" if i % 2 == 0 else "jsonl",
                event_type="authentication" if i < 3 else "network.connection",
            )
            for i in range(6)
        ]
        repo.insert_events(events)

        # Filter by host.
        host0 = repo.get_events(host="host-0")
        assert len(host0) == 3

        # Filter by source.
        jsonl_events = repo.get_events(source="jsonl")
        assert len(jsonl_events) == 3

        # Filter by event_type.
        auth_events = repo.get_events(event_type="authentication")
        assert len(auth_events) == 3

        # Pagination.
        first_page = repo.get_events(limit=2, offset=0)
        assert len(first_page) == 2
        second_page = repo.get_events(limit=2, offset=2)
        assert len(second_page) == 2
        assert first_page[0].event_id != second_page[0].event_id
    finally:
        os.unlink(path)


def test_detection_query_filtering():
    path = _tmp_db_path()
    try:
        db = Database(path)
        db.initialize()
        repo = DetectionRepository(db)

        det_high = _make_detection(
            rule_id="rule-high", host="host-a", severity=Severity.HIGH
        )
        det_low = _make_detection(
            rule_id="rule-low", host="host-b", severity=Severity.LOW
        )
        repo.insert_detection(det_high)
        repo.insert_detection(det_low)

        high = repo.get_detections(severity="high")
        assert len(high) == 1
        assert high[0].rule_id == "rule-high"

        host_a = repo.get_detections(host="host-a")
        assert len(host_a) == 1
        assert host_a[0].rule_id == "rule-high"
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# Search functionality
# ---------------------------------------------------------------------------


def test_event_search():
    path = _tmp_db_path()
    try:
        db = Database(path)
        db.initialize()
        repo = EventRepository(db)

        event = _make_event(raw_extra={"unique_marker": "find-me-12345"})
        repo.insert_event(event)

        results = repo.search_events("find-me-12345")
        assert len(results) == 1
        assert results[0].event_id == "evt-1"

        results = repo.search_events("nonexistent-query")
        assert results == []
    finally:
        os.unlink(path)


def test_detection_search():
    path = _tmp_db_path()
    try:
        db = Database(path)
        db.initialize()
        repo = DetectionRepository(db)

        det = _make_detection(
            rule_id="rule-searchable", description="suspicious PowerShell execution"
        )
        repo.insert_detection(det)

        results = repo.search_detections("PowerShell")
        assert len(results) == 1
        assert results[0].rule_id == "rule-searchable"

        results = repo.search_detections("nonexistent")
        assert results == []
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# Unicode and special-character handling
# ---------------------------------------------------------------------------


def test_unicode_handling():
    path = _tmp_db_path()
    try:
        db = Database(path)
        db.initialize()
        repo = EventRepository(db)

        raw = {
            "event_id": "evt-unicode",
            "user": " администратор ",
            "host": "서버-01",
            "data": "émoji 🚀 test",
        }
        event = NormalizedEvent(
            event_id="evt-unicode",
            timestamp="2024-01-01T00:00:00+00:00",
            source="json",
            raw=raw,
            user=" администратор ",
            host="서버-01",
        )
        repo.insert_event(event)
        retrieved = repo.get_event("evt-unicode")
        assert retrieved is not None
        assert retrieved.raw["user"] == " администратор "
        assert retrieved.raw["host"] == "서버-01"
        assert retrieved.raw["data"] == "émoji 🚀 test"
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# Analytics
# ---------------------------------------------------------------------------


def test_count_events():
    path = _tmp_db_path()
    try:
        db = Database(path)
        db.initialize()
        repo = EventRepository(db)
        assert repo.count_events() == 0

        repo.insert_event(_make_event(event_id="evt-a"))
        repo.insert_event(_make_event(event_id="evt-b"))
        assert repo.count_events() == 2
    finally:
        os.unlink(path)


def test_count_detections_by_severity():
    path = _tmp_db_path()
    try:
        db = Database(path)
        db.initialize()
        repo = DetectionRepository(db)

        repo.insert_detection(_make_detection(rule_id="r1", severity=Severity.HIGH))
        repo.insert_detection(_make_detection(rule_id="r2", severity=Severity.HIGH))
        repo.insert_detection(_make_detection(rule_id="r3", severity=Severity.LOW))

        counts = repo.count_detections_by_severity()
        assert counts.get("high") == 2
        assert counts.get("low") == 1
    finally:
        os.unlink(path)


def test_get_top_suspicious_hosts():
    path = _tmp_db_path()
    try:
        db = Database(path)
        db.initialize()
        repo = DetectionRepository(db)

        repo.insert_detection(_make_detection(rule_id="r1", host="host-a"))
        repo.insert_detection(_make_detection(rule_id="r2", host="host-a"))
        repo.insert_detection(_make_detection(rule_id="r3", host="host-b"))

        top = repo.get_top_suspicious_hosts(limit=5)
        assert top[0] == ("host-a", 2)
        assert ("host-b", 1) in top
    finally:
        os.unlink(path)


def test_get_detection_timeline():
    path = _tmp_db_path()
    try:
        db = Database(path)
        db.initialize()
        repo = DetectionRepository(db)

        repo.insert_detection(_make_detection(rule_id="r1", host="host-a"))
        repo.insert_detection(_make_detection(rule_id="r2", host="host-b"))

        timeline = repo.get_detection_timeline()
        assert len(timeline) == 2
        assert "ts" in timeline[0]
        assert "rule_id" in timeline[0]
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# Persistence across application restarts
# ---------------------------------------------------------------------------


def test_persistence_across_restarts():
    path = _tmp_db_path()
    try:
        # First "session": write data.
        db1 = Database(path)
        db1.initialize()
        repo1 = EventRepository(db1)
        repo1.insert_event(_make_event(event_id="evt-persist"))
        det_repo1 = DetectionRepository(db1)
        det_repo1.insert_detection(_make_detection())

        # Second "session": new Database instance, same file.
        db2 = Database(path)
        assert db2.schema_version() == SCHEMA_VERSION
        repo2 = EventRepository(db2)
        retrieved = repo2.get_event("evt-persist")
        assert retrieved is not None
        assert retrieved.event_id == "evt-persist"

        det_repo2 = DetectionRepository(db2)
        retrieved_det = det_repo2.get_detection("sentinelforge.detection.test")
        assert retrieved_det is not None
        assert retrieved_det.rule_id == "sentinelforge.detection.test"
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# Foreign-key integrity (hardening)
# ---------------------------------------------------------------------------


def test_unknown_detection_id_rejected_by_fk():
    """Risk assessment cannot link to a nonexistent detection."""
    path = _tmp_db_path()
    try:
        db = Database(path)
        db.initialize()
        repo = RiskAssessmentRepository(db)

        assessment = _make_assessment(
            assessment_id="assess-unknown",
            contributing_detection_ids=["nonexistent-rule"],
        )
        with pytest.raises(ValueError, match="nonexistent detection"):
            repo.insert_risk_assessment(assessment)
    finally:
        os.unlink(path)


def test_evidence_with_external_event_ref():
    """Evidence referencing an event not in the events table uses
    external_event_ref instead of event_id (nullable reference)."""
    path = _tmp_db_path()
    try:
        db = Database(path)
        db.initialize()
        det_repo = DetectionRepository(db)

        # Evidence references an external event id not in events table.
        det = _make_detection()
        external_evidence = Evidence(
            event_id="external-evt-999",
            timestamp=det.evidence[0].timestamp,
            source=det.evidence[0].source,
            event_type=det.evidence[0].event_type,
            user=det.evidence[0].user,
            host=det.evidence[0].host,
            source_address=det.evidence[0].source_address,
            raw={"external": True},
        )
        det2 = DetectionResult(
            rule_id=det.rule_id,
            rule_name=det.rule_name,
            severity=det.severity,
            description=det.description,
            evidence=[external_evidence],
            metadata=det.metadata,
            triggered_at=det.triggered_at,
            detection_id=det.rule_id,
        )
        det_repo.insert_detection(det2)

        retrieved = det_repo.get_detection("sentinelforge.detection.test")
        assert retrieved is not None
        assert len(retrieved.evidence) == 1
        ev = retrieved.evidence[0]
        assert ev.event_id == "external-evt-999"
        assert ev.raw["external"] is True
    finally:
        os.unlink(path)


def test_repeated_identical_evidence_insertion():
    """Re-inserting identical evidence is idempotent — no duplication."""
    path = _tmp_db_path()
    try:
        db = Database(path)
        db.initialize()
        det_repo = DetectionRepository(db)

        det = _make_detection()
        det_repo.insert_detection(det)
        det_repo.insert_detection(det)  # same content again

        retrieved = det_repo.get_detection("sentinelforge.detection.test")
        assert len(retrieved.evidence) == 1  # evidence not duplicated
    finally:
        os.unlink(path)


def test_conflicting_evidence_collision():
    """Re-inserting a detection with the same ID but different evidence
    content is idempotent at the detection level; evidence is additive."""
    path = _tmp_db_path()
    try:
        db = Database(path)
        db.initialize()
        det_repo = DetectionRepository(db)

        det1 = _make_detection()
        det_repo.insert_detection(det1)

        # Re-insert same detection_id with different evidence — should be
        # idempotent (detection unchanged), evidence added.
        additional_evidence = Evidence(
            event_id="evt-additional",
            timestamp="2024-01-01T00:00:00+00:00",
            source="jsonl",
            event_type="network.connection",
            user="user-1",
            host="host-1",
            source_address="10.0.0.1",
            raw={"additional": True},
        )
        det2 = DetectionResult(
            rule_id="sentinelforge.detection.test",
            rule_name="Test Detection",
            severity=Severity.HIGH,
            description="A test detection",
            evidence=[additional_evidence],
            metadata={"host": "host-1", "custom_field": "custom_value"},
            triggered_at="2024-01-01T00:00:00+00:00",
            detection_id="sentinelforge.detection.test",
        )
        det_repo.insert_detection(det2)

        retrieved = det_repo.get_detection("sentinelforge.detection.test")
        assert retrieved is not None
        # Both evidence items preserved.
        assert len(retrieved.evidence) == 2
    finally:
        os.unlink(path)


def test_evidence_preserved_after_reinsert():
    """Re-inserting an existing detection cannot silently remove evidence."""
    path = _tmp_db_path()
    try:
        db = Database(path)
        db.initialize()
        det_repo = DetectionRepository(db)

        det = _make_detection()
        det_repo.insert_detection(det)
        assert len(det_repo.get_detection("sentinelforge.detection.test").evidence) == 1

        # Re-insert same detection — evidence count stays the same.
        det_repo.insert_detection(det)
        retrieved = det_repo.get_detection("sentinelforge.detection.test")
        assert len(retrieved.evidence) == 1
        assert retrieved.evidence[0].raw["data"] == "preserved"
    finally:
        os.unlink(path)


def test_rollback_after_integrity_violation():
    """Transaction rollback leaves no partial state after FK violation."""
    path = _tmp_db_path()
    try:
        db = Database(path)
        db.initialize()
        event_repo = EventRepository(db)
        det_repo = DetectionRepository(db)

        # Insert an event successfully.
        event_repo.insert_event(_make_event(event_id="evt-valid"))
        assert event_repo.count_events() == 1

        # Attempt an insert that violates FK (evidence with nonexistent
        # detection) — should roll back.
        det = _make_detection()
        # Force a bad detection_id that references nothing.
        det.rule_id = "nonexistent-rule"
        try:
            det_repo.insert_detection(det)
        except ValueError:
            pass

        # The valid event from before the failed transaction should persist.
        assert event_repo.count_events() == 1
        assert event_repo.get_event("evt-valid") is not None
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# Schema migration (hardening)
# ---------------------------------------------------------------------------


def test_migration_version_recorded():
    """Schema version is recorded and retrievable after initialization."""
    path = _tmp_db_path()
    try:
        db = Database(path)
        version = db.initialize()
        assert version == SCHEMA_VERSION
        assert db.schema_version() == SCHEMA_VERSION
    finally:
        os.unlink(path)


def test_migration_creates_external_event_ref_column():
    """Migrated v2 schema has external_event_ref column in evidence table."""
    path = _tmp_db_path()
    try:
        db = Database(path)
        db.initialize()
        assert db.schema_version() == SCHEMA_VERSION

        with db.connection() as conn:
            columns = {
                row["name"]
                for row in conn.execute("PRAGMA table_info(evidence)").fetchall()
            }
            assert "external_event_ref" in columns
            # event_id should be nullable (no NOTNULL constraint).
            for row in conn.execute("PRAGMA table_info(evidence)").fetchall():
                if row["name"] == "event_id":
                    assert row["notnull"] == 0
                    break
            else:
                raise AssertionError("event_id column not found")
    finally:
        os.unlink(path)


def test_migration_restores_detection_fk():
    """risk_assessment_detections.detection_id references detections after migration."""
    path = _tmp_db_path()
    try:
        db = Database(path)
        db.initialize()

        # Insert a detection, then a risk assessment linking to it.
        det_repo = DetectionRepository(db)
        det_repo.insert_detection(_make_detection())

        risk_repo = RiskAssessmentRepository(db)
        assessment = _make_assessment(
            contributing_detection_ids=["sentinelforge.detection.test"]
        )
        risk_repo.insert_risk_assessment(assessment)

        # Link exists.
        retrieved = risk_repo.get_risk_assessment("assess-1")
        assert retrieved is not None
        assert "sentinelforge.detection.test" in retrieved.contributing_detection_ids
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# Evidence collision integrity (hardening)
# ---------------------------------------------------------------------------


def test_evidence_collision_different_content_raises():
    """Same evidence ID with different raw content must raise
    DuplicateIdCollisionError — never silently discard conflicting evidence."""
    path = _tmp_db_path()
    try:
        db = Database(path)
        db.initialize()
        det_repo = DetectionRepository(db)

        # First insertion with content A.
        det1 = _make_detection()
        det_repo.insert_detection(det1)

        # Second insertion with same evidence_id but different raw content.
        conflicting_evidence = Evidence(
            event_id="evt-1",
            timestamp="2024-01-01T00:00:00+00:00",
            source="jsonl",
            event_type="network.connection",
            user="user-1",
            host="host-1",
            source_address="10.0.0.1",
            raw={"conflicting": "different-content"},
        )
        det2 = DetectionResult(
            rule_id="sentinelforge.detection.test",
            rule_name="Test Detection",
            severity=Severity.HIGH,
            description="A test detection",
            evidence=[conflicting_evidence],
            metadata={"host": "host-1", "custom_field": "custom_value"},
            triggered_at="2024-01-01T00:00:00+00:00",
            detection_id="sentinelforge.detection.test",
        )
        with pytest.raises(DuplicateIdCollisionError):
            det_repo.insert_detection(det2)

        # Original evidence must be preserved.
        retrieved = det_repo.get_detection("sentinelforge.detection.test")
        assert retrieved is not None
        assert len(retrieved.evidence) == 1
        assert retrieved.evidence[0].raw["data"] == "preserved"
    finally:
        os.unlink(path)


def test_detection_immutable_content_collision():
    """Same rule_id with changed immutable content must raise
    DuplicateIdCollisionError."""
    path = _tmp_db_path()
    try:
        db = Database(path)
        db.initialize()
        det_repo = DetectionRepository(db)

        det1 = _make_detection()
        det_repo.insert_detection(det1)

        # Same rule_id but different description → collision.
        det2 = _make_detection(
            description="A completely different description",
        )
        with pytest.raises(DuplicateIdCollisionError):
            det_repo.insert_detection(det2)

        # Original detection preserved.
        retrieved = det_repo.get_detection("sentinelforge.detection.test")
        assert retrieved is not None
        assert retrieved.description == "A test detection"
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# Actual schema migration v1 → v2 (hardening)
# ---------------------------------------------------------------------------


def _create_v1_database(path: str) -> None:
    """Create a populated v1 schema database fixture for migration testing."""
    import sqlite3

    conn = sqlite3.connect(path)
    conn.execute("PRAGMA foreign_keys = ON;")
    cur = conn.cursor()

    # v1 schema (without external_event_ref, without detection_id FK on
    # risk_assessment_detections, event_id NOT NULL on evidence).
    cur.executescript(
        """
        CREATE TABLE schema_metadata (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE events (
            event_id           TEXT PRIMARY KEY,
            timestamp          TEXT,
            source             TEXT NOT NULL,
            raw                TEXT NOT NULL,
            event_type         TEXT,
            user               TEXT,
            host               TEXT,
            process_pid        INTEGER,
            process_ppid       INTEGER,
            process_name       TEXT,
            process_path       TEXT,
            process_command_line TEXT,
            process_user       TEXT,
            process_hash_sha256 TEXT,
            network_direction  TEXT,
            network_local_address TEXT,
            network_remote_address TEXT,
            network_local_port  INTEGER,
            network_remote_port INTEGER,
            network_protocol   TEXT,
            auth_outcome       TEXT,
            auth_method        TEXT,
            auth_username      TEXT,
            auth_source_address TEXT,
            ingested_at        TEXT NOT NULL
        );
        CREATE TABLE detections (
            detection_id   TEXT PRIMARY KEY,
            rule_id        TEXT NOT NULL,
            rule_name      TEXT NOT NULL,
            severity       TEXT NOT NULL,
            description    TEXT NOT NULL,
            triggered_at   TEXT NOT NULL,
            metadata       TEXT NOT NULL,
            host           TEXT
        );
        CREATE TABLE evidence (
            evidence_id   TEXT PRIMARY KEY,
            detection_id  TEXT NOT NULL,
            event_id      TEXT NOT NULL,
            timestamp     TEXT,
            source        TEXT,
            event_type    TEXT,
            user          TEXT,
            host          TEXT,
            source_address TEXT,
            raw           TEXT NOT NULL,
            FOREIGN KEY (detection_id) REFERENCES detections(detection_id)
        );
        CREATE TABLE risk_assessments (
            assessment_id          TEXT PRIMARY KEY,
            affected_host          TEXT,
            risk_score             INTEGER NOT NULL,
            risk_classification    TEXT NOT NULL,
            explanation            TEXT NOT NULL,
            evidence_confidence    TEXT NOT NULL,
            detection_severity     TEXT NOT NULL,
            asset_criticality_provided INTEGER NOT NULL DEFAULT 0,
            supporting_evidence_count INTEGER NOT NULL DEFAULT 0,
            created_at             TEXT NOT NULL,
            scoring_factors_json   TEXT NOT NULL DEFAULT '[]',
            contributing_detection_ids_json TEXT NOT NULL DEFAULT '[]',
            score_breakdown_json   TEXT NOT NULL DEFAULT '{}',
            recommended_investigation_priorities_json TEXT NOT NULL DEFAULT '[]'
        );
        CREATE TABLE risk_assessment_detections (
            assessment_id TEXT NOT NULL,
            detection_id  TEXT NOT NULL,
            PRIMARY KEY (assessment_id, detection_id),
            FOREIGN KEY (assessment_id) REFERENCES risk_assessments(assessment_id)
        );
        """
    )

    # Insert v1 data.
    cur.execute(
        "INSERT INTO schema_metadata (key, value) VALUES ('schema_version', '1')"
    )
    cur.execute(
        "INSERT INTO events (event_id, timestamp, source, raw, event_type, user, host, ingested_at) "
        "VALUES ('evt-v1', '2024-01-01T00:00:00+00:00', 'jsonl', '{\"k\":\"v\"}', 'network.connection', 'user-1', 'host-1', '2024-01-01T00:00:00+00:00')"
    )
    cur.execute(
        "INSERT INTO detections (detection_id, rule_id, rule_name, severity, description, triggered_at, metadata, host) "
        "VALUES ('rule-v1', 'sentinelforge.detection.test', 'Test Detection', 'high', 'A test detection', '2024-01-01T00:00:00+00:00', '{}', 'host-1')"
    )
    cur.execute(
        "INSERT INTO evidence (evidence_id, detection_id, event_id, raw) "
        "VALUES ('ev-v1', 'rule-v1', 'evt-v1', '{\"preserved\": true}')"
    )
    cur.execute(
        "INSERT INTO risk_assessments (assessment_id, affected_host, risk_score, risk_classification, explanation, evidence_confidence, detection_severity, asset_criticality_provided, supporting_evidence_count, created_at) "
        "VALUES ('assess-v1', 'host-1', 75, 'high', 'Test', 'high', 'high', 0, 3, '2024-01-01T00:00:00+00:00')"
    )
    cur.execute(
        "INSERT INTO risk_assessment_detections (assessment_id, detection_id) "
        "VALUES ('assess-v1', 'rule-v1')"
    )
    conn.commit()
    conn.close()


def test_actual_v1_to_v3_migration():
    """Construct a populated v1 database, migrate v1 → v2 → v3, verify all
    data survives."""
    path = _tmp_db_path()
    try:
        _create_v1_database(path)

        # Verify it's v1 before migration.
        from sentinelforge.storage.schema import get_schema_version

        assert get_schema_version(path) == 1

        # Migrate to v3 (v1 → v2 → v3).
        db = Database(path)
        version = db.initialize()
        assert version == 3
        assert db.schema_version() == 3

        # Verify all v1 data survives migration.
        event_repo = EventRepository(db)
        det_repo = DetectionRepository(db)
        risk_repo = RiskAssessmentRepository(db)

        # Events survive.
        event = event_repo.get_event("evt-v1")
        assert event is not None
        assert event.event_id == "evt-v1"

        # Detections survive.
        detection = det_repo.get_detection("rule-v1")
        assert detection is not None
        assert detection.rule_id == "sentinelforge.detection.test"

        # Evidence survives.
        assert len(detection.evidence) == 1
        assert detection.evidence[0].raw["preserved"] is True

        # Risk assessments survive.
        assessment = risk_repo.get_risk_assessment("assess-v1")
        assert assessment is not None
        assert assessment.risk_score == 75
        assert assessment.affected_host == "host-1"

        # Relationships survive.
        assert "rule-v1" in assessment.contributing_detection_ids

        # v3: evidence.event_id FK to events exists.
        with db.connection() as conn:
            columns = {
                row["name"]
                for row in conn.execute("PRAGMA table_info(evidence)").fetchall()
            }
            assert "external_event_ref" in columns
            # event_id column exists and is nullable.
            for row in conn.execute("PRAGMA table_info(evidence)").fetchall():
                if row["name"] == "event_id":
                    assert row["notnull"] == 0
                    break
            else:
                raise AssertionError("event_id column not found")

        # Foreign-key checks pass.
        with db.connection() as conn:
            fk_violations = conn.execute("PRAGMA foreign_key_check").fetchall()
        assert len(fk_violations) == 0

        # Integrity check passes.
        with db.connection() as conn:
            integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
        assert integrity == "ok"
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# Evidence FK integrity (schema v3)
# ---------------------------------------------------------------------------


def test_evidence_valid_event_reference_accepted():
    """Evidence referencing an existing event is accepted (event_id FK)."""
    path = _tmp_db_path()
    try:
        db = Database(path)
        db.initialize()
        event_repo = EventRepository(db)
        det_repo = DetectionRepository(db)

        event = _make_event(event_id="evt-valid")
        event_repo.insert_event(event)

        det = _make_detection()
        # Evidence references an existing event -> event_id set internally.
        det_repo.insert_detection(det)

        retrieved = det_repo.get_detection("sentinelforge.detection.test")
        assert retrieved is not None
        assert len(retrieved.evidence) == 1
        assert retrieved.evidence[0].event_id == "evt-1"
    finally:
        os.unlink(path)


def test_evidence_invalid_event_reference_rejected():
    """Evidence referencing a non-existent event is rejected by FK when
    event_id is set directly (bypassing repository's external-event-ref
    fallback)."""
    path = _tmp_db_path()
    try:
        db = Database(path)
        db.initialize()
        det_repo = DetectionRepository(db)

        det = _make_detection()
        det_repo.insert_detection(det)

        # Directly insert evidence with an event_id that does not exist in
        # the events table -> FK violation.
        with db.connection() as conn, pytest.raises(Exception):  # noqa: B017 - intentional: any exception indicates FK constraint enforced
            conn.execute(
                "INSERT INTO evidence (evidence_id, detection_id, event_id, raw) "
                "VALUES (?, ?, ?, ?)",
                ("ev-bad-ref", "sentinelforge.detection.test", "nonexistent-evt", "{}"),
            )
    finally:
        os.unlink(path)


def test_evidence_external_event_reference_accepted():
    """Evidence with NULL event_id and external_event_ref is accepted
    when the event is not in the events table."""
    path = _tmp_db_path()
    try:
        db = Database(path)
        db.initialize()
        det_repo = DetectionRepository(db)

        det = _make_detection()
        external_evidence = Evidence(
            event_id="external-evt-999",
            timestamp=det.evidence[0].timestamp,
            source=det.evidence[0].source,
            event_type=det.evidence[0].event_type,
            user=det.evidence[0].user,
            host=det.evidence[0].host,
            source_address=det.evidence[0].source_address,
            raw={"external": True},
        )
        det2 = DetectionResult(
            rule_id=det.rule_id,
            rule_name=det.rule_name,
            severity=det.severity,
            description=det.description,
            evidence=[external_evidence],
            metadata={"host": "host-1", "custom_field": "custom_value"},
            triggered_at=det.triggered_at,
            detection_id=det.rule_id,
        )
        det_repo.insert_detection(det2)

        retrieved = det_repo.get_detection("sentinelforge.detection.test")
        assert retrieved is not None
        assert len(retrieved.evidence) == 1
        assert retrieved.evidence[0].event_id == "external-evt-999"
        assert retrieved.evidence[0].raw["external"] is True
    finally:
        os.unlink(path)


def test_referenced_event_cannot_be_deleted():
    """ON DELETE RESTRICT: an event referenced by evidence cannot be deleted."""
    path = _tmp_db_path()
    try:
        db = Database(path)
        db.initialize()
        event_repo = EventRepository(db)
        det_repo = DetectionRepository(db)

        # Insert event with id "evt-1" (matching evidence's event_id).
        event_repo.insert_event(_make_event(event_id="evt-1"))
        det_repo.insert_detection(_make_detection())

        # Attempt to delete the referenced event -> FK RESTRICT violation.
        with db.connection() as conn, pytest.raises(Exception):  # noqa: B017 - intentional: any exception indicates FK constraint enforced
            conn.execute("DELETE FROM events WHERE event_id = ?", ("evt-1",))
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# Event immutability (complete record comparison)
# ---------------------------------------------------------------------------


def test_event_same_id_same_complete_content_idempotent():
    """Same event_id with same complete normalized content is idempotent."""
    path = _tmp_db_path()
    try:
        db = Database(path)
        db.initialize()
        repo = EventRepository(db)

        event = _make_event(event_id="evt-immutable")
        repo.insert_event(event)
        assert repo.count_events() == 1

        # Re-insert same event — idempotent, no error.
        repo.insert_event(event)
        assert repo.count_events() == 1

        retrieved = repo.get_event("evt-immutable")
        assert retrieved is not None
        assert retrieved.host == "host-1"
        assert retrieved.event_type == "network.connection"
    finally:
        os.unlink(path)


def test_event_same_id_changed_host_collision():
    """Same event_id with same raw JSON but different normalized host → collision."""
    path = _tmp_db_path()
    try:
        db = Database(path)
        db.initialize()
        repo = EventRepository(db)

        event = _make_event(event_id="evt-immutable", host="host-a")
        repo.insert_event(event)
        assert repo.count_events() == 1

        # Same raw JSON, different host → collision.
        event2 = _make_event(event_id="evt-immutable", host="host-b")
        with pytest.raises(DuplicateIdCollisionError):
            repo.insert_event(event2)

        # Original event preserved.
        retrieved = repo.get_event("evt-immutable")
        assert retrieved is not None
        assert retrieved.host == "host-a"
    finally:
        os.unlink(path)


def test_event_same_id_changed_timestamp_collision():
    """Same event_id with same raw JSON but different timestamp → collision."""
    path = _tmp_db_path()
    try:
        db = Database(path)
        db.initialize()
        repo = EventRepository(db)

        raw = {
            "event_id": "evt-immutable",
            "timestamp": "2024-01-01T00:00:00Z",
            "event_type": "network.connection",
            "user": "user-1",
            "host": "host-1",
        }
        event = NormalizedEvent(
            event_id="evt-immutable",
            timestamp="2024-01-01T00:00:00+00:00",
            source="jsonl",
            raw=raw,
            event_type="network.connection",
            user="user-1",
            host="host-1",
        )
        repo.insert_event(event)

        event2 = NormalizedEvent(
            event_id="evt-immutable",
            timestamp="2024-01-01T01:00:00+00:00",
            source="jsonl",
            raw=raw,
            event_type="network.connection",
            user="user-1",
            host="host-1",
        )
        with pytest.raises(DuplicateIdCollisionError):
            repo.insert_event(event2)

        # Original event preserved.
        retrieved = repo.get_event("evt-immutable")
        assert retrieved is not None
        assert retrieved.timestamp == "2024-01-01T00:00:00+00:00"
    finally:
        os.unlink(path)
