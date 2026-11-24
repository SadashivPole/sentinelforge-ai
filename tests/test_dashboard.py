"""Tests for the local dashboard — queries, HTML escaping, and server smoke tests."""

from __future__ import annotations

import html
import os
import sqlite3
import subprocess
import sys
import tempfile
import time

import pytest

from sentinelforge.dashboard.queries import (
    connect,
    count_alerts,
    count_detections,
    count_events,
    get_attacks_coverage,
    get_event_detail,
    get_system_diagnostics,
    list_alerts,
    list_detection_rules,
    list_events,
)
from sentinelforge.dashboard.views import _e
from sentinelforge.storage.schema import get_schema_sql

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_temp_db() -> str:
    """Create a temp SQLite database with the canonical schema and synthetic data."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)

    conn = sqlite3.connect(path)
    conn.execute("PRAGMA foreign_keys = ON;")
    for stmt in get_schema_sql():
        conn.execute(stmt)

    now = "2026-01-15T03:12:01Z"

    # Events (canonical schema)
    conn.executemany(
        """
        INSERT INTO events (
            event_id, timestamp, source, raw, event_type, user, host,
            process_pid, process_ppid, process_name, process_path,
            process_command_line, process_user, process_hash_sha256,
            network_direction, network_local_address, network_remote_address,
            network_local_port, network_remote_port, network_protocol,
            auth_outcome, auth_method, auth_username, auth_source_address,
            ingested_at
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        [
            (
                "evt-001",
                now,
                "json",
                '{"raw": "test"}',
                "auth.login.failure",
                "admin",
                "host-1",
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                "failure",
                "password",
                "admin",
                "203.0.113.45",
                now,
            ),
            (
                "evt-002",
                now,
                "json",
                '{"raw": "<script>alert(1)</script>"}',
                "process.create",
                "svc_deploy",
                "host-2",
                1234,
                1,
                "cmd.exe",
                "C:\\\\Windows\\\\cmd.exe",
                "/c whoami",
                "SYSTEM",
                None,
                "inbound",
                "10.0.1.50",
                "10.0.1.100",
                445,
                12345,
                "TCP",
                None,
                None,
                None,
                None,
                now,
            ),
        ],
    )

    # Detections (canonical schema — no event_id column)
    conn.executemany(
        """
        INSERT INTO detections (
            detection_id, rule_id, rule_name, severity, description,
            triggered_at, metadata, host
        ) VALUES (?,?,?,?,?,?,?,?)
        """,
        [
            (
                "det-001",
                "FailedLoginBurstRule",
                "Failed Login Burst",
                "High",
                "Multiple failed logins",
                now,
                '{"host": "host-1"}',
                "host-1",
            ),
            (
                "det-002",
                "SuspiciousProcessRule",
                "Suspicious Process",
                "Medium",
                "Suspicious process",
                now,
                '{"host": "host-2"}',
                "host-2",
            ),
        ],
    )

    # Evidence (links detections to events)
    conn.executemany(
        """
        INSERT INTO evidence (
            evidence_id, detection_id, event_id, external_event_ref,
            timestamp, source, event_type, user, host, source_address, raw
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?)
        """,
        [
            (
                "ev-001",
                "det-001",
                "evt-001",
                None,
                now,
                "json",
                "auth.login.failure",
                "admin",
                "host-1",
                "203.0.113.45",
                '{"raw": "test"}',
            ),
            (
                "ev-002",
                "det-002",
                "evt-002",
                None,
                now,
                "json",
                "process.create",
                "svc_deploy",
                "host-2",
                "10.0.1.50",
                '{"raw": "<script>alert(1)</script>"}',
            ),
        ],
    )

    conn.execute(
        "INSERT INTO schema_metadata (key, value) VALUES ('schema_version', '3')"
    )
    conn.commit()
    conn.close()

    return path


def _make_empty_db() -> str:
    """Create a temp SQLite database with the canonical schema but no data."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)

    conn = sqlite3.connect(path)
    conn.execute("PRAGMA foreign_keys = ON;")
    for stmt in get_schema_sql():
        conn.execute(stmt)
    conn.execute(
        "INSERT INTO schema_metadata (key, value) VALUES ('schema_version', '3')"
    )
    conn.commit()
    conn.close()

    return path


# ---------------------------------------------------------------------------
# Query tests (SQL injection safety, empty DB, filtering)
# ---------------------------------------------------------------------------


class TestQueries:
    def test_count_events_and_detections(self):
        path = _make_temp_db()
        try:
            conn = connect(path)
            assert count_events(conn) == 2
            assert count_detections(conn) == 2
            assert count_alerts(conn) == 2
            conn.close()
        finally:
            os.unlink(path)

    def test_empty_database(self):
        path = _make_empty_db()
        try:
            conn = connect(path)
            assert count_events(conn) == 0
            assert count_detections(conn) == 0
            assert count_alerts(conn) == 0
            assert list_events(conn) == []
            assert list_alerts(conn) == []
            assert list_detection_rules(conn) == []
            assert get_event_detail(conn, "nonexistent") is None
            diag = get_system_diagnostics(conn)
            assert diag["total_events"] == 0
            assert diag["total_detections"] == 0
            conn.close()
        finally:
            os.unlink(path)

    def test_list_events_filtering(self):
        path = _make_temp_db()
        try:
            conn = connect(path)

            # No filter
            events = list_events(conn)
            assert len(events) == 2

            # Filter by event_type
            events = list_events(conn, event_type="auth.login.failure")
            assert len(events) == 1
            assert events[0]["event_id"] == "evt-001"

            # Filter by rule (via evidence → detections)
            events = list_events(conn, rule="FailedLoginBurstRule")
            assert len(events) == 1
            assert events[0]["event_id"] == "evt-001"

            # Pagination
            events = list_events(conn, limit=1)
            assert len(events) == 1

            conn.close()
        finally:
            os.unlink(path)

    def test_sql_injection_filter_values(self):
        """SQL injection payloads as filter values must not break queries or bypass filtering.

        Verifies that:
        - Search filters do not return unrelated records.
        - Rule filters do not bypass filtering.
        - Injection attempts do not modify or delete database tables.
        - Existing sentinel records remain accessible afterward.
        - Database record counts remain unchanged.
        """
        path = _make_temp_db()
        try:
            conn = connect(path)

            injection_payloads = [
                "' OR '1'='1",
                "'; DROP TABLE events; --",
                "' UNION SELECT * FROM detections --",
                "<script>alert('xss')</script>",
                '" OR "1"="1',
            ]

            # Capture baseline counts and records before injection attempts
            baseline_events = count_events(conn)
            baseline_detections = count_detections(conn)
            baseline_alerts = count_alerts(conn)
            baseline_all_events = list_events(conn)
            baseline_all_alerts = list_alerts(conn)

            for payload in injection_payloads:
                # Search filters must not return unrelated records
                events = list_events(conn, search=payload)
                assert isinstance(events, list)
                assert events == [], (
                    f"search={payload!r} returned {len(events)} events (expected 0)"
                )

                alerts = list_alerts(conn, search=payload)
                assert isinstance(alerts, list)
                assert alerts == [], (
                    f"alerts search={payload!r} returned {len(alerts)} alerts (expected 0)"
                )

                # Rule filters must not bypass filtering
                events_by_rule = list_events(conn, rule=payload)
                assert isinstance(events_by_rule, list)
                assert events_by_rule == [], (
                    f"events rule={payload!r} returned {len(events_by_rule)} events (expected 0)"
                )

                # list_alerts with rule filter must not bypass filtering
                alerts_by_rule = list_alerts(conn, rule=payload)
                assert isinstance(alerts_by_rule, list)
                assert alerts_by_rule == [], (
                    f"alerts rule={payload!r} returned {len(alerts_by_rule)} alerts (expected 0)"
                )

            # Database tables must not be modified or deleted
            assert count_events(conn) == baseline_events, (
                "event count changed after injection attempts"
            )
            assert count_detections(conn) == baseline_detections, (
                "detection count changed after injection attempts"
            )
            assert count_alerts(conn) == baseline_alerts, (
                "alert count changed after injection attempts"
            )

            # Existing sentinel records remain accessible
            assert list_events(conn) == baseline_all_events
            assert list_alerts(conn) == baseline_all_alerts
            assert list_detection_rules(conn) is not None

            conn.close()
        finally:
            os.unlink(path)

    def test_list_detection_rules(self):
        path = _make_temp_db()
        try:
            conn = connect(path)
            rules = list_detection_rules(conn)
            assert len(rules) == 2
            rule_ids = {r["rule_id"] for r in rules}
            assert rule_ids == {"FailedLoginBurstRule", "SuspiciousProcessRule"}
            for r in rules:
                assert "detection_count" in r
                assert "host_count" in r
                assert "last_seen" in r
            conn.close()
        finally:
            os.unlink(path)

    def test_list_alerts(self):
        path = _make_temp_db()
        try:
            conn = connect(path)
            alerts = list_alerts(conn)
            assert len(alerts) == 2
            for a in alerts:
                assert "rule_id" in a
                assert "detection_count" in a
                assert "first_seen" in a
                assert "last_seen" in a
            conn.close()
        finally:
            os.unlink(path)

    def test_get_event_detail_evidence_relationship(self):
        """Event detail must resolve detections through the evidence table."""
        path = _make_temp_db()
        try:
            conn = connect(path)

            detail = get_event_detail(conn, "evt-001")
            assert detail is not None
            assert detail["event_id"] == "evt-001"
            assert len(detail["detections"]) == 1
            assert detail["detections"][0]["rule_id"] == "FailedLoginBurstRule"

            detail = get_event_detail(conn, "evt-002")
            assert detail is not None
            assert len(detail["detections"]) == 1
            assert detail["detections"][0]["rule_id"] == "SuspiciousProcessRule"

            # Non-existent event
            assert get_event_detail(conn, "nonexistent") is None

            conn.close()
        finally:
            os.unlink(path)

    def test_get_attacks_coverage(self):
        path = _make_temp_db()
        try:
            conn = connect(path)
            coverage = get_attacks_coverage(conn)
            assert len(coverage) == 2
            for c in coverage:
                assert "rule_id" in c
                assert "detection_count" in c
                assert "host_count" in c
            conn.close()
        finally:
            os.unlink(path)

    def test_get_system_diagnostics(self):
        path = _make_temp_db()
        try:
            conn = connect(path)
            diag = get_system_diagnostics(conn)
            assert diag["total_events"] == 2
            assert diag["total_detections"] == 2
            assert "events" in diag["tables"]
            assert "detections" in diag["tables"]
            assert "evidence" in diag["tables"]
            conn.close()
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# HTML escaping tests
# ---------------------------------------------------------------------------


class testHTMLEscaping:
    def test_e_escape_html(self):
        """_e() must escape HTML special characters."""
        assert _e("<script>alert(1)</script>") == (
            "&lt;script&gt;alert(1)&lt;/script&gt;"
        )
        assert _e('"><img src=x onerror=alert(1)>') == (
            "&quot;&gt;&lt;img src=x onerror=alert(1)&gt;"
        )
        assert _e("normal text") == "normal text"
        assert _e(None) == ""
        assert _e(42) == "42"

    def test_html_module_escape(self):
        """Python's html.escape produces the same result as _e()."""
        payload = "<img src=x onerror=alert(1)>"
        assert _e(payload) == html.escape(payload)


# ---------------------------------------------------------------------------
# Server smoke tests
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="Server smoke test requires Unix-style process management",
)
class TestDashboardServer:
    def test_dashboard_routes_with_canonical_db(self):
        """Start the dashboard on a real canonical database and test all routes."""
        db_path = _make_temp_db()

        # Start server
        proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "sentinelforge.dashboard.server",
                "--host",
                "127.0.0.1",
                "--port",
                "18080",
                "--db-path",
                db_path,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        try:
            # Bounded readiness loop
            import urllib.error
            import urllib.request

            ready = False
            for _ in range(30):
                try:
                    urllib.request.urlopen("http://127.0.0.1:18080/overview", timeout=1)
                    ready = True
                    break
                except OSError:
                    time.sleep(0.5)
            assert ready, "Dashboard did not become ready"

            # Test all routes
            routes = [
                "/",
                "/overview",
                "/alerts",
                "/events",
                "/rules",
                "/attacks",
                "/diagnostics",
                "/event/evt-001",
                "/static/css/dashboard.css",
                "/static/js/dashboard.js",
            ]
            for route in routes:
                resp = urllib.request.urlopen(
                    f"http://127.0.0.1:18080{route}", timeout=5
                )
                assert resp.status == 200, f"Route {route} returned {resp.status}"
                body = resp.read().decode("utf-8")
                assert len(body) > 0, f"Route {route} returned empty body"

            # Test 404 for unknown route
            try:
                urllib.request.urlopen("http://127.0.0.1:18080/nonexistent", timeout=5)
                assert False, "Expected HTTP error for unknown route"
            except urllib.error.HTTPError as exc:
                assert exc.code == 404

        finally:
            proc.terminate()
            proc.wait(timeout=10)
            os.unlink(db_path)
