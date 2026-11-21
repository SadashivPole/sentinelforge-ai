"""Tests for the detection engine foundation and failed login burst rule.

Covers:
1. Normal single failed login (below threshold, no alert)
2. Multiple failures from one source (burst alert)
3. Multiple usernames targeted by one source (per-username grouping)
4. Failures outside the configured time window (no alert)
5. Missing source IP (grouped safely, alert if count reaches threshold)
6. Missing username (grouped safely, alert if count reaches threshold)
7. Duplicate events (deduplicated by event_id)
8. Out-of-order timestamps (sorted before windowing)
9. Invalid timestamps (skipped from windowing)
10. Benign successful authentication (no alert)
"""

from __future__ import annotations

from typing import Optional

from sentinelforge.detection.failed_logins import FailedLoginBurstRule
from sentinelforge.detection.base import Severity
from sentinelforge.ingestion.normalizer import normalize


def _make_auth_event(
    event_id: str,
    timestamp: str,
    username: str = "admin",
    source_address: Optional[str] = "10.0.0.1",
    host: str = "host-1",
    outcome: str = "failure",
):
    """Build a normalized authentication event from a raw-like dict.

    The raw payload is preserved verbatim under ``event.raw``.
    """
    raw = {
        "event_id": event_id,
        "timestamp": timestamp,
        "event_type": "authentication",
        "user": username,
        "host": host,
        "authentication": {
            "outcome": outcome,
            "method": "password",
            "username": username,
            "source_address": source_address,
        },
    }
    return normalize(raw, source="jsonl")


def _make_rule(threshold: int = 5, window_seconds: int = 300) -> FailedLoginBurstRule:
    return FailedLoginBurstRule(threshold=threshold, window_seconds=window_seconds)


def test_single_failed_login_no_alert():
    events = [_make_auth_event("evt-1", "2024-01-01T00:00:00Z")]
    results = _make_rule().evaluate(events)
    assert results == []


def test_multiple_failures_from_one_source_trigger_alert():
    events = [
        _make_auth_event(f"evt-{i}", f"2024-01-01T00:00:{i:02d}Z")
        for i in range(6)
    ]
    results = _make_rule(threshold=5, window_seconds=300).evaluate(events)
    assert len(results) == 1
    result = results[0]
    assert result.rule_id == "sentinelforge.detection.failed_login_burst"
    assert result.severity == Severity.HIGH
    assert len(result.evidence) == 6
    assert result.metadata["count"] == 6
    # Every evidence row cites the original raw log.
    for ev in result.evidence:
        assert ev.raw is not None
        assert ev.event_id in {f"evt-{i}" for i in range(6)}


def test_multiple_usernames_targeted_by_one_source():
    events: list = []
    for username in ("admin", "root", "user"):
        for i in range(6):
            events.append(
                _make_auth_event(
                    f"evt-{username}-{i}",
                    f"2024-01-01T00:00:{i:02d}Z",
                    username=username,
                    source_address="10.0.0.1",
                )
            )
    results = _make_rule(threshold=5, window_seconds=300).evaluate(events)
    # One burst per username (grouped by source_ip + username + host).
    assert len(results) == 3
    for result in results:
        assert len(result.evidence) == 6
        usernames = {ev.user for ev in result.evidence}
        assert len(usernames) == 1  # each burst is single-username


def test_failures_outside_time_window_no_alert():
    # 6 failures spread at 5-minute intervals (0, 300, 600, ... s). Window is
    # 300s, so at most 2 events fall in any window → no alert.
    events = [
        _make_auth_event(f"evt-{i}", f"2024-01-01T00:{i * 5:02d}:00Z")
        for i in range(6)
    ]
    results = _make_rule(threshold=5, window_seconds=300).evaluate(events)
    assert results == []


def test_missing_source_ip_grouped_safely():
    events = [
        _make_auth_event(f"evt-{i}", f"2024-01-01T00:00:{i:02d}Z", source_address=None)
        for i in range(6)
    ]
    results = _make_rule(threshold=5, window_seconds=300).evaluate(events)
    assert len(results) == 1
    assert results[0].metadata["count"] == 6
    # Group key records the missing source address explicitly.
    assert results[0].metadata["group_key"]["source_address"] is None


def test_missing_username_grouped_safely():
    events = [
        _make_auth_event(f"evt-{i}", f"2024-01-01T00:00:{i:02d}Z", username=None)
        for i in range(6)
    ]
    results = _make_rule(threshold=5, window_seconds=300).evaluate(events)
    assert len(results) == 1
    assert results[0].metadata["count"] == 6
    assert results[0].metadata["group_key"]["username"] is None


def test_duplicate_events_deduplicated():
    # Same event_id repeated 6 times → counts as one unique failure.
    base = _make_auth_event("evt-dup", "2024-01-01T00:00:00Z")
    events = [base for _ in range(6)]
    results = _make_rule(threshold=5, window_seconds=300).evaluate(events)
    assert results == []


def test_out_of_order_timestamps_still_trigger():
    # 6 failures within 300s but delivered out of order.
    timestamps = [
        "2024-01-01T00:00:10Z",
        "2024-01-01T00:00:00Z",
        "2024-01-01T00:00:20Z",
        "2024-01-01T00:00:05Z",
        "2024-01-01T00:00:25Z",
        "2024-01-01T00:00:15Z",
    ]
    events = [
        _make_auth_event(f"evt-{i}", ts) for i, ts in enumerate(timestamps)
    ]
    results = _make_rule(threshold=5, window_seconds=300).evaluate(events)
    assert len(results) == 1
    assert results[0].metadata["count"] == 6


def test_invalid_timestamps_skipped_no_false_alert():
    # 6 events with unparseable timestamps → none can be placed in a window.
    events = [
        _make_auth_event(f"evt-{i}", "not-a-timestamp") for i in range(6)
    ]
    results = _make_rule(threshold=5, window_seconds=300).evaluate(events)
    assert results == []


def test_benign_successful_authentication_no_alert():
    events = [
        _make_auth_event(f"evt-{i}", f"2024-01-01T00:00:{i:02d}Z", outcome="success")
        for i in range(6)
    ]
    results = _make_rule(threshold=5, window_seconds=300).evaluate(events)
    assert results == []
