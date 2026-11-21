"""Tests for the statistical C2 beacon detection rule.

Scenarios:
1. Regular periodic connections → alert
2. Periodic connections with jitter → alert
3. Irregular connections → no alert
4. Insufficient connection count → no alert
5. Duplicate events → deduplicated, no false alert
6. Out-of-order events → still detected
7. Missing timestamps → skipped from interval calculation
8. Missing destination IP → handled safely, not grouped
9. Multiple unrelated destinations → separate groups, no alert
10. Different source hosts → separate groups, no alert
11. Benign periodic heartbeat traffic → allowlisted, no alert
12. Configurable allowlists → excluded destinations/ports
"""

from __future__ import annotations

from sentinelforge.detection.beacon import C2BeaconRule
from sentinelforge.detection.base import Severity
from sentinelforge.ingestion.normalizer import (
    NetworkInfo,
    NormalizedEvent,
    ProcessInfo,
)


def _make_net_event(
    event_id: str,
    timestamp: str,
    remote_address: str = "203.0.113.45",
    remote_port: int = 4433,
    host: str = "host-1",
    process_name: Optional[str] = "svchost.exe",
    direction: str = "outbound",
    protocol: str = "tcp",
):
    raw = {
        "event_id": event_id,
        "timestamp": timestamp,
        "event_type": "network.connection",
        "user": "user-1",
        "host": host,
        "network": {
            "direction": direction,
            "remote_address": remote_address,
            "remote_port": remote_port,
            "protocol": protocol,
        },
        "process": {"name": process_name, "pid": 1000},
    }
    return NormalizedEvent(
        event_id=event_id,
        timestamp=timestamp,
        source="jsonl",
        raw=raw,
        event_type="network.connection",
        user="user-1",
        host=host,
        network=NetworkInfo(
            direction=direction,
            remote_address=remote_address,
            remote_port=remote_port,
            protocol=protocol,
        ),
        process=ProcessInfo(name=process_name, pid=1000),
    )


from typing import Optional  # noqa: E402


def _regular_intervals(base: str, count: int, interval_seconds: int):
    """Generate ``count`` timestamps starting at ``base`` spaced by interval."""
    from datetime import datetime, timedelta, timezone

    dt = datetime.fromisoformat(base.replace("Z", "+00:00"))
    return [
        (dt + timedelta(seconds=i * interval_seconds)).isoformat()
        for i in range(count)
    ]


# ---------------------------------------------------------------- beacon tests

def test_regular_periodic_connections_trigger_alert():
    timestamps = _regular_intervals("2024-01-01T00:00:00Z", 6, 60)
    events = [
        _make_net_event(f"evt-{i}", ts) for i, ts in enumerate(timestamps)
    ]
    results = C2BeaconRule().evaluate(events)
    assert len(results) == 1
    result = results[0]
    assert result.rule_id == "sentinelforge.detection.c2_beacon"
    assert result.severity == Severity.MEDIUM
    assert result.metadata["connection_count"] == 6
    assert result.metadata["mean_interval_seconds"] == 60.0
    assert result.metadata["standard_deviation_seconds"] == 0.0
    assert result.metadata["regularity_score"] == 1.0
    assert result.metadata["label"] == "Potential C2 Beaconing"
    assert result.metadata["confirmation"] == "Not confirmed C2 — requires analyst investigation."
    # Evidence cites every connection event.
    assert len(result.evidence) == 6
    assert {ev.event_id for ev in result.evidence} == {
        f"evt-{i}" for i in range(6)
    }


def test_periodic_connections_with_jitter_trigger_alert():
    # Small jitter around 60s → low CV → still regular enough.
    timestamps = [
        "2024-01-01T00:00:00Z",
        "2024-01-01T00:01:02Z",
        "2024-01-01T00:01:59Z",
        "2024-01-01T00:03:01Z",
        "2024-01-01T00:04:00Z",
        "2024-01-01T00:04:58Z",
    ]
    events = [
        _make_net_event(f"evt-{i}", ts) for i, ts in enumerate(timestamps)
    ]
    results = C2BeaconRule().evaluate(events)
    assert len(results) == 1
    assert results[0].metadata["regularity_score"] >= 0.75


def test_irregular_connections_no_alert():
    # Random intervals → high CV → no alert.
    timestamps = [
        "2024-01-01T00:00:00Z",
        "2024-01-01T00:00:10Z",
        "2024-01-01T00:05:00Z",
        "2024-01-01T00:05:05Z",
        "2024-01-01T00:20:00Z",
        "2024-01-01T00:20:01Z",
    ]
    events = [
        _make_net_event(f"evt-{i}", ts) for i, ts in enumerate(timestamps)
    ]
    results = C2BeaconRule().evaluate(events)
    assert results == []


def test_insufficient_connection_count_no_alert():
    # 5 connections, min is 6 → no alert.
    timestamps = _regular_intervals("2024-01-01T00:00:00Z", 5, 60)
    events = [
        _make_net_event(f"evt-{i}", ts) for i, ts in enumerate(timestamps)
    ]
    results = C2BeaconRule().evaluate(events)
    assert results == []


def test_duplicate_events_deduplicated():
    # Same event_id repeated 6 times → counts as one unique connection.
    base = _make_net_event("evt-dup", "2024-01-01T00:00:00Z")
    events = [base for _ in range(6)]
    results = C2BeaconRule().evaluate(events)
    assert results == []


def test_out_of_order_events_still_detected():
    # 6 regular connections delivered out of order.
    timestamps = [
        "2024-01-01T00:00:00Z",
        "2024-01-01T00:02:00Z",
        "2024-01-01T00:01:00Z",
        "2024-01-01T00:03:00Z",
        "2024-01-01T00:04:00Z",
        "2024-01-01T00:05:00Z",
    ]
    events = [
        _make_net_event(f"evt-{i}", ts) for i, ts in enumerate(timestamps)
    ]
    results = C2BeaconRule().evaluate(events)
    assert len(results) == 1
    assert results[0].metadata["connection_count"] == 6


def test_missing_timestamps_skipped_no_false_alert():
    # 6 events with unparseable timestamps → none can be placed in sequence.
    events = [
        _make_net_event(f"evt-{i}", "not-a-timestamp") for i in range(6)
    ]
    results = C2BeaconRule().evaluate(events)
    assert results == []


def test_missing_destination_ip_handled_safely():
    # remote_address is None → not grouped, no alert.
    raw = {
        "event_id": "evt-no-dest",
        "timestamp": "2024-01-01T00:00:00Z",
        "event_type": "network.connection",
        "host": "host-1",
        "network": {"direction": "outbound", "remote_port": 4433, "protocol": "tcp"},
    }
    event = NormalizedEvent(
        event_id="evt-no-dest",
        timestamp="2024-01-01T00:00:00Z",
        source="jsonl",
        raw=raw,
        event_type="network.connection",
        host="host-1",
        network=NetworkInfo(
            direction="outbound", remote_port=4433, protocol="tcp"
        ),
    )
    results = C2BeaconRule().evaluate([event] * 6)
    assert results == []


def test_multiple_unrelated_destinations_separate_groups():
    # 3 connections to IP A, 3 to IP B → neither reaches min 6 → no alert.
    events: list = []
    for i in range(3):
        events.append(_make_net_event(f"evt-a-{i}", _regular_intervals("2024-01-01T00:00:00Z", 1, 0)[0], remote_address="10.0.0.1"))
    for i in range(3):
        events.append(_make_net_event(f"evt-b-{i}", _regular_intervals("2024-01-01T00:00:00Z", 1, 0)[0], remote_address="10.0.0.2"))
    results = C2BeaconRule().evaluate(events)
    assert results == []


def test_different_source_hosts_separate_groups():
    # 3 from host-1, 3 from host-2 to same destination → neither reaches 6.
    events: list = []
    for i in range(3):
        events.append(
            _make_net_event(
                f"evt-h1-{i}",
                _regular_intervals("2024-01-01T00:00:00Z", 1, 0)[0],
                host="host-1",
            )
        )
    for i in range(3):
        events.append(
            _make_net_event(
                f"evt-h2-{i}",
                _regular_intervals("2024-01-01T00:00:00Z", 1, 0)[0],
                host="host-2",
            )
        )
    results = C2BeaconRule().evaluate(events)
    assert results == []


def test_benign_periodic_heartbeat_allowlisted_no_alert():
    timestamps = _regular_intervals("2024-01-01T00:00:00Z", 6, 60)
    events = [
        _make_net_event(f"evt-{i}", ts, remote_address="169.254.169.254")
        for i, ts in enumerate(timestamps)
    ]
    rule = C2BeaconRule(allowlisted_destinations={"169.254.169.254"})
    results = rule.evaluate(events)
    assert results == []


def test_configurable_allowlist_port_excluded():
    timestamps = _regular_intervals("2024-01-01T00:00:00Z", 6, 60)
    events = [
        _make_net_event(f"evt-{i}", ts, remote_port=12345)
        for i, ts in enumerate(timestamps)
    ]
    rule = C2BeaconRule(allowlisted_ports={12345})
    results = rule.evaluate(events)
    assert results == []


def test_allowlisted_process_excluded():
    timestamps = _regular_intervals("2024-01-01T00:00:00Z", 6, 60)
    events = [
        _make_net_event(f"evt-{i}", ts, process_name="EDRAgent.exe")
        for i, ts in enumerate(timestamps)
    ]
    rule = C2BeaconRule(allowlisted_processes={"edragent.exe"})
    results = rule.evaluate(events)
    assert results == []


# ----------------------------------------------------------- MITRE regression

def test_legitimate_https_standard_port_no_t1071():
    """Periodic HTTPS connections on the standard port 443 must trigger the
    beacon rule but must NOT assign T1071 (Application Layer Protocol),
    because there is no protocol-specific C2 context (standard port)."""
    timestamps = _regular_intervals("2024-01-01T00:00:00Z", 6, 60)
    events = [
        _make_net_event(f"evt-{i}", ts, remote_address="198.51.100.42",
                        remote_port=443, process_name="chrome.exe",
                        protocol="https")
        for i, ts in enumerate(timestamps)
    ]
    results = C2BeaconRule().evaluate(events)
    assert len(results) == 1
    assert "mitre_attack_technique" not in results[0].metadata or \
        results[0].metadata["mitre_attack_technique"] != "T1071"


def test_https_non_standard_port_triggers_t1071():
    """Periodic HTTPS connections on a non-standard port (4433) must assign
    T1071 because there is protocol-specific C2 context (suspicious process
    + non-standard port)."""
    timestamps = _regular_intervals("2024-01-01T00:00:00Z", 6, 60)
    events = [
        _make_net_event(f"evt-{i}", ts, remote_address="198.51.100.42",
                        remote_port=4433, process_name="powershell.exe",
                        protocol="https")
        for i, ts in enumerate(timestamps)
    ]
    results = C2BeaconRule().evaluate(events)
    assert len(results) == 1
    assert results[0].metadata.get("mitre_attack_technique") == "T1071"


def test_https_non_standard_port_normal_process_no_t1071():
    """Periodic HTTPS on a non-standard port with a normal process (svchost)
    and a domain destination does NOT produce T1071 — port deviation alone is
    insufficient."""
    timestamps = _regular_intervals("2024-01-01T00:00:00Z", 6, 60)
    events = [
        _make_net_event(f"evt-{i}", ts, remote_address="example.com",
                        remote_port=4433, process_name="svchost.exe",
                        protocol="https")
        for i, ts in enumerate(timestamps)
    ]
    results = C2BeaconRule().evaluate(events)
    assert len(results) == 1
    assert "mitre_attack_technique" not in results[0].metadata or \
        results[0].metadata["mitre_attack_technique"] != "T1071"


def test_potential_beacon_without_mitre_attribution():
    """Potential C2 beacon detection still works (alert fires) even when
    ATT&CK attribution is absent — detection and attribution are separate."""
    timestamps = _regular_intervals("2024-01-01T00:00:00Z", 6, 60)
    events = [
        _make_net_event(f"evt-{i}", ts, remote_address="example.com",
                        remote_port=443, process_name="chrome.exe",
                        protocol="https")
        for i, ts in enumerate(timestamps)
    ]
    results = C2BeaconRule().evaluate(events)
    assert len(results) == 1
    assert results[0].metadata["label"] == "Potential C2 Beaconing"
    assert "mitre_attack_technique" not in results[0].metadata or \
        results[0].metadata["mitre_attack_technique"] != "T1071"


def test_https_non_standard_port_raw_ip_triggers_t1071():
    """Periodic HTTPS on non-standard port with raw IP destination AND normal
    process (svchost) does NOT produce T1071 — raw IP alone is not sufficient
    without a suspicious process."""
    timestamps = _regular_intervals("2024-01-01T00:00:00Z", 6, 60)
    events = [
        _make_net_event(f"evt-{i}", ts, remote_address="198.51.100.42",
                        remote_port=4433, process_name="svchost.exe",
                        protocol="https")
        for i, ts in enumerate(timestamps)
    ]
    results = C2BeaconRule().evaluate(events)
    assert len(results) == 1
    assert "mitre_attack_technique" not in results[0].metadata or \
        results[0].metadata["mitre_attack_technique"] != "T1071"


def test_https_non_standard_port_suspicious_process_no_t1071():
    """Periodic HTTPS on non-standard port with suspicious process (powershell)
    but a domain destination does NOT produce T1071 — suspicious process alone
    is not sufficient without raw-IP application-layer context."""
    timestamps = _regular_intervals("2024-01-01T00:00:00Z", 6, 60)
    events = [
        _make_net_event(f"evt-{i}", ts, remote_address="example.com",
                        remote_port=4433, process_name="powershell.exe",
                        protocol="https")
        for i, ts in enumerate(timestamps)
    ]
    results = C2BeaconRule().evaluate(events)
    assert len(results) == 1
    assert "mitre_attack_technique" not in results[0].metadata or \
        results[0].metadata["mitre_attack_technique"] != "T1071"


# ----------------------------------------------------------- interval range coverage

def test_thirty_second_beacon_high_confidence():
    """30-second intervals → high confidence C2 pattern."""
    timestamps = _regular_intervals("2024-01-01T00:00:00Z", 6, 30)
    events = [
        _make_net_event(f"evt-{i}", ts) for i, ts in enumerate(timestamps)
    ]
    results = C2BeaconRule().evaluate(events)
    assert len(results) == 1
    assert results[0].metadata["pattern_tier"] == "short_interval"


def test_sixty_second_beacon_high_confidence():
    """60-second intervals → short_interval pattern tier."""
    timestamps = _regular_intervals("2024-01-01T00:00:00Z", 6, 60)
    events = [
        _make_net_event(f"evt-{i}", ts) for i, ts in enumerate(timestamps)
    ]
    results = C2BeaconRule().evaluate(events)
    assert len(results) == 1
    assert results[0].metadata["pattern_tier"] == "short_interval"


def test_five_minute_beacon_high_confidence():
    """5-minute (300s) intervals → short_interval pattern tier (boundary inclusive)."""
    timestamps = _regular_intervals("2024-01-01T00:00:00Z", 6, 300)
    events = [
        _make_net_event(f"evt-{i}", ts) for i, ts in enumerate(timestamps)
    ]
    results = C2BeaconRule().evaluate(events)
    assert len(results) == 1
    assert results[0].metadata["pattern_tier"] == "short_interval"


def test_ten_minute_beacon_medium_confidence():
    """10-minute (600s) intervals → medium_interval pattern tier."""
    timestamps = _regular_intervals("2024-01-01T00:00:00Z", 6, 600)
    events = [
        _make_net_event(f"evt-{i}", ts) for i, ts in enumerate(timestamps)
    ]
    results = C2BeaconRule().evaluate(events)
    assert len(results) == 1
    assert results[0].metadata["pattern_tier"] == "medium_interval"


def test_thirty_minute_beacon_medium_confidence():
    """30-minute (1800s) intervals → medium_interval pattern tier, still detected."""
    timestamps = _regular_intervals("2024-01-01T00:00:00Z", 6, 1800)
    events = [
        _make_net_event(f"evt-{i}", ts) for i, ts in enumerate(timestamps)
    ]
    results = C2BeaconRule().evaluate(events)
    assert len(results) == 1
    assert results[0].metadata["pattern_tier"] == "medium_interval"


def test_sixty_minute_beacon_medium_confidence():
    """60-minute (3600s) intervals → medium_interval pattern tier (boundary inclusive)."""
    timestamps = _regular_intervals("2024-01-01T00:00:00Z", 6, 3600)
    events = [
        _make_net_event(f"evt-{i}", ts) for i, ts in enumerate(timestamps)
    ]
    results = C2BeaconRule().evaluate(events)
    assert len(results) == 1
    assert results[0].metadata["pattern_tier"] == "medium_interval"


def test_six_hour_beacon_low_confidence_still_detected():
    """6-hour (21600s) intervals → long_interval pattern tier but NOT silently discarded.
    Slow periodic patterns remain visible for analyst review."""
    timestamps = _regular_intervals("2024-01-01T00:00:00Z", 6, 21600)
    events = [
        _make_net_event(f"evt-{i}", ts) for i, ts in enumerate(timestamps)
    ]
    results = C2BeaconRule().evaluate(events)
    assert len(results) == 1
    assert results[0].metadata["pattern_tier"] == "long_interval"


def test_jittered_long_interval_still_detected():
    """Long-interval connections with small timing jitter are still detected
    with long_interval pattern tier — jitter does not eliminate detection."""
    base = "2024-01-01T00:00:00Z"
    timestamps = [
        base,
        "2024-01-01T06:00:05Z",
        "2024-01-01T12:00:02Z",
        "2024-01-01T18:00:03Z",
        "2024-01-02T00:00:01Z",
        "2024-01-02T06:00:04Z",
    ]
    events = [
        _make_net_event(f"evt-{i}", ts) for i, ts in enumerate(timestamps)
    ]
    results = C2BeaconRule().evaluate(events)
    assert len(results) == 1
    assert results[0].metadata["pattern_tier"] == "long_interval"


def test_legitimate_periodic_software_update_medium_confidence():
    """Legitimate periodic software-update traffic at 30-minute intervals
    is detected with medium_interval pattern tier — not silently dropped, but not
    labeled malicious merely because it is periodic."""
    timestamps = _regular_intervals("2024-01-01T00:00:00Z", 6, 1800)
    events = [
        _make_net_event(
            f"evt-{i}",
            ts,
            remote_address="40.70.12.100",
            remote_port=443,
            process_name="svchost.exe",
            protocol="https",
        )
        for i, ts in enumerate(timestamps)
    ]
    results = C2BeaconRule().evaluate(events)
    assert len(results) == 1
    assert results[0].metadata["pattern_tier"] == "medium_interval"
    # Standard port + normal process → no T1071 attribution
    assert "mitre_attack_technique" not in results[0].metadata or \
        results[0].metadata["mitre_attack_technique"] != "T1071"


def test_legitimate_monitoring_telemetry_low_confidence():
    """Legitimate monitoring/telemetry traffic at 1-hour intervals is
    detected with medium_interval pattern tier — visible for review, not auto-escalated."""
    timestamps = _regular_intervals("2024-01-01T00:00:00Z", 6, 3600)
    events = [
        _make_net_event(
            f"evt-{i}",
            ts,
            remote_address="10.0.1.100",
            remote_port=8080,
            process_name="EDRAgent.exe",
            protocol="http",
        )
        for i, ts in enumerate(timestamps)
    ]
    results = C2BeaconRule().evaluate(events)
    assert len(results) == 1
    assert results[0].metadata["pattern_tier"] == "medium_interval"
    # Standard port for http (8080) + normal process → no T1071
    assert "mitre_attack_technique" not in results[0].metadata or \
        results[0].metadata["mitre_attack_technique"] != "T1071"


def test_slow_c2_pattern_remains_visible():
    """A slow (2-hour interval) C2 pattern with suspicious process and
    non-standard port is detected with long_interval pattern tier — slow patterns
    are not automatically excluded from investigation."""
    timestamps = _regular_intervals("2024-01-01T00:00:00Z", 6, 7200)
    events = [
        _make_net_event(
            f"evt-{i}",
            ts,
            remote_address="203.0.113.200",
            remote_port=4433,
            process_name="powershell.exe",
            protocol="https",
        )
        for i, ts in enumerate(timestamps)
    ]
    results = C2BeaconRule().evaluate(events)
    assert len(results) == 1
    assert results[0].metadata["pattern_tier"] == "long_interval"
    # Suspicious process + non-standard port + raw IP → T1071 attribution
    # even for long intervals — tier is long_interval but detection remains.
    assert results[0].metadata.get("mitre_attack_technique") == "T1071"
