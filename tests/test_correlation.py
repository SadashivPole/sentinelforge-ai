"""Tests for the multi-key detection correlator.

Covers deterministic incident IDs, single-key and multi-key grouping,
time-window splitting, and rationale generation. The existing host-scoped
``DetectionCorrelator`` is unchanged and covered elsewhere.
"""

from __future__ import annotations

from datetime import datetime

from sentinelforge.detection.base import DetectionResult, Evidence, Severity
from sentinelforge.risk.correlator import (
    CorrelationGroup,
    _incident_id,
    correlate_multi_key,
)


def _dt(iso: str) -> datetime:
    return datetime.fromisoformat(iso)


def _result(
    detection_id: str,
    rule_id: str,
    triggered_at: str,
    host: str | None = None,
    user: str | None = None,
    source_address: str | None = None,
    technique: str | None = None,
    severity: Severity = Severity.HIGH,
) -> DetectionResult:
    metadata: dict[str, object] = {}
    if host:
        metadata["host"] = host
    if user:
        metadata["user"] = user
    if source_address:
        metadata["source_address"] = source_address
    if technique:
        metadata["attack_technique"] = technique
    evidence = None
    if source_address:
        evidence = [
            Evidence(
                event_id=f"evt-{detection_id}",
                timestamp=triggered_at,
                source="test",
                event_type="authentication",
                user=user,
                host=host,
                source_address=source_address,
                raw={},
            )
        ]
    return DetectionResult(
        detection_id=detection_id,
        rule_id=rule_id,
        rule_name="test-rule",
        severity=severity,
        description="test detection",
        triggered_at=triggered_at,
        metadata=metadata,
        evidence=evidence or [],
    )


def test_incident_id_is_deterministic() -> None:
    ids = ["det-2", "det-1", "det-3"]
    first = _incident_id(ids)
    second = _incident_id(["det-3", "det-1", "det-2"])
    assert first == second
    assert first.startswith("incident-")
    assert len(first) == len("incident-") + 16


def test_incident_id_differs_for_different_sets() -> None:
    assert _incident_id(["det-1"]) != _incident_id(["det-1", "det-2"])


def test_single_key_host_grouping() -> None:
    base = "2024-01-15T08:00:00+00:00"
    results = [
        _result("d1", "rule-a", base, host="HOST-1"),
        _result("d2", "rule-b", "2024-01-15T08:05:00+00:00", host="HOST-1"),
        _result("d3", "rule-a", base, host="HOST-2"),
    ]
    groups = correlate_multi_key(results, keys=("host",), window_seconds=3600)
    host1 = [g for g in groups if g.key_value == "HOST-1"]
    host2 = [g for g in groups if g.key_value == "HOST-2"]
    assert len(host1) == 1
    assert len(host2) == 1
    assert set(host1[0].detection_ids) == {"d1", "d2"}
    assert set(host2[0].detection_ids) == {"d3"}
    assert host1[0].key_type == "host"
    assert "share host=HOST-1" in host1[0].rationale


def test_multi_key_grouping() -> None:
    base = "2024-01-15T08:00:00+00:00"
    results = [
        _result(
            "d1",
            "rule-a",
            base,
            host="HOST-1",
            user="alice",
            source_address="10.0.0.5",
        ),
        _result(
            "d2",
            "rule-b",
            "2024-01-15T08:05:00+00:00",
            host="HOST-1",
            user="alice",
            source_address="10.0.0.5",
        ),
    ]
    groups = correlate_multi_key(
        results, keys=("host", "user", "source_address"), window_seconds=3600
    )
    by_key = {g.key_type: g for g in groups}
    assert set(by_key["host"].detection_ids) == {"d1", "d2"}
    assert set(by_key["user"].detection_ids) == {"d1", "d2"}
    assert set(by_key["source_address"].detection_ids) == {"d1", "d2"}


def test_time_window_splits_groups() -> None:
    results = [
        _result("d1", "rule-a", "2024-01-15T08:00:00+00:00", host="HOST-1"),
        _result(
            "d2",
            "rule-a",
            "2024-01-15T08:50:00+00:00",
            host="HOST-1",
        ),  # 50 min later -> outside 30 min window
        _result(
            "d3",
            "rule-a",
            "2024-01-15T09:10:00+00:00",
            host="HOST-1",
        ),  # 20 min after d2 -> same cluster as d2
    ]
    groups = correlate_multi_key(results, keys=("host",), window_seconds=1800)
    host_groups = [g for g in groups if g.key_value == "HOST-1"]
    assert len(host_groups) == 2
    sizes = sorted(len(g.detection_ids) for g in host_groups)
    assert sizes == [1, 2]


def test_unrelated_hosts_never_mixed() -> None:
    results = [
        _result("d1", "rule-a", "2024-01-15T08:00:00+00:00", host="HOST-1"),
        _result("d2", "rule-a", "2024-01-15T08:01:00+00:00", host="HOST-2"),
    ]
    groups = correlate_multi_key(results, keys=("host",), window_seconds=3600)
    assert len(groups) == 2
    for g in groups:
        assert len(g.detection_ids) == 1


def test_group_has_deterministic_id_from_detection_ids() -> None:
    base = "2024-01-15T08:00:00+00:00"
    results = [
        _result("d2", "rule-a", base, host="HOST-1"),
        _result("d1", "rule-b", base, host="HOST-1"),
    ]
    groups = correlate_multi_key(results, keys=("host",), window_seconds=3600)
    assert len(groups) == 1
    assert groups[0].group_id == _incident_id(["d1", "d2"])
    assert set(groups[0].detection_ids) == {"d1", "d2"}


def test_empty_input_returns_no_groups() -> None:
    assert correlate_multi_key([], keys=("host",)) == []


def test_correlation_group_fields() -> None:
    base = "2024-01-15T08:00:00+00:00"
    results = [
        _result("d1", "rule-a", base, host="HOST-1", technique="T1110.001"),
    ]
    groups = correlate_multi_key(
        results, keys=("host", "attack_technique"), window_seconds=3600
    )
    assert len(groups) == 2
    host_g = next(g for g in groups if g.key_type == "host")
    tech_g = next(g for g in groups if g.key_type == "attack_technique")
    assert isinstance(host_g, CorrelationGroup)
    assert host_g.rule_ids == {"rule-a"}
    assert host_g.severities == [Severity.HIGH]
    assert tech_g.key_value == "T1110.001"
    assert (
        tech_g.rationale
        == "1 detection(s) share attack_technique=T1110.001 within the correlation window"
    )
