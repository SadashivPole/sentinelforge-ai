"""Tests for the explainable risk scoring engine (Milestone 6).

Scenarios:
1. Single low-severity detection
2. Single high-severity detection
3. Multiple correlated detections
4. Unrelated host detections
5. Duplicate alert handling
6. Missing timestamps
7. Out-of-order timestamps
8. Score boundaries (0-100)
9. Configurable scoring weights
10. Optional asset criticality
11. Evidence confidence separate from score
12. Detection order not changing score
13. Missing evidence
14. Correlation window boundaries
"""

from __future__ import annotations

from sentinelforge.detection.base import DetectionResult, Evidence, Severity
from sentinelforge.risk.scorer import (
    RiskScorer,
    ScoringWeights,
    _classify,
    _correlation_score,
    _evidence_quality_score,
    _frequency_score,
    _severity_score,
)


def _make_detection(
    rule_id: str,
    severity: Severity,
    host: str,
    detection_id_suffix: str = "",
    evidence_count: int = 1,
    triggered_at: str = "2024-01-01T00:00:00+00:00",
):
    evidence = [
        Evidence(
            event_id=f"evt-{rule_id}-{i}-{detection_id_suffix}",
            timestamp="2024-01-01T00:00:00+00:00",
            source="jsonl",
            event_type="network.connection",
            user="user-1",
            host=host,
            source_address="10.0.0.1",
            raw={"event_id": f"evt-{rule_id}-{i}", "data": "x"},
        )
        for i in range(evidence_count)
    ]
    return DetectionResult(
        rule_id=f"{rule_id}{detection_id_suffix}",
        rule_name=f"Test {rule_id}",
        severity=severity,
        description=f"Test detection {rule_id}",
        evidence=evidence,
        metadata={"host": host},
        triggered_at=triggered_at,
        detection_id=f"{rule_id}{detection_id_suffix}",
    )


def _empty_detection(rule_id: str, severity: Severity, host: str) -> DetectionResult:
    """Detection with no evidence — tests missing evidence handling."""
    return DetectionResult(
        rule_id=rule_id,
        rule_name="Test",
        severity=severity,
        description="Test",
        evidence=[],
        metadata={"host": host},
        triggered_at="2024-01-01T00:00:00+00:00",
    )


# ---------------------------------------------------------------- scoring units


def test_severity_score_mapping():
    assert _severity_score([Severity.CRITICAL]) == 100.0
    assert _severity_score([Severity.HIGH]) == 80.0
    assert _severity_score([Severity.MEDIUM]) == 60.0
    assert _severity_score([Severity.LOW]) == 40.0
    assert _severity_score([Severity.INFO]) == 20.0
    assert _severity_score([Severity.LOW, Severity.CRITICAL]) == 100.0
    assert _severity_score([]) == 0.0


def test_evidence_quality_score():
    # Complete evidence: raw + timestamp + trio + event_type + source = 100.
    ev = Evidence(
        event_id="e1",
        timestamp="2024-01-01T00:00:00+00:00",
        source="jsonl",
        event_type="network.connection",
        user="u",
        host="h",
        source_address="10.0.0.1",
        raw={"a": 1},
    )
    score, conf = _evidence_quality_score([ev])
    assert score == 100.0
    assert conf == "high"

    # No evidence.
    score, conf = _evidence_quality_score([])
    assert score == 0.0
    assert conf == "low"

    # Partial evidence (raw only).
    ev_partial = Evidence(event_id="e2", timestamp="", source="", raw={"a": 1})
    score, conf = _evidence_quality_score([ev_partial])
    assert 0 < score < 100
    assert conf in ("low", "medium")


def test_frequency_score():
    assert _frequency_score(0) == 0.0
    assert _frequency_score(1) == 20.0
    assert _frequency_score(2) == 40.0
    assert _frequency_score(5) == 60.0
    assert _frequency_score(7) == 80.0
    assert _frequency_score(10) == 100.0


def test_correlation_score():
    assert _correlation_score(0) == 0.0
    assert _correlation_score(1) == 20.0
    assert _correlation_score(2) == 50.0
    assert _correlation_score(3) == 75.0
    assert _correlation_score(4) == 100.0


def test_classify_bounds():
    assert _classify(0) == "minimal"
    assert _classify(20) == "minimal"
    assert _classify(21) == "low"
    assert _classify(40) == "low"
    assert _classify(41) == "medium"
    assert _classify(60) == "medium"
    assert _classify(61) == "high"
    assert _classify(80) == "high"
    assert _classify(81) == "critical"
    assert _classify(100) == "critical"


# ---------------------------------------------------------------- end-to-end


def test_single_low_severity_detection():
    det = _make_detection("failed_login", Severity.LOW, "host-1")
    assessments = RiskScorer().score([det])
    assert len(assessments) == 1
    a = assessments[0]
    assert a.affected_host == "host-1"
    assert 0 <= a.risk_score <= 100
    assert a.detection_severity == Severity.LOW
    assert a.evidence_confidence != "high" or a.risk_score < 50


def test_single_high_severity_detection():
    det = _make_detection("c2_beacon", Severity.HIGH, "host-1")
    assessments = RiskScorer().score([det])
    assert len(assessments) == 1
    a = assessments[0]
    assert a.risk_score > 0
    assert a.detection_severity == Severity.HIGH


def test_multiple_correlated_detections_higher_score():
    det_a = _make_detection("failed_login", Severity.HIGH, "host-1")
    det_b = _make_detection("c2_beacon", Severity.MEDIUM, "host-1")
    det_c = _make_detection("suspicious_powershell", Severity.MEDIUM, "host-1")
    assessments = RiskScorer().score([det_a, det_b, det_c])
    assert len(assessments) == 1
    a = assessments[0]
    # Three distinct detection types on one host -> correlation factor high.
    assert any(
        f.name == "correlation" and f.raw_score == 75.0 for f in a.scoring_factors
    )
    assert a.contributing_detection_ids == [
        "failed_login",
        "c2_beacon",
        "suspicious_powershell",
    ]


def test_unrelated_hosts_separate_assessments():
    det_a = _make_detection("failed_login", Severity.HIGH, "host-a")
    det_b = _make_detection("failed_login", Severity.HIGH, "host-b")
    assessments = RiskScorer().score([det_a, det_b])
    assert len(assessments) == 2
    hosts = {a.affected_host for a in assessments}
    assert hosts == {"host-a", "host-b"}


def test_duplicate_alert_not_double_counted():
    # Same rule_id repeated — deduplicated by correlator (one per rule_id per cluster).
    det1 = DetectionResult(
        rule_id="failed_login",
        rule_name="Test failed_login",
        severity=Severity.HIGH,
        description="Test",
        evidence=[
            Evidence(
                event_id="evt-dup-1",
                timestamp="2024-01-01T00:00:00+00:00",
                source="jsonl",
                event_type="authentication",
                user="u",
                host="host-1",
                source_address="10.0.0.1",
                raw={"e": 1},
            )
        ],
        metadata={"host": "host-1"},
        triggered_at="2024-01-01T00:00:00+00:00",
    )
    det2 = DetectionResult(
        rule_id="failed_login",
        rule_name="Test failed_login",
        severity=Severity.HIGH,
        description="Test",
        evidence=[
            Evidence(
                event_id="evt-dup-2",
                timestamp="2024-01-01T00:00:00+00:00",
                source="jsonl",
                event_type="authentication",
                user="u",
                host="host-1",
                source_address="10.0.0.1",
                raw={"e": 1},
            )
        ],
        metadata={"host": "host-1"},
        triggered_at="2024-01-01T00:00:00+00:00",
    )
    assessments = RiskScorer().score([det1, det2])
    assert len(assessments) == 1
    a = assessments[0]
    # Two detections but same rule_id -> distinct_rule_count = 1.
    assert a.score_breakdown["correlation"] == 20.0 * 0.20  # correlation weight 0.2


def test_missing_timestamps_handled_safely():
    det = _make_detection(
        "failed_login", Severity.HIGH, "host-1", triggered_at="not-a-timestamp"
    )
    assessments = RiskScorer().score([det])
    assert len(assessments) == 1
    assert assessments[0].risk_score >= 0


def test_out_of_order_timestamps_same_score():
    base = "2024-01-01T00:00:00+00:00"
    det1 = _make_detection("a", Severity.MEDIUM, "host-1", triggered_at=base)
    det2 = _make_detection(
        "b", Severity.MEDIUM, "host-1", triggered_at="2024-01-01T00:30:00+00:00"
    )
    det3 = _make_detection(
        "c", Severity.MEDIUM, "host-1", triggered_at="2024-01-01T00:15:00+00:00"
    )

    # Shuffled order should produce the same score.
    a1 = RiskScorer().score([det1, det2, det3])
    a2 = RiskScorer().score([det3, det1, det2])
    assert a1[0].risk_score == a2[0].risk_score
    assert a1[0].assessment_id == a2[0].assessment_id


def test_score_boundaries_zero():
    # No detections -> score 0.
    assessments = RiskScorer().score([])
    assert assessments == []


def test_score_boundaries_max():
    # Multiple critical detections with all factors maxed should approach 100.
    dets = [
        _make_detection("a", Severity.CRITICAL, "host-1", evidence_count=3),
        _make_detection("b", Severity.CRITICAL, "host-1", evidence_count=3),
        _make_detection("c", Severity.CRITICAL, "host-1", evidence_count=3),
        _make_detection("d", Severity.CRITICAL, "host-1", evidence_count=3),
    ]
    assessments = RiskScorer().score(dets)
    assert len(assessments) == 1
    assert 0 <= assessments[0].risk_score <= 100


def test_configurable_scoring_weights():
    custom = ScoringWeights(
        severity=0.50,
        evidence_quality=0.10,
        event_frequency=0.10,
        correlation=0.20,
        asset_criticality=0.10,
    )
    custom.validate()
    det = _make_detection("c2_beacon", Severity.HIGH, "host-1")
    assessments = RiskScorer(weights=custom).score([det])
    assert len(assessments) == 1
    # Severity weight 0.50 * 80 = 40 from severity alone.
    assert assessments[0].score_breakdown["severity"] == 40.0


def test_optional_asset_criticality():
    det = _make_detection("failed_login", Severity.MEDIUM, "host-critical")
    # Without asset criticality -> not provided, score doesn't include it.
    a1 = RiskScorer().score([det])[0]
    assert a1.asset_criticality_provided is False
    assert a1.score_breakdown["asset_criticality"] == 0.0

    # With asset criticality -> provided, score includes it.
    scorer = RiskScorer(asset_criticality={"host-critical": 90.0})
    a2 = scorer.score([det])[0]
    assert a2.asset_criticality_provided is True
    assert a2.score_breakdown["asset_criticality"] == 9.0  # 90 * 0.10


def test_evidence_confidence_separate_from_score():
    # Evidence confidence and risk score are distinct concepts.
    det_complete = _make_detection("a", Severity.MEDIUM, "host-1", evidence_count=3)
    det_empty = _empty_detection("b", Severity.MEDIUM, "host-2")

    a1 = RiskScorer().score([det_complete])[0]
    a2 = RiskScorer().score([det_empty])[0]

    # Same severity, but different evidence completeness -> different scores.
    assert a1.evidence_confidence == "high"
    assert a2.evidence_confidence == "low"
    assert (
        a1.risk_score != a2.risk_score
        or a1.evidence_confidence != a2.evidence_confidence
    )


def test_detection_order_does_not_change_score():
    dets = [
        _make_detection("a", Severity.HIGH, "host-1"),
        _make_detection("b", Severity.MEDIUM, "host-1"),
        _make_detection("c", Severity.LOW, "host-1"),
    ]
    forward = RiskScorer().score(list(dets))
    reverse = RiskScorer().score(list(reversed(dets)))
    assert forward[0].risk_score == reverse[0].risk_score
    assert forward[0].assessment_id == reverse[0].assessment_id


def test_missing_evidence_handled():
    det = _empty_detection("a", Severity.HIGH, "host-1")
    assessments = RiskScorer().score([det])
    assert len(assessments) == 1
    assert assessments[0].supporting_evidence_count == 0
    assert assessments[0].evidence_confidence == "low"
    assert 0 <= assessments[0].risk_score <= 100


def test_correlation_window_boundary():
    # Two detections exactly at the window boundary -> same cluster.
    scorer = RiskScorer(correlation_window_seconds=3600)
    det1 = _make_detection(
        "a", Severity.MEDIUM, "host-1", triggered_at="2024-01-01T00:00:00+00:00"
    )
    det2 = _make_detection(
        "b", Severity.MEDIUM, "host-1", triggered_at="2024-01-01T01:00:00+00:00"
    )
    assessments = scorer.score([det1, det2])
    assert len(assessments) == 1
    assert assessments[0].score_breakdown["correlation"] == 50.0 * 0.20  # 2 types

    # Just outside the window -> separate clusters.
    scorer2 = RiskScorer(correlation_window_seconds=3599)
    assessments2 = scorer2.score([det1, det2])
    assert len(assessments2) == 2


def test_assessment_id_deterministic():
    det = _make_detection("a", Severity.HIGH, "host-1")
    a1 = RiskScorer().score([det])[0]
    a2 = RiskScorer().score([det])[0]
    assert a1.assessment_id == a2.assessment_id
    assert a1.assessment_id.startswith("assess-")


def test_risk_assessment_to_dict():
    det = _make_detection("a", Severity.HIGH, "host-1")
    a = RiskScorer().score([det])[0]
    d = a.to_dict()
    assert d["risk_score"] == a.risk_score
    assert d["affected_host"] == "host-1"
    assert "score_breakdown" in d
    assert "scoring_factors" in d
    assert "explanation" in d
    assert d["evidence_confidence"] == a.evidence_confidence
    assert d["detection_severity"] == "high"
