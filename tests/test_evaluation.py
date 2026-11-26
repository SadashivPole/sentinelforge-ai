"""Tests for the detection evaluation module.

Tests the two independent evaluation models:
- Alert-level: TP/FP per alert, precision only.
- Event-level: TP/FN per suspicious event, recall only.
- F1 only valid when precision and recall share the same unit.
"""

from __future__ import annotations

from sentinelforge.datasets.evaluation import evaluate_detections


def make_gt_entry(
    event_id: str,
    classification: str,
    scenario_id: str | None = None,
    expected_detection_category: str = "",
    expected_severity_range: str = "",
    explanation: str = "",
) -> dict:
    return {
        "event_id": event_id,
        "classification": classification,
        "scenario_id": scenario_id,
        "expected_detection_category": expected_detection_category,
        "expected_severity_range": expected_severity_range,
        "explanation": explanation,
    }


def make_detection_result(
    rule_id: str,
    rule_name: str,
    evidence_event_ids: list[str],
    mitre_technique: str | None = None,
):
    """Create a minimal DetectionResult-like object for testing."""
    from sentinelforge.detection.base import DetectionResult, Evidence, Severity

    evidence = [
        Evidence(
            event_id=eid,
            timestamp="2024-01-01T00:00:00+00:00",
            source="jsonl",
            event_type="auth.login.failed",
            user="user-1",
            host="host-1",
            source_address="10.0.0.1",
            raw={},
        )
        for eid in evidence_event_ids
    ]
    metadata = {}
    if mitre_technique:
        metadata["mitre_attack_technique"] = mitre_technique
    return DetectionResult(
        rule_id=rule_id,
        rule_name=rule_name,
        severity=Severity.HIGH,
        description="test detection",
        evidence=evidence,
        metadata=metadata,
    )


def evaluate_with_gt(
    detection_results,
    suspicious_events: list[dict],
    benign_events: list[dict],
    unlabeled_events: list[dict] | None = None,
):
    """Helper to build ground truth and evaluate."""
    entries = []
    for e in suspicious_events:
        entries.append(
            make_gt_entry(
                e["event_id"],
                "suspicious",
                e.get("scenario_id"),
                e.get("expected_detection_category", ""),
                e.get("expected_severity_range", ""),
                e.get("explanation", ""),
            )
        )
    for e in benign_events:
        entries.append(
            make_gt_entry(
                e["event_id"],
                "benign",
                e.get("scenario_id"),
                e.get("expected_detection_category", ""),
                e.get("expected_severity_range", ""),
                e.get("explanation", ""),
            )
        )
    for e in unlabeled_events or []:
        entries.append(
            make_gt_entry(
                e["event_id"],
                "unlabeled",
                None,
                "",
                "",
                "Not part of any scenario.",
            )
        )
    return evaluate_detections(
        "test-ds",
        detection_results,
        {"dataset_id": "test-ds", "total_events": len(entries), "entries": entries},
    )


# ---------------------------------------------------------------------------
# Alert-level tests
# ---------------------------------------------------------------------------


def test_alert_level_true_positive():
    """Detection on suspicious event with matching category = alert-level TP."""
    gt_suspicious = [
        {
            "event_id": "evt-susp-1",
            "scenario_id": "scenario-st-002",
            "expected_detection_category": "failed_login_burst",
            "expected_severity_range": "high",
            "explanation": "Brute force",
        }
    ]
    det = make_detection_result(
        rule_id="sentinelforge.detection.failed_login_burst",
        rule_name="Failed Login Burst",
        evidence_event_ids=["evt-susp-1"],
        mitre_technique="T1110",
    )
    result = evaluate_with_gt([det], gt_suspicious, [])
    # Alert-level: 1 TP, 0 FP
    assert result.alert_level.total_alerts == 1
    assert result.alert_level.true_positive_alerts == 1
    assert result.alert_level.false_positive_alerts == 0
    assert result.alert_level.precision == 1.0


def test_alert_level_false_positive():
    """Detection on benign event = alert-level FP."""
    gt_benign = [
        {
            "event_id": "evt-benign-1",
            "scenario_id": "scenario-st-005",
            "expected_detection_category": "none",
            "expected_severity_range": "info",
            "explanation": "EDR heartbeat",
        }
    ]
    det = make_detection_result(
        rule_id="sentinelforge.detection.c2_beacon",
        rule_name="C2 Beacon",
        evidence_event_ids=["evt-benign-1"],
        mitre_technique="T1071",
    )
    result = evaluate_with_gt([det], [], gt_benign)
    assert result.alert_level.total_alerts == 1
    assert result.alert_level.true_positive_alerts == 0
    assert result.alert_level.false_positive_alerts == 1
    assert result.alert_level.precision == 0.0


def test_alert_level_unassessed_excluded():
    """Alert on unlabeled evidence only = unassessed, not FP."""
    gt_unlabeled = [
        {
            "event_id": "evt-unlabeled-1",
            "scenario_id": None,
            "expected_detection_category": "",
            "expected_severity_range": "",
            "explanation": "Not in any scenario.",
        }
    ]
    det = make_detection_result(
        rule_id="sentinelforge.detection.c2_beacon",
        rule_name="C2 Beacon",
        evidence_event_ids=["evt-unlabeled-1"],
        mitre_technique="T1071",
    )
    result = evaluate_with_gt([det], [], [], gt_unlabeled)
    assert result.alert_level.total_alerts == 1
    assert result.alert_level.true_positive_alerts == 0
    assert result.alert_level.false_positive_alerts == 0
    assert result.alert_level.unassessed_alerts == 1
    assert result.alert_level.precision == 0.0  # 0 / (0 + 0)


def test_alert_level_category_mismatch_is_attribution_error():
    """Detection with non-matching category on suspicious event = attribution error, not FP.

    A category mismatch means the system detected suspicious activity
    (correct detection) but attributed it to the wrong technique (wrong label).
    This is NOT an ordinary false positive — something bad did happen.
    """
    gt_suspicious = [
        {
            "event_id": "evt-susp-1",
            "scenario_id": "scenario-st-002",
            "expected_detection_category": "failed_login_burst",
            "expected_severity_range": "high",
            "explanation": "Brute force",
        }
    ]
    # C2 beacon detection on a brute-force event — category mismatch
    det = make_detection_result(
        rule_id="sentinelforge.detection.c2_beacon",
        rule_name="C2 Beacon",
        evidence_event_ids=["evt-susp-1"],
        mitre_technique="T1071",
    )
    result = evaluate_with_gt([det], gt_suspicious, [])
    assert result.alert_level.true_positive_alerts == 0
    assert result.alert_level.false_positive_alerts == 0  # benign-only = true FP
    assert result.alert_level.attribution_error_alerts == 1  # wrong category
    assert result.alert_level.assessed_alerts == 1
    assert result.alert_level.precision == 0.0  # 0 / 1 assessed


# ---------------------------------------------------------------------------
# Event-level tests
# ---------------------------------------------------------------------------


def test_event_level_true_positive():
    """Suspicious event with at least one matching detection = event-level TP."""
    gt_suspicious = [
        {
            "event_id": "evt-susp-1",
            "scenario_id": "scenario-st-002",
            "expected_detection_category": "failed_login_burst",
            "expected_severity_range": "high",
            "explanation": "Brute force",
        }
    ]
    det = make_detection_result(
        rule_id="sentinelforge.detection.failed_login_burst",
        rule_name="Failed Login Burst",
        evidence_event_ids=["evt-susp-1"],
        mitre_technique="T1110",
    )
    result = evaluate_with_gt([det], gt_suspicious, [])
    # Event-level: 1 detected, 0 missed
    assert result.event_level.total_suspicious_events == 1
    assert result.event_level.detected_suspicious_events == 1
    assert result.event_level.undetected_suspicious_events == 0
    assert result.event_level.recall == 1.0


def test_event_level_false_negative():
    """Suspicious event with no detection = event-level FN."""
    gt_suspicious = [
        {
            "event_id": "evt-susp-1",
            "scenario_id": "scenario-st-002",
            "expected_detection_category": "failed_login_burst",
            "expected_severity_range": "high",
            "explanation": "Brute force",
        }
    ]
    result = evaluate_with_gt([], gt_suspicious, [])
    assert result.event_level.total_suspicious_events == 1
    assert result.event_level.detected_suspicious_events == 0
    assert result.event_level.undetected_suspicious_events == 1
    assert result.event_level.recall == 0.0


def test_event_level_unlabeled_excluded():
    """Unlabeled events don't affect event-level recall."""
    gt_unlabeled = [
        {
            "event_id": "evt-unlabeled-1",
            "scenario_id": None,
            "expected_detection_category": "",
            "expected_severity_range": "",
            "explanation": "Not in any scenario.",
        }
    ]
    det = make_detection_result(
        rule_id="sentinelforge.detection.c2_beacon",
        rule_name="C2 Beacon",
        evidence_event_ids=["evt-unlabeled-1"],
        mitre_technique="T1071",
    )
    result = evaluate_with_gt([det], [], [], gt_unlabeled)
    # No suspicious events -> recall denominator is 0
    assert result.event_level.total_suspicious_events == 0
    assert result.event_level.recall == 0.0


# ---------------------------------------------------------------------------
# F1 tests
# ---------------------------------------------------------------------------


def test_f1_alert_not_valid():
    """Alert-level F1 is not valid (no alert-level recall)."""
    result = evaluate_with_gt([], [], [])
    assert result.f1_alert.valid is False
    assert result.f1_alert.f1_score == 0.0


def test_f1_event_not_valid():
    """Event-level F1 is not valid (no event-level precision)."""
    result = evaluate_with_gt([], [], [])
    assert result.f1_event.valid is False
    assert result.f1_event.f1_score == 0.0


# ---------------------------------------------------------------------------
# Per-rule metrics tests
# ---------------------------------------------------------------------------


def test_rule_alert_metrics_structure():
    """Rule alert metrics contain all required fields."""
    gt_suspicious = [
        {
            "event_id": "evt-susp-1",
            "scenario_id": "scenario-st-002",
            "expected_detection_category": "failed_login_burst",
            "expected_severity_range": "high",
            "explanation": "Brute force",
        }
    ]
    det = make_detection_result(
        rule_id="sentinelforge.detection.failed_login_burst",
        rule_name="Failed Login Burst",
        evidence_event_ids=["evt-susp-1"],
        mitre_technique="T1110",
    )
    result = evaluate_with_gt([det], gt_suspicious, [])
    rule_m = result.rule_alert_metrics[0]
    assert rule_m.rule_id == "sentinelforge.detection.failed_login_burst"
    assert rule_m.rule_name == "Failed Login Burst"
    assert rule_m.total_alerts == 1
    assert rule_m.true_positive_alerts == 1
    assert rule_m.false_positive_alerts == 0
    assert rule_m.unassessed_alerts == 0
    assert rule_m.precision == 1.0


def test_rule_event_metrics_structure():
    """Rule event metrics contain all required fields."""
    gt_suspicious = [
        {
            "event_id": "evt-susp-1",
            "scenario_id": "scenario-st-002",
            "expected_detection_category": "failed_login_burst",
            "expected_severity_range": "high",
            "explanation": "Brute force",
        }
    ]
    det = make_detection_result(
        rule_id="sentinelforge.detection.failed_login_burst",
        rule_name="Failed Login Burst",
        evidence_event_ids=["evt-susp-1"],
        mitre_technique="T1110",
    )
    result = evaluate_with_gt([det], gt_suspicious, [])
    rule_m = result.rule_event_metrics[0]
    assert rule_m.rule_id == "sentinelforge.detection.failed_login_burst"
    assert rule_m.rule_name == "Failed Login Burst"
    assert rule_m.expected_events == 1
    assert rule_m.detected_events == 1
    assert rule_m.missed_events == 0
    assert rule_m.recall == 1.0


def test_no_detections_zero_metrics():
    """Zero detections produces zero metrics across both models."""
    result = evaluate_with_gt([], [], [])
    assert result.alert_level.total_alerts == 0
    assert result.alert_level.true_positive_alerts == 0
    assert result.alert_level.false_positive_alerts == 0
    assert result.alert_level.precision == 0.0
    assert result.event_level.total_suspicious_events == 0
    assert result.event_level.recall == 0.0
    assert result.f1_alert.valid is False
    assert result.f1_event.valid is False


# ---------------------------------------------------------------------------
# Mathematical verification: exact numerators and denominators
# ---------------------------------------------------------------------------


def test_alert_level_precision_exact_numerator_denominator():
    """Alert-level precision = TP / assessed with exact counts.

    3 TP alerts, 1 FP alert (benign evidence), 1 attribution error
    (category mismatch on suspicious evidence), 5 unassessed alerts.
    Assessed = 3 + 1 + 1 = 5. Precision = 3 / 5 = 0.6.
    Unassessed alerts are excluded from the denominator.
    """
    # 3 suspicious events, all matched by detections with correct category
    gt_suspicious = [
        make_gt_entry(
            "evt-susp-1",
            "suspicious",
            "scenario-st-001",
            "suspicious_processtree",
            "high",
            "Word->PowerShell",
        ),
        make_gt_entry(
            "evt-susp-2",
            "suspicious",
            "scenario-st-002",
            "failed_login_burst",
            "high",
            "8 failed logins",
        ),
        make_gt_entry(
            "evt-susp-3",
            "suspicious",
            "scenario-st-004",
            "c2_beacon",
            "medium",
            "Periodic connections",
        ),
    ]
    # 1 benign event that triggers a detection (true FP)
    gt_benign = [
        make_gt_entry(
            "evt-benign-1", "benign", "scenario-st-005", "none", "info", "EDR heartbeat"
        ),
    ]
    # 5 unlabeled events that trigger detections (unassessed)
    gt_unlabeled = [
        make_gt_entry(f"evt-unlabeled-{i}", "unlabeled", None, "", "", "")
        for i in range(5)
    ]

    # 3 TP alerts: each matches a suspicious event with correct category
    tp_alerts = [
        make_detection_result(
            "sentinelforge.detection.suspicious_processtree",
            "Suspicious Process Tree",
            ["evt-susp-1"],
            "T1204.002",
        ),
        make_detection_result(
            "sentinelforge.detection.failed_login_burst",
            "Failed Login Burst",
            ["evt-susp-2"],
            "T1110",
        ),
        make_detection_result(
            "sentinelforge.detection.c2_beacon", "C2 Beacon", ["evt-susp-3"], "T1071"
        ),
    ]
    # 1 FP alert: detection on benign event
    fp_alerts = [
        make_detection_result(
            "sentinelforge.detection.suspicious_processtree",
            "Suspicious Process Tree",
            ["evt-benign-1"],
            "T1204.002",
        ),  # benign event
    ]
    # 1 attribution error: category mismatch on suspicious event
    attribution_error_alerts = [
        make_detection_result(
            "sentinelforge.detection.c2_beacon", "C2 Beacon", ["evt-susp-1"], "T1071"
        ),  # wrong category
    ]
    # 5 unassessed alerts: all on unlabeled events
    unassessed_alerts = [
        make_detection_result(
            "sentinelforge.detection.c2_beacon",
            "C2 Beacon",
            [f"evt-unlabeled-{i}"],
            "T1071",
        )
        for i in range(5)
    ]

    all_alerts = tp_alerts + fp_alerts + attribution_error_alerts + unassessed_alerts
    result = evaluate_with_gt(all_alerts, gt_suspicious, gt_benign, gt_unlabeled)

    # Alert-level: precision = 3 / 5 = 0.6
    assert result.alert_level.total_alerts == 10
    assert result.alert_level.true_positive_alerts == 3
    assert result.alert_level.false_positive_alerts == 1  # benign only
    assert result.alert_level.attribution_error_alerts == 1  # wrong category
    assert result.alert_level.unassessed_alerts == 5
    assert result.alert_level.assessed_alerts == 5  # 3 + 1 + 1
    assert result.alert_level.precision == 0.6, (
        f"Expected precision 0.6 (3/5), got {result.alert_level.precision}"
    )
    assert result.alert_level.assessment_coverage == 0.5  # 5 / 10

    # Per-rule metrics
    rule_map = {m.rule_id: m for m in result.rule_alert_metrics}
    assert (
        rule_map["sentinelforge.detection.suspicious_processtree"].true_positive_alerts
        == 1
    )
    assert (
        rule_map["sentinelforge.detection.suspicious_processtree"].false_positive_alerts
        == 1
    )  # alert on benign evt-benign-1
    assert (
        rule_map[
            "sentinelforge.detection.suspicious_processtree"
        ].attribution_error_alerts
        == 0
    )
    assert (
        rule_map["sentinelforge.detection.suspicious_processtree"].assessed_alerts == 2
    )
    assert (
        rule_map["sentinelforge.detection.suspicious_processtree"].precision == 0.5
    )  # 1 / 2
    assert (
        rule_map["sentinelforge.detection.failed_login_burst"].true_positive_alerts == 1
    )
    assert rule_map["sentinelforge.detection.failed_login_burst"].assessed_alerts == 1
    assert rule_map["sentinelforge.detection.failed_login_burst"].precision == 1.0
    assert rule_map["sentinelforge.detection.c2_beacon"].true_positive_alerts == 1
    assert rule_map["sentinelforge.detection.c2_beacon"].attribution_error_alerts == 1
    assert rule_map["sentinelforge.detection.c2_beacon"].assessed_alerts == 2
    assert rule_map["sentinelforge.detection.c2_beacon"].precision == 0.5  # 1 / 2


def test_event_level_recall_exact_numerator_denominator():
    """Event-level recall = TP / (TP + FN) with exact counts.

    5 suspicious events total.
    3 detected by at least one matching alert.
    2 undetected (no matching alert).
    Recall = 3 / 5 = 0.6

    Multiple detections of the same event are deduplicated (count once).
    """
    gt_suspicious = [
        make_gt_entry(
            "evt-susp-1",
            "suspicious",
            "scenario-st-001",
            "suspicious_processtree",
            "high",
            "Word->PowerShell",
        ),
        make_gt_entry(
            "evt-susp-2",
            "suspicious",
            "scenario-st-002",
            "failed_login_burst",
            "high",
            "8 failed logins",
        ),
        make_gt_entry(
            "evt-susp-3",
            "suspicious",
            "scenario-st-003",
            "password_spray",
            "high",
            "Password spraying",
        ),
        make_gt_entry(
            "evt-susp-4",
            "suspicious",
            "scenario-st-004",
            "c2_beacon",
            "medium",
            "Periodic connections",
        ),
        make_gt_entry(
            "evt-susp-5",
            "suspicious",
            "scenario-st-007",
            "failed_login_burst",
            "high",
            "Multi-host brute force",
        ),
    ]
    gt_benign = [
        make_gt_entry(
            "evt-benign-1", "benign", "scenario-st-005", "none", "info", "EDR heartbeat"
        ),
    ]
    gt_unlabeled = [make_gt_entry("evt-unlabeled-1", "unlabeled", None, "", "", "")]

    # 3 events detected:
    # evt-susp-1 detected by processtree rule
    # evt-susp-2 detected by failed_login_burst rule (twice - deduplicated)
    # evt-susp-3 detected by password_spray rule
    # evt-susp-4 NOT detected (no matching alert)
    # evt-susp-5 NOT detected (no matching alert)
    det1 = make_detection_result(
        "sentinelforge.detection.suspicious_processtree",
        "Suspicious Process Tree",
        ["evt-susp-1"],
        "T1204.002",
    )
    det2 = make_detection_result(
        "sentinelforge.detection.failed_login_burst",
        "Failed Login Burst",
        ["evt-susp-2"],
        "T1110",
    )
    det3 = make_detection_result(
        "sentinelforge.detection.failed_login_burst",
        "Failed Login Burst",
        ["evt-susp-2"],
        "T1110",
    )  # duplicate detection
    det4 = make_detection_result(
        "sentinelforge.detection.password_spray",
        "Password Spray",
        ["evt-susp-3"],
        "T1110.003",
    )
    # FP on benign event
    det5 = make_detection_result(
        "sentinelforge.detection.c2_beacon", "C2 Beacon", ["evt-benign-1"], "T1071"
    )

    result = evaluate_with_gt(
        [det1, det2, det3, det4, det5], gt_suspicious, gt_benign, gt_unlabeled
    )

    # Event-level: recall = 3 / 5 = 0.6
    assert result.event_level.total_suspicious_events == 5
    assert result.event_level.detected_suspicious_events == 3
    assert result.event_level.undetected_suspicious_events == 2
    assert result.event_level.recall == 0.6, (
        f"Expected recall 0.6 (3/5), got {result.event_level.recall}"
    )

    # Per-rule event metrics
    rule_map = {m.rule_id: m for m in result.rule_event_metrics}
    assert (
        rule_map["sentinelforge.detection.suspicious_processtree"].expected_events == 1
    )
    assert (
        rule_map["sentinelforge.detection.suspicious_processtree"].detected_events == 1
    )
    assert rule_map["sentinelforge.detection.failed_login_burst"].expected_events == 2
    assert rule_map["sentinelforge.detection.failed_login_burst"].detected_events == 1
    assert rule_map["sentinelforge.detection.password_spray"].expected_events == 1
    assert rule_map["sentinelforge.detection.password_spray"].detected_events == 1


def test_alert_on_mixed_evidence_classification():
    """Alert with mixed evidence (suspicious + benign) classified correctly.

    If any evidence is suspicious with matching category -> TP.
    If all evidence is benign -> FP.
    If mixed but no suspicious match -> FP.
    """
    gt_suspicious = [
        make_gt_entry(
            "evt-susp-1",
            "suspicious",
            "scenario-st-001",
            "suspicious_processtree",
            "high",
            "Word->PowerShell",
        ),
    ]
    gt_benign = [
        make_gt_entry(
            "evt-benign-1", "benign", "scenario-st-005", "none", "info", "EDR heartbeat"
        ),
    ]

    # Mixed evidence: one suspicious (matching) + one benign -> TP
    det_mixed_tp = make_detection_result(
        "sentinelforge.detection.suspicious_processtree",
        "Suspicious Process Tree",
        ["evt-susp-1", "evt-benign-1"],
        "T1204.002",
    )
    # All benign evidence -> FP
    det_benign_only = make_detection_result(
        "sentinelforge.detection.c2_beacon", "C2 Beacon", ["evt-benign-1"], "T1071"
    )

    result = evaluate_with_gt([det_mixed_tp, det_benign_only], gt_suspicious, gt_benign)

    assert result.alert_level.true_positive_alerts == 1
    assert result.alert_level.false_positive_alerts == 1
    assert result.alert_level.precision == 0.5  # 1 / (1 + 1)


def test_multiple_detections_same_event_deduplicated():
    """Multiple detections of the same event count once at event level."""
    gt_suspicious = [
        make_gt_entry(
            "evt-susp-1",
            "suspicious",
            "scenario-st-001",
            "suspicious_processtree",
            "high",
            "Word->PowerShell",
        ),
    ]

    # Two detections on the same event with matching category
    det1 = make_detection_result(
        "sentinelforge.detection.suspicious_processtree",
        "Suspicious Process Tree",
        ["evt-susp-1"],
        "T1204.002",
    )
    det2 = make_detection_result(
        "sentinelforge.detection.suspicious_processtree",
        "Suspicious Process Tree (2nd)",
        ["evt-susp-1"],
        "T1204.002",
    )

    result = evaluate_with_gt([det1, det2], gt_suspicious, [])

    # Event level: 1 event detected (deduplicated)
    assert result.event_level.detected_suspicious_events == 1
    assert result.event_level.undetected_suspicious_events == 0
    assert result.event_level.recall == 1.0

    # Alert level: 2 alerts, both TP
    assert result.alert_level.total_alerts == 2
    assert result.alert_level.true_positive_alerts == 2
    assert result.alert_level.precision == 1.0


# ---------------------------------------------------------------------------
# Metric terminology: three separate precision/coverage measures (M8.3.2)
# ---------------------------------------------------------------------------


def test_category_correct_precision_only_counts_category_correct_tp():
    """Category-correct precision = category-correct TP / assessed.

    Category-correct TP means the alert matched both the suspicious
    classification AND the expected detection category.

    2 category-correct TP, 1 FP (benign evidence), 1 attribution error
    (wrong category on suspicious evidence), 5 unassessed.
    Assessed = 2 + 1 + 1 = 4. Category-correct precision = 2 / 4 = 0.5.
    """
    gt_suspicious = [
        make_gt_entry(
            "evt-susp-1",
            "suspicious",
            "scenario-st-001",
            "suspicious_processtree",
            "high",
            "Word->PowerShell",
        ),
        make_gt_entry(
            "evt-susp-2",
            "suspicious",
            "scenario-st-002",
            "failed_login_burst",
            "high",
            "8 failed logins",
        ),
    ]
    gt_benign = [
        make_gt_entry(
            "evt-benign-1", "benign", "scenario-st-005", "none", "info", "EDR heartbeat"
        ),
    ]
    gt_unlabeled = [
        make_gt_entry(f"evt-unlabeled-{i}", "unlabeled", None, "", "", "")
        for i in range(5)
    ]

    # 2 category-correct TP alerts
    tp_alerts = [
        make_detection_result(
            "sentinelforge.detection.suspicious_processtree",
            "Suspicious Process Tree",
            ["evt-susp-1"],
            "T1204.002",
        ),
        make_detection_result(
            "sentinelforge.detection.failed_login_burst",
            "Failed Login Burst",
            ["evt-susp-2"],
            "T1110",
        ),
    ]
    # 1 FP alert: detection on benign event
    fp_alerts = [
        make_detection_result(
            "sentinelforge.detection.suspicious_processtree",
            "Suspicious Process Tree",
            ["evt-benign-1"],
            "T1204.002",
        ),
    ]
    # 1 attribution error: category mismatch on suspicious event
    attribution_error_alerts = [
        make_detection_result(
            "sentinelforge.detection.c2_beacon", "C2 Beacon", ["evt-susp-1"], "T1071"
        ),  # wrong category
    ]
    # 5 unassessed alerts: all on unlabeled events
    unassessed_alerts = [
        make_detection_result(
            "sentinelforge.detection.c2_beacon",
            "C2 Beacon",
            [f"evt-unlabeled-{i}"],
            "T1071",
        )
        for i in range(5)
    ]

    all_alerts = tp_alerts + fp_alerts + attribution_error_alerts + unassessed_alerts
    result = evaluate_with_gt(all_alerts, gt_suspicious, gt_benign, gt_unlabeled)

    # Category-correct precision = 2 / 4 = 0.5
    assert result.alert_level.total_alerts == 9  # 2 + 1 + 1 + 5
    assert result.alert_level.true_positive_alerts == 2
    assert result.alert_level.false_positive_alerts == 1  # benign only
    assert result.alert_level.attribution_error_alerts == 1
    assert result.alert_level.assessed_alerts == 4  # 2 + 1 + 1
    assert result.alert_level.precision == 0.5  # 2 / 4


def test_suspicious_activity_precision_counts_attribution_errors_as_detected():
    """Suspicious-activity precision = (category-correct TP + attribution errors) / assessed.

    This measures whether the system detected suspicious activity at all,
    regardless of whether the technique/category attribution was correct.
    Attribution errors are counted as "detected suspicious activity" because
    something bad did happen — the wrong label was just assigned.

    2 category-correct TP, 1 attribution error, 1 FP (benign evidence),
    5 unassessed. Assessed = 2 + 1 + 1 = 4.
    Suspicious-activity precision = (2 + 1) / 4 = 0.75.

    This is NOT ordinary binary suspicious-activity precision — attribution
    errors are tracked separately from true positives.
    """
    gt_suspicious = [
        make_gt_entry(
            "evt-susp-1",
            "suspicious",
            "scenario-st-001",
            "suspicious_processtree",
            "high",
            "Word->PowerShell",
        ),
        make_gt_entry(
            "evt-susp-2",
            "suspicious",
            "scenario-st-002",
            "failed_login_burst",
            "high",
            "8 failed logins",
        ),
    ]
    gt_benign = [
        make_gt_entry(
            "evt-benign-1", "benign", "scenario-st-005", "none", "info", "EDR heartbeat"
        ),
    ]
    gt_unlabeled = [
        make_gt_entry(f"evt-unlabeled-{i}", "unlabeled", None, "", "", "")
        for i in range(5)
    ]

    tp_alerts = [
        make_detection_result(
            "sentinelforge.detection.suspicious_processtree",
            "Suspicious Process Tree",
            ["evt-susp-1"],
            "T1204.002",
        ),
        make_detection_result(
            "sentinelforge.detection.failed_login_burst",
            "Failed Login Burst",
            ["evt-susp-2"],
            "T1110",
        ),
    ]
    fp_alerts = [
        make_detection_result(
            "sentinelforge.detection.suspicious_processtree",
            "Suspicious Process Tree",
            ["evt-benign-1"],
            "T1204.002",
        ),
    ]
    attribution_error_alerts = [
        make_detection_result(
            "sentinelforge.detection.c2_beacon", "C2 Beacon", ["evt-susp-1"], "T1071"
        ),
    ]
    unassessed_alerts = [
        make_detection_result(
            "sentinelforge.detection.c2_beacon",
            "C2 Beacon",
            [f"evt-unlabeled-{i}"],
            "T1071",
        )
        for i in range(5)
    ]

    all_alerts = tp_alerts + fp_alerts + attribution_error_alerts + unassessed_alerts
    result = evaluate_with_gt(all_alerts, gt_suspicious, gt_benign, gt_unlabeled)

    # Suspicious-activity precision = (2 + 1) / 4 = 0.75
    assert result.alert_level.true_positive_alerts == 2
    assert result.alert_level.attribution_error_alerts == 1
    assert result.alert_level.false_positive_alerts == 1
    assert result.alert_level.assessed_alerts == 4  # 2 + 1 + 1
    suspicious_activity_precision = (
        result.alert_level.true_positive_alerts
        + result.alert_level.attribution_error_alerts
    ) / result.alert_level.assessed_alerts
    assert suspicious_activity_precision == 0.75  # 3 / 4


def test_assessment_coverage_exact_numerator_denominator():
    """Assessment coverage = assessed alerts / total alerts.

    2 TP + 1 FP + 1 attribution error = 4 assessed.
    5 unassessed.
    Total = 9. Coverage = 4 / 9 = 0.4444.
    """
    gt_suspicious = [
        make_gt_entry(
            "evt-susp-1",
            "suspicious",
            "scenario-st-001",
            "suspicious_processtree",
            "high",
            "Word->PowerShell",
        ),
    ]
    gt_benign = [
        make_gt_entry(
            "evt-benign-1", "benign", "scenario-st-005", "none", "info", "EDR heartbeat"
        ),
    ]
    gt_unlabeled = [
        make_gt_entry(f"evt-unlabeled-{i}", "unlabeled", None, "", "", "")
        for i in range(5)
    ]

    tp_alerts = [
        make_detection_result(
            "sentinelforge.detection.suspicious_processtree",
            "Suspicious Process Tree",
            ["evt-susp-1"],
            "T1204.002",
        ),
    ]
    fp_alerts = [
        make_detection_result(
            "sentinelforge.detection.suspicious_processtree",
            "Suspicious Process Tree",
            ["evt-benign-1"],
            "T1204.002",
        ),
    ]
    attribution_error_alerts = [
        make_detection_result(
            "sentinelforge.detection.c2_beacon", "C2 Beacon", ["evt-susp-1"], "T1071"
        ),
    ]
    unassessed_alerts = [
        make_detection_result(
            "sentinelforge.detection.c2_beacon",
            "C2 Beacon",
            [f"evt-unlabeled-{i}"],
            "T1071",
        )
        for i in range(5)
    ]

    all_alerts = tp_alerts + fp_alerts + attribution_error_alerts + unassessed_alerts
    result = evaluate_with_gt(all_alerts, gt_suspicious, gt_benign, gt_unlabeled)

    # Assessment coverage = 4 / 8 = 0.5
    assert result.alert_level.total_alerts == 8  # 1 + 1 + 1 + 5
    assert result.alert_level.assessed_alerts == 3  # 1 + 1 + 1
    assert result.alert_level.unassessed_alerts == 5
    assert result.alert_level.assessment_coverage == round(3 / 8, 4)


# ---------------------------------------------------------------------------
# Regression test: M8.1 metric discrepancy
# ---------------------------------------------------------------------------
#
# The M8.1 report's event-level evaluation (evaluate_detections) and its
# confusion matrix (generate_confusion_matrix) disagreed: 498 vs 501 detected
# suspicious events. Root cause: generate_confusion_matrix() counted ANY
# alert touching a suspicious event as "detected", while evaluate_detections()
# required the alert's category to match the event's expected detection
# category. A wrong-category alert on suspicious evidence is an attribution
# error, not a true detection.
#
# Both paths now share alert_categories_match() + CATEGORY_ALIASES so they can
# never diverge again. This test reproduces the discrepancy scenario at small
# scale and asserts both report the same detected count.


def test_event_level_detected_requires_category_match():
    """Wrong-category detection on a suspicious event is not event-level TP.

    Reproduces the M8.1 divergence: a password_spray alert firing on an event
    whose ground truth expects failed_login_burst. Before the fix,
    generate_confusion_matrix() counted it as detected; evaluate_detections()
    did not. Both must now agree (counted once = category match only).
    """
    from run_m8_1_evaluation import generate_confusion_matrix

    gt_entries = [
        make_gt_entry(
            "evt-wrong-cat-1",
            "suspicious",
            "scenario-st-002",
            "failed_login_burst",
            "high",
            "brute force",
        ),
        make_gt_entry(
            "evt-right-cat-1",
            "suspicious",
            "scenario-st-003",
            "password_spray",
            "high",
            "password spraying",
        ),
    ]
    gt = {
        "dataset_id": "test-ds",
        "total_events": len(gt_entries),
        "entries": gt_entries,
    }

    # password_spray alert on the failed_login_burst event -> WRONG category.
    wrong_cat_det = make_detection_result(
        rule_id="sentinelforge.detection.password_spray",
        rule_name="Password Spray",
        evidence_event_ids=["evt-wrong-cat-1"],
        mitre_technique="T1110.003",
    )
    # password_spray alert on the password_spray event -> correct category.
    right_cat_det = make_detection_result(
        rule_id="sentinelforge.detection.password_spray",
        rule_name="Password Spray",
        evidence_event_ids=["evt-right-cat-1"],
        mitre_technique="T1110.003",
    )

    detection_results = [wrong_cat_det, right_cat_det]

    # evaluate_detections() event-level path.
    result = evaluate_with_gt(detection_results, gt_entries, [])
    assert result.event_level.total_suspicious_events == 2
    assert result.event_level.detected_suspicious_events == 1
    assert result.event_level.undetected_suspicious_events == 1
    assert result.event_level.recall == 0.5

    # generate_confusion_matrix() must agree exactly.
    confusion = generate_confusion_matrix(detection_results, gt)
    assert confusion["suspicious_events_detected"] == 1
    assert confusion["suspicious_events_missed"] == 1
    assert (
        confusion["suspicious_events_detected"]
        == result.event_level.detected_suspicious_events
    )
    assert (
        confusion["suspicious_events_missed"]
        == result.event_level.undetected_suspicious_events
    )


def test_alert_categories_match_helper():
    """alert_categories_match() encodes the shared match definition."""
    from sentinelforge.datasets.evaluation import alert_categories_match

    alert_cats = {"password_spray", "t1110.003"}

    # Category matches expected category.
    assert alert_categories_match(alert_cats, "password_spray") is True
    # Comma-separated list, one matches.
    assert alert_categories_match(alert_cats, "c2_beacon, password_spray") is True
    # No match -> not detected.
    assert alert_categories_match(alert_cats, "failed_login_burst") is False
    # No expected categories -> any alert counts as detected.
    assert alert_categories_match(alert_cats, "") is True
    assert alert_categories_match(alert_cats, []) is True
    # Case-insensitive.
    assert alert_categories_match(alert_cats, "PASSWORD_SPRAY") is True
