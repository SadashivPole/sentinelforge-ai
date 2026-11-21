"""Explainable risk scoring engine.

Produces a deterministic, reproducible risk score (0-100) per host from
detection results. Three concepts are kept strictly separate:

1. Risk score — a numeric 0-100 assessment, NOT a probability of compromise.
2. Evidence confidence — how well-supported the underlying evidence is.
3. Detection severity — the severity assigned by each detection rule.

All scoring weights are configurable. Asset criticality is only applied when
explicitly provided; it is never invented.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

from sentinelforge.config import settings
from sentinelforge.detection.base import DetectionResult, Severity
from sentinelforge.risk.correlator import CorrelationCluster, DetectionCorrelator

# Severity -> raw score (0-100).
SEVERITY_SCORES: dict[Severity, int] = {
    Severity.CRITICAL: 100,
    Severity.HIGH: 80,
    Severity.MEDIUM: 60,
    Severity.LOW: 40,
    Severity.INFO: 20,
}

# Risk classification bands.
RISK_MINIMAL = "minimal"
RISK_LOW = "low"
RISK_MEDIUM = "medium"
RISK_HIGH = "high"
RISK_CRITICAL = "critical"


def _classify(score: int) -> str:
    if score >= 81:
        return RISK_CRITICAL
    if score >= 61:
        return RISK_HIGH
    if score >= 41:
        return RISK_MEDIUM
    if score >= 21:
        return RISK_LOW
    return RISK_MINIMAL


@dataclass(frozen=True)
class ScoringFactor:
    """One weighted component of the risk score."""

    name: str
    weight: float
    raw_score: float  # 0-100 before weighting
    weighted_score: float  # raw_score * weight
    description: str


@dataclass
class ScoringWeights:
    """Configurable weights for each scoring dimension. Must sum to 1.0."""

    severity: float = 0.30
    evidence_quality: float = 0.20
    event_frequency: float = 0.20
    correlation: float = 0.20
    asset_criticality: float = 0.10

    def validate(self) -> None:
        total = (
            self.severity
            + self.evidence_quality
            + self.event_frequency
            + self.correlation
            + self.asset_criticality
        )
        if abs(total - 1.0) > 1e-6:
            raise ValueError(
                f"Scoring weights must sum to 1.0, got {total:.6f}"
            )


@dataclass
class RiskAssessment:
    """A single explainable risk assessment for a host."""

    assessment_id: str
    affected_host: Optional[str]
    risk_score: int  # 0-100
    risk_classification: str
    contributing_detection_ids: list[str]
    scoring_factors: list[ScoringFactor]
    score_breakdown: dict[str, float]
    supporting_evidence_count: int
    explanation: str
    recommended_investigation_priorities: list[str]
    # Kept separate from risk_score — never conflated.
    evidence_confidence: str  # low | medium | high
    detection_severity: Severity  # highest severity among contributing detections
    asset_criticality_provided: bool = False  # whether criticality was explicit

    def to_dict(self) -> dict[str, Any]:
        return {
            "assessment_id": self.assessment_id,
            "affected_host": self.affected_host,
            "risk_score": self.risk_score,
            "risk_classification": self.risk_classification,
            "contributing_detection_ids": self.contributing_detection_ids,
            "scoring_factors": [
                {
                    "name": f.name,
                    "weight": f.weight,
                    "raw_score": f.raw_score,
                    "weighted_score": f.weighted_score,
                    "description": f.description,
                }
                for f in self.scoring_factors
            ],
            "score_breakdown": self.score_breakdown,
            "supporting_evidence_count": self.supporting_evidence_count,
            "explanation": self.explanation,
            "recommended_investigation_priorities": self.recommended_investigation_priorities,
            "evidence_confidence": self.evidence_confidence,
            "detection_severity": self.detection_severity.value,
            "asset_criticality_provided": self.asset_criticality_provided,
        }


def _evidence_quality_score(evidence_list: list[Any]) -> tuple[float, str]:
    """Score evidence completeness (0-100) and return confidence band.

    Each evidence item earns points for: raw log present (25), valid
    timestamp (25), and at least one of source_address/user/host (25 each,
    capped at 25 total for the trio). Confidence is low/medium/high based on
    the average score.
    """
    if not evidence_list:
        return 0.0, "low"

    total = 0.0
    for ev in evidence_list:
        pts = 0.0
        if getattr(ev, "raw", None):
            pts += 25.0
        if getattr(ev, "timestamp", None):
            pts += 25.0
        trio = any(
            getattr(ev, field, None)
            for field in ("source_address", "user", "host")
        )
        if trio:
            pts += 25.0
        # Fourth 25 points for event_type and source presence.
        if getattr(ev, "event_type", None) and getattr(ev, "source", None):
            pts += 25.0
        total += min(pts, 100.0)

    avg = total / len(evidence_list)
    if avg >= 75:
        confidence = "high"
    elif avg >= 40:
        confidence = "medium"
    else:
        confidence = "low"
    return avg, confidence


def _frequency_score(detection_count: int) -> float:
    """Score event frequency (0-100). More detections = higher frequency."""
    if detection_count <= 0:
        return 0.0
    if detection_count == 1:
        return 20.0
    if detection_count <= 3:
        return 40.0
    if detection_count <= 5:
        return 60.0
    if detection_count <= 9:
        return 80.0
    return 100.0


def _correlation_score(distinct_rule_count: int) -> float:
    """Score correlation breadth (0-100). More distinct detection types = higher."""
    if distinct_rule_count <= 0:
        return 0.0
    if distinct_rule_count == 1:
        return 20.0
    if distinct_rule_count == 2:
        return 50.0
    if distinct_rule_count == 3:
        return 75.0
    return 100.0


def _severity_score(severities: list[Severity]) -> float:
    """Highest severity among detections -> raw score (0-100)."""
    if not severities:
        return 0.0
    return float(max(SEVERITY_SCORES.get(s, 20) for s in severities))


def _assessment_id(host: Optional[str], detection_ids: list[str]) -> str:
    """Deterministic assessment id from host + detection ids."""
    payload = f"{(host or 'unknown')}|{'|'.join(sorted(detection_ids))}"
    return f"assess-{hashlib.sha256(payload.encode()).hexdigest()[:16]}"


class RiskScorer:
    """Scores detection results into explainable risk assessments.

    One assessment is produced per correlation cluster (host + time window).
    The score is a weighted sum of five factors, clamped to 0-100.
    """

    def __init__(
        self,
        weights: Optional[ScoringWeights] = None,
        correlation_window_seconds: int = 3600,
        asset_criticality: Optional[dict[str, float]] = None,
    ) -> None:
        self.weights = weights or ScoringWeights()
        self.weights.validate()
        self.correlator = DetectionCorrelator(
            window_seconds=correlation_window_seconds
        )
        # Asset criticality: host -> score (0-100). Only applied when
        # explicitly provided; never invented.
        self.asset_criticality = asset_criticality or {}

    def score(self, results: list[DetectionResult]) -> list[RiskAssessment]:
        """Score all detection results, returning one assessment per cluster."""
        clusters = self.correlator.correlate(results)
        assessments: list[RiskAssessment] = []

        # Index results by detection_id for evidence lookup.
        result_by_id: dict[str, DetectionResult] = {}
        for r in results:
            result_by_id[r.detection_id] = r

        for cluster in clusters:
            assessment = self._score_cluster(cluster, result_by_id)
            assessments.append(assessment)

        return assessments

    def _score_cluster(
        self,
        cluster: CorrelationCluster,
        result_by_id: dict[str, DetectionResult],
    ) -> RiskAssessment:
        host = cluster.host
        detection_ids = cluster.detection_ids

        # Gather the actual results for this cluster.
        cluster_results = [
            result_by_id[rid] for rid in detection_ids if rid in result_by_id
        ]

        # --- Factor 1: Severity ---
        severities = cluster.severities
        severity_raw = _severity_score(severities)
        severity_weighted = severity_raw * self.weights.severity
        highest_severity = (
            max(severities, key=lambda s: SEVERITY_SCORES.get(s, 0))
            if severities
            else Severity.INFO
        )

        # --- Factor 2: Evidence quality ---
        all_evidence: list[Any] = []
        for r in cluster_results:
            all_evidence.extend(r.evidence)
        evidence_raw, evidence_confidence = _evidence_quality_score(all_evidence)
        evidence_weighted = evidence_raw * self.weights.evidence_quality

        # --- Factor 3: Event frequency ---
        frequency_raw = _frequency_score(len(cluster_results))
        frequency_weighted = frequency_raw * self.weights.event_frequency

        # --- Factor 4: Correlation ---
        correlation_raw = _correlation_score(cluster.distinct_rule_count)
        correlation_weighted = correlation_raw * self.weights.correlation

        # --- Factor 5: Asset criticality (optional) ---
        asset_provided = host is not None and host in self.asset_criticality
        if asset_provided:
            asset_raw = self.asset_criticality[host]
            asset_raw = max(0.0, min(100.0, asset_raw))
        else:
            asset_raw = 0.0
        asset_weighted = asset_raw * self.weights.asset_criticality

        # --- Final score (weighted sum, clamped 0-100) ---
        raw_total = (
            severity_weighted
            + evidence_weighted
            + frequency_weighted
            + correlation_weighted
            + asset_weighted
        )
        risk_score = max(0, min(100, int(round(raw_total))))

        # --- Build factors list ---
        factors: list[ScoringFactor] = [
            ScoringFactor(
                name="severity",
                weight=self.weights.severity,
                raw_score=severity_raw,
                weighted_score=severity_weighted,
                description=(
                    f"Highest detection severity: {highest_severity.value} "
                    f"({len(severities)} detection(s))"
                ),
            ),
            ScoringFactor(
                name="evidence_quality",
                weight=self.weights.evidence_quality,
                raw_score=evidence_raw,
                weighted_score=evidence_weighted,
                description=(
                    f"Evidence completeness across {len(all_evidence)} "
                    f"evidence item(s); confidence {evidence_confidence}"
                ),
            ),
            ScoringFactor(
                name="event_frequency",
                weight=self.weights.event_frequency,
                raw_score=frequency_raw,
                weighted_score=frequency_weighted,
                description=f"{len(cluster_results)} detection(s) in cluster",
            ),
            ScoringFactor(
                name="correlation",
                weight=self.weights.correlation,
                raw_score=correlation_raw,
                weighted_score=correlation_weighted,
                description=(
                    f"{cluster.distinct_rule_count} distinct detection type(s) "
                    f"on host {host or '<unknown>'}"
                ),
            ),
            ScoringFactor(
                name="asset_criticality",
                weight=self.weights.asset_criticality,
                raw_score=asset_raw,
                weighted_score=asset_weighted,
                description=(
                    "Explicitly provided asset criticality"
                    if asset_provided
                    else "Not provided (not factored)"
                ),
            ),
        ]

        breakdown = {
            "severity": round(severity_weighted, 2),
            "evidence_quality": round(evidence_weighted, 2),
            "event_frequency": round(frequency_weighted, 2),
            "correlation": round(correlation_weighted, 2),
            "asset_criticality": round(asset_weighted, 2),
            "total": round(raw_total, 2),
        }

        # --- Explanation ---
        parts = [
            f"Risk score {risk_score} ({_classify(risk_score)}) for host "
            f"{host or '<unknown>'} based on {len(cluster_results)} detection(s)",
            f"across {cluster.distinct_rule_count} distinct detection type(s).",
        ]
        if asset_provided:
            parts.append(
                f"Asset criticality explicitly provided ({asset_raw:.0f}/100)."
            )
        else:
            parts.append("No asset criticality provided.")
        parts.append(f"Evidence confidence: {evidence_confidence}.")
        explanation = " ".join(parts)

        # --- Investigation priorities ---
        priorities: list[str] = []
        if highest_severity in (Severity.CRITICAL, Severity.HIGH):
            priorities.append(
                f"Investigate {highest_severity.value}-severity detection(s) first"
            )
        if cluster.distinct_rule_count >= 2:
            priorities.append(
                "Correlate across detection types — possible multi-stage activity"
            )
        if evidence_confidence == "low":
            priorities.append("Gather additional evidence before escalating")
        if not priorities:
            priorities.append("Review detection details and baseline behavior")

        return RiskAssessment(
            assessment_id=_assessment_id(host, detection_ids),
            affected_host=host,
            risk_score=risk_score,
            risk_classification=_classify(risk_score),
            contributing_detection_ids=detection_ids,
            scoring_factors=factors,
            score_breakdown=breakdown,
            supporting_evidence_count=len(all_evidence),
            explanation=explanation,
            recommended_investigation_priorities=priorities,
            evidence_confidence=evidence_confidence,
            detection_severity=highest_severity,
            asset_criticality_provided=asset_provided,
        )
