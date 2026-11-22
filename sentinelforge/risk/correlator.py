"""Detection correlation for risk scoring.

Groups detection results by host within a configurable time window so that
multiple independent detection types affecting the same host can be scored
together. Correlation never inflates scores through duplicate alerts — each
detection is counted once, and unrelated hosts are never mixed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from sentinelforge.detection.base import DetectionResult, Severity


def _parse_triggered_at(result: DetectionResult) -> datetime | None:
    """Parse a detection's triggered_at timestamp into an aware UTC datetime."""
    if not result.triggered_at:
        return None
    text = result.triggered_at.strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


def _host_of(result: DetectionResult) -> str | None:
    """Extract the affected host from a detection result.

    Host is taken from metadata first (set by most rules), then from the
    first evidence entry. Missing hosts are represented as None and are never
    correlated with other hosts.
    """
    if result.metadata and result.metadata.get("host"):
        return str(result.metadata["host"])
    if result.evidence and result.evidence[0].host:
        return result.evidence[0].host
    return None


@dataclass(frozen=True)
class CorrelationCluster:
    """A group of detections on the same host within a time window."""

    host: str | None
    detection_ids: list[str]
    rule_ids: set[str]
    severities: list[Severity]
    first_triggered: datetime | None
    last_triggered: datetime | None
    distinct_rule_count: int = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "distinct_rule_count", len(self.rule_ids))


@dataclass
class DetectionCorrelator:
    """Correlates detection results by host within a time window.

    Each detection is counted once. Unrelated hosts are never mixed. The
    time window is configurable; detections outside it form separate
    clusters.
    """

    window_seconds: int

    def correlate(self, results: list[DetectionResult]) -> list[CorrelationCluster]:
        """Group detections into host-scoped time-window clusters."""
        # Group by host first.
        by_host: dict[str | None, list[DetectionResult]] = {}
        for result in results:
            host = _host_of(result)
            by_host.setdefault(host, []).append(result)

        clusters: list[CorrelationCluster] = []
        for host, host_results in by_host.items():
            # Sort by triggered_at (missing timestamps go to the end).
            sorted_results = sorted(
                host_results,
                key=lambda r: (
                    _parse_triggered_at(r) or datetime.min.replace(tzinfo=UTC)
                ),
            )

            # Sliding window: start a new cluster when the gap from the
            # cluster's first detection exceeds the window.
            current: list[DetectionResult] = []
            cluster_start: datetime | None = None

            for result in sorted_results:
                ts = _parse_triggered_at(result)
                if cluster_start is None:
                    cluster_start = ts
                    current = [result]
                    continue

                if ts is not None and cluster_start is not None:
                    gap = (ts - cluster_start).total_seconds()
                else:
                    gap = float("inf")

                if gap <= self.window_seconds:
                    current.append(result)
                else:
                    # Close current cluster and start a new one.
                    clusters.append(self._make_cluster(host, current))
                    current = [result]
                    cluster_start = ts

            if current:
                clusters.append(self._make_cluster(host, current))

        return clusters

    def _make_cluster(
        self, host: str | None, results: list[DetectionResult]
    ) -> CorrelationCluster:
        ids = [r.detection_id for r in results]
        rule_ids = {r.rule_id for r in results}
        severities = [r.severity for r in results]
        timestamps = [_parse_triggered_at(r) for r in results]
        valid_ts = [t for t in timestamps if t is not None]
        return CorrelationCluster(
            host=host,
            detection_ids=ids,
            rule_ids=rule_ids,
            severities=severities,
            first_triggered=min(valid_ts) if valid_ts else None,
            last_triggered=max(valid_ts) if valid_ts else None,
        )
