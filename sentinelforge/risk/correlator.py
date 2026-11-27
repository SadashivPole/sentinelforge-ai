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


def _incident_id(detection_ids: list[str]) -> str:
    """Deterministic incident ID derived from the sorted detection IDs.

    The same set of detections always yields the same incident ID, which makes
    correlation reproducible and idempotent.
    """
    import hashlib

    joined = ",".join(sorted(detection_ids))
    return "incident-" + hashlib.sha256(joined.encode("utf-8")).hexdigest()[:16]


def _user_of(result: DetectionResult) -> str | None:
    """Extract the affected user from a detection result."""
    if result.metadata and result.metadata.get("user"):
        return str(result.metadata["user"])
    if result.evidence and result.evidence[0].user:
        return result.evidence[0].user
    return None


def _addresses_of(result: DetectionResult, field: str) -> list[str]:
    """Extract address values (source or destination) from evidence + metadata."""
    values: list[str] = []
    if result.metadata and result.metadata.get(field):
        values.append(str(result.metadata[field]))
    for evidence in result.evidence:
        value = getattr(evidence, field, None)
        if value:
            values.append(str(value))
    return values


def _technique_of(result: DetectionResult) -> str | None:
    """Extract the ATT&CK technique from detection metadata, if recorded."""
    if result.metadata and result.metadata.get("attack_technique"):
        return str(result.metadata["attack_technique"])
    return None


def _values_for_key(result: DetectionResult, key: str) -> list[str]:
    """Extract the correlation values for a single key from a detection result."""
    if key == "host":
        host = _host_of(result)
        return [host] if host else []
    if key == "user":
        user = _user_of(result)
        return [user] if user else []
    if key == "source_address":
        return _addresses_of(result, "source_address")
    if key == "destination_address":
        return _addresses_of(result, "destination_address")
    if key == "attack_technique":
        technique = _technique_of(result)
        return [technique] if technique else []
    return []


@dataclass(frozen=True)
class CorrelationGroup:
    """A group of detections sharing one correlation key within a time window.

    Correlation does not imply causation; ``rationale`` records the key and
    values that justified the grouping so analysts can verify it.
    """

    group_id: str
    key_type: str
    key_value: str
    detection_ids: list[str]
    rule_ids: set[str]
    severities: list[Severity]
    first_triggered: datetime | None
    last_triggered: datetime | None
    rationale: str


def correlate_multi_key(
    results: list[DetectionResult],
    keys: tuple[str, ...] = ("host",),
    window_seconds: int = 3600,
) -> list[CorrelationGroup]:
    """Group detections by shared correlation key within a time window.

    For each key type, detections are grouped by key value; within each value
    group a sliding time window splits the detections into sub-clusters. Each
    sub-cluster becomes a :class:`CorrelationGroup` with a deterministic
    ``group_id``. A detection can appear in multiple groups (once per matching
    key), which is intentional — a host and an IP are independent pivot points.

    Existing detections are counted once per group; unrelated key values are
    never mixed.
    """
    groups: list[CorrelationGroup] = []
    for key in keys:
        by_value: dict[str, list[DetectionResult]] = {}
        for result in results:
            for value in _values_for_key(result, key):
                by_value.setdefault(value, []).append(result)

        for key_value, value_results in by_value.items():
            sorted_results = sorted(
                value_results,
                key=lambda r: (
                    _parse_triggered_at(r) or datetime.min.replace(tzinfo=UTC)
                ),
            )
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
                if gap <= window_seconds:
                    current.append(result)
                else:
                    groups.append(_make_group(key, key_value, current))
                    current = [result]
                    cluster_start = ts
            if current:
                groups.append(_make_group(key, key_value, current))
    return groups


def _make_group(
    key: str, key_value: str, results: list[DetectionResult]
) -> CorrelationGroup:
    ids = [r.detection_id for r in results]
    rule_ids = {r.rule_id for r in results}
    severities = [r.severity for r in results]
    timestamps = [_parse_triggered_at(r) for r in results]
    valid_ts = [t for t in timestamps if t is not None]
    rationale = (
        f"{len(results)} detection(s) share {key}={key_value} "
        f"within the correlation window"
    )
    return CorrelationGroup(
        group_id=_incident_id(ids),
        key_type=key,
        key_value=key_value,
        detection_ids=ids,
        rule_ids=rule_ids,
        severities=severities,
        first_triggered=min(valid_ts) if valid_ts else None,
        last_triggered=max(valid_ts) if valid_ts else None,
        rationale=rationale,
    )
