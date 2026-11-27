"""Failed login burst detection rule.

Detects multiple failed authentication attempts within a configurable time
window, grouped by source IP, username and destination host where available.

Every alert is backed by evidence from the original log events. No automatic
remediation is performed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sentinelforge.config import settings
from sentinelforge.detection.base import (
    DetectionResult,
    DetectionRule,
    Evidence,
    RuleCatalogEntry,
    Severity,
)
from sentinelforge.ingestion.normalizer import NormalizedEvent


def _parse_timestamp(value: str | None) -> datetime | None:
    """Parse an ISO-8601 timestamp string into an aware UTC datetime.

    Returns None when the value is missing or unparseable. We never invent a
    timestamp.
    """
    if not value:
        return None
    text = value.strip()
    if not text:
        return None
    # fromisoformat (3.11+) accepts a trailing 'Z'; normalize it for safety.
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


def _evidence_from_event(event: NormalizedEvent) -> Evidence:
    auth = event.authentication
    return Evidence(
        event_id=event.event_id,
        timestamp=event.timestamp or "",
        source=event.source,
        event_type=event.event_type,
        user=event.user,
        host=event.host,
        source_address=auth.source_address if auth else None,
        raw=event.raw,
    )


@dataclass
class FailedLoginBurstRule(DetectionRule):
    """Detects multiple failed authentication attempts within a time window.

    Attempts are grouped by (source_address, username, host), using whatever
    fields are present in the log. Missing fields are represented as ``None``
    in the grouping key so events are never dropped or fabricated.
    """

    rule_id: str = "sentinelforge.detection.failed_login_burst"
    name: str = "Failed Login Burst"
    description: str = (
        "Multiple failed authentication attempts from a source within a time window"
    )
    severity: Severity = Severity.HIGH
    threshold: int = settings.failed_login_threshold
    window_seconds: int = settings.failed_login_window_seconds
    metadata: dict[str, Any] = field(
        default_factory=lambda: {
            "mitre_attack_technique": "T1110",
            "mitre_attack_subtechnique": "T1110.001",
            "mitre_attack_tactic": "Credential Access",
            "mitre_attack_tactic_id": "TA0006",
            "mitre_attack_mapping_confidence": "high",
            "mitre_attack_mapping_rationale": "Multiple failed authentication attempts against one account within a time window is the canonical definition of password guessing/brute force. The FailedLoginBurstRule groups failures by source IP, username, and host within a configurable window.",
            "mitre_attack_investigation_recommendations": [
                "Check for successful logins from source IP",
                "Review account lockout policies",
                "Identify targeted accounts",
            ],
            "mitre_attack_catalogue_version": "v20.1",
        }
    )

    def __post_init__(self) -> None:
        # Ensure instance metadata is independent of the class-level default.
        if self.metadata is None:
            self.metadata = {}
        self.metadata = dict(self.metadata)

    def evaluate(self, events: list[NormalizedEvent]) -> list[DetectionResult]:
        """Evaluate failed-login bursts against normalized events."""
        results: list[DetectionResult] = []

        # Collect authentication failures, deduped by event_id, with valid
        # timestamps. Missing/invalid fields are handled safely.
        failures: list[tuple[NormalizedEvent, datetime]] = []
        seen_ids: set[str] = set()

        for event in events:
            event_id = event.event_id
            if event_id in seen_ids:
                continue  # avoid counting duplicate events multiple times

            auth = event.authentication
            if auth is None:
                continue
            if auth.outcome is None or str(auth.outcome).strip().lower() != "failure":
                continue  # only failed authentication attempts count

            ts = _parse_timestamp(event.timestamp)
            if ts is None:
                continue  # cannot place an event with no valid timestamp in a window

            seen_ids.add(event_id)
            failures.append((event, ts))

        if not failures:
            return results

        # Sort by timestamp so out-of-order events are handled correctly.
        failures.sort(key=lambda item: item[1])

        # Group by (source_address, username, host) — whatever is available.
        groups: dict[
            tuple[str | None, str | None, str | None],
            list[tuple[NormalizedEvent, datetime]],
        ] = {}
        for event, ts in failures:
            auth = event.authentication
            key = (
                auth.source_address if auth else None,
                auth.username if auth else None,
                event.host,
            )
            groups.setdefault(key, []).append((event, ts))

        for key, group_events in groups.items():
            burst = self._find_burst(group_events, self.threshold, self.window_seconds)
            if burst is None:
                continue

            evidence = [_evidence_from_event(event) for event, _ in burst]

            source_address, username, host = key
            group_label = ", ".join(
                str(value) if value is not None else "<missing>" for value in key
            )
            description = (
                f"{len(burst)} failed authentication attempts from {group_label} "
                f"within {self.window_seconds}s (threshold {self.threshold})"
            )

            rule_metadata = dict(self.metadata)
            rule_metadata.update(
                {
                    "threshold": self.threshold,
                    "window_seconds": self.window_seconds,
                    "count": len(burst),
                    "group_key": {
                        "source_address": source_address,
                        "username": username,
                        "host": host,
                    },
                    "first_timestamp": burst[0][0].timestamp,
                    "last_timestamp": burst[-1][0].timestamp,
                }
            )

            results.append(
                DetectionResult(
                    rule_id=self.rule_id,
                    rule_name=self.name,
                    severity=self.severity,
                    description=description,
                    evidence=evidence,
                    metadata=rule_metadata,
                )
            )

        return results

    @staticmethod
    def _find_burst(
        events: list[tuple[NormalizedEvent, datetime]],
        threshold: int,
        window_seconds: int,
    ) -> list[tuple[NormalizedEvent, datetime]] | None:
        """Find the densest window of ``threshold``+ events within ``window_seconds``.

        ``events`` must be sorted by timestamp. Returns the event slice for the
        window with the most events, or None when no window reaches threshold.
        Uses a sliding two-pointer window so out-of-order input (already sorted
        by the caller) is handled correctly.
        """
        n = len(events)
        if n < threshold:
            return None

        best_slice: list[tuple[NormalizedEvent, datetime]] | None = None
        best_count = 0
        j = 0
        for i in range(n):
            j = max(j, i)
            while (
                j < n
                and (events[j][1] - events[i][1]).total_seconds() <= window_seconds
            ):
                j += 1
            count = j - i
            if count >= threshold and count > best_count:
                best_count = count
                best_slice = events[i:j]

        return best_slice


CATALOG_ENTRY = RuleCatalogEntry(
    rule_id="sentinelforge.detection.failed_login_burst",
    name="Failed Login Burst",
    version="1.0.0",
    objective=(
        "Detect multiple failed authentication attempts from one source "
        "against one account within a configurable time window"
    ),
    category="authentication",
    severity=Severity.HIGH,
    attack_tactic="Credential Access",
    attack_tactic_id="TA0006",
    attack_technique="T1110",
    attack_technique_id="T1110.001",
    required_data_source="authentication logs",
    required_fields=[
        "event_type",
        "source_address",
        "username",
        "host",
        "timestamp",
        "outcome",
    ],
    threshold="settings.failed_login_threshold",
    time_window_seconds="settings.failed_login_window_seconds",
    false_positive_conditions=[
        "Legitimate repeated login failures (e.g., user forgot password)",
        "Service-account retry storms after credential rotation",
    ],
    investigation_instructions=[
        "Check for successful logins from the same source IP",
        "Review account lockout policies",
        "Identify targeted accounts",
    ],
    external_references=["MITRE ATT&CK T1110 / T1110.001"],
    test_references=[
        "tests/test_detection.py::test_multiple_failures_from_one_source_trigger_alert",
        "tests/test_detection.py::test_single_failed_login_no_alert",
        "tests/test_detection.py::test_failures_outside_time_window_no_alert",
    ],
    execution_status="working",
    validation_status="validated",
)
