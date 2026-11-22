"""Password spraying detection rule.

Detects authentication attempts from a single source IP against multiple
usernames within a configurable time window — distinct from brute-force
(which targets one account with many passwords).

Password spraying is a low-and-slow technique: one or a few passwords are
tried against many accounts to avoid account lockout thresholds.

Every alert cites the exact original log event(s) as evidence. No automatic
remediation is performed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sentinelforge.detection.base import (
    DetectionResult,
    DetectionRule,
    Evidence,
    Severity,
)
from sentinelforge.ingestion.normalizer import NormalizedEvent


def _parse_timestamp(value: str | None) -> datetime | None:
    """Parse an ISO-8601 timestamp string into an aware UTC datetime."""
    if not value:
        return None
    text = value.strip()
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
class PasswordSprayRule(DetectionRule):
    """Detects password spraying: one source IP targeting multiple usernames.

    Unlike brute-force (many attempts against one account), password spraying
    tries a small set of passwords against many accounts to avoid lockout.

    Grouped by source IP across distinct usernames within a time window.
    A single failed login against one username is not spraying — the rule
    requires multiple distinct target accounts from the same source.
    """

    rule_id: str = "sentinelforge.detection.password_spray"
    name: str = "Password Spray"
    description: str = (
        "Authentication failures from one source IP against multiple "
        "distinct usernames within a time window"
    )
    severity: Severity = Severity.HIGH
    # Minimum distinct usernames targeted from one source to constitute spraying.
    username_threshold: int = field(default=3)
    # Time window in seconds.
    window_seconds: int = field(default=3600)
    # Minimum total failed attempts (in addition to username diversity).
    attempt_threshold: int = field(default=3)
    metadata: dict[str, Any] = field(
        default_factory=lambda: {
            "mitre_attack_technique": "T1110.003",
            "mitre_attack_tactic": "Credential Access",
            "mitre_attack_tactic_id": "TA0006",
            "mitre_attack_mapping_confidence": "high",
            "mitre_attack_mapping_rationale": "One source IP attempting authentication against multiple distinct usernames is the exact definition of password spraying. The PasswordSprayRule groups failures by source IP and counts distinct target usernames.",
            "mitre_attack_investigation_recommendations": [
                "Check for successful logins from source IP against targeted accounts",
                "Force password reset for targeted accounts",
                "Review account lockout thresholds",
            ],
            "mitre_attack_catalogue_version": "v20.1",
        }
    )

    def __post_init__(self) -> None:
        if self.metadata is None:
            self.metadata = {}
        self.metadata = dict(self.metadata)

    def evaluate(self, events: list[NormalizedEvent]) -> list[DetectionResult]:
        """Evaluate password spraying against normalized events."""
        results: list[DetectionResult] = []

        # Collect authentication failures with valid timestamps.
        failures: list[tuple[NormalizedEvent, datetime]] = []
        seen_ids: set[str] = set()

        for event in events:
            event_id = event.event_id
            if event_id in seen_ids:
                continue  # dedupe by event id

            auth = event.authentication
            if auth is None:
                continue
            if auth.outcome is None or str(auth.outcome).strip().lower() != "failure":
                continue  # only failed authentication attempts count

            ts = _parse_timestamp(event.timestamp)
            if ts is None:
                continue

            seen_ids.add(event_id)
            failures.append((event, ts))

        if not failures:
            return results

        # Sort by timestamp.
        failures.sort(key=lambda item: item[1])

        # Group by source address only. Events with no source address
        # cannot be reliably attributed to a single source and are
        # excluded from spray detection — otherwise unrelated events
        # from different hosts could be incorrectly combined into one
        # alert.
        groups: dict[str | None, list[tuple[NormalizedEvent, datetime]]] = {}
        for event, ts in failures:
            auth = event.authentication
            source_address = auth.source_address if auth else None
            if source_address is None:
                continue  # missing source address — cannot group by source
            groups.setdefault(source_address, []).append((event, ts))

        for source_address, group_events in groups.items():
            # Count distinct usernames targeted from this source.
            distinct_users = {
                str(ev.authentication.username)
                for ev, _ in group_events
                if ev.authentication and ev.authentication.username
            }

            if len(distinct_users) < self.username_threshold:
                continue  # not enough distinct targets for spraying

            if len(group_events) < self.attempt_threshold:
                continue  # not enough total attempts

            # Sliding window: find a window containing username_threshold+
            # distinct users and attempt_threshold+ total attempts.
            window = self._find_spray_window(
                group_events,
                self.window_seconds,
                self.username_threshold,
                self.attempt_threshold,
            )
            if window is None:
                continue

            evidence = [_evidence_from_event(event) for event, _ in window]

            group_label = source_address or "<missing>"
            description = (
                f"{len(window)} failed authentication attempts from "
                f"{group_label} against {len(distinct_users)} distinct "
                f"username(s) within {self.window_seconds}s "
                f"(username threshold {self.username_threshold})"
            )

            rule_metadata = dict(self.metadata)
            rule_metadata.update(
                {
                    "source_address": source_address,
                    "distinct_username_count": len(distinct_users),
                    "targeted_usernames": sorted(distinct_users),
                    "total_attempts": len(window),
                    "username_threshold": self.username_threshold,
                    "attempt_threshold": self.attempt_threshold,
                    "window_seconds": self.window_seconds,
                    "first_timestamp": window[0][0].timestamp,
                    "last_timestamp": window[-1][0].timestamp,
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
    def _find_spray_window(
        events: list[tuple[NormalizedEvent, datetime]],
        window_seconds: int,
        username_threshold: int,
        attempt_threshold: int,
    ) -> list[tuple[NormalizedEvent, datetime]] | None:
        """Find a time window containing enough distinct users and attempts.

        Uses a sliding two-pointer window. Returns the event slice for the
        best window, or None when no window meets both thresholds.
        """
        n = len(events)
        if n < attempt_threshold:
            return None

        best_slice: list[tuple[NormalizedEvent, datetime]] | None = None
        best_user_count = 0

        j = 0
        for i in range(n):
            j = max(j, i)
            while (
                j < n
                and (events[j][1] - events[i][1]).total_seconds() <= window_seconds
            ):
                j += 1

            window_events = events[i:j]
            distinct_users = {
                str(ev.authentication.username)
                for ev, _ in window_events
                if ev.authentication and ev.authentication.username
            }

            user_count = len(distinct_users)
            attempt_count = len(window_events)

            if (
                user_count >= username_threshold
                and attempt_count >= attempt_threshold
                and user_count > best_user_count
            ):
                best_user_count = user_count
                best_slice = window_events

        return best_slice
