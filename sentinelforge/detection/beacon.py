"""Statistical C2 beacon detection rule.

Analyzes outbound network connection intervals to detect potential beaconing
patterns — repeated, periodic connections to a destination that are
characteristic of command-and-control (C2) communication.

The rule does NOT classify traffic as confirmed C2. It flags "Potential C2
Beaconing" for analyst review. Legitimate periodic traffic (EDR heartbeats,
software updates, monitoring agents, scheduled polling) can produce similar
patterns and is handled via configurable allowlists and false-positive notes.

Every alert cites the original raw log events as evidence.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sentinelforge.config import settings
from sentinelforge.detection.base import (
    DetectionResult,
    DetectionRule,
    Evidence,
    Severity,
)
from sentinelforge.ingestion.normalizer import NetworkInfo, NormalizedEvent


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
    net = event.network
    return Evidence(
        event_id=event.event_id,
        timestamp=event.timestamp or "",
        source=event.source,
        event_type=event.event_type,
        user=event.user,
        host=event.host,
        source_address=net.remote_address if net else None,
        raw=event.raw,
    )


def _regularity_score(std_dev: float, mean_interval: float) -> float:
    """Return a regularity score in [0.0, 1.0].

    1.0 = perfectly regular (zero variance). 0.0 = highly irregular.
    Computed as 1 - coefficient_of_variation, clamped to [0, 1].
    """
    if mean_interval <= 0:
        # All intervals identical (or zero): perfectly regular.
        return 1.0 if std_dev == 0 else 0.0
    cv = std_dev / mean_interval
    return max(0.0, min(1.0, 1.0 - cv))


def _heuristic_pattern_tier(mean_interval: float) -> str:
    """Return a heuristic pattern tier based on beacon interval length.

    Short-period, highly regular connections are more characteristic of
    C2 beaconing. Long-period periodic patterns are more commonly
    legitimate (software updates, EDR heartbeats, scheduled polling) and
    therefore receive a lower heuristic tier — but they are still reported
    for analyst review rather than silently discarded.

    These tiers are heuristic, not statistically calibrated. They do not
    represent a measured probability of maliciousness.

    Tiers:
    - \"short_interval\": mean interval <= 300s   (short-period beaconing pattern)
    - \"medium_interval\": 300s < mean <= 3600s    (moderate-period pattern)
    - \"long_interval\": mean interval > 3600s   (long-period pattern, commonly benign)
    """
    if mean_interval <= 300.0:
        return "short_interval"
    if mean_interval <= 3600.0:
        return "medium_interval"
    return "long_interval"


# Application-layer protocols (vs. transport-layer tcp/udp/ip). T1071
# (Application Layer Protocol) is only attributed when an application-layer
# protocol is present AND there is additional protocol-specific C2 context
# (e.g. a non-standard port for that protocol). Periodic connections and a
# protocol name alone are insufficient.
_APPLICATION_LAYER_PROTOCOLS = {
    "http",
    "https",
    "dns",
    "smb",
    "ssh",
    "ftp",
    "smtp",
    "imap",
    "pop3",
    "ntp",
    "snmp",
    "ldap",
}

# Default/standard ports per application-layer protocol. Connections on these
# ports are considered normal; non-standard ports are potential C2 context.
_STANDARD_PORTS: dict[str, set[int]] = {
    "http": {80, 8080},
    "https": {443, 8443},
    "dns": {53},
    "ssh": {22},
    "smtp": {25, 587},
    "ftp": {21},
    "imap": {143, 993},
    "pop3": {110, 995},
    "ldap": {389, 636},
    "ntp": {123},
    "snmp": {161},
    "smb": {445},
}

# Processes whose use of an application-layer protocol is suspicious —
# these are not typical producers/consumers of the protocol and may
# indicate C2 communication when combined with non-standard ports.
_SUSPICIOUS_PROCESSES = {
    "powershell",
    "pwsh",
    "cmd",
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "certutil",
    "certutil.exe",
    "bitsadmin",
    "bitsadmin.exe",
    "mshta",
    "mshta.exe",
    "wscript",
    "wscript.exe",
    "cscript",
    "cscript.exe",
}


def _is_ip_address(value: str | None) -> bool:
    """Return True when ``value`` looks like an IPv4 or IPv6 address."""
    if not value:
        return False
    text = value.strip()
    parts = text.split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return True
    return ":" in text


def _has_suspicious_app_context(net: NetworkInfo, process_name: str | None) -> bool:
    """Return True when there is additional suspicious application-layer
    context beyond protocol name and port deviation.

    Requires BOTH:
    - A suspicious process using the protocol (e.g. powershell.exe over HTTPS),
    - AND a raw IP destination (no DNS resolution) for HTTP/DNS/SMB.

    Neither indicator alone is sufficient for T1071 attribution.
    """
    suspicious_process = False
    if process_name:
        proc_norm = process_name.strip().lower()
        for ext in (".exe", ".com", ".bat", ".cmd"):
            if proc_norm.endswith(ext):
                proc_norm = proc_norm[: -len(ext)]
                break
        if proc_norm in _SUSPICIOUS_PROCESSES:
            suspicious_process = True

    raw_ip = False
    if net.remote_address and _is_ip_address(net.remote_address):
        proto = (net.protocol or "").strip().lower()
        if proto in ("http", "https", "dns", "smb"):
            raw_ip = True

    return suspicious_process and raw_ip


def _has_c2_context_evidence(net: NetworkInfo, process_name: str | None = None) -> bool:
    """Return True when there is protocol-specific C2 evidence beyond an
    application-layer protocol name.

    Requires ALL of:
    1. An application-layer protocol is present, AND
    2. The destination port is present and non-standard for that protocol,
    3. Additional suspicious application-layer context (abnormal process,
       raw IP destination, etc.)

    Port deviation alone does NOT establish T1071.
    """
    if not net.protocol:
        return False
    proto = net.protocol.strip().lower()
    if proto not in _APPLICATION_LAYER_PROTOCOLS:
        return False
    if net.remote_port is None:
        return False
    standard = _STANDARD_PORTS.get(proto, set())
    if net.remote_port in standard:
        # Port is standard — not C2 context by itself.
        return False
    # Require additional suspicious context beyond port deviation.
    return _has_suspicious_app_context(net, process_name)


@dataclass
class C2BeaconRule(DetectionRule):
    """Detects potential C2 beaconing from statistical regularity of
    connection intervals."""

    rule_id: str = "sentinelforge.detection.c2_beacon"
    name: str = "Potential C2 Beaconing"
    description: str = (
        "Repeated, periodic outbound connections to a destination consistent "
        "with command-and-control beaconing"
    )
    severity: Severity = Severity.MEDIUM
    min_connections: int = settings.beacon_min_connections  # default 6
    regularity_tolerance: float = settings.beacon_regularity_tolerance  # default 0.25
    # Allowlists for false-positive reduction. Empty = allowlist disabled.
    allowlisted_destinations: set[str] = field(default_factory=set)
    allowlisted_ports: set[int] = field(default_factory=set)
    allowlisted_processes: set[str] = field(default_factory=set)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.metadata is None:
            self.metadata = {}
        self.metadata = dict(self.metadata)

    def evaluate(self, events: list[NormalizedEvent]) -> list[DetectionResult]:
        results: list[DetectionResult] = []
        seen_ids: set[str] = set()

        # Collect network connection events with a valid timestamp and
        # destination address. Deduplicate by event_id.
        connections: list[tuple[NormalizedEvent, datetime, Any]] = []
        for event in events:
            event_id = event.event_id
            if event_id in seen_ids:
                continue
            net = event.network
            if net is None:
                continue
            if net.remote_address is None:
                continue  # missing destination IP — cannot group meaningfully
            ts = _parse_timestamp(event.timestamp)
            if ts is None:
                continue  # invalid timestamp — cannot place in interval sequence
            seen_ids.add(event_id)
            connections.append((event, ts, net))

        if not connections:
            return results

        # Group by (source host, destination IP, destination port). This keeps
        # unrelated hosts and destinations in separate buckets.
        groups: dict[
            tuple[str | None, str | None, int | None],
            list[tuple[NormalizedEvent, datetime, Any]],
        ] = {}
        for event, ts, net in connections:
            key = (event.host, net.remote_address, net.remote_port)
            groups.setdefault(key, []).append((event, ts, net))

        for key, group in groups.items():
            host, dest_ip, dest_port = key

            # Allowlist exclusions — maintain auditability by recording why.
            if dest_ip in self.allowlisted_destinations:
                continue
            if dest_port is not None and dest_port in self.allowlisted_ports:
                continue

            process_name = _group_process_name(group)
            if process_name and process_name.lower() in {
                p.lower() for p in self.allowlisted_processes
            }:
                continue

            # Need at least min_connections to evaluate regularity.
            if len(group) < self.min_connections:
                continue

            # Sort by timestamp so out-of-order events are handled correctly.
            group.sort(key=lambda item: item[1])

            # Compute intervals between consecutive connections.
            intervals: list[float] = []
            for i in range(1, len(group)):
                delta = (group[i][1] - group[i - 1][1]).total_seconds()
                if delta >= 0:
                    intervals.append(delta)

            if len(intervals) < 1:
                continue

            # Statistical descriptors.
            total_connections = len(group)
            mean_interval = statistics.mean(intervals)
            median_interval = statistics.median(intervals)
            if len(intervals) >= 2:
                std_dev = statistics.pstdev(intervals)
            else:
                std_dev = 0.0
            min_interval = min(intervals)
            max_interval = max(intervals)
            score = _regularity_score(std_dev, mean_interval)

            # Regularity threshold: score must exceed (1 - tolerance).
            # With tolerance 0.25, threshold = 0.75.
            if score < (1.0 - self.regularity_tolerance):
                continue  # too irregular to be a beacon

            evidence = [_evidence_from_event(event) for event, _, _ in group]

            first_ts = group[0][0].timestamp
            last_ts = group[-1][0].timestamp

            # Interval-based pattern tier: short-period regular patterns are
            # more characteristic of C2 beaconing; long-period patterns are
            # more commonly legitimate periodic traffic. The tier is
            # heuristic — it does not affect alert generation, risk scoring,
            # ATT&CK attribution, or severity. It only informs analyst
            # presentation.
            pattern_tier = _heuristic_pattern_tier(mean_interval)

            rule_metadata = dict(self.metadata)
            rule_metadata["pattern_tier"] = pattern_tier
            # T1071 requires app-layer protocol + non-standard port +
            # additional suspicious application-layer context. Port deviation
            # alone does NOT establish T1071. If required context is absent,
            # the ATT&CK mapping is left empty — the beacon detection itself
            # still works without MITRE attribution.
            net_sample = group[0][2]
            if _has_c2_context_evidence(net_sample, process_name):
                rule_metadata.update(
                    {
                        "mitre_attack_technique": "T1071",
                        "mitre_attack_tactic": "Command and Control",
                        "mitre_attack_tactic_id": "TA0011",
                        "mitre_attack_mapping_confidence": "medium",
                        "mitre_attack_mapping_rationale": "Periodic outbound connections with non-standard ports and suspicious process context are consistent with C2 beaconing, but legitimate periodic traffic (EDR heartbeats, software updates) can produce identical patterns. T1071 is only mapped when protocol-specific C2 context is present.",
                        "mitre_attack_investigation_recommendations": [
                            "Correlate with process execution events on source host",
                            "Check destination reputation",
                            "Review command-line context",
                            "Compare against baseline network behavior",
                        ],
                        "mitre_attack_catalogue_version": "v20.1",
                    }
                )
            rule_metadata.update(
                {
                    "detection_id": f"{self.rule_id}.{host}.{dest_ip}.{dest_port}",
                    "host": host,
                    "destination_ip": dest_ip,
                    "destination_port": dest_port,
                    "connection_count": total_connections,
                    "mean_interval_seconds": round(mean_interval, 4),
                    "median_interval_seconds": round(median_interval, 4),
                    "standard_deviation_seconds": round(std_dev, 4),
                    "coefficient_of_variation": round(
                        std_dev / mean_interval if mean_interval > 0 else 0.0, 4
                    ),
                    "regularity_score": round(score, 4),
                    "regularity_threshold": round(1.0 - self.regularity_tolerance, 4),
                    "min_interval_seconds": round(min_interval, 4),
                    "max_interval_seconds": round(max_interval, 4),
                    "first_timestamp": first_ts,
                    "last_timestamp": last_ts,
                    "process_name": process_name,
                    "label": "Potential C2 Beaconing",
                    "confirmation": "Not confirmed C2 — requires analyst investigation.",
                    "false_positive_considerations": (
                        "Legitimate periodic traffic (EDR heartbeats, software "
                        "update checks, DNS monitoring, monitoring agents, "
                        "scheduled application polling) can produce similar "
                        "patterns. Review allowlist and baseline behavior before "
                        "escalating."
                    ),
                    "investigation_recommendations": (
                        "Correlate with process execution events on the source "
                        "host; check destination reputation; review command-line "
                        "context; compare against baseline network behavior."
                    ),
                }
            )

            description = (
                f"Potential C2 beaconing: {total_connections} connections from "
                f"{host or '<unknown>'} to {dest_ip}:{dest_port or '<any>'} "
                f"with mean interval {mean_interval:.1f}s, regularity "
                f"score {score:.2f} (threshold {1.0 - self.regularity_tolerance:.2f}), "
                f"pattern_tier={pattern_tier}"
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


def _group_process_name(
    group: list[tuple[NormalizedEvent, datetime, Any]],
) -> str | None:
    """Return the most common process name in a connection group, if any."""
    from collections import Counter

    names: list[str] = []
    for event, _, _ in group:
        proc = event.process
        if proc is None:
            continue
        name = proc.name or proc.path
        if name:
            names.append(name)
    if not names:
        return None
    return Counter(names).most_common(1)[0][0]
