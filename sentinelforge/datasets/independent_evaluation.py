"""SentinelForge AI — Independent C2 Detection Evaluation.

Creates a NEW independently generated evaluation dataset with ground truth
established BEFORE evaluating the detection logic. This dataset is separate
from the holdout dataset used to select the previous 300-second threshold
(tuning data). Results here are not contaminated by threshold tuning.

Measures:
- Precision, Recall, F1
- False-positive rate, False-negative rate
- Alert-level and event-level metrics
- Results by beacon interval range

Clearly distinguishes synthetic evaluation from real-world validation.
Does NOT claim 100% accuracy unless the independent evaluation supports it.

Usage:
    from sentinelforge.datasets.independent_evaluation import run_independent_evaluation
    results = run_independent_evaluation()
    print(results.summary_text())
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from sentinelforge.detection.base import RuleRegistry, Severity
from sentinelforge.detection.beacon import C2BeaconRule
from sentinelforge.ingestion.normalizer import (
    AuthenticationInfo,
    NetworkInfo,
    NormalizedEvent,
    ProcessInfo,
)

BASE = datetime(2024, 3, 15, 8, 0, 0, tzinfo=timezone.utc)


def make_event(
    event_id: str,
    timestamp: str,
    event_type: str,
    source: str,
    user: str | None = None,
    host: str | None = None,
    authentication: dict[str, Any] | None = None,
    process: dict[str, Any] | None = None,
    network: dict[str, Any] | None = None,
    raw: dict[str, Any] | None = None,
) -> NormalizedEvent:
    """Build a NormalizedEvent from keyword arguments."""
    return NormalizedEvent(
        event_id=event_id,
        timestamp=timestamp,
        source=source,
        raw=raw or {},
        event_type=event_type,
        user=user,
        host=host,
        authentication=(
            AuthenticationInfo(**authentication) if authentication else None
        ),
        process=ProcessInfo(**process) if process else None,
        network=NetworkInfo(**network) if network else None,
    )


# ---------------------------------------------------------------------------
# Independently generated evaluation dataset
# Ground truth established BEFORE detection evaluation.
# Events are NOT from sentinelforge.datasets.scenarios and NOT from the
# holdout dataset used for threshold tuning.
# ---------------------------------------------------------------------------

eval_events: list[NormalizedEvent] = []
eval_ground_truth: list[dict[str, Any]] = []  # {event_id, is_suspicious, expected_category, interval_seconds}


def add_events(
    event_ids: list[str],
    timestamps: list[str],
    event_type: str,
    source: str,
    is_suspicious: bool,
    expected_category: str | None,
    host: str,
    user: str | None = None,
    network_info: dict[str, Any] | None = None,
    process_info: dict[str, Any] | None = None,
    interval_seconds: int | None = None,
) -> None:
    for eid, ts in zip(event_ids, timestamps):
        eval_events.append(
            make_event(
                event_id=eid,
                timestamp=ts,
                event_type=event_type,
                source=source,
                user=user,
                host=host,
                authentication=None,
                process=process_info,
                network=network_info,
                raw={"event_id": eid},
            )
        )
        eval_ground_truth.append(
            {
                "event_id": eid,
                "is_suspicious": is_suspicious,
                "expected_category": expected_category,
                "interval_seconds": interval_seconds,
            }
        )


# --- Suspicious: Short-interval C2 beaconing (30s) ---
timestamps = [(BASE + timedelta(seconds=i * 30)).isoformat() for i in range(6)]
add_events(
    event_ids=[f"eval-c2-30s-{i:02d}" for i in range(6)],
    timestamps=timestamps,
    event_type="network.connection",
    source="windows_sysmon",
    is_suspicious=True,
    expected_category="c2_beacon_30s",
    host="WKSTN-10",
    user="CORP\\jdoe",
    network_info={
        "direction": "outbound",
        "local_address": "10.0.1.50",
        "remote_address": "203.0.113.50",
        "local_port": 50001,
        "remote_port": 4433,
        "protocol": "https",
    },
    process_info={
        "name": "powershell.exe",
        "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "pid": 3333,
        "ppid": 0,
        "command_line": "powershell.exe -EncodedCommand ...",
    },
    interval_seconds=30,
)

# --- Suspicious: Short-interval C2 beaconing (60s) ---
timestamps = [(BASE + timedelta(minutes=i)).isoformat() for i in range(6)]
add_events(
    event_ids=[f"eval-c2-60s-{i:02d}" for i in range(6)],
    timestamps=timestamps,
    event_type="network.connection",
    source="windows_sysmon",
    is_suspicious=True,
    expected_category="c2_beacon_60s",
    host="WKSTN-11",
    user="CORP\\asmith",
    network_info={
        "direction": "outbound",
        "local_address": "10.0.1.51",
        "remote_address": "198.51.100.77",
        "local_port": 50002,
        "remote_port": 8443,
        "protocol": "https",
    },
    process_info={
        "name": "certutil.exe",
        "path": "C:\\Windows\\System32\\certutil.exe",
        "pid": 4444,
        "ppid": 0,
        "command_line": "certutil -urlcache -split -f http://...",
    },
    interval_seconds=60,
)

# --- Suspicious: Medium-interval C2 beaconing (10 min) ---
timestamps = [(BASE + timedelta(minutes=i * 10)).isoformat() for i in range(6)]
add_events(
    event_ids=[f"eval-c2-10m-{i:02d}" for i in range(6)],
    timestamps=timestamps,
    event_type="network.connection",
    source="windows_sysmon",
    is_suspicious=True,
    expected_category="c2_beacon_10m",
    host="WKSTN-12",
    user="CORP\\rjohnson",
    network_info={
        "direction": "outbound",
        "local_address": "10.0.1.52",
        "remote_address": "192.0.2.99",
        "local_port": 50003,
        "remote_port": 4433,
        "protocol": "https",
    },
    process_info={
        "name": "bitsadmin.exe",
        "path": "C:\\Windows\\System32\\bitsadmin.exe",
        "pid": 5555,
        "ppid": 0,
        "command_line": "bitsadmin /transfer ...",
    },
    interval_seconds=600,
)

# --- Suspicious: Long-interval C2 beaconing (2 hours) ---
timestamps = [(BASE + timedelta(hours=i * 2)).isoformat() for i in range(6)]
add_events(
    event_ids=[f"eval-c2-2h-{i:02d}" for i in range(6)],
    timestamps=timestamps,
    event_type="network.connection",
    source="windows_sysmon",
    is_suspicious=True,
    expected_category="c2_beacon_2h",
    host="WKSTN-13",
    user="CORP\\mwilson",
    network_info={
        "direction": "outbound",
        "local_address": "10.0.1.53",
        "remote_address": "203.0.113.99",
        "local_port": 50004,
        "remote_port": 4433,
        "protocol": "https",
    },
    process_info={
        "name": "powershell.exe",
        "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "pid": 6666,
        "ppid": 0,
        "command_line": "powershell -ExecutionPolicy Bypass ...",
    },
    interval_seconds=7200,
)

# --- Suspicious: Very long-interval C2 beaconing (6 hours) ---
timestamps = [(BASE + timedelta(hours=i * 6)).isoformat() for i in range(6)]
add_events(
    event_ids=[f"eval-c2-6h-{i:02d}" for i in range(6)],
    timestamps=timestamps,
    event_type="network.connection",
    source="windows_sysmon",
    is_suspicious=True,
    expected_category="c2_beacon_6h",
    host="WKSTN-14",
    user="CORP\\slee",
    network_info={
        "direction": "outbound",
        "local_address": "10.0.1.54",
        "remote_address": "198.51.100.99",
        "local_port": 50005,
        "remote_port": 4433,
        "protocol": "https",
    },
    process_info={
        "name": "wscript.exe",
        "path": "C:\\Windows\\System32\\wscript.exe",
        "pid": 7777,
        "ppid": 0,
        "command_line": "wscript.exe ...",
    },
    interval_seconds=21600,
)

# --- Benign: Legitimate software update (30 min, standard port 443) ---
timestamps = [(BASE + timedelta(minutes=i * 30)).isoformat() for i in range(6)]
add_events(
    event_ids=[f"eval-benign-update-{i:02d}" for i in range(6)],
    timestamps=timestamps,
    event_type="network.connection",
    source="windows_sysmon",
    is_suspicious=False,
    expected_category=None,
    host="WKSTN-20",
    user=None,
    network_info={
        "direction": "outbound",
        "local_address": "10.0.1.60",
        "remote_address": "40.70.12.100",
        "local_port": 51001,
        "remote_port": 443,
        "protocol": "https",
    },
    process_info={
        "name": "svchost.exe",
        "path": "C:\\Windows\\System32\\svchost.exe",
        "pid": 8888,
        "ppid": 0,
        "command_line": "svchost.exe -k netsvcs",
    },
    interval_seconds=1800,
)

# --- Benign: EDR heartbeat (1 hour, standard port 443) ---
timestamps = [(BASE + timedelta(hours=i)).isoformat() for i in range(6)]
add_events(
    event_ids=[f"eval-benign-edr-{i:02d}" for i in range(6)],
    timestamps=timestamps,
    event_type="network.connection",
    source="windows_sysmon",
    is_suspicious=False,
    expected_category=None,
    host="WKSTN-21",
    user=None,
    network_info={
        "direction": "outbound",
        "local_address": "10.0.1.61",
        "remote_address": "52.160.100.200",
        "local_port": 51002,
        "remote_port": 443,
        "protocol": "https",
    },
    process_info={
        "name": "EDRAgent.exe",
        "path": "C:\\Program Files\\EDR\\EDRAgent.exe",
        "pid": 9999,
        "ppid": 0,
        "command_line": "EDRAgent.exe --heartbeat",
    },
    interval_seconds=3600,
)

# --- Benign: Scheduled monitoring telemetry (6 hours, standard port 8080) ---
timestamps = [(BASE + timedelta(hours=i * 6)).isoformat() for i in range(6)]
add_events(
    event_ids=[f"eval-benign-mon-{i:02d}" for i in range(6)],
    timestamps=timestamps,
    event_type="network.connection",
    source="windows_sysmon",
    is_suspicious=False,
    expected_category=None,
    host="WKSTN-22",
    user=None,
    network_info={
        "direction": "outbound",
        "local_address": "10.0.1.62",
        "remote_address": "10.0.1.100",
        "local_port": 51003,
        "remote_port": 8080,
        "protocol": "http",
    },
    process_info={
        "name": "monitoring-agent.exe",
        "path": "C:\\Program Files\\Monitoring\\monitoring-agent.exe",
        "pid": 10000,
        "ppid": 0,
        "command_line": "monitoring-agent.exe --telemetry",
    },
    interval_seconds=21600,
)

# --- Benign: Legitimate admin HTTPS browsing (irregular, not beaconing) ---
admin_timestamps = [
    "2024-03-15T08:00:00Z",
    "2024-03-15T08:05:30Z",
    "2024-03-15T08:12:00Z",
    "2024-03-15T08:45:00Z",
    "2024-03-15T09:10:00Z",
    "2024-03-15T09:55:00Z",
]
add_events(
    event_ids=[f"eval-benign-admin-{i:02d}" for i in range(6)],
    timestamps=admin_timestamps,
    event_type="network.connection",
    source="windows_sysmon",
    is_suspicious=False,
    expected_category=None,
    host="WKSTN-23",
    user="CORP\\admin",
    network_info={
        "direction": "outbound",
        "local_address": "10.0.1.63",
        "remote_address": "example.com",
        "local_port": 51004,
        "remote_port": 443,
        "protocol": "https",
    },
    process_info={
        "name": "chrome.exe",
        "path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        "pid": 11111,
        "ppid": 0,
        "command_line": "chrome.exe https://example.com",
    },
    interval_seconds=None,
)


# ---------------------------------------------------------------------------
# Run detection on independent evaluation dataset
# ---------------------------------------------------------------------------


def run_independent_evaluation() -> str:
    """Run the independent C2 detection evaluation and return a text report.

    The report has the same format and metric semantics as the legacy
    ``evaluate_independent.py`` script, but is fully self-contained within
    the ``sentinelforge`` package and does not depend on repository-root
    files or the current working directory.
    """
    print(f"Independent evaluation dataset: {len(eval_events)} events")
    print(
        f"  Suspicious (ground truth): "
        f"{sum(1 for g in eval_ground_truth if g['is_suspicious'])}"
    )
    print(
        f"  Benign (ground truth): "
        f"{sum(1 for g in eval_ground_truth if not g['is_suspicious'])}"
    )

    registry = RuleRegistry()
    registry.register(C2BeaconRule())

    detection_results = registry.evaluate_all(eval_events)

    print(f"\nDetections: {len(detection_results)}")
    for r in detection_results:
        print(
            f"  {r.rule_id}: {len(r.evidence)} evidence events, "
            f"pattern_tier={r.metadata.get('pattern_tier', 'N/A')}, "
            f"mitre={r.metadata.get('mitre_attack_technique', 'N/A')}"
        )

    # ------------------------------------------------------------------
    # Calculate metrics per interval range
    # ------------------------------------------------------------------
    gt_lookup = {g["event_id"]: g for g in eval_ground_truth}

    detection_citations: dict[str, list] = {}
    for r in detection_results:
        for ev in r.evidence:
            detection_citations.setdefault(ev.event_id, []).append(r)

    all_suspicious_ids = {
        g["event_id"] for g in eval_ground_truth if g["is_suspicious"]
    }
    all_benign_ids = {
        g["event_id"] for g in eval_ground_truth if not g["is_suspicious"]
    }

    detected_ids = set()
    for r in detection_results:
        for ev in r.evidence:
            detected_ids.add(ev.event_id)

    all_tp = detected_ids & all_suspicious_ids
    all_fp = detected_ids & all_benign_ids
    all_fn = all_suspicious_ids - detected_ids

    overall_precision = (
        len(all_tp) / (len(all_tp) + len(all_fp))
        if (len(all_tp) + len(all_fp)) > 0
        else 0.0
    )
    overall_recall = (
        len(all_tp) / (len(all_tp) + len(all_fn))
        if (len(all_tp) + len(all_fn)) > 0
        else 0.0
    )
    overall_f1 = (
        2 * overall_precision * overall_recall
        / (overall_precision + overall_recall)
        if (overall_precision + overall_recall) > 0
        else 0.0
    )
    fpr = (
        len(all_fp) / len(all_benign_ids) if len(all_benign_ids) > 0 else 0.0
    )
    fnr = (
        len(all_fn) / len(all_suspicious_ids)
        if len(all_suspicious_ids) > 0
        else 0.0
    )

    lines: list[str] = []
    lines.append("=" * 80)
    lines.append("INDEPENDENT EVALUATION — OVERALL METRICS")
    lines.append("=" * 80)
    lines.append(f"Total suspicious (GT): {len(all_suspicious_ids)}")
    lines.append(f"Total benign (GT): {len(all_benign_ids)}")
    lines.append(f"Total detected: {len(detected_ids)}")
    lines.append(f"Overall True Positives: {len(all_tp)}")
    lines.append(f"Overall False Positives: {len(all_fp)}")
    lines.append(f"Overall False Negatives: {len(all_fn)}")
    lines.append(
        f"Overall Precision: {overall_precision:.4f} "
        f"({len(all_tp)}/{len(all_tp) + len(all_fp)})"
    )
    lines.append(
        f"Overall Recall: {overall_recall:.4f} "
        f"({len(all_tp)}/{len(all_tp) + len(all_fn)})"
    )
    lines.append(f"Overall F1: {overall_f1:.4f}")
    lines.append(f"False Positive Rate: {fpr:.4f} ({len(all_fp)}/{len(all_benign_ids)})")
    lines.append(
        f"False Negative Rate: {fnr:.4f} ({len(all_fn)}/{len(all_suspicious_ids)})"
    )

    # Per-interval-range breakdown
    lines.append("")
    lines.append("=" * 80)
    lines.append("INDEPENDENT EVALUATION — RESULTS BY INTERVAL RANGE")
    lines.append("=" * 80)

    interval_ranges = [
        ("30s", 0, 60),
        ("60s", 60, 300),
        ("5min", 300, 600),
        ("10min-1hr", 600, 3600),
        ("2hr-6hr", 3600, float("inf")),
        ("irregular/benign", None, None),
    ]

    for label, min_sec, max_sec in interval_ranges:
        if min_sec is None:
            # Irregular/benign admin browsing
            range_ids = {
                g["event_id"]
                for g in eval_ground_truth
                if g["interval_seconds"] is None
            }
        else:
            range_ids = {
                g["event_id"]
                for g in eval_ground_truth
                if g["interval_seconds"] is not None
                and min_sec <= g["interval_seconds"] < max_sec
            }

        if not range_ids:
            continue

        range_suspicious = {
            eid for eid in range_ids if gt_lookup[eid]["is_suspicious"]
        }
        range_benign = {
            eid for eid in range_ids if not gt_lookup[eid]["is_suspicious"]
        }

        range_detected = detected_ids & range_ids
        range_tp = range_detected & range_suspicious
        range_fp = range_detected & range_benign
        range_fn = range_suspicious - range_detected

        range_precision = (
            len(range_tp) / (len(range_tp) + len(range_fp))
            if (len(range_tp) + len(range_fp)) > 0
            else 0.0
        )
        range_recall = (
            len(range_tp) / (len(range_tp) + len(range_fn))
            if (len(range_tp) + len(range_fn)) > 0
            else 0.0
        )
        range_f1 = (
            2 * range_precision * range_recall
            / (range_precision + range_recall)
            if (range_precision + range_recall) > 0
            else 0.0
        )

        lines.append("")
        lines.append(f"--- {label} ---")
        lines.append(
            f"  Ground truth events: {len(range_ids)} "
            f"(suspicious: {len(range_suspicious)}, benign: {len(range_benign)})"
        )
        lines.append(f"  Detected: {len(range_detected)}")
        lines.append(f"  True Positives: {len(range_tp)}")
        lines.append(f"  False Positives: {len(range_fp)}")
        lines.append(f"  False Negatives: {len(range_fn)}")
        lines.append(f"  Precision: {range_precision:.4f}")
        lines.append(f"  Recall: {range_recall:.4f}")
        lines.append(f"  F1: {range_f1:.4f}")
        if range_fp:
            lines.append(f"  FP event IDs: {sorted(range_fp)}")
        if range_fn:
            lines.append(f"  FN event IDs: {sorted(range_fn)}")

    # Confidence distribution of detections
    lines.append("")
    lines.append("=" * 80)
    lines.append(
        "INDEPENDENT EVALUATION — CONFIDENCE DISTRIBUTION OF DETECTIONS"
    )
    lines.append("=" * 80)

    pattern_tier_counts: dict[str, int] = {}
    for r in detection_results:
        tier = r.metadata.get("pattern_tier", "unknown")
        pattern_tier_counts[tier] = pattern_tier_counts.get(tier, 0) + 1

    for tier in ("short_interval", "medium_interval", "long_interval", "unknown"):
        count = pattern_tier_counts.get(tier, 0)
        lines.append(f"  {tier}: {count} detection(s)")

    lines.append("")
    lines.append("=" * 80)
    lines.append("LIMITATION NOTICE")
    lines.append("=" * 80)
    lines.append(
        "Available telemetry (interval, port, protocol, process, destination IP)"
    )
    lines.append(
        "CANNOT reliably distinguish benign periodic traffic (software updates,"
    )
    lines.append(
        "EDR heartbeats, monitoring telemetry) from low-frequency C2 beaconing."
    )
    lines.append(
        "Both produce regular periodic connections. The detector reports all"
    )
    lines.append(
        "regular periodic traffic with interval-adjusted confidence — it does"
    )
    lines.append(
        "not claim to distinguish them. Analyst investigation with destination"
    )
    lines.append("reputation and process context is required.")
    lines.append("=" * 80)

    return "\n".join(lines)


def main() -> None:
    """Entry point for running the independent evaluation as a script."""
    print(run_independent_evaluation())


if __name__ == "__main__":
    main()
