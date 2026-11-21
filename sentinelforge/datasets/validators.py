"""Dataset validation utilities.

Validates generated synthetic datasets for schema correctness, unique event
IDs, timestamp validity, referential integrity, host consistency, and
ground-truth completeness.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _iso_ok(value: str) -> bool:
    """Return True if value is a parseable ISO-8601 timestamp."""
    try:
        text = value.replace("Z", "+00:00")
        dt = datetime.fromisoformat(text)
        return dt.tzinfo is not None
    except (ValueError, AttributeError):
        return False


def validate_dataset(output_dir: str | Path) -> dict[str, Any]:
    """Run all validation checks on a generated dataset.

    Returns a dict with check results and any errors.
    """
    output_dir = Path(output_dir)
    results: dict[str, Any] = {
        "valid": True,
        "checks": {},
        "errors": [],
    }

    # --- Load category files ---
    categories = [
        "windows_sysmon", "linux_auth", "firewall", "dns",
        "network", "correlated_attacks", "benign_activity",
    ]
    all_events: list[dict] = []
    events_by_category: dict[str, list[dict]] = {}

    for cat in categories:
        filepath = output_dir / f"{cat}.jsonl"
        events: list[dict] = []
        if filepath.exists():
            with open(filepath, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        events.append(json.loads(line))
            all_events.extend(events)
        events_by_category[cat] = events

    # --- Check 1: Total event count ---
    total = len(all_events)
    results["checks"]["total_event_count"] = {
        "value": total,
        "passed": total >= 10000,
    }
    if total < 10000:
        results["valid"] = False
        results["errors"].append(f"Total event count {total} < 10000")

    # --- Check 2: Unique event IDs ---
    event_ids = [e.get("event_id") for e in all_events if e.get("event_id")]
    unique_ids = set(event_ids)
    results["checks"]["unique_event_ids"] = {
        "total": len(event_ids),
        "unique": len(unique_ids),
        "passed": len(event_ids) == len(unique_ids),
    }
    if len(event_ids) != len(unique_ids):
        results["valid"] = False
        results["errors"].append("Duplicate event IDs found")

    # --- Check 3: Schema correctness ---
    required_fields = {"event_id", "timestamp", "event_type", "host", "user", "source"}
    schema_errors = 0
    for ev in all_events:
        missing = required_fields - set(ev.keys())
        if missing:
            schema_errors += 1
    results["checks"]["schema_correctness"] = {
        "errors": schema_errors,
        "passed": schema_errors == 0,
    }
    if schema_errors > 0:
        results["valid"] = False
        results["errors"].append(f"{schema_errors} events missing required fields")

    # --- Check 4: Timestamp validity ---
    ts_errors = 0
    for ev in all_events:
        ts = ev.get("timestamp")
        if ts and not _iso_ok(ts):
            ts_errors += 1
    results["checks"]["timestamp_validity"] = {
        "errors": ts_errors,
        "passed": ts_errors == 0,
    }
    if ts_errors > 0:
        results["valid"] = False
        results["errors"].append(f"{ts_errors} events have invalid timestamps")

    # --- Check 5: Host consistency ---
    hosts_in_dataset: set[str] = set()
    for ev in all_events:
        h = ev.get("host")
        if h:
            hosts_in_dataset.add(h)
    results["checks"]["host_consistency"] = {
        "distinct_hosts": len(hosts_in_dataset),
        "hosts": sorted(hosts_in_dataset),
        "passed": len(hosts_in_dataset) >= 2,
    }

    # --- Check 6: Ground truth completeness ---
    gt_path = output_dir / "ground_truth.json"
    gt_entries = 0
    gt_event_ids: set[str] = set()
    if gt_path.exists():
        with open(gt_path, "r", encoding="utf-8") as fh:
            gt_data = json.load(fh)
        gt_entries = gt_data.get("entry_count", 0)
        for entry in gt_data.get("entries", []):
            gt_event_ids.update(entry.get("event_ids", []))

    # All ground-truth event IDs must exist in the dataset
    missing_gt_ids = gt_event_ids - set(event_ids)
    results["checks"]["ground_truth_completeness"] = {
        "entries": gt_entries,
        "labelled_events": len(gt_event_ids),
        "missing_from_dataset": len(missing_gt_ids),
        "passed": len(missing_gt_ids) == 0 and gt_entries > 0,
    }
    if missing_gt_ids:
        results["valid"] = False
        results["errors"].append(f"{len(missing_gt_ids)} ground-truth event IDs not in dataset")

    # --- Check 7: Ground truth separate from raw events ---
    # Verify no raw event contains classification labels
    label_fields = {"classification", "benign", "suspicious", "ground_truth", "label"}
    leaked = 0
    for ev in all_events:
        if label_fields & set(ev.keys()):
            leaked += 1
    results["checks"]["no_label_leakage"] = {
        "events_with_labels": leaked,
        "passed": leaked == 0,
    }
    if leaked > 0:
        results["valid"] = False
        results["errors"].append(f"{leaked} raw events contain ground-truth labels")

    # --- Check 8: Valid JSON/JSONL ---
    json_errors = 0
    for cat in categories:
        filepath = output_dir / f"{cat}.jsonl"
        if filepath.exists():
            with open(filepath, "r", encoding="utf-8") as fh:
                for line_num, line in enumerate(fh, 1):
                    line = line.strip()
                    if line:
                        try:
                            json.loads(line)
                        except json.JSONDecodeError:
                            json_errors += 1
    results["checks"]["valid_jsonl"] = {
        "errors": json_errors,
        "passed": json_errors == 0,
    }
    if json_errors > 0:
        results["valid"] = False
        results["errors"].append(f"{json_errors} invalid JSON lines")

    # --- Check 9: Dataset manifest ---
    manifest_path = output_dir / "dataset_manifest.json"
    results["checks"]["dataset_manifest"] = {
        "exists": manifest_path.exists(),
        "passed": manifest_path.exists(),
    }

    return results
