"""SentinelForge AI command-line interface.

Provides a lightweight CLI for ingesting logs, running detection rules,
and evaluating detection quality. Reuses existing ingestion, detection,
and storage services — no business logic is duplicated.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

from sentinelforge.config import settings
from sentinelforge.detection.base import RuleRegistry
from sentinelforge.detection.beacon import C2BeaconRule
from sentinelforge.detection.failed_logins import FailedLoginBurstRule
from sentinelforge.detection.password_spray import PasswordSprayRule
from sentinelforge.detection.powershell import SuspiciousPowerShellRule
from sentinelforge.detection.processtree import SuspiciousProcessTreeRule
from sentinelforge.ingestion.normalizer import normalize
from sentinelforge.ingestion.reader import LogParseError, reader_for
from sentinelforge.risk.correlator import DetectionCorrelator
from sentinelforge.risk.scorer import RiskScorer
from sentinelforge.storage.database import Database
from sentinelforge.storage.repositories import (
    DetectionRepository,
    DuplicateIdCollisionError,
    EventRepository,
    RiskAssessmentRepository,
)

EXIT_OK = 0
EXIT_ERROR = 1


def _build_registry() -> RuleRegistry:
    """Build and register all detection rules."""
    registry = RuleRegistry()
    registry.register(FailedLoginBurstRule())
    registry.register(PasswordSprayRule())
    registry.register(SuspiciousPowerShellRule())
    registry.register(SuspiciousProcessTreeRule())
    registry.register(C2BeaconRule())
    return registry


# ---------------------------------------------------------------------------
# ingest command
# ---------------------------------------------------------------------------

def cmd_ingest(args: argparse.Namespace) -> int:
    """Ingest log files into the SQLite database.

    Reads one or more log files (JSON, JSONL, or Sysmon-converted JSON),
    normalizes each event, and stores immutable records in SQLite.
    """
    input_paths = [Path(p) for p in args.input]
    db = Database(args.db_path)

    try:
        db.initialize()
    except Exception as exc:
        print(f"ERROR: Failed to initialize database: {exc}", file=sys.stderr)
        return EXIT_ERROR

    event_repo = EventRepository(db)
    total_normalized = 0
    total_stored = 0
    total_skipped = 0
    errors: list[str] = []

    for input_path in input_paths:
        if not input_path.exists():
            errors.append(f"Input file not found: {input_path}")
            continue

        try:
            reader = reader_for(input_path)
        except (OSError, UnicodeDecodeError) as exc:
            errors.append(f"Cannot open {input_path}: {exc}")
            continue

        source = input_path.suffix.lower().lstrip(".") or "json"
        if source not in ("json", "jsonl", "sysmon"):
            source = "json"

        try:
            for raw in reader.read(input_path):
                total_normalized += 1
                try:
                    event = normalize(raw, source=source)
                    try:
                        event_repo.insert_event(event)
                        total_stored += 1
                    except DuplicateIdCollisionError:
                        # Idempotent re-ingest of same content — skip silently.
                        total_skipped += 1
                except ValueError as exc:
                    errors.append(f"Normalization error in {input_path}: {exc}")
        except LogParseError as exc:
            errors.append(f"Parse error in {input_path} line {exc.line_number}: {exc}")
        except OSError as exc:
            errors.append(f"Read error in {input_path}: {exc}")

    print(f"Ingestion complete.")
    print(f"  Files processed: {len(input_paths)}")
    print(f"  Events normalized: {total_normalized}")
    print(f"  Events stored: {total_stored}")
    print(f"  Duplicates skipped: {total_skipped}")
    if errors:
        print(f"  Errors: {len(errors)}")
        for err in errors[:10]:
            print(f"    - {err}")
        if len(errors) > 10:
            print(f"    ... and {len(errors) - 10} more")
        return EXIT_ERROR
    return EXIT_OK


# ---------------------------------------------------------------------------
# detect command
# ---------------------------------------------------------------------------

def cmd_detect(args: argparse.Namespace) -> int:
    """Run detection rules on stored events and optionally write results."""
    db = Database(args.db_path)

    try:
        version = db.schema_version()
        if version is None:
            print("ERROR: Database not initialized. Run 'ingest' first.", file=sys.stderr)
            return EXIT_ERROR
    except Exception as exc:
        print(f"ERROR: Cannot read database schema: {exc}", file=sys.stderr)
        return EXIT_ERROR

    event_repo = EventRepository(db)
    detection_repo = DetectionRepository(db)

    # Load all events from the database.
    events = event_repo.get_events(limit=100_000)
    if not events:
        print("No events found in database. Run 'ingest' first.")
        return EXIT_OK

    registry = _build_registry()
    results = registry.evaluate_all(events)

    # Persist detections and evidence.
    total_stored = 0
    for result in results:
        try:
            detection_repo.insert_detection(result)
            total_stored += 1
        except DuplicateIdCollisionError:
            # Idempotent re-detection — skip.
            pass

    # Print summary.
    print(f"Detection complete.")
    print(f"  Events evaluated: {len(events)}")
    print(f"  Detection alerts: {len(results)}")
    print(f"  Alerts stored: {total_stored}")

    # Per-rule breakdown.
    rule_counts: dict[str, int] = {}
    for r in results:
        rule_counts[r.rule_id] = rule_counts.get(r.rule_id, 0) + 1
    if rule_counts:
        print("  Alerts by rule:")
        for rule_id, count in sorted(rule_counts.items()):
            print(f"    - {rule_id}: {count}")

    # Optional structured output.
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_data = []
        for r in results:
            output_data.append(
                {
                    "rule_id": r.rule_id,
                    "rule_name": r.rule_name,
                    "severity": r.severity.value,
                    "description": r.description,
                    "detection_id": r.detection_id,
                    "triggered_at": r.triggered_at,
                    "metadata": r.metadata,
                    "evidence_count": len(r.evidence),
                    "evidence": [
                        {
                            "event_id": ev.event_id,
                            "timestamp": ev.timestamp,
                            "source": ev.source,
                            "event_type": ev.event_type,
                            "user": ev.user,
                            "host": ev.host,
                            "source_address": ev.source_address,
                            "raw": ev.raw,
                        }
                        for ev in r.evidence
                    ],
                }
            )
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(output_data, fh, indent=2)
        print(f"  Results written to: {output_path}")

    return EXIT_OK


# ---------------------------------------------------------------------------
# evaluate command
# ---------------------------------------------------------------------------

def cmd_evaluate(args: argparse.Namespace) -> int:
    """Run detection quality evaluation.

    Without --input, runs the built-in independent evaluation
    (evaluate_independent.py logic) against generated synthetic data.
    With --input, evaluates detection results stored in the database
    against a ground-truth JSON file.
    """
    if args.input:
        return _evaluate_from_db(args)
    return _evaluate_builtin(output_path=args.output)


def _evaluate_builtin(output_path: Optional[str] = None) -> int:
    """Run the built-in independent evaluation (same logic as evaluate_independent.py)."""
    import contextlib
    import importlib.util
    import io

    spec = importlib.util.spec_from_file_location(
        "evaluate_independent", "evaluate_independent.py"
    )
    if spec is None or spec.loader is None:
        print("ERROR: Cannot locate evaluate_independent.py", file=sys.stderr)
        return EXIT_ERROR

    module = importlib.util.module_from_spec(spec)

    # Capture the module's stdout so we can write it to the output file if requested.
    captured = io.StringIO()
    with contextlib.redirect_stdout(captured):
        spec.loader.exec_module(module)

    output_text = captured.getvalue()
    sys.stdout.write(output_text)

    if output_path:
        output_path_obj = Path(output_path)
        output_path_obj.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path_obj, "w", encoding="utf-8") as fh:
            fh.write(output_text)
        print(f"  Report written to: {output_path_obj}")

    return EXIT_OK


def _evaluate_from_db(args: argparse.Namespace) -> int:
    """Evaluate stored detections against a ground-truth file."""
    db = Database(args.db_path)
    detection_repo = DetectionRepository(db)
    event_repo = EventRepository(db)

    # Load ground truth.
    gt_path = Path(args.input)
    if not gt_path.exists():
        print(f"ERROR: Ground truth file not found: {gt_path}", file=sys.stderr)
        return EXIT_ERROR

    try:
        with open(gt_path, "r", encoding="utf-8") as fh:
            ground_truth = json.load(fh)
    except json.JSONDecodeError as exc:
        print(f"ERROR: Invalid JSON in ground truth file {gt_path}: {exc}", file=sys.stderr)
        return EXIT_ERROR

    gt_entries = ground_truth.get("entries", ground_truth)
    gt_lookup: dict[str, dict] = {}
    for entry in gt_entries:
        for eid in entry.get("event_ids", []):
            gt_lookup[eid] = entry

    # Load stored detections.
    detections = detection_repo.get_detections(limit=100_000)
    if not detections:
        print("No detections found in database. Run 'detect' first.")
        return EXIT_OK

    # Build detection citations: event_id -> list of detections.
    suspicious_ids = {
        eid for eid, g in gt_lookup.items() if g.get("classification") == "suspicious"
    }
    benign_ids = {
        eid for eid, g in gt_lookup.items() if g.get("classification") == "benign"
    }

    detected_ids: set[str] = set()
    for det in detections:
        for ev in det.evidence:
            detected_ids.add(ev.event_id)

    tp = detected_ids & suspicious_ids
    fp = detected_ids & benign_ids
    fn = suspicious_ids - detected_ids

    precision = len(tp) / (len(tp) + len(fp)) if (len(tp) + len(fp)) > 0 else 0.0
    recall = len(tp) / (len(tp) + len(fn)) if (len(tp) + len(fn)) > 0 else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) > 0
        else 0.0
    )

    print(f"Evaluation complete.")
    print(f"  Ground truth events: {len(gt_lookup)}")
    print(f"    Suspicious: {len(suspicious_ids)}")
    print(f"    Benign: {len(benign_ids)}")
    print(f"  Detection results: {len(detections)}")
    print(f"  Unique events detected: {len(detected_ids)}")
    print(f"  True Positives: {len(tp)}")
    print(f"  False Positives: {len(fp)}")
    print(f"  False Negatives: {len(fn)}")
    print(f"  Precision: {precision:.4f}")
    print(f"  Recall: {recall:.4f}")
    print(f"  F1: {f1:.4f}")

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        report = {
            "total_ground_truth": len(gt_lookup),
            "suspicious_count": len(suspicious_ids),
            "benign_count": len(benign_ids),
            "detection_count": len(detections),
            "detected_event_count": len(detected_ids),
            "true_positives": len(tp),
            "false_positives": len(fp),
            "false_negatives": len(fn),
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "tp_event_ids": sorted(tp),
            "fp_event_ids": sorted(fp),
            "fn_event_ids": sorted(fn),
        }
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        print(f"  Report written to: {output_path}")

    return EXIT_OK


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinelforge",
        description="SentinelForge AI — SOC log analysis and detection CLI.",
    )
    parser.add_argument(
        "--db-path",
        default=settings.db_path,
        help=f"SQLite database path (default: {settings.db_path})",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # ingest
    p_ingest = subparsers.add_parser("ingest", help="Ingest log files into the database")
    p_ingest.add_argument(
        "input",
        nargs="+",
        help="One or more log file paths (JSON, JSONL, or Sysmon-converted JSON)",
    )
    p_ingest.set_defaults(func=cmd_ingest)

    # detect
    p_detect = subparsers.add_parser(
        "detect", help="Run detection rules on stored events"
    )
    p_detect.add_argument(
        "--output",
        help="Write detection results to a JSON file",
    )
    p_detect.set_defaults(func=cmd_detect)

    # evaluate
    p_eval = subparsers.add_parser(
        "evaluate", help="Evaluate detection quality"
    )
    p_eval.add_argument(
        "--input",
        help="Ground truth JSON file for database-backed evaluation",
    )
    p_eval.add_argument(
        "--output",
        help="Write evaluation report to a JSON file",
    )
    p_eval.set_defaults(func=cmd_evaluate)

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return EXIT_OK

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
