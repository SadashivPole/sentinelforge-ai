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
from typing import Any

from sentinelforge.config import settings
from sentinelforge.datasets.evaluation import evaluate_detections
from sentinelforge.detection.base import RuleRegistry
from sentinelforge.detection.beacon import C2BeaconRule
from sentinelforge.detection.failed_logins import FailedLoginBurstRule
from sentinelforge.detection.password_spray import PasswordSprayRule
from sentinelforge.detection.powershell import SuspiciousPowerShellRule
from sentinelforge.detection.processtree import SuspiciousProcessTreeRule
from sentinelforge.ingestion.normalizer import normalize
from sentinelforge.ingestion.reader import LogParseError, reader_for
from sentinelforge.storage.database import Database
from sentinelforge.storage.repositories import (
    DetectionRepository,
    DuplicateIdCollisionError,
    EventRepository,
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


def _source_from_reader(reader: Any) -> str:
    """Map a reader instance to its source name for normalization.

    The reader is selected by content sniffing in reader_for(), so this
    mapping reflects the actual format detected, not the file extension.
    This ensures Sysmon-formatted content is normalized using Sysmon field
    mapping regardless of file extension.
    """
    from sentinelforge.ingestion.reader import (
        JSONLReader,
        JSONReader,
        SysmonReader,
    )

    if isinstance(reader, SysmonReader):
        return "sysmon"
    if isinstance(reader, JSONLReader):
        return "jsonl"
    if isinstance(reader, JSONReader):
        return "json"
    return "json"


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
    except Exception as exc:  # noqa: BLE001 - intentional broad catch for CLI error reporting
        print(f"ERROR: Failed to initialize database: {exc}", file=sys.stderr)
        return EXIT_ERROR

    event_repo = EventRepository(db)
    total_normalized = 0
    total_stored = 0
    total_skipped = 0
    total_rejected = 0
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

        # Determine source from the reader type (content sniffed), not the
        # file extension. This ensures Sysmon-formatted content is
        # normalized using Sysmon field mapping regardless of extension.
        source = _source_from_reader(reader)

        # Per-file record counter for stable, collision-free event id
        # generation. Position is sequential within this file; combined
        # with source_file and content hash it guarantees that identical
        # records at different positions or in different files receive
        # distinct ids.
        position = 0

        try:
            for raw in reader.read(input_path):
                position += 1
                total_normalized += 1
                try:
                    event = normalize(
                        raw,
                        source=source,
                        source_file=str(input_path),
                        position=position,
                    )
                    try:
                        event_repo.insert_event(event)
                        total_stored += 1
                    except DuplicateIdCollisionError:
                        # Idempotent re-ingest of same content — skip silently.
                        total_skipped += 1
                except ValueError as exc:
                    errors.append(f"Normalization error in {input_path}: {exc}")
            # Report rejected (non-dict) records from this reader.
            rejected = len(reader.skipped_records)
            total_rejected += rejected
            if rejected:
                for line_no, content, reason in reader.skipped_records:
                    print(
                        f"  Rejected record in {input_path} line {line_no}: "
                        f"{reason} ({content})"
                    )
        except LogParseError as exc:
            errors.append(f"Parse error in {input_path} line {exc.line_number}: {exc}")
        except OSError as exc:
            errors.append(f"Read error in {input_path}: {exc}")

    print("Ingestion complete.")
    print(f"  Files processed: {len(input_paths)}")
    print(f"  Events normalized: {total_normalized}")
    print(f"  Events stored: {total_stored}")
    print(f"  Duplicates skipped: {total_skipped}")
    print(f"  Records rejected: {total_rejected}")
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
            print(
                "ERROR: Database not initialized. Run 'ingest' first.", file=sys.stderr
            )
            return EXIT_ERROR
    except Exception as exc:  # noqa: BLE001 - intentional broad catch for CLI error reporting
        print(f"ERROR: Cannot read database schema: {exc}", file=sys.stderr)
        return EXIT_ERROR

    event_repo = EventRepository(db)
    detection_repo = DetectionRepository(db)

    # Safety guard: refuse to load all events when the database exceeds the
    # configured maximum. Unbounded fetchall() can exhaust memory on large
    # datasets; we never silently truncate.
    event_count = event_repo.count_events()
    if event_count > settings.max_detection_events:
        print(
            "ERROR: Database contains "
            f"{event_count} events, exceeding the configured maximum of "
            f"{settings.max_detection_events} for detection. "
            f"Increase SENTINELFORGE_MAX_DETECTION_EVENTS or reduce the "
            f"dataset before running detection.",
            file=sys.stderr,
        )
        return EXIT_ERROR

    # Load ALL events from the database (no arbitrary limit).
    # If the dataset is very large, this may use significant memory,
    # but processing all events is required for correct detection.
    events = event_repo.get_events(limit=None)
    if not events:
        print("No events found in database. Run 'ingest' first.")
        return EXIT_OK

    total_events = len(events)
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
    print("Detection complete.")
    print(f"  Events evaluated: {total_events}")
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


def _evaluate_builtin(output_path: str | None = None) -> int:
    """Run the built-in independent evaluation (packaged evaluator)."""
    import contextlib
    import io
    import sys

    from sentinelforge.datasets.independent_evaluation import main

    captured = io.StringIO()
    with contextlib.redirect_stdout(captured):
        try:
            main()
        except FileNotFoundError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return EXIT_ERROR

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
    """Evaluate stored detections against a ground-truth file.

    Uses the canonical evaluation implementation from
    sentinelforge.datasets.evaluation to compute alert-level and
    event-level metrics separately, avoiding mixed-population F1 scores.
    """
    db = Database(args.db_path)
    detection_repo = DetectionRepository(db)

    # Load ground truth.
    gt_path = Path(args.input)
    if not gt_path.exists():
        print(f"ERROR: Ground truth file not found: {gt_path}", file=sys.stderr)
        return EXIT_ERROR

    try:
        with open(gt_path, "r", encoding="utf-8") as fh:
            ground_truth = json.load(fh)
    except json.JSONDecodeError as exc:
        print(
            f"ERROR: Invalid JSON in ground truth file {gt_path}: {exc}",
            file=sys.stderr,
        )
        return EXIT_ERROR

    # Load ALL stored detections (no arbitrary limit).
    # Safety guard: refuse when the detection count exceeds the configured
    # maximum to avoid unbounded memory consumption.
    detection_count = detection_repo.count_detections()
    if detection_count > settings.max_detection_events:
        print(
            "ERROR: Database contains "
            f"{detection_count} detections, exceeding the configured maximum of "
            f"{settings.max_detection_events} for evaluation. "
            f"Increase SENTINELFORGE_MAX_DETECTION_EVENTS or reduce the "
            f"dataset before running evaluation.",
            file=sys.stderr,
        )
        return EXIT_ERROR

    detections = detection_repo.get_detections(limit=None)
    total_detections = len(detections)
    if total_detections == 0:
        print("No detections found in database. Run 'detect' first.")
        return EXIT_OK

    # Run canonical evaluation: alert-level and event-level metrics computed
    # separately, with F1 marked valid only when unit and population match.
    results = evaluate_detections(
        dataset_id=gt_path.stem,
        detection_results=detections,
        event_ground_truth=ground_truth,
    )

    print("Evaluation complete.")
    print(f"  Dataset: {results.dataset_id}")
    print(f"  Total ground truth events: {results.total_events}")
    print(f"    Suspicious: {results.suspicious_events}")
    print(f"    Benign: {results.benign_events}")
    print(f"    Unlabeled: {results.unlabeled_events}")
    print(f"  Detection alerts loaded: {total_detections}")
    print()
    print("  Alert-level evaluation:")
    al = results.alert_level
    print(f"    Total alerts: {al.total_alerts}")
    print(f"    True positives: {al.true_positive_alerts}")
    print(f"    False positives: {al.false_positive_alerts}")
    print(f"    Attribution errors: {al.attribution_error_alerts}")
    print(f"    Unassessed: {al.unassessed_alerts}")
    print(f"    Assessed: {al.assessed_alerts}")
    print(f"    Precision: {al.precision:.4f}")
    print(f"    Assessment coverage: {al.assessment_coverage:.4f}")
    print()
    print("  Event-level evaluation:")
    el = results.event_level
    print(f"    Total suspicious: {el.total_suspicious_events}")
    print(f"    Detected: {el.detected_suspicious_events}")
    print(f"    Undetected: {el.undetected_suspicious_events}")
    print(f"    Recall: {el.recall:.4f}")
    print()
    print("  F1 scores:")
    fa = results.f1_alert
    fe = results.f1_event
    print(
        f"    Alert-level:  valid={fa.valid}, precision={fa.precision}, "
        f"recall={fa.recall}, f1={fa.f1_score} ({fa.formula})"
    )
    print(
        f"    Event-level:  valid={fe.valid}, precision={fe.precision}, "
        f"recall={fe.recall}, f1={fe.f1_score} ({fe.formula})"
    )

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        results.write_json(output_path)
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
    p_ingest = subparsers.add_parser(
        "ingest", help="Ingest log files into the database"
    )
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
    p_eval = subparsers.add_parser("evaluate", help="Evaluate detection quality")
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


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return EXIT_OK

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
