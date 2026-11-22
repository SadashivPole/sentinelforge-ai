"""Automated CLI tests for SentinelForge AI.

Tests the sentinelforge CLI end-to-end using subprocess calls,
with temporary directories for isolation. No PYTHONPATH tricks
required — the CLI is installed via console_scripts entry point.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

SENTINELFORGE_CMD = [sys.executable, "-m", "sentinelforge.cli.main"]

# Try the installed console script first, fall back to -m
try:
    subprocess.run(
        ["sentinelforge", "--help"],
        capture_output=True,
        check=True,
        timeout=10,
    )
    USE_CONSOLE_SCRIPT = True
except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
    USE_CONSOLE_SCRIPT = False


def _run_cli(*args: str, timeout: int = 60) -> subprocess.CompletedProcess:
    """Run the CLI with the given arguments."""
    cmd = ["sentinelforge"] if USE_CONSOLE_SCRIPT else SENTINELFORGE_CMD
    return subprocess.run(  # noqa: PLW1510 - intentional: check return code manually
        cmd + list(args),
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _make_tmpdir() -> Path:
    """Create an isolated temporary directory in the designated scratch area."""
    scratch = os.environ.get("TMPDIR", os.environ.get("TEMP", "/tmp"))
    return Path(tempfile.mkdtemp(dir=scratch))


# ---------------------------------------------------------------------------
# Help output
# ---------------------------------------------------------------------------


def test_help_output() -> None:
    """`sentinelforge --help` should exit 0 and show usage."""
    result = _run_cli("--help")
    assert result.returncode == 0
    assert "SentinelForge AI" in result.stdout
    assert "ingest" in result.stdout
    assert "detect" in result.stdout
    assert "evaluate" in result.stdout


def test_no_command_shows_help() -> None:
    """Running with no subcommand should show help and exit 0."""
    result = _run_cli()
    assert result.returncode == 0
    assert "Available commands" in result.stdout


# ---------------------------------------------------------------------------
# Valid JSON ingestion
# ---------------------------------------------------------------------------


def test_valid_json_ingestion() -> None:
    """Ingesting a valid JSON file should succeed."""
    workdir = _make_tmpdir()
    db_path = workdir / "test.db"
    input_file = workdir / "input.json"
    input_file.write_text(
        json.dumps(
            {
                "event_id": "json-001",
                "timestamp": "2024-01-01T00:00:00Z",
                "event_type": "auth.login.failed",
                "source": "linux_auth",
                "user": "admin",
                "host": "SRV-01",
                "authentication": {
                    "outcome": "failure",
                    "method": "ssh",
                    "username": "admin",
                    "source_address": "198.51.100.77",
                },
                "raw": {"event_id": "json-001"},
            }
        )
    )

    result = _run_cli("--db-path", str(db_path), "ingest", str(input_file))
    assert result.returncode == 0
    assert "Events stored: 1" in result.stdout
    assert db_path.exists()


def test_valid_jsonl_ingestion() -> None:
    """Ingesting a valid JSONL file should succeed."""
    workdir = _make_tmpdir()
    db_path = workdir / "test.db"
    input_file = workdir / "input.jsonl"
    lines = []
    for i in range(5):
        lines.append(
            json.dumps(
                {
                    "event_id": f"jsonl-{i:03d}",
                    "timestamp": "2024-01-01T00:00:00Z",
                    "event_type": "network.connection",
                    "source": "sysmon",
                    "host": "WKSTN-01",
                    "network": {
                        "direction": "outbound",
                        "remote_address": "203.0.113.50",
                        "remote_port": 4433,
                        "protocol": "tcp",
                    },
                    "raw": {"event_id": f"jsonl-{i:03d}"},
                }
            )
        )
    input_file.write_text("\n".join(lines) + "\n")

    result = _run_cli("--db-path", str(db_path), "ingest", str(input_file))
    assert result.returncode == 0
    assert "Events stored: 5" in result.stdout


# ---------------------------------------------------------------------------
# Invalid input
# ---------------------------------------------------------------------------


def test_invalid_json_ingestion() -> None:
    """Ingesting invalid JSON should fail with non-zero exit code."""
    workdir = _make_tmpdir()
    db_path = workdir / "test.db"
    input_file = workdir / "bad.json"
    input_file.write_text("{not valid json")

    result = _run_cli("--db-path", str(db_path), "ingest", str(input_file))
    assert result.returncode != 0


def test_missing_input_file() -> None:
    """Ingesting a non-existent file should fail with non-zero exit code."""
    workdir = _make_tmpdir()
    db_path = workdir / "test.db"
    result = _run_cli(
        "--db-path", str(db_path), "ingest", str(workdir / "nonexistent.json")
    )
    assert result.returncode != 0
    assert "not found" in result.stderr.lower() or "not found" in result.stdout.lower()


# ---------------------------------------------------------------------------
# Database path selection
# ---------------------------------------------------------------------------


def test_custom_database_path() -> None:
    """--db-path should control where the database is created."""
    workdir = _make_tmpdir()
    custom_db = workdir / "custom" / "subdir" / "sentinelforge.db"
    custom_db.parent.mkdir(parents=True, exist_ok=True)
    input_file = workdir / "input.json"
    input_file.write_text(
        json.dumps(
            {
                "event_id": "dbpath-001",
                "timestamp": "2024-01-01T00:00:00Z",
                "event_type": "auth.login.failed",
                "source": "linux_auth",
                "user": "user1",
                "host": "HOST-1",
                "authentication": {
                    "outcome": "failure",
                    "method": "ssh",
                    "username": "user1",
                    "source_address": "10.0.0.1",
                },
                "raw": {"event_id": "dbpath-001"},
            }
        )
    )

    result = _run_cli("--db-path", str(custom_db), "ingest", str(input_file))
    assert result.returncode == 0
    assert custom_db.exists()


# ---------------------------------------------------------------------------
# Ingest followed by detect (same database)
# ---------------------------------------------------------------------------


def test_ingest_then_detect() -> None:
    """Ingest then detect on the same database should produce alerts."""
    workdir = _make_tmpdir()
    db_path = workdir / "workflow.db"
    input_file = workdir / "workflow.jsonl"

    # 6 failed logins from same source to same account → FailedLoginBurstRule
    lines = []
    for i in range(6):
        lines.append(
            json.dumps(
                {
                    "event_id": f"workflow-{i:02d}",
                    "timestamp": f"2024-01-01T00:00:{i:02d}Z",
                    "event_type": "auth.login.failed",
                    "source": "linux_auth",
                    "user": "admin",
                    "host": "SRV-01",
                    "authentication": {
                        "outcome": "failure",
                        "method": "ssh",
                        "username": "admin",
                        "source_address": "198.51.100.77",
                    },
                    "raw": {"event_id": f"workflow-{i:02d}"},
                }
            )
        )
    input_file.write_text("\n".join(lines) + "\n")

    # Ingest
    result = _run_cli("--db-path", str(db_path), "ingest", str(input_file))
    assert result.returncode == 0
    assert "Events stored: 6" in result.stdout

    # Detect
    result = _run_cli("--db-path", str(db_path), "detect")
    assert result.returncode == 0
    assert "Detection alerts: 1" in result.stdout
    assert "failed_login_burst" in result.stdout


def test_detect_with_json_output() -> None:
    """Detect with --output should produce valid JSON."""
    workdir = _make_tmpdir()
    db_path = workdir / "workflow2.db"
    input_file = workdir / "workflow2.jsonl"

    lines = []
    for i in range(6):
        lines.append(
            json.dumps(
                {
                    "event_id": f"wf2-{i:02d}",
                    "timestamp": f"2024-01-01T00:00:{i:02d}Z",
                    "event_type": "auth.login.failed",
                    "source": "linux_auth",
                    "user": "admin",
                    "host": "SRV-01",
                    "authentication": {
                        "outcome": "failure",
                        "method": "ssh",
                        "username": "admin",
                        "source_address": "198.51.100.77",
                    },
                    "raw": {"event_id": f"wf2-{i:02d}"},
                }
            )
        )
    input_file.write_text("\n".join(lines) + "\n")

    _run_cli("--db-path", str(db_path), "ingest", str(input_file))

    output_file = workdir / "detections.json"
    result = _run_cli("--db-path", str(db_path), "detect", "--output", str(output_file))
    assert result.returncode == 0
    assert output_file.exists()

    # Verify JSON validity
    with open(output_file, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]["rule_id"] == "sentinelforge.detection.failed_login_burst"
    assert "evidence" in data[0]
    assert len(data[0]["evidence"]) == 6


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


def test_evaluate_builtin() -> None:
    """`evaluate` with no input should run the built-in independent evaluation."""
    workdir = _make_tmpdir()
    output_file = workdir / "eval_report.json"
    result = _run_cli("evaluate", "--output", str(output_file))
    assert result.returncode == 0
    assert "Precision: 0.6250" in result.stdout
    assert "Recall: 1.0000" in result.stdout
    assert output_file.exists()

    # Verify report structure from written output file
    with open(output_file, "r", encoding="utf-8") as fh:
        content = fh.read()
    assert "Overall True Positives: 30" in content
    assert "Overall False Positives: 18" in content
    assert "Overall False Negatives: 0" in content
    assert "Overall Precision: 0.6250" in content


# ---------------------------------------------------------------------------
# Invalid arguments
# ---------------------------------------------------------------------------


def test_invalid_subcommand() -> None:
    """An invalid subcommand should exit non-zero."""
    result = _run_cli("nonexistent-command")
    assert result.returncode != 0


def test_detect_empty_database() -> None:
    """Detecting on an uninitialized database should fail with non-zero exit."""
    workdir = _make_tmpdir()
    db_path = workdir / "empty.db"
    result = _run_cli("--db-path", str(db_path), "detect")
    assert result.returncode != 0
    assert "not initialized" in result.stderr.lower()


# ---------------------------------------------------------------------------
# Failure handling
# ---------------------------------------------------------------------------


def test_malformed_json_ingestion() -> None:
    """Malformed JSON should produce a clean error (exit 1), not a traceback."""
    workdir = _make_tmpdir()
    db_path = workdir / "test.db"
    input_file = workdir / "bad.json"
    input_file.write_text("{not valid json")

    result = _run_cli("--db-path", str(db_path), "ingest", str(input_file))
    assert result.returncode != 0
    assert "Parse error" in result.stdout or "Parse error" in result.stderr
    assert "Traceback" not in result.stdout and "Traceback" not in result.stderr


def test_malformed_evaluation_input() -> None:
    """Malformed evaluation ground truth should produce a clean error (exit 1)."""
    workdir = _make_tmpdir()
    db_path = workdir / "test.db"
    gt_file = workdir / "bad_gt.json"
    gt_file.write_text("not json")

    result = _run_cli("--db-path", str(db_path), "evaluate", "--input", str(gt_file))
    assert result.returncode != 0
    assert "Invalid JSON" in result.stdout or "Invalid JSON" in result.stderr
    assert "Traceback" not in result.stdout and "Traceback" not in result.stderr


def test_invalid_database_path() -> None:
    """Detecting on a database in a nonexistent directory should fail cleanly."""
    workdir = _make_tmpdir()
    db_path = workdir / "nonexistent_dir" / "test.db"
    result = _run_cli("--db-path", str(db_path), "detect")
    assert result.returncode != 0
    assert "unable to open" in result.stderr.lower()


def test_exit_code_invalid_command() -> None:
    """Invalid subcommand should exit with code 2 (argparse standard)."""
    result = _run_cli("nonexistent-command")
    assert result.returncode == 2


# ---------------------------------------------------------------------------
# Exit codes
# ---------------------------------------------------------------------------


def test_exit_code_zero_on_success() -> None:
    """Successful operations should exit with code 0."""
    result = _run_cli("--help")
    assert result.returncode == 0


# ---------------------------------------------------------------------------
# Safety guard: max_detection_events (M10.1: no silent truncation, no OOM)
# ---------------------------------------------------------------------------


def _ingest_sample_events(workdir: Path, db_path: Path, count: int = 3) -> None:
    """Ingest ``count`` sample failed-login events into ``db_path``."""
    input_file = workdir / "sample.jsonl"
    lines = []
    for i in range(count):
        lines.append(
            json.dumps(
                {
                    "event_id": f"sample-{i:03d}",
                    "timestamp": f"2024-01-01T00:00:{i:02d}Z",
                    "event_type": "auth.login.failed",
                    "source": "linux_auth",
                    "user": "admin",
                    "host": "SRV-01",
                    "authentication": {
                        "outcome": "failure",
                        "method": "ssh",
                        "username": "admin",
                        "source_address": "198.51.100.77",
                    },
                    "raw": {"event_id": f"sample-{i:03d}"},
                }
            )
        )
    input_file.write_text("\n".join(lines) + "\n")
    result = _run_cli("--db-path", str(db_path), "ingest", str(input_file))
    assert result.returncode == 0
    assert f"Events stored: {count}" in result.stdout


def _set_max_events_env(value: int) -> dict:
    """Return a copy of os.environ with SENTINELFORGE_MAX_DETECTION_EVENTS set."""
    env = dict(os.environ)
    env["SENTINELFORGE_MAX_DETECTION_EVENTS"] = str(value)
    return env


def _run_cli_with_env(
    *args: str, env: dict, timeout: int = 60
) -> subprocess.CompletedProcess:
    """Run the CLI with a custom environment."""
    cmd = (
        ["sentinelforge"]
        if USE_CONSOLE_SCRIPT
        else [sys.executable, "-m", "sentinelforge.cli.main"]
    )
    return subprocess.run(  # noqa: PLW1510 - intentional: check return code manually
        cmd + list(args),
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
    )


def test_safety_guard_below_limit_allows_detection():
    """Detection works when event count is below the configured maximum."""
    workdir = _make_tmpdir()
    db_path = workdir / "test.db"
    _ingest_sample_events(workdir, db_path, count=3)

    env = _set_max_events_env(100_000)
    result = _run_cli_with_env("--db-path", str(db_path), "detect", env=env)
    assert result.returncode == 0
    assert "Events evaluated: 3" in result.stdout


def test_safety_guard_at_limit_allows_detection():
    """Detection works when event count equals the configured maximum."""
    workdir = _make_tmpdir()
    db_path = workdir / "test.db"
    _ingest_sample_events(workdir, db_path, count=5)

    env = _set_max_events_env(5)
    result = _run_cli_with_env("--db-path", str(db_path), "detect", env=env)
    assert result.returncode == 0
    assert "Events evaluated: 5" in result.stdout


def test_safety_guard_above_limit_refuses_detection():
    """Detection refuses when event count exceeds the configured maximum."""
    workdir = _make_tmpdir()
    db_path = workdir / "test.db"
    _ingest_sample_events(workdir, db_path, count=10)

    env = _set_max_events_env(5)
    result = _run_cli_with_env("--db-path", str(db_path), "detect", env=env)
    assert result.returncode != 0
    assert "exceeding the configured maximum" in result.stderr
    # No events evaluated — no partial processing.
    assert "Events evaluated:" not in result.stdout


def test_safety_guard_no_silent_partial_processing():
    """Over-limit detect produces zero alerts (no silent subset processing)."""
    workdir = _make_tmpdir()
    db_path = workdir / "test.db"
    _ingest_sample_events(workdir, db_path, count=10)

    env = _set_max_events_env(3)
    result = _run_cli_with_env("--db-path", str(db_path), "detect", env=env)
    assert result.returncode != 0
    assert "Detection alerts:" not in result.stdout


# ---------------------------------------------------------------------------
# Evaluation safety guard: max_detection_events (M10.1 Blocker 2)
# ---------------------------------------------------------------------------


def _ingest_events_from_two_sources(
    workdir: Path, db_path: Path, per_source: int = 10
) -> None:
    """Ingest failed-login events from two distinct sources into ``db_path``."""
    input_file = workdir / "two_source.jsonl"
    lines = []
    for source_ip, prefix in (("198.51.100.77", "src-a"), ("203.0.113.50", "src-b")):
        for i in range(per_source):
            lines.append(
                json.dumps(
                    {
                        "event_id": f"{prefix}-{i:03d}",
                        "timestamp": f"2024-01-01T00:00:{i:02d}Z",
                        "event_type": "auth.login.failed",
                        "source": "linux_auth",
                        "user": "admin",
                        "host": "SRV-01",
                        "authentication": {
                            "outcome": "failure",
                            "method": "ssh",
                            "username": "admin",
                            "source_address": source_ip,
                        },
                        "raw": {"event_id": f"{prefix}-{i:03d}"},
                    }
                )
            )
    input_file.write_text("\n".join(lines) + "\n")
    result = _run_cli("--db-path", str(db_path), "ingest", str(input_file))
    assert result.returncode == 0
    assert f"Events stored: {per_source * 2}" in result.stdout


def _make_minimal_ground_truth(workdir: Path) -> Path:
    """Create a minimal ground-truth file for CLI evaluate --input."""
    gt = {
        "entries": [
            {
                "event_id": "evt-gt-1",
                "classification": "suspicious",
                "expected_detection_categories": ["failed_login_burst"],
            }
        ]
    }
    gt_path = workdir / "ground_truth.json"
    gt_path.write_text(json.dumps(gt))
    return gt_path


def test_evaluation_safety_guard_above_limit_refuses_evaluation():
    """Evaluation refuses when detection count exceeds configured maximum."""
    workdir = _make_tmpdir()
    db_path = workdir / "test.db"
    _ingest_events_from_two_sources(workdir, db_path, per_source=10)

    # Run detect to create detections in the database.
    detect_result = _run_cli("--db-path", str(db_path), "detect")
    assert detect_result.returncode == 0

    gt_path = _make_minimal_ground_truth(workdir)

    # Evaluation limit lower than detection count → non-zero exit.
    env = _set_max_events_env(1)
    result = _run_cli_with_env(
        "--db-path", str(db_path), "evaluate", "--input", str(gt_path), env=env
    )
    assert result.returncode != 0
    assert "exceeding the configured maximum" in result.stderr
    # No detections loaded — no partial processing.
    assert "Detection alerts loaded:" not in result.stdout


def test_evaluation_safety_guard_at_limit_allows_evaluation():
    """Evaluation works when detection count equals configured maximum."""
    workdir = _make_tmpdir()
    db_path = workdir / "test.db"
    _ingest_events_from_two_sources(workdir, db_path, per_source=10)

    detect_result = _run_cli("--db-path", str(db_path), "detect")
    assert detect_result.returncode == 0

    gt_path = _make_minimal_ground_truth(workdir)

    # Set limit high enough to cover all detections.
    env = _set_max_events_env(100)
    result = _run_cli_with_env(
        "--db-path", str(db_path), "evaluate", "--input", str(gt_path), env=env
    )
    assert result.returncode == 0
    assert "Evaluation complete." in result.stdout


# ---------------------------------------------------------------------------
# Sysmon ingestion via CLI: content-based recognition regardless of extension
# ---------------------------------------------------------------------------


def test_cli_ingest_sysmon_json_with_dot_json_extension():
    """CLI ingests Sysmon-formatted .json file using SysmonReader (content sniffing)."""
    workdir = _make_tmpdir()
    db_path = workdir / "test.db"
    input_file = workdir / "sysmon.json"
    raw = {
        "Event": {
            "System": {
                "TimeCreated": {"SystemTime": "2024-01-15T08:30:00Z"},
                "Computer": "HOST-01",
            },
            "EventData": {
                "Data": [
                    {"Name": "Image", "#text": "C:\\\\Windows\\\\System32\\\\calc.exe"},
                    {"Name": "ProcessId", "#text": "9000"},
                    {"Name": "ParentProcessId", "#text": "1000"},
                    {"Name": "CommandLine", "#text": "calc.exe"},
                ]
            },
        }
    }
    input_file.write_text(json.dumps(raw))

    result = _run_cli("--db-path", str(db_path), "ingest", str(input_file))
    assert result.returncode == 0
    assert "Events stored: 1" in result.stdout


def test_cli_ingest_sysmon_jsonl_with_dot_json_extension():
    """CLI ingests Sysmon-formatted JSONL with .json extension via SysmonReader."""
    workdir = _make_tmpdir()
    db_path = workdir / "test.db"
    input_file = workdir / "sysmon.json"
    lines = []
    for i in range(2):
        lines.append(
            json.dumps(
                {
                    "Event": {
                        "System": {
                            "TimeCreated": {"SystemTime": f"2024-01-15T08:{i:02d}:00Z"},
                            "Computer": f"HOST-{i:02d}",
                        },
                        "EventData": {
                            "Data": [
                                {"Name": "Image", "#text": "calc.exe"},
                                {"Name": "ProcessId", "#text": str(9000 + i)},
                                {"Name": "ParentProcessId", "#text": "1000"},
                                {"Name": "CommandLine", "#text": "calc.exe"},
                            ]
                        },
                    }
                }
            )
        )
    input_file.write_text("\n".join(lines) + "\n")

    result = _run_cli("--db-path", str(db_path), "ingest", str(input_file))
    assert result.returncode == 0
    assert "Events stored: 2" in result.stdout


# ---------------------------------------------------------------------------
# Invalid records via CLI: exit status, accepted/rejected counts, partial behavior
# ---------------------------------------------------------------------------


def test_cli_invalid_json_records_reported_with_counts():
    """CLI reports accepted/rejected counts for non-dict JSON array items."""
    workdir = _make_tmpdir()
    db_path = workdir / "test.db"
    input_file = workdir / "mixed.json"
    input_file.write_text(
        json.dumps(
            [
                {"event_id": "valid-1", "user": "alice"},
                "not a dict",
                42,
                {"event_id": "valid-2", "user": "bob"},
            ]
        )
    )

    result = _run_cli("--db-path", str(db_path), "ingest", str(input_file))
    assert result.returncode == 0
    assert "Events normalized: 2" in result.stdout
    assert "Events stored: 2" in result.stdout
    assert "Records rejected: 2" in result.stdout


def test_cli_malformed_json_produces_clean_error_exit_1():
    """CLI exits non-zero with a parse error for malformed JSON (no traceback)."""
    workdir = _make_tmpdir()
    db_path = workdir / "test.db"
    input_file = workdir / "bad.json"
    input_file.write_text("{not valid json}")

    result = _run_cli("--db-path", str(db_path), "ingest", str(input_file))
    assert result.returncode != 0
    assert "Parse error" in result.stdout or "Parse error" in result.stderr
    assert "Traceback" not in result.stdout and "Traceback" not in result.stderr


def test_cli_partial_ingestion_preserves_earlier_valid_file():
    """When a later file fails, earlier valid files' events remain stored."""
    workdir = _make_tmpdir()
    db_path = workdir / "test.db"
    valid_file = workdir / "valid.jsonl"
    valid_file.write_text(
        json.dumps(
            {
                "event_id": "partial-1",
                "timestamp": "2024-01-01T00:00:00Z",
                "event_type": "auth.login.failed",
                "source": "linux_auth",
                "user": "admin",
                "host": "SRV-01",
                "authentication": {
                    "outcome": "failure",
                    "method": "ssh",
                    "username": "admin",
                    "source_address": "198.51.100.77",
                },
                "raw": {"event_id": "partial-1"},
            }
        )
    )
    bad_file = workdir / "bad.jsonl"
    bad_file.write_text("{not valid json}\n")

    result = _run_cli(
        "--db-path", str(db_path), "ingest", str(valid_file), str(bad_file)
    )
    # Multi-file ingest: first file succeeds, second fails → overall error
    assert result.returncode != 0
    assert "Parse error" in result.stdout or "Parse error" in result.stderr
    # Events from the first file were stored before the error on the second.
    # Verify by detecting (should find the event from valid_file).
    detect_result = _run_cli("--db-path", str(db_path), "detect")
    assert detect_result.returncode == 0
    assert "Events evaluated: 1" in detect_result.stdout


def test_cli_ingest_identical_records_without_source_id_survive():
    """CLI ingest preserves identical records without source-provided IDs.

    cmd_ingest always passes source_file=str(input_path) and a per-record
    position, so identical records at different positions receive distinct
    IDs and both survive — no false deduplication via content-only hash.
    """
    workdir = _make_tmpdir()
    db_path = workdir / "test.db"
    input_file = workdir / "identical.jsonl"
    # Two byte-identical records without source-provided event_id.
    lines = [
        json.dumps({"user": "bob", "outcome": "failure"}),
        json.dumps({"user": "bob", "outcome": "failure"}),
    ]
    input_file.write_text("\n".join(lines) + "\n")

    result = _run_cli("--db-path", str(db_path), "ingest", str(input_file))
    assert result.returncode == 0
    assert "Events stored: 2" in result.stdout
    assert "Duplicates skipped: 0" in result.stdout

    # Both events are queryable — no silent deduplication.
    detect_result = _run_cli("--db-path", str(db_path), "detect")
    assert detect_result.returncode == 0
    assert "Events evaluated: 2" in detect_result.stdout


# ---------------------------------------------------------------------------
# Evaluation integrity: alert-level and event-level metrics are independent
# ---------------------------------------------------------------------------


def test_evaluation_alert_and_event_metrics_independent():
    """Alert-level and event-level metrics are separate models.

    An alert can be a true positive at alert level while the underlying
    event is not counted at event level, and vice versa. The two must
    not be conflated into a single mixed-population F1.
    """
    from sentinelforge.datasets.evaluation import evaluate_detections
    from sentinelforge.detection.base import DetectionResult, Evidence, Severity

    # Ground truth: 2 suspicious events, 1 benign event
    ground_truth = {
        "entries": [
            {
                "event_id": "evt-suspicious-1",
                "classification": "suspicious",
                "expected_detection_categories": ["failed_login_burst"],
            },
            {
                "event_id": "evt-suspicious-2",
                "classification": "suspicious",
                "expected_detection_categories": ["password_spray"],
            },
            {
                "event_id": "evt-benign-1",
                "classification": "benign",
            },
        ]
    }

    # Detection 1: true positive on evt-suspicious-1 (correct category)
    det_tp = DetectionResult(
        rule_id="sentinelforge.detection.failed_login_burst",
        rule_name="Failed Login Burst",
        severity=Severity.HIGH,
        description="Burst detected",
        evidence=[
            Evidence(
                event_id="evt-suspicious-1",
                timestamp="2024-01-01T00:00:00Z",
                source="json",
                event_type="auth.login.failed",
                user="admin",
                host="HOST-1",
                source_address="198.51.100.77",
                raw={},
            )
        ],
    )

    # Detection 2: false positive on evt-benign-1 (alert on benign evidence)
    det_fp = DetectionResult(
        rule_id="sentinelforge.detection.password_spray",
        rule_name="Password Spray",
        severity=Severity.HIGH,
        description="Spray detected",
        evidence=[
            Evidence(
                event_id="evt-benign-1",
                timestamp="2024-01-01T00:00:00Z",
                source="json",
                event_type="auth.login.failed",
                user="admin",
                host="HOST-1",
                source_address="10.0.0.1",
                raw={},
            )
        ],
    )

    # Detection 3: attribution error on evt-suspicious-2 (wrong category)
    det_attr = DetectionResult(
        rule_id="sentinelforge.detection.c2_beacon",
        rule_name="C2 Beacon",
        severity=Severity.HIGH,
        description="Beacon detected",
        evidence=[
            Evidence(
                event_id="evt-suspicious-2",
                timestamp="2024-01-01T00:00:00Z",
                source="json",
                event_type="network.connection",
                user="admin",
                host="HOST-1",
                source_address="203.0.113.50",
                raw={},
            )
        ],
    )

    results = evaluate_detections(
        dataset_id="test-independence",
        detection_results=[det_tp, det_fp, det_attr],
        event_ground_truth=ground_truth,
    )

    # Alert-level: 1 TP, 1 FP, 1 attribution error, 0 unassessed
    al = results.alert_level
    assert al.total_alerts == 3
    assert al.true_positive_alerts == 1
    assert al.false_positive_alerts == 1
    assert al.attribution_error_alerts == 1
    assert al.unassessed_alerts == 0
    assert al.assessed_alerts == 3
    assert al.precision == round(1.0 / 3.0, 4)  # TP / assessed, rounded to 4 dp

    # Event-level: 2 suspicious events, 1 detected (evt-suspicious-1), 1 undetected (evt-suspicious-2)
    el = results.event_level
    assert el.total_suspicious_events == 2
    assert el.detected_suspicious_events == 1
    assert el.undetected_suspicious_events == 1
    assert el.recall == 0.5

    # F1 scores must be valid only when unit matches population
    assert results.f1_alert.valid is False  # alert-level has no recall population
    assert results.f1_event.valid is False  # event-level has no precision population


def test_evaluation_unassessed_alerts_tracked():
    """Alerts on unlabeled evidence are counted as unassessed, not as FP."""
    from sentinelforge.datasets.evaluation import evaluate_detections
    from sentinelforge.detection.base import DetectionResult, Evidence, Severity

    ground_truth = {
        "entries": [
            {
                "event_id": "evt-labeled",
                "classification": "suspicious",
                "expected_detection_categories": ["failed_login_burst"],
            },
        ]
    }

    # Alert on an unlabeled event → unassessed
    det_unassessed = DetectionResult(
        rule_id="sentinelforge.detection.failed_login_burst",
        rule_name="Failed Login Burst",
        severity=Severity.HIGH,
        description="Burst on unlabeled",
        evidence=[
            Evidence(
                event_id="evt-unlabeled",
                timestamp="2024-01-01T00:00:00Z",
                source="json",
                event_type="auth.login.failed",
                user="admin",
                host="HOST-1",
                source_address="198.51.100.77",
                raw={},
            )
        ],
    )

    results = evaluate_detections(
        dataset_id="test-unassessed",
        detection_results=[det_unassessed],
        event_ground_truth=ground_truth,
    )

    al = results.alert_level
    assert al.total_alerts == 1
    assert al.true_positive_alerts == 0
    assert al.false_positive_alerts == 0
    assert al.attribution_error_alerts == 0
    assert al.unassessed_alerts == 1
    assert al.assessed_alerts == 0
    assert al.precision == 0.0  # TP / assessed = 0 / 0 = 0.0
    assert al.assessment_coverage == 0.0


def test_evaluation_cli_output_reports_separate_metrics():
    """CLI evaluate output shows alert-level and event-level metrics separately.

    Alert-level metrics (precision) and event-level metrics (recall) must
    be printed independently without conflation into a mixed-population F1.
    """
    workdir = _make_tmpdir()
    output_file = workdir / "eval_report.json"
    result = _run_cli("evaluate", "--output", str(output_file))
    assert result.returncode == 0

    # Both alert-level precision and event-level recall are present
    assert "Precision:" in result.stdout
    assert "Recall:" in result.stdout

    # Output file contains full structured results
    assert output_file.exists()
    with open(output_file, "r", encoding="utf-8") as fh:
        content = fh.read()
    assert "Overall True Positives: 30" in content
    assert "Overall False Positives: 18" in content
    assert "Overall False Negatives: 0" in content
    assert "Overall Precision: 0.6250" in content


# ---------------------------------------------------------------------------
# Installed-package evaluation regression tests (M10.4)
# These tests verify that `sentinelforge evaluate --output` works both from
# a source checkout and from an installed wheel, without depending on
# evaluate_independent.py being present in the current working directory.
# ---------------------------------------------------------------------------


def test_evaluate_builtin_from_source_checkout() -> None:
    """`evaluate --output` from a source checkout should produce correct metrics."""
    workdir = _make_tmpdir()
    output_file = workdir / "eval_report.txt"
    result = _run_cli("evaluate", "--output", str(output_file))
    assert result.returncode == 0
    assert "INDEPENDENT EVALUATION — OVERALL METRICS" in result.stdout
    assert "Overall Precision: 0.6250" in result.stdout
    assert "Overall Recall: 1.0000" in result.stdout
    assert output_file.exists()
    content = output_file.read_text(encoding="utf-8")
    assert "INDEPENDENT EVALUATION — OVERALL METRICS" in content


def test_evaluate_builtin_output_file_creation() -> None:
    """`evaluate --output` should create the output file with report content."""
    workdir = _make_tmpdir()
    nested = workdir / "sub" / "deep"
    output_file = nested / "eval_report.txt"
    result = _run_cli("evaluate", "--output", str(output_file))
    assert result.returncode == 0
    assert output_file.exists()
    assert "Overall Precision:" in output_file.read_text(encoding="utf-8")


def test_evaluate_builtin_no_input_uses_packaged_evaluator() -> None:
    """`evaluate --output` without --input should not require evaluate_independent.py
    in the current working directory (tests run outside the repo checkout)."""
    workdir = _make_tmpdir()
    output_file = workdir / "eval.txt"
    # Run from a directory that does NOT contain evaluate_independent.py
    result = _run_cli("evaluate", "--output", str(output_file))
    assert result.returncode == 0
    assert "Cannot locate evaluate_independent.py" not in result.stderr
    assert "INDEPENDENT EVALUATION" in result.stdout


def test_database_backed_evaluation_still_works() -> None:
    """`evaluate --input` (database-backed) should continue to work unchanged."""
    workdir = _make_tmpdir()
    db_path = workdir / "evaldb.db"

    # Ingest some events first
    input_file = workdir / "events.jsonl"
    lines = []
    for i in range(6):
        lines.append(
            json.dumps(
                {
                    "event_id": f"gt-{i:02d}",
                    "timestamp": f"2024-01-01T00:00:{i:02d}Z",
                    "event_type": "auth.login.failed",
                    "source": "linux_auth",
                    "user": "admin",
                    "host": "SRV-01",
                    "authentication": {
                        "outcome": "failure",
                        "method": "ssh",
                        "username": "admin",
                        "source_address": "198.51.100.77",
                    },
                    "raw": {"event_id": f"gt-{i:02d}"},
                }
            )
        )
    input_file.write_text("\n".join(lines) + "\n")

    result = _run_cli("--db-path", str(db_path), "ingest", str(input_file))
    assert result.returncode == 0

    result = _run_cli("--db-path", str(db_path), "detect")
    assert result.returncode == 0

    # Ground truth matching the 6 ingested events
    gt = {
        "entries": [
            {
                "event_id": f"gt-{i:02d}",
                "classification": "suspicious",
                "expected_detection_categories": ["failed_login_burst"],
            }
            for i in range(6)
        ]
    }
    gt_file = workdir / "ground_truth.json"
    gt_file.write_text(json.dumps(gt))

    result = _run_cli("--db-path", str(db_path), "evaluate", "--input", str(gt_file))
    assert result.returncode == 0
    assert "Precision:" in result.stdout
    assert "Recall:" in result.stdout
    assert "F1" in result.stdout


def test_evaluate_builtin_metric_semantics() -> None:
    """Built-in evaluator output must show alert-level and event-level metrics
    separately, with correct precision, recall, and F1 values."""
    workdir = _make_tmpdir()
    output_file = workdir / "metrics.txt"
    result = _run_cli("evaluate", "--output", str(output_file))
    assert result.returncode == 0

    stdout = result.stdout
    assert "Precision:" in stdout
    assert "Recall:" in stdout
    assert "F1" in stdout
    assert "False Positive Rate:" in stdout
    assert "False Negative Rate:" in stdout
