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

import pytest

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
    return subprocess.run(
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

    result = _run_cli(
        "--db-path", str(db_path), "ingest", str(input_file)
    )
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

    result = _run_cli(
        "--db-path", str(custom_db), "ingest", str(input_file)
    )
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
    result = _run_cli(
        "--db-path", str(db_path), "ingest", str(input_file)
    )
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
