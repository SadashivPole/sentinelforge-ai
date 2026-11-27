"""Integration tests for the IOC import/persistence CLI command.

Exercises ``sentinelforge ioc import`` and ``sentinelforge ioc validate``
against a real temporary SQLite database, covering:

1. Valid JSON feed import -> indicators stored in SQLite.
2. Valid CSV feed import -> indicators stored in SQLite.
3. ``ioc list`` shows imported indicators.
4. ``ioc inspect`` retrieves stored metadata.
5. Re-importing the same feed is idempotent (no duplicates).
6. Conflicting existing indicator content is handled safely.
7. Invalid records are rejected while valid records are persisted.
8. ``ioc validate`` never writes to the database.
9. Oversized files are rejected with bounded reads.
10. Non-object JSON records are rejected without crashing.
11. A failed persistence operation never reports a false successful import.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os

import pytest

from sentinelforge.cli.main import cmd_ioc
from sentinelforge.storage.database import Database
from sentinelforge.storage.repositories import DuplicateIdCollisionError, IOCRepository
from sentinelforge.storage.schema import IOC


def _json(records) -> bytes:
    return json.dumps(records).encode("utf-8")


def _csv(header: str, rows: list[str]) -> bytes:
    return (header + "\n" + "\n".join(rows)).encode("utf-8")


def _indicator_id(source_name: str, indicator_type: str, value: str) -> str:
    """Reproduce the deterministic ID used by imports._make_indicator_id."""
    payload = f"{source_name}|{indicator_type}|{value}"
    return "ioc-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:24]


def _write_feed(db: Database, name: str, content: bytes) -> str:
    """Write a feed file into the same directory as the temp database."""
    directory = os.path.dirname(db.db_path)
    path = os.path.join(directory, name)
    with open(path, "wb") as fh:
        fh.write(content)
    return path


def _import_args(db: Database, feed_path: str, source: str = "test-src") -> argparse.Namespace:
    return argparse.Namespace(
        ioc_command="import",
        file=feed_path,
        source=source,
        source_reference=None,
        db_path=db.db_path,
    )


def _list_args(db: Database) -> argparse.Namespace:
    return argparse.Namespace(
        ioc_command="list",
        limit=50,
        offset=0,
        db_path=db.db_path,
    )


def _inspect_args(db: Database, indicator_id: str) -> argparse.Namespace:
    return argparse.Namespace(
        ioc_command="inspect",
        indicator_id=indicator_id,
        db_path=db.db_path,
    )


def _validate_args(db: Database, feed_path: str) -> argparse.Namespace:
    return argparse.Namespace(
        ioc_command="validate",
        file=feed_path,
        source="validate-src",
        source_reference=None,
        db_path=db.db_path,
    )


def _count_iocs(db: Database) -> int:
    return IOCRepository(db).count_iocs()


# --------------------------------------------------------------------------- #
# 1. Valid JSON feed import -> stored in SQLite
# --------------------------------------------------------------------------- #
def test_cli_import_json_feed_stores_indicators(tmp_db: Database) -> None:
    feed = _write_feed(
        tmp_db,
        "feed.json",
        _json(
            [
                {
                    "indicator_type": "ipv4",
                    "indicator_value": "192.168.1.100",
                    "source_name": "intel-src",
                    "confidence": 85,
                    "context": "c2 beacon",
                },
                {
                    "indicator_type": "sha256",
                    "indicator_value": "a" * 64,
                    "source_name": "intel-src",
                },
            ]
        ),
    )
    args = _import_args(tmp_db, feed)
    code = cmd_ioc(args)
    assert code == 0

    repo = IOCRepository(tmp_db)
    assert repo.count_iocs() == 2
    assert repo.get_ioc_by_value("192.168.1.100", "ipv4") is not None
    assert repo.get_ioc_by_value("a" * 64, "sha256") is not None


# --------------------------------------------------------------------------- #
# 2. Valid CSV feed import -> stored in SQLite
# --------------------------------------------------------------------------- #
def test_cli_import_csv_feed_stores_indicators(tmp_db: Database) -> None:
    feed = _write_feed(
        tmp_db,
        "feed.csv",
        _csv(
            "indicator_type,indicator_value,source_name,confidence,context",
            [
                "domain,example.com,test-src,70,phishing",
                "ipv4,10.0.0.5,test-src,,scanner",
            ],
        ),
    )
    args = _import_args(tmp_db, feed)
    code = cmd_ioc(args)
    assert code == 0

    repo = IOCRepository(tmp_db)
    assert repo.count_iocs() == 2
    assert repo.get_ioc_by_value("example.com", "domain") is not None
    assert repo.get_ioc_by_value("10.0.0.5", "ipv4") is not None


# --------------------------------------------------------------------------- #
# 3. ioc list shows imported indicators
# --------------------------------------------------------------------------- #
def test_cli_list_shows_imported_indicators(tmp_db: Database, capsys) -> None:
    repo = IOCRepository(tmp_db)
    repo.insert_ioc(
        IOC(
            indicator_id="ioc-abc",
            indicator_value="1.2.3.4",
            indicator_type="ipv4",
            source_name="src",
            confidence=70,
        )
    )

    args = _list_args(tmp_db)
    code = cmd_ioc(args)
    assert code == 0
    captured = capsys.readouterr()
    assert "ioc-abc" in captured.out
    assert "1.2.3.4" in captured.out


# --------------------------------------------------------------------------- #
# 4. ioc inspect retrieves stored metadata
# --------------------------------------------------------------------------- #
def test_cli_inspect_retrieves_metadata(tmp_db: Database, capsys) -> None:
    repo = IOCRepository(tmp_db)
    repo.insert_ioc(
        IOC(
            indicator_id="ioc-inspect-1",
            indicator_value="https://evil.example.com/payload",
            indicator_type="url",
            source_name="feed-1",
            source_reference="ref-123",
            confidence=90,
            context="malware download",
        )
    )

    args = _inspect_args(tmp_db, "ioc-inspect-1")
    code = cmd_ioc(args)
    assert code == 0
    captured = capsys.readouterr()
    assert "ioc-inspect-1" in captured.out
    assert "https://evil.example.com/payload" in captured.out
    assert "url" in captured.out
    assert "feed-1" in captured.out
    assert "90" in captured.out


# --------------------------------------------------------------------------- #
# 5. Re-importing the same feed is idempotent (no duplicates)
# --------------------------------------------------------------------------- #
def test_cli_reimport_idempotent(tmp_db: Database) -> None:
    feed = _write_feed(
        tmp_db,
        "feed.json",
        _json(
            [
                {
                    "indicator_type": "ipv4",
                    "indicator_value": "203.0.113.5",
                    "source_name": "src-a",
                }
            ]
        ),
    )

    # First import: stored
    args = _import_args(tmp_db, feed)
    code = cmd_ioc(args)
    assert code == 0
    assert _count_iocs(tmp_db) == 1

    # Second import: already present, no duplicates
    code = cmd_ioc(args)
    assert code == 0
    assert _count_iocs(tmp_db) == 1


# --------------------------------------------------------------------------- #
# 6. Conflicting existing indicator content handled safely
# --------------------------------------------------------------------------- #
def test_cli_conflicting_content_not_overwritten(tmp_db: Database) -> None:
    # Pre-insert with the same source name the import CLI uses ("test-src").

    indicator_id = _indicator_id("test-src", "ipv4", "10.0.0.99")

    repo = IOCRepository(tmp_db)
    repo.insert_ioc(
        IOC(
            indicator_id=indicator_id,
            indicator_value="10.0.0.99",
            indicator_type="ipv4",
            source_name="test-src",
            confidence=50,
            validation_status="valid",
        )
    )

    # Try to import the same indicator with different confidence (conflict).
    feed = _write_feed(
        tmp_db,
        "feed.json",
        _json(
            [
                {
                    "indicator_type": "ipv4",
                    "indicator_value": "10.0.0.99",
                    "source_name": "test-src",
                    "confidence": 99,
                }
            ]
        ),
    )
    args = _import_args(tmp_db, feed)
    code = cmd_ioc(args)
    assert code == 0

    # Count unchanged (no duplicate inserted) and original content preserved.
    assert _count_iocs(tmp_db) == 1
    got = repo.get_ioc(indicator_id)
    assert got is not None
    assert got.confidence == 50  # original preserved, not overwritten to 99


# --------------------------------------------------------------------------- #
# 7. Invalid records rejected while valid records persisted
# --------------------------------------------------------------------------- #
def test_cli_invalid_records_rejected_valid_persisted(tmp_db: Database, capsys) -> None:
    repo = IOCRepository(tmp_db)
    feed = _write_feed(
        tmp_db,
        "feed.json",
        _json(
            [
                {
                    "indicator_type": "ipv4",
                    "indicator_value": "10.0.0.1",
                    "source_name": "src",
                },
                {
                    "indicator_type": "not-a-type",
                    "indicator_value": "whatever",
                    "source_name": "src",
                },
                {
                    "indicator_type": "ipv4",
                    "indicator_value": "999.999.999.999",
                    "source_name": "src",
                },
            ]
        ),
    )
    args = _import_args(tmp_db, feed)
    code = cmd_ioc(args)
    assert code == 0

    captured = capsys.readouterr()
    assert "Stored: 1" in captured.out
    assert "Rejected: 2" in captured.out
    assert _count_iocs(tmp_db) == 1
    assert repo.get_ioc_by_value("10.0.0.1", "ipv4") is not None


# --------------------------------------------------------------------------- #
# 8. ioc validate never writes to the database
# --------------------------------------------------------------------------- #
def test_cli_validate_never_writes(tmp_db: Database) -> None:
    feed = _write_feed(
        tmp_db,
        "feed.json",
        _json(
            [
                {
                    "indicator_type": "domain",
                    "indicator_value": "validate.example.com",
                    "source_name": "validate-src",
                }
            ]
        ),
    )
    assert _count_iocs(tmp_db) == 0

    args = _validate_args(tmp_db, feed)
    code = cmd_ioc(args)
    assert code == 0

    # Database must be unchanged.
    assert _count_iocs(tmp_db) == 0


# --------------------------------------------------------------------------- #
# 9. Oversized files rejected with bounded reads
# --------------------------------------------------------------------------- #
def test_cli_oversized_file_rejected(tmp_db: Database) -> None:
    # File larger than MAX_IMPORT_FILE_BYTES (5 MiB).
    big = b"x" * (5 * 1024 * 1024 + 1)
    feed = _write_feed(tmp_db, "big.json", big)

    args = _import_args(tmp_db, feed)
    code = cmd_ioc(args)
    assert code == 1  # EXIT_ERROR
    assert _count_iocs(tmp_db) == 0

    # Validate command must also reject oversized files.
    validate_args = _validate_args(tmp_db, feed)
    code = cmd_ioc(validate_args)
    assert code == 1
    assert _count_iocs(tmp_db) == 0


# --------------------------------------------------------------------------- #
# 10. Non-object JSON records rejected without crashing
# --------------------------------------------------------------------------- #
def test_cli_non_object_json_records_rejected(tmp_db: Database, capsys) -> None:
    repo = IOCRepository(tmp_db)
    feed = _write_feed(
        tmp_db,
        "feed.json",
        json.dumps(
            [
                {"indicator_type": "ipv4", "indicator_value": "1.2.3.4", "source_name": "s"},
                123,
                None,
                "malformed",
                {"indicator_type": "domain", "indicator_value": "good.example.com", "source_name": "s"},
            ]
        ).encode("utf-8"),
    )
    args = _import_args(tmp_db, feed)
    code = cmd_ioc(args)
    assert code == 0

    captured = capsys.readouterr()
    assert "Stored: 2" in captured.out
    assert "Rejected: 3" in captured.out
    assert _count_iocs(tmp_db) == 2
    assert repo.get_ioc_by_value("1.2.3.4", "ipv4") is not None
    assert repo.get_ioc_by_value("good.example.com", "domain") is not None


# --------------------------------------------------------------------------- #
# 11. Failed persistence never reports false successful import
# --------------------------------------------------------------------------- #
def test_cli_persistence_failure_not_reported_as_success(tmp_db: Database, capsys) -> None:
    # Pre-insert with the same source name the import CLI uses ("test-src").

    indicator_id = _indicator_id("test-src", "domain", "conflict.example.com")

    repo = IOCRepository(tmp_db)
    repo.insert_ioc(
        IOC(
            indicator_id=indicator_id,
            indicator_value="conflict.example.com",
            indicator_type="domain",
            source_name="test-src",
            confidence=30,
        )
    )

    feed = _write_feed(
        tmp_db,
        "feed.json",
        _json(
            [
                {
                    "indicator_type": "domain",
                    "indicator_value": "conflict.example.com",
                    "source_name": "test-src",
                    "confidence": 80,
                }
            ]
        ),
    )
    args = _import_args(tmp_db, feed)
    code = cmd_ioc(args)
    assert code == 0

    captured = capsys.readouterr()
    # Conflict is reported as "Conflicting", never as "Stored".
    assert "Conflicting: 1" in captured.out
    assert "Stored: 0" in captured.out

    # Original content preserved — not silently overwritten.
    got = repo.get_ioc(indicator_id)
    assert got is not None
    assert got.confidence == 30

    # Verify DuplicateIdCollisionError is the expected exception type.
    with pytest.raises(DuplicateIdCollisionError):
        repo.insert_ioc(
            IOC(
                indicator_id=indicator_id,
                indicator_value="conflict.example.com",
                indicator_type="domain",
                source_name="src-c",
                confidence=80,
            )
        )
