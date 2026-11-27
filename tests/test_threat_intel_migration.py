"""Tests for SQLite schema migration to v5 (sentinelforge.storage.schema).

Scenarios:
1. Fresh database initializes at schema version 5
2. Migration from v4 to v5 adds IOC/retro-hunt tables and preserves existing records
3. v5 indexes exist
4. Foreign keys are enforced on IOC matches
"""

from __future__ import annotations

import sqlite3

import pytest

from sentinelforge.storage.database import Database
from sentinelforge.storage.repositories import IOCRepository
from sentinelforge.storage.schema import IOC, SCHEMA_VERSION, IOCMatch


def _schema_version(db: Database) -> int:
    return db.schema_version() or 0


def _set_schema_version(db: Database, version: int) -> None:
    import sqlite3

    conn = sqlite3.connect(db.db_path)
    try:
        conn.execute(
            "UPDATE schema_metadata SET value = ? WHERE key = 'schema_version'",
            (str(version),),
        )
        conn.commit()
    finally:
        conn.close()


def _drop_ioc_tables(db: Database) -> None:
    import sqlite3

    conn = sqlite3.connect(db.db_path)
    try:
        for table in ("retro_hunt_matches", "retro_hunts", "ioc_matches", "iocs"):
            conn.execute(f"DROP TABLE IF EXISTS {table}")
        conn.commit()
    finally:
        conn.close()


# --------------------------------------------------------------------------- #
# Fresh initialization
# --------------------------------------------------------------------------- #
def test_fresh_db_is_schema_v5(tmp_db: Database) -> None:
    assert _schema_version(tmp_db) == SCHEMA_VERSION == 5


# --------------------------------------------------------------------------- #
# Migration v4 -> v5
# --------------------------------------------------------------------------- #
def test_v4_to_v5_migration_preserves_records_and_adds_tables(tmp_db: Database) -> None:
    assert _schema_version(tmp_db) == 5

    # Insert v4-era records before simulating the v4 state.
    with tmp_db.transaction() as conn:
        conn.execute(
            "INSERT INTO events (event_id, source, raw, ingested_at) VALUES (?, ?, ?, ?)",
            ("evt-preserved", "adapter", '{"k":"v"}', "2026-01-01T00:00:00Z"),
        )
        conn.execute(
            "INSERT INTO incidents (incident_id, title, correlation_rationale, severity, status, first_seen, last_seen, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "inc-preserved",
                "t",
                "rationale",
                "high",
                "open",
                "2026-01-01T00:00:00Z",
                "2026-01-01T00:10:00Z",
                "2026-01-01T00:00:00Z",
                "2026-01-01T00:10:00Z",
            ),
        )

    # Simulate a database at v4: drop v5-only IOC tables, reset version to 4.
    _drop_ioc_tables(tmp_db)
    _set_schema_version(tmp_db, 4)
    assert _schema_version(tmp_db) == 4

    # Re-run migration: should apply _migrate_v4_to_v5.
    new_version = tmp_db.initialize()
    assert new_version == 5
    assert _schema_version(tmp_db) == 5

    # Existing records are preserved (additive migration).
    with tmp_db.transaction() as conn:
        row = conn.execute(
            "SELECT event_id FROM events WHERE event_id = ?", ("evt-preserved",)
        ).fetchone()
        assert row is not None
        row = conn.execute(
            "SELECT incident_id FROM incidents WHERE incident_id = ?",
            ("inc-preserved",),
        ).fetchone()
        assert row is not None

    # v5-only tables are recreated.
    with tmp_db.transaction() as conn:
        tables = {
            r[0]
            for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        assert {"iocs", "ioc_matches", "retro_hunts", "retro_hunt_matches"} <= tables


def test_v5_indexes_exist(tmp_db: Database) -> None:
    expected = {
        "idx_iocs_type_value",
        "idx_ioc_matches_event",
        "idx_ioc_matches_indicator",
        "idx_retro_hunts_indicator",
    }
    with tmp_db.transaction() as conn:
        indexes = {
            r[0]
            for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'index'")
        }
    assert expected <= indexes


def test_foreign_key_enforced_on_ioc_match(tmp_db: Database) -> None:
    repo = IOCRepository(tmp_db)
    repo.insert_ioc(
        IOC(
            indicator_id="ioc-1",
            indicator_value="1.2.3.4",
            indicator_type="ipv4",
            source_name="s",
        )
    )
    # Persist the referenced event so the first ioc_match insert is valid;
    # the FK violation under test is on the nonexistent indicator_id below.
    with tmp_db.transaction() as conn:
        conn.execute(
            "INSERT INTO events (event_id, source, raw, ingested_at) VALUES (?, ?, ?, ?)",
            ("evt-1", "unit-test", "{}", "2026-01-01T00:00:00Z"),
        )
    repo.insert_ioc_match(
        IOCMatch(
            match_id="m-1",
            indicator_id="ioc-1",
            event_id="evt-1",
            match_type="exact_ip",
        )
    )
    with pytest.raises(sqlite3.IntegrityError):
        repo.insert_ioc_match(
            IOCMatch(
                match_id="m-2",
                indicator_id="nonexistent",
                event_id="evt-1",
                match_type="exact_ip",
            )
        )
