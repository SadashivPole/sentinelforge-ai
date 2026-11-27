"""Tests for retrospective hunting (sentinelforge.threat_intel.retro_hunt).

Scenarios:
1. Hunting a missing IOC raises ValueError
2. A retro-hunt records scope, events searched, and match count
3. Matches are stored and linked to the hunt
4. Fixed search timestamp yields deterministic hunt IDs
5. Zero-match hunt still records the hunt record
6. Retro-hunt findings are append-only (original events/alerts untouched)
"""

from __future__ import annotations

import json

import pytest

from sentinelforge.storage.database import Database
from sentinelforge.storage.repositories import IOCRepository
from sentinelforge.storage.schema import IOC
from sentinelforge.threat_intel.retro_hunt import RetroHuntResult, run_retro_hunt


def _store_ioc(
    db: Database,
    indicator_id: str = "ioc-1",
    value: str = "1.2.3.4",
    itype: str = "ipv4",
) -> IOC:
    repo = IOCRepository(db)
    ioc = IOC(
        indicator_id=indicator_id,
        indicator_value=value,
        indicator_type=itype,
        source_name="test-src",
    )
    repo.insert_ioc(ioc)
    return ioc


def _events(count: int = 3, matching: int = 1) -> list[dict]:
    events: list[dict] = []
    for i in range(count):
        events.append(
            {
                "event_id": f"evt-{i}",
                "timestamp": "2026-01-01T00:00:00Z",
                "auth_source_address": "1.2.3.4" if i < matching else "9.9.9.9",
                "network_remote_address": None,
                "network_local_address": None,
                "process_hash_sha256": None,
                "raw": {},
            }
        )
    return events


def _persist_events(db: Database, events: list[dict]) -> None:
    """Persist events so their event_id satisfies the ioc_matches foreign key."""
    with db.transaction() as conn:
        for event in events:
            conn.execute(
                "INSERT INTO events (event_id, source, raw, ingested_at) VALUES (?, ?, ?, ?)",
                (
                    event["event_id"],
                    "retro-hunt-test",
                    json.dumps(event.get("raw", {})),
                    event["timestamp"],
                ),
            )


def test_retro_hunt_unknown_ioc_raises(tmp_db: Database) -> None:
    with pytest.raises(ValueError, match="not found"):
        run_retro_hunt(tmp_db, "ioc-does-not-exist", _events())


def test_retro_hunt_records_scope_and_counts(tmp_db: Database) -> None:
    _store_ioc(tmp_db)
    events = _events(count=5, matching=2)
    _persist_events(tmp_db, events)
    result = run_retro_hunt(tmp_db, "ioc-1", events)
    assert isinstance(result, RetroHuntResult)
    assert result.hunt.match_count == 2
    assert result.hunt.total_events_searched == 5
    assert "5 events searched" in result.hunt.search_scope
    assert result.hunt.search_timestamp
    assert result.hunt.hunt_id.startswith("hunt-")


def test_retro_hunt_stores_hunt_and_matches(tmp_db: Database) -> None:
    _store_ioc(tmp_db)
    events = _events(count=3, matching=1)
    _persist_events(tmp_db, events)
    result = run_retro_hunt(tmp_db, "ioc-1", events)

    repo = IOCRepository(tmp_db)
    hunt = repo.get_retro_hunt(result.hunt.hunt_id)
    assert hunt is not None
    assert hunt.indicator_id == "ioc-1"
    assert hunt.match_count == 1

    matches = repo.get_ioc_matches("ioc-1")
    assert len(matches) == 1
    assert matches[0].event_id == "evt-0"
    assert matches[0].matched_field == "auth_source_address"
    assert matches[0].matched_value == "1.2.3.4"
    assert matches[0].match_type == "exact_ip"


def test_retro_hunt_deterministic_hunt_id(tmp_db: Database) -> None:
    _store_ioc(tmp_db)
    events = _events()
    _persist_events(tmp_db, events)
    ts = "2026-03-01T12:00:00Z"
    r1 = run_retro_hunt(tmp_db, "ioc-1", events, search_timestamp=ts)
    r2 = run_retro_hunt(tmp_db, "ioc-1", events, search_timestamp=ts)
    assert r1.hunt.hunt_id == r2.hunt.hunt_id
    assert r1.hunt.search_timestamp == ts


def test_retro_hunt_zero_matches(tmp_db: Database) -> None:
    _store_ioc(tmp_db, value="1.2.3.4")
    events = _events(count=4, matching=0)  # all 9.9.9.9
    _persist_events(tmp_db, events)
    result = run_retro_hunt(tmp_db, "ioc-1", events)
    assert result.hunt.match_count == 0
    assert result.hunt.total_events_searched == 4
    assert result.matches == []


def test_retro_hunt_does_not_modify_events(tmp_db: Database) -> None:
    _store_ioc(tmp_db)
    before = [dict(e) for e in _events(count=2, matching=1)]
    _persist_events(tmp_db, before)
    run_retro_hunt(tmp_db, "ioc-1", before)
    after = _events(count=2, matching=1)
    assert before == after  # original event dicts untouched


def test_retro_hunt_result_fields(tmp_db: Database) -> None:
    _store_ioc(tmp_db)
    events = _events(count=1, matching=1)
    _persist_events(tmp_db, events)
    result = run_retro_hunt(tmp_db, "ioc-1", events)
    assert isinstance(result.hunt.match_count, int)
    assert isinstance(result.hunt.total_events_searched, int)
    assert len(result.match_links) == len(result.matches)
    for hunt_id, match_id in result.match_links:
        assert hunt_id == result.hunt.hunt_id
