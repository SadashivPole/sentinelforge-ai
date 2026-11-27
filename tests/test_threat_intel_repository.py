"""Tests for IOCRepository (sentinelforge.storage.repositories).

Scenarios:
1. Count / insert / get / list indicators
2. Get indicator by value + type
3. Idempotent re-insert of identical content
4. Conflicting re-insert raises DuplicateIdCollisionError
5. IOC match recording and retrieval
6. Retro-hunt record and match linking
"""

from __future__ import annotations

import pytest

from sentinelforge.storage.database import Database
from sentinelforge.storage.repositories import (
    DuplicateIdCollisionError,
    IOCRepository,
)
from sentinelforge.storage.schema import IOC, IOCMatch, RetroHunt


def _ioc(
    repo: IOCRepository,
    indicator_id: str = "ioc-1",
    indicator_value: str = "1.2.3.4",
    indicator_type: str = "ipv4",
    source_name: str = "src",
    confidence: int | None = 70,
    validation_status: str = "valid",
) -> IOC:
    ioc = IOC(
        indicator_id=indicator_id,
        indicator_value=indicator_value,
        indicator_type=indicator_type,
        source_name=source_name,
        confidence=confidence,
        validation_status=validation_status,
    )
    repo.insert_ioc(ioc)
    return ioc


# --------------------------------------------------------------------------- #
# CRUD
# --------------------------------------------------------------------------- #
def test_count_iocs_empty(tmp_db: Database) -> None:
    assert IOCRepository(tmp_db).count_iocs() == 0


def test_insert_and_get_ioc(tmp_db: Database) -> None:
    repo = IOCRepository(tmp_db)
    _ioc(repo)
    assert repo.count_iocs() == 1
    got = repo.get_ioc("ioc-1")
    assert got is not None
    assert got.indicator_value == "1.2.3.4"
    assert got.confidence == 70
    assert repo.get_ioc("nope") is None


def test_get_ioc_by_value(tmp_db: Database) -> None:
    repo = IOCRepository(tmp_db)
    _ioc(repo)
    got = repo.get_ioc_by_value("1.2.3.4", "ipv4")
    assert got is not None
    assert got.indicator_id == "ioc-1"
    assert repo.get_ioc_by_value("1.2.3.4", "ipv6") is None


def test_list_iocs_filters(tmp_db: Database) -> None:
    repo = IOCRepository(tmp_db)
    _ioc(repo, indicator_id="ioc-1", indicator_value="1.2.3.4", indicator_type="ipv4")
    _ioc(
        repo,
        indicator_id="ioc-2",
        indicator_value="example.com",
        indicator_type="domain",
    )
    _ioc(repo, indicator_id="ioc-3", indicator_value="a" * 64, indicator_type="sha256")

    assert len(repo.list_iocs()) == 3
    assert len(repo.list_iocs(indicator_type="ipv4")) == 1
    assert len(repo.list_iocs(indicator_type="domain")) == 1
    assert len(repo.list_iocs(validation_status="valid")) == 3


# --------------------------------------------------------------------------- #
# Duplicate handling
# --------------------------------------------------------------------------- #
def test_insert_ioc_idempotent_same_content(tmp_db: Database) -> None:
    repo = IOCRepository(tmp_db)
    ioc = IOC(
        indicator_id="ioc-1",
        indicator_value="1.2.3.4",
        indicator_type="ipv4",
        source_name="src",
    )
    first = repo.insert_ioc(ioc)
    second = repo.insert_ioc(ioc)
    assert first == second == "ioc-1"
    assert repo.count_iocs() == 1


def test_insert_ioc_conflicting_content_rejected(tmp_db: Database) -> None:
    repo = IOCRepository(tmp_db)
    repo.insert_ioc(
        IOC(
            indicator_id="ioc-1",
            indicator_value="1.2.3.4",
            indicator_type="ipv4",
            source_name="src",
        )
    )
    conflicting = IOC(
        indicator_id="ioc-1",
        indicator_value="5.6.7.8",
        indicator_type="ipv4",
        source_name="src",
    )
    with pytest.raises(DuplicateIdCollisionError):
        repo.insert_ioc(conflicting)
    # Original untouched
    got = repo.get_ioc("ioc-1")
    assert got is not None
    assert got.indicator_value == "1.2.3.4"


# --------------------------------------------------------------------------- #
# Matches and retro-hunts
# --------------------------------------------------------------------------- #
def test_insert_and_get_ioc_match(tmp_db: Database) -> None:
    repo = IOCRepository(tmp_db)
    _ioc(repo)
    match = IOCMatch(
        match_id="match-1",
        indicator_id="ioc-1",
        event_id="evt-1",
        matched_field="auth_source_address",
        matched_value="1.2.3.4",
        indicator_source="src",
        match_type="exact_ip",
    )
    # The ioc_matches.event_id FK requires the event to exist.
    with tmp_db.transaction() as conn:
        conn.execute(
            "INSERT INTO events (event_id, source, raw, ingested_at) VALUES (?, ?, ?, ?)",
            ("evt-1", "unit-test", "{}", "2026-01-01T00:00:00Z"),
        )
    repo.insert_ioc_match(match)
    matches = repo.get_ioc_matches("ioc-1")
    assert len(matches) == 1
    assert matches[0].event_id == "evt-1"
    assert matches[0].match_type == "exact_ip"


def test_insert_retro_hunt_and_link(tmp_db: Database) -> None:
    repo = IOCRepository(tmp_db)
    _ioc(repo)
    # Persist the referenced event so the ioc_match FK is satisfied.
    with tmp_db.transaction() as conn:
        conn.execute(
            "INSERT INTO events (event_id, source, raw, ingested_at) VALUES (?, ?, ?, ?)",
            ("e-1", "unit-test", "{}", "2026-01-01T00:00:00Z"),
        )
    repo.insert_ioc_match(
        IOCMatch(
            match_id="m-1", indicator_id="ioc-1", event_id="e-1", match_type="exact_ip"
        )
    )
    hunt = RetroHunt(
        hunt_id="h-1",
        indicator_id="ioc-1",
        search_scope="2 events",
        total_events_searched=2,
        match_count=1,
    )
    hid = repo.insert_retro_hunt(hunt)
    assert hid == "h-1"
    repo.link_retro_hunt_match("h-1", "m-1")
    got = repo.get_retro_hunt("h-1")
    assert got is not None
    assert got.match_count == 1
    assert repo.list_retro_hunts() == [got]


def test_list_retro_hunts_pagination(tmp_db: Database) -> None:
    repo = IOCRepository(tmp_db)
    _ioc(repo)
    for i in range(5):
        repo.insert_retro_hunt(
            RetroHunt(
                hunt_id=f"h-{i}",
                indicator_id="ioc-1",
                search_scope="s",
                total_events_searched=1,
                match_count=0,
                search_timestamp=f"2026-01-01T00:00:{i:02d}Z",
            )
        )
    assert len(repo.list_retro_hunts(limit=2)) == 2
    assert len(repo.list_retro_hunts(limit=2, offset=2)) == 2
