"""Tests for the IncidentRepository and the incidents CLI command."""

from __future__ import annotations

import argparse
import tempfile

import pytest

from sentinelforge.cli.main import cmd_incidents
from sentinelforge.storage.database import Database
from sentinelforge.storage.repositories import IncidentRepository
from sentinelforge.storage.schema import Incident


def _incident(**overrides) -> Incident:
    base = {
        "incident_id": "inc-1",
        "title": "Brute force on WKSTN-10",
        "correlation_rationale": "4625 failures from 10.0.0.99 targeting administrator",
        "severity": "high",
        "status": "open",
        "hosts": ["WKSTN-10"],
        "users": ["administrator"],
        "source_addresses": ["10.0.0.99"],
        "first_seen": "2024-01-15T08:00:00+00:00",
        "last_seen": "2024-01-15T08:10:00+00:00",
        "evidence_complete": False,
        "related_alert_count": 3,
        "related_event_count": 45,
        "created_at": "2024-01-15T08:00:00+00:00",
        "updated_at": "2024-01-15T08:10:00+00:00",
    }
    base.update(overrides)
    return Incident(**base)


def _db() -> Database:
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        name = tmp.name
    db = Database(name)
    db.initialize()
    return db


def test_insert_and_get_incident() -> None:
    db = _db()
    repo = IncidentRepository(db)
    inc = _incident()
    assert repo.insert_incident(inc) == "inc-1"

    got = repo.get_incident("inc-1")
    assert got is not None
    assert got.incident_id == "inc-1"
    assert got.title == "Brute force on WKSTN-10"
    assert got.severity == "high"
    assert got.status == "open"
    assert got.hosts == ["WKSTN-10"]
    assert got.users == ["administrator"]
    assert got.source_addresses == ["10.0.0.99"]
    assert got.related_alert_count == 3
    assert got.related_event_count == 45
    assert got.evidence_complete is False


def test_get_missing_incident_returns_none() -> None:
    db = _db()
    repo = IncidentRepository(db)
    assert repo.get_incident("does-not-exist") is None


def test_list_incidents_empty() -> None:
    db = _db()
    repo = IncidentRepository(db)
    assert repo.list_incidents() == []


def test_list_incidents_filters() -> None:
    db = _db()
    repo = IncidentRepository(db)
    repo.insert_incident(_incident(incident_id="inc-1", severity="high", status="open"))
    repo.insert_incident(
        _incident(incident_id="inc-2", severity="medium", status="closed")
    )
    assert len(repo.list_incidents()) == 2
    assert len(repo.list_incidents(status="open")) == 1
    assert repo.list_incidents(status="open")[0].incident_id == "inc-1"
    assert len(repo.list_incidents(severity="medium")) == 1


def test_insert_idempotent_same_content() -> None:
    db = _db()
    repo = IncidentRepository(db)
    inc = _incident()
    assert repo.insert_incident(inc) == "inc-1"
    assert repo.insert_incident(inc) == "inc-1"  # idempotent


def test_insert_conflicting_content_raises() -> None:
    from sentinelforge.storage.repositories import DuplicateIdCollisionError

    db = _db()
    repo = IncidentRepository(db)
    repo.insert_incident(_incident(incident_id="inc-1", severity="high"))
    with pytest.raises(DuplicateIdCollisionError):
        repo.insert_incident(_incident(incident_id="inc-1", severity="critical"))


def test_cli_list_empty(capsys) -> None:  # type: ignore[no-untyped-def]
    db = _db()
    args = argparse.Namespace(
        db_path=db.db_path, show=None, status=None, severity=None, limit=50
    )
    # cmd_incidents reads args.db_path directly.
    code = cmd_incidents(args)
    assert code == 0
    captured = capsys.readouterr()
    assert "No incidents." in captured.out


def test_cli_show_inserted_incident(capsys) -> None:  # type: ignore[no-untyped-def]
    db = _db()
    repo = IncidentRepository(db)
    repo.insert_incident(_incident(incident_id="inc-1", title="T1"))
    args = argparse.Namespace(
        db_path=db.db_path, show="inc-1", status=None, severity=None, limit=50
    )
    code = cmd_incidents(args)
    assert code == 0
    captured = capsys.readouterr()
    assert "Incident inc-1" in captured.out
    assert "T1" in captured.out
