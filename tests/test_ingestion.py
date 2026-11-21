"""Tests for log ingestion and normalization (milestone 1-2).

Covers JSON, JSONL and Sysmon-style readers, raw-log preservation, normalized
schema fields, event-id fallback, and graceful handling of malformed input.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from sentinelforge.ingestion.normalizer import normalize
from sentinelforge.ingestion.reader import JSONLReader, JSONReader, SysmonReader, reader_for, LogParseError


def _write_tmp(content: str, suffix: str) -> str:
    fd, path = tempfile.mkstemp(suffix=suffix, text=True)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(content)
    return path


def test_json_reader_single_event():
    path = _write_tmp(json.dumps({"event_id": "evt-1", "user": "alice"}), ".json")
    events = list(JSONReader().read(path))
    assert len(events) == 1
    assert events[0]["event_id"] == "evt-1"
    assert events[0]["user"] == "alice"


def test_json_reader_event_list():
    path = _write_tmp(
        json.dumps([{"event_id": "a"}, {"event_id": "b"}]), ".json"
    )
    events = list(JSONReader().read(path))
    assert [e["event_id"] for e in events] == ["a", "b"]


def test_jsonl_reader_raises_on_malformed_line():
    """JSONLReader raises LogParseError on malformed line (no silent data loss)."""
    content = '{"event_id": "1"}\n\nnot json\n{"event_id": "2"}\n'
    path = _write_tmp(content, ".jsonl")
    try:
        list(JSONLReader().read(path))
        assert False, "Expected LogParseError"
    except LogParseError as e:
        assert e.line_number == 3  # line 3 is "not json"
        assert "not json" in e.line


def test_jsonl_reader_imports_logparseerror():
    """LogParseError is importable from reader module."""
    from sentinelforge.ingestion.reader import LogParseError
    assert issubclass(LogParseError, ValueError)


def test_sysmon_reader_extracts_fields():
    raw = {
        "Event": {
            "System": {"TimeCreated": {"#text": "2024-01-01T00:00:00Z"}, "Computer": "HOST-1"},
            "EventData": {
                "Data": [
                    {"Name": "Image", "#text": "C:\\Windows\\System32\\powershell.exe"},
                    {"Name": "CommandLine", "#text": "-enc AAAA"},
                    {"Name": "ProcessId", "#text": "4242"},
                    {"Name": "ParentProcessId", "#text": "1337"},
                ]
            },
        }
    }
    path = _write_tmp(json.dumps(raw), ".json")
    events = list(SysmonReader().read(path))
    assert len(events) == 1
    fields = events[0]["Event"]["EventData"]["Data"]
    names = {d["Name"] for d in fields}
    assert "Image" in names and "CommandLine" in names


def test_normalize_preserves_raw_verbatim():
    raw = {"event_id": "evt-1", "user": "alice", "extra": {"nested": [1, 2]}}
    event = normalize(raw, source="json")
    assert event.raw == raw
    assert event.event_id == "evt-1"
    assert event.user == "alice"
    assert event.source == "json"


def test_normalize_jsonl_raw_event():
    raw = {
        "timestamp": "2024-01-01T00:00:00Z",
        "event_type": "authentication",
        "user": "bob",
        "authentication": {"outcome": "failure", "method": "password"},
    }
    event = normalize(raw, source="jsonl")
    assert event.timestamp == "2024-01-01T00:00:00+00:00"
    assert event.event_type == "authentication"
    assert event.authentication is not None
    assert event.authentication.outcome == "failure"


def test_normalize_sysmon_maps_process_tree():
    raw = {
        "Event": {
            "System": {"TimeCreated": {"#text": "2024-01-01T00:00:00Z"}},
            "EventData": {
                "Data": [
                    {"Name": "Image", "#text": "C:\\Windows\\System32\\calc.exe"},
                    {"Name": "ProcessId", "#text": "9000"},
                    {"Name": "ParentProcessId", "#text": "1000"},
                    {"Name": "CommandLine", "#text": "calc.exe"},
                ]
            },
        }
    }
    event = normalize(raw, source="sysmon")
    assert event.process is not None
    assert event.process.pid == 9000
    assert event.process.ppid == 1000
    assert event.process.name == "C:\\Windows\\System32\\calc.exe"


def test_normalize_missing_fields_are_absent_not_invented():
    raw = {"event_id": "evt-empty"}
    event = normalize(raw, source="json")
    assert event.user is None
    assert event.host is None
    assert event.process is None
    assert event.network is None
    assert event.authentication is None
    assert event.event_id == "evt-empty"


def test_normalize_generates_id_when_missing():
    raw = {"user": "noid"}
    event = normalize(raw, source="json")
    assert isinstance(event.event_id, str) and event.event_id


def test_reader_for_picks_by_extension():
    jsonl_path = _write_tmp('{"a": 1}\n{"b": 2}\n', ".jsonl")
    json_path = _write_tmp('{"a": 1}', ".json")
    assert isinstance(reader_for(jsonl_path), JSONLReader)
    assert isinstance(reader_for(json_path), JSONReader)
