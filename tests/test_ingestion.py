"""Tests for log ingestion and normalization (milestone 1-2).

Covers JSON, JSONL and Sysmon-style readers, raw-log preservation, normalized
schema fields, event-id fallback, and graceful handling of malformed input.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from sentinelforge.ingestion.normalizer import normalize, normalize_stream
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


# ---------------------------------------------------------------------------
# Invalid records handling (M9.1 finding: non-dict records must be recorded
# as skipped, not silently dropped)
# ---------------------------------------------------------------------------


def test_json_reader_skips_non_dict_items():
    """Non-dict items in a JSON array are recorded as skipped, not dropped."""
    path = _write_tmp(
        json.dumps([{"event_id": "a"}, "not a dict", 42, {"event_id": "b"}]),
        ".json",
    )
    reader = JSONReader()
    events = list(reader.read(path))
    assert len(events) == 2
    assert [e["event_id"] for e in events] == ["a", "b"]
    assert len(reader.skipped_records) == 2
    # Verify skipped record info includes line number and content
    for line_no, content, reason in reader.skipped_records:
        assert line_no > 0
        assert "not a JSON object" in reason


def test_jsonl_reader_skips_non_dict_lines():
    """Non-dict JSONL lines are recorded as skipped, not silently dropped."""
    path = _write_tmp(
        '{"event_id": "a"}\n12345\n{"event_id": "b"}\ntrue\n',
        ".jsonl",
    )
    reader = JSONLReader()
    events = list(reader.read(path))
    assert len(events) == 2
    assert [e["event_id"] for e in events] == ["a", "b"]
    assert len(reader.skipped_records) == 2
    # Verify line numbers are correct
    line_nos = [ln for ln, _, _ in reader.skipped_records]
    assert 2 in line_nos  # "12345" is line 2
    assert 4 in line_nos  # "true" is line 4


def test_sysmon_reader_skips_non_dict_records():
    """Non-dict records in Sysmon input are recorded as skipped."""
    path = _write_tmp(
        json.dumps([
            {"Event": {"System": {}, "EventData": {"Data": []}}},
            "not a dict",
            42,
            {"Event": {"System": {}, "EventData": {"Data": []}}},
        ]),
        ".json",
    )
    reader = SysmonReader()
    events = list(reader.read(path))
    assert len(events) == 2
    assert len(reader.skipped_records) == 2


# ---------------------------------------------------------------------------
# Event ID correctness (M10.1: source_file + position + content hash)
# ---------------------------------------------------------------------------


def test_event_id_preserves_source_supplied_id():
    """Source-supplied event_id is preserved verbatim."""
    raw = {"event_id": "src-id-123", "user": "alice"}
    event = normalize(raw, source="json")
    assert event.event_id == "src-id-123"


def test_event_id_identical_records_different_positions_get_distinct_ids():
    """Two identical records at different positions must get distinct IDs."""
    raw = {"user": "bob", "outcome": "failure"}
    e1 = normalize(raw, source="jsonl", source_file="/logs/a.jsonl", position=1)
    e2 = normalize(raw, source="jsonl", source_file="/logs/a.jsonl", position=2)
    assert e1.event_id != e2.event_id


def test_event_id_identical_records_different_files_get_distinct_ids():
    """Identical records in different source files must get distinct IDs."""
    raw = {"user": "bob", "outcome": "failure"}
    e1 = normalize(raw, source="jsonl", source_file="/logs/file1.jsonl", position=1)
    e2 = normalize(raw, source="jsonl", source_file="/logs/file2.jsonl", position=1)
    assert e1.event_id != e2.event_id


def test_event_id_same_file_same_position_stable_on_reingest():
    """Re-ingesting the same source record produces a stable ID."""
    raw = {"user": "carol", "outcome": "failure"}
    e1 = normalize(raw, source="json", source_file="/logs/single.json", position=1)
    e2 = normalize(raw, source="json", source_file="/logs/single.json", position=1)
    assert e1.event_id == e2.event_id


def test_event_id_changed_content_gets_distinct_id():
    """Different content at the same source+position gets a distinct ID."""
    raw_a = {"user": "dave", "action": "login"}
    raw_b = {"user": "dave", "action": "logout"}
    e1 = normalize(raw_a, source="json", source_file="/logs/x.json", position=1)
    e2 = normalize(raw_b, source="json", source_file="/logs/x.json", position=1)
    assert e1.event_id != e2.event_id


def test_event_id_no_source_file_falls_back_to_content_hash():
    """Without source_file/position, content-only hash is used (backward compat)."""
    raw = {"user": "eve"}
    e1 = normalize(raw, source="json")
    e2 = normalize(raw, source="json")
    assert e1.event_id == e2.event_id


# ---------------------------------------------------------------------------
# Sysmon ingestion: content-based recognition regardless of extension
# ---------------------------------------------------------------------------


def test_sysmon_recognized_by_content_not_extension():
    """Sysmon-formatted JSON with a .json extension uses SysmonReader."""
    raw = {
        "Event": {
            "System": {"TimeCreated": {"SystemTime": "2024-01-01T00:00:00Z"}},
            "EventData": {
                "Data": [
                    {"Name": "Image", "#text": "C:\\\\Windows\\\\calc.exe"},
                    {"Name": "ProcessId", "#text": "9000"},
                    {"Name": "ParentProcessId", "#text": "1000"},
                    {"Name": "CommandLine", "#text": "calc.exe"},
                ]
            },
        }
    }
    path = _write_tmp(json.dumps(raw), ".json")
    reader = reader_for(path)
    assert isinstance(reader, SysmonReader)


def test_sysmon_normalization_maps_process_fields():
    """Sysmon normalization maps PID, PPID, path, command line, hostname, timestamps."""
    raw = {
        "Event": {
            "System": {
                "TimeCreated": {"SystemTime": "2024-01-15T08:30:00Z"},
                "Computer": "HOST-01",
            },
            "EventData": {
                "Data": [
                    {"Name": "Image", "#text": "C:\\\\Windows\\\\System32\\\\powershell.exe"},
                    {"Name": "ProcessId", "#text": "4242"},
                    {"Name": "ParentProcessId", "#text": "1337"},
                    {"Name": "CommandLine", "#text": "powershell -enc AAAA"},
                    {"Name": "User", "#text": "USER-01\\\\admin"},
                ]
            },
        }
    }
    path = _write_tmp(json.dumps(raw), ".json")
    events = list(SysmonReader().read(path))
    event = normalize(events[0], source="sysmon")
    assert event.process is not None
    assert event.process.pid == 4242
    assert event.process.ppid == 1337
    assert event.process.path == "C:\\\\Windows\\\\System32\\\\powershell.exe"
    assert event.process.command_line == "powershell -enc AAAA"
    assert event.host == "HOST-01"
    assert event.timestamp == "2024-01-15T08:30:00+00:00"


def test_sysmon_unknown_fields_preserved_in_raw():
    """Unknown Sysmon fields remain preserved in the raw payload."""
    raw = {
        "Event": {
            "System": {"TimeCreated": {"SystemTime": "2024-01-01T00:00:00Z"}},
            "EventData": {
                "Data": [
                    {"Name": "Image", "#text": "calc.exe"},
                    {"Name": "CustomField", "#text": "custom-value"},
                ]
            },
        }
    }
    path = _write_tmp(json.dumps(raw), ".json")
    events = list(SysmonReader().read(path))
    event = normalize(events[0], source="sysmon")
    raw_event = events[0]
    data_map = {d["Name"]: d["#text"] for d in raw_event["Event"]["EventData"]["Data"]}
    assert data_map.get("CustomField") == "custom-value"


# ---------------------------------------------------------------------------
# normalize_stream: source identity and position for stream ingestion
# ---------------------------------------------------------------------------


def test_normalize_stream_distinct_positions_distinct_ids():
    """normalize_stream assigns distinct IDs to identical records at different positions."""
    raw = {"user": "bob", "outcome": "failure"}
    events = list(
        normalize_stream(
            iter([raw, raw]),
            source="jsonl",
            source_file="/logs/stream.jsonl",
            start_position=1,
        )
    )
    assert len(events) == 2
    assert events[0].event_id != events[1].event_id


def test_normalize_stream_distinct_files_distinct_ids():
    """normalize_stream assigns distinct IDs to identical records from different files."""
    raw = {"user": "bob", "outcome": "failure"}
    e1 = list(
        normalize_stream(
            iter([raw]),
            source="jsonl",
            source_file="/logs/file_a.jsonl",
            start_position=1,
        )
    )[0]
    e2 = list(
        normalize_stream(
            iter([raw]),
            source="jsonl",
            source_file="/logs/file_b.jsonl",
            start_position=1,
        )
    )[0]
    assert e1.event_id != e2.event_id


def test_normalize_stream_stable_on_reingest():
    """normalize_stream produces stable IDs when re-ingesting the same source."""
    raw = {"user": "carol", "outcome": "failure"}
    e1 = list(
        normalize_stream(
            iter([raw]), source="json", source_file="/logs/single.json", start_position=1
        )
    )[0]
    e2 = list(
        normalize_stream(
            iter([raw]), source="json", source_file="/logs/single.json", start_position=1
        )
    )[0]
    assert e1.event_id == e2.event_id


def test_normalize_stream_requires_source_file():
    """normalize_stream without source_file raises ValueError (no content-only fallback).

    Persistent stream/batch ingestion must not silently fall back to
    content-only hashing, because identical records would be falsely
    deduplicated.
    """
    raw = {"user": "eve"}
    try:
        list(normalize_stream(iter([raw]), source="json"))
        assert False, "Expected ValueError for normalize_stream without source_file"
    except ValueError as exc:
        assert "source_file" in str(exc)
        assert "source-supplied event ID" in str(exc)


def test_normalize_stream_with_source_provided_ids_works_without_source_file():
    """normalize_stream works without source_file when all records have source-provided IDs.

    Source-provided IDs take priority over generated IDs, so source_file
    is not needed when every record carries its own event_id.
    """
    raw_a = {"event_id": "src-id-a", "user": "alice"}
    raw_b = {"event_id": "src-id-b", "user": "bob"}
    events = list(
        normalize_stream(
            iter([raw_a, raw_b]), source="json", source_file=None
        )
    )
    assert len(events) == 2
    assert events[0].event_id == "src-id-a"
    assert events[1].event_id == "src-id-b"


def test_normalize_stream_mixed_source_and_missing_ids_fails():
    """A stream with some records lacking source-provided IDs fails when source_file is missing.

    Even one record without a source-provided ID in a stream without
    source_file must fail, because its generated ID would be content-only
    and could falsely deduplicate.
    """
    raw_with_id = {"event_id": "src-id-1", "user": "alice"}
    raw_without_id = {"user": "bob"}
    try:
        list(
            normalize_stream(
                iter([raw_with_id, raw_without_id]),
                source="json",
                source_file=None,
            )
        )
        assert False, "Expected ValueError for stream with missing source_file and missing source ID"
    except ValueError as exc:
        assert "source_file" in str(exc)


def test_normalize_stream_changed_content_at_same_position_distinct_ids():
    """Changed content at the same source position produces a distinct ID.

    The collision policy stores both records; different content at the same
    source+position yields different IDs so neither silently overwrites the
    other.
    """
    raw_a = {"user": "dave", "action": "login"}
    raw_b = {"user": "dave", "action": "logout"}
    e1 = list(
        normalize_stream(
            iter([raw_a]),
            source="json",
            source_file="/logs/x.json",
            start_position=1,
        )
    )[0]
    e2 = list(
        normalize_stream(
            iter([raw_b]),
            source="json",
            source_file="/logs/x.json",
            start_position=1,
        )
    )[0]
    assert e1.event_id != e2.event_id


# ---------------------------------------------------------------------------
# Config boundary: max_detection_events validation
# ---------------------------------------------------------------------------


def test_config_max_detection_events_default():
    """Default max_detection_events is 100_000."""
    from sentinelforge.config import Settings

    s = Settings()
    assert s.max_detection_events == 100_000


def test_config_max_detection_events_rejects_zero():
    """max_detection_events=0 raises ValueError."""
    from sentinelforge.config import Settings

    try:
        Settings(max_detection_events=0)
        assert False, "Expected ValueError for max_detection_events=0"
    except ValueError as exc:
        assert "max_detection_events" in str(exc)


def test_config_max_detection_events_rejects_negative():
    """max_detection_events=-5 raises ValueError."""
    from sentinelforge.config import Settings

    try:
        Settings(max_detection_events=-5)
        assert False, "Expected ValueError for max_detection_events=-5"
    except ValueError as exc:
        assert "max_detection_events" in str(exc)


def test_config_max_detection_env_var_malformed_raises_error():
    """Malformed env var raises ValueError instead of silent fallback."""
    import os

    os.environ["SENTINELFORGE_MAX_DETECTION_EVENTS"] = "abc"
    try:
        import importlib

        import sentinelforge.config as config_mod

        importlib.reload(config_mod)
        assert False, "Expected ValueError for malformed max_detection_events"
    except ValueError as exc:
        assert "SENTINELFORGE_MAX_DETECTION_EVENTS" in str(exc)
        assert "abc" in str(exc)
    finally:
        os.environ.pop("SENTINELFORGE_MAX_DETECTION_EVENTS", None)
        importlib.reload(config_mod)


def test_config_max_detection_env_var_empty_raises_error():
    """Empty env var value raises ValueError instead of silent fallback."""
    import os

    os.environ["SENTINELFORGE_MAX_DETECTION_EVENTS"] = "   "
    try:
        import importlib

        import sentinelforge.config as config_mod

        importlib.reload(config_mod)
        assert False, "Expected ValueError for empty max_detection_events"
    except ValueError as exc:
        assert "SENTINELFORGE_MAX_DETECTION_EVENTS" in str(exc)
        assert "empty or whitespace-only" in str(exc)
    finally:
        os.environ.pop("SENTINELFORGE_MAX_DETECTION_EVENTS", None)
        importlib.reload(config_mod)


def test_config_max_detection_events_accepts_valid_boundary():
    """max_detection_events=1 is accepted."""
    from sentinelforge.config import Settings

    s = Settings(max_detection_events=1)
    assert s.max_detection_events == 1
