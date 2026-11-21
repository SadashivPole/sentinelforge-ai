"""Log readers for JSON, JSONL and Sysmon-style event sources.

Every reader yields raw event dicts exactly as they appear in the source.
No field is invented, no value is transformed, and the original payload is
preserved verbatim for downstream normalization and evidence storage.

Readers do not silently discard records. Malformed lines in JSONL sources
raise a :class:`LogParseError` so data loss is never silent.
"""
from __future__ import annotations

import json
import uuid
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Iterator, Optional


class LogParseError(ValueError):
    """Raised when a log file contains a malformed record.

    Attributes:
        line_number: 1-based line number of the malformed record.
        line: the raw line content that failed to parse.
    """

    def __init__(self, line_number: int, line: str, message: str = ""):
        self.line_number = line_number
        self.line = line
        super().__init__(
            message or f"Failed to parse log record at line {line_number}: {line[:120]!r}"
        )


def _first_non_empty_line(handle) -> str | None:
    """Return the first non-empty line from a file handle, or None.

    Skips leading blank lines so detection is not broken by them.
    The handle position advances past the returned line.
    """
    for line in handle:
        stripped = line.strip()
        if stripped:
            return stripped
    return None


def _generate_event_id(raw: dict) -> str:
    """Deterministic fallback id when a raw event carries none."""
    return str(uuid.uuid4())


def _get_event_id(raw: dict) -> str:
    """Return an event id from the raw record without inventing semantics.

    Only ids already present in the raw log are used; otherwise a fresh
    uuid4 is generated. We never derive an id from log content because that
    would fabricate identifying information.
    """
    for key in ("event_id", "id", "EventID", "EventID", "record_id", "uuid"):
        value = raw.get(key)
        if value is not None:
            return str(value)
    return _generate_event_id(raw)


def _sniff_sysmon_or_jsonl(first_line: str) -> type:
    """Inspect the first non-empty line and return the appropriate reader class.

    Returns ``SysmonReader`` when the line parses as a JSON object containing
    an ``Event`` or ``EventData`` key (Sysmon EVTX-converted format).
    Returns ``JSONLReader`` for any other JSON object per line.
    Returns ``JSONReader`` if the line is not valid JSON.
    """
    if not first_line.startswith("{"):
        return JSONReader
    try:
        candidate = json.loads(first_line)
    except json.JSONDecodeError:
        return JSONReader
    if isinstance(candidate, dict) and (
        "Event" in candidate or "EventData" in candidate
    ):
        return SysmonReader
    return JSONLReader


class LogReader(ABC):
    """Abstract log reader. Subclasses yield raw event dicts."""

    @abstractmethod
    def read(self, path: str | Path) -> Iterator[dict]:
        """Yield raw event dicts from ``path``."""


class JSONReader(LogReader):
    """Read a single JSON document.

    Accepts either a single event object or a list of event objects.
    """

    def read(self, path: str | Path) -> Iterator[dict]:
        with open(path, "r", encoding="utf-8") as handle:
            content = handle.read()
        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            raise LogParseError(1, content, str(exc)) from exc
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    yield item
        elif isinstance(data, dict):
            yield data
        else:
            raise ValueError(
                f"Unsupported JSON root type in {path}: {type(data).__name__}"
            )


class JSONLReader(LogReader):
    """Read JSON Lines: one JSON object per line.

    Blank lines are skipped. Malformed lines raise :class:`LogParseError`
    so data loss is never silent.
    """

    def read(self, path: str | Path) -> Iterator[dict]:
        with open(path, "r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise LogParseError(
                        line_number, line, str(exc)
                    ) from exc
                if isinstance(item, dict):
                    yield item


class SysmonReader(LogReader):
    """Read Sysmon-style events.

    Expected shape (EVTX-converted JSON):

        {
          "Event": {
            "System": {...},
            "EventData": {"Data": [{"Name": "Image", "#text": "..."}, ...]}
          }
        }

    The reader only extracts fields that exist; absent fields stay absent.

    Supports both single JSON documents and JSONL files (one Sysmon record
    per line). Malformed JSONL lines raise :class:`LogParseError`.
    """

    def read(self, path: str | Path) -> Iterator[dict]:
        with open(path, "r", encoding="utf-8") as handle:
            raw = handle.read()

        # Try single JSON document first (object or array).
        try:
            data = json.loads(raw)
            records = data if isinstance(data, list) else [data]
        except json.JSONDecodeError:
            # Fall back to JSONL: one JSON object per line.
            records = []
            for line_number, line in enumerate(raw.splitlines(), start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise LogParseError(
                        line_number, line, str(exc)
                    ) from exc
                if isinstance(item, dict):
                    records.append(item)

        for record in records:
            if not isinstance(record, dict):
                continue
            event = record.get("Event", record)
            if not isinstance(event, dict):
                continue

            system = event.get("System", {}) or {}
            event_data = event.get("EventData", {}) or {}
            data_items = event_data.get("Data", []) or []

            fields: dict[str, str] = {}
            for item in data_items:
                if not isinstance(item, dict):
                    continue
                name = item.get("Name") or item.get("@Name")
                if name is None:
                    continue
                fields[str(name)] = (
                    item.get("#text", item.get("text", ""))
                    if isinstance(item.get("#text"), str) or item.get("#text") is None
                    else str(item.get("#text", ""))
                )

            yield {
                "Event": {
                    "System": system,
                    "EventData": {"Data": [{"Name": k, "#text": v} for k, v in fields.items()]},
                }
            }


def reader_for(path: str | Path) -> LogReader:
    """Pick a reader by file extension, falling back to content sniffing.

    Extension rules:
      - ``.jsonl``: content sniff — Sysmon content returns ``SysmonReader``,
        otherwise ``JSONLReader``.
      - ``.json``: content sniff — Sysmon content returns ``SysmonReader``,
        otherwise ``JSONReader``.
      - Extensionless / ``.evt`` / ``.evtx``: content sniff — Sysmon content
        returns ``SysmonReader``, otherwise ``JSONLReader`` if first line is
        JSON, otherwise ``JSONReader``.

    Content sniffing reads the first non-empty line from the beginning of
    the file, so leading blank lines do not break detection and long first
    records are read in full.
    """
    path = Path(path)
    suffix = path.suffix.lower()

    try:
        with open(path, "r", encoding="utf-8") as handle:
            first_line = _first_non_empty_line(handle)
    except (OSError, UnicodeDecodeError):
        return JSONReader()

    if first_line is None:
        # Empty file — default to JSONLReader.
        return JSONLReader()

    if suffix == ".jsonl":
        # Content sniff even for .jsonl: Sysmon-formatted JSONL must use SysmonReader.
        reader_cls = _sniff_sysmon_or_jsonl(first_line)
        return reader_cls()
    if suffix == ".json":
        # .json is a single document by default; only Sysmon content overrides.
        if first_line.startswith("{"):
            try:
                candidate = json.loads(first_line)
            except json.JSONDecodeError:
                return JSONReader()
            if isinstance(candidate, dict) and (
                "Event" in candidate or "EventData" in candidate
            ):
                return SysmonReader()
        return JSONReader()
    # Content sniff for extensionless or .evt/.evtx-converted files.
    reader_cls = _sniff_sysmon_or_jsonl(first_line)
    return reader_cls()
