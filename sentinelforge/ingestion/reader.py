"""Log readers for JSON, JSONL and Sysmon-style event sources.

Every reader yields raw event dicts exactly as they appear in the source.
No field is invented, no value is transformed, and the original payload is
preserved verbatim for downstream normalization and evidence storage.

Readers do not silently discard records. Malformed lines in JSONL sources
raise a :class:`LogParseError` so data loss is never silent.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from collections.abc import Iterator
from pathlib import Path


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
            message
            or f"Failed to parse log record at line {line_number}: {line[:120]!r}"
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


def _generate_event_id(
    raw: dict, source_file: str | None = None, position: int | None = None
) -> str:
    """Generate a deterministic event ID from source identity + content.

    When ``source_file`` and ``position`` are provided, the ID is derived
    from (source_file, position, canonical content). This ensures:

    - Two identical records at different positions get distinct IDs.
    - Identical records in different source files get distinct IDs.
    - Re-ingesting the same source file produces stable IDs.

    When ``source_file`` is missing (single-event utility calls without
    ingestion context), a content-only hash is used for backward
    compatibility. In that fallback mode, distinct but identical records
    may receive the same ID — this is safe only for single-event,
    non-persistent use. Persistent batch/stream ingestion must supply
    source_file via normalize_stream() or cmd_ingest().

    The identifier depends on the source file path; moving or renaming a
    source file changes generated IDs. Do not claim universal idempotency
    across relocated files.
    """
    import hashlib
    import json

    identity_parts: list[str] = []
    if source_file is not None:
        identity_parts.append(f"source:{source_file}")
    if position is not None:
        identity_parts.append(f"position:{position}")
    identity_parts.append(
        f"content:{json.dumps(raw, sort_keys=True, ensure_ascii=False)}"
    )

    return hashlib.sha256("|".join(identity_parts).encode("utf-8")).hexdigest()


def _get_event_id(
    raw: dict,
    source_file: str | None = None,
    position: int | None = None,
    allow_fallback: bool = False,
) -> str:
    """Return an event id from the raw record without inventing semantics.

    Only ids already present in the raw log are used; otherwise a
    deterministic id is derived from source file, record position, and
    canonical content.

    Identity policy:
      A. Source-supplied event_id is preserved verbatim.
      B. For generated ids: source_file + position + content hash.
      C. Same source record + same content = idempotent re-ingestion.
      D. Different source record + identical content = distinct IDs (both
         preserved; no false deduplication).
      E. Same generated id with different content = collision, detected
         by the storage layer's content-hash comparison.

    Parameters:
        allow_fallback: When True and no source-supplied ID exists and
            source_file is None, fall back to a content-only hash. This
            is safe only for single-event, non-persistent use. When
            False (stream/batch ingestion), a ValueError is raised
            instead.

    Raises:
        ValueError: If no source-supplied ID exists, source_file is None,
            and allow_fallback is False.
    """
    for key in ("event_id", "id", "EventID", "record_id", "uuid"):
        value = raw.get(key)
        if value is not None:
            return str(value)
    if source_file is None and not allow_fallback:
        raise ValueError(
            "Cannot generate event ID without source_file: record lacks a "
            "source-supplied event ID and no source identity was provided. "
            "Persistent batch/stream ingestion requires source_file so that "
            "identical records receive distinct IDs. Provide source_file or "
            "ensure records carry an event_id field."
        )
    return _generate_event_id(raw, source_file=source_file, position=position)


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
    """Abstract reader. Subclasses yield raw event dicts."""

    def __init__(self) -> None:
        self.skipped_records: list[tuple[int, str, str]] = []
        """Records that could not be parsed as event objects.

        Each entry is (line_number, raw_content, reason).
        """

    @abstractmethod
    def read(self, path: str | Path) -> Iterator[dict]:
        """Yield raw event dicts from ``path``."""


class JSONReader(LogReader):
    """Read a single JSON document.

    Accepts either a single event object or a list of event objects.
    Non-dict items in a JSON array are recorded as skipped records rather
    than silently dropped.
    """

    def read(self, path: str | Path) -> Iterator[dict]:
        with open(path, "r", encoding="utf-8") as handle:
            content = handle.read()
        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            raise LogParseError(1, content, str(exc)) from exc
        if isinstance(data, list):
            for i, item in enumerate(data):
                if isinstance(item, dict):
                    yield item
                else:
                    self.skipped_records.append(
                        (i + 1, json.dumps(item)[:200], "not a JSON object")
                    )
        elif isinstance(data, dict):
            yield data
        else:
            raise TypeError(
                f"Unsupported JSON root type in {path}: {type(data).__name__}"
            )


class JSONLReader(LogReader):
    """Read JSON Lines: one JSON object per line.

    Blank lines are skipped. Malformed lines raise :class:`LogParseError`
    so data loss is never silent. Non-dict JSON objects are recorded as
    skipped records rather than silently dropped.
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
                    raise LogParseError(line_number, line, str(exc)) from exc
                if isinstance(item, dict):
                    yield item
                else:
                    self.skipped_records.append(
                        (line_number, line[:200], "not a JSON object")
                    )


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
    per line). Malformed JSONL lines raise :class:`LogParseError`. Non-dict
    records are recorded as skipped rather than silently dropped.
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
                    raise LogParseError(line_number, line, str(exc)) from exc
                if isinstance(item, dict):
                    records.append(item)
                else:
                    self.skipped_records.append(
                        (line_number, line[:200], "not a JSON object")
                    )

        for record in records:
            if not isinstance(record, dict):
                self.skipped_records.append(
                    (0, json.dumps(record)[:200], "not a JSON object")
                )
                continue
            event = record.get("Event", record)
            if not isinstance(event, dict):
                self.skipped_records.append(
                    (0, json.dumps(record)[:200], "not a Sysmon event object")
                )
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
                fields[str(name)] = str(item.get("#text", item.get("text", "")) or "")

            yield {
                "Event": {
                    "System": system,
                    "EventData": {
                        "Data": [{"Name": k, "#text": v} for k, v in fields.items()]
                    },
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
