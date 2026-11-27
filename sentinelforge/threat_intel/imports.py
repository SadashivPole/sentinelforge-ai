"""Bounded local IOC import workflow.

Imports indicators from CSV or JSON files stored locally. Validates syntax,
canonicalizes values, rejects malformed records, caps file size and record
count, and preserves source provenance. No network requests are made and no
data is uploaded to external services.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sentinelforge.threat_intel.validator import (
    ValidationError,
    validate_indicator,
)

MAX_IMPORT_FILE_BYTES = 5 * 1024 * 1024  # 5 MiB
MAX_IMPORT_RECORDS = 10_000

_VALID_TYPES = {"ipv4", "ipv6", "domain", "url", "sha256"}


@dataclass(frozen=True)
class ImportedIOC:
    """A successfully imported and validated IOC, ready for storage."""

    indicator_id: str
    indicator_value: str
    indicator_type: str
    source_name: str
    source_reference: str | None = None
    confidence: int | None = None
    first_seen: str | None = None
    last_seen: str | None = None
    expiration: str | None = None
    imported_at: str = ""
    context: str | None = None
    provenance: str | None = None
    validation_status: str = "valid"


@dataclass(frozen=True)
class RejectedRecord:
    """A record that failed import validation."""

    line_number: int
    raw: str
    reason: str


@dataclass(frozen=True)
class ImportResult:
    """Outcome of an import: accepted IOCs and rejected records."""

    imported: list[ImportedIOC]
    rejected: list[RejectedRecord]
    source_name: str


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _make_indicator_id(source_name: str, indicator_type: str, value: str) -> str:
    payload = f"{source_name}|{indicator_type}|{value}"
    return "ioc-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:24]


def _parse_confidence(raw: Any) -> int | None:
    if raw is None or raw == "":
        return None
    try:
        conf = int(raw)
    except (TypeError, ValueError):
        return None
    return conf if 0 <= conf <= 100 else None


def _read_json_records(text: str) -> list[dict[str, Any]]:
    """Parse JSON safely (json module only — no eval/exec)."""
    data = json.loads(text)
    if isinstance(data, dict):
        indicators = data.get("indicators")
        if isinstance(indicators, list):
            return indicators
        return [data]
    if isinstance(data, list):
        return data
    raise ValueError("JSON payload must be an object or array of records")


def _read_csv_records(text: str) -> list[dict[str, Any]]:
    reader = csv.DictReader(io.StringIO(text))
    return [dict(row) for row in reader]


def import_iocs(
    file_bytes: bytes,
    source_name: str,
    *,
    source_reference: str | None = None,
) -> ImportResult:
    """Import and validate IOCs from a local CSV/JSON file.

    Returns an :class:`ImportResult` with imported IOCs and rejected
    records. Does not mutate the database directly; the caller persists via
    :class:`~sentinelforge.storage.repositories.IOCRepository`.
    """
    if not source_name or not source_name.strip():
        raise ValueError("source_name is required")

    if len(file_bytes) > MAX_IMPORT_FILE_BYTES:
        raise ValueError(
            f"Import file too large: {len(file_bytes)} bytes "
            f"(max {MAX_IMPORT_FILE_BYTES})"
        )

    try:
        text = file_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Import file must be UTF-8 encoded") from exc

    stripped = text.lstrip()
    if stripped.startswith(("{", "[")):
        raw_records = _read_json_records(text)
    else:
        raw_records = _read_csv_records(text)

    if len(raw_records) > MAX_IMPORT_RECORDS:
        raise ValueError(
            f"Too many records: {len(raw_records)} (max {MAX_IMPORT_RECORDS})"
        )

    imported: list[ImportedIOC] = []
    rejected: list[RejectedRecord] = []
    now = _now_iso()
    seen: set[tuple[str, str]] = set()

    for line_number, record in enumerate(raw_records, start=1):
        raw = str(record)
        if not isinstance(record, dict):
            rejected.append(
                RejectedRecord(line_number, raw, "record is not a JSON object")
            )
            continue
        indicator_type = str(record.get("indicator_type", "")).strip().lower()
        value = str(record.get("indicator_value", "")).strip()

        if indicator_type not in _VALID_TYPES:
            rejected.append(
                RejectedRecord(line_number, raw, "missing or invalid indicator_type")
            )
            continue
        if not value:
            rejected.append(RejectedRecord(line_number, raw, "missing indicator_value"))
            continue

        try:
            canonical = validate_indicator(indicator_type, value)
        except ValidationError as exc:
            rejected.append(RejectedRecord(line_number, raw, str(exc)))
            continue

        key = (indicator_type, canonical)
        if key in seen:
            rejected.append(
                RejectedRecord(line_number, raw, "duplicate indicator within import")
            )
            continue
        seen.add(key)

        confidence = _parse_confidence(record.get("confidence"))
        imported.append(
            ImportedIOC(
                indicator_id=_make_indicator_id(source_name, indicator_type, canonical),
                indicator_value=canonical,
                indicator_type=indicator_type,
                source_name=source_name.strip(),
                source_reference=source_reference,
                confidence=confidence,
                first_seen=record.get("first_seen") or None,
                last_seen=record.get("last_seen") or None,
                expiration=record.get("expiration") or None,
                imported_at=now,
                context=record.get("context") or None,
                provenance=f"import:{source_name.strip()}",
                validation_status="valid",
            )
        )

    return ImportResult(
        imported=imported, rejected=rejected, source_name=source_name.strip()
    )
