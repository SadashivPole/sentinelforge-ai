"""Read-only SQLite data-access layer for the SOC Analyst MCP server.

Enforces read-only access independently of the rest of the codebase:
- SQLite URI ``mode=ro`` prevents file-level writes.
- ``PRAGMA query_only = ON`` prevents any SQL mutation at the connection level.
- All queries are static strings with parameterized values only.
- Result sizes are bounded via explicit LIMIT/OFFSET caps.
- Input strings are length-validated; time ranges are sanity-checked.
- Errors never leak internal paths or credentials.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Self


class ReadOnlyDatabaseError(Exception):
    """Raised when a read-only database operation cannot proceed safely."""

    def __init__(self, code: str, message: str, remediation: str | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.remediation = remediation


class DatabaseMissingError(ReadOnlyDatabaseError):
    """The database file does not exist at the configured path."""


class DatabaseNotInitializedError(ReadOnlyDatabaseError):
    """The database file exists but has not been initialized (no schema_metadata)."""


# --- safety limits ---
MAX_LIMIT = 500
MAX_OFFSET = 10_000
MAX_INPUT_LEN = 10_000
MAX_RULE_ID_LEN = 128
MAX_HOST_LEN = 256
MAX_SEVERITY_LEN = 32
MAX_TIME_RANGE_DAYS = 365


@dataclass(frozen=True)
class Pagination:
    limit: int
    offset: int

    def __post_init__(self) -> None:
        if self.limit < 1 or self.limit > MAX_LIMIT:
            raise ReadOnlyDatabaseError(
                "bad_input",
                f"limit must be between 1 and {MAX_LIMIT}",
                f"Use limit between 1 and {MAX_LIMIT}.",
            )
        if self.offset < 0 or self.offset > MAX_OFFSET:
            raise ReadOnlyDatabaseError(
                "bad_input",
                f"offset must be between 0 and {MAX_OFFSET}",
                f"Use offset between 0 and {MAX_OFFSET}.",
            )


@dataclass(frozen=True)
class TimeRange:
    start: str | None
    end: str | None

    def __post_init__(self) -> None:
        if self.start is None and self.end is None:
            return
        if self.start is not None:
            s = _parse_ts(self.start, "start")
            if s.tzinfo is None:
                raise ReadOnlyDatabaseError(
                    "bad_input",
                    "timestamps must be timezone-aware (include UTC offset or Z).",
                    "Use ISO 8601 with explicit timezone, e.g. "
                    "2024-01-15T09:30:00Z or 2024-01-15T09:30:00+00:00.",
                )
        if self.end is not None:
            e = _parse_ts(self.end, "end")
            if e.tzinfo is None:
                raise ReadOnlyDatabaseError(
                    "bad_input",
                    "timestamps must be timezone-aware (include UTC offset or Z).",
                    "Use ISO 8601 with explicit timezone, e.g. "
                    "2024-01-15T09:30:00Z or 2024-01-15T09:30:00+00:00.",
                )
        if self.start is not None and self.end is not None:
            s = _parse_ts(self.start, "start")
            e = _parse_ts(self.end, "end")
            if e < s:
                raise ReadOnlyDatabaseError(
                    "bad_input",
                    "time range end must be after start",
                    "Provide start before end.",
                )
            delta_seconds = (e - s).total_seconds()
            if delta_seconds > MAX_TIME_RANGE_DAYS * 86_400:
                raise ReadOnlyDatabaseError(
                    "bad_input",
                    f"time range must not exceed {MAX_TIME_RANGE_DAYS} days",
                    f"Narrow the time range to {MAX_TIME_RANGE_DAYS} days or less.",
                )


def _parse_ts(value: str, field: str) -> datetime:
    try:
        return datetime.fromisoformat(value)
    except (ValueError, AttributeError) as exc:
        raise ReadOnlyDatabaseError(
            "bad_input",
            f"invalid {field} timestamp: {value}",
            "Use ISO 8601 format (e.g. 2024-01-15T09:30:00Z).",
        ) from exc


def _validate_string(value: str, field: str, max_len: int) -> str:
    if not isinstance(value, str):
        raise ReadOnlyDatabaseError(
            "bad_input",
            f"{field} must be a string",
            f"Provide {field} as a JSON string.",
        )
    if len(value) > max_len:
        raise ReadOnlyDatabaseError(
            "bad_input",
            f"{field} exceeds {max_len} characters",
            f"Shorten {field} to {max_len} characters or less.",
        )
    return value


class ReadOnlyDatabase:
    """Enforced read-only wrapper around a SQLite database.

    Opens the database with ``file:path?mode=ro`` so the OS itself
    rejects writes, then sets ``PRAGMA query_only = ON`` so even
    parameterized DDL/DML cannot execute on this connection.
    """

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self._conn: sqlite3.Connection | None = None

    def __enter__(self) -> Self:
        self.open()
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def open(self) -> None:
        import os

        if not os.path.exists(self.db_path):
            raise DatabaseMissingError(
                "database_missing",
                "Database not found at the configured path.",
                "Run SentinelForge ingestion first to create the database, "
                "or set SENTINELFORGE_DB_PATH to an existing database file.",
            )

        uri = f"file:{self.db_path}?mode=ro"
        self._conn = sqlite3.connect(uri, uri=True)
        self._conn.row_factory = sqlite3.Row
        # Double enforcement: query_only prevents any mutation SQL at the
        # SQLite level, independent of the URI mode.
        self._conn.execute("PRAGMA query_only = ON;")

        # Verify schema is initialized.
        cur = self._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_metadata'"
        )
        if not cur.fetchone():
            self.close()
            raise DatabaseNotInitializedError(
                "database_not_initialized",
                "Database exists but has no schema_metadata.",
                "Initialize the database with SentinelForge before querying via MCP.",
            )

        # Prove writes are rejected at this connection level.
        self._verify_read_only()

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def _verify_read_only(self) -> None:
        """Attempt a harmless write to confirm the connection rejects it."""
        if self._conn is None:
            raise ReadOnlyDatabaseError(
                "database_not_open",
                "Database connection is not open",
                "Use ReadOnlyDatabase as a context manager or call open() first.",
            )
        try:
            self._conn.execute("CREATE TEMP TABLE IF NOT EXISTS _mcp_probe (x INTEGER)")
            raise ReadOnlyDatabaseError(
                "internal",
                "Read-only enforcement failed: a write succeeded on the MCP connection",
                "Contact the SentinelForge maintainers; the MCP database layer is misconfigured.",
            )
        except sqlite3.OperationalError:
            # Expected: query_only=ON blocks DDL.
            pass

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            raise ReadOnlyDatabaseError(
                "database_not_open",
                "Database connection is not open",
                "Use ReadOnlyDatabase as a context manager or call open() first.",
            )
        return self._conn

    # --- schema status ---

    def schema_version(self) -> int | None:
        cur = self.conn.execute(
            "SELECT value FROM schema_metadata WHERE key = ?", ("schema_version",)
        )
        row = cur.fetchone()
        return int(row[0]) if row else None

    def table_counts(self) -> dict[str, int]:
        """Return row counts per table. Table names are from a hardcoded
        allowlist; never from user input."""
        tables = ["events", "detections", "evidence", "risk_assessments"]
        counts: dict[str, int] = {}
        for table in tables:
            # nosec B608: table is from a hardcoded allowlist, never user input
            cur = self.conn.execute(f"SELECT COUNT(*) AS c FROM {table}")  # nosec B608
            counts[table] = int(cur.fetchone()[0])
        return counts

    def latest_timestamps(self) -> dict[str, str | None]:
        out: dict[str, str | None] = {}
        try:
            cur = self.conn.execute("SELECT MAX(timestamp) AS t FROM events")
            row = cur.fetchone()
            out["latest_event"] = row[0] if row else None
        except sqlite3.OperationalError:
            out["latest_event"] = None
        try:
            cur = self.conn.execute("SELECT MAX(triggered_at) AS t FROM detections")
            row = cur.fetchone()
            out["latest_detection"] = row[0] if row else None
        except sqlite3.OperationalError:
            out["latest_detection"] = None
        return out

    # --- alerts (detections) ---

    def list_alerts(
        self,
        pagination: Pagination,
        host: str | None = None,
        severity: str | None = None,
        rule_id: str | None = None,
        time_range: TimeRange | None = None,
    ) -> list[dict[str, Any]]:
        """List detections (alerts) with bounded pagination and filters."""
        if host is not None:
            _validate_string(host, "host", MAX_HOST_LEN)
        if severity is not None:
            _validate_string(severity, "severity", MAX_SEVERITY_LEN)
        if rule_id is not None:
            _validate_string(rule_id, "rule_id", MAX_RULE_ID_LEN)

        sql = (
            "SELECT detection_id, rule_id, rule_name, severity, description, "
            "triggered_at, host, metadata FROM detections WHERE 1=1"
        )
        params: list[Any] = []

        if host is not None:
            sql += " AND host = ?"
            params.append(host)
        if severity is not None:
            sql += " AND severity = ?"
            params.append(severity)
        if rule_id is not None:
            sql += " AND rule_id = ?"
            params.append(rule_id)
        if time_range is not None:
            if time_range.start is not None:
                sql += " AND julianday(triggered_at) >= julianday(?)"
                params.append(time_range.start)
            if time_range.end is not None:
                sql += " AND julianday(triggered_at) <= julianday(?)"
                params.append(time_range.end)

        sql += " ORDER BY triggered_at DESC LIMIT ? OFFSET ?"
        params.extend([pagination.limit, pagination.offset])

        cur = self.conn.execute(sql, params)
        rows = cur.fetchall()
        return [dict(r) for r in rows]

    def get_alert(self, detection_id: str) -> dict[str, Any] | None:
        _validate_string(detection_id, "detection_id", MAX_RULE_ID_LEN)
        cur = self.conn.execute(
            "SELECT detection_id, rule_id, rule_name, severity, description, "
            "triggered_at, host, metadata FROM detections WHERE detection_id = ?",
            (detection_id,),
        )
        row = cur.fetchone()
        return dict(row) if row else None

    def get_alert_evidence(
        self, detection_id: str, pagination: Pagination
    ) -> list[dict[str, Any]]:
        _validate_string(detection_id, "detection_id", MAX_RULE_ID_LEN)
        cur = self.conn.execute(
            "SELECT evidence_id, detection_id, event_id, external_event_ref, "
            "timestamp, source, event_type, user, host, source_address, raw "
            "FROM evidence WHERE detection_id = ? "
            "ORDER BY timestamp ASC LIMIT ? OFFSET ?",
            (detection_id, pagination.limit, pagination.offset),
        )
        rows = cur.fetchall()
        return [dict(r) for r in rows]

    def evidence_count(self, detection_id: str) -> int:
        """Return the exact number of evidence rows for a detection.

        Uses a single parameterized COUNT(*) query — no rows are loaded,
        so this avoids N+1 connection churn and never returns raw payloads.
        """
        _validate_string(detection_id, "detection_id", MAX_RULE_ID_LEN)
        cur = self.conn.execute(
            "SELECT COUNT(*) AS c FROM evidence WHERE detection_id = ?",
            (detection_id,),
        )
        return int(cur.fetchone()[0])

    # --- events ---

    def search_events(
        self,
        pagination: Pagination,
        query: str | None = None,
        host: str | None = None,
        event_type: str | None = None,
        source: str | None = None,
        user: str | None = None,
        time_range: TimeRange | None = None,
    ) -> list[dict[str, Any]]:
        """Search events using static SQL with parameterized values."""
        if query is not None:
            _validate_string(query, "query", MAX_INPUT_LEN)
        if host is not None:
            _validate_string(host, "host", MAX_HOST_LEN)
        if event_type is not None:
            _validate_string(event_type, "event_type", MAX_RULE_ID_LEN)
        if source is not None:
            _validate_string(source, "source", MAX_RULE_ID_LEN)
        if user is not None:
            _validate_string(user, "user", MAX_RULE_ID_LEN)

        sql = (
            "SELECT event_id, timestamp, source, event_type, user, host, "
            "process_name, process_command_line, network_remote_address, "
            "network_remote_port, auth_outcome, auth_username "
            "FROM events WHERE 1=1"
        )
        params: list[Any] = []

        if query is not None:
            sql += (
                " AND (raw LIKE ? OR event_type LIKE ? OR host LIKE ? OR user LIKE ?)"
            )
            like = f"%{query}%"
            params.extend([like, like, like, like])
        if host is not None:
            sql += " AND host = ?"
            params.append(host)
        if event_type is not None:
            sql += " AND event_type = ?"
            params.append(event_type)
        if source is not None:
            sql += " AND source = ?"
            params.append(source)
        if user is not None:
            sql += " AND user = ?"
            params.append(user)
        if time_range is not None:
            if time_range.start is not None:
                sql += " AND julianday(timestamp) >= julianday(?)"
                params.append(time_range.start)
            if time_range.end is not None:
                sql += " AND julianday(timestamp) <= julianday(?)"
                params.append(time_range.end)

        sql += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([pagination.limit, pagination.offset])

        cur = self.conn.execute(sql, params)
        rows = cur.fetchall()
        return [dict(r) for r in rows]

    # --- risk assessments ---

    def list_risk_assessments(
        self,
        pagination: Pagination,
        host: str | None = None,
        min_score: int | None = None,
    ) -> list[dict[str, Any]]:
        if host is not None:
            _validate_string(host, "host", MAX_HOST_LEN)
        if min_score is not None and (min_score < 0 or min_score > 100):
            raise ReadOnlyDatabaseError(
                "bad_input",
                "min_score must be between 0 and 100",
                "Provide min_score between 0 and 100.",
            )

        sql = (
            "SELECT assessment_id, affected_host, risk_score, risk_classification, "
            "explanation, evidence_confidence, detection_severity, created_at, "
            "supporting_evidence_count FROM risk_assessments WHERE 1=1"
        )
        params: list[Any] = []

        if host is not None:
            sql += " AND affected_host = ?"
            params.append(host)
        if min_score is not None:
            sql += " AND risk_score >= ?"
            params.append(min_score)

        sql += " ORDER BY risk_score DESC, created_at DESC LIMIT ? OFFSET ?"
        params.extend([pagination.limit, pagination.offset])

        cur = self.conn.execute(sql, params)
        rows = cur.fetchall()
        return [dict(r) for r in rows]
