"""SentinelForge local dashboard — SQLite read-only queries.

All queries use the canonical schema defined in ``sentinelforge.storage.schema``.
Detections do not directly contain an ``event_id`` column; the relationship
between detections and events goes through the ``evidence`` table.
"""

from __future__ import annotations

import sqlite3
from typing import Any


def connect(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def count_events(conn: sqlite3.Connection) -> int:
    row = conn.execute("SELECT COUNT(*) AS c FROM events").fetchone()
    return int(row["c"]) if row else 0


def count_detections(conn: sqlite3.Connection) -> int:
    try:
        row = conn.execute("SELECT COUNT(*) AS c FROM detections").fetchone()
        return int(row["c"]) if row else 0
    except sqlite3.OperationalError:
        return 0


def count_alerts(conn: sqlite3.Connection) -> int:
    try:
        row = conn.execute(
            "SELECT COUNT(DISTINCT rule_id || ':' || COALESCE(host, '')) AS c "
            "FROM detections"
        ).fetchone()
        return int(row["c"]) if row else 0
    except sqlite3.OperationalError:
        return 0


def list_detection_rules(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    try:
        rows = conn.execute(
            """
            SELECT rule_id,
                   COUNT(*) AS detection_count,
                   COUNT(DISTINCT COALESCE(host, '')) AS host_count,
                   MAX(triggered_at) AS last_seen
            FROM detections
            GROUP BY rule_id
            ORDER BY detection_count DESC
            """
        ).fetchall()
        return [dict(r) for r in rows]
    except sqlite3.OperationalError:
        return []


def list_alerts(
    conn: sqlite3.Connection,
    *,
    rule: str | None = None,
    search: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[dict[str, Any]]:
    conditions: list[str] = []
    params: list[Any] = []

    if rule:
        conditions.append("rule_id = ?")
        params.append(rule)
    if search:
        conditions.append("(rule_id LIKE ? OR COALESCE(host, '') LIKE ?)")
        params.extend([f"%{search}%", f"%{search}%"])

    try:
        query = """
            SELECT rule_id,
                   COUNT(*) AS detection_count,
                   COUNT(DISTINCT COALESCE(host, '')) AS host_count,
                   MIN(triggered_at) AS first_seen,
                   MAX(triggered_at) AS last_seen
            FROM detections
"""
        if conditions:
            query = query.rstrip() + "\nWHERE " + " AND ".join(conditions) + "\n"
        query += "GROUP BY rule_id ORDER BY first_seen DESC LIMIT ? OFFSET ?"

        rows = conn.execute(query, [*params, limit, offset]).fetchall()
        return [dict(r) for r in rows]
    except sqlite3.OperationalError:
        return []


def list_events(
    conn: sqlite3.Connection,
    *,
    event_type: str | None = None,
    search: str | None = None,
    rule: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """Return events with optional filtering and pagination.

    Events are queried directly from the ``events`` table. When ``rule`` is
    supplied, only events that have evidence linked to a detection with that
    rule_id are returned (the event→detection relationship goes through the
    ``evidence`` table).

    Columns returned match the canonical ``events`` schema:
    ``event_id``, ``timestamp``, ``event_type``, ``source_address``,
    ``target_address``, ``user``, ``raw_log``.

    ``source_address`` is derived from ``auth_source_address`` (auth events)
    or ``network_remote_address`` (network events). ``target_address`` is
    derived from ``network_local_address``. ``raw_log`` comes from the
    ``raw`` column.
    """
    conditions: list[str] = []
    params: list[Any] = []

    if event_type:
        conditions.append("e.event_type = ?")
        params.append(event_type)
    if search:
        conditions.append("(e.raw LIKE ? OR e.source LIKE ? OR e.host LIKE ?)")
        params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])

    if rule:
        conditions.append(
            "e.event_id IN ("
            "SELECT ev.event_id FROM evidence ev "
            "JOIN detections d ON d.detection_id = ev.detection_id "
            "WHERE d.rule_id = ?"
            ")"
        )
        params.append(rule)

    try:
        query = """
            SELECT e.event_id,
                   e.timestamp,
                   e.event_type,
                   COALESCE(e.auth_source_address, e.network_remote_address) AS source_address,
                   e.network_local_address AS target_address,
                   e.user,
                   e.raw AS raw_log
            FROM events e
        """
        if conditions:
            query = query.rstrip() + "\nWHERE " + " AND ".join(conditions) + "\n"
        query += "ORDER BY e.timestamp DESC LIMIT ? OFFSET ?"

        rows = conn.execute(query, [*params, limit, offset]).fetchall()
        return [dict(r) for r in rows]
    except sqlite3.OperationalError:
        return []


def get_event_detail(conn: sqlite3.Connection, event_id: str) -> dict[str, Any] | None:
    """Return a single event with its linked detections.

    Detections are joined through the ``evidence`` table since detections do
    not directly contain an ``event_id`` column. Detection timestamps use
    ``triggered_at``. No confidence or risk_score values are returned — those
    are not stored in the canonical detections schema.
    """
    try:
        row = conn.execute(
            """
            SELECT e.event_id, e.timestamp, e.event_type,
                   COALESCE(e.auth_source_address, e.network_remote_address) AS source_address,
                   e.network_local_address AS target_address,
                   e.user,
                   e.raw AS raw_log
            FROM events e
            WHERE e.event_id = ?
            """,
            (event_id,),
        ).fetchone()
        if not row:
            return None

        det_rows = conn.execute(
            """
            SELECT d.rule_id, d.triggered_at AS detection_timestamp
            FROM detections d
            JOIN evidence ev ON ev.detection_id = d.detection_id
            WHERE ev.event_id = ?
            """,
            (event_id,),
        ).fetchall()

        result = dict(row)
        result["detections"] = [dict(r) for r in det_rows]
        return result
    except sqlite3.OperationalError:
        return None


def get_attacks_coverage(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    try:
        rows = conn.execute(
            """
            SELECT d.rule_id,
                   COUNT(*) AS detection_count,
                   COUNT(DISTINCT COALESCE(d.host, '')) AS host_count
            FROM detections d
            GROUP BY d.rule_id
            ORDER BY detection_count DESC
            """
        ).fetchall()
        return [dict(r) for r in rows]
    except sqlite3.OperationalError:
        return []


def get_system_diagnostics(conn: sqlite3.Connection) -> dict[str, Any]:
    result: dict[str, Any] = {}

    try:
        row = conn.execute("SELECT COUNT(*) AS c FROM events").fetchone()
        result["total_events"] = int(row["c"]) if row else 0
    except sqlite3.OperationalError:
        result["total_events"] = 0

    try:
        row = conn.execute("SELECT COUNT(*) AS c FROM detections").fetchone()
        result["total_detections"] = int(row["c"]) if row else 0
    except sqlite3.OperationalError:
        result["total_detections"] = 0

    try:
        row = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        result["tables"] = [r["name"] for r in row]
    except sqlite3.OperationalError:
        result["tables"] = []

    try:
        row = conn.execute("PRAGMA database_list").fetchone()
        result["database_file"] = row["file"] if row else "unknown"
    except sqlite3.OperationalError:
        result["database_file"] = "unknown"

    return result
