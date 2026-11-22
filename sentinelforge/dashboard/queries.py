"""SentinelForge local dashboard — SQLite read-only queries."""

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
                   MAX(timestamp) AS last_seen
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

    where = "WHERE " + " AND ".join(conditions) if conditions else ""

    try:
        rows = conn.execute(
            f"""
            SELECT rule_id,
                   COUNT(*) AS event_count,
                   COUNT(DISTINCT COALESCE(host, '')) AS host_count,
                   MIN(timestamp) AS first_seen,
                   MAX(timestamp) AS last_seen
            FROM detections
            {where}
            GROUP BY rule_id
            ORDER BY first_seen DESC
            LIMIT ? OFFSET ?
            """,
            [*params, limit, offset],
        ).fetchall()
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
    conditions: list[str] = []
    params: list[Any] = []

    if event_type:
        conditions.append("e.event_type = ?")
        params.append(event_type)
    if search:
        conditions.append("(e.raw_log LIKE ? OR e.source_address LIKE ? OR e.target_address LIKE ?)")
        params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])

    join = ""
    if rule:
        join = "JOIN detections d ON d.event_id = e.event_id"
        conditions.append("d.rule_id = ?")
        params.append(rule)

    where = "WHERE " + " AND ".join(conditions) if conditions else ""

    try:
        rows = conn.execute(
            f"""
            SELECT e.event_id, e.timestamp, e.event_type, e.source_address,
                   e.target_address, e.user, e.raw_log, e.source_file,
                   e.position, d.rule_id AS detection_rule
            FROM events e
            {join}
            {where}
            GROUP BY e.event_id
            ORDER BY e.timestamp DESC
            LIMIT ? OFFSET ?
            """,
            [*params, limit, offset],
        ).fetchall()
        return [dict(r) for r in rows]
    except sqlite3.OperationalError:
        return []


def get_event_detail(conn: sqlite3.Connection, event_id: str) -> dict[str, Any] | None:
    try:
        row = conn.execute(
            """
            SELECT e.event_id, e.timestamp, e.event_type, e.source_address,
                   e.target_address, e.user, e.raw_log, e.source_file,
                   e.position
            FROM events e
            WHERE e.event_id = ?
            """,
            (event_id,),
        ).fetchone()
        if not row:
            return None

        det_rows = conn.execute(
            """
            SELECT d.rule_id, d.timestamp AS detection_timestamp,
                   d.confidence, d.risk_score
            FROM detections d
            WHERE d.event_id = ?
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
