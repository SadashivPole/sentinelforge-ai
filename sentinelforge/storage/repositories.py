"""Repository layer for SQLite persistence.

Provides CRUD and query operations for events, detections, evidence, and
risk assessments. All methods use parameterized SQL and operate within
transactions where writes are involved.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from sentinelforge.detection.base import DetectionResult, Evidence, Severity
from sentinelforge.ingestion.normalizer import (
    AuthenticationInfo,
    NetworkInfo,
    NormalizedEvent,
    ProcessInfo,
)
from sentinelforge.risk.scorer import RiskAssessment, ScoringFactor
from sentinelforge.storage.database import Database
from sentinelforge.storage.schema import (
    IOC,
    Incident,
    IOCMatch,
    RetroHunt,
)


class DuplicateIdCollisionError(ValueError):
    """Raised when an immutable record is re-inserted with the same ID but
    different content. Security records are immutable; re-insertion must not
    silently overwrite existing evidence.
    """


# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _content_hash(obj: Any) -> str:
    """Return a stable hash of a serializable object for collision detection."""
    import hashlib

    return hashlib.sha256(
        json.dumps(obj, sort_keys=True, ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def _evidence_content_hash(evidence: Evidence) -> str:
    """Return a stable hash of an Evidence record for collision detection.

    Compares all fields that constitute the immutable evidence content:
    event_id, timestamp, source, event_type, user, host, source_address, raw.
    """
    return _content_hash(
        {
            "event_id": evidence.event_id,
            "timestamp": evidence.timestamp,
            "source": evidence.source,
            "event_type": evidence.event_type,
            "user": evidence.user,
            "host": evidence.host,
            "source_address": evidence.source_address,
            "raw": evidence.raw,
        }
    )


def _event_content_hash(event: NormalizedEvent) -> str:
    """Return a stable hash of a NormalizedEvent for collision detection.

    Compares the complete immutable record: timestamp, source, event_type,
    user, host, process fields, network fields, auth fields — not just raw
    JSON. Two events with the same raw but different normalized host or
    timestamp will collide.
    """
    proc = event.process
    net = event.network
    auth = event.authentication
    return _content_hash(
        {
            "timestamp": event.timestamp,
            "source": event.source,
            "event_type": event.event_type,
            "user": event.user,
            "host": event.host,
            "process": {
                "pid": proc.pid if proc else None,
                "ppid": proc.ppid if proc else None,
                "name": proc.name if proc else None,
                "path": proc.path if proc else None,
                "command_line": proc.command_line if proc else None,
                "user": proc.user if proc else None,
                "hash_sha256": proc.hash_sha256 if proc else None,
            },
            "network": {
                "direction": net.direction if net else None,
                "local_address": net.local_address if net else None,
                "remote_address": net.remote_address if net else None,
                "local_port": net.local_port if net else None,
                "remote_port": net.remote_port if net else None,
                "protocol": net.protocol if net else None,
            },
            "authentication": {
                "outcome": auth.outcome if auth else None,
                "method": auth.method if auth else None,
                "username": auth.username if auth else None,
                "source_address": auth.source_address if auth else None,
            },
            "raw": event.raw,
        }
    )


def _event_to_row(event: NormalizedEvent) -> dict[str, Any]:
    """Flatten a NormalizedEvent into a dictionary of column values."""
    proc = event.process
    net = event.network
    auth = event.authentication
    return {
        "event_id": event.event_id,
        "timestamp": event.timestamp,
        "source": event.source,
        "raw": json.dumps(event.raw, ensure_ascii=False),
        "event_type": event.event_type,
        "user": event.user,
        "host": event.host,
        "process_pid": proc.pid if proc else None,
        "process_ppid": proc.ppid if proc else None,
        "process_name": proc.name if proc else None,
        "process_path": proc.path if proc else None,
        "process_command_line": proc.command_line if proc else None,
        "process_user": proc.user if proc else None,
        "process_hash_sha256": proc.hash_sha256 if proc else None,
        "network_direction": net.direction if net else None,
        "network_local_address": net.local_address if net else None,
        "network_remote_address": net.remote_address if net else None,
        "network_local_port": net.local_port if net else None,
        "network_remote_port": net.remote_port if net else None,
        "network_protocol": net.protocol if net else None,
        "auth_outcome": auth.outcome if auth else None,
        "auth_method": auth.method if auth else None,
        "auth_username": auth.username if auth else None,
        "auth_source_address": auth.source_address if auth else None,
        "ingested_at": event.ingested_at,
    }


def _row_to_event(row) -> NormalizedEvent:
    """Reconstruct a NormalizedEvent from a database row."""
    process: ProcessInfo | None = None
    if any(
        row[key] is not None
        for key in (
            "process_pid",
            "process_ppid",
            "process_name",
            "process_path",
            "process_command_line",
            "process_user",
            "process_hash_sha256",
        )
    ):
        process = ProcessInfo(
            pid=row["process_pid"],
            ppid=row["process_ppid"],
            name=row["process_name"],
            path=row["process_path"],
            command_line=row["process_command_line"],
            user=row["process_user"],
            hash_sha256=row["process_hash_sha256"],
        )

    network: NetworkInfo | None = None
    if any(
        row[key] is not None
        for key in (
            "network_direction",
            "network_local_address",
            "network_remote_address",
            "network_local_port",
            "network_remote_port",
            "network_protocol",
        )
    ):
        network = NetworkInfo(
            direction=row["network_direction"],
            local_address=row["network_local_address"],
            remote_address=row["network_remote_address"],
            local_port=row["network_local_port"],
            remote_port=row["network_remote_port"],
            protocol=row["network_protocol"],
        )

    authentication: AuthenticationInfo | None = None
    if any(
        row[key] is not None
        for key in (
            "auth_outcome",
            "auth_method",
            "auth_username",
            "auth_source_address",
        )
    ):
        authentication = AuthenticationInfo(
            outcome=row["auth_outcome"],
            method=row["auth_method"],
            username=row["auth_username"],
            source_address=row["auth_source_address"],
        )

    return NormalizedEvent(
        event_id=row["event_id"],
        timestamp=row["timestamp"],
        source=row["source"],
        raw=json.loads(row["raw"]),
        event_type=row["event_type"],
        user=row["user"],
        host=row["host"],
        process=process,
        network=network,
        authentication=authentication,
        ingested_at=row["ingested_at"],
    )


def _detection_to_row(result: DetectionResult) -> dict[str, Any]:
    """Flatten a DetectionResult into a dictionary of column values."""
    return {
        "detection_id": result.detection_id,
        "rule_id": result.rule_id,
        "rule_name": result.rule_name,
        "severity": result.severity.value,
        "description": result.description,
        "triggered_at": result.triggered_at,
        "metadata": json.dumps(result.metadata, ensure_ascii=False),
        "host": result.metadata.get("host"),
    }


def _row_to_detection(row) -> DetectionResult:
    """Reconstruct a DetectionResult from a database row."""
    metadata = json.loads(row["metadata"]) if row["metadata"] else {}
    evidence_rows: list = []  # populated separately by the caller via join
    return DetectionResult(
        detection_id=row["detection_id"],
        rule_id=row["rule_id"],
        rule_name=row["rule_name"],
        severity=Severity(row["severity"]),
        description=row["description"],
        evidence=evidence_rows,
        metadata=metadata,
        triggered_at=row["triggered_at"],
    )


def _evidence_to_row(
    evidence: Evidence, detection_id: str, conn=None
) -> dict[str, Any]:
    """Flatten an Evidence into a dictionary of column values.

    If ``conn`` is provided, checks whether the event exists in the events
    table. If it does, the event_id is stored in the ``event_id`` column
    (internal reference). If not, ``event_id`` is stored as NULL and the
    original event id is stored in ``external_event_ref`` (external reference
    for unpersisted events).
    """
    evidence_id = f"{detection_id}-{evidence.event_id}"
    event_id_col: str | None = None
    external_event_ref: str | None = None

    if conn is not None:
        event_exists = (
            conn.execute(
                "SELECT 1 FROM events WHERE event_id = ?",
                (evidence.event_id,),
            ).fetchone()
            is not None
        )
    else:
        event_exists = False

    if event_exists:
        event_id_col = evidence.event_id
    else:
        external_event_ref = evidence.event_id

    return {
        "evidence_id": evidence_id,
        "detection_id": detection_id,
        "event_id": event_id_col,
        "external_event_ref": external_event_ref,
        "timestamp": evidence.timestamp,
        "source": evidence.source,
        "event_type": evidence.event_type,
        "user": evidence.user,
        "host": evidence.host,
        "source_address": evidence.source_address,
        "raw": json.dumps(evidence.raw, ensure_ascii=False),
    }


def _row_to_evidence(row) -> Evidence:
    """Reconstruct an Evidence from a database row.

    If the ``event_id`` column is NULL (external reference), the
    ``external_event_ref`` column is used as the event id.
    """
    event_id = row["event_id"] or row["external_event_ref"] or ""
    return Evidence(
        event_id=event_id,
        timestamp=row["timestamp"] or "",
        source=row["source"] or "",
        event_type=row["event_type"],
        user=row["user"],
        host=row["host"],
        source_address=row["source_address"],
        raw=json.loads(row["raw"]) if row["raw"] else {},
    )


def _insert_evidence_with_collision_check(
    conn, erow: dict[str, Any], evidence: Evidence
) -> None:
    """Insert evidence with collision detection.

    Same evidence_id + identical content = idempotent (no-op).
    Same evidence_id + different content = DuplicateIdCollisionError.
    Never silently discards conflicting security evidence.

    Compares all evidence fields: event references (event_id /
    external_event_ref), timestamp, source, event_type, user, host,
    source_address, and raw evidence.
    """
    existing = conn.execute(
        "SELECT raw, timestamp, source, event_type, user, host, "
        "source_address, event_id, external_event_ref "
        "FROM evidence WHERE evidence_id = ?",
        (erow["evidence_id"],),
    ).fetchone()
    if existing is not None:
        # DB event_id is NULL when external_event_ref holds the evidence
        # event_id (unpersisted event). Map external_event_ref back to
        # event_id so the hash matches _evidence_content_hash(evidence)
        # which always uses evidence.event_id.
        db_event_id = existing["event_id"] or existing["external_event_ref"]
        existing_hash = _content_hash(
            {
                "event_id": db_event_id,
                "timestamp": existing["timestamp"],
                "source": existing["source"],
                "event_type": existing["event_type"],
                "user": existing["user"],
                "host": existing["host"],
                "source_address": existing["source_address"],
                "raw": json.loads(existing["raw"]),
            }
        )
        new_hash = _evidence_content_hash(evidence)
        if existing_hash != new_hash:
            raise DuplicateIdCollisionError(
                f"Evidence {erow['evidence_id']} already exists with different "
                "content; immutable evidence cannot be overwritten."
            )
        # Same content — idempotent, no-op.
        return
    conn.execute(
        """
        INSERT INTO evidence (
            evidence_id, detection_id, event_id, external_event_ref,
            timestamp, source, event_type, user, host,
            source_address, raw
        ) VALUES (
            :evidence_id, :detection_id, :event_id, :external_event_ref,
            :timestamp, :source, :event_type, :user, :host,
            :source_address, :raw
        )
        """,
        erow,
    )


def _assessment_to_row(assessment: RiskAssessment) -> dict[str, Any]:
    """Flatten a RiskAssessment into a dictionary of column values."""
    return {
        "assessment_id": assessment.assessment_id,
        "affected_host": assessment.affected_host,
        "risk_score": assessment.risk_score,
        "risk_classification": assessment.risk_classification,
        "explanation": assessment.explanation,
        "evidence_confidence": assessment.evidence_confidence,
        "detection_severity": assessment.detection_severity.value,
        "asset_criticality_provided": int(assessment.asset_criticality_provided),
        "supporting_evidence_count": assessment.supporting_evidence_count,
        "created_at": _now_iso(),
    }


def _row_to_assessment(row) -> RiskAssessment:
    """Reconstruct a RiskAssessment from a database row."""
    factors = [
        ScoringFactor(
            name=f["name"],
            weight=f["weight"],
            raw_score=f["raw_score"],
            weighted_score=f["weighted_score"],
            description=f["description"],
        )
        for f in json.loads(row["scoring_factors_json"])
    ]
    return RiskAssessment(
        assessment_id=row["assessment_id"],
        affected_host=row["affected_host"],
        risk_score=row["risk_score"],
        risk_classification=row["risk_classification"],
        contributing_detection_ids=json.loads(row["contributing_detection_ids_json"]),
        scoring_factors=factors,
        score_breakdown=json.loads(row["score_breakdown_json"]),
        supporting_evidence_count=row["supporting_evidence_count"],
        explanation=row["explanation"],
        recommended_investigation_priorities=json.loads(
            row["recommended_investigation_priorities_json"]
        ),
        evidence_confidence=row["evidence_confidence"],
        detection_severity=Severity(row["detection_severity"]),
        asset_criticality_provided=bool(row["asset_criticality_provided"]),
    )


# ---------------------------------------------------------------------------
# Event repository
# ---------------------------------------------------------------------------


class EventRepository:
    """Repository for normalized events."""

    def __init__(self, db: Database) -> None:
        self.db = db

    def insert_event(self, event: NormalizedEvent) -> str:
        """Insert a single normalized event. Returns the event_id.

        Events are immutable security records. Re-inserting the same event_id
        is idempotent if the complete content matches; if the content differs,
        a :class:`DuplicateIdCollisionError` is raised.
        """
        row = _event_to_row(event)
        with self.db.transaction() as conn:
            existing = conn.execute(
                "SELECT raw, timestamp, source, event_type, user, host, "
                "process_pid, process_ppid, process_name, process_path, "
                "process_command_line, process_user, process_hash_sha256, "
                "network_direction, network_local_address, "
                "network_remote_address, network_local_port, network_remote_port, "
                "network_protocol, auth_outcome, auth_method, auth_username, "
                "auth_source_address FROM events WHERE event_id = ?",
                (event.event_id,),
            ).fetchone()
            if existing is not None:
                existing_hash = _content_hash(
                    {
                        "timestamp": existing["timestamp"],
                        "source": existing["source"],
                        "event_type": existing["event_type"],
                        "user": existing["user"],
                        "host": existing["host"],
                        "process": {
                            "pid": existing["process_pid"],
                            "ppid": existing["process_ppid"],
                            "name": existing["process_name"],
                            "path": existing["process_path"],
                            "command_line": existing["process_command_line"],
                            "user": existing["process_user"],
                            "hash_sha256": existing["process_hash_sha256"],
                        },
                        "network": {
                            "direction": existing["network_direction"],
                            "local_address": existing["network_local_address"],
                            "remote_address": existing["network_remote_address"],
                            "local_port": existing["network_local_port"],
                            "remote_port": existing["network_remote_port"],
                            "protocol": existing["network_protocol"],
                        },
                        "authentication": {
                            "outcome": existing["auth_outcome"],
                            "method": existing["auth_method"],
                            "username": existing["auth_username"],
                            "source_address": existing["auth_source_address"],
                        },
                        "raw": json.loads(existing["raw"]),
                    }
                )
                new_hash = _event_content_hash(event)
                if existing_hash != new_hash:
                    raise DuplicateIdCollisionError(
                        f"Event {event.event_id} already exists with different "
                        "content; immutable record cannot be overwritten."
                    )
                # Same content — idempotent, no-op.
                return event.event_id
            conn.execute(
                """
                INSERT INTO events (
                    event_id, timestamp, source, raw, event_type, user, host,
                    process_pid, process_ppid, process_name, process_path,
                    process_command_line, process_user, process_hash_sha256,
                    network_direction, network_local_address,
                    network_remote_address, network_local_port,
                    network_remote_port, network_protocol,
                    auth_outcome, auth_method, auth_username,
                    auth_source_address, ingested_at
                ) VALUES (
                    :event_id, :timestamp, :source, :raw, :event_type, :user, :host,
                    :process_pid, :process_ppid, :process_name, :process_path,
                    :process_command_line, :process_user, :process_hash_sha256,
                    :network_direction, :network_local_address,
                    :network_remote_address, :network_local_port,
                    :network_remote_port, :network_protocol,
                    :auth_outcome, :auth_method, :auth_username,
                    :auth_source_address, :ingested_at
                )
                """,
                row,
            )
        return event.event_id

    def insert_events(self, events: list[NormalizedEvent]) -> list[str]:
        """Bulk-insert normalized events. Returns list of event_ids.

        Events are immutable. Re-inserting the same event_id with matching
        content is idempotent; conflicting content raises
        :class:`DuplicateIdCollisionError`.
        """
        ids: list[str] = []
        with self.db.transaction() as conn:
            for event in events:
                row = _event_to_row(event)
                existing = conn.execute(
                    "SELECT raw, timestamp, source, event_type, user, host, "
                    "process_pid, process_ppid, process_name, process_path, "
                    "process_command_line, process_user, process_hash_sha256, "
                    "network_direction, network_local_address, "
                    "network_remote_address, network_local_port, network_remote_port, "
                    "network_protocol, auth_outcome, auth_method, auth_username, "
                    "auth_source_address FROM events WHERE event_id = ?",
                    (event.event_id,),
                ).fetchone()
                if existing is not None:
                    existing_hash = _content_hash(
                        {
                            "timestamp": existing["timestamp"],
                            "source": existing["source"],
                            "event_type": existing["event_type"],
                            "user": existing["user"],
                            "host": existing["host"],
                            "process": {
                                "pid": existing["process_pid"],
                                "ppid": existing["process_ppid"],
                                "name": existing["process_name"],
                                "path": existing["process_path"],
                                "command_line": existing["process_command_line"],
                                "user": existing["process_user"],
                                "hash_sha256": existing["process_hash_sha256"],
                            },
                            "network": {
                                "direction": existing["network_direction"],
                                "local_address": existing["network_local_address"],
                                "remote_address": existing["network_remote_address"],
                                "local_port": existing["network_local_port"],
                                "remote_port": existing["network_remote_port"],
                                "protocol": existing["network_protocol"],
                            },
                            "authentication": {
                                "outcome": existing["auth_outcome"],
                                "method": existing["auth_method"],
                                "username": existing["auth_username"],
                                "source_address": existing["auth_source_address"],
                            },
                            "raw": json.loads(existing["raw"]),
                        }
                    )
                    new_hash = _event_content_hash(event)
                    if existing_hash != new_hash:
                        raise DuplicateIdCollisionError(
                            f"Event {event.event_id} already exists with "
                            "different content; immutable record cannot be "
                            "overwritten."
                        )
                    ids.append(event.event_id)
                    continue
                conn.execute(
                    """
                    INSERT INTO events (
                        event_id, timestamp, source, raw, event_type, user, host,
                        process_pid, process_ppid, process_name, process_path,
                        process_command_line, process_user, process_hash_sha256,
                        network_direction, network_local_address,
                        network_remote_address, network_local_port,
                        network_remote_port, network_protocol,
                        auth_outcome, auth_method, auth_username,
                        auth_source_address, ingested_at
                    ) VALUES (
                        :event_id, :timestamp, :source, :raw, :event_type, :user, :host,
                        :process_pid, :process_ppid, :process_name, :process_path,
                        :process_command_line, :process_user, :process_hash_sha256,
                        :network_direction, :network_local_address,
                        :network_remote_address, :network_local_port,
                        :network_remote_port, :network_protocol,
                        :auth_outcome, :auth_method, :auth_username,
                        :auth_source_address, :ingested_at
                    )
                    """,
                    row,
                )
                ids.append(event.event_id)
        return ids

    def get_event(self, event_id: str) -> NormalizedEvent | None:
        """Retrieve a single event by id."""
        with self.db.connection() as conn:
            row = conn.execute(
                "SELECT * FROM events WHERE event_id = ?", (event_id,)
            ).fetchone()
            return _row_to_event(row) if row else None

    def get_events(
        self,
        limit: int | None = 100,
        offset: int = 0,
        host: str | None = None,
        source: str | None = None,
        event_type: str | None = None,
    ) -> list[NormalizedEvent]:
        """Retrieve events with optional filtering and pagination.

        If ``limit`` is None, all matching events are returned (no LIMIT
        clause). Otherwise, at most ``limit`` events are returned starting
        at ``offset``.
        """
        # Normalize empty strings to None so they are treated as "no filter",
        # matching the previous truthy-check behaviour.
        host = host or None
        source = source or None
        event_type = event_type or None

        params: list[Any] = [host, host, source, source, event_type, event_type]

        with self.db.connection() as conn:
            if limit is not None:
                rows = conn.execute(
                    """
                    SELECT * FROM events
                    WHERE (? IS NULL OR host = ?)
                      AND (? IS NULL OR source = ?)
                      AND (? IS NULL OR event_type = ?)
                    ORDER BY timestamp DESC
                    LIMIT ? OFFSET ?
                    """,
                    [*params, limit, offset],
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT * FROM events
                    WHERE (? IS NULL OR host = ?)
                      AND (? IS NULL OR source = ?)
                      AND (? IS NULL OR event_type = ?)
                    ORDER BY timestamp DESC
                    """,
                    params,
                ).fetchall()
            return [_row_to_event(row) for row in rows]

    def search_events(self, query: str, limit: int = 100) -> list[NormalizedEvent]:
        """Full-text search over raw event payloads and key fields."""
        like = f"%{query}%"
        with self.db.connection() as conn:
            rows = conn.execute(
                """
                SELECT * FROM events
                WHERE raw LIKE ? OR host LIKE ? OR user LIKE ?
                   OR event_type LIKE ? OR source LIKE ?
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                [like, like, like, like, like, limit],
            ).fetchall()
            return [_row_to_event(row) for row in rows]

    def count_events(self) -> int:
        """Return the total number of stored events."""
        with self.db.connection() as conn:
            row = conn.execute("SELECT COUNT(*) AS c FROM events").fetchone()
            return int(row["c"]) if row else 0


# ---------------------------------------------------------------------------
# Detection repository
# ---------------------------------------------------------------------------


class DetectionRepository:
    """Repository for detection results and their evidence."""

    def __init__(self, db: Database) -> None:
        self.db = db

    def count_detections(self) -> int:
        """Return the total number of stored detections."""
        with self.db.connection() as conn:
            row = conn.execute("SELECT COUNT(*) AS c FROM detections").fetchone()
            return int(row["c"]) if row else 0

    def insert_detection(self, result: DetectionResult) -> str:
        """Insert a single detection result with its evidence.

        Returns the detection_id. Detections are immutable security
        records: re-inserting the same detection_id with matching content is
        idempotent; conflicting content raises
        :class:`DuplicateIdCollisionError`. Evidence is also immutable —
        existing evidence is preserved, never deleted or replaced.

        The detection must exist in the ``detections`` table before evidence
        can reference it (foreign-key enforcement).
        """
        row = _detection_to_row(result)
        with self.db.transaction() as conn:
            existing = conn.execute(
                "SELECT metadata, severity, description, rule_id, rule_name, "
                "triggered_at, host FROM detections WHERE detection_id = ?",
                (result.detection_id,),
            ).fetchone()
            if existing is not None:
                existing_hash = _content_hash(
                    {
                        "rule_id": existing["rule_id"],
                        "rule_name": existing["rule_name"],
                        "severity": existing["severity"],
                        "description": existing["description"],
                        "triggered_at": existing["triggered_at"],
                        "metadata": json.loads(existing["metadata"]),
                        "host": existing["host"],
                    }
                )
                new_hash = _content_hash(
                    {
                        "rule_id": result.rule_id,
                        "rule_name": result.rule_name,
                        "severity": result.severity.value,
                        "description": result.description,
                        "triggered_at": result.triggered_at,
                        "metadata": result.metadata,
                        "host": result.metadata.get("host"),
                    }
                )
                if existing_hash != new_hash:
                    raise DuplicateIdCollisionError(
                        f"Detection {result.detection_id} already exists with "
                        "different content; immutable record cannot be "
                        "overwritten."
                    )
                # Same detection content — idempotent. Still insert any new
                # evidence items (immutable, collision-checked).
                for evidence in result.evidence:
                    erow = _evidence_to_row(evidence, result.detection_id, conn)
                    _insert_evidence_with_collision_check(conn, erow, evidence)
                return result.detection_id

            conn.execute(
                """
                INSERT INTO detections (
                    detection_id, rule_id, rule_name, severity, description,
                    triggered_at, metadata, host
                ) VALUES (
                    :detection_id, :rule_id, :rule_name, :severity,
                    :description, :triggered_at, :metadata, :host
                )
                """,
                row,
            )
            for evidence in result.evidence:
                erow = _evidence_to_row(evidence, result.detection_id, conn)
                _insert_evidence_with_collision_check(conn, erow, evidence)
        return result.detection_id

    def insert_detections(self, results: list[DetectionResult]) -> list[str]:
        """Bulk-insert detection results with evidence in a single transaction.

        Detections are immutable. Re-inserting the same detection_id with
        matching content is idempotent; conflicting content raises
        :class:`DuplicateIdCollisionError`. Evidence is preserved — never
        deleted or replaced.
        """
        ids: list[str] = []
        with self.db.transaction() as conn:
            for result in results:
                row = _detection_to_row(result)
                existing = conn.execute(
                    "SELECT metadata, severity, description, rule_id, rule_name, "
                    "triggered_at, host FROM detections WHERE detection_id = ?",
                    (result.detection_id,),
                ).fetchone()
                if existing is not None:
                    existing_hash = _content_hash(
                        {
                            "rule_id": existing["rule_id"],
                            "rule_name": existing["rule_name"],
                            "severity": existing["severity"],
                            "description": existing["description"],
                            "triggered_at": existing["triggered_at"],
                            "metadata": json.loads(existing["metadata"]),
                            "host": existing["host"],
                        }
                    )
                    new_hash = _content_hash(
                        {
                            "rule_id": result.rule_id,
                            "rule_name": result.rule_name,
                            "severity": result.severity.value,
                            "description": result.description,
                            "triggered_at": result.triggered_at,
                            "metadata": result.metadata,
                            "host": result.metadata.get("host"),
                        }
                    )
                    if existing_hash != new_hash:
                        raise DuplicateIdCollisionError(
                            f"Detection {result.detection_id} already exists with "
                            "different content; immutable record cannot be "
                            "overwritten."
                        )
                    # Same detection content — idempotent. Add any new evidence.
                    for evidence in result.evidence:
                        erow = _evidence_to_row(evidence, result.detection_id, conn)
                        _insert_evidence_with_collision_check(conn, erow, evidence)
                    ids.append(result.detection_id)
                    continue

                conn.execute(
                    """
                    INSERT INTO detections (
                        detection_id, rule_id, rule_name, severity, description,
                        triggered_at, metadata, host
                    ) VALUES (
                        :detection_id, :rule_id, :rule_name, :severity,
                        :description, :triggered_at, :metadata, :host
                    )
                    """,
                    row,
                )
                for evidence in result.evidence:
                    erow = _evidence_to_row(evidence, result.detection_id, conn)
                    _insert_evidence_with_collision_check(conn, erow, evidence)
                ids.append(result.detection_id)
        return ids

    def get_detection(self, detection_id: str) -> DetectionResult | None:
        """Retrieve a single detection with its evidence."""
        with self.db.connection() as conn:
            row = conn.execute(
                "SELECT * FROM detections WHERE detection_id = ?",
                (detection_id,),
            ).fetchone()
            if not row:
                return None
            evidence_rows = conn.execute(
                "SELECT * FROM evidence WHERE detection_id = ?",
                (detection_id,),
            ).fetchall()
            result = _row_to_detection(row)
            result.evidence = [_row_to_evidence(r) for r in evidence_rows]
            return result

    def get_detections(
        self,
        limit: int | None = 100,
        offset: int = 0,
        host: str | None = None,
        severity: str | None = None,
        rule_id: str | None = None,
    ) -> list[DetectionResult]:
        """Retrieve detections with optional filtering.

        If ``limit`` is None, all matching detections are returned without
        a LIMIT clause.
        """
        # Normalize empty strings to None so they are treated as "no filter",
        # matching the previous truthy-check behaviour.
        host = host or None
        severity = severity or None
        rule_id = rule_id or None

        params: list[Any] = [host, host, severity, severity, rule_id, rule_id]

        with self.db.connection() as conn:
            if limit is not None:
                rows = conn.execute(
                    """
                    SELECT * FROM detections
                    WHERE (? IS NULL OR host = ?)
                      AND (? IS NULL OR severity = ?)
                      AND (? IS NULL OR rule_id = ?)
                    ORDER BY triggered_at DESC
                    LIMIT ? OFFSET ?
                    """,
                    [*params, limit, offset],
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT * FROM detections
                    WHERE (? IS NULL OR host = ?)
                      AND (? IS NULL OR severity = ?)
                      AND (? IS NULL OR rule_id = ?)
                    ORDER BY triggered_at DESC
                    """,
                    params,
                ).fetchall()
            results: list[DetectionResult] = []
            for row in rows:
                result = _row_to_detection(row)
                ev_rows = conn.execute(
                    "SELECT * FROM evidence WHERE detection_id = ?",
                    (row["detection_id"],),
                ).fetchall()
                result.evidence = [_row_to_evidence(r) for r in ev_rows]
                results.append(result)
            return results

    def search_detections(self, query: str, limit: int = 100) -> list[DetectionResult]:
        """Search detections by description, rule name, or metadata."""
        like = f"%{query}%"
        with self.db.connection() as conn:
            rows = conn.execute(
                """
                SELECT * FROM detections
                WHERE description LIKE ? OR rule_name LIKE ? OR rule_id LIKE ?
                   OR metadata LIKE ? OR host LIKE ?
                ORDER BY triggered_at DESC
                LIMIT ?
                """,
                [like, like, like, like, like, limit],
            ).fetchall()
            results: list[DetectionResult] = []
            for row in rows:
                result = _row_to_detection(row)
                ev_rows = conn.execute(
                    "SELECT * FROM evidence WHERE detection_id = ?",
                    (row["detection_id"],),
                ).fetchall()
                result.evidence = [_row_to_evidence(r) for r in ev_rows]
                results.append(result)
            return results

    def count_detections_by_severity(self) -> dict[str, int]:
        """Return detection counts grouped by severity."""
        with self.db.connection() as conn:
            rows = conn.execute(
                "SELECT severity, COUNT(*) AS c FROM detections GROUP BY severity"
            ).fetchall()
            return {row["severity"]: int(row["c"]) for row in rows}

    def get_top_suspicious_hosts(self, limit: int = 10) -> list[tuple[str, int]]:
        """Return hosts with the most detections, ordered by count desc."""
        with self.db.connection() as conn:
            rows = conn.execute(
                "SELECT host, COUNT(*) AS c FROM detections "
                "WHERE host IS NOT NULL GROUP BY host "
                "ORDER BY c DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [(row["host"], int(row["c"])) for row in rows]

    def get_detection_timeline(
        self,
        host: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Return detections over time for timeline visualization."""
        # Normalize empty strings to None so they are treated as "no filter",
        # matching the previous truthy-check behaviour.
        host = host or None

        params: list[Any] = [host, host]

        with self.db.connection() as conn:
            rows = conn.execute(
                """
                SELECT triggered_at AS ts, rule_id, severity, host, description
                FROM detections
                WHERE (? IS NULL OR host = ?)
                ORDER BY triggered_at DESC
                LIMIT ?
                """,
                [*params, limit],
            ).fetchall()
            return [dict(row) for row in rows]


# ---------------------------------------------------------------------------
# Risk assessment repository
# ---------------------------------------------------------------------------


class RiskAssessmentRepository:
    """Repository for risk assessments."""

    def __init__(self, db: Database) -> None:
        self.db = db

    def insert_risk_assessment(self, assessment: RiskAssessment) -> str:
        """Insert a risk assessment and its linked detections.

        Risk assessments are intentionally mutable: re-inserting the same
        assessment_id replaces the record (explicit UPSERT).

        Detection links are created only for detections that already exist in
        the ``detections`` table (foreign-key enforcement). A risk assessment
        cannot silently link to nonexistent detections. Parent detection
        records must be inserted before the risk assessment that references
        them.
        """
        with self.db.transaction() as conn:
            row = _assessment_to_row(assessment)
            conn.execute(
                """
                INSERT OR REPLACE INTO risk_assessments (
                    assessment_id, affected_host, risk_score,
                    risk_classification, explanation, evidence_confidence,
                    detection_severity, asset_criticality_provided,
                    supporting_evidence_count, created_at,
                    scoring_factors_json, contributing_detection_ids_json,
                    score_breakdown_json,
                    recommended_investigation_priorities_json
                ) VALUES (
                    :assessment_id, :affected_host, :risk_score,
                    :risk_classification, :explanation, :evidence_confidence,
                    :detection_severity, :asset_criticality_provided,
                    :supporting_evidence_count, :created_at,
                    :scoring_factors_json, :contributing_detection_ids_json,
                    :score_breakdown_json,
                    :recommended_investigation_priorities_json
                )
                """,
                {
                    **row,
                    "scoring_factors_json": json.dumps(
                        [
                            {
                                "name": f.name,
                                "weight": f.weight,
                                "raw_score": f.raw_score,
                                "weighted_score": f.weighted_score,
                                "description": f.description,
                            }
                            for f in assessment.scoring_factors
                        ],
                        ensure_ascii=False,
                    ),
                    "contributing_detection_ids_json": json.dumps(
                        assessment.contributing_detection_ids,
                        ensure_ascii=False,
                    ),
                    "score_breakdown_json": json.dumps(
                        assessment.score_breakdown, ensure_ascii=False
                    ),
                    "recommended_investigation_priorities_json": json.dumps(
                        assessment.recommended_investigation_priorities,
                        ensure_ascii=False,
                    ),
                },
            )
            # Replace detection links.
            conn.execute(
                "DELETE FROM risk_assessment_detections WHERE assessment_id = ?",
                (assessment.assessment_id,),
            )
            for det_id in assessment.contributing_detection_ids:
                # Verify the detection exists before creating the link.
                # Foreign-key enforcement would reject orphan links; we check
                # explicitly to give a clear error.
                exists = conn.execute(
                    "SELECT 1 FROM detections WHERE detection_id = ?",
                    (det_id,),
                ).fetchone()
                if exists is None:
                    raise ValueError(
                        f"Cannot link risk assessment {assessment.assessment_id} "
                        f"to nonexistent detection {det_id}. Insert the "
                        "detection record first."
                    )
                conn.execute(
                    """
                    INSERT OR IGNORE INTO risk_assessment_detections
                    (assessment_id, detection_id) VALUES (?, ?)
                    """,
                    (assessment.assessment_id, det_id),
                )
        return assessment.assessment_id

    def get_risk_assessment(self, assessment_id: str) -> RiskAssessment | None:
        """Retrieve a single risk assessment by id."""
        with self.db.connection() as conn:
            row = conn.execute(
                "SELECT * FROM risk_assessments WHERE assessment_id = ?",
                (assessment_id,),
            ).fetchone()
            return _row_to_assessment(row) if row else None

    def get_risk_assessments(
        self,
        limit: int = 100,
        offset: int = 0,
        host: str | None = None,
        min_score: int | None = None,
    ) -> list[RiskAssessment]:
        """Retrieve risk assessments with optional filtering."""
        # Normalize empty strings to None so they are treated as "no filter",
        # matching the previous truthy-check behaviour.
        host = host or None

        params: list[Any] = [host, host, min_score, min_score]

        with self.db.connection() as conn:
            rows = conn.execute(
                """
                SELECT * FROM risk_assessments
                WHERE (? IS NULL OR affected_host = ?)
                  AND (? IS NULL OR risk_score >= ?)
                ORDER BY risk_score DESC, created_at DESC
                LIMIT ? OFFSET ?
                """,
                [*params, limit, offset],
            ).fetchall()
            return [_row_to_assessment(row) for row in rows]


def _row_to_incident(row) -> Incident:
    return Incident(
        incident_id=row["incident_id"],
        title=row["title"],
        correlation_rationale=row["correlation_rationale"],
        severity=row["severity"],
        status=row["status"],
        hosts=json.loads(row["hosts_json"] or "[]"),
        users=json.loads(row["users_json"] or "[]"),
        source_addresses=json.loads(row["source_addresses_json"] or "[]"),
        destination_addresses=json.loads(row["destination_addresses_json"] or "[]"),
        first_seen=row["first_seen"],
        last_seen=row["last_seen"],
        evidence_complete=bool(row["evidence_complete"]),
        related_alert_count=row["related_alert_count"],
        related_event_count=row["related_event_count"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


class IncidentRepository:
    """Repository for correlated incident groupings.

    Incidents are analyst-facing groupings produced by explicit correlation
    rules. Alerts and events are linked to an incident through junction
    tables; the raw evidence itself remains in the ``events`` and
    ``detections`` tables.
    """

    def __init__(self, db: Database) -> None:
        self.db = db

    def count_incidents(self) -> int:
        """Return the total number of stored incidents."""
        with self.db.connection() as conn:
            row = conn.execute("SELECT COUNT(*) AS c FROM incidents").fetchone()
            return int(row["c"]) if row else 0

    def insert_incident(self, incident: Incident) -> str:
        """Insert an incident.

        Returns the incident_id. Re-inserting the same incident_id with
        identical content is idempotent; conflicting content is rejected to
        preserve the integrity of the correlation record.
        """
        row = incident.to_row()
        with self.db.transaction() as conn:
            existing = conn.execute(
                "SELECT status, severity, first_seen, last_seen, "
                "related_alert_count, related_event_count, updated_at "
                "FROM incidents WHERE incident_id = ?",
                (incident.incident_id,),
            ).fetchone()
            if existing is not None:
                existing_hash = _content_hash(
                    {
                        "status": existing["status"],
                        "severity": existing["severity"],
                        "first_seen": existing["first_seen"],
                        "last_seen": existing["last_seen"],
                        "related_alert_count": existing["related_alert_count"],
                        "related_event_count": existing["related_event_count"],
                        "updated_at": existing["updated_at"],
                    }
                )
                new_hash = _content_hash(
                    {
                        "status": incident.status,
                        "severity": incident.severity,
                        "first_seen": incident.first_seen,
                        "last_seen": incident.last_seen,
                        "related_alert_count": incident.related_alert_count,
                        "related_event_count": incident.related_event_count,
                        "updated_at": incident.updated_at,
                    }
                )
                if existing_hash != new_hash:
                    raise DuplicateIdCollisionError(
                        f"Incident {incident.incident_id} already exists with "
                        "different content; immutable record cannot be "
                        "overwritten."
                    )
                return incident.incident_id

            conn.execute(
                """
                INSERT INTO incidents (
                    incident_id, title, correlation_rationale, severity,
                    status, hosts_json, users_json, source_addresses_json,
                    destination_addresses_json, first_seen, last_seen,
                    evidence_complete, related_alert_count,
                    related_event_count, created_at, updated_at
                ) VALUES (
                    :incident_id, :title, :correlation_rationale, :severity,
                    :status, :hosts, :users, :source_addresses,
                    :destination_addresses, :first_seen, :last_seen,
                    :evidence_complete, :related_alert_count,
                    :related_event_count, :created_at, :updated_at
                )
                """,
                row,
            )
        return incident.incident_id

    def get_incident(self, incident_id: str) -> Incident | None:
        """Retrieve a single incident by ID."""
        with self.db.connection() as conn:
            row = conn.execute(
                "SELECT * FROM incidents WHERE incident_id = ?",
                (incident_id,),
            ).fetchone()
            return _row_to_incident(row) if row else None

    def list_incidents(
        self,
        limit: int = 100,
        offset: int = 0,
        status: str | None = None,
        severity: str | None = None,
    ) -> list[Incident]:
        """Retrieve incidents with optional status and severity filtering."""
        status = status or None
        severity = severity or None
        params: list[Any] = [status, status, severity, severity]
        with self.db.connection() as conn:
            rows = conn.execute(
                """
                SELECT * FROM incidents
                WHERE (? IS NULL OR status = ?)
                  AND (? IS NULL OR severity = ?)
                ORDER BY first_seen DESC, incident_id
                LIMIT ? OFFSET ?
                """,
                [*params, limit, offset],
            ).fetchall()
            return [_row_to_incident(row) for row in rows]

    def link_alert(self, incident_id: str, detection_id: str) -> None:
        """Link a detection (alert) to an incident."""
        with self.db.transaction() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO incident_alerts (incident_id, detection_id)
                VALUES (?, ?)
                """,
                (incident_id, detection_id),
            )

    def link_event(self, incident_id: str, event_id: str) -> None:
        """Link an event to an incident."""
        with self.db.transaction() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO incident_events (incident_id, event_id)
                VALUES (?, ?)
                """,
                (incident_id, event_id),
            )


class IOCRepository:
    """Repository for local threat-intelligence indicators and retrospective
    hunt findings.

    IOCs are immutable once validated and stored. Retro-hunt findings are
    append-only records of historical searches; they never modify the
    original alerts or detection records.
    """

    def __init__(self, db: Database) -> None:
        self.db = db

    def count_iocs(self) -> int:
        """Return the total number of stored IOCs."""
        with self.db.connection() as conn:
            row = conn.execute("SELECT COUNT(*) AS c FROM iocs").fetchone()
            return int(row["c"]) if row else 0

    def insert_ioc(self, ioc: IOC) -> str:
        """Insert a validated IOC.

        Returns the indicator_id. Re-inserting the same indicator_id with
        identical content is idempotent; conflicting content is rejected to
        preserve the integrity of the indicator record.
        """
        row = ioc.to_row()
        with self.db.transaction() as conn:
            existing = conn.execute(
                "SELECT indicator_value, indicator_type, source_name, "
                "confidence, validation_status FROM iocs WHERE indicator_id = ?",
                (ioc.indicator_id,),
            ).fetchone()
            if existing is not None:
                existing_hash = _content_hash(
                    {
                        "indicator_value": existing["indicator_value"],
                        "indicator_type": existing["indicator_type"],
                        "source_name": existing["source_name"],
                        "confidence": existing["confidence"],
                        "validation_status": existing["validation_status"],
                    }
                )
                new_hash = _content_hash(
                    {
                        "indicator_value": ioc.indicator_value,
                        "indicator_type": ioc.indicator_type,
                        "source_name": ioc.source_name,
                        "confidence": ioc.confidence,
                        "validation_status": ioc.validation_status,
                    }
                )
                if existing_hash != new_hash:
                    raise DuplicateIdCollisionError(
                        f"IOC {ioc.indicator_id} already exists with "
                        "different content; immutable record cannot be "
                        "overwritten."
                    )
                return ioc.indicator_id

            conn.execute(
                """
                INSERT INTO iocs (
                    indicator_id, indicator_value, indicator_type,
                    source_name, source_reference, confidence, first_seen,
                    last_seen, expiration, imported_at, context, provenance,
                    validation_status
                ) VALUES (
                    :indicator_id, :indicator_value, :indicator_type,
                    :source_name, :source_reference, :confidence, :first_seen,
                    :last_seen, :expiration, :imported_at, :context,
                    :provenance, :validation_status
                )
                """,
                row,
            )
        return ioc.indicator_id

    def get_ioc(self, indicator_id: str) -> IOC | None:
        """Retrieve a single IOC by ID."""
        with self.db.connection() as conn:
            row = conn.execute(
                "SELECT * FROM iocs WHERE indicator_id = ?",
                (indicator_id,),
            ).fetchone()
            return _row_to_ioc(row) if row else None

    def get_ioc_by_value(self, indicator_value: str, indicator_type: str) -> IOC | None:
        """Retrieve a single IOC by value and type."""
        with self.db.connection() as conn:
            row = conn.execute(
                "SELECT * FROM iocs WHERE indicator_value = ? AND indicator_type = ?",
                (indicator_value, indicator_type),
            ).fetchone()
            return _row_to_ioc(row) if row else None

    def list_iocs(
        self,
        limit: int = 100,
        offset: int = 0,
        indicator_type: str | None = None,
        validation_status: str | None = None,
    ) -> list[IOC]:
        """Retrieve IOCs with optional type and validation-status filtering."""
        with self.db.connection() as conn:
            rows = conn.execute(
                """
                SELECT * FROM iocs
                WHERE (? IS NULL OR indicator_type = ?)
                  AND (? IS NULL OR validation_status = ?)
                ORDER BY imported_at DESC, indicator_id
                LIMIT ? OFFSET ?
                """,
                [
                    indicator_type,
                    indicator_type,
                    validation_status,
                    validation_status,
                    limit,
                    offset,
                ],
            ).fetchall()
            return [_row_to_ioc(row) for row in rows]

    def insert_ioc_match(self, match: IOCMatch) -> str:
        """Record a single IOC match against a stored event.

        Returns the match_id. Duplicate matches are ignored.
        """
        with self.db.transaction() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO ioc_matches (
                    match_id, indicator_id, event_id, event_timestamp,
                    matched_field, matched_value, indicator_source, match_type
                ) VALUES (
                    :match_id, :indicator_id, :event_id, :event_timestamp,
                    :matched_field, :matched_value, :indicator_source,
                    :match_type
                )
                """,
                match.to_row(),
            )
        return match.match_id

    def get_ioc_matches(self, indicator_id: str) -> list[IOCMatch]:
        """Return all recorded matches for an IOC."""
        with self.db.connection() as conn:
            rows = conn.execute(
                "SELECT * FROM ioc_matches WHERE indicator_id = ? "
                "ORDER BY event_timestamp, match_id",
                (indicator_id,),
            ).fetchall()
            return [_row_to_ioc_match(row) for row in rows]

    def insert_retro_hunt(self, hunt: RetroHunt) -> str:
        """Record a retrospective hunt and return its hunt_id.

        Idempotent: re-recording a hunt whose ID already exists (deterministic
        hunt IDs are derived from indicator + timestamp) returns the existing
        ID without duplicating the row, so re-running the same hunt is safe.
        """
        with self.db.transaction() as conn:
            existing = conn.execute(
                "SELECT hunt_id FROM retro_hunts WHERE hunt_id = ?",
                (hunt.hunt_id,),
            ).fetchone()
            if existing is not None:
                return existing[0]
            conn.execute(
                """
                INSERT INTO retro_hunts (
                    hunt_id, indicator_id, search_scope,
                    total_events_searched, match_count, search_timestamp
                ) VALUES (
                    :hunt_id, :indicator_id, :search_scope,
                    :total_events_searched, :match_count, :search_timestamp
                )
                """,
                hunt.to_row(),
            )
        return hunt.hunt_id

    def get_retro_hunt(self, hunt_id: str) -> RetroHunt | None:
        """Retrieve a single retro-hunt by ID."""
        with self.db.connection() as conn:
            row = conn.execute(
                "SELECT * FROM retro_hunts WHERE hunt_id = ?",
                (hunt_id,),
            ).fetchone()
            return _row_to_retro_hunt(row) if row else None

    def link_retro_hunt_match(self, hunt_id: str, match_id: str) -> None:
        """Associate an IOC match with a retro-hunt finding."""
        with self.db.transaction() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO retro_hunt_matches (hunt_id, match_id)
                VALUES (?, ?)
                """,
                (hunt_id, match_id),
            )

    def list_retro_hunts(self, limit: int = 100, offset: int = 0) -> list[RetroHunt]:
        """List retro-hunts, most recent first."""
        with self.db.connection() as conn:
            rows = conn.execute(
                """
                SELECT * FROM retro_hunts
                ORDER BY search_timestamp DESC, hunt_id
                LIMIT ? OFFSET ?
                """,
                (limit, offset),
            ).fetchall()
            return [_row_to_retro_hunt(row) for row in rows]


def _row_to_ioc(row: Any) -> IOC:
    return IOC(
        indicator_id=row["indicator_id"],
        indicator_value=row["indicator_value"],
        indicator_type=row["indicator_type"],
        source_name=row["source_name"],
        source_reference=row["source_reference"],
        confidence=row["confidence"],
        first_seen=row["first_seen"],
        last_seen=row["last_seen"],
        expiration=row["expiration"],
        imported_at=row["imported_at"],
        context=row["context"],
        provenance=row["provenance"],
        validation_status=row["validation_status"],
    )


def _row_to_ioc_match(row: Any) -> IOCMatch:
    return IOCMatch(
        match_id=row["match_id"],
        indicator_id=row["indicator_id"],
        event_id=row["event_id"],
        event_timestamp=row["event_timestamp"],
        matched_field=row["matched_field"],
        matched_value=row["matched_value"],
        indicator_source=row["indicator_source"],
        match_type=row["match_type"],
    )


def _row_to_retro_hunt(row: Any) -> RetroHunt:
    return RetroHunt(
        hunt_id=row["hunt_id"],
        indicator_id=row["indicator_id"],
        search_scope=row["search_scope"],
        total_events_searched=row["total_events_searched"],
        match_count=row["match_count"],
        search_timestamp=row["search_timestamp"],
    )
