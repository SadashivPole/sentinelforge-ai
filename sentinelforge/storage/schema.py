"""Database schema definition and versioned migrations.

Defines the canonical schema for all SentinelForge AI tables and provides
migration functions to evolve the schema version over time. Schema version is
tracked in the ``schema_metadata`` table.
"""

from __future__ import annotations

from typing import Optional

# Current schema version. Increment on every breaking schema change.
SCHEMA_VERSION = 3

# Full DDL for all tables, in dependency order.
CREATE_TABLES: list[str] = [
    """
    CREATE TABLE IF NOT EXISTS events (
        event_id           TEXT PRIMARY KEY,
        timestamp          TEXT,
        source             TEXT NOT NULL,
        raw                TEXT NOT NULL,
        event_type         TEXT,
        user               TEXT,
        host               TEXT,
        process_pid        INTEGER,
        process_ppid       INTEGER,
        process_name       TEXT,
        process_path       TEXT,
        process_command_line TEXT,
        process_user       TEXT,
        process_hash_sha256 TEXT,
        network_direction  TEXT,
        network_local_address TEXT,
        network_remote_address TEXT,
        network_local_port  INTEGER,
        network_remote_port INTEGER,
        network_protocol   TEXT,
        auth_outcome       TEXT,
        auth_method        TEXT,
        auth_username      TEXT,
        auth_source_address TEXT,
        ingested_at        TEXT NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS detections (
        detection_id   TEXT PRIMARY KEY,
        rule_id        TEXT NOT NULL,
        rule_name      TEXT NOT NULL,
        severity       TEXT NOT NULL,
        description    TEXT NOT NULL,
        triggered_at   TEXT NOT NULL,
        metadata       TEXT NOT NULL,
        host           TEXT
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS evidence (
        evidence_id       TEXT PRIMARY KEY,
        detection_id      TEXT NOT NULL,
        event_id          TEXT,  -- nullable: NULL for external/unpersisted events
        external_event_ref TEXT,  -- external reference when event not in events table
        timestamp         TEXT,
        source            TEXT,
        event_type        TEXT,
        user              TEXT,
        host              TEXT,
        source_address    TEXT,
        raw               TEXT NOT NULL,
        FOREIGN KEY (detection_id) REFERENCES detections(detection_id),
        FOREIGN KEY (event_id) REFERENCES events(event_id) ON DELETE RESTRICT
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS risk_assessments (
        assessment_id          TEXT PRIMARY KEY,
        affected_host          TEXT,
        risk_score             INTEGER NOT NULL,
        risk_classification    TEXT NOT NULL,
        explanation            TEXT NOT NULL,
        evidence_confidence    TEXT NOT NULL,
        detection_severity     TEXT NOT NULL,
        asset_criticality_provided INTEGER NOT NULL DEFAULT 0,
        supporting_evidence_count INTEGER NOT NULL DEFAULT 0,
        created_at             TEXT NOT NULL,
        scoring_factors_json   TEXT NOT NULL DEFAULT '[]',
        contributing_detection_ids_json TEXT NOT NULL DEFAULT '[]',
        score_breakdown_json   TEXT NOT NULL DEFAULT '{}',
        recommended_investigation_priorities_json TEXT NOT NULL DEFAULT '[]'
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS risk_assessment_detections (
        assessment_id TEXT NOT NULL,
        detection_id  TEXT NOT NULL,
        PRIMARY KEY (assessment_id, detection_id),
        FOREIGN KEY (assessment_id) REFERENCES risk_assessments(assessment_id),
        FOREIGN KEY (detection_id) REFERENCES detections(detection_id)
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS schema_metadata (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );
    """,
]

# Indexes for query performance.
CREATE_INDEXES: list[str] = [
    "CREATE INDEX IF NOT EXISTS idx_events_host ON events(host);",
    "CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);",
    "CREATE INDEX IF NOT EXISTS idx_events_source ON events(source);",
    "CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type);",
    "CREATE INDEX IF NOT EXISTS idx_detections_host ON detections(host);",
    "CREATE INDEX IF NOT EXISTS idx_detections_severity ON detections(severity);",
    "CREATE INDEX IF NOT EXISTS idx_detections_rule_id ON detections(rule_id);",
    "CREATE INDEX IF NOT EXISTS idx_detections_triggered_at ON detections(triggered_at);",
    "CREATE INDEX IF NOT EXISTS idx_evidence_detection_id ON evidence(detection_id);",
    "CREATE INDEX IF NOT EXISTS idx_evidence_event_id ON evidence(event_id);",
    "CREATE INDEX IF NOT EXISTS idx_risk_assessments_host ON risk_assessments(affected_host);",
    "CREATE INDEX IF NOT EXISTS idx_risk_assessments_score ON risk_assessments(risk_score);",
]


def get_schema_sql() -> list[str]:
    """Return the full list of schema DDL statements (tables + indexes)."""
    return list(CREATE_TABLES) + list(CREATE_INDEXES)


def _migrate_v1_to_v2(cur) -> None:
    """Migrate schema from v1 to v2.

    Changes:
    * evidence.event_id made nullable (no NOT NULL)
    * evidence.external_event_ref column added
    * risk_assessment_detections.detection_id -> detections.detection_id FK restored
    """
    # Recreate evidence table with nullable event_id + external_event_ref
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS evidence_new (
            evidence_id       TEXT PRIMARY KEY,
            detection_id      TEXT NOT NULL,
            event_id          TEXT,
            external_event_ref TEXT,
            timestamp         TEXT,
            source            TEXT,
            event_type        TEXT,
            user              TEXT,
            host              TEXT,
            source_address    TEXT,
            raw               TEXT NOT NULL,
            FOREIGN KEY (detection_id) REFERENCES detections(detection_id)
        )
        """
    )
    cur.execute(
        """
        INSERT INTO evidence_new (
            evidence_id, detection_id, event_id, external_event_ref,
            timestamp, source, event_type, user, host, source_address, raw
        )
        SELECT evidence_id, detection_id, event_id, NULL,
               timestamp, source, event_type, user, host, source_address, raw
        FROM evidence
        """
    )
    cur.execute("DROP TABLE evidence")
    cur.execute("ALTER TABLE evidence_new RENAME TO evidence")
    cur.execute(
        "CREATE INDEX IF NOT EXISTS idx_evidence_event_id ON evidence(event_id);"
    )

    # Recreate risk_assessment_detections with detection_id FK
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS risk_assessment_detections_new (
            assessment_id TEXT NOT NULL,
            detection_id  TEXT NOT NULL,
            PRIMARY KEY (assessment_id, detection_id),
            FOREIGN KEY (assessment_id) REFERENCES risk_assessments(assessment_id),
            FOREIGN KEY (detection_id) REFERENCES detections(detection_id)
        )
        """
    )
    cur.execute(
        """
        INSERT INTO risk_assessment_detections_new (assessment_id, detection_id)
        SELECT assessment_id, detection_id FROM risk_assessment_detections
        """
    )
    cur.execute("DROP TABLE risk_assessment_detections")
    cur.execute("ALTER TABLE risk_assessment_detections_new RENAME TO risk_assessment_detections")

    # Populate contributing_detection_ids_json from the junction table data
    # so that risk assessment relationships survive migration.
    cur.execute(
        """
        SELECT assessment_id, GROUP_CONCAT(detection_id)
        FROM risk_assessment_detections
        GROUP BY assessment_id
        """
    )
    for assessment_id, detection_ids in cur.fetchall():
        if detection_ids:
            id_list = detection_ids.split(",")
            json_array = "[" + ",".join(f'"{did}"' for did in id_list) + "]"
        else:
            json_array = "[]"
        cur.execute(
            "UPDATE risk_assessments SET contributing_detection_ids_json = ? "
            "WHERE assessment_id = ?",
            (json_array, assessment_id),
        )


def _migrate_v2_to_v3(cur) -> None:
    """Migrate schema from v2 to v3.

    Changes:
    * evidence.event_id gets FOREIGN KEY REFERENCES events(event_id)
      ON DELETE RESTRICT. event_id remains nullable (NULL values bypass FK
      checks and use external_event_ref instead).
    """
    # Recreate evidence table with event_id FK to events
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS evidence_new (
            evidence_id       TEXT PRIMARY KEY,
            detection_id      TEXT NOT NULL,
            event_id          TEXT,
            external_event_ref TEXT,
            timestamp         TEXT,
            source            TEXT,
            event_type        TEXT,
            user              TEXT,
            host              TEXT,
            source_address    TEXT,
            raw               TEXT NOT NULL,
            FOREIGN KEY (detection_id) REFERENCES detections(detection_id),
            FOREIGN KEY (event_id) REFERENCES events(event_id) ON DELETE RESTRICT
        )
        """
    )
    cur.execute(
        """
        INSERT INTO evidence_new (
            evidence_id, detection_id, event_id, external_event_ref,
            timestamp, source, event_type, user, host, source_address, raw
        )
        SELECT evidence_id, detection_id, event_id, external_event_ref,
               timestamp, source, event_type, user, host, source_address, raw
        FROM evidence
        """
    )
    cur.execute("DROP TABLE evidence")
    cur.execute("ALTER TABLE evidence_new RENAME TO evidence")
    cur.execute(
        "CREATE INDEX IF NOT EXISTS idx_evidence_event_id ON evidence(event_id);"
    )


def migrate(db_path: str, target_version: int = SCHEMA_VERSION) -> int:
    """Ensure the database at ``db_path`` is migrated to ``target_version``.

    Creates all tables and indexes if they do not exist, and records the
    schema version in ``schema_metadata``. Returns the current schema version.
    """
    import sqlite3

    conn = sqlite3.connect(db_path)
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
        cur = conn.cursor()

        # Create the metadata table first so we can read the current version.
        cur.execute(
            "CREATE TABLE IF NOT EXISTS schema_metadata ("
            "key   TEXT PRIMARY KEY,"
            "value TEXT NOT NULL)"
        )

        # Read current version.
        cur.execute(
            "SELECT value FROM schema_metadata WHERE key = ?",
            ("schema_version",),
        )
        row = cur.fetchone()
        current_version = int(row[0]) if row else 0

        if current_version >= target_version:
            conn.commit()
            return current_version

        # Apply incremental migrations.
        if current_version < 1:
            # Fresh database: create all v3 tables directly.
            for statement in get_schema_sql():
                cur.execute(statement)
        elif current_version == 1:
            _migrate_v1_to_v2(cur)
            _migrate_v2_to_v3(cur)
        elif current_version == 2:
            _migrate_v2_to_v3(cur)
        else:
            raise ValueError(
                f"Cannot migrate from schema version {current_version} to "
                f"{target_version}"
            )

        # Upsert schema version.
        cur.execute(
            "INSERT INTO schema_metadata (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            ("schema_version", str(target_version)),
        )
        conn.commit()
        return target_version
    finally:
        conn.close()


def get_schema_version(db_path: str) -> Optional[int]:
    """Return the current schema version, or None if not initialized."""
    import sqlite3

    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        # schema_metadata may not exist yet on a fresh database.
        cur.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name = 'schema_metadata'"
        )
        if not cur.fetchone():
            return None
        cur.execute(
            "SELECT value FROM schema_metadata WHERE key = ?",
            ("schema_version",),
        )
        row = cur.fetchone()
        return int(row[0]) if row else None
    finally:
        conn.close()
