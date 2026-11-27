"""Database schema definition and versioned migrations.

Defines the canonical schema for all SentinelForge AI tables and provides
migration functions to evolve the schema version over time. Schema version is
tracked in the ``schema_metadata`` table.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field

# Current schema version. Increment on every breaking schema change.
SCHEMA_VERSION = 5


@dataclass(frozen=True)
class Incident:
    """A correlated grouping of related detections and events.

    Incidents are analyst-facing groupings produced by explicit correlation
    rules (shared host, user, IP, process lineage, ATT&CK behavior, time
    window). Correlation does not imply causation; each incident carries its
    rationale so analysts can verify the grouping.
    """

    incident_id: str
    title: str
    correlation_rationale: str
    severity: str
    status: str = "open"
    hosts: list[str] = field(default_factory=list)
    users: list[str] = field(default_factory=list)
    source_addresses: list[str] = field(default_factory=list)
    destination_addresses: list[str] = field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""
    evidence_complete: bool = False
    related_alert_count: int = 0
    related_event_count: int = 0
    created_at: str = ""
    updated_at: str = ""

    def to_row(self) -> dict[str, object]:
        """Serialize to a row suitable for the ``incidents`` table."""
        data = asdict(self)
        data["hosts"] = json.dumps(data["hosts"])
        data["users"] = json.dumps(data["users"])
        data["source_addresses"] = json.dumps(data["source_addresses"])
        data["destination_addresses"] = json.dumps(data["destination_addresses"])
        data["evidence_complete"] = int(data["evidence_complete"])
        return data


@dataclass(frozen=True)
class IOC:
    """A local threat-intelligence indicator of compromise.

    IOCs are imported from bounded local sources (CSV/JSON) and validated
    before storage. Confidence, reputation and attribution are never
    invented; they are recorded only when supplied by the source.
    """

    indicator_id: str
    indicator_value: str
    indicator_type: str  # ipv4 | ipv6 | domain | url | sha256
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

    def to_row(self) -> dict[str, object]:
        """Serialize to a row suitable for the ``iocs`` table."""
        return asdict(self)


@dataclass(frozen=True)
class IOCMatch:
    """A single IOC match against a stored event."""

    match_id: str
    indicator_id: str
    event_id: str
    event_timestamp: str | None = None
    matched_field: str = ""
    matched_value: str = ""
    indicator_source: str = ""
    match_type: str = ""  # exact_ip | exact_hash | normalized_domain | normalized_url

    def to_row(self) -> dict[str, object]:
        """Serialize to a row suitable for the ``ioc_matches`` table."""
        return asdict(self)


@dataclass(frozen=True)
class RetroHunt:
    """A retrospective hunt: searching stored events for a newly imported IOC."""

    hunt_id: str
    indicator_id: str
    search_scope: str
    total_events_searched: int = 0
    match_count: int = 0
    search_timestamp: str = ""

    def to_row(self) -> dict[str, object]:
        """Serialize to a row suitable for the ``retro_hunts`` table."""
        return asdict(self)


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
    CREATE TABLE IF NOT EXISTS incidents (
        incident_id                    TEXT PRIMARY KEY,
        title                          TEXT NOT NULL,
        correlation_rationale          TEXT NOT NULL,
        severity                       TEXT NOT NULL,
        status                         TEXT NOT NULL DEFAULT 'open',
        hosts_json                     TEXT NOT NULL DEFAULT '[]',
        users_json                     TEXT NOT NULL DEFAULT '[]',
        source_addresses_json          TEXT NOT NULL DEFAULT '[]',
        destination_addresses_json     TEXT NOT NULL DEFAULT '[]',
        first_seen                     TEXT NOT NULL,
        last_seen                      TEXT NOT NULL,
        evidence_complete              INTEGER NOT NULL DEFAULT 0,
        related_alert_count            INTEGER NOT NULL DEFAULT 0,
        related_event_count            INTEGER NOT NULL DEFAULT 0,
        created_at                     TEXT NOT NULL,
        updated_at                     TEXT NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS incident_alerts (
        incident_id TEXT NOT NULL,
        detection_id  TEXT NOT NULL,
        PRIMARY KEY (incident_id, detection_id),
        FOREIGN KEY (incident_id) REFERENCES incidents(incident_id) ON DELETE CASCADE,
        FOREIGN KEY (detection_id) REFERENCES detections(detection_id) ON DELETE CASCADE
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS incident_events (
        incident_id TEXT NOT NULL,
        event_id    TEXT NOT NULL,
        PRIMARY KEY (incident_id, event_id),
        FOREIGN KEY (incident_id) REFERENCES incidents(incident_id) ON DELETE CASCADE,
        FOREIGN KEY (event_id) REFERENCES events(event_id) ON DELETE CASCADE
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS iocs (
        indicator_id       TEXT PRIMARY KEY,
        indicator_value    TEXT NOT NULL,
        indicator_type     TEXT NOT NULL CHECK (indicator_type IN ('ipv4', 'ipv6', 'domain', 'url', 'sha256')),
        source_name        TEXT NOT NULL,
        source_reference   TEXT,
        confidence         INTEGER,
        first_seen         TEXT,
        last_seen          TEXT,
        expiration         TEXT,
        imported_at        TEXT NOT NULL,
        context            TEXT,
        provenance         TEXT,
        validation_status  TEXT NOT NULL DEFAULT 'valid'
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ioc_matches (
        match_id         TEXT PRIMARY KEY,
        indicator_id     TEXT NOT NULL,
        event_id         TEXT NOT NULL,
        event_timestamp  TEXT,
        matched_field    TEXT NOT NULL,
        matched_value    TEXT NOT NULL,
        indicator_source TEXT NOT NULL,
        match_type       TEXT NOT NULL,
        FOREIGN KEY (indicator_id) REFERENCES iocs(indicator_id),
        FOREIGN KEY (event_id) REFERENCES events(event_id) ON DELETE RESTRICT
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS retro_hunts (
        hunt_id             TEXT PRIMARY KEY,
        indicator_id        TEXT NOT NULL,
        search_scope        TEXT NOT NULL,
        total_events_searched INTEGER NOT NULL DEFAULT 0,
        match_count         INTEGER NOT NULL DEFAULT 0,
        search_timestamp    TEXT NOT NULL,
        FOREIGN KEY (indicator_id) REFERENCES iocs(indicator_id)
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS retro_hunt_matches (
        hunt_id   TEXT NOT NULL,
        match_id  TEXT NOT NULL,
        PRIMARY KEY (hunt_id, match_id),
        FOREIGN KEY (hunt_id) REFERENCES retro_hunts(hunt_id) ON DELETE CASCADE,
        FOREIGN KEY (match_id) REFERENCES ioc_matches(match_id) ON DELETE CASCADE
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
    "CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);",
    "CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);",
    "CREATE INDEX IF NOT EXISTS idx_incidents_first_seen ON incidents(first_seen);",
    "CREATE INDEX IF NOT EXISTS idx_incident_alerts_detection ON incident_alerts(detection_id);",
    "CREATE INDEX IF NOT EXISTS idx_incident_events_event ON incident_events(event_id);",
    "CREATE INDEX IF NOT EXISTS idx_iocs_type_value ON iocs(indicator_type, indicator_value);",
    "CREATE INDEX IF NOT EXISTS idx_ioc_matches_event ON ioc_matches(event_id);",
    "CREATE INDEX IF NOT EXISTS idx_ioc_matches_indicator ON ioc_matches(indicator_id);",
    "CREATE INDEX IF NOT EXISTS idx_retro_hunts_indicator ON retro_hunts(indicator_id);",
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
    cur.execute(
        "ALTER TABLE risk_assessment_detections_new RENAME TO risk_assessment_detections"
    )

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


def _migrate_v3_to_v4(cur) -> None:
    """Migrate schema from v3 to v4.

    Changes:
    * Add ``incidents``, ``incident_alerts`` and ``incident_events`` tables
      for correlated incident grouping (additive; existing tables untouched).
    """
    for statement in (
        s
        for s in get_schema_sql()
        if "incidents" in s or "incident_alerts" in s or "incident_events" in s
    ):
        cur.execute(statement)


def _migrate_v4_to_v5(cur) -> None:
    """Migrate schema from v4 to v5.

    Changes:
    * Add ``iocs``, ``ioc_matches``, ``retro_hunts`` and ``retro_hunt_matches``
      tables for local-first threat intelligence and retrospective hunting
      (additive; existing tables untouched).
    """
    for statement in (
        s
        for s in get_schema_sql()
        if "iocs" in s
        or "ioc_matches" in s
        or "retro_hunts" in s
        or "retro_hunt_matches" in s
    ):
        cur.execute(statement)


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
            # Fresh database: create all v4 tables directly.
            for statement in get_schema_sql():
                cur.execute(statement)
        elif current_version == 1:
            _migrate_v1_to_v2(cur)
            _migrate_v2_to_v3(cur)
            _migrate_v3_to_v4(cur)
            _migrate_v4_to_v5(cur)
        elif current_version == 2:
            _migrate_v2_to_v3(cur)
            _migrate_v3_to_v4(cur)
            _migrate_v4_to_v5(cur)
        elif current_version == 3:
            _migrate_v3_to_v4(cur)
            _migrate_v4_to_v5(cur)
        elif current_version == 4:
            _migrate_v4_to_v5(cur)
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


def get_schema_version(db_path: str) -> int | None:
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
