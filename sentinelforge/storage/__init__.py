"""SQLite storage layer for SentinelForge AI.

Provides a modular, versioned SQLite persistence layer for normalized events,
detection results, evidence, and risk assessments. Uses Python's built-in
sqlite3 library — no external dependencies.

Design principles:
- Original raw logs are preserved verbatim (serialized as JSON).
- No API credentials are ever stored.
- No stored commands are ever executed.
- Historical evidence is never automatically deleted.
- Parameterized queries throughout; foreign keys enforced.
- Idempotent inserts where identifiers are stable.
- Database file stays in the project data directory.
"""
