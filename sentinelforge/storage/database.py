"""SQLite database connection management.

Provides a thread-safe connection factory, schema initialization, and context
manager for transactions. All connections enforce foreign keys and use
parameterized queries.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from typing import Optional

from sentinelforge.config import settings
from sentinelforge.storage.schema import migrate, get_schema_version


class Database:
    """Manages SQLite connections for the SentinelForge AI project.

    The database file lives in the project data directory (configured via
    ``SENTINELFORGE_DB_PATH``, default ``data/sentinelforge.db``).
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        self.db_path = db_path or settings.db_path

    def connect(self) -> sqlite3.Connection:
        """Open a new SQLite connection with foreign keys enabled.

        The caller is responsible for closing the connection. Use
        :meth:`transaction` for automatic commit/rollback handling.
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn

    def initialize(self) -> int:
        """Create tables and migrate to the current schema version.

        Returns the schema version after migration.
        """
        return migrate(self.db_path)

    @contextmanager
    def transaction(self):
        """Context manager for a transactional connection.

        Commits on success, rolls back on exception, and always closes the
        connection.
        """
        conn = self.connect()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    @contextmanager
    def connection(self):
        """Context manager for a read-only connection (auto-closes)."""
        conn = self.connect()
        try:
            yield conn
        finally:
            conn.close()

    def schema_version(self) -> Optional[int]:
        """Return the current schema version, or None if not initialized."""
        return get_schema_version(self.db_path)


# Module-level default instance for convenience.
default_db = Database()
