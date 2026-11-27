"""Shared fixtures for the SentinelForge test suite.

Provides a ``tmp_db`` fixture yielding a freshly initialized
:class:`~sentinelforge.storage.database.Database` backed by a temporary
SQLite file. Each test gets an isolated database so tests never share state.
"""

from __future__ import annotations

import os
import tempfile

import pytest

from sentinelforge.storage.database import Database


@pytest.fixture
def tmp_db() -> Database:
    """Return a fresh, schema-initialized Database in a temp file."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    os.unlink(path)  # let SQLite create it fresh
    db = Database(path)
    db.initialize()
    return db
