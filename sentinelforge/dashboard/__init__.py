"""SentinelForge local dashboard package.

Provides a read-only, localhost-only HTTP dashboard backed by the
SQLite database used by the CLI. No new detection engine — the existing
Python detection engine remains the source of truth.
"""

from sentinelforge.dashboard.server import run, main, DEFAULT_HOST, DEFAULT_PORT

__all__ = ["run", "main", "DEFAULT_HOST", "DEFAULT_PORT"]
