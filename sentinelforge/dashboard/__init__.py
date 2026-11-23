"""SentinelForge local dashboard package.

Provides a read-only, localhost-only HTTP dashboard backed by the
SQLite database used by the CLI. No new detection engine — the existing
Python detection engine remains the source of truth.
"""

from sentinelforge.dashboard.server import DEFAULT_HOST, DEFAULT_PORT, main, run

__all__ = ["DEFAULT_HOST", "DEFAULT_PORT", "main", "run"]
