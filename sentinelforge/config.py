"""Environment-driven configuration.

No credentials or API keys are stored in source code. All settings come from
environment variables with safe defaults. A local `config.env` file may be used
for development and must never be committed.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _env_bool(name: str, default: bool = False) -> bool:
    return str(os.environ.get(name, str(default))).lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


@dataclass(frozen=True)
class Settings:
    # Database
    db_path: str = _env("SENTINELFORGE_DB_PATH", "data/sentinelforge.db")

    # Ingestion
    max_events_per_ingest: int = _env_int("SENTINELFORGE_MAX_EVENTS_PER_INGEST", 100_000)

    # Detection thresholds
    failed_login_threshold: int = _env_int("SENTINELFORGE_FAILED_LOGIN_THRESHOLD", 5)
    failed_login_window_seconds: int = _env_int(
        "SENTINELFORGE_FAILED_LOGIN_WINDOW_SECONDS", 300
    )

    # C2 beacon detection
    beacon_min_connections: int = _env_int("SENTINELFORGE_BEACON_MIN_CONNECTIONS", 6)
    beacon_regularity_tolerance: float = _env_float(
        "SENTINELFORGE_BEACON_REGULARITY_TOLERANCE", 0.25
    )

    # AI provider (optional, off by default)
    ai_provider: str = _env("SENTINELFORGE_AI_PROVIDER", "mock")
    ai_model: Optional[str] = _env("SENTINELFORGE_AI_MODEL", None)
    ai_base_url: Optional[str] = _env("SENTINELFORGE_AI_BASE_URL", None)
    # API keys must never be hard-coded; read only when a real provider is used.
    ai_api_key_env: Optional[str] = _env("SENTINELFORGE_AI_API_KEY_ENV", None)

    def ai_enabled(self) -> bool:
        return self.ai_provider != "mock"


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


settings = Settings()
