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


def _env_int_required(name: str, default: int) -> int:
    """Read an integer env var, raising a clear error on invalid explicit values.

    If the variable is unset, ``default`` is returned. If it is set but
    empty, whitespace-only, or not a valid integer, ``ValueError`` is raised
    identifying the variable and expected format. The default is never
    silently substituted for an explicitly supplied invalid value.
    """
    raw = os.environ.get(name)
    if raw is None:
        return default
    stripped = raw.strip()
    if not stripped:
        raise ValueError(
            f"{name} must be a positive integer, got empty or whitespace-only value"
        )
    try:
        return int(stripped)
    except (TypeError, ValueError):
        raise ValueError(
            f"{name} must be a positive integer, got {raw!r}"
        ) from None


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

    # Safety guard: maximum events loaded for detection/evaluation.
    # Prevents unbounded memory consumption on large databases.
    max_detection_events: int = _env_int_required(
        "SENTINELFORGE_MAX_DETECTION_EVENTS", 100_000
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

    def __post_init__(self) -> None:
        """Validate configuration values after initialization.

        Raises ValueError if any threshold or window value is invalid
        (non-positive), preventing silent misconfiguration.
        """
        if self.failed_login_threshold <= 0:
            raise ValueError(
                f"failed_login_threshold must be positive, got {self.failed_login_threshold}"
            )
        if self.failed_login_window_seconds <= 0:
            raise ValueError(
                f"failed_login_window_seconds must be positive, got {self.failed_login_window_seconds}"
            )
        if self.beacon_min_connections <= 0:
            raise ValueError(
                f"beacon_min_connections must be positive, got {self.beacon_min_connections}"
            )
        if not (0.0 < self.beacon_regularity_tolerance <= 1.0):
            raise ValueError(
                f"beacon_regularity_tolerance must be in (0, 1], "
                f"got {self.beacon_regularity_tolerance}"
            )
        if self.max_detection_events <= 0:
            raise ValueError(
                f"max_detection_events must be positive, "
                f"got {self.max_detection_events}"
            )


settings = Settings()
