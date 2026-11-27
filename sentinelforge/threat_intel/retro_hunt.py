"""Retrospective hunting workflow.

Searches previously ingested telemetry for historical IOC matches and
records retro-hunt findings. Findings are append-only and distinct from
real-time detections; they never modify the original alert or detection
records, and a historical match is never counted as a detection made at
the original event time.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any

from sentinelforge.storage.database import Database
from sentinelforge.storage.repositories import IOCRepository
from sentinelforge.storage.schema import IOCMatch, RetroHunt
from sentinelforge.threat_intel.matcher import match_iocs


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _make_hunt_id(indicator_id: str, search_timestamp: str) -> str:
    payload = f"hunt|{indicator_id}|{search_timestamp}"
    return "hunt-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


class RetroHuntResult:
    """Outcome of a retrospective hunt."""

    def __init__(
        self,
        hunt: RetroHunt,
        matches: list[IOCMatch],
        match_links: list[tuple[str, str]],
    ) -> None:
        self.hunt = hunt
        self.matches = matches
        self.match_links = match_links


def run_retro_hunt(
    db: Database,
    indicator_id: str,
    events: list[dict[str, Any]],
    *,
    search_timestamp: str | None = None,
) -> RetroHuntResult:
    """Run a retrospective hunt for an IOC against stored events.

    Stores the retro-hunt record and its IOC matches. Returns the result
    without modifying any existing alert or detection record.

    Parameters
    ----------
    db:
        The SentinelForge database.
    indicator_id:
        The IOC to hunt for (must already be stored).
    events:
        The previously ingested events to search (the search scope).
    search_timestamp:
        Optional fixed timestamp for deterministic tests. Defaults to now.
    """
    timestamp = search_timestamp or _now_iso()
    repo = IOCRepository(db)
    ioc = repo.get_ioc(indicator_id)
    if ioc is None:
        raise ValueError(f"IOC {indicator_id} not found")

    matches = match_iocs(events, [ioc])

    hunt = RetroHunt(
        hunt_id=_make_hunt_id(indicator_id, timestamp),
        indicator_id=indicator_id,
        search_scope=(
            f"{len(events)} events searched for IOC {indicator_id} "
            f"({ioc.indicator_type})"
        ),
        total_events_searched=len(events),
        match_count=len(matches),
        search_timestamp=timestamp,
    )
    hunt_id = repo.insert_retro_hunt(hunt)

    match_links: list[tuple[str, str]] = []
    for match in matches:
        match_id = repo.insert_ioc_match(match)
        repo.link_retro_hunt_match(hunt_id, match_id)
        match_links.append((hunt_id, match_id))

    return RetroHuntResult(hunt=hunt, matches=matches, match_links=match_links)
