"""Linux authentication adapter.

Parses SSH and sudo authentication events shipped as JSONL into the common
normalized event schema. The adapter is lenient about key naming and records a
warning for every field it cannot locate.
"""

from __future__ import annotations

from typing import Any

from sentinelforge.ingestion.adapters.base import Adapter, register
from sentinelforge.ingestion.normalizer import (
    AuthenticationInfo,
    NormalizedEvent,
)

_EVENT_TYPE_BY_PROGRAM: dict[str, str] = {
    "sshd": "authentication",
    "sudo": "privilege_escalation",
    "su": "privilege_escalation",
}


def _first(raw: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in raw and raw[key] is not None:
            return raw[key]
    return None


class LinuxAuthAdapter(Adapter):
    source = "linux_auth"

    def can_handle(self, raw: dict[str, Any]) -> bool:
        return (
            raw.get("source") == "linux_auth"
            or raw.get("program") in ("sshd", "sudo", "su")
            or raw.get("event_type") in ("ssh_login", "sudo", "su")
        )

    def adapt(self, raw: dict[str, Any]) -> NormalizedEvent | None:
        if not self.can_handle(raw):
            return None

        warnings: list[str] = []

        event_id = _first(raw, "event_id")
        if event_id is None:
            warnings.append("missing event_id")
            event_id = f"linux-auth-{_first(raw, 'pid')}"

        timestamp = _first(raw, "timestamp", "@timestamp", "time")
        host = _first(raw, "host", "hostname", "computer")
        program = _first(raw, "program", "service")
        username = _first(raw, "username", "user", "target_user")
        source_address = _first(
            raw, "source_address", "source_ip", "src_ip", "remote_address"
        )
        outcome = _first(raw, "outcome", "result", "status")

        event_type = _first(raw, "event_type")
        if event_type is None and program:
            event_type = _EVENT_TYPE_BY_PROGRAM.get(str(program), "linux_auth")

        auth = None
        if program in ("sshd", "sudo", "su"):
            auth = AuthenticationInfo(
                outcome=str(outcome) if outcome else None,
                method=str(program) if program else None,
                username=str(username) if username else None,
                source_address=str(source_address) if source_address else None,
            )

        if not timestamp:
            warnings.append("missing timestamp")
        if not host:
            warnings.append("missing host")
        if not source_address:
            warnings.append("missing source_address")

        self.warnings = warnings

        return NormalizedEvent(
            event_id=str(event_id),
            source=self.source,
            raw=raw,
            timestamp=str(timestamp) if timestamp else None,
            event_type=event_type,
            user=str(username) if username else None,
            host=str(host) if host else None,
            authentication=auth,
        )


register(LinuxAuthAdapter())
