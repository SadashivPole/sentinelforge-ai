"""Linux auditd adapter.

Parses auditd process-execution and audit events shipped as JSONL into the
common normalized event schema. The adapter is lenient about key naming and
records a warning for every field it cannot locate.
"""

from __future__ import annotations

from typing import Any

from sentinelforge.ingestion.adapters.base import Adapter, register
from sentinelforge.ingestion.normalizer import (
    NormalizedEvent,
    ProcessInfo,
)


def _first(raw: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in raw and raw[key] is not None:
            return raw[key]
    return None


class AuditdAdapter(Adapter):
    source = "auditd"

    def can_handle(self, raw: dict[str, Any]) -> bool:
        return (
            raw.get("source") == "auditd"
            or raw.get("audit_type") == "auditd"
            or "exe" in raw
            or "pid" in raw
        )

    def adapt(self, raw: dict[str, Any]) -> NormalizedEvent | None:
        if not self.can_handle(raw):
            return None

        warnings: list[str] = []

        event_id = _first(raw, "event_id")
        if event_id is None:
            warnings.append("missing event_id")
            event_id = f"auditd-{_first(raw, 'pid')}"

        timestamp = _first(raw, "timestamp", "@timestamp", "time")
        host = _first(raw, "host", "hostname", "computer")
        user = _first(raw, "user", "uid", "username")
        exe = _first(raw, "exe", "executable", "command")
        command_line = _first(raw, "command_line", "cmdline", "args")
        pid = _first(raw, "pid")
        ppid = _first(raw, "ppid", "parent_pid")

        process = None
        if exe or command_line or pid:
            process = ProcessInfo(
                pid=int(pid)
                if isinstance(pid, int) or (isinstance(pid, str) and pid.isdigit())
                else None,
                ppid=int(ppid)
                if isinstance(ppid, int) or (isinstance(ppid, str) and ppid.isdigit())
                else None,
                name=str(exe) if exe else None,
                command_line=str(command_line) if command_line else None,
                user=str(user) if user else None,
            )

        if not timestamp:
            warnings.append("missing timestamp")
        if not host:
            warnings.append("missing host")

        self.warnings = warnings

        return NormalizedEvent(
            event_id=str(event_id),
            source=self.source,
            raw=raw,
            timestamp=str(timestamp) if timestamp else None,
            event_type=_first(raw, "event_type", "audit_type") or "process_execution",
            user=str(user) if user else None,
            host=str(host) if host else None,
            process=process,
        )


register(AuditdAdapter())
