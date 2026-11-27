"""Windows Security event adapter.

Parses Windows Security audit events (e.g. 4624 logon success, 4625 logon
failure, 4688 process creation) shipped as JSONL into the common normalized
event schema. Field names follow the common WinLogbeat/JSONL export shape but
the adapter is deliberately lenient about key naming and records a warning for
every field it cannot locate.
"""

from __future__ import annotations

from typing import Any

from sentinelforge.ingestion.adapters.base import Adapter, register
from sentinelforge.ingestion.normalizer import (
    AuthenticationInfo,
    NormalizedEvent,
)

# Windows Security event codes the adapter maps to detection-relevant types.
_EVENT_TYPE_BY_CODE: dict[int, str] = {
    4624: "authentication.success",
    4625: "authentication.failure",
    4648: "authentication.explicit_credentials",
    4672: "privilege_assignment",
    4688: "process_creation",
}


def _first(raw: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in raw and raw[key] is not None:
            return raw[key]
    return None


def _outcome(code: int | None) -> str | None:
    if code == 4624:
        return "success"
    if code == 4625:
        return "failure"
    return None


class WinSecurityAdapter(Adapter):
    source = "win_security"

    def can_handle(self, raw: dict[str, Any]) -> bool:
        return (
            raw.get("source") == "win_security"
            or "event_id_code" in raw
            or "EventID" in raw
        )

    def adapt(self, raw: dict[str, Any]) -> NormalizedEvent | None:
        if not self.can_handle(raw):
            return None

        warnings: list[str] = []

        event_id = _first(raw, "event_id")
        if event_id is None:
            warnings.append("missing event_id")
            event_id = f"win-{_first(raw, 'event_id_code')}"

        timestamp = _first(raw, "timestamp", "TimeCreated", "time_created")
        host = _first(raw, "host", "computer", "Computer", "hostname")
        user = _first(
            raw,
            "target_username",
            "username",
            "TargetUserName",
            "user",
        )
        source_address = _first(
            raw, "source_address", "SourceAddress", "source_ip", "ip_address"
        )

        code = _first(raw, "event_id_code", "EventID")
        code_int = None
        if isinstance(code, int):
            code_int = code
        elif isinstance(code, str) and code.isdigit():
            code_int = int(code)

        event_type = _first(raw, "event_type")
        if event_type is None and code_int is not None:
            event_type = _EVENT_TYPE_BY_CODE.get(code_int, "windows_security")

        auth = None
        if code_int in (4624, 4625):
            auth = AuthenticationInfo(
                outcome=_outcome(code_int),
                method=_first(raw, "authentication_package", "AuthenticationPackage"),
                username=str(user) if user else None,
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
            user=str(user) if user else None,
            host=str(host) if host else None,
            authentication=auth,
        )


register(WinSecurityAdapter())
