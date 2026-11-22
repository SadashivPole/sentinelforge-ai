"""Common event normalization schema.

Maps raw reader output to :class:`NormalizedEvent`. Every normalized event
carries its original raw payload under ``raw`` so that detection rules and the
SOC dashboard can always point back to the exact log evidence. No fields are
invented: only data present in the raw log (or a generated event id) is used.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

from sentinelforge.ingestion.reader import _get_event_id


@dataclass(frozen=True)
class ProcessInfo:
    pid: int | None = None
    ppid: int | None = None
    name: str | None = None
    path: str | None = None
    command_line: str | None = None
    user: str | None = None
    hash_sha256: str | None = None


@dataclass(frozen=True)
class NetworkInfo:
    direction: str | None = None  # inbound | outbound | unknown
    local_address: str | None = None
    remote_address: str | None = None
    local_port: int | None = None
    remote_port: int | None = None
    protocol: str | None = None  # tcp | udp | ...


@dataclass(frozen=True)
class AuthenticationInfo:
    outcome: str | None = None  # success | failure | ...
    method: str | None = None
    username: str | None = None
    source_address: str | None = None


@dataclass(frozen=True)
class NormalizedEvent:
    """A normalized security event with the original raw log preserved."""

    event_id: str
    source: str  # json | jsonl | sysmon
    raw: dict  # original payload, preserved verbatim
    timestamp: str | None = None  # ISO-8601 UTC (absent when not parseable)
    event_type: str | None = None
    user: str | None = None
    host: str | None = None
    process: ProcessInfo | None = None
    network: NetworkInfo | None = None
    authentication: AuthenticationInfo | None = None
    ingested_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _iso_now() -> str:
    return datetime.now(UTC).isoformat()


def _to_iso(value: Any) -> str | None:
    """Best-effort ISO-8601 conversion of a timestamp present in the log.

    Returns None when no parseable timestamp exists; we never invent one.
    """
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(float(value), tz=UTC).isoformat()
        except (OverflowError, OSError, ValueError):
            return None
    text = str(value)
    for fmt in (
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
    ):
        try:
            dt = datetime.strptime(text, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
            return dt.isoformat()
        except ValueError:
            continue
    return None


def _first(d: dict, *keys: str) -> str | None:
    for key in keys:
        if key in d and d[key] is not None:
            return str(d[key])
    return None


def _int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _extract_sysmon_fields(raw: dict) -> dict[str, str]:
    event = raw.get("Event", {}) if isinstance(raw, dict) else {}
    data_items = (
        (event.get("EventData", {}) or {}).get("Data", [])
        if isinstance(event, dict)
        else []
    )
    fields: dict[str, str] = {}
    for item in data_items:
        if not isinstance(item, dict):
            continue
        name = item.get("Name") or item.get("@Name")
        if name is None:
            continue
        fields[str(name)] = item.get("#text", item.get("text", "")) or ""
    return fields


def normalize(
    raw: dict,
    source: str = "json",
    source_file: str | None = None,
    position: int | None = None,
    allow_fallback: bool = True,
) -> NormalizedEvent:
    """Normalize one raw event into :class:`NormalizedEvent`.

    ``source`` must be one of ``json``, ``jsonl`` or ``sysmon``. The original
    ``raw`` dict is stored verbatim under ``NormalizedEvent.raw``.

    ``source_file`` and ``position`` are used when generating an event id
    for records that lack a source-supplied id. Together with the canonical
    content they ensure that identical records at different positions or in
    different files receive distinct ids (no false deduplication). When
    omitted (single-event utility calls), a content-only hash is used —
    this is safe only for non-persistent, single-event use; distinct but
    identical records may receive the same ID. Persistent batch/stream
    ingestion must supply source_file via normalize_stream() or cmd_ingest().

    ``allow_fallback`` controls whether a content-only hash is used when
    no source-supplied ID exists and source_file is None. Single-event
    utility calls default to True; normalize_stream() passes False to
    enforce source identity for persistent ingestion.
    """
    if not isinstance(raw, dict):
        raise TypeError("raw event must be a dict")

    event_id = _get_event_id(
        raw, source_file=source_file, position=position, allow_fallback=allow_fallback
    )

    if source == "sysmon":
        fields = _extract_sysmon_fields(raw)
        system = (raw.get("Event", {}) or {}).get("System", {}) or {}
        # Sysmon TimeCreated is an element with a SystemTime attribute;
        # when converted to JSON it becomes {"SystemTime": "..."}.
        time_created = system.get("TimeCreated")
        if isinstance(time_created, dict):
            time_created = time_created.get("SystemTime")
        elif time_created is not None:
            time_created = str(time_created)
        timestamp = _to_iso(time_created or _first(fields, "TimeCreated"))
        event_type = _first(fields, "EventType", "Type") or (
            "process.create" if fields.get("Image") else None
        )
        user = _first(fields, "User", "UserName", "SubjectUserName")
        host = _first(system, "Computer", "Host") or _first(
            fields, "Computer", "HostName"
        )
        process = ProcessInfo(
            pid=_int(_first(fields, "ProcessId", "PID")),
            ppid=_int(_first(fields, "ParentProcessId", "PPID")),
            name=_first(fields, "Image", "ProcessName"),
            path=_first(fields, "Image"),
            command_line=_first(fields, "CommandLine"),
            user=user,
            hash_sha256=_first(fields, "Hash", "SHA256", "Hashes"),
        )
        network = None
        authentication = None
    else:
        timestamp = _to_iso(
            _first(raw, "timestamp", "time", "@timestamp", "event_time", "TimeCreated")
        )
        event_type = _first(raw, "event_type", "eventType", "type")
        user = _first(raw, "user", "username", "UserName")
        host = _first(raw, "host", "hostname", "Computer")

        proc_raw = raw.get("process")
        process = None
        if isinstance(proc_raw, dict):
            process = ProcessInfo(
                pid=_int(proc_raw.get("pid") or proc_raw.get("PID")),
                ppid=_int(proc_raw.get("ppid") or proc_raw.get("PPID")),
                name=_first(proc_raw, "name", "process_name", "Image"),
                path=_first(proc_raw, "path", "executable", "Image"),
                command_line=_first(
                    proc_raw, "command_line", "commandLine", "CommandLine"
                ),
                user=_first(proc_raw, "user", "username"),
                hash_sha256=_first(proc_raw, "hash_sha256", "sha256", "Hash"),
            )

        net_raw = raw.get("network")
        network = None
        if isinstance(net_raw, dict):
            network = NetworkInfo(
                direction=_first(net_raw, "direction"),
                local_address=_first(net_raw, "local_address", "localAddress"),
                remote_address=_first(net_raw, "remote_address", "remoteAddress"),
                local_port=_int(net_raw.get("local_port") or net_raw.get("localPort")),
                remote_port=_int(
                    net_raw.get("remote_port") or net_raw.get("remotePort")
                ),
                protocol=_first(net_raw, "protocol"),
            )

        auth_raw = raw.get("authentication")
        authentication = None
        if isinstance(auth_raw, dict):
            authentication = AuthenticationInfo(
                outcome=_first(auth_raw, "outcome", "status", "result"),
                method=_first(auth_raw, "method", "auth_method"),
                username=_first(auth_raw, "username", "user"),
                source_address=_first(
                    auth_raw, "source_address", "src_address", "source_ip"
                ),
            )

    return NormalizedEvent(
        event_id=event_id,
        timestamp=timestamp,
        source=source,
        raw=raw,
        event_type=event_type,
        user=user,
        host=host,
        process=process,
        network=network,
        authentication=authentication,
    )


def normalize_stream(
    raw_events: Iterator[dict],
    source: str = "json",
    source_file: str | None = None,
    start_position: int = 1,
) -> Iterator[NormalizedEvent]:
    """Normalize an iterator of raw events, preserving order.

    ``source_file`` and ``start_position`` are passed through to
    :func:`normalize` for every record that lacks a source-supplied event
    ID. Records that carry their own ``event_id`` are preserved verbatim
    and do not require source_file. Records without a source-supplied ID
    require source_file to be set, otherwise a ValueError is raised
    (content-only hashes are not safe for batch ingestion).

    ``start_position`` sets the initial record position; combined with
    ``source_file`` it ensures stable, collision-free IDs across
    re-ingestion of the same source file.
    """
    position = start_position
    for raw in raw_events:
        yield normalize(
            raw,
            source=source,
            source_file=source_file,
            position=position,
            allow_fallback=False,
        )
        position += 1
