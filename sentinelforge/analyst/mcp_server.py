"""SentinelForge SOC Analyst MCP server.

Local stdio-only MCP server exposing read-only access to SentinelForge
detection data. No ingestion, deletion, alteration, shell execution,
network access, or arbitrary SQL is available through MCP tools.

Trust model: untrusted local component. Read-only enforcement is at the
SQLite connection level (mode=ro + PRAGMA query_only=ON), not merely a
tool annotation.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any

try:
    from mcp.server import Server
    from mcp.server.context import ServerRequestContext
    from mcp.server.models import InitializationOptions
    from mcp.server.stdio import stdio_server
    from mcp.types import (
        CallToolRequestParams,
        CallToolResult,
        ListToolsResult,
        PaginatedRequestParams,
        ServerCapabilities,
        TextContent,
        Tool,
        ToolAnnotations,
        ToolsCapability,
    )

    _MCP_AVAILABLE = True
except ImportError:
    _MCP_AVAILABLE = False

from sentinelforge.analyst.database import (
    DatabaseMissingError,
    DatabaseNotInitializedError,
    Pagination,
    ReadOnlyDatabase,
    ReadOnlyDatabaseError,
    TimeRange,
)
from sentinelforge.detection.base import (
    DetectionResult,
    Evidence,
    Severity,
)
from sentinelforge.risk.correlator import DetectionCorrelator

logger = logging.getLogger("sentinelforge.mcp")

SERVER_NAME = "sentinelforge-analyst"
SERVER_VERSION = "0.1.0"

# Maximum raw payload bytes returned by get_alert_evidence to prevent
# oversize responses from a single evidence record.
MAX_EVIDENCE_RAW_BYTES = 65_536

# Maximum total serialized bytes for any single MCP tool response. Responses
# exceeding this are truncated with explicit metadata rather than silently
# producing oversize or invalid JSON.
MAX_RESPONSE_BYTES = 1_048_576  # 1 MiB


def _annotations(read_only: bool = True) -> ToolAnnotations:
    return ToolAnnotations(
        read_only_hint=read_only,
        destructive_hint=False,
        idempotent_hint=True,
        open_world_hint=False,
    )


def _tool(
    name: str,
    title: str,
    description: str,
    input_schema: dict[str, Any],
) -> Tool:
    return Tool(
        name=name,
        title=title,
        description=description,
        input_schema=input_schema,
        annotations=_annotations(),
    )


def _make_tools() -> list[Tool]:
    return [
        _tool(
            "sentinelforge_get_status",
            "SentinelForge status",
            "Database/schema status, event and detection counts, latest timestamps, and a safe source summary. No raw log contents are returned.",
            {
                "type": "object",
                "properties": {},
                "additionalProperties": False,
            },
        ),
        _tool(
            "sentinelforge_list_alerts",
            "List alerts (detections)",
            "List detection alerts with bounded pagination. Filter by host, severity, rule ID, and optional time range. Returns alert IDs, rule names, severity, host, timestamps, and evidence counts — not raw evidence payloads.",
            {
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 500,
                        "default": 50,
                    },
                    "offset": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": 10000,
                        "default": 0,
                    },
                    "host": {"type": "string", "maxLength": 256},
                    "severity": {"type": "string", "maxLength": 32},
                    "rule_id": {"type": "string", "maxLength": 128},
                    "start_time": {
                        "type": "string",
                        "description": "ISO 8601 start timestamp (inclusive)",
                    },
                    "end_time": {
                        "type": "string",
                        "description": "ISO 8601 end timestamp (inclusive)",
                    },
                },
                "additionalProperties": False,
            },
        ),
        _tool(
            "sentinelforge_get_alert",
            "Get alert by detection ID",
            "Fetch one alert using its exact detection ID. Includes metadata and evidence references. Returns a clear not-found result when absent.",
            {
                "type": "object",
                "properties": {
                    "detection_id": {"type": "string", "maxLength": 128},
                },
                "required": ["detection_id"],
                "additionalProperties": False,
            },
        ),
        _tool(
            "sentinelforge_get_alert_evidence",
            "Get alert evidence",
            "Retrieve evidence for an alert with offset/limit pagination. Includes event ID, timestamp, source, event type, host, user, and available network context. Raw payloads are bounded and only returned by this explicit call.",
            {
                "type": "object",
                "properties": {
                    "detection_id": {"type": "string", "maxLength": 128},
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 500,
                        "default": 50,
                    },
                    "offset": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": 10000,
                        "default": 0,
                    },
                },
                "required": ["detection_id"],
                "additionalProperties": False,
            },
        ),
        _tool(
            "sentinelforge_search_events",
            "Search events",
            "Search normalized event fields and raw-event text using parameterized queries. Bounded results. Discloses exactly which search scope and filters were applied.",
            {
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 500,
                        "default": 50,
                    },
                    "offset": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": 10000,
                        "default": 0,
                    },
                    "query": {
                        "type": "string",
                        "maxLength": 10000,
                        "description": "Free-text search matched against raw event text and normalized fields",
                    },
                    "host": {"type": "string", "maxLength": 256},
                    "event_type": {"type": "string", "maxLength": 128},
                    "source": {"type": "string", "maxLength": 128},
                    "user": {"type": "string", "maxLength": 128},
                    "start_time": {
                        "type": "string",
                        "description": "ISO 8601 start timestamp (inclusive)",
                    },
                    "end_time": {
                        "type": "string",
                        "description": "ISO 8601 end timestamp (inclusive)",
                    },
                },
                "additionalProperties": False,
            },
        ),
        _tool(
            "sentinelforge_build_investigation_brief",
            "Build investigation brief",
            "Build a deterministic event/alert timeline for a host, alert ID, or other supported scope. Uses existing detections, evidence, and detection correlation. Separates facts from derivations and unknowns. Does not invent entities or attack-chain relationships.",
            {
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "maxLength": 256,
                        "description": "Investigate a specific host",
                    },
                    "alert_id": {
                        "type": "string",
                        "maxLength": 128,
                        "description": "Investigate a specific detection ID",
                    },
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 500,
                        "default": 100,
                    },
                },
                "additionalProperties": False,
            },
        ),
        _tool(
            "sentinelforge_list_risk_assessments",
            "List risk assessments",
            "Retrieve existing risk assessments with bounded pagination and filters. Keeps risk score, detection severity, and evidence confidence separate.",
            {
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 500,
                        "default": 50,
                    },
                    "offset": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": 10000,
                        "default": 0,
                    },
                    "host": {"type": "string", "maxLength": 256},
                    "min_score": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": 100,
                        "description": "Minimum risk score (0-100)",
                    },
                },
                "additionalProperties": False,
            },
        ),
    ]


def _error_result(
    code: str, message: str, remediation: str | None = None
) -> CallToolResult:
    payload = {"error": {"code": code, "message": message}}
    if remediation:
        payload["error"]["remediation"] = remediation
    return CallToolResult(
        content=[TextContent(type="text", text=json.dumps(payload, indent=2))],
        is_error=True,
    )


def _ok_result(payload: dict[str, Any]) -> CallToolResult:
    return CallToolResult(
        content=[TextContent(type="text", text=_serialize_with_budget(payload))],
        is_error=False,
    )


def _serialize_with_budget(payload: dict[str, Any]) -> str:
    """Serialize payload to JSON, enforcing MAX_RESPONSE_BYTES.

    If the full payload exceeds the budget, truncates the largest array
    (evidence or events) progressively until it fits, then adds explicit
    truncation metadata. Never produces invalid JSON.
    """
    text = json.dumps(payload, indent=2)
    if len(text.encode("utf-8")) <= MAX_RESPONSE_BYTES:
        return text

    # Work on a mutable copy; shrink arrays until within budget.
    working = dict(payload)
    truncated_keys: list[str] = []

    for key in ("evidence", "events"):
        arr = working.get(key)
        if not isinstance(arr, list) or not arr:
            continue
        # Binary-search the largest prefix that fits.
        lo, hi = 0, len(arr)
        best = 0
        while lo <= hi:
            mid = (lo + hi) // 2
            trial = dict(working)
            trial[key] = arr[:mid]
            trial["truncated"] = True
            trial["truncated_keys"] = truncated_keys + [key]
            trial["returned"] = len(trial.get(key, []))
            trial_text = json.dumps(trial, indent=2)
            if len(trial_text.encode("utf-8")) <= MAX_RESPONSE_BYTES:
                best = mid
                lo = mid + 1
            else:
                hi = mid - 1
        working[key] = arr[:best]
        truncated_keys.append(key)
        working["truncated"] = True
        working["truncated_keys"] = truncated_keys
        working["returned"] = len(working[key])
        text = json.dumps(working, indent=2)
        if len(text.encode("utf-8")) <= MAX_RESPONSE_BYTES:
            break

    # Final safety: if still over budget, return a bounded error payload.
    if len(text.encode("utf-8")) > MAX_RESPONSE_BYTES:
        error_payload = {
            "error": {
                "code": "response_too_large",
                "message": "Response exceeds the maximum serialized size budget.",
                "remediation": "Narrow the query scope (smaller limit, more "
                "specific filters) and retry.",
            }
        }
        text = json.dumps(error_payload, indent=2)

    return text


class AnalystMCPServer:
    """Wraps the MCP Server with SentinelForge read-only data access."""

    def __init__(self, db_path: str) -> None:
        if not _MCP_AVAILABLE:
            raise ImportError(
                "The MCP server requires the optional 'analyst-mcp' extra. "
                "Install it with: pip install 'sentinelforge[analyst-mcp]'"
            )
        self.db_path = db_path
        self.server = Server(SERVER_NAME)
        self._register_handlers()

    def _register_handlers(self) -> None:
        server = self.server

        async def handle_list_tools(
            _context: ServerRequestContext,
            _request: PaginatedRequestParams | None = None,
        ) -> ListToolsResult:
            return ListToolsResult(tools=_make_tools())

        async def handle_call_tool(
            _context: ServerRequestContext,
            request: CallToolRequestParams,
        ) -> CallToolResult:
            name = request.name
            args = request.arguments or {}
            return self._dispatch(name, args)

        server.add_request_handler(
            "tools/list",
            PaginatedRequestParams,
            handle_list_tools,
        )
        server.add_request_handler(
            "tools/call",
            CallToolRequestParams,
            handle_call_tool,
        )

    def _dispatch(self, name: str, args: dict[str, Any]) -> CallToolResult:
        try:
            if name == "sentinelforge_get_status":
                return self._get_status()
            elif name == "sentinelforge_list_alerts":
                return self._list_alerts(args)
            elif name == "sentinelforge_get_alert":
                return self._get_alert(args)
            elif name == "sentinelforge_get_alert_evidence":
                return self._get_alert_evidence(args)
            elif name == "sentinelforge_search_events":
                return self._search_events(args)
            elif name == "sentinelforge_build_investigation_brief":
                return self._build_investigation_brief(args)
            elif name == "sentinelforge_list_risk_assessments":
                return self._list_risk_assessments(args)
            else:
                return _error_result("not_found", f"Unknown tool: {name}")
        except ReadOnlyDatabaseError as exc:
            return _error_result(exc.code, exc.message, exc.remediation)
        except Exception:  # pragma: no cover - defensive catch-all
            logger.exception("MCP tool %s failed", name)
            return _error_result(
                "internal",
                "An internal error occurred while processing the request.",
                "Retry the request. If it persists, contact the SentinelForge maintainers.",
            )

    # --- tool implementations ---

    def _get_status(self) -> CallToolResult:
        try:
            with ReadOnlyDatabase(self.db_path) as db:
                version = db.schema_version()
                counts = db.table_counts()
                latest = db.latest_timestamps()
        except DatabaseMissingError as exc:
            return _error_result(exc.code, exc.message, exc.remediation)
        except DatabaseNotInitializedError as exc:
            return _error_result(exc.code, exc.message, exc.remediation)
        except ReadOnlyDatabaseError as exc:
            return _error_result(exc.code, exc.message, exc.remediation)

        return _ok_result(
            {
                "database": {
                    "initialized": True,
                    "schema_version": version,
                    "mode": "read-only",
                },
                "counts": counts,
                "latest_timestamps": latest,
                "sources_summary": {
                    "note": "Use sentinelforge_search_events or sentinelforge_list_alerts to inspect specific sources and records.",
                },
            }
        )

    def _list_alerts(self, args: dict[str, Any]) -> CallToolResult:
        try:
            limit = int(args.get("limit", 50))
            offset = int(args.get("offset", 0))
            pagination = Pagination(limit=limit, offset=offset)
        except (ValueError, TypeError) as exc:
            return _error_result("bad_input", f"Invalid limit/offset: {exc}")

        time_range = None
        if args.get("start_time") or args.get("end_time"):
            try:
                time_range = TimeRange(
                    start=args.get("start_time"),
                    end=args.get("end_time"),
                )
            except ReadOnlyDatabaseError as exc:
                return _error_result(exc.code, exc.message, exc.remediation)

        try:
            with ReadOnlyDatabase(self.db_path) as db:
                alerts = db.list_alerts(
                    pagination=pagination,
                    host=args.get("host"),
                    severity=args.get("severity"),
                    rule_id=args.get("rule_id"),
                    time_range=time_range,
                )
                # Add exact evidence counts via a single COUNT(*) query per
                # alert — no raw payloads loaded, no N+1 connections.
                for alert in alerts:
                    alert["evidence_count"] = db.evidence_count(alert["detection_id"])
        except ReadOnlyDatabaseError as exc:
            return _error_result(exc.code, exc.message, exc.remediation)

        return _ok_result(
            {
                "tool": "sentinelforge_list_alerts",
                "filters_applied": {
                    "host": args.get("host"),
                    "severity": args.get("severity"),
                    "rule_id": args.get("rule_id"),
                    "start_time": args.get("start_time"),
                    "end_time": args.get("end_time"),
                },
                "pagination": {"limit": pagination.limit, "offset": pagination.offset},
                "returned": len(alerts),
                "alerts": alerts,
            }
        )

    def _get_alert(self, args: dict[str, Any]) -> CallToolResult:
        detection_id = args.get("detection_id")
        if not detection_id or not isinstance(detection_id, str):
            return _error_result(
                "bad_input",
                "detection_id is required and must be a string",
                "Provide detection_id as a non-empty string.",
            )

        try:
            with ReadOnlyDatabase(self.db_path) as db:
                alert = db.get_alert(detection_id)
        except ReadOnlyDatabaseError as exc:
            return _error_result(exc.code, exc.message, exc.remediation)

        if alert is None:
            return _error_result(
                "not_found",
                f"No alert with detection_id={detection_id}",
                "Verify the detection ID and try again.",
            )

        # Include evidence references (IDs and count) without raw payloads
        # so analysts can navigate to related evidence.
        evidence_refs: list[str] = []
        evidence_count: int | None = None
        evidence_count_exact = False
        has_more = False
        next_offset: int | None = None
        evidence_lookup_error: str | None = None
        try:
            with ReadOnlyDatabase(self.db_path) as db:
                ev_rows = db.get_alert_evidence(
                    detection_id, Pagination(limit=500, offset=0)
                )
                evidence_refs = [
                    r["evidence_id"] for r in ev_rows if r.get("evidence_id")
                ]
                evidence_count = db.evidence_count(detection_id)
                evidence_count_exact = True
                has_more = evidence_count > len(evidence_refs)
                next_offset = 500 if has_more else None
        except ReadOnlyDatabaseError as exc:
            # Evidence lookup failure must not hide the alert itself, but we
            # must not silently present an incomplete list as complete.
            evidence_count = None
            evidence_count_exact = False
            evidence_lookup_error = exc.message

        return _ok_result(
            {
                "tool": "sentinelforge_get_alert",
                "alert": alert,
                "evidence_references": {
                    "evidence_ids": evidence_refs,
                    "evidence_count": evidence_count,
                    "evidence_count_exact": evidence_count_exact,
                    "has_more": has_more,
                    "next_offset": next_offset,
                    "evidence_lookup_error": evidence_lookup_error,
                },
            }
        )

    def _get_alert_evidence(self, args: dict[str, Any]) -> CallToolResult:
        detection_id = args.get("detection_id")
        if not detection_id or not isinstance(detection_id, str):
            return _error_result(
                "bad_input",
                "detection_id is required and must be a string",
                "Provide detection_id as a non-empty string.",
            )

        try:
            limit = int(args.get("limit", 50))
            offset = int(args.get("offset", 0))
            pagination = Pagination(limit=limit, offset=offset)
        except (ValueError, TypeError) as exc:
            return _error_result("bad_input", f"Invalid limit/offset: {exc}")

        try:
            with ReadOnlyDatabase(self.db_path) as db:
                evidence = db.get_alert_evidence(detection_id, pagination)
        except ReadOnlyDatabaseError as exc:
            return _error_result(exc.code, exc.message, exc.remediation)

        # Bound raw payload size per record.
        bounded: list[dict[str, Any]] = []
        for row in evidence:
            raw = row.get("raw")
            if (
                isinstance(raw, str)
                and len(raw.encode("utf-8")) > MAX_EVIDENCE_RAW_BYTES
            ):
                row = dict(row)
                truncated = raw.encode("utf-8")[:MAX_EVIDENCE_RAW_BYTES].decode(
                    "utf-8", errors="replace"
                )
                row["raw"] = truncated + "... [truncated]"
                row["raw_truncated"] = True
            else:
                row["raw_truncated"] = False
            bounded.append(row)

        return _ok_result(
            {
                "tool": "sentinelforge_get_alert_evidence",
                "detection_id": detection_id,
                "pagination": {"limit": pagination.limit, "offset": pagination.offset},
                "returned": len(bounded),
                "evidence": bounded,
            }
        )

    def _search_events(self, args: dict[str, Any]) -> CallToolResult:
        try:
            limit = int(args.get("limit", 50))
            offset = int(args.get("offset", 0))
            pagination = Pagination(limit=limit, offset=offset)
        except (ValueError, TypeError) as exc:
            return _error_result("bad_input", f"Invalid limit/offset: {exc}")

        time_range = None
        if args.get("start_time") or args.get("end_time"):
            try:
                time_range = TimeRange(
                    start=args.get("start_time"),
                    end=args.get("end_time"),
                )
            except ReadOnlyDatabaseError as exc:
                return _error_result(exc.code, exc.message, exc.remediation)

        try:
            with ReadOnlyDatabase(self.db_path) as db:
                events = db.search_events(
                    pagination=pagination,
                    query=args.get("query"),
                    host=args.get("host"),
                    event_type=args.get("event_type"),
                    source=args.get("source"),
                    user=args.get("user"),
                    time_range=time_range,
                )
        except ReadOnlyDatabaseError as exc:
            return _error_result(exc.code, exc.message, exc.remediation)

        return _ok_result(
            {
                "tool": "sentinelforge_search_events",
                "search_scope": "events",
                "filters_applied": {
                    "query": args.get("query"),
                    "host": args.get("host"),
                    "event_type": args.get("event_type"),
                    "source": args.get("source"),
                    "user": args.get("user"),
                    "start_time": args.get("start_time"),
                    "end_time": args.get("end_time"),
                },
                "pagination": {"limit": pagination.limit, "offset": pagination.offset},
                "returned": len(events),
                "events": events,
            }
        )

    def _build_investigation_brief(self, args: dict[str, Any]) -> CallToolResult:
        host = args.get("host")
        alert_id = args.get("alert_id")
        try:
            limit = int(args.get("limit", 100))
        except (ValueError, TypeError) as exc:
            return _error_result("bad_input", f"Invalid limit: {exc}")

        if not host and not alert_id:
            return _error_result(
                "bad_input",
                "Provide either host or alert_id to scope the investigation.",
                "Specify host and/or alert_id.",
            )

        if host and not isinstance(host, str):
            return _error_result("bad_input", "host must be a string")
        if alert_id and not isinstance(alert_id, str):
            return _error_result("bad_input", "alert_id must be a string")

        try:
            with ReadOnlyDatabase(self.db_path) as db:
                # --- Scope validation: mixed-host prevention ---
                # If both host and alert_id are supplied, retrieve the alert
                # and verify its host matches the requested host.
                requested_host = host
                scope_conflict = None
                if alert_id and requested_host:
                    alert = db.get_alert(alert_id)
                    if alert is None:
                        return _error_result(
                            "not_found",
                            f"No alert with detection_id={alert_id}",
                            "Verify the detection ID and try again.",
                        )
                    alert_host = alert.get("host")
                    if alert_host is None:
                        scope_conflict = (
                            f"Alert {alert_id} has no host recorded; cannot "
                            "establish a host relationship with "
                            f"requested host={requested_host}."
                        )
                    elif alert_host != requested_host:
                        scope_conflict = (
                            f"Alert {alert_id} belongs to host={alert_host}, "
                            f"which does not match requested host="
                            f"{requested_host}."
                        )
                if scope_conflict:
                    return _error_result(
                        "scope_conflict",
                        scope_conflict,
                        "Supply a single host scope, or omit host to "
                        "investigate the alert independently.",
                    )

                # Gather alerts in scope.
                alerts: list[dict[str, Any]] = []
                if alert_id:
                    alert = db.get_alert(alert_id)
                    if alert:
                        alerts.append(alert)
                        requested_host = requested_host or alert.get("host")
                if requested_host:
                    alerts.extend(
                        db.list_alerts(
                            pagination=Pagination(limit=limit, offset=0),
                            host=requested_host,
                        )
                    )

                # Deduplicate by detection_id.
                seen: set[str] = set()
                unique_alerts = []
                for a in alerts:
                    did = a["detection_id"]
                    if did not in seen:
                        seen.add(did)
                        unique_alerts.append(a)

                # Gather events in scope (by host if available).
                events: list[dict[str, Any]] = []
                if requested_host:
                    events = db.search_events(
                        pagination=Pagination(limit=limit, offset=0),
                        host=requested_host,
                    )

                # --- Detection correlation using DetectionCorrelator ---
                # Convert database alert rows into DetectionResult objects
                # only when all required data is available.
                correlator = DetectionCorrelator(
                    window_seconds=86_400  # 24-hour default window
                )
                convertible: list[DetectionResult] = []
                uncorrelatable: list[dict[str, str]] = []  # missing host/ts

                for a in unique_alerts:
                    did = a["detection_id"]
                    rule_id = a.get("rule_id") or ""
                    rule_name = a.get("rule_name") or ""
                    severity_raw = a.get("severity") or "info"
                    description = a.get("description") or ""
                    triggered_at = a.get("triggered_at")
                    alert_host = a.get("host")
                    metadata_raw = a.get("metadata")
                    metadata = {}
                    if isinstance(metadata_raw, str):
                        try:
                            metadata = json.loads(metadata_raw)
                        except json.JSONDecodeError:
                            metadata = {}
                    elif isinstance(metadata_raw, dict):
                        metadata = metadata_raw

                    # Build evidence list from evidence references (IDs only,
                    # no raw payloads — correlation does not need raw content).
                    evidence_refs: list[dict[str, Any]] = []
                    try:
                        ev_rows = db.get_alert_evidence(
                            did, Pagination(limit=500, offset=0)
                        )
                        for r in ev_rows:
                            evidence_refs.append(
                                {
                                    "event_id": r.get("event_id"),
                                    "timestamp": r.get("timestamp"),
                                    "source": r.get("source"),
                                    "event_type": r.get("event_type"),
                                    "host": r.get("host"),
                                }
                            )
                    except ReadOnlyDatabaseError:
                        pass

                    # A detection can only be correlated if it has a host and
                    # a valid timestamp. Otherwise report it as unknown.
                    if not alert_host:
                        uncorrelatable.append(
                            {
                                "detection_id": did,
                                "reason": "missing_host",
                                "detail": "No host recorded for this detection.",
                            }
                        )
                        continue
                    if not triggered_at:
                        uncorrelatable.append(
                            {
                                "detection_id": did,
                                "reason": "missing_timestamp",
                                "detail": "No triggered_at recorded for this detection.",
                            }
                        )
                        continue

                    # Validate timestamp is parseable and timezone-aware.
                    ts_text = triggered_at.strip()
                    if ts_text.endswith("Z"):
                        ts_text = ts_text[:-1] + "+00:00"
                    try:
                        ts = datetime.fromisoformat(ts_text)
                    except ValueError:
                        uncorrelatable.append(
                            {
                                "detection_id": did,
                                "reason": "invalid_timestamp",
                                "detail": f"Unable to parse triggered_at={triggered_at}.",
                            }
                        )
                        continue
                    if ts.tzinfo is None:
                        ts = ts.replace(tzinfo=UTC)

                    sev = Severity.INFO
                    try:
                        sev = Severity(severity_raw.lower())
                    except ValueError:
                        sev = Severity.INFO

                    evidence = [
                        Evidence(
                            event_id=e.get("event_id") or "",
                            timestamp=e.get("timestamp") or "",
                            source=e.get("source") or "",
                            event_type=e.get("event_type"),
                            user=e.get("user"),
                            host=e.get("host"),
                            source_address=e.get("source_address"),
                            raw={},  # raw payloads not needed for correlation
                        )
                        for e in evidence_refs
                    ]

                    convertible.append(
                        DetectionResult(
                            rule_id=rule_id,
                            rule_name=rule_name,
                            severity=sev,
                            description=description,
                            evidence=evidence,
                            triggered_at=triggered_at,
                            metadata=metadata,
                            detection_id=did,
                        )
                    )

                # Run the correlator only on convertible detections.
                clusters = correlator.correlate(convertible)

                # Classify clusters: same-host vs correlated-within-window.
                same_host_groups: dict[str | None, list[str]] = {}
                correlated_clusters: list[dict[str, Any]] = []
                for cluster in clusters:
                    host_key = cluster.host
                    ids = cluster.detection_ids
                    same_host_groups.setdefault(host_key, []).extend(ids)
                    if len(ids) > 1 and cluster.first_triggered is not None:
                        span_seconds: float = 0.0
                        if cluster.last_triggered is not None:
                            span_seconds = (
                                cluster.last_triggered - cluster.first_triggered
                            ).total_seconds()
                        correlated_clusters.append(
                            {
                                "host": host_key,
                                "detection_ids": ids,
                                "rule_ids": sorted(cluster.rule_ids),
                                "first_triggered": (
                                    cluster.first_triggered.isoformat()
                                    if cluster.first_triggered
                                    else None
                                ),
                                "last_triggered": (
                                    cluster.last_triggered.isoformat()
                                    if cluster.last_triggered
                                    else None
                                ),
                                "span_seconds": span_seconds,
                                "within_configured_window": span_seconds
                                <= correlator.window_seconds,
                                "basis": (
                                    "Same-host detections within the "
                                    f"{correlator.window_seconds}s "
                                    "configured correlation window."
                                ),
                            }
                        )

                # Same-host groups that did NOT form a multi-detection
                # time-window cluster (single detection or out-of-window).
                same_host_only: list[dict[str, Any]] = []
                for hkey, ids in same_host_groups.items():
                    clustered_ids = {
                        did for c in correlated_clusters for did in c["detection_ids"]
                    }
                    unclustered = [did for did in ids if did not in clustered_ids]
                    if unclustered:
                        same_host_only.append(
                            {
                                "host": hkey,
                                "detection_ids": unclustered,
                                "basis": (
                                    "Same host, but not within the "
                                    "configured correlation time window "
                                    "(or a single detection)."
                                ),
                            }
                        )

                # Build timeline: merge alerts and events by timestamp.
                timeline_entries: list[dict[str, Any]] = []
                for a in unique_alerts:
                    timeline_entries.append(
                        {
                            "type": "alert",
                            "id": a["detection_id"],
                            "timestamp": a.get("triggered_at"),
                            "rule_id": a.get("rule_id"),
                            "rule_name": a.get("rule_name"),
                            "severity": a.get("severity"),
                            "host": a.get("host"),
                            "description": a.get("description"),
                            "basis": "Detection fired by SentinelForge detection engine",
                        }
                    )
                for e in events:
                    timeline_entries.append(
                        {
                            "type": "event",
                            "id": e.get("event_id"),
                            "timestamp": e.get("timestamp"),
                            "event_type": e.get("event_type"),
                            "source": e.get("source"),
                            "host": e.get("host"),
                            "user": e.get("user"),
                            "process_name": e.get("process_name"),
                            "network_remote_address": e.get("network_remote_address"),
                            "basis": "Normalized log event from ingestion pipeline",
                        }
                    )

                timeline_entries.sort(
                    key=lambda x: (
                        x.get("timestamp") or "",
                        x.get("type", ""),
                        x.get("id", ""),
                    )
                )

                # Identify unknowns.
                unknowns: list[str] = []
                if requested_host:
                    hosts_with_data = {
                        a.get("host") for a in unique_alerts if a.get("host")
                    }
                    hosts_with_data.update(
                        {e.get("host") for e in events if e.get("host")}
                    )
                    if requested_host not in hosts_with_data:
                        unknowns.append(f"No records found for host={requested_host}")
                if alert_id and not any(
                    a["detection_id"] == alert_id for a in unique_alerts
                ):
                    unknowns.append(f"No alert found for detection_id={alert_id}")
                for u in uncorrelatable:
                    unknowns.append(
                        f"Detection {u['detection_id']} cannot be correlated: "
                        f"{u['detail']}"
                    )

                # ATT&CK mapping — only from detection metadata.
                attack_techniques: list[str] = []
                for a in unique_alerts:
                    metadata_raw = a.get("metadata")
                    if isinstance(metadata_raw, str):
                        try:
                            metadata = json.loads(metadata_raw)
                        except json.JSONDecodeError:
                            metadata = {}
                    elif isinstance(metadata_raw, dict):
                        metadata = metadata_raw
                    else:
                        metadata = {}
                    attack = metadata.get("attack_technique") or metadata.get("attack")
                    if isinstance(attack, str):
                        attack_techniques.append(attack)
                    elif isinstance(attack, list):
                        attack_techniques.extend(attack)

                confirmed: list[str] = []
                derivations: list[str] = []
                hypotheses: list[str] = []

                for a in unique_alerts:
                    confirmed.append(
                        f"Alert {a['detection_id']}: rule '{a['rule_name']}' "
                        f"(severity {a.get('severity')}) fired on "
                        f"{a.get('host') or 'unknown host'} at "
                        f"{a.get('triggered_at') or 'unknown time'}."
                    )

                # Derived findings: separate same-host from time-window
                # correlation; never claim causation.
                if correlated_clusters:
                    derivations.append(
                        f"{len(correlated_clusters)} host-scoped cluster(s) of "
                        "detections fall within the configured correlation "
                        "time window. Host/time proximity alone does not "
                        "imply causation or an attack chain."
                    )
                if same_host_only:
                    derivations.append(
                        f"{len(same_host_only)} same-host grouping(s) of "
                        "detection(s) fall outside the configured correlation "
                        "window (or are single detections)."
                    )
                if events:
                    derivations.append(
                        f"{len(events)} event(s) found in the investigation "
                        "scope, providing raw log context for the detections."
                    )

                if not confirmed and not unknowns:
                    hypotheses.append(
                        "No detections or events match the investigation "
                        "scope. This may mean no activity occurred, or the "
                        "data has not been ingested."
                    )

        except ReadOnlyDatabaseError as exc:
            return _error_result(exc.code, exc.message, exc.remediation)

        return _ok_result(
            {
                "tool": "sentinelforge_build_investigation_brief",
                "scope": {"host": requested_host, "alert_id": alert_id},
                "confirmed_observations": confirmed,
                "derived_findings": derivations,
                "ai_hypotheses": hypotheses,
                "unknowns_and_limitations": unknowns,
                "attack_technique_mapping": sorted(set(attack_techniques)) or None,
                "correlation": {
                    "window_seconds": correlator.window_seconds,
                    "correlated_clusters": correlated_clusters,
                    "same_host_only": same_host_only,
                    "uncorrelatable": uncorrelatable,
                },
                "timeline": timeline_entries[:limit],
                "timeline_returned": len(timeline_entries[:limit]),
                "timeline_total": len(timeline_entries),
                "evidence_references": {
                    "alert_ids": [a["detection_id"] for a in unique_alerts],
                    "event_ids": [
                        e.get("event_id") for e in events if e.get("event_id")
                    ],
                },
            }
        )

    def _list_risk_assessments(self, args: dict[str, Any]) -> CallToolResult:
        try:
            limit = int(args.get("limit", 50))
            offset = int(args.get("offset", 0))
            pagination = Pagination(limit=limit, offset=offset)
        except (ValueError, TypeError) as exc:
            return _error_result("bad_input", f"Invalid limit/offset: {exc}")

        try:
            with ReadOnlyDatabase(self.db_path) as db:
                assessments = db.list_risk_assessments(
                    pagination=pagination,
                    host=args.get("host"),
                    min_score=args.get("min_score"),
                )
        except ReadOnlyDatabaseError as exc:
            return _error_result(exc.code, exc.message, exc.remediation)

        return _ok_result(
            {
                "tool": "sentinelforge_list_risk_assessments",
                "filters_applied": {
                    "host": args.get("host"),
                    "min_score": args.get("min_score"),
                },
                "pagination": {"limit": pagination.limit, "offset": pagination.offset},
                "returned": len(assessments),
                "risk_assessments": assessments,
            }
        )

    async def run(self) -> None:
        async with stdio_server() as (read_stream, write_stream):
            await self.server.run(
                read_stream,
                write_stream,
                InitializationOptions(
                    server_name=SERVER_NAME,
                    server_version=SERVER_VERSION,
                    capabilities=ServerCapabilities(tools=ToolsCapability()),
                ),
            )


def main() -> None:
    """Entry point for the sentinelforge-mcp console script."""
    import os

    if not _MCP_AVAILABLE:
        print(
            "ERROR: The MCP SDK is not installed. "
            "Install SentinelForge with the analyst-mcp extra:\n"
            "  pip install sentinelforge[analyst-mcp]",
            file=sys.stderr,
        )
        sys.exit(1)

    db_path = os.environ.get("SENTINELFORGE_DB_PATH", "data/sentinelforge.db")
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        stream=sys.stderr,
    )
    server = AnalystMCPServer(db_path)
    asyncio.run(server.run())


if __name__ == "__main__":
    main()
