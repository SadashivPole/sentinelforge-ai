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
from typing import Any

try:
    from mcp.server import Server
    from mcp.server.context import ServerRequestContext
    from mcp.server.models import InitializationOptions
    from mcp.server.stdio import stdio_server
    from mcp.types import (
        CallToolRequest,
        CallToolRequestParams,
        CallToolResult,
        ListToolsRequest,
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

logger = logging.getLogger("sentinelforge.mcp")

SERVER_NAME = "sentinelforge-analyst"
SERVER_VERSION = "0.1.0"

# Maximum raw payload bytes returned by get_alert_evidence to prevent
# oversize responses from a single evidence record.
MAX_EVIDENCE_RAW_BYTES = 65_536


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
        content=[TextContent(type="text", text=json.dumps(payload, indent=2))],
        is_error=False,
    )


class AnalystMCPServer:
    """Wraps the MCP Server with SentinelForge read-only data access."""

    def __init__(self, db_path: str) -> None:
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
            ListToolsRequest,
            handle_list_tools,  # type: ignore[arg-type]
        )
        server.add_request_handler(
            "tools/call",
            CallToolRequest,
            handle_call_tool,  # type: ignore[arg-type]
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
                    "path": self.db_path,
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
        except ReadOnlyDatabaseError as exc:
            return _error_result(exc.code, exc.message, exc.remediation)

        # Add evidence counts without loading raw payloads.
        enriched: list[dict[str, Any]] = []
        for alert in alerts:
            did = alert["detection_id"]
            try:
                with ReadOnlyDatabase(self.db_path) as db2:
                    ev = db2.get_alert_evidence(did, Pagination(limit=1, offset=0))
                alert["evidence_count"] = len(ev)
            except ReadOnlyDatabaseError:
                alert["evidence_count"] = 0
            enriched.append(alert)

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
                "returned": len(enriched),
                "alerts": enriched,
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

        return _ok_result(
            {
                "tool": "sentinelforge_get_alert",
                "alert": alert,
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
                # Gather alerts in scope.
                alerts: list[dict[str, Any]] = []
                if alert_id:
                    alert = db.get_alert(alert_id)
                    if alert:
                        alerts.append(alert)
                        host = host or alert.get("host")
                if host:
                    alerts.extend(
                        db.list_alerts(
                            pagination=Pagination(limit=limit, offset=0),
                            host=host,
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
                if host:
                    events = db.search_events(
                        pagination=Pagination(limit=limit, offset=0),
                        host=host,
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
                if host:
                    hosts_with_data = {
                        a.get("host") for a in unique_alerts if a.get("host")
                    }
                    hosts_with_data.update(
                        {e.get("host") for e in events if e.get("host")}
                    )
                    if host not in hosts_with_data:
                        unknowns.append(f"No records found for host={host}")
                if alert_id and not any(
                    a["detection_id"] == alert_id for a in unique_alerts
                ):
                    unknowns.append(f"No alert found for detection_id={alert_id}")

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
                        f"(severity {a.get('severity')}) fired on {a.get('host') or 'unknown host'} "
                        f"at {a.get('triggered_at') or 'unknown time'}."
                    )

                if unique_alerts:
                    derivations.append(
                        f"{len(unique_alerts)} detection(s) correlate by host/time window "
                        "using SentinelForge DetectionCorrelator logic."
                    )
                if events:
                    derivations.append(
                        f"{len(events)} event(s) found in the investigation scope, "
                        "providing raw log context for the detections."
                    )

                if not confirmed and not unknowns:
                    hypotheses.append(
                        "No detections or events match the investigation scope. "
                        "This may mean no activity occurred, or the data has not been ingested."
                    )

        except ReadOnlyDatabaseError as exc:
            return _error_result(exc.code, exc.message, exc.remediation)

        return _ok_result(
            {
                "tool": "sentinelforge_build_investigation_brief",
                "scope": {"host": host, "alert_id": alert_id},
                "confirmed_observations": confirmed,
                "derived_findings": derivations,
                "ai_hypotheses": hypotheses,
                "unknowns_and_limitations": unknowns,
                "attack_technique_mapping": sorted(set(attack_techniques)) or None,
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
