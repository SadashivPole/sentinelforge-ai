"""SentinelForge local dashboard HTTP server.

Binds to 127.0.0.1 only. Serves a read-only dashboard backed by the
SQLite database used by the CLI. No state-changing endpoints.
"""

from __future__ import annotations

import json
import os
import re
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, ClassVar
from urllib.parse import parse_qs, urlparse

from sentinelforge.config import settings
from sentinelforge.dashboard.queries import (
    connect,
    count_alerts,
    count_detections,
    count_events,
    get_attacks_coverage,
    get_event_detail,
    get_system_diagnostics,
    list_alerts,
    list_detection_rules,
    list_events,
)
from sentinelforge.dashboard.views import (
    render_alerts,
    render_attacks,
    render_diagnostics,
    render_error,
    render_event_detail,
    render_events,
    render_not_found,
    render_overview,
    render_rules,
)

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8080


def _int_param(params: dict[str, list[str]], name: str, default: int) -> int:
    values = params.get(name)
    if not values:
        return default
    try:
        return max(0, int(values[0]))
    except (ValueError, TypeError):
        return default


def _str_param(params: dict[str, list[str]], name: str) -> str | None:
    values = params.get(name)
    if not values or not values[0].strip():
        return None
    return values[0].strip()


class DashboardHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the local dashboard."""

    ROUTES: ClassVar[list[tuple[re.Pattern[str], str]]] = [
        (re.compile(r"^/$"), "overview"),
        (re.compile(r"^/overview$"), "overview"),
        (re.compile(r"^/alerts$"), "alerts"),
        (re.compile(r"^/events$"), "events"),
        (re.compile(r"^/rules$"), "rules"),
        (re.compile(r"^/attacks$"), "attacks"),
        (re.compile(r"^/event/(?P<capture>.+)$"), "event_detail"),
        (re.compile(r"^/diagnostics$"), "diagnostics"),
        (re.compile(r"^/static/css/(?P<capture>.+)$"), "static_css"),
        (re.compile(r"^/static/js/(?P<capture>.+)$"), "static_js"),
    ]

    db_path: str = settings.db_path

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _send_html(self, content: str, status: int = 200) -> None:
        body = content.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, data: Any, status: int = 200) -> None:
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _route(self, path: str) -> tuple[str, dict[str, str]] | None:
        parsed = urlparse(path)
        for pattern, handler_name in self.ROUTES:
            m = pattern.match(parsed.path)
            if m:
                capture = ""
                if m.re.groups > 0:
                    try:
                        capture = m.group("capture")
                    except IndexError:
                        capture = m.group(1) or ""
                return handler_name, {"capture": capture}
        return None

    def do_GET(self) -> None:
        route = self._route(self.path)
        if not route:
            self._send_html(render_not_found(), 404)
            return

        handler_name, captures = route
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        try:
            conn = connect(self.db_path)
            try:
                if handler_name == "overview":
                    self._handle_overview(conn)
                elif handler_name == "alerts":
                    self._handle_alerts(conn, params)
                elif handler_name == "events":
                    self._handle_events(conn, params)
                elif handler_name == "rules":
                    self._handle_rules(conn)
                elif handler_name == "attacks":
                    self._handle_attacks(conn)
                elif handler_name == "event_detail":
                    event_id = captures.get("capture", "")
                    self._handle_event_detail(conn, event_id)
                elif handler_name == "diagnostics":
                    self._handle_diagnostics(conn)
                elif handler_name == "static_css":
                    self._serve_static(captures.get("capture", ""), "text/css")
                elif handler_name == "static_js":
                    self._serve_static(
                        captures.get("capture", ""), "application/javascript"
                    )
            finally:
                conn.close()
        except Exception as exc:  # noqa: BLE001
            self._send_html(render_error(str(exc)), 500)

    def _serve_static(self, path: str, content_type: str) -> None:
        safe_name = os.path.basename(path)
        if not safe_name:
            self._send_html(render_not_found(), 404)
            return

        static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
        file_path = os.path.join(static_dir, safe_name)

        try:
            with open(file_path, "rb") as f:
                body = f.read()
            self.send_response(200)
            self.send_header("Content-Type", f"{content_type}; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)
        except FileNotFoundError:
            self._send_html(render_not_found(), 404)

    def _handle_overview(self, conn) -> None:
        data = {
            "total_events": count_events(conn),
            "total_detections": count_detections(conn),
            "total_alerts": count_alerts(conn),
        }
        self._send_html(render_overview(data))

    def _handle_alerts(self, conn, params: dict[str, list[str]]) -> None:
        rule = _str_param(params, "rule")
        search = _str_param(params, "search")
        limit = _int_param(params, "limit", 50)
        offset = _int_param(params, "offset", 0)
        alerts = list_alerts(conn, rule=rule, search=search, limit=limit, offset=offset)
        rules = list_detection_rules(conn)
        self._send_html(
            render_alerts(
                alerts, rules, rule=rule, search=search, limit=limit, offset=offset
            )
        )

    def _handle_events(self, conn, params: dict[str, list[str]]) -> None:
        event_type = _str_param(params, "event_type")
        search = _str_param(params, "search")
        rule = _str_param(params, "rule")
        limit = _int_param(params, "limit", 50)
        offset = _int_param(params, "offset", 0)
        events = list_events(
            conn,
            event_type=event_type,
            search=search,
            rule=rule,
            limit=limit,
            offset=offset,
        )
        self._send_html(
            render_events(
                events,
                event_type=event_type,
                search=search,
                rule=rule,
                limit=limit,
                offset=offset,
            )
        )

    def _handle_rules(self, conn) -> None:
        rules = list_detection_rules(conn)
        self._send_html(render_rules(rules))

    def _handle_attacks(self, conn) -> None:
        coverage = get_attacks_coverage(conn)
        self._send_html(render_attacks(coverage))

    def _handle_event_detail(self, conn, event_id: str) -> None:
        detail = get_event_detail(conn, event_id)
        if not detail:
            self._send_html(render_not_found(), 404)
            return
        self._send_html(render_event_detail(detail))

    def _handle_diagnostics(self, conn) -> None:
        diag = get_system_diagnostics(conn)
        self._send_html(render_diagnostics(diag))


def run(
    host: str = DEFAULT_HOST, port: int = DEFAULT_PORT, db_path: str = settings.db_path
) -> None:
    """Start the dashboard HTTP server.

    Binds to 127.0.0.1 by default. Never binds to 0.0.0.0.
    """
    DashboardHandler.db_path = db_path
    server = HTTPServer((host, port), DashboardHandler)
    print(f"SentinelForge dashboard listening on http://{host}:{port}")
    print("Bind address: 127.0.0.1 only (localhost)")
    print("Press Ctrl+C to stop")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down dashboard...")
        server.shutdown()
        server.server_close()


def main() -> None:
    """CLI entry point for the dashboard."""
    import argparse

    parser = argparse.ArgumentParser(
        prog="sentinelforge dashboard",
        description="Run the local SentinelForge SOC dashboard (localhost only).",
    )
    parser.add_argument(
        "--host",
        default=DEFAULT_HOST,
        help=f"Host to bind to (default: {DEFAULT_HOST})",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help=f"Port to bind to (default: {DEFAULT_PORT})",
    )
    parser.add_argument(
        "--db-path",
        default=settings.db_path,
        help=f"Path to SQLite database (default: {settings.db_path})",
    )
    args = parser.parse_args()

    if args.host not in ("127.0.0.1", "localhost"):
        print(
            f"Warning: binding to {args.host} exposes the dashboard beyond localhost."
        )
        print("For safety, use 127.0.0.1 (default).")

    run(host=args.host, port=args.port, db_path=args.db_path)


if __name__ == "__main__":
    main()
