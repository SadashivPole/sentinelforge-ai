"""SentinelForge local dashboard — HTML view generators."""

from __future__ import annotations

from typing import Any

_NAV_LINKS = [
    ("Overview", "/overview"),
    ("Alerts", "/alerts"),
    ("Events", "/events"),
    ("Rules", "/rules"),
    ("ATT&CK", "/attacks"),
    ("Diagnostics", "/diagnostics"),
]


def _nav() -> str:
    links = "".join(
        f'<a href="{url}">{name}</a>' for name, url in _NAV_LINKS
    )
    return f'<nav class="dashboard-nav">{links}</nav>'


def _page(title: str, body: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{title} — SentinelForge Dashboard</title>
  <link rel="stylesheet" href="/static/css/dashboard.css">
</head>
<body>
  <header class="dashboard-header">
    <div class="container">
      <div class="dashboard-logo">Sentinel<span>Forge</span></div>
      {_nav()}
      <div class="dashboard-badge">Localhost only</div>
    </div>
  </header>
  <main class="container">
    {body}
  </main>
  <footer class="dashboard-footer">
    <div class="container">
      <p>SentinelForge local dashboard · Read-only · Binds to 127.0.0.1</p>
    </div>
  </footer>
</body>
</html>"""


def _table(headers, rows) -> str:
    header_row = "".join(f"<th>{h}</th>" for h in headers)
    body_rows = ""
    for row in rows:
        body_rows += "<tr>" + "".join(f"<td>{c}</td>" for c in row) + "</tr>"
    return f"""
    <table class="dashboard-table">
      <thead><tr>{header_row}</tr></thead>
      <tbody>{body_rows}</tbody>
    </table>"""


def render_overview(data: dict[str, Any]) -> str:
    body = f"""
    <h1>SOC Overview</h1>
    <div class="dashboard-grid">
      <div class="dashboard-card">
        <h3>Total Events</h3>
        <div class="dashboard-metric">{data.get('total_events', 0):,}</div>
      </div>
      <div class="dashboard-card">
        <h3>Total Detections</h3>
        <div class="dashboard-metric">{data.get('total_detections', 0):,}</div>
      </div>
      <div class="dashboard-card">
        <h3>Total Alerts</h3>
        <div class="dashboard-metric">{data.get('total_alerts', 0):,}</div>
      </div>
    </div>
    <div class="dashboard-callout">
      <p>This is a local, read-only dashboard backed by the SQLite database
      used by the SentinelForge CLI. All data originates from the detection
      engine — nothing is fabricated.</p>
    </div>
    """
    return _page("Overview", _nav() + body)


def render_alerts(alerts, rules, *, rule=None, search=None, limit=50, offset=0) -> str:
    filter_chips = ""
    if rule:
        filter_chips += f'<span class="dashboard-chip">Rule: {rule}</span> '
    if search:
        filter_chips += f'<span class="dashboard-chip">Search: {search}</span> '

    headers = ["Rule", "Events", "Hosts", "First Seen", "Last Seen"]
    rows = []
    for a in alerts:
        rows.append([
            a.get("rule_id", "—"),
            str(a.get("event_count", 0)),
            str(a.get("host_count", 0)),
            a.get("first_seen", "—"),
            a.get("last_seen", "—"),
        ])

    body = f"""
    <h1>Alert Explorer</h1>
    {filter_chips}
    <p>Alerts are grouped detections by rule.</p>
    {_table(headers, rows)}
    """
    return _page("Alerts", _nav() + body)


def render_events(events, *, event_type=None, search=None, rule=None, limit=50, offset=0) -> str:
    filter_chips = ""
    if event_type:
        filter_chips += f'<span class="dashboard-chip">Type: {event_type}</span> '
    if search:
        filter_chips += f'<span class="dashboard-chip">Search: {search}</span> '
    if rule:
        filter_chips += f'<span class="dashboard-chip">Rule: {rule}</span> '

    headers = ["Time", "Type", "Source", "Target", "User", "Detection Rule", "Raw Log"]
    rows = []
    for e in events:
        raw = e.get("raw_log", "")
        if len(raw) > 80:
            raw = raw[:77] + "..."
        rows.append([
            e.get("timestamp", "—"),
            e.get("event_type", "—"),
            e.get("source_address", "—"),
            e.get("target_address", "—"),
            e.get("user", "—"),
            e.get("detection_rule", "—"),
            raw,
        ])

    body = f"""
    <h1>Event Explorer</h1>
    {filter_chips}
    <p>Events are normalized log entries with raw log preserved verbatim.</p>
    {_table(headers, rows)}
    """
    return _page("Events", _nav() + body)


def render_rules(rules) -> str:
    headers = ["Rule", "Detections", "Hosts", "Last Seen"]
    rows = []
    for r in rules:
        rows.append([
            r.get("rule_id", "—"),
            str(r.get("detection_count", 0)),
            str(r.get("host_count", 0)),
            r.get("last_seen", "—"),
        ])

    body = f"""
    <h1>Detection Rule Inventory</h1>
    <p>Detection rules and their activity across the stored dataset.</p>
    {_table(headers, rows)}
    """
    return _page("Rules", _nav() + body)


def render_attacks(coverage) -> str:
    headers = ["Rule (Detection)", "Detections", "Hosts"]
    rows = []
    for c in coverage:
        rows.append([
            c.get("rule_id", "—"),
            str(c.get("detection_count", 0)),
            str(c.get("host_count", 0)),
        ])

    body = f"""
    <h1>ATT&CK Coverage</h1>
    <p>Detection coverage organized by detection rule.</p>
    {_table(headers, rows)}
    """
    return _page("ATT&CK Coverage", _nav() + body)


def render_event_detail(detail) -> str:
    detections = detail.get("detections", [])
    det_rows = []
    for d in detections:
        det_rows.append([
            d.get("rule_id", "—"),
            d.get("detection_timestamp", "—"),
            str(d.get("confidence", "—")),
            str(d.get("risk_score", "—")),
        ])

    body = f"""
    <h1>Event Detail</h1>
    <table class="dashboard-table">
      <tr><th>Event ID</th><td>{detail.get('event_id', '—')}</td></tr>
      <tr><th>Timestamp</th><td>{detail.get('timestamp', '—')}</td></tr>
      <tr><th>Type</th><td>{detail.get('event_type', '—')}</td></tr>
      <tr><th>Source</th><td>{detail.get('source_address', '—')}</td></tr>
      <tr><th>Target</th><td>{detail.get('target_address', '—')}</td></tr>
      <tr><th>User</th><td>{detail.get('user', '—')}</td></tr>
      <tr><th>Source File</th><td>{detail.get('source_file', '—')}</td></tr>
      <tr><th>Position</th><td>{detail.get('position', '—')}</td></tr>
    </table>
    <h3>Raw Log</h3>
    <pre class="dashboard-rawlog">{detail.get('raw_log', '')}</pre>
    <h3>Detections ({len(detections)})</h3>
    {_table(['Rule', 'Detected At', 'Confidence', 'Risk Score'], det_rows) if det_rows else '<p>No detections associated with this event.</p>'}
    """
    return _page("Event Detail", _nav() + body)


def render_diagnostics(diag) -> str:
    body = f"""
    <h1>System Diagnostics</h1>
    <table class="dashboard-table">
      <tr><th>Total Events</th><td>{diag.get('total_events', 0):,}</td></tr>
      <tr><th>Total Detections</th><td>{diag.get('total_detections', 0):,}</td></tr>
      <tr><th>Database File</th><td>{diag.get('database_file', 'unknown')}</td></tr>
      <tr><th>Tables</th><td>{', '.join(diag.get('tables', [])) or 'none'}</td></tr>
    </table>
    """
    return _page("Diagnostics", _nav() + body)


def render_not_found() -> str:
    body = """
    <h1>Not Found</h1>
    <p>The requested page was not found in the local dashboard.</p>
    <p><a href="/overview">Return to Overview</a></p>
    """
    return _page("Not Found", _nav() + body)


def render_error(message: str) -> str:
    safe = message.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    body = f"""
    <h1>Error</h1>
    <p>{safe}</p>
    <p><a href="/overview">Return to Overview</a></p>
    """
    return _page("Error", _nav() + body)


DASHBOARD_CSS = """
/* SentinelForge Local Dashboard Styles */
* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  background: #0B1220;
  color: #E8F0FA;
  font-size: 16px;
  line-height: 1.6;
}
.dashboard-header {
  background: #17263C;
  border-bottom: 1px solid rgba(232,240,250,0.1);
  padding: 0 1rem;
  position: sticky;
  top: 0;
  z-index: 50;
}
.dashboard-header .container {
  display: flex;
  align-items: center;
  justify-content: space-between;
  height: 56px;
  max-width: 1200px;
  margin: 0 auto;
}
.dashboard-logo {
  font-size: 1.25rem;
  font-weight: 700;
  color: #E8F0FA;
}
.dashboard-logo span { color: #35D6C3; }
.dashboard-nav a {
  color: #9FB0C4;
  text-decoration: none;
  margin-left: 1.5rem;
  font-size: 0.9375rem;
}
.dashboard-nav a:hover { color: #35D6C3; }
.dashboard-badge {
  background: rgba(53,214,195,0.15);
  color: #35D6C3;
  padding: 2px 8px;
  border-radius: 999px;
  font-size: 0.75rem;
  font-weight: 600;
}
.container { max-width: 1200px; margin: 0 auto; padding: 1.5rem; }
h1 { font-size: 1.75rem; font-weight: 700; margin: 0 0 1rem 0; }
h3 { font-size: 1.125rem; font-weight: 600; margin: 1rem 0 0.5rem 0; }
p { color: #9FB0C4; }
.dashboard-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 1rem;
  margin-bottom: 2rem;
}
.dashboard-card {
  background: #17263C;
  border: 1px solid rgba(232,240,250,0.1);
  border-radius: 8px;
  padding: 1.5rem;
}
.dashboard-card h3 { margin: 0 0 0.5rem 0; font-size: 0.875rem; color: #9FB0C4; text-transform: uppercase; letter-spacing: 0.5px; }
.dashboard-metric { font-size: 2rem; font-weight: 700; color: #E8F0FA; }
.dashboard-callout {
  background: rgba(23,38,60,0.5);
  border: 1px solid rgba(232,240,250,0.1);
  border-radius: 8px;
  padding: 1rem;
  margin: 1.5rem 0;
}
.dashboard-callout p { margin: 0; color: #9FB0C4; font-size: 0.9375rem; }
.dashboard-table {
  width: 100%;
  border-collapse: collapse;
  background: #17263C;
  border: 1px solid rgba(232,240,250,0.1);
  border-radius: 8px;
  overflow: hidden;
  margin-bottom: 1.5rem;
}
.dashboard-table th, .dashboard-table td {
  padding: 0.75rem 1rem;
  text-align: left;
  border-bottom: 1px solid rgba(232,240,250,0.05);
}
.dashboard-table th {
  background: rgba(23,38,60,0.5);
  font-weight: 600;
  font-size: 0.8125rem;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  color: #9FB0C4;
}
.dashboard-table tr:hover { background: rgba(53,214,195,0.05); }
.dashboard-rawlog {
  background: #0a0f1a;
  border: 1px solid rgba(232,240,250,0.1);
  border-radius: 6px;
  padding: 1rem;
  font-family: 'SF Mono', Monaco, 'Cascadia Code', monospace;
  font-size: 0.8125rem;
  color: #9FB0C4;
  overflow-x: auto;
  max-height: 300px;
  overflow-y: auto;
}
.dashboard-chip {
  display: inline-block;
  background: rgba(53,214,195,0.15);
  color: #35D6C3;
  padding: 2px 8px;
  border-radius: 999px;
  font-size: 0.75rem;
  font-weight: 600;
  margin-right: 0.5rem;
}
.btn {
  display: inline-flex;
  align-items: center;
  gap: 0.25rem;
  padding: 0.5rem 1rem;
  font-size: 0.9375rem;
  font-weight: 600;
  border-radius: 4px;
  border: none;
  cursor: pointer;
  text-decoration: none;
}
.btn-secondary {
  background: #17263C;
  color: #E8F0FA;
  border: 1px solid rgba(232,240,250,0.1);
}
.btn-secondary:hover { background: #1f334f; }
.btn:disabled { opacity: 0.5; cursor: not-allowed; }
.dashboard-pager {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  margin-top: 1rem;
  color: #9FB0C4;
  font-size: 0.9375rem;
}
.dashboard-footer {
  border-top: 1px solid rgba(232,240,250,0.1);
  padding: 1rem 0;
  margin-top: 2rem;
  color: #6B80A0;
  font-size: 0.875rem;
}
.dashboard-footer .container {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
@media (max-width: 768px) {
  .dashboard-header .container { flex-direction: column; height: auto; padding: 1rem 0; gap: 1rem; }
  .dashboard-nav a { margin: 0.5rem 0; }
  .container { padding: 1rem; }
}
"""


def render_static_css() -> str:
    return DASHBOARD_CSS


DASHBOARD_JS = """
// SentinelForge Local Dashboard — client-side enhancements
document.addEventListener('DOMContentLoaded', () => {
  const currentPath = window.location.pathname;
  document.querySelectorAll('.dashboard-nav a').forEach(link => {
    if (link.getAttribute('href') === currentPath) {
      link.style.color = '#35D6C3';
      link.style.fontWeight = '600';
    }
  });
  console.log('SentinelForge dashboard loaded — read-only, localhost-only');
});
"""


def render_static_js() -> str:
    return DASHBOARD_JS
