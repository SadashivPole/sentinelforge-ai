# Security & Privacy

## Security Properties

- **Localhost-only binding:** The local dashboard binds to `127.0.0.1:8080` only — not accessible from other hosts
- **No credentials in source:** All configuration comes from `SENTINELFORGE_*` environment variables
- **SQLite not encrypted at rest:** Restrict database file access at the OS level
- **Public demo uses synthetic data only:** No real logs, no local data access
- **HTTPS is transport security, not E2EE:** GitHub Pages serves over HTTPS, but this is transport-layer security only

## Data Handling

- Raw log payloads are preserved verbatim alongside normalized events
- Original logs are never modified during analysis
- Command strings in logs are inspected as text only — never executed
- No automatic remediation — detection rules surface findings; humans act

## What Is Not Covered

This is a **prototype**, not a production system. The following are NOT implemented:

- Authentication / authorization / RBAC
- Encryption at rest for the SQLite database
- Network encryption / TLS beyond GitHub Pages HTTPS
- Audit logging for administrative actions
- Real-time threat intelligence
- Production deployment hardening

Do not deploy this prototype to production environments or use it with real customer data without first addressing these gaps.

