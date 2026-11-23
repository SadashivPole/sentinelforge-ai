# SentinelForge AI — Security Threat Model

**Branch:** feature/sentinelforge-public-platform
**Base commit:** 58534f3 (M10 remediation merge)
**Status:** Planning

## Scope

Covers the public website, public interactive demo, and local SOC dashboard.

## Data Classification

| Classification | Examples | Storage | Network Exposure |
|---------------|----------|---------|------------------|
| Public | Website content, documentation, demo synthetic data | Git repo, GitHub Pages | Public (intentional) |
| Internal | Local SQLite DB, raw logs, detection results, risk scores | Local host filesystem | None (localhost only) |
| Secret | Credentials, API keys, tokens | Never in source; SENTINELFORGE_* env vars | None |

## Key Threats & Mitigations

| Threat | Component | Severity | Mitigation |
|--------|-----------|----------|------------|
| Information disclosure | Local SQLite DB | High | OS-level file permissions; documented limitation |
| Credentials in repo | Source repository | Critical | Pre-commit review; .gitignore; secret scanning in CI |
| Elevation of privilege | Local dashboard | High | 127.0.0.1 only bind; no shell execution; no wildcard CORS |
| Information disclosure | Public demo | High | Synthetic data only; no local data access |

## Security Requirements

- Local dashboard binds to 127.0.0.1 only by default
- No wildcard CORS on local dashboard
- No arbitrary shell execution or filesystem path traversal
- Error messages do not leak raw event data
- No credentials/API keys in source code
- Security checks in CI are blocking gates
- Public demo uses synthetic data only, no local data access
