# SentinelForge SOC Analyst MCP — Architecture

## Overview

The SOC Analyst MCP integration provides read-only, local stdio-only access
to SentinelForge detection data through the Model Context Protocol (MCP).
It is an optional component: SentinelForge functions completely without it.

## Package Layout

```
sentinelforge/analyst/
├── __init__.py        # Package marker
├── database.py        # Enforced read-only SQLite data-access layer
└── mcp_server.py      # MCP server with 7 read-only tools
```

## Components

### ReadOnlyDatabase (`sentinelforge/analyst/database.py`)

Enforces read-only access at the SQLite connection level, independently of
the rest of the codebase:

- **SQLite URI `mode=ro`** — the OS itself rejects file-level writes
- **`PRAGMA query_only = ON`** — SQLite rejects any mutation SQL at the
  connection level, even parameterized DDL/DML
- **Static SQL only** — all query strings are static literals; values are
  parameterized via `?` placeholders
- **Bounded pagination** — `LIMIT` capped at 500, `OFFSET` capped at 10,000
- **Input length validation** — all string inputs checked against maximums
- **Time range validation** — start must precede end; range capped at 365 days
- **Output-size bounds** — evidence raw payloads truncated at 64 KiB
- **Write verification** — `_verify_read_only()` attempts a write on open
  and raises if it succeeds
- **No schema migration** — the MCP connection never runs `migrate()`

### AnalystMCPServer (`sentinelforge/analyst/mcp_server.py`)

MCP SDK v2 server exposing 7 read-only tools over stdio:

1. `sentinelforge_get_status` — schema version, counts, latest timestamps
2. `sentinelforge_list_alerts` — detection alerts with pagination + filters
3. `sentinelforge_get_alert` — single alert by detection ID
4. `sentinelforge_get_alert_evidence` — evidence for an alert (bounded)
5. `sentinelforge_search_events` — event search with disclosed filters
6. `sentinelforge_build_investigation_brief` — deterministic timeline
7. `sentinelforge_list_risk_assessments` — risk assessments with filters

All tools carry MCP annotations:
- `readOnlyHint: true`
- `destructiveHint: false`
- `idempotentHint: true`
- `openWorldHint: false`

Annotations are hints, not a security boundary. Enforcement is at the
database connection level.

### Entry Point

`sentinelforge-mcp` console script → `sentinelforge.analyst.mcp_server:main`

Reads `SENTINELFORGE_DB_PATH` env var (default: `data/sentinelforge.db`),
then runs the MCP server over stdio.

## Data Flow

```
┌─────────────────┐     stdio (JSON-RPC 2.0)     ┌─────────────────────┐
│   MCP Client    │ ───────────────────────────> │  AnalystMCPServer   │
│ (Hermes, etc.)  │ <─────────────────────────── │   (stdio only)      │
└─────────────────┘                              └──────────┬──────────┘
                                                            │ read-only
                                                            │ SQLite URI
                                                            │ mode=ro + query_only
                                                            ▼
                                                    ┌─────────────────────┐
                                                    │  SentinelForge DB   │
                                                    │  (events,          │
                                                    │   detections,       │
                                                    │   evidence,         │
                                                    │   risk_assessments) │
                                                    └─────────────────────┘
```

## Trust Boundaries

| Boundary | Enforcement |
|----------|-------------|
| MCP client → server | stdio only; no network, no HTTP |
| Server → database | `mode=ro` URI + `PRAGMA query_only=ON` |
| Server → filesystem | No filesystem access; database path only |
| Server → network | No outbound network connections |
| Server → shell | No command execution |
| Tools → mutations | No INSERT/UPDATE/DELETE/DDL tools |

## Configuration

Added to `pyproject.toml`:

```toml
[project.optional-dependencies]
analyst-mcp = ["mcp>=1.0,<3.0"]

[project.scripts]
sentinelforge-mcp = "sentinelforge.analyst.mcp_server:main"

[tool.hatch.build.targets.wheel]
packages = ["sentinelforge", "sentinelforge.analyst", "sentinelforge.dashboard"]
```

Default installation (without `[analyst-mcp]`) does not include the `mcp`
dependency and cannot import `sentinelforge.analyst.mcp_server`.

## Craft Anything Adaptation

Patterns adapted from Craft Anything (storytold/craft-anything, MIT OR Apache-2.0):

- Shared typed tool contracts via MCP `Tool` definitions with `input_schema`
- Effect/capability classification via `ToolAnnotations`
- Fail-closed read-only tool host (no write tools exposed)
- Explicit approval for side effects (none needed — all tools read-only)
- Evidence identifiers and integrity checks (detection_id, event_id, evidence_id)
- Observed/derived/inferred confidence separation (confirmed vs hypotheses)
- Coverage and limitations reporting (pagination, filters applied, unknowns)
- Summary-first retrieval and pagination (LIMIT/OFFSET bounds)
- Long-operation cancellation and bounded output (evidence truncation)

Not adapted: reverse-engineering engines, disassembler, desktop UI, website builder,
game tools, or any code copied without license verification.

## What Is Not Implemented

- Case/incident management (Phase 2)
- Threat intelligence adapters (Phase 3)
- Real-time ingestion (Phase 4)
- Detection content interoperability (Phase 5)
- Governed response automation (Phase 6)

SentinelForge is a prototype, not a production SIEM or autonomous SOC.
