# SentinelForge SOC Analyst MCP — Security Review

## Trust Model

The MCP server is an **untrusted local component**. It runs on the same host
as SentinelForge and communicates with clients (Hermes, IDEs) over stdio.
It must never be exposed to the public internet.

## Read-Only Enforcement

Read-only access is enforced at **two independent layers**:

### Layer 1: SQLite Connection (primary enforcement)

- SQLite URI `file:path?mode=ro` — OS-level read-only file handle
- `PRAGMA query_only = ON` — SQLite rejects all mutation SQL
- Write verification on open — `_verify_read_only()` attempts a DDL write
  and raises `ReadOnlyDatabaseError` if it succeeds

### Layer 2: Tool Annotations (secondary, hint only)

- `readOnlyHint: true`, `destructiveHint: false`, `idempotentHint: true`,
  `openWorldHint: false`
- These are hints for MCP clients, not a security boundary

## What the MCP Server Cannot Do

| Capability | Status | Reason |
|------------|--------|--------|
| Ingest logs | ❌ No tool | No ingestion tools implemented |
| Delete/alter data | ❌ No tool | Read-only connection rejects writes |
| Execute shell/commands | ❌ No tool | No shell tools in allowlist |
| Browse filesystem | ❌ No tool | Database path only |
| Arbitrary SQL | ❌ No tool | Static SQL with parameterized values only |
| Network lookups | ❌ No tool | No outbound connections |
| Public HTTP endpoint | ❌ No | stdio only |
| Remote database access | ❌ No | Local SQLite file only |
| Schema migration | ❌ No | `migrate()` never called from MCP |

## Input Validation

- Pagination: `LIMIT` ≤ 500, `OFFSET` ≤ 10,000
- String length limits: host ≤ 256, severity ≤ 32, rule_id/detection_id ≤ 128,
  query ≤ 10,000, event_type/source/user ≤ 128
- Time range: start ≤ end, max 365 days; timestamps must be timezone-aware
  (naive or mixed aware/naive timestamps are rejected with `bad_input`)
- Response budget: maximum 1 MiB serialized per MCP tool response; oversize
  responses are truncated with explicit `truncated` metadata, never silently
  producing invalid JSON
- All values parameterized via `?` placeholders — no string interpolation
  in query values
- Table names in `table_counts()` come from a hardcoded allowlist
  (`# nosec B608`)

## Error Handling

- Errors never leak internal file paths or credentials. The database path
  is not included in `database_missing` or `database_not_initialized` error
  messages, nor in `sentinelforge_get_status` output.
- Database missing → `database_missing` error with remediation
- Database not initialized → `database_not_initialized` error
- Scope conflict (host/alert_id mismatch) → `scope_conflict` error
- Read-only violation → `internal` error (should never happen)
- Response too large → `response_too_large` error with truncation guidance
- All errors return `is_error: true` with safe messages

## Credentials and Secrets

- No credentials stored in source code
- Configuration via `SENTINELFORGE_DB_PATH` environment variable only
- No API keys, tokens, or secrets in the MCP server
- No GitHub tokens, cloud provider keys, or unrelated secrets configured

## Known Limitations

- The MCP server runs with the permissions of the host user
- File-level read-only depends on OS file permissions
- No authentication between MCP client and server (stdio is local-only)
- No audit logging of MCP tool calls (beyond stderr logging)

## What Is Not Yet Implemented

- Authentication/authorization for MCP clients
- Audit logging of MCP tool usage
- Query result encryption in transit (stdio is local, no encryption needed)

## Hermes Configuration

When configuring the MCP server in Hermes:

```yaml
mcp:
  servers:
    sentinelforge-analyst:
      command: <path-to-sentinelforge-mcp>
      args: []
      env:
        SENTINELFORGE_DB_PATH: /path/to/data/sentinelforge.db
      trust: untrusted
      tools.include:
        - sentinelforge_get_status
        - sentinelforge_list_alerts
        - sentinelforge_get_alert
        - sentinelforge_get_alert_evidence
        - sentinelforge_search_events
        - sentinelforge_build_investigation_brief
        - sentinelforge_list_risk_assessments
      resources: false
      prompts: false
      timeout: 30000
      enabled: true
```

## Craft Anything Security Patterns Adapted

- Fail-closed read-only tool host
- Explicit effect classification (readOnlyHint, destructiveHint)
- Evidence identifiers and integrity (detection_id, event_id, evidence_id)
- Summary-first retrieval with bounded output

Not adapted: clean-room mode (not an OS sandbox), consent model for side
effects (none needed — all tools read-only).
