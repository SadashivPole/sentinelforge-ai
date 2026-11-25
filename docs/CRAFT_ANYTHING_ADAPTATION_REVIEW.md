# Craft Anything Adaptation Review

## Source

Craft Anything (storytold/craft-anything)
- License: MIT OR Apache-2.0
- Status: early alpha
- Rust 1.97+ required
- Commit inspected: latest at clone time (--depth 1)

## Patterns Adapted

| Craft Anything Pattern | SentinelForge Implementation | Location |
|------------------------|------------------------------|----------|
| Shared typed tool contracts | MCP `Tool` definitions with `input_schema` | `sentinelforge/analyst/mcp_server.py` |
| Effect/capability classification | `ToolAnnotations` (readOnlyHint, destructiveHint, idempotentHint, openWorldHint) | `sentinelforge/analyst/mcp_server.py` |
| Fail-closed read-only tool host | No write/shell/filesystem tools in allowlist | `pyproject.toml` tools.include |
| Evidence identifiers | detection_id, event_id, evidence_id throughout | `sentinelforge/analyst/database.py` |
| Observed vs derived vs inferred | confirmed_observations / derived_findings / ai_hypotheses | `sentinelforge/analyst/mcp_server.py` |
| Coverage and limitations | Pagination bounds, filters_applied, unknowns | `sentinelforge/analyst/mcp_server.py` |
| Summary-first retrieval | LIMIT/OFFSET bounds, evidence truncation at 64 KiB | `sentinelforge/analyst/database.py`, `mcp_server.py` |
| Error contract with remediation | `ReadOnlyDatabaseError` with code, message, remediation | `sentinelforge/analyst/database.py` |

## Patterns Not Adapted

| Craft Anything Pattern | Reason Not Adapted |
|------------------------|-------------------|
| Reverse-engineering engines | Unrelated to SOC analysis |
| Disassembler | Unrelated to SOC analysis |
| Desktop UI (egui) | SentinelForge is CLI/API-first |
| Website builder | Unrelated to SOC analysis |
| Game tools | Unrelated to SOC analysis |
| Consent model for side effects | All MCP tools are read-only — no consent needed |
| Clean-room mode | Not an OS sandbox; SentinelForge runs locally |

## Code Copying

No code was copied from Craft Anything. All patterns were independently
implemented in SentinelForge's Python architecture. No attribution is
required since no source code was reused.

## Third-Party Dependency Licenses

Craft Anything's Cargo.lock was inspected. Dependencies include various
licenses (MIT, Apache-2.0, BSD, etc.). No GPL/LGPL/AGPL dependencies were
found in the core MCP-related crates. Since no Craft Anything code was
copied, no dependency licenses affect SentinelForge.
