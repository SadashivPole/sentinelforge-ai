# SentinelForge SOC Upgrade — Architecture

Branch: `feat/advanced-soc-ai-upgrade`
Base commit: `ef4269f`
Status: Design document for Phase 2 (implementation not yet started)

This document describes the target architecture for the SentinelForge SOC upgrade. It is proportionate to the existing Python + SQLite prototype — it does not recreate AiSOC's larger distributed service architecture (event streaming, multiple databases, vendor connector fleet, AI agent services, governed-response services).

## 1. Current architecture (baseline)

```
Log files (JSON / JSONL / Sysmon)
        |
        v
sentinelforge/ingestion/   (readers + normalizer)
        |
        v
sentinelforge/storage/     (SQLite schema v3, repositories)
        |
        v
sentinelforge/detection/   (5 rules + registry)
        |
        v
sentinelforge/risk/        (scorer + correlator)
        |
        v
sentinelforge/cli/main.py  (ingest / detect / evaluate / dashboard)
        |
        v
sentinelforge/dashboard/   (local HTTP, 127.0.0.1:8080, read-only)
sentinelforge/analyst/     (MCP server, stdio, SQLite mode=ro)
```

Key properties preserved in the upgrade:
- Core installation is dependency-free (`pyproject.toml` `dependencies = []`).
- MCP is an optional `analyst-mcp` extra (`mcp==2.3.0`).
- SQLite read-only enforcement for MCP (`mode=ro` URI + `PRAGMA query_only=ON`).
- Dashboard binds to `127.0.0.1` only, no state-changing endpoints.
- Original raw payload preserved verbatim alongside normalized event.

## 2. Target architecture (after upgrade)

```
                    ┌─────────────────────────────────────┐
                    │   Security telemetry sources        │
                    │  Windows Security, Sysmon, Linux    │
                    │  auth/auditd, DNS, firewall, proxy, │
                    │  cloud audit, EDR/identity (JSONL)  │
                    └──────────────────┬──────────────────┘
                                       │ file / stdin
                                       v
                    ┌─────────────────────────────────────┐
                    │   Source adapters (modular)         │
                    │  win_security, sysmon, linux_auth,  │
                    │  auditd, dns, firewall, cloud_audit │
                    └──────────────────┬──────────────────┘
                                       │ raw event
                                       v
                    ┌─────────────────────────────────────┐
                    │   Normalization layer               │
                    │  common schema + raw preservation   │
                    │  parser version, mapping provenance │
                    │  validation warnings, idempotency   │
                    └──────────────────┬──────────────────┘
                                       │ normalized event
                                       v
                    ┌─────────────────────────────────────┐
                    │   SQLite evidence storage (schema v3)│
                    │  events, alerts, incidents, IOCs,   │
                    │  investigation ledger               │
                    └──────────────────┬──────────────────┘
                                       │
           ┌───────────────────────────┼───────────────────────────┐
           │                           │                           │
           v                           v                           v
┌──────────────────┐      ┌──────────────────┐      ┌──────────────────┐
│  Detection       │      │  Correlation /   │      │  Threat intel    │
│  engine + catalog│      │  incident model  │      │  (IOC matching,  │
│  (native Python) │      │  (host/user/IP)  │      │  retro-hunt)     │
└────────┬─────────┘      └────────┬─────────┘      └────────┬─────────┘
         │                         │                         │
         v                         v                         v
┌─────────────────────────────────────────────────────────────────────┐
│  Risk scoring (explainable 0-100) + investigation audit ledger     │
└─────────────────────────────────────────────────────────────────────┘
                                       │
                                       v
┌──────────────────┐      ┌──────────────────┐      ┌──────────────────┐
│  MCP server      │      │  Local dashboard │      │  Hermes skills   │
│  (read-only,     │      │  (127.0.0.1:8080)│      │  (soc-analyst,   │
│  stdio, SQLite   │      │                  │      │  detection-eng)  │
│  mode=ro)        │      │                  │      │                  │
└──────────────────┘      └──────────────────┘      └──────────────────┘
```

### Data flows

1. **Ingestion flow**: source file → adapter reads raw lines → normalizer maps to common schema → validation warnings recorded → raw payload + normalized event stored in SQLite → ingestion timestamp recorded.
2. **Detection flow**: normalized events → rule registry → each rule evaluates against its required fields/time window → `DetectionResult` with evidence references → alerts stored.
3. **Correlation flow**: alerts → grouped by explicit keys (host, user, process lineage, IP, time window, ATT&CK behavior) → correlated groups (not incidents unless causation evidence exists) → rationale recorded.
4. **Risk flow**: detection results + evidence quality + severity + recency → explainable 0–100 score with factor breakdown → score is not a probability of compromise.
5. **Investigation flow**: analyst queries via MCP/dashboard → evidence timeline → host/user pivots → related events → investigation audit record (inputs, tool calls, returned evidence, hypotheses vs confirmed findings).
6. **Threat-intel flow**: local IOC import → validation → match against stored events (real-time) + historical re-scan (retro-hunt) → findings linked to events with provenance, confidence, discovery time vs event time.

## 3. Module responsibilities

| Module | Responsibility | Change in upgrade |
|--------|--------------|-------------------|
| `sentinelforge/ingestion/` | Source adapters + normalization | Add modular adapters for Windows Security, Sysmon, Linux auth/auditd, DNS, firewall, cloud audit; preserve raw payload |
| `sentinelforge/detection/` | Rule registry + native Python rules | Add structured catalog metadata; review 5 existing rules; add new high-value rules only where telemetry is ready |
| `sentinelforge/risk/` | Scoring + correlation | Extend correlator with explicit keys + incident grouping rationale |
| `sentinelforge/storage/` | SQLite schema v3 + repositories | Add incidents, IOC, investigation-ledger tables (schema remains v3-compatible) |
| `sentinelforge/datasets/` | Synthetic datasets + evaluation | Holdout evaluation preserved; evaluation consistency checks |
| `sentinelforge/dashboard/` | Local read-only HTTP | Add detection catalog, ATT&CK coverage, evaluation, investigation views |
| `sentinelforge/analyst/` | MCP server | Add read-only tools backed by actual data (catalog, coverage, IOC, incident, entity) |
| `integrations/hermes/skills/` | Hermes skill docs | Update soc-analyst skill; add detection-engineer skill |

## 4. Security boundaries (mandatory, unchanged)

- Dashboard: `127.0.0.1` only, read-only endpoints.
- MCP: stdio only, SQLite `mode=ro` + `PRAGMA query_only=ON`, parameterized SQL, bounded pagination, 1 MiB response budget, no arbitrary SQL/shell/write.
- Logs treated as untrusted data; no execution of command strings from logs.
- No credentials in source code.
- No autonomous response (blocking, isolation, deletion, vendor API actions).
- AI hypotheses kept separate from confirmed findings; AI cannot override deterministic severity/risk.

## 5. What is intentionally NOT in scope

- Kafka, Kubernetes, PostgreSQL, or distributed event pipeline.
- Neo4j or graph database (relational SQLite sufficient for initial entity context).
- External threat-intelligence providers (MISP/OpenCTI) as mandatory dependencies.
- Production RBAC, encryption at rest, or case-management system.
- Reproducing AiSOC's entire service architecture — principles adopted, infrastructure not copied.
