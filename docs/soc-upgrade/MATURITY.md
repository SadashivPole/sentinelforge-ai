# SentinelForge SOC Upgrade — Maturity Register

Branch: `feat/advanced-soc-ai-upgrade`
Base commit: `ef4269f`
Status: Phase 2 design; implementation not yet started

This register classifies each SentinelForge capability using evidence-based maturity levels. A capability is classified WORKING only when actual execution evidence supports the claim. Documentation alone does not promote maturity.

## 1. Maturity scale

| Level | Definition |
|-------|------------|
| WORKING | Implemented and tested along the actual operational path, with a meaningful negative control and repeatable validation. Evidence: tests pass, deterministic output reproducible. |
| PARTIAL | Implemented and tested, but missing operational proof or important controls (e.g., no negative control, no reproducibility proof, limited fixture coverage). |
| EXPERIMENTAL | Implemented but not yet validated end-to-end; behavior may change. |
| DEMO-ONLY | UI or preview surface with no connected backend or real data path. |
| DOCS-ONLY | Described in documentation; no implementation. |
| NOT IMPLEMENTED | Not present in code. |
| BROKEN | Present but failing tests or known defective. |

## 2. Capability register (baseline, from committed code)

| Capability | Maturity | Evidence | Location | Limitations |
|------------|----------|----------|----------|-------------|
| Detection engine (5 rules) | WORKING | 461 tests pass; each rule has positive/negative/boundary tests; deterministic output | `sentinelforge/detection/` | Only 5 techniques covered; no per-rule recall breakdown reported |
| Detection catalog metadata | PARTIAL | Rule metadata exists in code; no unified catalog schema or catalog-level validation | `sentinelforge/detection/*.py` | Metadata not machine-validated as a catalog |
| Rule validation lifecycle | PARTIAL | Tests exist per rule; no explicit positive/negative/boundary/missing-field/malformed classification enforced | `tests/` | No validation-coverage assertion per rule |
| ATT&CK coverage map | DOCS-ONLY | ATT&CK IDs in rule metadata; no coverage register or gap report | `sentinelforge/detection/*.py` metadata | No machine-readable coverage map |
| Log ingestion (JSON/JSONL/Sysmon) | WORKING | Tests pass; raw payload preserved; normalization deterministic | `sentinelforge/ingestion/` | Only 3 source formats; no Windows/Linux/network/cloud adapters |
| Normalization + provenance | PARTIAL | Raw payload + source preserved; parser version/mapping provenance not fully tracked | `sentinelforge/ingestion/normalizer.py` | Provenance fields not complete |
| SQLite evidence storage (schema v3) | WORKING | `PRAGMA integrity_check` ok; zero FK violations; repositories tested | `sentinelforge/storage/` | No encryption at rest |
| Synthetic dataset generation | WORKING | Deterministic seed 42; 11,298 events; ground truth separate from raw events | `sentinelforge/datasets/` | Synthetic only; not real telemetry |
| Detection evaluation (event-level) | WORKING | Alert-level and event-level metrics separate; category-match logic shared; reproducible report | `sentinelforge/datasets/evaluation.py` | Per-rule multi-label vs global unique distinction must be preserved |
| Risk scoring (0–100, explainable) | WORKING | Tests pass; severity/evidence/frequency/correlation factors; score not probability of compromise | `sentinelforge/risk/scorer.py` | Asset criticality not supplied by default |
| Correlation (host/time-window) | WORKING | Tests pass; unrelated hosts never mixed; each detection counted once | `sentinelforge/risk/correlator.py` | Single correlation key (host); no explicit rationale |
| Incident / case management | NOT IMPLEMENTED | No incident table or lifecycle | — | Planned in P3-1 |
| MCP server (7 read-only tools) | WORKING | StdIO smoke test passed; `mode=ro` + `PRAGMA query_only=ON`; bounded pagination; 1 MiB budget | `sentinelforge/analyst/mcp_server.py` | No catalog/coverage/IOC/incident/entity tools yet |
| Local dashboard (127.0.0.1:8080) | WORKING | Read-only HTTP; views for overview/alerts/events/rules/attacks/diagnostics | `sentinelforge/dashboard/` | No detection-catalog validation status or coverage-gap views |
| CLI (ingest/detect/evaluate/dashboard) | WORKING | Console scripts installed; commands functional | `sentinelforge/cli/main.py` | No IOC or playbook commands |
| Threat intelligence / IOC matching | NOT IMPLEMENTED | No IOC table or matcher | — | Planned in P4-1/P4-2 |
| Retro-hunting | NOT IMPLEMENTED | No historical IOC re-scan | — | Planned in P4-2 |
| Entity context / risk | PARTIAL | Risk assessments exist; no entity relationship context | `sentinelforge/risk/scorer.py` | No host/user/IP/process/hash pivot |
| AI investigation | EXPERIMENTAL | `build_investigation_brief` returns deterministic timeline; no audit ledger | `sentinelforge/analyst/mcp_server.py` | No investigation ledger; no observed/derived/hypothesis/unknown separation |
| Investigation audit ledger | NOT IMPLEMENTED | No ledger table | — | Planned in P3-2 |
| Sigma / pySigma integration | NOT IMPLEMENTED | No Sigma parser/converter | — | Optional; not implemented |
| Governed response / playbooks | NOT IMPLEMENTED | Advisory-only by design; no playbook templates | — | Planned in P7-1 (advisory only) |
| Hermes soc-analyst skill | WORKING | Documents 7 verified MCP tools | `integrations/hermes/skills/sentinelforge-soc-analyst/SKILL.md` | Must be updated to match final tool set |
| Hermes detection-engineer skill | NOT IMPLEMENTED | No skill exists | — | Planned in P6-2 |
| Dashboard AI chat (public website) | DEMO-ONLY | UI preview; no backend; no AI responses | Public website | Not connected to SentinelForge |

## 3. Maturity promotion criteria

To promote a capability to WORKING, all of the following must hold:
1. Implementation exists in committed source.
2. Automated tests cover normal behavior, failure behavior, invalid input, and a negative control.
3. Negative control is demonstrated to fail (i.e., the test catches incorrect behavior).
4. Output is reproducible across runs (deterministic or seeded).
5. Limitations are documented in this register.

To promote to PARTIAL: implementation + tests exist, but one or more WORKING criteria are unmet.

## 4. Register synchronization

This register must be updated whenever:
- A capability's implementation changes.
- Tests are added or removed for a capability.
- A capability is promoted or demoted.

The register is reviewed in Phase 12 (maturity, reliability, quality controls) and kept synchronized with the real implementation. No capability is described as WORKING without test evidence.
