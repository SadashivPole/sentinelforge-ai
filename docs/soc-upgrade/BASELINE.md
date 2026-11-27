# SentinelForge SOC Upgrade — Baseline (Phase 1)

Branch: `feat/advanced-soc-ai-upgrade`
Base commit: `ef4269f` (PR #6 merged into main)
Worktree: `C:\Users\legen\Projects\sentinelforge-ai-soc-upgrade`
Authoritative source: latest committed `origin/main`

This document records the evidence-based baseline for the SentinelForge AI SOC upgrade. All figures were recalculated from the latest committed artifacts; none are carried over as assumed values.

## 1. Repository structure

```
sentinelforge/
├── cli/main.py           # ingest, detect, evaluate, dashboard commands
├── ingestion/            # JSON / JSONL / Sysmon readers + normalizer
├── detection/            # 5 detection rules + rule registry
├── risk/                 # explainable risk scoring + correlator
├── storage/              # SQLite schema (v3) + repositories
├── datasets/             # synthetic dataset generation + evaluation
├── dashboard/            # local read-only HTTP dashboard (127.0.0.1:8080)
└── analyst/              # optional MCP server (7 read-only tools)
```

Supporting:
- `integrations/hermes/skills/sentinelforge-soc-analyst/SKILL.md`
- `scripts/`, `tests/` (14 test modules)
- `docs/` (architecture, security, installation, SOC analyst workflows)

## 2. Capability inventory (current state)

| Area | Capability | Status | Evidence location |
|------|-----------|--------|-------------------|
| Detection engine | 5 rules + registry | Implemented + tested | `sentinelforge/detection/` |
| Detection rules | FailedLoginBurstRule (T1110/T1110.001) | Implemented + positive/negative tests | `sentinelforge/detection/failed_logins.py` |
| | PasswordSprayRule (T1110.003) | Implemented + tested | `sentinelforge/detection/password_spray.py` |
| | SuspiciousPowerShellRule (T1059.001) | Implemented + tested | `sentinelforge/detection/powershell.py` |
| | SuspiciousProcessTreeRule (T1204/T1204.002) | Implemented + tested | `sentinelforge/detection/processtree.py` |
| | C2BeaconRule (T1071) | Implemented + tested | `sentinelforge/detection/beacon.py` |
| Ingestion | JSON, JSONL, Sysmon readers | Implemented + tested | `sentinelforge/ingestion/reader.py` |
| Normalization | Common event schema + raw preservation | Implemented + tested | `sentinelforge/ingestion/normalizer.py` |
| Storage | SQLite schema v3, migrations, repositories | Implemented + tested | `sentinelforge/storage/schema.py`, `repositories.py` |
| Risk scoring | Explainable 0-100 score, separate evidence confidence | Implemented + tested | `sentinelforge/risk/scorer.py` |
| Correlation | Host-scoped time-window clustering | Implemented + tested | `sentinelforge/risk/correlator.py` |
| Evaluation | Alert-level + event-level, separate F1 validity | Implemented + tested | `sentinelforge/datasets/evaluation.py` |
| MCP server | 7 read-only tools, stdio, SQLite `mode=ro` | Implemented + smoke tested | `sentinelforge/analyst/mcp_server.py` |
| Dashboard | Local read-only HTTP, 127.0.0.1:8080 | Implemented | `sentinelforge/dashboard/` |
| CLI | ingest / detect / evaluate / dashboard | Implemented | `sentinelforge/cli/main.py` |
| Synthetic datasets | 11,298 events, 19 scenarios | Generated | `data/generated/*.jsonl` |
| Ground truth | event_ground_truth.json (committed) | Regenerated & committed | `data/generated/event_ground_truth.json` |

### Detection rule metadata (structured)

Each rule carries: rule ID, name, description, severity, MITRE ATT&CK technique/tactic, thresholds, time windows, required fields, evidence references, and test fixtures. Rules are deterministic and produce `DetectionResult` objects with full evidence tracking.

No Sigma rule compilation or conversion path exists today.

## 3. Baseline measurements

### 3.1 Dataset

- Total synthetic events: **11,298** (10,000 base + scenario events)
- Classification: **suspicious: 641**, **benign: 657**, **unlabeled: 10,000**
- Ground-truth labels stored separately from raw events (no data leakage)
- Dataset generation is deterministic (seed 42)

### 3.2 Detection evaluation (event level)

Recalculated from committed `data/generated/event_ground_truth.json` via `run_m8_1_evaluation.py`:

| Metric | Value |
|--------|-------|
| Total events | 11,298 |
| Suspicious events | 641 |
| Detected events | 498 |
| Missed events | 143 |
| Event-level recall | 0.7769 |

Per-rule event metrics (global multi-label, sum exceeds global unique counts because events can carry multiple expected categories):

| Metric | Sum of per-rule | Global unique |
|--------|----------------|---------------|
| Expected | 649 | 641 |
| Detected | 500 | 498 |
| Missed | 149 | 143 |

The differences are explained by multi-category ground-truth events counted once per expected category at per-rule level, and once per unique event ID at global level. This is intentional multi-label behavior, verified against actual event IDs (see PR #6 reconciliation).

### 3.3 Alert-level evaluation

- Precision, true positives, false positives, attribution errors, unassessed alerts tracked separately
- Attribution errors (correct detection, wrong category) are distinct from true false positives (alert on benign evidence)
- F1 marked valid only when precision and recall share the same unit and population

### 3.4 Detection output (sample pipeline run)

Ingest → normalize → detect → correlate → risk score → SQLite produces:
- **172 detections**
- **7 risk assessments**
- `PRAGMA integrity_check`: `ok`
- Zero foreign-key violations

### 3.5 MCP server

- 7 read-only tools over local stdio (JSON-RPC 2.0)
- Read-only enforcement at SQLite connection level (`mode=ro` URI + `PRAGMA query_only=ON`)
- Bounded pagination (LIMIT ≤ 500, OFFSET ≤ 10,000)
- 1 MiB response-size budget with explicit truncation metadata
- No network, no shell, no arbitrary SQL, no write operations
- MCP SDK: `mcp==2.3.0` (optional `analyst-mcp` extra)

### 3.6 Dashboard

- Local HTTP on `127.0.0.1:8080` only
- Read-only: no state-changing endpoints
- Views: overview, alerts, events, rules, attacks (ATT&CK coverage), event detail, diagnostics, static assets

### 3.7 Test suite

| Check | Result |
|-------|--------|
| `pytest tests/` | **461 passed, 1 skipped** (Python 3.14.9 local) |
| `ruff check sentinelforge/ tests/` | All checks passed |
| `ruff format --check sentinelforge/ tests/` | Passed |
| `mypy sentinelforge/` | No issues in 43 source files |
| `bandit -r sentinelforge/` | No issues identified |
| `pip-audit -r requirements.txt` | No known vulnerabilities |

CI matrix targets Python 3.12 and 3.13 (local 3.14.9 is outside the CI matrix and untested in CI).

### 3.8 Packaging

- `pyproject.toml`: `requires-python >=3.11`, hatchling build, console scripts `sentinelforge`, `sentinelforge-dashboard`, `sentinelforge-mcp`
- Optional extra: `analyst-mcp = ["mcp==2.3.0"]`
- No runtime dependencies in core install

## 4. Known limitations (baseline)

1. **No full real-time telemetry collection** — ingestion is file-based (JSON/JSONL/Sysmon), not a streaming collector.
2. **No production connector framework** — no vendor-aware telemetry connectors, cloud audit ingestion, or EDR/identity adapters.
3. **No Sigma rule compilation** — rules are native Python only; no Sigma parsing/conversion path.
4. **No incident/case management** — correlation produces same-host/time-window clusters only; no incident lifecycle, status, assignment, or resolution tracking.
5. **No threat-intelligence adapter framework** — no IOC ingestion, historical IOC matching, or retro-hunting.
6. **No production RBAC** — MCP is read-only by design but there is no role-based access control.
7. **No encryption at rest** for SQLite.
8. **No autonomous response** — advisory-only; no blocking, isolation, or vendor API actions.
9. **Dashboard AI chat** (public website) is a UI preview with no connected backend.
10. **No investigation/audit ledger** for AI findings — no traceable record of prompts, tool calls, or AI verdicts.
11. **CI matrix** covers 3.12/3.13 only; local 3.14.9 is untested in CI.
12. **`git push` is blocked** (>600s, no credential helper/network auth configured) — branches cannot be pushed or PRs opened via CLI yet.

## 5. Measurements defined for the 70% target

Per the upgrade brief, improvement must be measured, not asserted. Candidate measurable areas and their baseline definitions:

| Area | Baseline metric | Formula | Baseline value |
|------|----------------|---------|----------------|
| Detection coverage | Validated rule count | Rules with positive + negative + boundary tests | 5 |
| Telemetry sources | Tested source adapters | JSON, JSONL, Sysmon parsers with fixtures | 3 |
| Event-level recall | TP / (TP + FN) | 498 / 641 | 0.7769 |
| Test count | Passing tests | pytest suite | 461 passed |
| MCP tools | Read-only tools | Enumerated MCP tools | 7 |
| Dashboard views | Routes served | overview, alerts, events, rules, attacks, diagnostics | 6 |
| ATT&CK techniques | Techniques backed by tested detections | T1110, T1110.001, T1110.003, T1059.001, T1204, T1204.002, T1071 | 7 |

Relative improvement formula (higher-is-better):
`((New - Baseline) / Baseline) × 100`

Reduction formula (lower-is-better):
`((Baseline - New) / Baseline) × 100`

Percentage-point changes reported separately for percentage metrics. No arbitrary combined score will be claimed.

## 6. Phase 1 conclusion

SentinelForge is a working, evidence-first SOC detection-engineering prototype with a solid foundation: 5 validated detection rules, normalized ingestion, explainable risk scoring, SQLite evidence storage, synthetic evaluation, a local read-only dashboard, and a secure read-only MCP server. All security and quality checks pass (bandit, pip-audit, mypy, ruff).

Clear upgrade opportunities exist in telemetry expansion (Windows Security, Linux auth/auditd, DNS, firewall, cloud audit), Sigma interoperability, incident/case management, threat-intelligence retro-hunting, entity risk, AI investigation ledger, and governed response playbooks. These will be designed in Phase 2 (ARCHITECTURE.md, ROADMAP.md, DETECTION_COVERAGE.md, MATURITY.md, REFERENCES.md) and implemented in Phase 3.

No code changes have been made yet in this worktree. Baseline is established.
