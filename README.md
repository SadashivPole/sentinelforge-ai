# SentinelForge AI

**Python-based SOC security log analysis and detection prototype featuring event normalization, explainable detection, evidence correlation, risk scoring and evaluation.**

**Version:** 0.1.0 (prototype)  
**Classification:** Demonstrable SOC Prototype — not production-ready  
**License:** MIT (proposed)  
**Python:** 3.12+

## Design principles

- **Evidence-first detection.** Every alert cites the exact raw log line(s) it
  was derived from. No invented indicators, no detection evidence fabricated.
- **Preserve original raw logs.** The raw payload is stored verbatim alongside
  the normalized event.
- **No automatic remediation.** The agent surfaces findings; humans act.
- **No execution of log content.** Command strings in logs are never executed,
  only inspected as text.
- **LLM calls optional.** Starts with a mock AI provider; real providers are
  pluggable and disabled by default.
- **No credentials in source code.** All configuration comes from environment
  variables or a local `config.env` (never committed).

## Architecture

```
sentinelforge-ai/
├── sentinelforge/            # Python package
│   ├── __init__.py
│   ├── config.py             # env-driven settings, no secrets
│   ├── ingestion/
│   │   ├── __init__.py
│   │   ├── reader.py         # JSON / JSONL / Sysmon-style readers
│   │   └── normalizer.py     # common event schema + raw preservation
│   ├── detection/
│   │   ├── __init__.py
│   │   ├── base.py           # Rule interface + Evidence/Detection models
│   │   ├── failed_logins.py  # failed-login burst detection
│   │   ├── password_spray.py # password spraying detection
│   │   ├── powershell.py     # suspicious PowerShell command lines
│   │   ├── processtree.py    # suspicious parent-child relationships
│   │   └── beacon.py         # statistical beaconing on connection intervals
│   ├── risk/
│   │   ├── __init__.py
│   │   ├── scorer.py         # explainable risk scoring (0-100)
│   │   └── correlator.py     # detection correlation by host + time window
│   ├── storage/
│   │   ├── __init__.py
│   │   ├── database.py       # SQLite connection management
│   │   ├── schema.py         # versioned schema (v3) + migrations
│   │   └── repositories.py   # CRUD + analytics for events/detections/risk
│   ├── datasets/
│   │   ├── __init__.py
│   │   ├── generator.py    # synthetic dataset generation
│   │   ├── ground_truth.py # separate label manifest
│   │   ├── ground_truth_labels.py  # per-event ground truth labels
│   │   ├── scenarios.py    # attack/benign scenario templates
│   │   ├── validators.py   # dataset validation checks
│   │   ├── evaluation.py   # alert-level + event-level metrics
│   │   └── native_sysmon.py  # native Sysmon EVTX-converted JSON generator
│   └── __init__.py
├── tests/                    # pytest suite (208 tests)
├── data/generated/           # synthetic datasets (11,298 events)
├── validate_*.py             # standalone validation scripts
├── benchmark_replay.py       # replay benchmark
├── run_pipeline_eval.py      # pipeline evaluation script
├── run_m8_1_evaluation.py    # M8.1 evaluation script
├── requirements.txt
├── .gitignore
├── LICENSE
├── CONTRIBUTING.md
├── SECURITY.md
└── README.md
```

## Common normalized event schema

Every incoming event is mapped to `NormalizedEvent`:

| Field | Type | Notes |
|---|---|---|
| `event_id` | str | Stable id; from raw log if present, else derived |
| `timestamp` | str | ISO-8601 UTC (optional, absent when unparseable) |
| `source` | str | `json` / `jsonl` / `sysmon` |
| `raw` | dict | Original log payload, preserved verbatim |
| `event_type` | str | `authentication`, `process.create`, `network.connection`, ... |
| `user` | str | |
| `host` | str | |
| `process` | dict | pid, ppid, name, path, command_line, user, hash |
| `network` | dict | direction, local/remote address+port, protocol |
| `authentication` | dict | outcome, method, username, source_address |
| `ingested_at` | str | Ingestion time, ISO-8601 UTC |

## SQLite storage schema (v3)

| Table | Description |
|---|---|
| `events` | Normalized events with flattened process/network/auth columns + raw JSON |
| `detections` | Detection results with metadata JSON |
| `evidence` | Evidence records linked to detections; `event_id` nullable with FK to `events(event_id) ON DELETE RESTRICT` + `external_event_ref` for unpersisted events |
| `risk_assessments` | Risk assessments with scoring factors JSON |
| `risk_assessment_detections` | Links assessments to detections (FK enforced both directions) |
| `schema_metadata` | Version tracking (current: v3) |

## Detection rules

- **FailedLoginBurstRule** (MITRE T1110 / T1110.001): Multiple failed authentications within a configurable window, grouped by (source IP, username, host)
- **SuspiciousPowerShellRule** (MITRE T1059.001): Encoded commands, hidden execution, execution policy bypass, download-and-execute, obfuscation — weighted scoring with configurable threshold
- **SuspiciousProcessTreeRule** (MITRE T1204 / T1204.002): Suspicious parent-child relationships (Office → PowerShell, etc.). T1204.002 requires cross-event correlation: file activity + process execution on same host/user within configurable time window
- **C2BeaconRule** (MITRE T1071): Statistical beaconing on connection intervals (mean, median, std dev, CV, regularity score). T1071 requires app-layer protocol + non-standard port + additional suspicious context (abnormal process, raw IP destination)

## Risk scoring

Deterministic, reproducible risk score (0-100) per host from detection results.
Five weighted factors: severity (30%), evidence quality (20%), event frequency (20%), correlation (20%), asset criticality (10% — optional, never invented). Three concepts kept separate: risk score, evidence confidence, detection severity.

## Storage integrity

- Versioned schema migrations (v1 → v2 → v3)
- Foreign key enforcement on all relationships including `evidence.event_id → events(event_id) ON DELETE RESTRICT`
- Immutable events and detections (INSERT with collision detection → DuplicateIdCollisionError on conflicting content)
- Immutable evidence (INSERT with collision detection, never deleted or replaced)
- Mutable risk assessments (explicit UPSERT — the only table using INSERT OR REPLACE)
- Parameterized queries throughout; transaction rollback on failure
- `PRAGMA integrity_check` and `PRAGMA foreign_key_check` pass cleanly
- No `INSERT OR REPLACE` on events, detections, or evidence
- No `INSERT OR IGNORE` on events, detections, or evidence (only on the junction table where duplicate links are harmless)

## Synthetic enterprise SOC datasets (Milestone 8)

The `sentinelforge/datasets/` package generates reproducible synthetic
enterprise SOC environments. Datasets are written to `data/generated/`.

### Generator
`DatasetGenerator(seed=42)` produces 11,298 events across 19 scenarios with reproducible random seed:

| Category | Events | Description |
|---|---|---|
| `windows_sysmon.jsonl` | 2,000 | Process creation, parent-child, PowerShell, file activity, network |
| `linux_auth.jsonl` | 2,000 | Successful/failed logins, brute-force, password spraying |
| `firewall.jsonl` | 2,000 | Inbound/outbound, allowed/denied, unusual ports |
| `dns.jsonl` | 2,000 | Normal queries, unusual domains, suspicious bursts |
| `network.jsonl` | 2,000 | Periodic connections, beacons, heartbeats, updates |
| `correlated_attacks.jsonl` | 32 | 7 correlated attack scenarios |
| `benign_activity.jsonl` | 52 | 6 benign activity scenarios |

Total: **11,298 events** across 7 output files.

### Ground truth
Labels are stored **separately** from raw events in two files:

- `data/generated/ground_truth.json` — scenario-level manifest (19 scenarios)
- `data/generated/event_ground_truth.json` — per-event labels (1,298 labeled entries)

No raw event contains classification labels, preventing data leakage. Each event is classified as `benign`, `suspicious`, or `unlabeled` — unknown events are never silently classified as benign.

### Scenarios (19 total)

| ID | Classification | Detection category | ATT&CK |
|---|---|---|---|
| scenario-st-001 | suspicious | processtree, beacon, powershell | T1204.002, T1059.001, T1071 |
| scenario-st-002 | suspicious | failed_login_burst | T1110 |
| scenario-st-003 | suspicious | password_spray | T1110.003 |
| scenario-st-004 | suspicious | c2_beacon | T1071 |
| scenario-st-005 | benign | none (allowlisted) | — |
| scenario-st-006 | suspicious | processtree, powershell | T1204.002, T1059.001 |
| scenario-st-007 | suspicious | failed_login_burst | T1110 |
| scenario-st-008 | benign | none | — |
| scenario-st-009 | benign | none | — |
| scenario-st-010 | benign | none | — |
| scenario-st-011 | benign | none | — |
| scenario-st-012 | benign | none | — |
| scenario-st-013 | benign | none | — |
| scenario-st-014 | benign | none | — |
| scenario-st-015-bf | suspicious | failed_login_burst | T1110 |
| scenario-st-015-c2 | suspicious | c2_beacon | T1071 |
| scenario-st-015-ps | suspicious | password_spray | T1110.003 |
| scenario-st-016 | benign | none | — |
| scenario-st-017 | suspicious | powershell | T1059.001 |

### Pipeline evaluation results

Running the generated dataset through the full pipeline (ingest → normalize → detect → correlate → risk score → SQLite):

| Metric | Value |
|---|---|
| Total events ingested | 11,298 |
| Detections produced | 166 |
| Risk assessments | 7 |
| Detections persisted | 166 |
| Risk assessments persisted | 7 |
| `PRAGMA integrity_check` | ok |
| `PRAGMA foreign_key_check` | 0 violations |

### Detection evaluation (against holdout ground truth)

An independently authored holdout dataset (69 events, NOT generated by the scenario code) was used to evaluate detection quality:

| Rule | TP | FP | FN | Precision | Recall |
|---|---|---|---|---|---|
| FailedLoginBurstRule | 15 | 0 | 0 | 1.0000 | 1.0000 |
| PasswordSprayRule | 15 | 0 | 0 | 1.0000 | 1.0000 |
| SuspiciousPowerShellRule | 1 | 0 | 0 | 1.0000 | 1.0000 |
| SuspiciousProcessTreeRule | 2 | 0 | 0 | 1.0000 | 1.0000 |
| C2BeaconRule | 12 | 10 | 0 | 0.5455 | 1.0000 |

**Overall**: precision=0.8182, recall=1.0000, F1=0.9000 (event-level)

**C2BeaconRule false positives:** 10 legitimate periodic HTTPS connections to a known software update server (port 443, 30-minute intervals) were flagged as beaconing. This is a known limitation requiring destination reputation and port filtering.

**No alert-level metrics cross-contaminated:** Alert-level precision and event-level recall are independent models. Attribution errors are tracked separately from false positives.


## Known limitations

- SQLite does not provide encryption — database file access must be restricted at the OS level
- Real security logs may contain sensitive information (PII, credentials, IP addresses)
- No `streamlit`/`pandas` installed (dashboard milestone pending); C: drive at 98% (~5.5 GB free)
- ATT&CK mappings are optional and only attributed when evidence supports them — absence of a mapping does not mean a detection is benign
- Risk score (0-100) is not a probability of compromise

## Development milestones

1. **Environment & workspace verification** — DONE
2. **Project scaffold + log ingestion & normalization** (JSON, JSONL, Sysmon) — DONE
3. Common event schema validation + raw-log preservation — DONE
4. Detection rules: failed-login bursts, suspicious PowerShell, parent-child anomalies — DONE
5. Statistical C2 beacon detection (intervals + regularity) — DONE
6. Explainable risk scoring — DONE
7. SQLite storage — DONE
8. Synthetic benign + suspicious datasets — DONE
9. Streamlit SOC dashboard — DEFERRED (not implemented; Streamlit/Pandas not installed)
10. Pytest test suite (all detection logic tested) — DONE (208 tests)

### Hardening pass (post-Milestone 7)

- Restored foreign-key integrity: `risk_assessment_detections.detection_id → detections.detection_id`
- `evidence.event_id` made nullable with `external_event_ref` for external/unpersisted references
- Immutable events/detections/evidence with collision detection on re-insert
- `DetectionResult` gained a unique `detection_id` (UUID) separate from `rule_id`
- T1204.002 requires cross-event correlation (file activity + process execution)
- T1071 requires additional suspicious context beyond port/protocol deviation
- Schema migration v1 → v2 → v3 implemented
- 18 new regression tests added

### Milestone 8: Synthetic enterprise SOC datasets

- `sentinelforge/datasets/` package with generator, ground truth, scenarios, validators
- 10,038 events generated across 7 categories with reproducible random seed
- Ground truth stored separately (no labels in raw events)
- 7 correlated attack scenarios + benign EDR heartbeat traffic
- Full pipeline evaluation: 287 detections, 7 risk assessments, all persisted to SQLite
- 6 new pytest tests for dataset generation and validation

### Future enhancements (not yet implemented)

- **Authentication and authorization** — user login, RBAC, session management
- **Encryption at rest** — SQLite database file encryption
- **C2BeaconRule FP reduction** — destination reputation filtering, port allowlisting
- **Threat intelligence integration** — IP/domain reputation lookup
- **Minimal analyst dashboard** — Streamlit/Pandas (currently deferred)
- **Controlled SOC pilot execution** — real-world feedback collection

## Quick start

```bash
cd C:/Users/legen/Projects/sentinelforge-ai
python -m venv .venv          # or use existing python
pip install -r requirements.txt
python -m pytest              # run the test suite (208 tests)
```

External API credentials are never stored in source. Set `SENTINELFORGE_AI_PROVIDER=mock`
(the default) so no network calls are ever made.
