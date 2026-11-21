# SentinelForge AI — Release Notes

**Version:** 0.1.0 (M8 Complete)
**Milestone:** M8 (Synthetic enterprise SOC dataset generator, detection evaluation metrics, native Sysmon support)
**Date:** 2026-11-19
**Dataset Version:** M8.3.6-baseline (seed=42)

---

## 1. Features Delivered (M1–M8)

### M8 — Synthetic Enterprise SOC Dataset Generator
- **Dataset generator:** 11,298 synthetic events across 19 scenarios (6 attack + 13 benign), deterministic with seed=42
- **Scenario library:** 19 scenario templates with explicit `expected_event_count` contracts, Small*/Bulk* class separation, st-015 split into bf/ps/c2 sub-scenarios
- **Per-event ground truth:** `event_ground_truth.json` (1,298 labeled events: 641 suspicious + 657 benign) + `ground_truth.json` (scenario-level manifest); labels stored separately from raw events to prevent data leakage
- **Native Sysmon support:** Sysmon EVTX-converted JSON format (Event/System/EventData), Event IDs 1 (Process Create), 3 (Network Connection), 11 (File Create), 22 (DNS Query)
- **Ground truth labels:** 15 scenarios, 636 attack + 5 PowerShell suspicious events, contextual-event handling (st-002 successful login excluded from recall denominator)
- **Validators:** 9 validation checks (count, schema, unique IDs, timestamps, referential integrity, host consistency, ground truth completeness, benign/suspicious distribution, scenario correlation)

### M8 — Detection Engine
- **Detection rules (5):** FailedLoginBurstRule (T1110), PasswordSprayRule (T1110.003), SuspiciousPowerShellRule (T1059.001), SuspiciousProcessTreeRule (T1204.002), C2BeaconRule (T1071)
- **DetectionResult:** Unique `detection_id` UUID separate from `rule_id`; evidence citation with raw event preservation
- **PasswordSprayRule:** Distinct from brute-force — source IP × multiple usernames within time window (MITRE T1110.003)

### M8 — Detection Evaluation
- **Two independent metric models:** Alert-level precision (TP/assessed, unassessed excluded) and event-level recall (detected/total suspicious); no F1 cross-contamination
- **Attribution errors separated from false positives:** Correct detection with wrong category tracked separately from true FP (alert on benign evidence)
- **Holdout validation:** Independently authored holdout dataset (69 events, not from scenario code); Precision=0.8182, Recall=1.0000, F1=0.9000

### M8 — Risk Scoring & Correlation
- **RiskScorer:** Deterministic risk scoring with correlation clusters keyed by `detection_id`
- **DetectionCorrelator:** Clusters related detections by host/time window

### M8 — Storage
- **SQLite database:** Schema v3, `data/sentinelforge.db` (env: `SENTINELFORGE_DB_PATH`), foreign key enforcement, `evidence.event_id REFERENCES events(event_id) ON DELETE RESTRICT`
- **Repositories:** EventRepository, DetectionRepository, RiskAssessmentRepository with duplicate ID collision detection (`DuplicateIdCollisionError`), evidence collision detection, detection immutability checks (7 fields)
- **ACID:** Transaction rollback, `PRAGMA integrity_check = ok`, `PRAGMA foreign_key_check = 0 violations`

### M8 — Ingestion
- **Readers:** JSONL reader, SysmonReader with JSONL support, content-based reader selection (`.jsonl`, `.json`, extensionless, `.evt`, `.evtx`)
- **Normalizer:** Maps raw events to `NormalizedEvent` with `ProcessInfo`, `NetworkInfo`, `AuthenticationInfo`; missing fields = null (never fabricated); `LogParseError` on malformed lines (no silent log loss)
- **Sysmon TimeCreated:** Handles nested `{"SystemTime": "..."}` dict format from EVTX conversion

### M8 — Configuration
- All configuration from `SENTINELFORGE_*` environment variables via `sentinelforge.config.settings`
- AI provider defaults to mock (`SENTINELFORGE_AI_PROVIDER=mock`)
- Detection thresholds configurable; no LLM for deterministic detection
- No credentials, API keys, tokens, or secrets in source code
- Reserved test IP ranges (RFC 5737) and `.example` domains (RFC 2606)

### M7 & Earlier — Foundation
- Ingestion reader/normalizer, storage schema v1→v3, risk correlator/scorer, detection base/failed_logins/powershell/processtree/beacon
- 208 tests passing, 0 failed

---

## 2. Known Limitations

| Limitation | Impact | Mitigation |
|---|---|---|
| **Batch-only architecture** | No real-time streaming, no sub-second alerting | Suitable for batch SOC analysis (hourly/daily log review); document as limitation, not claim live streaming |
| **C2BeaconRule false positives** | 10 FPs on legitimate periodic HTTPS (port 443, known update server, 30-min intervals) | Tune rule with destination reputation, port filtering, longer-interval exclusion |
| **No authentication/authorization** | No user login, RBAC, or session management | Add for production deployment |
| **No encryption at rest** | SQLite database file unencrypted | Add for production deployment |
| **No threat intelligence** | No IP/domain reputation lookup | Integrate threat intel feeds |
| **No dashboard/UI** | No analyst-facing interface | Streamlit/Pandas deferred; add minimal dashboard |
| **Missing MITRE mappings** | C2BeaconRule and SuspiciousProcessTreeRule lack technique mapping | Add ATT&CK technique IDs |
| **No cross-alert correlation** | Multiple alerts for same host not auto-grouped | Add correlation by host/time |

---

## 3. Setup Instructions

### Prerequisites
- Python 3.12+ (pytest 8.4.2, pyyaml, fastapi, uvicorn)
- Windows 11 (bash/MSYS shell) or Linux
- Docker 29.9.2 (optional)

### Installation
```bash
# Clone or navigate to project
cd C:\Users\legen\Projects\sentinelforge-ai

# No pip install required — all dependencies pre-installed in Python 3.12.10
# Verify pytest availability
python -m pytest --version
```

### Configuration (environment variables, never committed)
Create `config.env` (not committed to version control):
```bash
SENTINELFORGE_DB_PATH=data/sentinelforge.db
SENTINELFORGE_AI_PROVIDER=mock
SENTINELFORGE_LOG_LEVEL=INFO
```

### Running the Test Suite
```bash
python -m pytest --tb=short
# Expected: 208 passed, 0 failed
```

### Generating the Dataset
```bash
python -c "
from sentinelforge.datasets.generator import DatasetGenerator
gen = DatasetGenerator(seed=42, output_dir='data/generated')
gen.generate(total_events=10000)
"
```

### Running Pipeline Evaluation
```bash
python run_pipeline_eval.py
```

### Running Validation Scripts
```bash
# Ingestion validation (28 tests)
python validate_ingestion.py

# Replay benchmark
python benchmark_replay.py

# Detection quality (holdout)
python validate_detection_quality.py

# SOC usefulness (5 case studies)
python validate_soc_usefulness.py

# System reliability (17 tests)
python validate_reliability.py

# Security and AI safety (17 tests)
python validate_security.py
```

---

## 4. Reproducibility Steps

### Dataset Reproducibility (Seed 42)
1. Run `DatasetGenerator(seed=42, output_dir=<tmpdir>).generate(total_events=10000)` twice
2. Compare SHA-256 hashes of all `data/generated/*.jsonl` and `*.json` files
3. All data files produce byte-identical hashes across runs (only `dataset_manifest.json` timestamp differs)

**Verified SHA-256 hashes (M8.3.6-baseline, seed=42):**
| File | SHA-256 |
|---|---|
| benign_activity.jsonl | c318616ab376465d6baa83da7de69a4848c32a427455afe73737c958e883ffb1 |
| correlated_attacks.jsonl | 601b6ca449fe053bdc7dfb0cf8093e9528e3e9c5b0010b8acbcb3ae369827e23 |
| dns.jsonl | 1378a52eff622050b273598f3cb19d7d3650a5e6e7970b1ce5b7096ec6dfc016 |
| firewall.jsonl | cff66c10cd577044cd40bb006123dfa08b492fb0af5567a945cc4bb860115275 |
| linux_auth.jsonl | 373604bac52f426c8b942d8ecab74d95a902b3d46ec21260b0a4f417c294ddfe |
| network.jsonl | 93773c3064b44c15426c9fac2a2717eeabdfd659f3b3ad25ebcd789ed3b87477 |
| windows_sysmon.jsonl | 577323acb4f754041a3c8f3deb4001073ca0d804d8f9b67d57d7a838c5a33c99 |
| event_ground_truth.json | 6cabdb7be88550db545d39a8ceb374a4b7062e1b4d0686614eb1072f242ebadc |
| ground_truth.json | b1279b6e9c5c3fc3a11074207fca02f3186a6f8d6fb48d8af33ebc60314b1d63 |

### Test Reproducibility
1. Run `python -m pytest --tb=short`
2. Expected: 208 passed, 0 failed, exit code 0
3. Deterministic: same seed produces same events, detections, and risk scores

---

## 5. Preserved Evidence

| Evidence | Location |
|---|---|
| Full test suite output | 208 passed, 0 failed (`pytest --tb=short`) |
| Dataset files | `data/generated/` (11 JSONL + 3 JSON files) |
| Dataset SHA-256 hashes | Above (Section 4) and `M8_3_6_BASELINE_PARITY_REPORT.md` |
| Ground-truth manifest | `data/generated/event_ground_truth.json`, `ground_truth.json` |
| Evaluation output | `data/generated/m8_1_evaluation_report.json` |
| M8.3.6 baseline report | `M8_3_6_BASELINE_PARITY_REPORT.md` |
| Phase 2 validation reports | `SENTINELFORGE_*_REPORT.md` (6 files) |
| Ingestion validation | `validate_ingestion.py` (28/28 pass) |
| Replay benchmark | `benchmark_replay.py` (26,986 eps max throughput) |
| Detection quality | `validate_detection_quality.py` (holdout: P=0.8182, R=1.0000) |
| SOC usefulness | `validate_soc_usefulness.py` (5 case studies) |
| System reliability | `validate_reliability.py` (17/17 pass) |
| Security/AI safety | `validate_security.py` (17/17 pass) |

---

## 6. Sysmon Field Normalization — Normalized vs. Raw-Only

When normalizing Sysmon EVTX-converted JSON events (`source="sysmon"`), the following fields are extracted into `NormalizedEvent` typed fields. Everything else is retained **only** in the verbatim `raw` dict.

### Normalized into `NormalizedEvent` fields

| Field | Source | Notes |
|---|---|---|
| `event_id` | Auto-generated UUID | Not present in raw Sysmon XML |
| `timestamp` | `Event.System.TimeCreated.SystemTime` | ISO-8601 UTC; nested `{"SystemTime": "..."}` dict handled |
| `event_type` | `EventData.EventType/Type`, or `"process.create"` if `Image` present | Derived, not directly in raw |
| `user` | `EventData.User/UserName/SubjectUserName` | From EventData |
| `host` | `Event.System.Computer/Host` | From System element |
| `process.pid` | `EventData.ProcessId/PID` | Integer |
| `process.ppid` | `EventData.ParentProcessId/PPID` | Integer |
| `process.name` | `EventData.Image/ProcessName` | Process name |
| `process.path` | `EventData.Image` | Same as name (Image field) |
| `process.command_line` | `EventData.CommandLine` | Full command line |
| `process.user` | `EventData.User` | Same as top-level user |
| `process.hash_sha256` | `EventData.Hash/SHA256/Hashes` | Process hash |

### Normalized as `None` (not populated for Sysmon)

| Field | Value | Reason |
|---|---|---|
| `network` | `None` | Sysmon network fields (DestinationIp, DestinationPort, Protocol, etc.) are NOT extracted into `NetworkInfo` |
| `authentication` | `None` | Sysmon auth fields are NOT extracted into `AuthenticationInfo` |

### Retained only in verbatim `raw` evidence (not normalized)

- `Event.System.EventID` number (1, 3, 11, 22)
- `Event.System.Provider` name and Guid
- All `EventData.Data` items not listed above (DestinationIp, DestinationPort, Protocol, QueryName, TargetFilename, etc.)
- The complete `Event` XML structure as converted to JSON
- Any fields absent from the normalized schema

**Design principle:** Missing or unextracted fields are `null`, never fabricated. Raw evidence is preserved verbatim for SOC analyst investigation and detection rule re-evaluation.

---


## 7. Constraint Compliance

- [x] No Streamlit or Pandas installed
- [x] No EvidenceForge files modified
- [x] No credentials/API keys/secrets in source code
- [x] No automatic remediation/blocking
- [x] LLM calls optional, default to mock provider
- [x] Detection thresholds configurable, no LLM for deterministic detection
- [x] Original raw logs preserved verbatim
- [x] SQLite database in project `data/` directory; no encryption claimed
- [x] All configuration from `SENTINELFORGE_*` environment variables
- [x] Ground-truth labels stored separately from raw events
- [x] Reserved test IP ranges (RFC 5737) and `.example` domains (RFC 2606)
- [x] M9 not started
