# SentinelForge AI — Project Overview

**Project:** SentinelForge AI  
**Version:** 0.1.0 (prototype)  
**Classification:** Demonstrable SOC Prototype — not production-ready

---

## 1. What is SentinelForge AI?

SentinelForge AI is a cybersecurity engineering prototype that shows how raw security logs travel through a detection pipeline — from raw log entry to analyst-ready alert — with every step documented and every piece of evidence preserved.

It is designed for three audiences:

| Audience | What they get |
|---|---|
| **Cybersecurity beginners** | A clear walkthrough of how detection works, with real examples |
| **SOC analysts** | Alert output with evidence, severity, and investigation next steps |
| **Detection engineers** | Runnable detection rules, normalizers, and evaluation methodology |
| **Recruiters / hiring managers** | Evidence of full-stack detection engineering: ingestion, normalization, rules, scoring, storage, evaluation, validation |

---

## 2. A Practical Example

Here is how one event flows through SentinelForge AI, end to end.

### Step 1: Raw Event

A Windows Sysmon log records PowerShell spawning from Word:

```json
{
  "Event": {
    "System": {
      "EventID": 1,
      "TimeCreated": {"SystemTime": "2024-01-15T08:30:00.000Z"},
      "Computer": "WKSTN-03"
    },
    "EventData": {
      "Data": [
        {"Name": "Image", "#text": "C:\\Program Files\\Microsoft Office\\WINWORD.EXE"},
        {"Name": "ProcessId", "#text": "1111"},
        {"Name": "ParentProcessId", "#text": "2222"},
        {"Name": "CommandLine", "#text": "WINWORD.EXE /document invoice.docx"},
        {"Name": "User", "#text": "OFFICE-01\\jdoe"}
      ]
    }
  }
}
```

### Step 2: Normalized Event

The normalizer maps the raw log to a common schema. Missing fields are `null` — nothing is invented:

```json
{
  "event_id": "auto-generated-uuid",
  "timestamp": "2024-01-15T08:30:00+00:00",
  "source": "sysmon",
  "event_type": "process.create",
  "user": "OFFICE-01\\jdoe",
  "host": "WKSTN-03",
  "process": {
    "pid": 1111,
    "ppid": 2222,
    "name": "WINWORD.EXE",
    "path": "C:\\Program Files\\Microsoft Office\\WINWORD.EXE",
    "command_line": "WINWORD.EXE /document invoice.docx",
    "user": "OFFICE-01\\jdoe",
    "hash_sha256": null
  },
  "network": null,
  "authentication": null,
  "raw": { ... original JSON preserved verbatim ... }
}
```

### Step 3: Detection

Two seconds later, PowerShell is launched by Word. The `SuspiciousProcessTreeRule` detects the parent-child relationship:

**Alert:** Suspicious Parent-Child Process  
**Severity:** MEDIUM  
**MITRE:** T1204.002 (if file-activity correlation found)  
**Evidence:** Two events — WINWORD.EXE (parent) and powershell.exe (child)  
**Confidence:** High (parent found + child command line + parent command line)

### Step 4: Evidence

The alert cites both raw events verbatim. A SOC analyst can inspect the exact command lines, timestamps, and user context — nothing is fabricated.

### Step 5: Risk Score

The `RiskScorer` combines this detection with others on the same host into a risk assessment:

- **Score:** 60 (medium)
- **Factors:** severity (30%), evidence quality (20%), event frequency (20%), correlation (20%), asset criticality (10% — not provided)
- **Evidence confidence:** High
- **Investigation priority:** Investigate the detection; gather additional evidence before escalating

### Step 6: SOC Analyst Investigation

The analyst can answer:

- **What happened?** Word spawned PowerShell — classic Office macro attack chain
- **Which host and user?** WKSTN-03 / OFFICE-01\jdoe
- **What triggered it?** Parent-child process relationship matches T1204.002 pattern
- **What is the time sequence?** Two events, 2 seconds apart
- **What evidence supports it?** Both raw events preserved verbatim
- **Why did the rule trigger?** Office application spawning PowerShell
- **What remains uncertain?** What the PowerShell command does; whether the document was malicious
- **What next?** Decode any encoded commands; check email attachments; review proxy logs; isolate host if needed

---

## 3. What Is Implemented

| Component | Files | Status |
|---|---|---|
| Configuration | `sentinelforge/config.py` | ✅ Implemented |
| Log ingestion | `sentinelforge/ingestion/reader.py` | ✅ Implemented |
| Normalization | `sentinelforge/ingestion/normalizer.py` | ✅ Implemented |
| Detection base | `sentinelforge/detection/base.py` | ✅ Implemented |
| Detection rules (5) | `sentinelforge/detection/*.py` | ✅ Implemented |
| Risk scoring | `sentinelforge/risk/scorer.py` | ✅ Implemented |
| Detection correlation | `sentinelforge/risk/correlator.py` | ✅ Implemented |
| Storage | `sentinelforge/storage/database.py`, `schema.py`, `repositories.py` | ✅ Implemented |
| Dataset generator | `sentinelforge/datasets/generator.py` | ✅ Implemented |
| Ground truth | `sentinelforge/datasets/ground_truth*.py` | ✅ Implemented |
| Scenarios | `sentinelforge/datasets/scenarios.py` | ✅ Implemented |
| Evaluation | `sentinelforge/datasets/evaluation.py` | ✅ Implemented |
| Validators | `sentinelforge/datasets/validators.py` | ✅ Implemented |
| Test suite | `tests/*.py` (208 tests) | ✅ All passing |
| Validation scripts | `validate_*.py` (6 scripts) | ✅ All passing |
| Reports | `M8_*.md`, `SENTINELFORGE_*.md` | ✅ Written |

---

## 4. What Is NOT Implemented

| Component | Status | Why it matters |
|---|---|---|
| Real-time streaming | ❌ Not implemented | Batch-only; no live alerting |
| Streamlit dashboard | ❌ Not implemented | No `app/` directory |
| AI investigation agent | ❌ Not implemented | Mock provider only; optional |
| Authentication / RBAC | ❌ Not implemented | No user login or access control |
| Encryption at rest | ❌ Not implemented | SQLite file unencrypted |
| Threat intelligence | ❌ Not implemented | No IP/domain reputation |
| CLI entry point | ❌ Not implemented | Used as Python library |

---

## 5. Validation Results (Verified)

| Metric | Value |
|---|---|
| pytest tests passed | 208 / 208 |
| Ingestion validation | 28 / 28 |
| Reliability validation | 17 / 17 |
| Security/AI safety | 17 / 17 |
| SQLite integrity | `ok` |
| SQLite FK violations | 0 |
| Holdout precision | 0.8182 |
| Holdout recall | 1.0000 |
| Holdout F1 | 0.9000 |
| Max benchmark throughput | ~6,839 events/sec |

---

## 6. Limitations (Honest)

- **Batch-only:** No real-time streaming or live alerting
- **C2BeaconRule false positives:** 10 legitimate periodic HTTPS connections flagged in holdout testing
- **No authN/authZ:** No user login, RBAC, or session management
- **No encryption:** SQLite database file unencrypted
- **No dashboard:** No Streamlit or frontend UI
- **Partial Sysmon normalization:** Network/DNS/file fields remain in raw evidence only
- **CPU/memory not measured:** No resource utilization instrumentation

---

## 7. How to Run

```bash
cd C:/Users/legen/Projects/sentinelforge-ai

# Run the full test suite
python -m pytest
# Expected: 208 passed, 0 failed

# Generate a synthetic dataset
python -c "
from sentinelforge.datasets.generator import DatasetGenerator
gen = DatasetGenerator(seed=42, output_dir='data/generated')
gen.generate(total_events=10000)
"

# Run validation scripts
python validate_ingestion.py
python validate_reliability.py
python validate_security.py
python validate_detection_quality.py
python validate_soc_usefulness.py
python benchmark_replay.py
```

---

## 8. Why This Project Matters

Most detection engineering examples show individual rules in isolation. SentinelForge AI demonstrates the **full pipeline**:

1. **Ingestion** — Multiple log formats, no silent data loss
2. **Normalization** — Common schema, raw evidence preserved
3. **Detection** — Five rules, each with traceable evidence
4. **Risk scoring** — Explainable 0-100 score with factor breakdown
5. **Storage** — SQLite with FK enforcement and immutability
6. **Evaluation** — Independent precision/recall models against holdout data

This makes it useful as a **teaching tool**, a **detection engineering reference**, and a **prototype foundation** for teams building their own detection pipelines.

---

## 9. Roadmap

| Milestone | Focus |
|---|---|
| M9.1 | Authentication, authorization, encryption at rest |
| M9.2 | C2BeaconRule FP reduction, threat intelligence |
| M9.3 | Minimal analyst dashboard |
| M9.4 | Controlled SOC pilot |
| M9.5 | Production readiness reassessment |

---

## 10. License

MIT License (proposed). Not a production system — use for learning, demonstration, and prototyping.