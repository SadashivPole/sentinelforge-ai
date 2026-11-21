# SentinelForge AI — GitHub Release Plan

**Project:** SentinelForge AI  
**Proposed Version:** v0.1.0  
**Classification:** Prototype release (not production)

---

## 1. Release Name

**v0.1.0 — "Demonstrable SOC Prototype"**

---

## 2. Release Description

SentinelForge AI v0.1.0 is a prototype release demonstrating a batch-oriented detection pipeline for SOC log analysis. It includes log ingestion (JSON, JSONL, Sysmon), event normalization, five detection rules, explainable risk scoring, SQLite storage with foreign-key enforcement, and reproducible synthetic dataset generation with ground-truth labels.

**This is NOT a production release.** It is suitable for demonstrations, learning, and controlled pilot evaluation only.

---

## 3. Changelog

### v0.1.0 (Initial Prototype)

**Features:**
- Log ingestion: JSON, JSONL, Sysmon EVTX-converted JSON readers
- Normalization: Common event schema with raw evidence preservation
- Detection rules: FailedLoginBurstRule, PasswordSprayRule, SuspiciousPowerShellRule, SuspiciousProcessTreeRule, C2BeaconRule
- Risk scoring: Deterministic 0-100 score with five weighted factors
- Storage: SQLite schema v3 with FK enforcement, migration v1→v2→v3
- Evaluation: Alert-level precision and event-level recall (independent models)
- Dataset generator: 11,298 events across 19 scenarios, seed=42 reproducible
- Ground truth: Stored separately from raw events

**Validation:**
- 208 pytest tests passed, 0 failed
- 28 ingestion validation tests passed
- 17 reliability tests passed
- 17 security tests passed
- Holdout detection: Precision=0.8182, Recall=1.0000, F1=0.9000

**Limitations:**
- Batch-only architecture (no real-time streaming)
- No authentication/authorization
- No encryption at rest
- No dashboard/UI
- C2BeaconRule false positives on legitimate periodic traffic
- Partial Sysmon normalization (network/DNS/file fields raw-only)

---

## 4. Release Checklist

- [ ] Repository initialized as git repo
- [ ] All source code committed
- [ ] README.md updated (accurate, no false claims)
- [ ] LICENSE file added (MIT)
- [ ] CONTRIBUTING.md added
- [ ] SECURITY.md added
- [ ] .gitignore reviewed (excludes __pycache__, *.db, .env, .venv, etc.)
- [ ] docs/SENTINELFORGE_ARCHITECTURE.md added
- [ ] docs/SENTINELFORGE_PROJECT_OVERVIEW.md added
- [ ] docs/reports/README.md added
- [ ] Validation scripts preserved (validate_*.py, benchmark_replay.py)
- [ ] No credentials or secrets in source code
- [ ] No data/generated/sentinelforge_eval.db committed (excluded by .gitignore)
- [ ] No Hermes internal files committed (HERMES_CAPABILITY_ASSESSMENT.md, LINKEDIN_*.md, kb/)
- [ ] No false claims (no Streamlit, no real-time, no AI agent, no production readiness)
- [ ] Test suite runs: 208 passed, 0 failed
- [ ] Tag created: v0.1.0
- [ ] Release notes drafted
- [ ] **APPROVAL REQUIRED** before public release

---

## 5. GitHub Release Notes

```
# SentinelForge AI v0.1.0 — Demonstrable SOC Prototype

A Python-based prototype for SOC log analysis and detection pipeline engineering.

## What's Included

- Log ingestion: JSON, JSONL, Sysmon EVTX-converted JSON
- Event normalization with raw evidence preservation
- 5 detection rules (failed login burst, password spray, suspicious PowerShell, suspicious process tree, C2 beaconing)
- Explainable risk scoring (0-100, 5 weighted factors)
- SQLite storage (schema v3, FK enforcement)
- Synthetic dataset generator (11,298 events, 19 scenarios, seed=42)
- Ground truth stored separately from raw events

## Validation

- 208 pytest tests passed
- Holdout detection: Precision=0.8182, Recall=1.0000, F1=0.9000

## Limitations

- Batch-only (no real-time streaming)
- No authentication/authorization
- No encryption at rest
- No dashboard/UI
- C2BeaconRule false positives on legitimate periodic traffic

This is a prototype, not a production system. Do not deploy to production.
```

---

## 6. Tags Recommendation

| Tag | Purpose |
|---|---|
| `v0.1.0` | Initial prototype release |
| `v0.1.0-beta` | Pre-release (if needed before approval) |

---

## 7. Repository Description

**Recommended:** "Python-based SOC security log analysis and detection prototype featuring event normalization, explainable detection, evidence correlation, risk scoring and evaluation."

---

## 8. GitHub Topics

**Recommended topics:** `soc`, `siem`, `detection-engineering`, `sysmon`, `detection-rules`, `risk-scoring`, `cybersecurity-prototype`, `evidence-based-detection`, `python`, `synthetic-dataset`

---

## 9. Approval Required

**Do not push, publish, upload, create public releases, or change repository visibility without explicit approval.**
