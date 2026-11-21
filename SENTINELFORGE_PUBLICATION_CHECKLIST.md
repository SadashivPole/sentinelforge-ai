# SentinelForge AI — Publication Checklist

**Project:** SentinelForge AI  
**Version:** 0.1.0 (prototype)  
**Status:** Pre-publication review  
**Approval required before any public release**

---

## Phase 1: Repository Cleanup and README

- [ ] Initialize git repository (`git init`)
- [ ] Commit all source code
- [ ] README.md updated — accurate claims only (no Streamlit, no real-time, no AI agent, no production readiness)
- [ ] Test count corrected (208, not 131)
- Event count corrected (11,298, not 10,084/10,038)
- [ ] PasswordSprayRule correctly listed as implemented (not "coming later")
- [ ] Schema version corrected (v3, not v2)
- [ ] Architecture diagram corrected (no `app/` directory, no `sentinelforge/ai/` package, no `cli.py`)

---

## Phase 2: Architecture Documentation and Validation Reports

- [ ] `docs/SENTINELFORGE_ARCHITECTURE.md` created with Mermaid diagram
- [ ] `docs/SENTINELFORGE_PROJECT_OVERVIEW.md` created
- [ ] `docs/reports/README.md` created as reports index
- [ ] All 6 validation reports preserved in project root
- [ ] `SENTINELFORGE_FINAL_VALIDATION_GATE.md` created
- [ ] All report counts consistent with actual test results

---

## Phase 3: Screenshots and Demonstration Preparation

- [ ] No fabricated screenshots
- [ ] No fake dashboard images (dashboard doesn't exist)
- [ ] Demo script uses actual terminal output
- [ ] Architecture diagram uses Mermaid (renders in GitHub)

---

## Phase 4: Private Release Review

- [ ] All documentation reviewed for accuracy
- [ ] No exaggerated claims
- [ ] No unsupported accuracy statements
- [ ] Limitations clearly documented
- [ ] SECURITY.md reviewed
- [ ] CONTRIBUTING.md reviewed
- [ ] LICENSE (MIT) added

---

## Phase 5: Public GitHub v0.1.0 (AFTER APPROVAL ONLY)

- [ ] Repository created on GitHub
- [ ] Repository description: "Python-based SOC security log analysis and detection prototype featuring event normalization, explainable detection, evidence correlation, risk scoring and evaluation."
- [ ] Topics: soc, siem, detection-engineering, sysmon, detection-rules, risk-scoring, cybersecurity-prototype, evidence-based-detection, python, synthetic-dataset
- [ ] Tag v0.1.0 created
- [ ] Release notes drafted (see SENTINELFORGE_GITHUB_RELEASE_PLAN.md)
- [ ] **EXPLICIT APPROVAL OBTAINED** before making public

---

## Phase 6: LinkedIn Announcement (AFTER APPROVAL ONLY)

- [ ] Launch post drafted (SENTINELFORGE_LINKEDIN_LAUNCH.md)
- [ ] Short version drafted
- [ ] Technical follow-up drafted
- [ ] Architecture image concept defined
- [ ] Demo video outline defined
- [ ] **EXPLICIT APPROVAL OBTAINED** before posting

---

## Phase 7: Medium Technical Article (AFTER APPROVAL ONLY)

- [ ] Article drafted (SENTINELFORGE_MEDIUM_ARTICLE.md)
- [ ] No promotional marketing language
- [ ] Limitations honestly documented
- [ ] **EXPLICIT APPROVAL OBTAINED** before posting

---

## Phase 8: YouTube Demonstration (AFTER APPROVAL ONLY)

- [ ] Demo script drafted (SENTINELFORGE_YOUTUBE_DEMO_SCRIPT.md)
- [ ] Actual terminal output only (no fabricated results)
- [ ] Limitations shown, not hidden
- [ ] **EXPLICIT APPROVAL OBTAINED** before posting

---

## Files to EXCLUDE from Publication

| File/Path | Reason |
|---|---|
| `HERMES_CAPABILITY_ASSESSMENT.md` | Hermes internal |
| `LINKEDIN_*.md` | Hermes internal (previous versions) |
| `kb/` directory | Hermes internal knowledge base |
| `data/generated/sentinelforge_eval.db` | SQLite database (binary, exclude via .gitignore) |
| `__pycache__/` directories | Python cache (exclude via .gitignore) |
| `.pytest_cache/` | Test cache (exclude via .gitignore) |
| `*.pyc` / `*.py[c]` | Compiled Python (exclude via .gitignore) |
| `.env` | Environment secrets (exclude via .gitignore) |
| `.venv/` | Virtual environment (exclude via .gitignore) |

---

## Files to INCLUDE in Publication

| File/Path | Reason |
|---|---|
| `README.md` | Project documentation (accurate version) |
| `LICENSE` | MIT license |
| `CONTRIBUTING.md` | Contribution guidelines |
| `SECURITY.md` | Security policy |
| `.gitignore` | Exclusion rules |
| `requirements.txt` | Dependencies |
| `sentinelforge/` | Source code |
| `tests/` | Test suite (208 tests) |
| `data/generated/` | Generated dataset (JSONL + JSON, NOT .db) |
| `run_pipeline_eval.py` | Pipeline script |
| `run_m8_1_evaluation.py` | Evaluation script |
| `validate_*.py` | Validation scripts (6) |
| `benchmark_replay.py` | Benchmark script |
| `M8_3_6_BASELINE_PARITY_REPORT.md` | Baseline report |
| `SENTINELFORGE_*.md` | Validation reports (6) |
| `docs/` | Documentation directory |

---

## Approval Sign-Off

| Item | Approver | Status |
|---|---|---|
| Repository initialization | User | Pending |
| README accuracy | User | Pending |
| Public GitHub release | User | Pending |
| LinkedIn announcement | User | Pending |
| Medium article | User | Pending |
| YouTube demonstration | User | Pending |

**DO NOT PROCEED WITH ANY PUBLIC RELEASE WITHOUT EXPLICIT USER APPROVAL.**
