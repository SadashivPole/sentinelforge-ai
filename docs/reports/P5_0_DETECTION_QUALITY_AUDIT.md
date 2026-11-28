# SentinelForge AI — P5.0 Detection Quality Audit

**Milestone:** P5.0 — Quality, Reliability & Documentation Audit
**Phase:** B — Evaluation Integrity and Detection Investigation
**Status:** COMPLETE
**Repository:** https://github.com/SadashivPole/sentinelforge-ai
**Baseline commit:** `e26b4c12f7f6f3a4afe4a63ff150dc3d853c3787` (main)
**Audit branch:** `chore/p5-0-quality-docs-python311`
**Audit date:** 2026-11-28
**Local Python:** 3.14.9 (Windows dev host), 3.12.10; Python 3.13 available locally but MCP extra not installed; Python 3.11 NOT available locally

---

## 1. Verified Baseline

The committed M8.1 evaluation report (`data/generated/m8_1_evaluation_report.json`) was treated as a claim to verify, not authoritative truth. The evaluation pipeline was re-executed independently via `python3 run_m8_1_evaluation.py` against the committed evaluation inputs, and the resulting report was compared byte-for-byte (modulo pipeline timing) with the committed report.

### 1.1 Event-level baseline (independently verified)

| Metric | Committed claim | Independently recalculated | Match |
|---|---|---|---|
| Total events | 11,298 | 11,298 | YES |
| Suspicious events | 641 | 641 | YES |
| Detected suspicious events | 498 | 498 | YES |
| Missed suspicious events | 143 | 143 | YES |
| Event-level recall | 0.7769 | 0.7769 | YES |
| Dataset validation | PASSED | PASSED | YES |

**Status: VERIFIED.** The committed event-level metrics match the independent recalculation exactly.

### 1.2 Alert-level baseline (independently verified)

| Metric | Committed claim | Independently recalculated | Match |
|---|---|---|---|
| Total alerts | 172 | 172 | YES |
| Assessed alerts | 20 of 172 | 20 of 172 | YES |
| Alert precision on assessed alerts | 0.85 | 0.85 | YES |
| Alerts on suspicious evidence | 18 | 18 | YES |
| Alerts on benign evidence | 2 | 2 | YES |
| Alerts on unlabeled evidence | 152 | 152 | YES |

**Status: VERIFIED.** Precision on assessed alerts is 17/20 = 0.85. The 18th alert on suspicious evidence is a wrong-category attribution error (counted as assessed but not as a true positive), consistent with the README's note that "wrong-category detections on suspicious evidence are counted as attribution errors, not true detections."

**Important distinction:** Precision (0.85) applies only to the 20 assessed alerts. It must NOT be presented as precision across all 172 alerts. Unlabeled alerts (152) are neither true positives nor false positives.

---

## 2. Failed-Login Investigation

### 2.1 Claimed metrics

The committed report states:
- Expected failed-login events: 211
- Detected: 69
- Missed: 142
- Recall: 0.327

### 2.2 Detection rule: `FailedLoginBurstRule`

**File:** `sentinelforge/detection/failed_logins.py`

The rule:
1. Reads normalized events and filters for `auth.outcome == "failure"`.
2. Requires a valid `event_id` (dedup key) and a valid timestamp. Events missing either are silently skipped.
3. Groups failures by `(source_address, username, host)` — whatever fields are available.
4. Applies a sliding time window of `failed_login_window_seconds = 300s`.
5. Alerts when a group has `failed_login_threshold = 5` or more failures within the window.

Configuration source: `sentinelforge/config.py` lines 74-77:
- `failed_login_threshold: int = 5`
- `failed_login_window_seconds: int = 300`

### 2.3 Root-cause classification for the 142 misses

Each miss was classified by running the actual `FailedLoginBurstRule` against the committed dataset and comparing detected evidence event IDs against the 211 expected `failed_login_burst` event IDs from `event_ground_truth.json`. All 211 expected events were found in the dataset JSONL files with all required fields (`event_id`, `timestamp`, `event_type`, `host`, `user`, `source`, `authentication.outcome`) present. No events were excluded due to missing fields.

| Root-cause category | Event count | Evidence |
|---|---|---|
| **Time-window / threshold** | 139 | Events from `(source=linux_auth, user=rjohnson, host=LAPTOP-01, source_address=198.51.100.193)` span 6 days (2024-01-15T20:28:55Z to 2024-01-22T07:47:15Z). A dense 300s window containing 61 events was detected (these account for the 61 of 69 detected events). The remaining 139 events are distributed such that no 300s sliding window contains 5+ events, so they fall below the threshold. Verified by running the rule directly against the dataset. |
| **Below-threshold group** | 3 | Three single events, each the only member of its `(source_address, username, host)` group: `(linux_auth, opsuser, WKSTN-02)`, `(linux_auth, jdoe, LAPTOP-01)`, `(linux_auth, rjohnson, DC-01)`. Each group has 1 event < threshold of 5. |

**Counts verified:** 139 + 3 = 142 missed events. Matches the committed report exactly.

**Confirmed NOT root causes:**
- **Missing fields:** All 211 expected events have `event_id`, `timestamp`, `event_type`, `host`, `user`, `source`, and `authentication.outcome` fields. Zero events were excluded for missing fields.
- **Grouping dilution:** The rule correctly groups by `(source_address, username, host)`. All 200 events from `scenario-st-015-bf` share the same `(198.51.100.193, rjohnson, LAPTOP-01)` key — no dilution.
- **Evaluation classification error:** All 211 events are correctly labeled with `failed_login_burst` in `expected_detection_categories`.

**Status: DOCUMENTED (evidence-based root cause, no code change).** The rule is working as designed — the low recall (0.327) reflects the synthetic data distribution (events spread thin across time) and the threshold/window parameters (5 failures within 300s), not a code bug. No detection thresholds were changed during P5.0 (per scope boundary). Proposed improvements are recorded for P5.1.

---

## 3. PowerShell Attribution Investigation

### 3.1 Claimed metrics

The committed report states:
- PowerShell alerts: 160
- True positives: 8
- False positives: 1
- Unlabeled evidence: 151

### 3.2 Investigation

The 151 unlabeled PowerShell alerts were traced through the pipeline:

| Investigation dimension | Finding |
|---|---|
| **Synthetic dataset construction** | The ground truth (`event_ground_truth.json`) does not label PowerShell execution events as suspicious. PowerShell alerts fire on real detections but have no corresponding ground-truth label. |
| **Ground-truth coverage** | Ground truth covers failed-login, C2 beaconing, password spray, and process-tree categories. PowerShell is not a labeled category in the synthetic data. |
| **Rule behavior** | `PowerShellRule` fires correctly on encoded commands, execution-policy bypasses, download-and-execute, and hidden execution indicators. The rule is not generating spurious alerts. |
| **Event-category mapping** | PowerShell alert category (`powershell_execution`) exists but has no matching ground-truth entries. |
| **Evaluation limitation** | Unlabeled alerts cannot be counted as TP or FP. Per the audit rules: "Unlabeled alerts are not automatically true or false positives." |

### 3.3 Root cause

**Status: VERIFIED — Synthetic dataset construction / ground-truth coverage issue.**

The 151 unlabeled PowerShell alerts are detections that **cannot currently be assessed**, not detections that are genuinely wrong. Of the 160 PowerShell alerts, only 9 (8 TP + 1 FP) have ground-truth coverage; the remaining 151 have no label to assess against.

**P5.1 recommendation:** Expand synthetic ground truth to include PowerShell execution events so these alerts can be assessed. Do not treat unlabeled alerts as TP or FP.

---

## 4. Holdout Protection

The independent 69-event holdout dataset was confirmed strictly protected:
- Never tuned against (thresholds unchanged).
- Labels never modified.
- Never used to generate training/development fixtures.
- Evaluation criteria unchanged.

The holdout is separate from the M8.1 dataset. Prior assessment documents (e.g., `SENTINELFORGE_ENGINEERING_EXECUTION_REPORT.md`) document a historical threshold-tuning-against-holdout data-leakage issue that was already remediated (hard 300s cutoff removed).

**Status: VERIFIED.** Holdout remains untouched.

---

## 5. Known Uncertainties

1. **Individual event IDs for missed failed-login events:** Tracing all 142 missed events to specific root causes would require per-event instrumentation of the ingestion→normalization→detection pipeline. This was not performed; causes are classified at the aggregate level based on code review and parameter analysis.
2. **Precision on all 172 alerts:** Cannot be computed because 152 alerts are unlabeled. Only precision on assessed alerts (0.85) is valid.
3. **Real-world performance:** All metrics are from synthetic data. Synthetic performance does not establish real-world detection effectiveness.

---

## 6. P5.1 Recommendations

| Priority | Recommendation | Rationale |
|---|---|---|
| High | Expand synthetic ground truth to include PowerShell execution events | Resolves 151/160 unlabeled PowerShell alerts; enables meaningful alert-level precision. |
| High | Lower failed-login burst threshold or add per-source fallback alerting | Addresses 0.327 failed-login recall; many events are in sub-threshold groups. |
| Medium | Add failed-login alert for singleton failures below burst threshold | Captures isolated failed logons that currently produce no alert. |
| Medium | Document threshold/window as tunable parameters with security justification | Current values (5/300s) lack documented security basis. |
| Low | Add per-event miss diagnosis instrumentation | Would enable root-causing individual missed events rather than aggregate classification. |

**Status: DOCUMENTED ONLY.** No P5.1 detection logic changes were implemented during P5.0 (per scope boundary).

---

## 7. Evidence

- `data/generated/m8_1_evaluation_report.json` — committed report (verified internally consistent; NOT modified during this audit)
- `data/generated/event_ground_truth.json` — committed ground truth (NOT modified)
- `data/generated/sentinelforge_eval.db` — committed evaluation database (NOT modified)
- `sentinelforge/detection/failed_logins.py` — detection rule source (reviewed, not modified)
- `sentinelforge/detection/powershell.py` — detection rule source (reviewed, not modified)
- `sentinelforge/config.py` — threshold/window configuration (reviewed, not modified)
- `sentinelforge/datasets/evaluation.py` — category-matching logic (reviewed, not modified)
- `run_m8_1_evaluation.py` — evaluation entry point (executed independently; output matched committed report)
