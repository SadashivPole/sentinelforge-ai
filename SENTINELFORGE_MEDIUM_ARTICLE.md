# SentinelForge AI — Medium Technical Article

**Suggested Title:** Building SentinelForge AI: From Raw Security Logs to Explainable SOC Detections

**Project:** SentinelForge AI  
**Version:** 0.1.0 (prototype)  
**Status:** Draft — do not publish without approval

---

## 1. Abstract

Most detection engineering examples show individual rules in isolation. This article walks through building SentinelForge AI, a Python-based prototype that demonstrates the complete detection pipeline — from raw security logs to analyst-ready alerts — with full evidence traceability, explainable risk scoring, and reproducible evaluation against independently authored holdout data.

---

## 2. The Problem

Security operations centers ingest logs from many sources in different formats. Before detection, logs must be normalized, correlated, scored, and evaluated. Most open-source examples show individual detection rules in isolation; few demonstrate the full pipeline with preserved raw evidence and reproducible results.

---

## 3. Architecture

The pipeline flows through seven stages:

1. **Ingestion** — JSON, JSONL, Sysmon readers with content-based selection
2. **Normalization** — Common event schema; raw payload preserved verbatim
3. **Detection** — Five rules, each citing evidence from original logs
4. **Evidence** — Original log events linked to detections
5. **Risk scoring** — 0-100 score with five weighted factors
6. **Storage** — SQLite with foreign-key enforcement
7. **Evaluation** — Independent precision and recall models

Missing fields are `null`, never fabricated. Malformed log records raise visible errors — no silent data loss.

---

## 4. Detection Rules

Five rules, each with MITRE ATT&CK candidate mappings:

| Rule | Technique | Severity |
|---|---|---|
| FailedLoginBurstRule | T1110 / T1110.001 | HIGH |
| PasswordSprayRule | T1110.003 | HIGH |
| SuspiciousPowerShellRule | T1059.001 | HIGH |
| SuspiciousProcessTreeRule | T1204 / T1204.002 | MEDIUM |
| C2BeaconRule | T1071 (conditional) | MEDIUM |

ATT&CK mappings are candidate attributions only — not definitive classifications.

---

## 5. Evidence Model

Every `Evidence` object carries the verbatim `raw` dict from the original log. Detection rules read but never modify raw evidence. This means a SOC analyst can always trace an alert back to the exact log line(s) that produced it.

---

## 6. Risk Scoring

A deterministic 0-100 score per host, computed from five weighted factors:

| Factor | Weight |
|---|---|
| Severity | 30% |
| Evidence quality | 20% |
| Event frequency | 20% |
| Correlation | 20% |
| Asset criticality | 10% (only when explicitly provided) |

Three concepts kept separate: risk score, evidence confidence, detection severity.

---

## 7. Dataset Design

11,298 synthetic events across 19 scenarios, generated with seed=42 for reproducibility. Ground truth labels stored separately from raw events — no labels embedded in events, preventing data leakage.

SHA-256 hashes recorded for all data files to verify reproducibility.

---

## 8. Evaluation

Two independent metric models:

- **Alert-level precision:** TP / assessed alerts (unassessed excluded)
- **Event-level recall:** detected suspicious / total suspicious

No F1 cross-contamination. Attribution errors separated from false positives.

### Holdout results (69 events, not from scenario code)

| Metric | Value |
|---|---|
| Precision | 0.8182 |
| Recall | 1.0000 |
| F1 | 0.9000 |
| False positives | 10 (all C2BeaconRule on legitimate HTTPS) |
| False negatives | 0 |

---

## 9. False-Positive Discovery

C2BeaconRule flagged 10 legitimate periodic HTTPS connections to a known software update server (port 443, 30-minute intervals) as beaconing. This is a known limitation — the rule lacks destination reputation filtering and port allowlisting. We document it rather than hiding it.

---

## 10. Validation Lessons

- **Test on independent data, not your own scenario output**
- **Separate alert-level and event-level metrics** — don't cross-contaminate
- **Track attribution errors separately from false positives**
- **Document false positives rather than whitelisting them away**
- **Batch-only architecture is fine for demonstration; don't claim real-time**

---

## 11. Limitations

- Batch-only architecture (no real-time streaming)
- No authentication/authorization
- No encryption at rest
- No dashboard/UI
- C2BeaconRule false positives
- Partial Sysmon normalization
- CPU/memory not measured

---

## 12. Future Work

- Authentication and authorization
- Encryption at rest
- Threat intelligence integration
- Minimal analyst dashboard
- Controlled SOC pilot

---

## 13. Conclusion

SentinelForge AI demonstrates that a transparent, evidence-first detection pipeline can be built as a prototype with reproducible results. It is not a production SIEM — but it is a useful reference for anyone building detection engineering tooling.

---

## 14. Approval Required

**Do not publish automatically.** Await explicit approval before posting.
