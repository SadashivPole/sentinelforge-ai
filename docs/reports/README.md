# Validation Reports Index

**Project:** SentinelForge AI  
**Location:** `docs/reports/`  
**Version:** 0.1.0

This directory contains the technical validation reports for SentinelForge AI. All reports are based on actual test execution and measured results — no fabricated metrics.

---

## Reports

| Report | File | Description |
|---|---|---|
| Baseline Parity | `M8_3_6_BASELINE_PARITY_REPORT.md` | Dataset baseline, scenario contracts, reproducible SHA-256 hashes, test results |
| Replay Validation | `SENTINELFORGE_REALTIME_VALIDATION_REPORT.md` | Batch replay benchmark, throughput, latency, architecture limitation |
| Detection Quality | `SENTINELFORGE_DETECTION_QUALITY_REPORT.md` | Holdout evaluation, confusion matrix, C2 false positives, per-rule metrics |
| SOC Usefulness | `SENTINELFORGE_SOC_USEFULNESS_ASSESSMENT.md` | 5 SOC investigation case studies, analyst perspective |
| Security & Reliability | `SENTINELFORGE_SECURITY_AND_RELIABILITY_REPORT.md` | 17 reliability + 17 security tests, SQL injection, no secrets, no remediation |
| Final Validation Gate | `SENTINELFORGE_FINAL_VALIDATION_GATE.md` | Pre-M9 quality gate, verified results, readiness decision |
| Project Readiness | `SENTINELFORGE_PROJECT_READINESS.md` | Dimension assessments, final decision, blockers |

---

## Report Consistency

All reports agree on the following verified results:

| Fact | Value | Source |
|---|---|---|
| pytest tests | 208 passed, 0 failed | All reports |
| Dataset events | 11,298 | Baseline parity, release notes |
| Suspicious events | 641 | Baseline parity |
| Benign events | 657 | Baseline parity |
| Labeled events | 1,298 | Baseline parity |
| Detection rules | 5 | All reports |
| C2BeaconRule FPs | 10 | Detection quality, final gate |
| Holdout precision | 0.8182 | Detection quality, final gate |
| Holdout recall | 1.0000 | Detection quality, final gate |
| Max throughput | ~6,839 events/sec | Replay validation |
| Architecture | Batch-only | All reports |

---

## How to Read

1. Start with [**SENTINELFORGE_FINAL_VALIDATION_GATE.md**](SENTINELFORGE_FINAL_VALIDATION_GATE.md) for the overall quality decision
2. Read [**M8_3_6_BASELINE_PARITY_REPORT.md**](M8_3_6_BASELINE_PARITY_REPORT.md) for dataset baseline details
3. Read [**SENTINELFORGE_DETECTION_QUALITY_REPORT.md**](SENTINELFORGE_DETECTION_QUALITY_REPORT.md) for detection metrics
4. Read [**SENTINELFORGE_REALTIME_VALIDATION_REPORT.md**](SENTINELFORGE_REALTIME_VALIDATION_REPORT.md) for performance characteristics
5. Read [**SENTINELFORGE_SOC_USEFULNESS_ASSESSMENT.md**](SENTINELFORGE_SOC_USEFULNESS_ASSESSMENT.md) for analyst perspective
6. Read [**SENTINELFORGE_SECURITY_AND_RELIABILITY_REPORT.md**](SENTINELFORGE_SECURITY_AND_RELIABILITY_REPORT.md) for security properties
7. Read [**SENTINELFORGE_PROJECT_READINESS.md**](SENTINELFORGE_PROJECT_READINESS.md) for deployment assessment

---