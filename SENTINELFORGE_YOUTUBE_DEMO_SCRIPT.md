# SentinelForge AI — YouTube Demonstration Script

**Project:** SentinelForge AI  
**Version:** 0.1.0 (prototype)  
**Duration:** 5-10 minutes  
**Status:** Draft — do not publish without approval

---

## 1. Introduction (1 minute)

**On camera / screen share:**

"Hi, I'm going to walk you through SentinelForge AI — a prototype detection pipeline for SOC log analysis. This shows how raw security logs flow from ingestion to analyst-ready alerts, with every alert backed by evidence from the original logs.

Important: this is a prototype, not a production SIEM. It's batch-only — no real-time streaming, no live alerting. No AI investigation agent. No authentication. Use it for learning and demonstration."

---

## 2. Architecture Overview (1 minute)

**Screen share: Architecture diagram**

"Here's the pipeline: raw events come in through ingestion, get normalized to a common schema, run through five detection rules, each alert cites its evidence, then risk scoring assigns a 0-100 score, everything goes into SQLite, and evaluation metrics are computed against ground truth.

Key principle: evidence-first. Raw logs are preserved verbatim. Nothing is invented."

---

## 3. Generating Synthetic Events (1 minute)

**Terminal demo:**

```python
from sentinelforge.datasets.generator import DatasetGenerator
gen = DatasetGenerator(seed=42, output_dir="data/generated")
gen.generate(total_events=10000)
```

"11,298 events across 19 scenarios, all reproducible with seed=42. SHA-256 hashes recorded so you can verify the same output every time."

---

## 4. Ingestion Demo (1 minute)

**Terminal demo:**

```python
from sentinelforge.ingestion.reader import reader_for
from sentinelforge.ingestion.normalizer import normalize

reader = reader_for("data/generated/linux_auth.jsonl")
raw_events = list(reader.read("data/generated/linux_auth.jsonl"))
normalized = [normalize(raw, source="json") for raw in raw_events]
```

"Read JSONL, normalize to common schema. Malformed lines raise errors — no silent data loss. Missing fields are null, never fabricated."

---

## 5. Detection Demo (2 minutes)

**Terminal demo:**

```python
from sentinelforge.detection.base import RuleRegistry
from sentinelforge.detection.failed_logins import FailedLoginBurstRule
from sentinelforge.detection.password_spray import PasswordSprayRule

registry = RuleRegistry()
registry.register(FailedLoginBurstRule())
registry.register(PasswordSprayRule())
results = registry.evaluate_all(normalized)

for r in results:
    print(f"{r.rule_name}: {len(r.evidence)} evidence events")
    for e in r.evidence[:3]:
        print(f"  - {e.event_id}: {e.timestamp} user={e.user} source={e.source_address}")
```

"Each rule fires independently. Every alert cites evidence events with timestamps, users, source IPs — you can trace back to the exact raw log."

---

## 6. Evidence Demo (1 minute)

**Screen show: raw JSON preserved**

"Here's the raw log behind an alert — untouched, unmodified. The analyst sees exactly what the detection rule saw."

---

## 7. Risk Score Demo (1 minute)

**Terminal demo:**

```python
from sentinelforge.risk.scorer import RiskScorer
scorer = RiskScorer()
assessments = scorer.score(results)

for a in assessments:
    print(f"Host {a.affected_host}: score={a.risk_score} ({a.risk_classification})")
    print(f"  Factors: {a.score_breakdown}")
    print(f"  Evidence confidence: {a.evidence_confidence}")
```

"0-100 score with five weighted factors. Evidence confidence kept separate from severity."

---

## 8. Evaluation Demo (1 minute)

**Screen show: holdout results**

"Independently authored holdout dataset — 69 events, not from our scenario code. Precision 0.82, recall 1.00, F1 0.90. Alert-level precision and event-level recall are separate models."

---

## 9. Limitations (30 seconds)

"Batch-only — no real-time streaming. C2BeaconRule flags legitimate periodic HTTPS — a known limitation we document, not hide. No auth, no encryption, no dashboard."

---

## 10. Roadmap (30 seconds)

"M9: authentication, encryption, threat intelligence, minimal dashboard, controlled pilot."

---

## 11. Closing (30 seconds)

"SentinelForge AI is open source (MIT license, pending approval). Built for learning and demonstration. Questions welcome."

---

## 12. Approval Required

**Do not publish automatically.** Await explicit approval before posting.
