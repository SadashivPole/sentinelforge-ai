# SentinelForge AI — Next Phase Roadmap

**Project:** SentinelForge AI  
**Document:** SENTINELFORGE_AI_NEXT_PHASE_ROADMAP.md  
**Version:** 1.0.0  
**Status:** Complete — Roadmap  
**Based on:** SENTINELFORGE_AI_COMPLETE_PROJECT_ASSESSMENT.md  
**Date:** 2026-11-20

---

## 1. Executive Summary

SentinelForge AI is a demonstrable SOC detection prototype with strong evidence-handling properties and deterministic detection logic. The next phase should prioritize **engineering hardening** over cosmetic additions: authentication/authorization, encryption at rest, C2BeaconRule false-positive reduction, threat intelligence integration, and a minimal analyst dashboard. These milestones move the project from "prototype" toward "controlled pilot candidate" while preserving the deterministic, evidence-first architecture.

**Total estimated effort:** 4–6 milestones over approximately 3–6 months, depending on team size and scope decisions.

---

## 2. Guiding Principles

1. **Preserve the deterministic core.** Detection rules, normalizer, storage schema, and evidence immutability must remain unchanged in behavior. New features wrap around, not replace, existing modules.
2. **AI is optional.** The deterministic pipeline must function identically with or without AI. AI is never a substitute for rule-based detection.
3. **Evidence-first remains.** Every new feature must preserve raw log verbatim and evidence traceability.
4. **Security first.** Authentication, authorization, and encryption at rest are prerequisites for any pilot deployment.
5. **No silent data loss.** Malformed input must be surfaced, not silently dropped.

---

## 2.1 Milestone Dependency Graph

```
M9.1 (AuthN/AuthZ + Encryption) ──┐
                                   ├─► M9.4 (Controlled Pilot)
M9.2 (C2 FP Reduction + TI) ───────┘
M9.3 (Minimal Dashboard) ─────────┘
```

- M9.1 must complete before M9.4 (pilot requires authN/authZ + encryption).
- M9.2 can proceed in parallel with M9.1.
- M9.3 can proceed in parallel with M9.1 and M9.2.
- M9.4 requires M9.1, M9.2, and M9.3 to be substantially complete.

---

## 3. Milestone Specifications

### M9.1 — Authentication, Authorization, and Encryption at Rest

**Objective:** Enable controlled pilot deployment by adding user authentication, role-based access control, and database encryption.

**Why it matters:** Without authentication and encryption, the system cannot be deployed in any environment where data sensitivity or access control matters. This is the foundational blocker for all subsequent pilot work.

**Prerequisites:** None (can start immediately).

**Scope:**

| Component | Change | Files Likely Affected |
|---|---|---|
| Authentication | Add username/password login with bcrypt/argon2 hashing; session management with time-limited tokens | `sentinelforge/auth/` (new package), `sentinelforge/config.py` (add auth settings) |
| Authorization | Role-based access control (admin, analyst, viewer) with per-endpoint/per-action checks | `sentinelforge/auth/` (new), `sentinelforge/storage/repositories.py` (add user context to queries) |
| Encryption at rest | SQLite database file encryption (SQLite Encryption Extension or application-layer encryption) | `sentinelforge/storage/database.py`, `sentinelforge/storage/schema.py` |
| Configuration | New SENTINELFORGE_AUTH_*, SENTINELFORGE_ENCRYPTION_* environment variables | `sentinelforge/config.py` |

**Tests required:**
- Unit tests for password hashing and verification
- Unit tests for session creation, expiration, and revocation
- Unit tests for RBAC enforcement (admin can X, analyst can Y, viewer cannot Z)
- Integration test: encrypted database can be opened with correct key and rejected with wrong key
- Integration test: unauthenticated requests are rejected

**Acceptance criteria:**
- Users can register, log in, and obtain a time-limited session
- Role-based access control restricts actions by role
- Database file is encrypted at rest (cannot be read with standard SQLite tools without the key)
- All existing 275 tests continue to pass
- No detection logic or thresholds modified

**Explicitly out of scope:** Multi-factor authentication, SSO/SAML/OIDC, password complexity rules, account lockout policies (beyond basic lockout after N failures).

---

### M9.2 — C2BeaconRule False-Positive Reduction + Threat Intelligence Integration

**Objective:** Reduce the 45.45% false-positive rate on legitimate periodic HTTPS traffic (10 FPs on holdout data) and add destination reputation context to C2 beaconing alerts.

**Why it matters:** C2BeaconRule is the only rule with significant false positives (10/22 alerts on legitimate HTTPS to a known update server). This is the primary blocker to analyst trust and production pilot readiness.

**Prerequisites:** None (can start in parallel with M9.1).

**Scope:**

| Component | Change | Files Likely Affected |
|---|---|---|
| C2BeaconRule tuning | Add destination reputation check; port allowlisting; longer minimum interval threshold; process reputation context | `sentinelforge/detection/beacon.py` |
| Threat intelligence | Add IP/domain reputation lookup interface; allowlist/denylist cache; local reputation cache (no external dependency required for offline operation) | `sentinelforge/intel/` (new package), `sentinelforge/config.py` (add TI settings) |
| C2 context logic | Refine `_has_c2_context_evidence` to incorporate reputation and allowlist data | `sentinelforge/detection/beacon.py` |

**Tests required:**
- Unit test: known update server IP:443 with 30-minute interval does NOT trigger alert
- Unit test: unknown IP:4433 with suspicious process DOES trigger alert
- Unit test: reputation cache hit/miss behavior
- Unit test: allowlisted destination is skipped
- Integration test: C2BeaconRule precision improves on holdout dataset (target: precision > 0.80, recall maintained ≥ 1.0000)

**Acceptance criteria:**
- C2BeaconRule precision on holdout dataset improves from 0.5455 to ≥ 0.80
- Recall remains ≥ 1.0000 (no suspicious events missed)
- Known infrastructure (update servers, management IPs) can be allowlisted
- Threat intelligence lookup failures degrade gracefully (detection continues without reputation context)
- All existing 275 tests continue to pass

**Explicitly out of scope:** Real-time threat intelligence feeds, automated IP blocking, domain generation algorithm (DGA) detection, DNS tunneling detection.

---

### M9.3 — Minimal Analyst Dashboard

**Objective:** Provide a minimal web interface for analysts to view detections, evidence, and risk assessments without writing Python.

**Why it matters:** The current library-only interface limits adoption to Python users. A minimal dashboard makes the tool usable by SOC analysts who are not Python developers.

**Prerequisites:** M9.1 (authentication required for dashboard access).

**Scope:**

| Component | Change | Files Likely Affected |
|---|---|---|
| Dashboard backend | Minimal FastAPI or Flask app serving detection listings, evidence details, and risk assessments | `sentinelforge/dashboard/` (new package), `sentinelforge/storage/repositories.py` (read-only query helpers) |
| Dashboard frontend | Minimal HTML/templates (no heavy framework); tables for detections, evidence drill-down, risk score visualization | `sentinelforge/dashboard/templates/` (new), `sentinelforge/dashboard/static/` (new) |
| Authentication integration | Dashboard requires valid session from M9.1 auth system | `sentinelforge/auth/` (existing), `sentinelforge/dashboard/` (new) |

**Tests required:**
- Unit test: dashboard endpoints require authentication
- Unit test: dashboard returns correct detection data for a given host/time range
- Unit test: evidence drill-down returns verbatim raw log content
- Integration test: dashboard loads without errors on a populated database

**Acceptance criteria:**
- Analyst can view list of detections with severity, rule, host, timestamp
- Analyst can click into a detection to see evidence (verbatim raw events) and ATT&CK mapping
- Analyst can view risk assessments with scoring factor breakdown
- Dashboard requires authentication (no anonymous access)
- Dashboard renders correctly on a database with ≥ 100 detections

**Explicitly out of scope:** Real-time alerting, charting libraries, export to CSV/PDF, case management workflow, alert suppression rules.

---

### M9.4 — Controlled Pilot Deployment

**Objective:** Deploy SentinelForge AI in a controlled SOC environment with a friendly team for 2–4 weeks to collect real-world feedback.

**Why it matters:** All prior milestones must be complete before a pilot can meaningfully evaluate the system in a real environment.

**Prerequisites:** M9.1, M9.2, M9.3 complete.

**Scope:**

| Activity | Description |
|---|---|
| Deployment runbook | Document installation, configuration, database initialization, and first detection run |
| Pilot SOC selection | Identify 1–2 friendly SOC teams with existing log sources that can be converted to JSON/JSONL |
| Log onboarding | Assist pilot team in normalizing their logs to SentinelForge format (or write adapters) |
| Pilot execution | Run detection pipeline against pilot logs for 2–4 weeks |
| Feedback collection | Collect FP/FN reports, analyst usability feedback, performance observations |
| Pilot report | Document findings, tuning recommendations, and go/no-go for production consideration |

**Tests required:**
- Pilot deployment succeeds without code changes
- Pilot logs ingest and normalize correctly
- Detections are produced and accessible via dashboard
- Analyst feedback is collected and categorized

**Acceptance criteria:**
- Pilot completes without code modifications to SentinelForge core
- At least one detection is validated as a true positive by the pilot SOC
- All pilot false positives are documented and categorized
- Deployment runbook is complete and reproducible

**Explicitly out of scope:** Production hardening beyond pilot scope, multi-tenant support, compliance reporting (SOC2, HIPAA, etc.), SLA guarantees.

---

## 4. Recommended Next Milestone

**Recommended next milestone: M9.1 — Authentication, Authorization, and Encryption at Rest.**

**Rationale:** This is the foundational blocker. Without authentication and encryption, no pilot deployment is possible, no analyst dashboard can be securely accessed, and no production consideration is feasible. M9.1 also unblocks M9.4 (pilot) and creates the security foundation for all subsequent work.

**Estimated effort:** 2–4 weeks for a single developer, depending on encryption library choice and authentication complexity.

**Immediate next steps:**
1. Review `sentinelforge/config.py` and add authentication/encryption configuration fields
2. Create `sentinelforge/auth/` package with password hashing and session management
3. Add authentication middleware to database access (all repository operations require authenticated session)
4. Implement SQLite encryption at rest (investigate SQLite Encryption Extension vs. application-layer encryption)
5. Write tests for all new functionality before implementation (TDD)

---

## 5. Development Roadmap Summary

| Milestone | Objective | Est. Effort | Prerequisites | Acceptance Gate |
|---|---|---|---|---|
| M9.1 | AuthN/AuthZ + Encryption at rest | 2–4 weeks | None | Encrypted DB accessible only with key; RBAC enforced; 275 tests pass |
| M9.2 | C2 FP reduction + Threat Intel | 2–3 weeks | None | C2 precision ≥ 0.80 on holdout; recall ≥ 1.0000 |
| M9.3 | Minimal analyst dashboard | 2–3 weeks | M9.1 | Dashboard requires auth; displays detections and evidence |
| M9.4 | Controlled pilot | 4–6 weeks | M9.1, M9.2, M9.3 | Pilot completes; FP/FN documented; go/no-go for production |

**Total estimated calendar time:** 3–6 months (with parallel execution of M9.1–M9.3).

---

## 6. What Should Remain Out of Scope

| Item | Reason |
|---|---|
| Real-time streaming / SIEM replacement | Architectural change; not a milestone goal |
| Autonomous remediation / blocking | Violates evidence-first, human-in-the-loop design principle |
| LLM-based detection | Violates evidence-grounded principle; AI is optional and explanatory only |
| Multi-tenant support | Not required for pilot; adds significant complexity |
| Compliance reporting (SOC2, HIPAA) | Requires production-grade infrastructure first |
| Streamlit/Pandas dashboard | Deferred; minimal dashboard (M9.3) is sufficient for pilot |
| API keys / secret rotation | Can be added in M9.2 or later when TI integration matures |

---

## 7. Success Criteria for Phase Completion

Phase 2 is complete when:

1. All 275 existing tests continue to pass (no regression).
2. M9.1 is implemented: authentication, authorization, and encryption at rest are functional.
3. M9.2 is implemented: C2BeaconRule precision ≥ 0.80 on holdout data; recall ≥ 1.0000.
4. M9.3 is implemented: minimal dashboard displays detections and evidence with authentication.
5. M9.4 is implemented: controlled pilot completes with documented findings.
6. No detection logic or detection thresholds were modified during Phase 2.
7. No historical datasets, ground truth, or evidence were modified.

---

## 8. Immediate Next Step

**Create `sentinelforge/auth/` package** with:
- `sentinelforge/auth/__init__.py`
- `sentinelforge/auth/password.py` (bcrypt/argon2 hashing and verification)
- `sentinelforge/auth/session.py` (session creation, validation, expiration)
- `sentinelforge/auth/rbac.py` (role-based access control: admin, analyst, viewer)

Then add authentication configuration to `sentinelforge/config.py` and write tests for all new functionality before implementing the database encryption layer.

**Stop here. Await approval before implementing M9.1.**

---
