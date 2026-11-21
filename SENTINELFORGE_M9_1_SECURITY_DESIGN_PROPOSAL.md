# SentinelForge AI — M9.1 Security Design Proposal

**Project:** SentinelForge AI  
**Document:** SENTINELFORGE_M9_1_SECURITY_DESIGN_PROPOSAL.md  
**Version:** 1.0.0  
**Status:** Design proposal — read-only, no implementation  
**Based on:** Repository inspection of `C:\Users\legen\Projects\sentinelforge-ai`  
**Date:** 2026-11-20

---

## 1. Purpose

This document proposes the security architecture for milestone M9.1 (Authentication, Authorization, and Encryption at Rest). It is a design document only. No source code, tests, datasets, databases, or existing reports are modified by this proposal.

The proposal is grounded in the actual repository state: a batch-oriented Python detection pipeline with SQLite persistence, five deterministic detection rules, no authentication, no encryption at rest, and no network-facing components.

---

## 2. Deployment Models from the Existing Project

The repository currently supports exactly one deployment model implicitly: **local, single-user batch application**. The other two models are analyzed below for completeness, but are not supported by current code.

### 2.1 Model A — Local, Single-User Batch Application (Current)

**Description:** A single analyst runs the Python package locally, ingests JSON/JSONL/Sysmon files, runs detection rules, and persists results to a local SQLite database. No server, no multi-user access, no network exposure.

| Security Control | Status | Rationale |
|---|---|---|
| Authentication | **Premature** | Only one user; no identity to verify; adds friction without reducing risk |
| Authorization | **Premature** | Only one user; no privilege boundaries to enforce; role model would be unused |
| Encryption at rest | **Optional** | Protects database file from offline access by other local users or stolen media; not required if the host itself is trusted and the disk is already encrypted by the OS |

**Justification:** The current architecture has no network listener, no shared database, and no concurrent users. The primary risk is local file disclosure, which is better addressed by OS-level full-disk encryption than application-layer database encryption at this stage.

### 2.2 Model B — Multi-User Analyst Application (Future)

**Description:** Multiple analysts access a shared SentinelForge instance (local or networked), each with their own login, viewing detections, evidence, and risk assessments. A dashboard or API would mediate access.

| Security Control | Status | Rationale |
|---|---|---|
| Authentication | **Necessary** | Multiple users must be identified before any authorization decision |
| Authorization | **Necessary** | Role-based access (admin/analyst/viewer) required to restrict who can view, modify, or delete detections and evidence |
| Encryption at rest | **Necessary** | Shared database on multi-user systems increases exposure of sensitive investigation data to other local users and backup media |

**Justification:** Multi-user access fundamentally changes the threat model. Identity and access boundaries become the primary control. This model requires the dashboard (M9.3) to exist first; without a UI or API, there is no multi-user surface to protect.

### 2.3 Model C — Deployed SOC Service (Future)

**Description:** SentinelForge runs as a networked service receiving logs from forwarders, serving alerts to analysts, and integrating with other SOC tools.

| Security Control | Status | Rationale |
|---|---|---|
| Authentication | **Necessary** | Network exposure requires strong identity verification for all clients and users |
| Authorization | **Necessary** | Fine-grained access control across tenants, rules, and data |
| Encryption at rest | **Necessary** | Server-hosted database is a high-value target; encryption protects against disk theft and backup exposure |
| Transport encryption | **Necessary** (out of M9.1 scope) | TLS/mTLS for all network traffic; not part of current architecture |

**Justification:** This model is beyond the current batch architecture. It requires real-time streaming, network listeners, and a deployment model that does not exist in the repository. M9.1 encryption-at-rest design can inform this model, but implementing it now would be premature.

---

## 3. Threat Model

### 3.1 Assets Requiring Protection

| Asset | Sensitivity | Current Protection |
|---|---|---|
| Raw log events (verbatim) | High — may contain credentials, hostnames, IP addresses, user activity | None beyond filesystem permissions |
| Normalized events | High — derived from raw logs, flattened PII fields | None beyond filesystem permissions |
| Detection results | High — reveal what the SOC is investigating and how | None beyond filesystem permissions |
| Risk assessments | High — reveal risk scoring logic and asset criticality | None beyond filesystem permissions |
| Ground-truth labels | High — reveal what is known malicious/benign; can guide evasion | Stored separately from raw events (already a good practice) |
| Detection rules and thresholds | Medium — reveal detection logic; can be used for evasion | Source code, accessible to anyone with repo access |
| SQLite database file | High — contains all of the above in one file | None (unencrypted) |

### 3.2 Trust Boundaries

| Boundary | Current State | Implication |
|---|---|---|
| Process boundary | Single Python process; no isolation | Any code running in the process has full access to all data |
| Filesystem boundary | SQLite file in `data/` directory | Protected only by OS file permissions |
| Network boundary | No network listener | No remote attack surface currently |
| User boundary | Single implicit user | No isolation between users |

### 3.3 Likely Attack Paths (Current Architecture)

1. **Offline database theft:** An attacker with access to the host or backup media copies `data/sentinelforge.db` and reads it with standard SQLite tools. No encryption means full disclosure.
2. **Local user snooping:** Another user on the same multi-user host reads the database file directly.
3. **Malicious log content:** Logs containing `'; DROP TABLE events; --` or shell commands — currently mitigated by parameterized queries and never-executing log content (verified by 17/17 security tests).
4. **Supply chain / dependency compromise:** Malicious PyPI package in dependency chain — not currently mitigated beyond pinned Python version.
5. **Log tampering before ingestion:** An attacker modifies raw log files before SentinelForge reads them — not mitigated; raw logs are trusted at ingestion time.

### 3.4 What M9.1 Addresses vs. Does Not Address

| Threat | M9.1 Scope? | Notes |
|---|---|---|
| Offline database theft | Yes | Encryption at rest |
| Local user snooping | Yes | Encryption at rest + authZ |
| Remote network attack | No | No network surface exists |
| Malicious log content | No | Already mitigated (parameterized SQL, no execution) |
| Log tampering pre-ingestion | No | Requires log signing/integrity (out of scope) |
| Insider threat (authorized user) | Partially | AuthZ limits what roles can do, but authorized users with DB access can still read everything |
| Dependency compromise | No | Out of scope for M9.1 |

---

## 4. Proposed Authentication and Authorization Architecture

### 4.1 Where It Is Justified

Authentication and authorization are **only justified for Model B (multi-user analyst application)** and **Model C (deployed SOC service)**. For Model A (current, local single-user batch), they are premature.

If M9.1 is implemented now for Model A, the auth system would have no users to authenticate, no roles to enforce, and no API/UI to protect. It would add complexity without security benefit.

### 4.2 Proposed Architecture (Deferred Until Multi-User)

If and when multi-user support is added:

| Component | Responsibility |
|---|---|
| `sentinelforge/auth/password.py` | Password hashing (bcrypt/argon2), verification |
| `sentinelforge/auth/session.py` | Session creation, validation, expiration, revocation |
| `sentinelforge/auth/rbac.py` | Role model (admin, analyst, viewer), permission checks |
| `sentinelforge/auth/middleware.py` | Request/authentication middleware (only if API/dashboard exists) |
| `sentinelforge/storage/repositories.py` | User-scoped queries, row-level access control (requires schema changes) |

**Key constraint:** AuthZ at the repository level requires every query to be user-scoped, which implies schema changes (user_id on events/detections/risk_assessments) and migration risk. This is not part of M9.1 for Model A.

---

## 5. SQLite Encryption Options

The repository uses SQLite v3 with schema migrations v1→v2→v3. The database file is at `data/sentinelforge.db` by default (configurable via `SENTINELFORGE_*` env vars through `sentinelforge.config.settings`).

### 5.1 Option 1 — SQLite Encryption Extension (SEE)

| Aspect | Detail |
|---|---|
| Mechanism | Commercial extension from SQLite consortium; encrypts entire database file |
| Pros | Native SQLite support, transparent to application, industry-standard |
| Cons | Commercial license required (not open source), requires recompiling SQLite, not available via standard pip install |
| Compatibility | Would require replacing Python's built-in `sqlite3` module with a SEE-enabled build |
| Verdict | **Not recommended** — licensing and build complexity outweigh benefits for a prototype |

### 5.2 Option 2 — SQLCipher

| Aspect | Detail |
|---|---|
| Mechanism | Open-source SQLite extension with 256-bit AES encryption |
| Pros | Well-established, open source, Python bindings available (`pysqlcipher3`), transparent encryption |
| Cons | New dependency, requires compiled C extension, key management still application responsibility, may not be available on all platforms |
| Compatibility | Requires replacing `sqlite3` usage with `sqlcipher` bindings throughout storage layer |
| Verdict | **Candidate** — viable but adds a compiled dependency and build complexity |

### 5.3 Option 3 — Application-Layer Encryption (File-Level)

| Aspect | Detail |
|---|---|
| Mechanism | Encrypt the entire `data/sentinelforge.db` file with Fernet/AES-256-GCM before writing; decrypt on read |
| Pros | No SQLite extension needed, works with standard `sqlite3`, key management in application, portable |
| Cons | Must decrypt entire file before any query (no partial reads), race conditions if multiple processes access, temporary decrypted file on disk creates attack surface, no row-level granularity |
| Verdict | **Candidate for Model A** — simplest to implement, but introduces temporary-decrypted-file risk |

### 5.4 Option 4 — OS-Level Full Disk Encryption (BitLocker/FileVault/LUKS)

| Aspect | Detail |
|---|---|
| Mechanism | Host OS encrypts the entire disk volume |
| Pros | Already available on Windows 11 (BitLocker), macOS (FileVault), Linux (LUKS); no application changes; protects against physical theft |
| Cons | Does not protect against other local users on a running system; does not protect backups taken while the volume is mounted |
| Verdict | **Recommended baseline for Model A** — zero code change, immediate protection for the primary threat (offline theft) |

### 5.5 Recommendation for M9.1 Scope

| Model | Recommended Encryption |
|---|---|
| Model A (current) | OS-level FDE + optional application-layer file encryption |
| Model B (multi-user) | SQLCipher or application-layer encryption + authZ |
| Model C (SOC service) | SQLCipher + transport encryption + authZ |

For M9.1 targeting Model A, **SQLCipher or application-layer encryption is premature**. The correct recommendation is to document OS-level FDE as the encryption-at-rest control for Model A, and defer application-layer encryption to when Model B is being built.

---

## 6. Encryption Key Storage, Rotation, Backup, and Recovery

If application-layer encryption is eventually adopted (not recommended for M9.1 Model A):

| Concern | Recommendation | M9.1 Status |
|---|---|---|
| Key storage | Environment variable `SENTINELFORGE_DB_ENCRYPTION_KEY` or OS keyring (Windows DPAPI/macOS Keychain) | Deferred |
| Key derivation | Argon2id from a passphrase + random salt stored with the ciphertext | Deferred |
| Key rotation | Re-encrypt database with new key; maintain key version in database header | Deferred |
| Backup | Encrypted backups stored separately from key; key escrow for recovery | Deferred |
| Recovery | Passphrase-based recovery; no backdoor | Deferred |
| Lost key | Database is unrecoverable; document this explicitly | Deferred |

**Assumption:** If M9.1 is narrowed to OS-level FDE for Model A, key management is handled by the OS (BitLocker recovery key, FileVault recovery key, LUKS passphrase). No application code changes required.

---

## 7. Database Migration and Backward-Compatibility Risks

The repository uses SQLite schema v3 with migrations v1→v2→v3 in `sentinelforge/storage/schema.py`.

| Risk | Description | Mitigation |
|---|---|---|
| Schema changes for authZ | Adding `user_id` to events/detections/risk_assessments tables requires migration v3→v4 | Test migration on copy of production DB; never migrate in place without backup |
| Encryption header | Application-layer encryption adds a header to the database file; existing unencrypted DBs cannot be opened without re-encryption or dual-format support | Provide migration path: decrypt old DB, re-encrypt with new key |
| Rolling upgrade | If multiple instances share a database (Model B/C), mixed encryption support breaks | Not applicable to Model A (single process) |
| Test impact | 275 existing tests assume unencrypted SQLite; adding encryption breaks tests unless they are updated | Tests must be updated to handle encryption (creates test complexity) |

**Backward compatibility principle:** Any encryption change must not break existing unencrypted databases without an explicit migration path. Existing test databases must remain unencrypted unless explicitly opted into encryption.

---

## 8. Security Tests and Measurable Acceptance Criteria

If M9.1 is implemented (in any scope), the following tests must be added and pass:

| Test Category | Test | Acceptance Criterion |
|---|---|---|
| Encryption | Database file cannot be read by standard `sqlite3` CLI without the key | `sqlite3 data/sentinelforge.db ".tables"` fails when encrypted |
| Encryption | Application can read and write its own encrypted database | All 275 existing tests pass with encryption enabled |
| Key management | Wrong key is rejected with clear error | Opening with wrong key raises `EncryptionError`, not silent corruption |
| Key rotation | Database can be re-encrypted with new key and old key no longer works | Old key rejected; new key succeeds |
| Backup recovery | Encrypted database can be restored from backup + key | Restore + open succeeds |
| AuthN (if multi-user) | Unauthenticated access is rejected | 401/error on unauthenticated requests |
| AuthZ (if multi-user) | Viewer cannot modify detections | Modification attempt raises `AuthorizationError` |
| Regression | All existing behavior unchanged | 275 tests pass (or updated equivalent) |

**Critical:** Passing tests verify correct implementation of controls, not complete security. A test suite cannot prove the absence of side-channel attacks, implementation flaws in the encryption library, or key management failures.

---

## 9. Dependencies, Implementation Complexity, and Maintenance Costs

| Component | Dependency | Complexity | Maintenance Cost |
|---|---|---|---|
| OS-level FDE | None (BitLocker/FileVault/LUKS) | Zero code change | Low (OS-managed) |
| SQLCipher | `pysqlcipher3` or similar; compiled C extension | High (replace `sqlite3` throughout storage layer) | High (dependency updates, build issues, platform compatibility) |
| Application-layer file encryption | `cryptography` (already may be available) | Medium (wrapper around sqlite3 file I/O) | Medium (key rotation logic, backup procedures) |
| Authentication (bcrypt/argon2) | `bcrypt` or `argon2-cffi` | Medium | Low |
| Authorization (RBAC) | None (application logic) | Medium-High (schema changes, repository changes) | Medium (role audits, permission reviews) |
| Session management | None (application logic) | Medium | Low (session cleanup, expiry) |

**Estimated effort for full M9.1 (auth + encryption + authZ):** 3–6 weeks for one developer, plus test updates.

**Estimated effort for narrowed M9.1 (encryption documentation only, Model A):** 1–2 days (documentation and procedure, no code).

---

## 10. Recommended Milestone Order and Deferrals

### Recommended Order

1. **Document OS-level FDE as encryption-at-rest for Model A** (immediate, no code change)
2. **Defer authentication and authorization** until Model B (multi-user dashboard/API) is being built — M9.3 or later
3. **Defer application-layer database encryption** until Model B or C — when shared database access creates real multi-user risk

### What Should Be Deferred

| Item | Reason |
|---|---|
| Application-layer SQLite encryption (SQLCipher or file-level) | Premature for Model A; adds dependency and build complexity without reducing the primary threat (offline theft, already handled by OS FDE) |
| Authentication system | No users, no API, no dashboard to protect; adds friction without security benefit |
| Authorization system (RBAC) | Single user; no privilege boundaries; schema changes required for user scoping |
| Session management | No authentication to session against |
| Row-level database security | Requires multi-user schema (user_id on all tables) and migration v3→v4 |

### Why Narrow Scope Is Correct for M9.1

The repository's own documentation (`SENTINELFORGE_PROJECT_READINESS.md`) classifies deployment readiness as "Partial — Works as batch analysis tool; missing: authN/authZ, encryption at rest, threat intel, real-time streaming." However, this does not mean all missing items must be implemented immediately. The threat model for Model A is local file disclosure, which OS-level FDE addresses more effectively than application-layer encryption, with zero code change and zero test breakage.

Implementing full authN/authZ + encryption now would:
- Break the 275-test suite (tests assume unencrypted SQLite)
- Require schema migrations with backward-compatibility risk
- Add dependencies (bcrypt, SQLCipher, etc.)
- Provide no meaningful security improvement for a single-user local batch tool

---

## 11. Explicit Assumptions

| # | Assumption | Evidence / Basis |
|---|---|---|
| A1 | The current deployment model is local, single-user batch | Repository has no server, no API, no dashboard, no multi-user code |
| A2 | The database file is at `data/sentinelforge.db` by default | `sentinelforge/storage/database.py` and `SENTINELFORGE_PROJECT_READINESS.md` |
| A3 | Schema is v3 with migrations v1→v2→v3 | `sentinelforge/storage/schema.py` |
| A4 | No authentication or authorization code exists | Inspected `sentinelforge/` package; no `auth/` module |
| A5 | No encryption at rest exists | `sentinelforge/storage/database.py` uses standard `sqlite3` with no encryption |
| A6 | 275 tests pass and assume unencrypted SQLite | Verified by `pytest` execution (275 passed) |
| A7 | OS-level FDE (BitLocker on Windows 11) is available on the target host | Host is Windows 11 per environment context |
| A8 | No network-facing components exist | No server/listener code in repository |
| A9 | Raw logs are trusted at ingestion time | No log signing or pre-ingestion integrity verification in code |

---

## 12. Recommendation

**Defer M9.1 (authentication, authorization, and application-layer encryption) for Model A.**

**Rationale:** The repository is a local, single-user batch application with no network surface, no dashboard, and no multi-user code. Authentication and authorization have no users to authenticate and no API/UI to protect. Application-layer SQLite encryption adds dependency complexity, test breakage, and migration risk without meaningfully reducing the primary threat (offline database theft), which is better addressed by OS-level full-disk encryption (BitLocker on Windows 11) with zero code change.

**Narrowed alternative (if encryption documentation is desired now):**
- Document OS-level FDE as the encryption-at-rest control for Model A
- Document the key recovery procedure (BitLocker recovery key)
- Add a note that application-layer encryption and authN/authZ are deferred to Model B (multi-user dashboard)
- No source code changes; no test changes; zero regression risk

**Full M9.1 should be revisited when:**
- A multi-user dashboard or API is being built (M9.3), OR
- The application is deployed as a networked SOC service (Model C), OR
- Multiple users share the same host and database

At that point, SQLCipher or application-layer encryption plus bcrypt/argon2 authentication and RBAC authorization become necessary, and should be implemented together with the dashboard, not before.

**Stop here. No implementation. Await approval before proceeding with any code changes.**

---
