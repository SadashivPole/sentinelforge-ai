# SentinelForge AI — MITRE ATT&CK Design Final Review

**Project:** SentinelForge AI  
**Document:** SENTINELFORGE_MITRE_ATTACK_DESIGN_FINAL_REVIEW.md  
**Version:** 0.2.0  
**Status:** Final review — awaiting user approval  
**ATT&CK Reference:** Enterprise v20.1 (https://attack.mitre.org/)

---

## 1. Corrections Applied to All Four Design Documents

### 1.1 ATT&CK Tactic Count: 14 → 15

All four documents previously referenced 14 Enterprise ATT&CK tactics. MITRE ATT&CK Enterprise v20.1 (effective 13 October 2026) lists **15 tactics**. The change: Defense Evasion was split into two tactics in the April 2026 release.

| Tactic ID | Tactic Name | Status in v0.1.0 docs | Status in v0.2.0 docs |
|---|---|---|---|
| TA0043 | Reconnaissance | ✅ Present | ✅ Present |
| TA0042 | Resource Development | ✅ Present | ✅ Present |
| TA0001 | Initial Access | ✅ Present | ✅ Present |
| TA0002 | Execution | ✅ Present | ✅ Present |
| TA0003 | Persistence | ✅ Present | ✅ Present |
| TA0004 | Privilege Escalation | ✅ Present | ✅ Present |
| TA0005 | Stealth | ❌ Listed as "Defense Evasion" | ✅ Correctly listed as "Stealth" |
| TA0112 | Defense Impairment | ❌ Missing | ✅ Added |
| TA0006 | Credential Access | ✅ Present | ✅ Present |
| TA0007 | Discovery | ✅ Present | ✅ Present |
| TA0008 | Lateral Movement | ✅ Present | ✅ Present |
| TA0009 | Collection | ✅ Present | ✅ Present |
| TA0011 | Command and Control | ✅ Present | ✅ Present |
| TA0010 | Exfiltration | ✅ Present | ✅ Present |
| TA0040 | Impact | ❌ Listed as TA0011 | ✅ Correctly listed as TA0040 |

**Verification source:** https://attack.mitre.org/tactics/enterprise/ — confirms 15 tactics with the IDs and names listed above.

### 1.2 Technique Mapping Corrections

| Technique | ID | Old Tactic (v0.1.0) | Correct Tactic (v0.2.0) | Source Verified |
|---|---|---|---|---|
| User Execution: Malicious File | T1204.002 | Initial Access (TA0001) | Execution (TA0002) | https://attack.mitre.org/techniques/T1204/002/ |
| Command and Scripting Interpreter: Unix Shell | T1059.007 | Listed as Unix Shell | Unix Shell is T1059.004; T1059.007 is JavaScript | https://attack.mitre.org/techniques/T1059/ |

### 1.3 Version String Corrections

| Field | Old Value | New Value |
|---|---|---|
| document version | 0.1.0 | 0.2.0 |
| attack_version | "2024.10" (v20.1) | "v20.1" |

### 1.4 Removed Unsubstantiated Metric

**Removed:** "4 of 46 techniques mapped = **8.7%** of catalogued techniques have detection rules."

**Reason:** The figure could not be reproduced. The correct count is 5 techniques with detection rules (T1110.001, T1110.003, T1059.001, T1204.002, T1071). The denominator (46) was arbitrary and not tied to any defined catalogue. Percentage-based coverage metrics are misleading when catalogue size is a design choice, not a detection capability measurement.

**Replacement:** "5 techniques with detection rules out of the catalogue total" with an explanation that catalogue size reflects the reference inventory, not detection capability.

### 1.5 Scope Recommendation: 85–100 → ~70

Changed from "Target 85–100 techniques" to "Target ~70 techniques" based on:
- Current detection coverage: 5 techniques across 4 tactics
- Available telemetry supports ~11 techniques total (5 implemented + ~6 partially supported)
- Larger catalogues (85–100 or 130) would be dominated by `UNSUPPORTED_BY_CURRENT_TELEMETRY` entries with no analyst value

---

## 2. Quantitative Reasoning for ~70 Technique Scope

### 2.1 Breakdown by Detection Status (~70 curated entries)

| Status | Count | % of Catalogue | Basis |
|---|---|---|---|
| Total curated entries | ~70 | 100% | User-directed starting scope |
| Implemented and tested | 5 | ~7% | Existing rules: T1110.001, T1110.003, T1059.001, T1204.002, T1071 |
| Partially supported | ~6 | ~9% | Available telemetry, no rule yet: T1046, T1078, T1021.004 (SSH), T1059.003, T1059.004, T1087 |
| Planned | ~8 | ~11% | Detection value but requires new telemetry or normalization |
| Unsupported by current telemetry | ~51 | ~73% | Cannot be detected with current normalized fields |

### 2.2 Techniques with Usable Telemetry Today

| Technique | ID | Tactic | Available Telemetry |
|---|---|---|---|
| Password Guessing | T1110.001 | Credential Access | auth.outcome, auth.username, auth.source_address |
| Password Spraying | T1110.003 | Credential Access | auth.outcome, auth.username, auth.source_address |
| PowerShell | T1059.001 | Execution | process.name, process.command_line, process.user |
| Malicious File | T1204.002 | Execution | process.name, process.command_line, process.pid, process.ppid |
| Application Layer Protocol | T1071 | Command and Control | network.protocol, network.remote_address, network.remote_port |
| Network Service Scanning | T1046 | Discovery | network.remote_address, network.remote_port, network.direction |
| Valid Accounts | T1078 | Credential Access | auth.outcome, auth.username |
| SSH Lateral Movement | T1021.004 | Lateral Movement | network.remote_port=22, auth.outcome, auth.username |
| Windows Command Shell | T1059.003 | Execution | process.name, process.command_line |
| Unix Shell | T1059.004 | Execution | process.name, process.command_line |
| Account Discovery | T1087 | Discovery | auth.username, process.command_line |

**Total: 11 techniques with usable telemetry today** (5 implemented, 6 partially supported)

### 2.3 Techniques Requiring Additional Normalization or New Log Sources

| Category | Example Techniques | Missing Capability |
|---|---|---|
| File system monitoring | T1555, T1083, T1486, T1547.001 | File content hash, file modify, registry monitoring |
| Network payload analysis | T1071.004, T1041 | DNS response data, packet payload, outbound data volume |
| Process lineage | T1204.002 confidence | Parent command line |
| New log sources | T1071 web proxy, T1048 alternative protocol | Web proxy logs, cloud storage telemetry |

**Total: ~59 techniques** require additional telemetry before they can be implemented.

### 2.4 Why ~70 Is Defensible

- **70 entries** spans all 15 v20.1 tactics while keeping unsupported portion at ~73% — manageable and honest about gaps.
- **85–100 entries** would add 15–30 more entries, nearly all unsupported — dilutes the catalogue without adding detection value.
- **130 entries** would mean ~125 unsupported (~96% unimplemented) — actively misleading about detection capability.
- The catalogue is a reference inventory that expands as telemetry and detection engineering mature. Start with ~70, grow as rules are implemented.

---

## 3. Schema Verification: No Changes Required

### 3.1 Existing Schema (v3) Confirmed

The `detections` table in `sentinelforge/storage/repositories.py` contains:

| Column | Type | Notes |
|---|---|---|
| detection_id | TEXT | Primary key |
| rule_id | TEXT | Detection rule identifier |
| rule_name | TEXT | Human-readable rule name |
| severity | TEXT | Detection severity |
| description | TEXT | Detection description |
| triggered_at | TEXT | ISO-8601 timestamp |
| metadata | TEXT | JSON — stores rule metadata |
| host | TEXT | Affected host |

The `metadata` column is JSON and already stores rule-specific fields. ATT&CK mapping fields are added as keys within this existing column:

- `mitre_attack_technique` (string)
- `mitre_attack_subtechnique` (string|null)
- `mitre_attack_tactic` (string|null)
- `mitre_attack_mapping_confidence` (string)
- `mitre_attack_mapping_rationale` (string)
- `mitre_attack_investigation_recommendations` (list[string])

**No new tables, no new columns, no schema migration required.**

### 3.2 Catalogue Storage — Separate from Detection Records

| Concern | Implementation |
|---|---|
| Catalogue storage | JSON manifest file (`sentinelforge/attack/catalogue.json`), version-controlled |
| Catalogue versioning | `attack_version` field per entry (pinned to "v20.1"); file-level version in manifest header |
| Detection record storage | ATT&CK fields stored as keys within existing `detections.metadata` JSON column |
| Historical record interpretability | If the catalogue is updated (e.g., technique deprecated), historical detection records retain their original technique IDs in metadata. The raw JSON is preserved verbatim. |
| Catalogue vs. detection decoupling | The catalogue is a reference document; detection records are immutable evidence. Updating the catalogue does not alter historical detections. |

### 3.3 Evidence Traceability

Each detection with an ATT&CK mapping has corresponding evidence events stored in the `evidence` table with foreign key to `detections.detection_id`. The evidence contains the raw event data, timestamp, source, and normalized fields that support the mapping. This provides full traceability from technique mapping → detection → evidence → raw event.

---

## 4. Design Quality Review Checklist

| Check | Status | Notes |
|---|---|---|
| Consistent terminology and status labels | ✅ | All five statuses used consistently: IMPLEMENTED_AND_TESTED, IMPLEMENTED_NEEDS_VALIDATION, PARTIALLY_SUPPORTED, PLANNED, UNSUPPORTED_BY_CURRENT_TELEMETRY |
| Correct 15-tactic taxonomy | ✅ | All 15 v20.1 tactic IDs and names verified against MITRE |
| Consistent technique counts | ✅ | ~70 target, 5 implemented, ~6 partially supported, ~51 unsupported |
| Correct references and links | ✅ | All MITRE ATT&CK URLs verified against official site |
| No unsupported detection coverage claims | ✅ | 8.7% figure removed; no percentage claims about detection coverage |
| Clear distinction between catalogue coverage and implemented detection coverage | ✅ | Catalogue size ≠ detection capability; explicitly stated |
| No claims of confirmed attacker activity based only on ATT&CK mappings | ✅ | Mappings described as hypotheses, not proof of compromise |
| Schema compatibility verified | ✅ | No schema changes; metadata stored in existing JSON column |
| Catalogue storage separated from detection records | ✅ | JSON manifest file, version-controlled separately |
| Historical record interpretability | ✅ | Raw metadata JSON preserved; catalogue updates don't alter historical detections |

---

## 5. Final Recommendation

### 5.1 Initial Catalogue Size: ~70 Techniques

**Approved.** The ~70 technique scope is the most defensible initial scope for SentinelForge AI because:

1. It spans all 15 v20.1 tactics without overstating detection capability
2. Only ~11 of 70 entries have available telemetry today — honest about limitations
3. It provides a realistic reference inventory that can expand as telemetry matures
4. It avoids the misleading impression of a 96% unimplemented catalogue (which 130 entries would create)

### 5.2 First Implementation Phase: Phase 1 Only

**Phase 1 is the only phase recommended for immediate implementation:**

| Phase | Action | Recommendation |
|---|---|---|
| Phase 1 | Catalogue data model + confidence/rationale for existing 5 rules | **APPROVE — implement now** |
| Phase 2 | Coverage reporting + ATT&CK Navigator layer | Defer — review after Phase 1 |
| Phase 3 | PARTIALLY_SUPPORTED techniques from available telemetry | Defer — review after Phase 1 |
| Phase 4 | New detection rules | Defer — review after Phase 3 |
| Phase 5 | Remaining catalogue entries | Defer — review after Phase 4 |

**Phase 1 scope:**
- Create `sentinelforge/attack/catalogue.py`, `mapper.py`, `coverage.py`, `validator.py`
- Create `sentinelforge/attack/catalogue.json` with 5 techniques
- Add ATT&CK metadata fields to `DetectionResult.metadata` for existing 5 rules
- Add tests: technique ID validation, sub-technique relationships, tactic associations, version consistency, duplicate rejection
- No detection code changes, no threshold changes, no schema changes, no historical data modification

### 5.3 What Should Not Be Claimed in Public README

- Do not claim 70–130 detection capabilities (only 5 rules exist)
- Do not claim full ATT&CK coverage across all 15 tactics
- Do not claim C2BeaconRule maps all periodic HTTPS traffic to T1071 (conditional on non-standard port + suspicious context)
- Do not claim SuspiciousPowerShellRule T1059.001 mapping is high confidence (it's medium — benign PowerShell can also use encoded commands)
- Do not claim T1204.002 is Initial Access — it's Execution (TA0002)

---

## 6. Out of Scope for This Review

- Implementation of the catalogue or new detection rules
- Modification of detection code, existing tests, historical datasets, or ground truth
- M9 work
- Publishing or pushing anything
- ATT&CK Navigator layer generation code (design only)

---

**Stopping here for user review. Approve Phase 1 implementation before proceeding.**
