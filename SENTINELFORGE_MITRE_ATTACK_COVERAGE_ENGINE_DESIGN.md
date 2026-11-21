# SentinelForge AI — MITRE ATT&CK Coverage Engine Design

**Project:** SentinelForge AI  
**Document:** SENTINELFORGE_MITRE_ATTACK_COVERAGE_ENGINE_DESIGN.md  
**Version:** 0.2.0 (design proposal — corrected and final review)  
**Status:** Draft — awaiting review  
**ATT&CK Reference:** Enterprise v20.1 (https://attack.mitre.org/)  
**Restrictions:** Read-only design. No source code changes. No detection threshold changes. No modification to existing datasets, ground truth, or reports.

---

## 1. Purpose

This document defines the architecture for an **ATT&CK Coverage Engine** — a structured, deterministic capability that maps SentinelForge AI detections to MITRE ATT&CK Enterprise techniques and sub-techniques, tracks coverage across tactics, and produces analyst-facing investigation context.

**Guiding principle:** Every ATT&CK mapping must be evidence-grounded and deterministic. A mapping is never claimed as proof of compromise or adversary attribution. It is a hypothesis that an observed behavior pattern is consistent with a known adversary technique, subject to analyst verification.

---

## 2. Current State Assessment

### 2.1 Existing Detection Rules and ATT&CK Mappings

| Rule | Rule ID | Technique | Sub-technique | Tactic | Mapping Status |
|---|---|---|---|---|---|
| FailedLoginBurstRule | sentinelforge.detection.failed_login_burst | Brute Force | T1110.001 Password Guessing | Credential Access (TA0006) | Implemented, fixed |
| PasswordSprayRule | sentinelforge.detection.password_spray | Password Spraying | T1110.003 | Credential Access (TA0006) | Implemented, fixed |
| SuspiciousPowerShellRule | sentinelforge.detection.suspicious_powershell | PowerShell | T1059.001 | Execution (TA0002) | Implemented, fixed (no confidence) |
| SuspiciousProcessTreeRule | sentinelforge.detection.suspicious_processtree | User Execution | T1204.002 Malicious File | Execution | TA0002 | Conditional on file correlation |
| C2BeaconRule | sentinelforge.detection.c2_beacon | Application Layer Protocol | T1071 | Command and Control (TA0011) | Conditional on protocol + port + context |

### 2.2 Available Telemetry (Normalized Schema)

| Log Source | Sysmon Event ID | Normalized Fields Available | NOT Available |
|---|---|---|---|
| Windows Sysmon | 1 Process Create | process name, path, pid, ppid, command_line, user, hash_sha256 | file content hash verification, parent command line |
| Windows Sysmon | 3 Network Connection | local/remote address+port, protocol, process | DNS response data, packet payload |
| Windows Sysmon | 11 File Create | process, target filename | file content, hash verification |
| Windows Sysmon | 22 DNS Query | process, query name | DNS response, query type details |
| Linux Auth | N/A | outcome, method, username, source_address, host | SSH key type, terminal info |
| Network | N/A | direction, addresses, ports, protocol | application payload, certificate info |

### 2.3 MITRE ATT&CK Enterprise v20.1 Tactics (15 total)

| # | Tactic ID | Tactic Name |
|---|---|---|
| 1 | TA0043 | Reconnaissance |
| 2 | TA0042 | Resource Development |
| 3 | TA0001 | Initial Access |
| 4 | TA0002 | Execution |
| 5 | TA0003 | Persistence |
| 6 | TA0004 | Privilege Escalation |
| 7 | TA0005 | Stealth |
| 8 | TA0112 | Defense Impairment |
| 9 | TA0006 | Credential Access |
| 10 | TA0007 | Discovery |
| 11 | TA0008 | Lateral Movement |
| 12 | TA0009 | Collection |
| 13 | TA0011 | Command and Control |
| 14 | TA0010 | Exfiltration |
| 15 | TA0040 | Impact |

**Correction from v0.1.0:** v20.1 has 15 tactics, not 14. Defense Evasion was split into Stealth (TA0005) and Defense Impairment (TA0112) in the April 2026 release. Impact is TA0040 (not TA0011, which is Command and Control).

### 2.4 Telemetry Gaps Relevant to ATT&CK Coverage

| Gap | Impact |
|---|---|
| No file content hash verification | Cannot confirm malicious file execution (T1204.002 relies on correlation, not hash match) |
| No process parent command line | Limited parent-child context for process tree analysis |
| No DNS response data | Cannot detect DNS tunneling or C2 via DNS responses |
| No proxy/web logs | Cannot detect web-based C2 or exfiltration beyond Sysmon |
| No EDR telemetry beyond Sysmon | Limited process lineage and memory analysis |

---

## 3. ATT&CK Coverage Engine — Data Model

Each catalogue entry is a deterministic record. No technique is mapped to a detection unless the detected behavior is directly observable in the normalized telemetry.

### 3.1 Catalogue Entry Schema

| Field | Type | Description | Example |
|---|---|---|---|
| technique_id | string | MITRE ATT&CK technique or sub-technique ID | "T1110.001" |
| technique_name | string | Official MITRE name | "Password Guessing" |
| technique_description | string | MITRE definition (verbatim or summarized) | "Adversaries may guess or brute force credentials..." |
| tactic_ids | list[string] | ATT&CK tactic IDs | ["TA0006"] |
| tactic_names | list[string] | ATT&CK tactic names | ["Credential Access"] |
| subtechnique_parent_id | string|null | Parent technique ID if this is a sub-technique | "T1110" |
| platforms | list[string] | MITRE-listed platforms | ["linux", "windows"] |
| attack_version | string | ATT&CK version validated against | "v20.1" |
| source_url | string | MITRE ATT&CK page URL | "https://attack.mitre.org/techniques/T1110/001" |
| applicable_log_sources | list[string] | SentinelForge sources that can produce evidence | ["linux_auth", "windows_sysmon"] |
| required_telemetry | list[string] | Normalized fields required for detection | ["authentication.outcome", "authentication.username", "authentication.source_address"] |
| available_telemetry | list[string] | Subset of required_telemetry actually present in normalized events | ["authentication.outcome", "authentication.username", "authentication.source_address"] |
| evidence_fields | list[string] | NormalizedEvent fields populated when this technique is detected | ["event_id", "timestamp", "host", "user", "authentication.outcome", "authentication.source_address"] |
| associated_detection_rule_ids | list[string] | Rule IDs that can produce this technique mapping | ["sentinelforge.detection.failed_login_burst"] |
| detection_status | string | "IMPLEMENTED_AND_TESTED" \| "IMPLEMENTED_NEEDS_VALIDATION" \| "PARTIALLY_SUPPORTED" \| "PLANNED" \| "UNSUPPORTED_BY_CURRENT_TELEMETRY" | "IMPLEMENTED_AND_TESTED" |
| mapping_confidence | string | "high" \| "medium" \| "low" | "high" |
| mapping_rationale | string | Human-readable explanation of why this technique maps to the detected behavior | "Multiple failed authentication attempts against live accounts — password guessing against authentication service" |
| investigation_recommendations | list[string] | Analyst next steps | ["Check for successful logins from source IP", "Review account lockout policies"] |
| validation_status | string | "validated" \| "unvalidated" | "validated" |
| last_reviewed | string | ISO-8601 date | "2026-11-19" |

### 3.2 DetectionResult Metadata Extension

Each `DetectionResult.metadata` dict gains the following optional fields (added alongside existing fields, never replacing existing ones):

| Metadata Field | Type | Description | Example |
|---|---|---|---|
| mitre_attack_mapping_confidence | string | "high" \| "medium" \| "low" | "high" |
| mitre_attack_mapping_rationale | string | Why this technique was assigned | "Multiple failed SSH logins from one source against one account — password guessing against live authentication" |
| mitre_attack_investigation_recommendations | list[string] | Analyst next steps | ["Check for successful logins from 198.51.100.77", "Review SSH logs for successful authentications"] |

### 3.3 Coverage Engine Components

| Component | Responsibility | Inputs | Outputs |
|---|---|---|---|
| `ATTACKCatalogue` | Loads and validates the technique catalogue from a JSON manifest | Catalogue JSON | Queryable technique registry |
| `ATTACKMapper` | Maps detection results to catalogue entries using rule_id -> technique_id | DetectionResult, catalogue | DetectionResult with enriched metadata |
| `CoverageReporter` | Computes coverage statistics by tactic, technique, log source | Catalogue, detection history | Coverage report (ATT&CK Navigator-compatible layer) |
| `MappingValidator` | Validates technique IDs, tactic associations, sub-technique relationships, version consistency | Catalogue JSON, MITRE STIX data | Pass/fail report |

---

## 4. Mapping Confidence Model

| Confidence Level | Definition | Example |
|---|---|---|
| high | The detected behavior directly and exclusively matches the technique definition. Multiple independent indicators confirm the technique. | Failed login burst against one account = T1110.001 |
| medium | The detected behavior is consistent with the technique but could also match adjacent techniques. Requires analyst corroboration. | PowerShell with encoded command = T1059.001 (could be legitimate admin) |
| low | The detected behavior is suggestive but not diagnostic. Requires significant additional evidence. | Periodic outbound HTTPS on non-standard port = possible C2 (T1071) but could be legitimate |

### 4.1 Confidence Assignment Rules

- **high**: Detection logic uniquely identifies the technique (e.g., failed login burst against one account can only be password guessing).
- **medium**: Detection logic identifies the technique family but not the specific sub-technique (e.g., PowerShell execution with encoded command could be T1059.001 or could be legitimate admin obfuscation).
- **low**: Detection logic detects suspicious activity consistent with the technique but not diagnostic (e.g., periodic network connections with no additional context).

### 4.2 No Mapping Case

If a detection cannot be mapped to any ATT&CK technique with at least "low" confidence, the `mitre_attack_technique` field is **omitted** from metadata. Absence of mapping is not failure; it is honest uncertainty.

---

## 5. Coverage Reporting

### 5.1 ATT&CK Navigator Layer

The engine can generate an ATT&CK Navigator-compatible layer JSON containing **only** techniques with `detection_status == "IMPLEMENTED_AND_TESTED"`. Planned, partial, and unsupported techniques are excluded.

Layer fields:
- `name`: "SentinelForge AI v0.1.0 Coverage"
- `versions`: {"attack": "v20.1"}
- `techniques`: list of `{techniqueID, score: 1, color, enabled: true, comment}` for implemented techniques only
- `tactic`: reference to tactic ID

### 5.2 Coverage Report Sections

| Metric | Definition |
|---|---|
| Total curated techniques | Count of all entries in the catalogue |
| Implemented and tested | Techniques with at least one corresponding detection rule and validation test |
| Partially supported | Techniques where detection exists but telemetry is incomplete |
| Planned | Techniques with no detection but planned for future work |
| Unsupported by current telemetry | Techniques that cannot be detected with current normalized fields |
| Coverage by tactic | Count per ATT&CK tactic |
| Coverage by log source | Count per normalized log source |
| Detection-to-technique relationships | List of rule_id -> technique_id mappings |

---

## 6. Database and Schema Compatibility

### 6.1 No Schema Changes Required

The existing `detections.metadata` JSON column already stores rule metadata as JSON. ATT&CK mapping fields (`mitre_attack_technique`, `mitre_attack_tactic`, `mitre_attack_subtechnique`, `mitre_attack_mapping_confidence`, `mitre_attack_mapping_rationale`, `mitre_attack_investigation_recommendations`) are added as keys within this existing JSON column.

**No new tables, no new columns, no schema migration.**

### 6.2 Existing Data Preservation

- Existing detections already in SQLite are not modified.
- New detections include ATT&CK metadata fields when available.
- Backward compatibility: code reading `metadata` must handle missing ATT&CK keys gracefully (`.get()` pattern already used throughout).

---

## 7. Testing Requirements

| Test | Rule/Component | Expected Behavior |
|---|---|---|
| `test_mitre_technique_id_valid` | Catalogue loader | Every technique_id matches `^T\d{4}(\.\d{3})?$` |
| `test_mitre_subtechnique_relationship` | Catalogue loader | Every sub-technique ID references an existing parent technique |
| `test_mitre_tactic_association` | Catalogue loader | Every tactic_id matches `^TA\d{4}$` |
| `test_mitre_attack_version` | Catalogue loader | attack_version == "v20.1" |
| `test_no_duplicate_technique_ids` | Catalogue loader | No duplicate technique_id entries |
| `test_unsupported_technique_not_detected` | Coverage engine | Techniques with status != "IMPLEMENTED_AND_TESTED" never appear in Navigator layer |
| `test_detection_to_technique_relationship` | Detection rules | Every detection with a mitre_attack_technique has a corresponding catalogue entry |
| `test_evidence_traceability` | Detection rules | Every detection with MITRE mapping has corresponding evidence events |
| `test_mapping_confidence_validation` | Detection rules | Every detection with MITRE mapping has a valid confidence value |
| `test_mapping_rationale_present` | Detection rules | Every detection with MITRE mapping has non-empty rationale |

---

## 8. Design Constraints Honored

| Constraint | How Addressed |
|---|---|
| No AI dependency | All mappings are deterministic, rule-based |
| No existing detection threshold changes | ATT&CK mapping metadata is additive; detection logic unchanged |
| No historical dataset modification | Existing raw events and ground truth untouched |
| No EvidenceForge modification | External project not referenced |
| No M9 work | This is a design document for M8 enhancement consideration only |
| Deterministic, evidence-grounded | Every mapping traces to specific normalized fields and detection logic |
| Reproducible | Catalogue JSON is version-controlled; technique IDs pinned to ATT&CK v20.1 |

---

## 9. Out of Scope

- Full 70–130 technique catalogue implementation (design only)
- Automatic ATT&CK technique assignment at detection time beyond existing rule metadata
- ATT&CK Navigator layer generation code (design only)
- Integration with external threat intelligence feeds
- Changes to SQLite schema
- Modification of existing detection rules' thresholds or logic

---

## 10. Next Steps (Requires User Approval)

1. Review and approve this design document.
2. Select final technique count (70, 100, or 130).
3. Approve implementation of Phase 1 (catalogue data model + mapping confidence/rationale for existing 5 rules).
4. Approve implementation of Phase 2 (coverage reporting + Navigator layer).
5. Approve implementation of Phase 3 (testing).

---

## 11. Appendix: Current MITRE ATT&CK Mapping Summary

| Rule | Technique | Sub-technique | Tactic | Confidence | Evidence Basis |
|---|---|---|---|---|---|
| FailedLoginBurstRule | T1110 | T1110.001 | TA0006 | high | Multiple failed auth attempts vs one account |
| PasswordSprayRule | T1110 | T1110.003 | TA0006 | high | One source IP vs multiple usernames |
| SuspiciousPowerShellRule | T1059 | T1059.001 | TA0002 | medium | PowerShell process with suspicious indicators |
| SuspiciousProcessTreeRule | T1204 User Execution | T1204.002 Malicious File | Execution | TA0002 | high (with file correlation) | Office → PowerShell + file activity correlation |
| C2BeaconRule | T1071 | (none) | TA0011 | high (with full context) | Periodic connections + non-standard port + suspicious process/raw IP |
