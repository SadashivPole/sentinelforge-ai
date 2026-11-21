# SentinelForge AI — MITRE ATT&CK Implementation Roadmap

**Project:** SentinelForge AI  
**Document:** SENTINELFORGE_MITRE_ATTACK_IMPLEMENTATION_ROADMAP.md  
**Version:** 0.2.0 (design proposal — corrected and final review)  
**Status:** Draft — awaiting review  
**ATT&CK Reference:** Enterprise v20.1 (https://attack.mitre.org/)  
**Restrictions:** Read-only design. No implementation of 70–130 techniques. No detection threshold changes. No modification to existing datasets, ground truth, or reports. No M9 work.

---

## 1. Purpose

This document defines a phased implementation roadmap for expanding SentinelForge AI's MITRE ATT&CK coverage from 5 techniques (current) to a curated catalogue of ~70 techniques. Each phase preserves backward compatibility, requires no new telemetry infrastructure unless stated, and never alters existing detection thresholds or historical data.

---

## 2. Current State

| Metric | Current Value |
|---|---|
| Total catalogue techniques | 5 (implicit, via rule metadata only) |
| Techniques with detection rules | 5 |
| Techniques with mapping confidence | 0 (no confidence field) |
| Techniques with mapping rationale | 0 (no rationale field) |
| Techniques with investigation recommendations | 1 (C2BeaconRule only) |
| SQLite schema version | 3 |
| Test count | 208 passed |

---

## 3. Roadmap Overview

| Phase | Duration | Techniques Impact | Deliverable |
|---|---|---|---|
| Phase 1 | Immediate | 0 new techniques (reclassifies existing 5) | Catalogue data model + confidence/rationale for existing rules |
| Phase 2 | Short-term | 0 new techniques | Coverage reporting + ATT&CK Navigator layer |
| Phase 3 | Medium-term | +5–10 techniques | PARTIALLY_SUPPORTED techniques from available telemetry |
| Phase 4 | Medium-term | +3–5 new detection rules | New detection rules for techniques with available telemetry |
| Phase 5 | Long-term | +50–60 techniques | Remaining catalogue entries (IMPLEMENTED_NEEDS_VALIDATION + UNSUPPORTED) |

**Total target:** ~70 techniques in catalogue; ~10–15 with detection rules; ~10 PARTIALLY_SUPPORTED; remainder planned/unsupported.

---

## 4. Phase 1 — Catalogue Data Model & Existing Rule Enhancement

**Goal:** Establish the ATT&CK catalogue data model and add mapping confidence/rationale to the 5 existing detection rules.

### 4.1 Scope

- Create `sentinelforge/attack/catalogue.py` — ATTACKCatalogue class loading technique entries from a JSON manifest
- Create `sentinelforge/attack/mapper.py` — ATTACKMapper class mapping DetectionResult metadata to catalogue entries
- Create `sentinelforge/attack/coverage.py` — CoverageReporter class computing coverage statistics
- Create `sentinelforge/attack/validator.py` — MappingValidator for technique ID validation
- Create `sentinelforge/attack/__init__.py`
- Add technique catalogue JSON manifest (starting with 5 techniques)
- Add ATT&CK metadata fields to DetectionResult.metadata for existing 5 rules:
  - `mitre_attack_technique`, `mitre_attack_subtechnique`, `mitre_attack_tactic`
  - `mitre_attack_mapping_confidence`
  - `mitre_attack_mapping_rationale`
  - `mitre_attack_investigation_recommendations`
- Add tests: technique ID validation, sub-technique relationships, tactic associations, version consistency, duplicate rejection

### 4.2 Deliverables

| File | Description |
|---|---|
| `sentinelforge/attack/catalogue.py` | Technique catalogue registry |
| `sentinelforge/attack/mapper.py` | Detection-to-technique mapping |
| `sentinelforge/attack/coverage.py` | Coverage statistics computation |
| `sentinelforge/attack/validator.py` | ATT&CK identifier validation |
| `sentinelforge/attack/catalogue.json` | Initial catalogue with 5 techniques |
| `tests/test_attack_catalogue.py` | Catalogue validation tests |

### 4.3 Constraints Honored

- No detection threshold changes
- No SQLite schema changes (metadata stored in existing JSON column)
- No historical dataset modification
- No ground truth modification

---

## 5. Phase 2 — Coverage Reporting & ATT&CK Navigator Layer

**Goal:** Enable analysts to see ATT&CK coverage across tactics and export Navigator-compatible layers.

### 5.1 Scope

- Extend `coverage.py` with report generation:
  - Coverage by tactic
  - Coverage by log source
  - Detection-to-technique relationships
  - Coverage gaps
- Generate ATT&CK Navigator-compatible layer JSON containing **only** IMPLEMENTED_AND_TESTED techniques
- Add CLI command or script for coverage report generation
- Add tests: coverage report calculations, Navigator layer generation, unsupported technique exclusion

### 5.2 Deliverables

| File | Description |
|---|---|
| `sentinelforge/attack/report.py` | Coverage report generation |
| `sentinelforge/attack/navigator.py` | ATT&CK Navigator layer generation |
| `tests/test_attack_coverage.py` | Coverage reporting tests |
| `scripts/generate_coverage_report.py` | CLI entry point (optional) |

### 5.3 Constraints Honored

- Planned/UNSUPPORTED techniques excluded from Navigator layer
- No historical dataset modification
- No M9 work

---

## 6. Phase 3 — PARTIALLY_SUPPORTED Techniques from Available Telemetry

**Goal:** Add techniques that have available telemetry but no detection rule yet, marked as PARTIALLY_SUPPORTED.

### 6.1 Candidate Techniques

| Technique | ID | Tactic | Evidence Basis | Estimated Effort |
|---|---|---|---|---|
| Network Service Scanning | T1046 | Discovery | network.remote_address, network.remote_port, network.direction available | Low (rule only) |
| Valid Accounts | T1078 | Credential Access | authentication.outcome, authentication.username available | Low (rule only) |
| SSH Lateral Movement | T1021.002 | Lateral Movement | network.remote_port=22, authentication available | Low (rule only) |
|| Windows Command Shell | T1059.003 | Execution | process.name, process.command_line available | Medium (rule + threshold tuning) ||
|| Unix Shell | T1059.004 | Execution | process.name, process.command_line available | Medium (rule + threshold tuning) ||
| Account Discovery | T1087 | Discovery | authentication.username, process.command_line available | Medium (rule + threshold tuning) |

### 6.2 Scope

- Add 6–10 technique entries to catalogue.json with detection_status = PARTIALLY_SUPPORTED
- Write detection rules for techniques marked IMPLEMENTED_NEEDS_VALIDATION
- Add tests for new rules
- Update coverage report to include new techniques

### 6.3 Deliverables

| File | Description |
|---|---|
| `sentinelforge/detection/network_scanning.py` | NetworkServiceScanningRule (T1046) |
| `sentinelforge/detection/valid_accounts.py` | ValidAccountsRule (T1078) |
| `sentinelforge/detection/ssh_lateral_movement.py` | SSHLateralMovementRule (T1021.002) |
| `tests/test_detection_network_scanning.py` | Tests for T1046 rule |
| `tests/test_detection_valid_accounts.py` | Tests for T1078 rule |
| `tests/test_detection_ssh_lateral.py` | Tests for T1021.002 rule |

### 6.3 Constraints Honored

- No detection threshold changes to existing rules
- New rules use configurable thresholds via SENTINELFORGE_* environment variables
- No historical dataset modification

---

## 7. Phase 4 — New Detection Rules for Available Telemetry

**Goal:** Implement detection rules for techniques where telemetry exists but no rule currently exists.

### 7.1 Candidate Techniques

| Technique | ID | Tactic | Missing Rule | Estimated Effort |
|---|---|---|---|---|
| File and Directory Discovery | T1083 | Discovery | FileCreateDiscoveryRule | Medium |
| Data from Local System | T1005 | Collection | LocalSystemCollectionRule | Medium |
| Data Encrypted for Impact | T1486 | Impact | DataEncryptionRule | Medium |
| PowerShell (refined) | T1059.001 | Execution | Refined PowerShell rule with confidence levels | Low |

### 7.2 Scope

- Write 3–4 new detection rules using existing normalized fields
- Add mapping confidence/rationale for each new rule
- Add tests for each new rule
- Update catalogue.json with new technique entries

### 7.2 Deliverables

| File | Description |
|---|---|
| `sentinelforge/detection/file_discovery.py` | FileDirectoryDiscoveryRule (T1083) |
| `sentinelforge/detection/local_collection.py` | LocalSystemCollectionRule (T1005) |
| `sentinelforge/detection/data_encryption.py` | DataEncryptionRule (T1486) |
| `tests/test_detection_file_discovery.py` | Tests for T1083 rule |
| `tests/test_detection_local_collection.py` | Tests for T1005 rule |
| `tests/test_detection_data_encryption.py` | Tests for T1486 rule |

### 7.3 Constraints Honored

- No detection threshold changes to existing rules
- No historical dataset modification
- No ground truth modification

---

## 8. Phase 5 — Remaining Catalogue Entries

**Goal:** Complete the 85–100 technique catalogue with IMPLEMENTED_NEEDS_VALIDATION and UNSUPPORTED_BY_CURRENT_TELEMETRY entries.

### 8.1 Scope

- Add remaining techniques to catalogue.json
- Mark techniques without detection rules as IMPLEMENTED_NEEDS_VALIDATION (if telemetry exists) or UNSUPPORTED_BY_CURRENT_TELEMETRY (if telemetry is missing)
- No new detection rules in this phase
- Update coverage report

### 8.2 Deliverables

| File | Description |
|---|---|
|| `sentinelforge/attack/catalogue.json` | Complete catalogue (~70 techniques) ||
|| `tests/test_attack_catalogue_completeness.py` | Catalogue size and coverage tests ||

---

## 9. Database & Schema Impact

| Phase | Schema Changes Required | Migration Needed? |
|---|---|---|
| Phase 1 | None (metadata stored in existing JSON column) | No |
| Phase 2 | None | No |
| Phase 3 | None | No |
| Phase 4 | None | No |
| Phase 5 | None | No |

**All ATT&CK metadata is stored as JSON keys within the existing `detections.metadata` column.** No new tables, no new columns, no schema migrations. Existing SQLite records are never modified.

---

## 10. Test Requirements by Phase

| Phase | Test Files | Test Count Estimate |
|---|---|---|
| Phase 1 | tests/test_attack_catalogue.py | 15–20 |
| Phase 2 | tests/test_attack_coverage.py | 10–15 |
| Phase 3 | tests/test_detection_network_scanning.py, tests/test_detection_valid_accounts.py, tests/test_detection_ssh_lateral.py | 25–35 |
| Phase 4 | tests/test_detection_file_discovery.py, tests/test_detection_local_collection.py, tests/test_detection_data_encryption.py | 25–35 |
| Phase 5 | tests/test_attack_catalogue_completeness.py | 5–10 |

**Total new tests:** ~80–110

### 10.1 Test Categories

| Category | Test Example | Expected Behavior |
|---|---|---|
| Valid ATT&CK identifiers | test_mitre_technique_id_valid | Every technique_id matches `^T\d{4}(\.\d{3})?$` |
| Technique-sub-technique relationships | test_mitre_subtechnique_relationship | Sub-technique references existing parent |
| Tactic associations | test_mitre_tactic_association | Tactic_id matches `^TA\d{4}$` |
| Version consistency | test_mitre_attack_version | attack_version == "2024.10" |
| Duplicate rejection | test_no_duplicate_technique_ids | No duplicate technique_id entries |
| Unsupported exclusion | test_unsupported_technique_not_detected | Non-implemented techniques excluded from Navigator layer |
| Detection-to-technique | test_detection_to_technique_relationship | Every MITRE-mapped detection has catalogue entry |
| Evidence traceability | test_evidence_traceability | Every MITRE-mapped detection has evidence events |
| Confidence validation | test_mapping_confidence_validation | Valid confidence values present |
| Rationale present | test_mapping_rationale_present | Non-empty rationale for every mapping |
| Coverage calculations | test_coverage_report_calculations | Report counts match catalogue statistics |

---

## 11. Out of Scope

| Item | Reason |
|---|---|
| Full 70–130 detection rule implementation | Would require new telemetry sources not currently normalized |
| ATT&CK Navigator layer generation code | Design only in Phase 2 |
| Integration with external threat intelligence feeds | Out of scope for MVP |
| Changes to existing detection rule thresholds | Explicitly prohibited |
| Modification of historical datasets or ground truth | Explicitly prohibited |
| Modification of EvidenceForge or any external project | External project not referenced |
| M9 work | Explicitly prohibited |
| SQLite schema changes | Not needed (metadata in existing JSON column) |

---

## 12. Success Criteria

| Criterion | Measurement |
|---|---|
|| Catalogue contains ~70 techniques | catalogue.json entry count ||
|| At least 10 techniques are IMPLEMENTED_AND_TESTED | detection_status field ||
|| At least 10 techniques are PARTIALLY_SUPPORTED | detection_status field ||
| All existing 5 rules have mapping confidence/rationale | metadata field check |
| Coverage report generates without errors | CLI/script execution |
| ATT&CK Navigator layer excludes non-implemented techniques | Layer JSON validation |
| All new tests pass | pytest run |
| PRAGMA integrity_check = ok | Database validation |
| Existing 208 tests still pass | Regression test run |

---

## 13. Recommendation

**Phase 1 is the only phase recommended for immediate implementation.** It establishes the ATT&CK catalogue data model and adds mapping confidence/rationale to the existing 5 rules without changing any detection behavior. Phases 2–5 should be considered only after Phase 1 is reviewed and approved.

**Do not proceed beyond Phase 1 without user review.** The decision between 70, 100, or 130 techniques as the final catalogue size should be made after Phase 1 is complete and the actual telemetry limitations are understood by stakeholders.

---

## 14. Appendix: Current MITRE ATT&CK Mapping Summary (for reference)

| Rule | Technique | Sub-technique | Tactic | Confidence | Evidence Basis |
|---|---|---|---|---|---|
| FailedLoginBurstRule | T1110 | T1110.001 | TA0006 | high | Multiple failed auth attempts vs one account |
| PasswordSprayRule | T1110 | T1110.003 | TA0006 | high | One source IP vs multiple usernames |
| SuspiciousPowerShellRule | T1059 | T1059.001 | TA0002 | medium | PowerShell process with suspicious indicators |
| SuspiciousProcessTreeRule | T1204 | T1204.002 | TA0002 | high (with file correlation) | Office → PowerShell + file activity correlation |
| C2BeaconRule | T1071 | (none) | TA0011 | high (with full context) | Periodic connections + non-standard port + suspicious process/raw IP |
