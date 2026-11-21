# SentinelForge AI — MITRE ATT&CK Mapping Quality Audit

**Project:** SentinelForge AI  
**Report:** SENTINELFORGE_MITRE_ATTACK_MAPPING_AUDIT.md  
**Audit Date:** 2026-11-19  
**Status:** READ-ONLY AUDIT — No source code modified  
**ATT&CK Reference:** MITRE ATT&CK Enterprise Knowledge Base (https://attack.mitre.org/), verified as of 2026-11-19

---

## 1. Executive Summary

SentinelForge AI implements MITRE ATT&CK mappings across all five detection rules. The mappings are **rule-level** (not event-level) — every detection from a given rule carries the same ATT&CK technique and tactic, regardless of the specific evidence. Mappings are stored as fixed metadata in each rule class and flow into detection result metadata, evaluation reports, and case studies.

**Overall assessment:** The mappings are generally accurate but inconsistently applied. Three of five rules map correctly; one (SuspiciousPowerShellRule) over-applies T1059.001 to all detections including potentially benign PowerShell usage; one (C2BeaconRule) correctly makes mapping conditional on additional evidence. No rule provides mapping confidence scores or explains *why* a particular ATT&CK technique was assigned.

---

## 2. Existing Implementation

All five detection rules define MITRE ATT&CK mappings as static metadata in their class definitions. The mappings are injected into every `DetectionResult.metadata` dictionary when an alert fires.

| Rule | Rule ID | MITRE Technique | Technique ID | Sub-technique | Sub-technique ID | Tactic | Tactic ID |
|---|---|---|---|---|---|---|---|
| FailedLoginBurstRule | sentinelforge.detection.failed_login_burst | Brute Force | T1110 | Password Guessing | T1110.001 | Credential Access | TA0006 |
| PasswordSprayRule | sentinelforge.detection.password_spray | Password Spraying | T1110.003 | (none) | (none) | Credential Access | TA0006 |
| SuspiciousPowerShellRule | sentinelforge.detection.suspicious_powershell | PowerShell | T1059.001 | (none) | (none) | Execution | TA0002 |
| SuspiciousProcessTreeRule | sentinelforge.detection.suspicious_processtree | User Execution | T1204 | Malicious File | T1204.002 | Initial Access | TA0001 |
| C2BeaconRule | sentinelforge.detection.c2_beacon | Application Layer Protocol | T1071 | (none) | (none) | Command and Control | TA0011 |

**Where mappings are defined:** Hardcoded in each rule class's `metadata` default factory.

**Where mappings appear:**
- `DetectionResult.metadata` dict (every alert)
- Evaluation reports (`validate_detection_quality.py`, `validate_soc_usefulness.py`)
- M8.3.6 baseline audit report
- SOC case studies

**Mapping type:** Fixed rule-level association. Every detection from a rule receives the same ATT&CK mapping regardless of individual event evidence. Exceptions:
- `C2BeaconRule`: Mapping is **conditional** — only applied when `_has_c2_context_evidence()` returns True (app-layer protocol + non-standard port + suspicious process/raw IP context)
- `SuspiciousProcessTreeRule`: Mapping is **conditional** — only applied when correlated file activity is found (`_has_correlated_file_activity()` returns True)

---

## 3. Rule-by-Rule Mapping Accuracy Assessment

### 3.1 FailedLoginBurstRule — T1110 / T1110.001 / Credential Access

**Verdict:** ACCURATE

**Reasoning:** The rule detects multiple failed authentication attempts from a source IP against one or more accounts within a time window. This is the canonical definition of brute force / password guessing against live authentication services (T1110). The sub-technique T1110.001 (Password Guessing) specifically covers "adversaries may guess or brute force credentials..." against interactive logon services. Since the rule operates against live SSH authentication events (not offline password cracking), T1110.001 is the correct sub-technique.

**Confidence:** High — the detected behavior directly matches the technique definition.

---

### 3.2 PasswordSprayRule — T1110.003 / Credential Access

**Verdict:** ACCURATE

**Reasoning:** The rule detects one source IP attempting authentication against multiple distinct usernames within a time window. This is the precise definition of password spraying (T1110.003): "Adversaries may attempt to login to multiple accounts with a small number of passwords..." The rule requires multiple distinct usernames from one source, which is the distinguishing characteristic of password spraying versus brute force.

**Confidence:** High — exact technique match.

---

### 3.3 SuspiciousPowerShellRule — T1059.001 / Execution

**Verdict:** PARTIALLY ACCURATE — POTENTIALLY OVER-BROAD

**Reasoning:** T1059.001 (PowerShell) covers "Adversaries may abuse PowerShell commands and scripts for execution." The rule detects PowerShell processes with indicators such as encoded commands, execution policy bypass, download-and-execute, and obfuscation.

**Problem:** The rule maps **every** detection to T1059.001 regardless of indicator weight. A PowerShell command with only a low-weight indicator (e.g., `-encodedcommand` weight 6, threshold 4) could trigger. However, benign administrative PowerShell usage (Get-Process, signed scripts with RemoteSigned policy) is explicitly excluded by the rule's indicator design — benign usage typically doesn't contain execution policy bypass or encoded commands.

**Residual concern:** The rule flags PowerShell with `-EncodedCommand` even if the encoded command is benign (e.g., an admin encoding a harmless command for obfuscation-free transport). T1059.001 correctly covers PowerShell execution, but the rule cannot distinguish malicious from benign encoded commands without decoding them (which the architecture explicitly avoids — log content is treated as untrusted text only).

**Confidence:** Medium — technique is correct for PowerShell execution generally, but not all flagged events are necessarily malicious.

---

### 3.4 SuspiciousProcessTreeRule — T1204 / T1204.002 / Initial Access

**Verdict:** ACCURATE WHEN CONDITIONS MET

**Reasoning:** T1204.002 (Malicious File) covers "Adversaries may rely upon a user opening a malicious file to execute code on a local system." The rule detects Office applications (WINWORD.EXE, EXCEL.EXE) spawning PowerShell — a classic initial access vector via malicious Office documents.

**Key safeguard:** The rule only applies the T1204.002 mapping when cross-event correlation is found — a file activity event (create/download/open) must be correlated with the process execution on the same host and user within a time window. Without this correlation, the ATT&CK mapping is left **empty**. This is the correct approach: a process tree relationship alone is suspicious context, not confirmed T1204.002.

**Confidence:** High when correlation evidence exists; appropriately unmapped when it doesn't.

---

### 3.5 C2BeaconRule — T1071 / Command and Control

**Verdict:** ACCURATE WHEN CONDITIONS MET

**Reasoning:** T1071 (Application Layer Protocol) covers "Adversaries may communicate using application layer protocols to avoid detection..." The rule detects periodic outbound connections (beaconing patterns) and only applies the T1071 mapping when:
1. An application-layer protocol is present (HTTP, HTTPS, DNS, etc.)
2. The destination port is non-standard for that protocol
3. Additional suspicious context exists (suspicious process like powershell.exe/cmd.exe, OR raw IP destination)

**Key safeguard:** The rule explicitly states "Port deviation alone does NOT establish T1071." It requires both protocol + non-standard port + additional suspicious context. Periodic HTTPS to port 443 (standard) would NOT trigger T1071 mapping. This correctly avoids false attribution.

**Confidence:** High when all conditions are met; appropriately unmapped when they aren't.

---

## 4. Evidence Traceability Assessment

### 4.1 What analysts can see for each detection

| Field | Available | Source |
|---|---|---|
| Detection name | Yes | `rule_name` in `DetectionResult` |
| Severity | Yes | `severity` enum (INFO/LOW/MEDIUM/HIGH/CRITICAL) |
| Evidence summary | Yes | `Evidence` objects with `event_id`, `timestamp`, `user`, `host`, `source_address`, `raw` |
| MITRE ATT&CK tactic | Yes | `metadata.mitre_attack_tactic` (when mapped) |
| MITRE ATT&CK technique/sub-technique ID | Yes | `metadata.mitre_attack_technique`, `metadata.mitre_attack_subtechnique` (when mapped) |
| Reason for mapping | **No** — metadata contains IDs but no explanation of why |
| Supporting event evidence | Yes | `evidence` list with raw event payloads preserved verbatim |
| Mapping confidence/qualification | Partially — C2BeaconRule has `confirmation` field; SuspiciousProcessTreeRule has `confidence` field; other rules have neither |
| Investigation questions | Partially — C2BeaconRule has `investigation_recommendations`; other rules do not |

### 4.2 Evidence traceability gaps

1. **No mapping rationale:** Analysts see `mitre_attack_technique: "T1059.001"` but not *why* it was assigned (e.g., "PowerShell process with encoded command indicator").
2. **Inconsistent confidence reporting:** Only C2BeaconRule and SuspiciousProcessTreeRule provide confidence/qualification fields. FailedLoginBurstRule, PasswordSprayRule, and SuspiciousPowerShellRule do not.
3. **Inconsistent investigation guidance:** Only C2BeaconRule provides `investigation_recommendations`.
4. **Rule-level, not event-level mapping:** All detections from a rule share the same ATT&CK mapping, even when individual evidence events might suggest different techniques.

---

## 5. Incorrect or Unsupported Mappings

| Rule | Mapping | Issue | Severity |
|---|---|---|---|
| SuspiciousPowerShellRule | T1059.001 applied to ALL detections | Benign PowerShell with encoded command (e.g., admin encoding a harmless command) would be mapped to T1059.001 as if malicious. The rule cannot distinguish malicious from benign encoded PowerShell without decoding (which architecture prohibits). | Medium — potential false attribution |
| C2BeaconRule | T1071 only with full context | Correctly conditional. No incorrect mappings observed. | Low |
| SuspiciousProcessTreeRule | T1204.002 only with file correlation | Correctly conditional. No incorrect mappings observed. | Low |
| FailedLoginBurstRule | T1110.001 applied to ALL detections | Correct — all failed auth bursts against live services are password guessing. | Low |
| PasswordSprayRule | T1110.003 applied to ALL detections | Correct — all detections are by definition password spraying. | Low |

---

## 6. Recommended Improvements

### Priority 1: Add mapping confidence and rationale (Highest value, lowest effort)

For each detection result, add optional fields to `metadata`:
- `mitre_attack_mapping_confidence`: "high" | "medium" | "low"
- `mitre_attack_mapping_rationale`: Short string explaining why this technique was assigned (e.g., "PowerShell process with execution policy bypass indicator", "Periodic HTTPS to non-standard port with suspicious process")

This applies to all five rules and requires no changes to detection logic — only to metadata population.

### Priority 2: Add investigation recommendations (Medium value)

Each rule should provide rule-specific investigation next steps in metadata, similar to C2BeaconRule's existing `investigation_recommendations` field.

### Priority 3: Consider event-level MITRE mapping (Lower value, higher complexity)

Currently mappings are rule-level. A more advanced approach would map individual evidence events to techniques based on their content. For example, a PowerShell event with `-EncodedCommand` maps to T1059.001, while a PowerShell event with only `-NoProfile` might not. This requires per-event analysis and is recommended for M9+, not the current prototype.

### What NOT to do

- **Do not** map every PowerShell execution to T1059.001 without considering indicator weight (already partially addressed by threshold, but confidence scoring would help)
- **Do not** represent ATT&CK tactics as a confirmed chronological attack sequence — they describe adversary objectives, not execution order
- **Do not** introduce AI/ML for ATT&CK mapping — keep it deterministic and evidence-grounded
- **Do not** claim confirmed C2 when only periodic connections are detected — C2BeaconRule already handles this correctly

---

## 7. Proposed Implementation Plan

### Phase 1: Mapping confidence and rationale (Immediate)

For each rule, add to `DetectionResult.metadata`:
- `mitre_attack_mapping_confidence`: "high" | "medium" | "low"
- `mitre_attack_mapping_rationale`: Short human-readable string

**Rule-specific rationale examples:**
- FailedLoginBurstRule: "Multiple failed authentication attempts against live accounts — password guessing"
- PasswordSprayRule: "One source IP targeting multiple distinct usernames — password spraying"
- SuspiciousPowerShellRule: "PowerShell process with [indicators] detected — PowerShell execution"
- SuspiciousProcessTreeRule: "Office application spawned PowerShell — possible malicious file execution"
- C2BeaconRule: "Periodic connections to [IP]:[port] with [process] — potential C2 beaconing"

### Phase 2: Investigation recommendations (Immediate)

Add `investigation_recommendations` to all rules, similar to C2BeaconRule's existing field:
- FailedLoginBurstRule: "Check for successful logins from source IP; review account lockout policies; block source IP at firewall"
- PasswordSprayRule: "Check for successful logins from source IP against targeted accounts; force password reset; block source IP"
- SuspiciousPowerShellRule: "Decode encoded commands; check user account activity; review PowerShell transcription logs"
- SuspiciousProcessTreeRule: "Check email attachments and web downloads; review parent process context; isolate host if malicious"
- C2BeaconRule: (Already implemented)

### Phase 3: Documentation update (Immediate)

Update `SENTINELFORGE_ARCHITECTURE.md` and `SENTINELFORGE_PROJECT_OVERVIEW.md` to document:
- Which ATT&CK techniques each rule maps to
- That mappings are candidate attributions, not confirmed classifications
- How analysts should interpret mapping confidence

### Phase 4: Testing (Immediate)

Add unit tests for mapping confidence and rationale:
- Verify each rule produces expected `mitre_attack_mapping_confidence` and `mitre_attack_mapping_rationale` fields
- Verify C2BeaconRule does not apply T1071 when conditions aren't met
- Verify SuspiciousProcessTreeRule does not apply T1204.002 without file correlation

---

## 8. Tests Required

| Test | Rule | Expected Behavior |
|---|---|---|
| `test_mitre_mapping_confidence_failed_login` | FailedLoginBurstRule | Every detection has `mitre_attack_mapping_confidence` = "high" |
| `test_mitre_mapping_confidence_password_spray` | PasswordSprayRule | Every detection has `mitre_attack_mapping_confidence` = "high" |
| `test_mitre_mapping_confidence_powershell` | SuspiciousPowerShellRule | Every detection has `mitre_attack_mapping_confidence` = "medium" |
| `test_mitre_mapping_confidence_processtree` | SuspiciousProcessTreeRule | Detection with file correlation = "high"; without = "low" or unmapped |
| `test_mitre_mapping_confidence_c2beacon` | C2BeaconRule | Detection with full context = "high"; without = unmapped |
| `test_mitre_rationale_present` | All rules | Every detection has `mitre_attack_mapping_rationale` string |
| `test_c2_no_mapping_without_context` | C2BeaconRule | Detection on standard port 443 has no T1071 mapping |
| `test_processtree_no_mapping_without_file` | SuspiciousProcessTreeRule | Detection without file correlation has no T1204.002 mapping |

---

## 9. Final Recommendation

**SentinelForge AI's MITRE ATT&CK implementation is sound but incomplete.**

The mappings themselves are accurate:
- T1110/T1110.001 for failed login bursts — correct
- T1110.003 for password spraying — correct
- T1059.001 for PowerShell — correct for technique, but applied uniformly without confidence grading
- T1204/T1204.002 for process trees — correct when file correlation exists (correctly conditional)
- T1071 for C2 beaconing — correct when full context exists (correctly conditional)

**The critical gap is not mapping accuracy but mapping transparency.** Analysts see technique IDs without understanding *why* they were assigned or how confident the rule is. Adding mapping confidence, rationale, and investigation recommendations to every detection would significantly improve analyst usefulness without requiring new detection logic or AI dependencies.

**Implement Phase 1 and Phase 2 immediately.** These are low-risk, deterministic additions that preserve the project's evidence-first philosophy while making ATT&CK mappings actionable for SOC analysts.

**Do not** implement event-level ATT&CK mapping or AI-assisted mapping at this stage — the current rule-level approach with added confidence scoring is sufficient for a demonstration prototype.

---

## Appendix: Rule-by-Rule Summary

| Rule | Technique | Confidence Model | Mapping Applied When | Analyst Can See |
|---|---|---|---|---|
| FailedLoginBurstRule | T1110/T1110.001 | Fixed (always) | Every detection | Name, severity, evidence, tactic, technique ID |
| PasswordSprayRule | T1110.003 | Fixed (always) | Every detection | Name, severity, evidence, tactic, technique ID |
| SuspiciousPowerShellRule | T1059.001 | Fixed (always) | Every detection | Name, severity, evidence, tactic, technique ID, indicators |
| SuspiciousProcessTreeRule | T1204/T1204.002 | Conditional (file correlation) | Only with file activity evidence | Name, severity, evidence, tactic, technique ID, confidence, parent/child PID |
| C2BeaconRule | T1071 | Conditional (protocol + port + context) | Only with full C2 context | Name, severity, evidence, tactic, technique ID, confirmation, investigation recommendations |