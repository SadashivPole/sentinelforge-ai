# SentinelForge AI — MITRE ATT&CK 70–130 Technique Catalogue Plan

**Project:** SentinelForge AI  
**Document:** SENTINELFORGE_MITRE_ATTACK_70_130_TECHNIQUE_CATALOGUE_PLAN.md  
**Version:** 0.2.0 (design proposal — corrected and final review)  
**Status:** Draft — awaiting review  
**ATT&CK Reference:** Enterprise v20.1 (https://attack.mitre.org/)  
**Restrictions:** Read-only design. No implementation of 70–130 techniques. No detection threshold changes. No modification to existing datasets.

---

## 1. Purpose

This document defines the technique selection methodology and presents a **sample catalogue** of representative MITRE ATT&CK Enterprise techniques and sub-techniques that could be mapped to SentinelForge AI detections. The catalogue is illustrative — it shows the structure, selection criteria, and telemetry coverage assessment format. It is **not** a proposal to implement 70–130 detection rules.

---

## 2. Technique Selection Methodology

### 2.1 Selection Criteria (applied in order of priority)

| Criterion | Weight | Description |
|---|---|---|
| Telemetry coverage | High | Does SentinelForge's normalized schema contain the fields needed to detect this technique? (See telemetry matrix below.) |
| Detection feasibility | High | Can a deterministic rule be written that produces actionable alerts with acceptable false-positive rates? |
| SOC investigation value | High | Would a SOC analyst benefit from knowing this technique was detected? |
| Tactic diversity | Medium | Coverage across all 15 ATT&CK tactics, not clustered in one area. |
| Technique vs. sub-technique balance | Medium | Prefer sub-techniques where they add specificity; parent techniques only when sub-techniques add no value. |

### 2.2 Counting Rules

- Each MITRE ATT&CK technique ID (e.g., T1110) and sub-technique ID (e.g., T1110.001) counts as **one** entry toward the 70–130 total.
- Parent techniques are counted **only** when they add information not covered by their sub-techniques.
- Deprecated or revoked techniques are **excluded**.
- Techniques with `detection_status: "UNSUPPORTED_BY_CURRENT_TELEMETRY"` are included in the catalogue but explicitly excluded from coverage reporting.

### 2.3 Target Distribution (70–130 techniques)

|| Tactic | Recommended Count | Rationale ||
||---|---|---||
|| Initial Access (TA0001) | 10–15 | High SOC value, multiple detection paths ||
|| Execution (TA0002) | 10–15 | Core to PowerShell, process tree rules ||
|| Persistence (TA0003) | 5–8 | Limited by Sysmon telemetry ||
|| Privilege Escalation (TA0004) | 3–5 | Limited telemetry ||
|| Stealth (TA0005) | 3–5 | Hiding and concealing actions, appearing as normal behavior ||
|| Defense Impairment (TA0112) | 3–5 | Breaking security mechanisms, pipelines, and tooling ||
|| Credential Access (TA0006) | 8–12 | Two existing rules cover this well ||
|| Discovery (TA0007) | 8–12 | Network and process telemetry supports this ||
|| Lateral Movement (TA0008) | 5–8 | Network correlation possible ||
|| Collection (TA0009) | 3–5 | File create (Event ID 11) supports some ||
|| Command and Control (TA0011) | 8–12 | C2BeaconRule covers this ||
|| Exfiltration (TA0010) | 3–5 | Limited telemetry ||
|| Impact (TA0040) | 3–5 | Limited telemetry ||
|| Reconnaissance (TA0043) | 3–5 | Network scanning possible ||
|| Resource Development (TA0042) | 0–3 | Mostly pre-attack, limited telemetry ||
|| **Total** | **70–130** | ||

**Recommended initial scope: approximately 70 curated techniques.** This is the minimum viable catalogue that spans all 15 v20.1 tactics while keeping the majority of entries as techniques with available telemetry. A larger catalogue (85–100 or 130) forces inclusion of many techniques with no available telemetry, resulting in a catalogue dominated by `UNSUPPORTED_BY_CURRENT_TELEMETRY` entries that provide no analyst value.

Quantitative breakdown for ~70 curated entries:

| Metric | Count | Basis |
|---|---|---|
| Total catalogue entries | ~70 | User-directed starting scope |
| Unique technique IDs | ~70 | Each technique/sub-technique ID counts as one entry |
| Implemented and tested | 5 | Existing rules: T1110.001, T1110.003, T1059.001, T1204.002, T1071 |
| Partially supported | ~6 | Available telemetry but no detection rule yet: T1046, T1078, T1021.002 (SSH), T1059.003, T1059.004, T1087 |
| Planned | ~8 | Techniques with detection value but requiring new telemetry or normalization |
| Unsupported by current telemetry | ~51 | Techniques that cannot be detected with current normalized fields |
| Techniques with usable telemetry today | ~11 | 5 implemented + ~6 partially supported |
| Techniques requiring additional normalization or new log sources | ~59 | Remaining catalogue entries |

**Why ~70 is defensible:**
- Current detection coverage is 5 techniques across 4 tactics (Credential Access, Execution, Command and Control). Expanding to 70 curated entries provides coverage across all 15 tactics while keeping the unsupported portion manageable (~73%).
- 130 entries would mean ~125 unsupported techniques — a catalogue that is 96% unimplemented, which misleads analysts about actual detection capability.
- The catalogue is designed to expand as telemetry and detection engineering mature. Start with 70, add techniques as detection rules are implemented.

Do not use the number of catalogue entries as a detection-coverage metric. Catalogue size reflects the reference inventory, not the number of techniques SentinelForge can actually detect.

---

## 3. Sample Catalogue: Representative Techniques (First 25)

The following 25 techniques are presented as a **representative sample** of what a 70–130 catalogue would contain. Each entry includes:

- technique_id / technique_name
- tactic_ids / tactic_names
- subtechnique_parent_id (if applicable)
- applicable_log_sources (from SentinelForge's supported sources)
- required_telemetry (normalized fields needed)
- available_telemetry (subset actually present)
- associated_detection_rule_ids (current rules that could map)
- detection_status
- mapping_confidence
- mapping_rationale
- investigation_recommendations
- attack_version: "2024.10"
- source_url: MITRE ATT&CK URL

### 3.1 Credential Access (TA0006)

#### T1110 — Brute Force
| Field | Value |
|---|---|
| technique_id | T1110 |
| technique_name | Brute Force |
| tactic_ids | ["TA0006"] |
| tactic_names | ["Credential Access"] |
| subtechnique_parent_id | null |
| platforms | ["linux", "windows", "macos"] |
| attack_version | "v20.1" |
| source_url | https://attack.mitre.org/techniques/T1110/ |
| applicable_log_sources | ["linux_auth", "windows_sysmon"] |
| required_telemetry | ["authentication.outcome", "authentication.username", "authentication.source_address", "host", "timestamp"] |
| available_telemetry | ["authentication.outcome", "authentication.username", "authentication.source_address", "host", "timestamp"] |
| associated_detection_rule_ids | ["sentinelforge.detection.failed_login_burst"] |
| detection_status | IMPLEMENTED_AND_TESTED |
| mapping_confidence | high |
| mapping_rationale | Multiple failed authentication attempts against live accounts is the canonical definition of password guessing/brute force. |
| investigation_recommendations | ["Check for successful logins from source IP", "Review account lockout policies", "Identify targeted accounts"] |
| validation_status | validated |
| last_reviewed | 2026-11-19 |

#### T1110.003 — Password Spraying
| Field | Value |
|---|---|
| technique_id | T1110.003 |
| technique_name | Password Spraying |
| tactic_ids | ["TA0006"] |
| tactic_names | ["Credential Access"] |
| subtechnique_parent_id | T1110 |
| platforms | ["linux", "windows"] |
| attack_version | "v20.1" |
| source_url | https://attack.mitre.org/techniques/T1110/003/ |
| applicable_log_sources | ["linux_auth", "windows_sysmon"] |
| required_telemetry | ["authentication.outcome", "authentication.username", "authentication.source_address", "host", "timestamp"] |
| available_telemetry | ["authentication.outcome", "authentication.username", "authentication.source_address", "host", "timestamp"] |
| associated_detection_rule_ids | ["sentinelforge.detection.password_spray"] |
| detection_status | IMPLEMENTED_AND_TESTED |
| mapping_confidence | high |
| mapping_rationale | One source IP attempting authentication against multiple distinct usernames is the exact definition of password spraying. |
| investigation_recommendations | ["Check for successful logins from source IP against targeted accounts", "Force password reset for targeted accounts", "Review account lockout thresholds"] |
| validation_status | validated |
| last_reviewed | 2026-11-19 |

### 3.2 Execution (TA0002)

#### T1059.001 — PowerShell
| Field | Value |
|---|---|
| technique_id | T1059.001 |
| technique_name | PowerShell |
| tactic_ids | ["TA0002"] |
| tactic_names | ["Execution"] |
| subtechnique_parent_id | T1059 |
| platforms | ["windows"] |
| attack_version | "v20.1" |
| source_url | https://attack.mitre.org/techniques/T1059/001/ |
| applicable_log_sources | ["windows_sysmon"] |
| required_telemetry | ["process.name", "process.command_line", "process.user", "process.host"] |
| available_telemetry | ["process.name", "process.command_line", "process.user", "process.host", "process.pid", "process.ppid"] |
| associated_detection_rule_ids | ["sentinelforge.detection.suspicious_powershell"] |
| detection_status | IMPLEMENTED_AND_TESTED |
| mapping_confidence | medium |
| mapping_rationale | PowerShell process execution with suspicious indicators (encoded command, execution policy bypass) is consistent with T1059.001, but benign administrative PowerShell usage can also contain encoded commands. |
| investigation_recommendations | ["Decode encoded commands", "Check user account activity", "Review PowerShell transcription logs", "Isolate host if command is malicious"] |
| validation_status | validated |
| last_reviewed | 2026-11-19 |

### 3.3 Initial Access (TA0001)

#### T1204.002 — Malicious File
| Field | Value |
|---|---|
| technique_id | T1204.002 |
| technique_name | Malicious File |
| tactic_ids | ["TA0002"] |
| tactic_names | ["Execution"] |
| subtechnique_parent_id | T1204 |
| platforms | ["windows", "macos", "linux"] |
| attack_version | "v20.1" |
| source_url | https://attack.mitre.org/techniques/T1204/002/ |
| applicable_log_sources | ["windows_sysmon"] |
| required_telemetry | ["process.name", "process.command_line", "process.parent.name", "process.parent.command_line", "process.pid", "process.ppid", "file.target_filename", "file.create.timestamp"] |
| available_telemetry | ["process.name", "process.command_line", "process.pid", "process.ppid", "process.user", "process.host", "network.remote_address", "network.remote_port"] |
| associated_detection_rule_ids | ["sentinelforge.detection.suspicious_processtree"] |
| detection_status | PARTIALLY_SUPPORTED |
| mapping_confidence | medium |
| mapping_rationale | Office application spawning PowerShell is consistent with T1204.002, but file hash verification and parent command line are not available in current telemetry. Correlation with file creation events provides supporting evidence. |
| investigation_recommendations | ["Check email attachments and web downloads", "Review parent process context", "Isolate host if malicious", "Check for additional spawned processes"] |
| validation_status | validated |
| last_reviewed | 2026-11-19 |

### 3.4 Command and Control (TA0011)

#### T1071 — Application Layer Protocol
| Field | Value |
|---|---|
| technique_id | T1071 |
| technique_name | Application Layer Protocol |
| tactic_ids | ["TA0011"] |
| tactic_names | ["Command and Control"] |
| subtechnique_parent_id | null |
| platforms | ["windows", "linux", "macos"] |
| attack_version | "v20.1" |
| source_url | https://attack.mitre.org/techniques/T1071/ |
| applicable_log_sources | ["windows_sysmon"] |
| required_telemetry | ["network.protocol", "network.remote_address", "network.remote_port", "network.direction", "process.name", "process.command_line", "host", "timestamp"] |
| available_telemetry | ["network.protocol", "network.remote_address", "network.remote_port", "network.direction", "process.name", "process.command_line", "host", "timestamp"] |
| associated_detection_rule_ids | ["sentinelforge.detection.c2_beacon"] |
| detection_status | PARTIALLY_SUPPORTED |
| mapping_confidence | medium |
| mapping_rationale | Periodic outbound connections with non-standard ports and suspicious process context are consistent with C2 beaconing, but legitimate periodic traffic (EDR heartbeats, software updates) can produce identical patterns. |
| investigation_recommendations | ["Correlate with process execution events on source host", "Check destination reputation", "Review command-line context", "Compare against baseline network behavior"] |
| validation_status | validated |
| last_reviewed | 2026-11-19 |

### 3.5 Discovery (TA0007)

#### T1046 — Network Service Scanning
| Field | Value |
|---|---|
| technique_id | T1046 |
| technique_name | Network Service Scanning |
| tactic_ids | ["TA0007"] |
| tactic_names | ["Discovery"] |
| subtechnique_parent_id | null |
| platforms | ["windows", "linux", "macos"] |
| attack_version | "v20.1" |
| source_url | https://attack.mitre.org/techniques/T1046/ |
| applicable_log_sources | ["windows_sysmon"] |
| required_telemetry | ["network.direction", "network.remote_address", "network.remote_port", "network.local_address", "network.local_port", "network.protocol", "host", "timestamp"] |
| available_telemetry | ["network.direction", "network.remote_address", "network.remote_port", "network.local_address", "network.local_port", "network.protocol", "host", "timestamp"] |
| associated_detection_rule_ids | [] |
| detection_status | UNSUPPORTED_BY_CURRENT_TELEMETRY |
| mapping_confidence | none |
| mapping_rationale | No detection rule exists for network service scanning. Sysmon Event ID 3 captures individual connections but no rule correlates them into scanning patterns. |
| investigation_recommendations | ["Review outbound connection patterns from hosts", "Identify hosts connecting to many different ports", "Check for port scanning behavior"] |
| validation_status | unvalidated |
| last_reviewed | 2026-11-19 |

---

## 4. Catalogue Selection Rationale (70–130 Techniques)

### 4.1 Techniques to Include in First ~70

The following technique categories are recommended for initial inclusion based on telemetry availability and detection value:

| Tactic | Techniques to Include | Rationale |
|---|---|---|
| Credential Access | T1110, T1110.001, T1110.003 | Two existing rules cover this well; password-related techniques are high-value |
| Execution | T1059, T1059.001, T1059.003, T1059.004, T1204, T1204.002 | PowerShell and process tree rules cover core execution techniques |
| Command and Control | T1071, T1071.001 | C2BeaconRule covers application layer protocols; HTTPS variant is conditionally detectable |
| Discovery | T1046, T1087 | Network service scanning and account discovery possible with Sysmon + auth telemetry |
| Initial Access | T1204, T1204.002 | User Execution with malicious file correlation |
| Lateral Movement | T1021, T1021.004 | Remote desktop and SSH possible with network + auth telemetry |
| Collection | T1005 | Data from local system possible with process + file telemetry |
| Exfiltration | T1041 | Exfiltration over C2 channel possible with network telemetry |
| Impact | T1486 | Data encrypted for impact possible with file + process telemetry |
| Persistence | T1547, T1547.001 | Boot or logon autostart execution, registry run keys |
| Privilege Escalation | T1078 | Valid credentials possible with auth telemetry |
| Stealth | — | No techniques with usable telemetry today |
| Defense Impairment | — | No techniques with usable telemetry today |
| Resource Development | — | Mostly pre-attack, limited telemetry |
| Reconnaissance | — | Network scanning possible but no rule exists |

### 4.2 Techniques to Mark as UNSUPPORTED_BY_CURRENT_TELEMETRY

| Technique | Reason |
|---|---|
| T1001 (Data Obfuscation) | No file content analysis capability |
| T1027 (Obfuscated Files or Information) | Cannot decode or analyze encoded file content |
| T1083 (File and Directory Discovery) | File system events beyond Sysmon Event ID 11 not normalized |
| T1098 (Account Manipulation) | No account creation/modification telemetry |
| T1562 (Impair Defenses) | No security tool disablement telemetry |
| T1490 (Inhibit System Recovery) | No system recovery inhibition telemetry |
| T1567 (Exfiltration Over Web Service) | No web proxy or cloud storage telemetry |

### 4.3 Why ~70 Techniques is the Recommended Scope

- **~70 techniques** is the recommended starting scope. It spans all 15 v20.1 tactics while keeping the unsupported portion manageable (~73% unsupported, ~27% with available telemetry). This provides a realistic reference inventory without overstating detection capability.
- **85–100 techniques** would add ~15–30 more entries, nearly all of which would be `UNSUPPORTED_BY_CURRENT_TELEMETRY`. This dilutes the catalogue with techniques that cannot be detected and provides no additional analyst value.
- **130 techniques** would mean ~125 unsupported techniques — a catalogue that is ~96% unimplemented, which actively misleads analysts about actual detection capability.

The catalogue is designed to expand as telemetry and detection engineering mature. Start with ~70 curated entries, add techniques as detection rules are implemented and telemetry is extended.

---

## 5. Implementation Roadmap Reference

| Phase | Action | Technique Count Impact |
|---|---|---|
| Phase 1 | Catalogue data model + mapping confidence/rationale for existing 5 rules | 0 new techniques (reclassifies existing 5) |
| Phase 2 | Coverage reporting + ATT&CK Navigator layer | 0 new techniques (reports on existing) |
| Phase 3 | Add 20–30 PARTIALLY_SUPPORTED techniques | +20–30 catalogue entries |
| Phase 4 | Implement 2–3 additional detection rules | +5–10 new IMPLEMENTED_AND_TESTED techniques |
| Phase 5 | Add remaining techniques to catalogue | +50–60 IMPLEMENTED_NEEDS_VALIDATION or UNSUPPORTED entries |

**Final recommendation: Target ~70 techniques in the initial catalogue.** This provides coverage across all 15 ATT&CK tactics while ensuring that ~11 entries have available telemetry (5 implemented and tested, ~6 partially supported) and the remaining ~59 are documented as unsupported with clear telemetry gaps.

---

## 6. Out of Scope

- Full implementation of 70–130 detection rules (would require new data sources not currently normalized)
- ATT&CK Navigator layer generation code (design only)
- Integration with external threat intelligence
- Changes to existing detection rules' thresholds or logic
- Modification of historical datasets or ground truth
- Modification of EvidenceForge or any external project

---

## 7. Appendix: Technique Selection Verification Against Current Telemetry

| Technique | Available Telemetry? | Detection Feasibility? | Recommended Status |
|---|---|---|---|
| T1110.001 Password Guessing | Yes (auth events) | Yes | IMPLEMENTED_AND_TESTED |
| T1110.003 Password Spraying | Yes (auth events) | Yes | IMPLEMENTED_AND_TESTED |
| T1059.001 PowerShell | Yes (Sysmon Event 1) | Yes | IMPLEMENTED_AND_TESTED |
| T1204.002 Malicious File | Partially (Sysmon Event 1 + file events) | Partial | PARTIALLY_SUPPORTED |
| T1071 Application Layer Protocol | Yes (Sysmon Event 3) | Yes | IMPLEMENTED_AND_TESTED |
| T1046 Network Service Scanning | Yes (Sysmon Event 3) | No rule exists | UNSUPPORTED_BY_CURRENT_TELEMETRY |
| T1021 Remote Desktop Protocol | Partially (Sysmon Event 3) | No rule exists | UNSUPPORTED_BY_CURRENT_TELEMETRY |
| T1078 Valid Accounts | Partially (auth events) | No rule exists | UNSUPPORTED_BY_CURRENT_TELEMETRY |
| T1547.001 Boot or Logon Autostart Execution | No (registry/file system telemetry missing) | No | UNSUPPORTED_BY_CURRENT_TELEMETRY |
| T1041 Exfiltration Over C2 Channel | Partially (Sysmon Event 3) | No rule exists | UNSUPPORTED_BY_CURRENT_TELEMETRY |
