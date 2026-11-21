# SentinelForge AI — MITRE ATT&CK Telemetry Coverage Matrix

**Project:** SentinelForge AI  
**Document:** SENTINELFORGE_MITRE_ATTACK_TELEMETRY_COVERAGE_MATRIX.md  
**Version:** 0.2.0 (design proposal — corrected and final review)  
**Status:** Draft — awaiting review  
**ATT&CK Reference:** Enterprise v20.1 (https://attack.mitre.org/)  
**Restrictions:** Read-only design. No implementation. No modification to existing datasets, rules, or reports.

---

## 1. Purpose

This document maps SentinelForge AI's **actual normalized telemetry** to MITRE ATT&CK Enterprise techniques and sub-techniques. It shows:

- Which telemetry fields are available from the current normalization pipeline
- Which techniques can be detected with available telemetry
- Which techniques lack required telemetry
- Where coverage gaps exist

**Critical principle:** A technique is only "detectable" if the normalized event schema contains the fields required to observe the behavior described by that technique. Telemetry that exists in raw Sysmon XML but is not extracted into normalized fields is **not** considered available.

---

## 2. Current Normalized Telemetry Inventory

### 2.1 NormalizedEvent Schema Fields

| Field | Type | Source | Description |
|---|---|---|---|
| event_id | string | Auto-generated | Unique event identifier |
| timestamp | string | ISO-8601 UTC | Event time |
| source | string | "json", "jsonl", "sysmon" | Log source type |
| raw | dict | Original payload | Verbose raw event (preserved verbatim) |
| event_type | string | Derived/extracted | "auth.login.failed", "process.create", "network.connection", etc. |
| user | string | Extracted | User account name |
| host | string | Extracted | Hostname or computer name |
| process | ProcessInfo | Extracted from Sysmon EventData | Process details |
| network | NetworkInfo | Extracted from Sysmon EventData | Network connection details |
| authentication | AuthenticationInfo | Extracted from Linux auth | Authentication details |
| ingested_at | string | Auto-generated | Ingestion timestamp |

### 2.2 ProcessInfo (from Sysmon Event ID 1)

| Field | Available? | Example |
|---|---|---|
| pid | Yes | 1111 |
| ppid | Yes | 2222 |
| name | Yes | "WINWORD.EXE" |
| path | Yes | "C:\Program Files\Microsoft Office\WINWORD.EXE" |
| command_line | Yes | "WINWORD.EXE /document invoice.docx" |
| user | Yes | "OFFICE-01\jdoe" |
| hash_sha256 | Yes (may be empty) | "a1b2c3d4..." |

### 2.3 NetworkInfo (from Sysmon Event ID 3)

| Field | Available? | Example |
|---|---|---|
| direction | Yes | "outbound" |
| local_address | Yes | "192.168.1.100" |
| remote_address | Yes | "203.0.113.200" |
| local_port | Yes | 49200 |
| remote_port | Yes | 443 |
| protocol | Yes | "tcp" |

### 2.4 AuthenticationInfo (from Linux Auth Logs)

| Field | Available? | Example |
|---|---|---|
| outcome | Yes | "failure", "success" |
| method | Yes | "ssh" |
| username | Yes | "jdoe" |
| source_address | Yes | "192.0.2.100" |

### 2.5 Event Type Mapping

| Event Type | Source Log Source | Sysmon Event ID |
|---|---|---|
| auth.login.failed | linux_auth | N/A |
| auth.login.success | linux_auth | N/A |
| process.create | windows_sysmon | Event ID 1 |
| network.connection | windows_sysmon | Event ID 3 |
| file.create | windows_sysmon | Event ID 11 |
| dns.query | windows_sysmon | Event ID 22 |

---

## 3. Telemetry Coverage Matrix by ATT&CK Tactic

### 3.1 Credential Access (TA0006)

| Technique | ID | Required Telemetry | Available? | Detection Rule | Status |
|---|---|---|---|---|---|
| Brute Force | T1110 | auth.outcome, auth.username, auth.source_address, host, timestamp | Yes | FailedLoginBurstRule | IMPLEMENTED_AND_TESTED |
| Password Guessing | T1110.001 | auth.outcome, auth.username, auth.source_address, host, timestamp | Yes | FailedLoginBurstRule | IMPLEMENTED_AND_TESTED |
| Password Spraying | T1110.003 | auth.outcome, auth.username, auth.source_address, host, timestamp | Yes | PasswordSprayRule | IMPLEMENTED_AND_TESTED |
| Credentials from Password Stores | T1555 | file.read, process.command_line | No | — | UNSUPPORTED |
| Credentials from Web Browsers | T1555.003 | file.read, network.connection | No | — | UNSUPPORTED |
| Extract Credentials from SAM | T1555.004 | file.read, process.command_line | No | — | UNSUPPORTED |
| Brute Force: Kerberoasting | T1558.003 | network.connection (port 88), process.command_line | Partially | — | PARTIALLY_SUPPORTED |

**Coverage summary:** 2 of 5 Credential Access techniques have detection rules. Available telemetry supports credential-based detection but lacks file access monitoring for credential store access.

---

### 3.2 Execution (TA0002)

| Technique | ID | Required Telemetry | Available? | Detection Rule | Status |
|---|---|---|---|---|---|
| PowerShell | T1059.001 | process.name, process.command_line, process.user, host | Yes | SuspiciousPowerShellRule | IMPLEMENTED_AND_TESTED |
| Windows Command Shell | T1059.003 | process.name, process.command_line, process.user, host | Partially | — | PARTIALLY_SUPPORTED |
| Windows Command Shell: cmd.exe | T1059.003 | process.name, process.command_line | Partially | — | PARTIALLY_SUPPORTED |
|| Unix Shell | T1059.004 | process.name, process.command_line, process.user | Partially | — | PARTIALLY_SUPPORTED ||
|| User Execution: Malicious File | T1204.002 | process.name, process.parent.name, file.create.timestamp | Partially | SuspiciousProcessTreeRule | PARTIALLY_SUPPORTED ||
| User Execution: Malicious Image | T1204.001 | process.name, process.command_line, file.download | Partially | — | PARTIALLY_SUPPORTED |
| User Execution: Malicious Link | T1204.003 | process.command_line, file.download | Partially | — | PARTIALLY_SUPPORTED |
| User Execution: Malicious Image | T1204.002 | process.name, process.command_line | Partially | SuspiciousProcessTreeRule | PARTIALLY_SUPPORTED |

**Coverage summary:** PowerShell is the only execution technique with an implemented detection rule. Other execution techniques lack corresponding detection rules even though telemetry partially exists.

---

### 3.3 Initial Access (TA0001)

| Technique | ID | Required Telemetry | Available? | Detection Rule | Status |
|---|---|---|---|---|---|
| Drive-by Compromise | T1189 | network.connection, process.command_line | Partially | — | UNSUPPORTED_BY_CURRENT_TELEMETRY |
| Exploit Public-Facing Application | T1190 | network.connection, process.command_line | Partially | — | UNSUPPORTED_BY_CURRENT_TELEMETRY |
| External Remote Services | T1021 | network.connection, authentication | Partially | — | UNSUPPORTED_BY_CURRENT_TELEMETRY |
| External Remote Services: RDP | T1021.001 | network.connection (port 3389), process.command_line | Partially | — | UNSUPPORTED_BY_CURRENT_TELEMETRY |
| External Remote Services: SSH | T1021.002 | network.connection (port 22), authentication | Partially | — | UNSUPPORTED_BY_CURRENT_TELEMETRY |
| Exploit Public-Facing Application | T1190 | network.connection, process.command_line | Partially | — | UNSUPPORTED_BY_CURRENT_TELEMETRY |

**Coverage summary:** No Initial Access techniques have detection rules. Network connection data exists but no rules correlate it into initial access detection.

---

### 3.4 Command and Control (TA0011)

| Technique | ID | Required Telemetry | Available? | Detection Rule | Status |
|---|---|---|---|---|---|
| Application Layer Protocol | T1071 | network.protocol, network.remote_address, network.remote_port, process.name | Yes | C2BeaconRule | IMPLEMENTED_AND_TESTED |
| Web Protocols | T1071.001 | network.protocol="http"/"https", network.remote_port | Partially | C2BeaconRule (conditional) | PARTIALLY_SUPPORTED |
| DNS | T1071.004 | network.protocol="dns", network.remote_address | Yes | C2BeaconRule (conditional) | PARTIALLY_SUPPORTED |
| Fallback Channels | T1071.004 | network.connection patterns | Partially | — | PARTIALLY_SUPPORTED |

**Coverage summary:** C2BeaconRule implements T1071 with conditional logic. Sub-technique mappings are not yet applied (only parent technique T1071 is used).

---

### 3.5 Discovery (TA0007)

| Technique | ID | Required Telemetry | Available? | Detection Rule | Status |
|---|---|---|---|---|---|
| Account Discovery | T1087 | authentication.username, process.command_line | Partially | — | UNSUPPORTED_BY_CURRENT_TELEMETRY |
| Network Service Scanning | T1046 | network.remote_address, network.remote_port, network.direction | Partially | — | UNSUPPORTED_BY_CURRENT_TELEMETRY |
| File and Directory Discovery | T1083 | process.command_line, file.create | No | — | UNSUPPORTED_BY_CURRENT_TELEMETRY |
| System Information Discovery | T1082 | process.command_line | Partially | — | UNSUPPORTED_BY_CURRENT_TELEMETRY |

**Coverage summary:** No Discovery techniques have detection rules. Network connection data exists but no scanning detection rules.

---

### 3.6 Lateral Movement (TA0008)

| Technique | ID | Required Telemetry | Available? | Detection Rule | Status |
|---|---|---|---|---|---|
| Remote Desktop Protocol | T1021.001 | network.remote_port=3389, process.command_line | Partially | — | UNSUPPORTED_BY_CURRENT_TELEMETRY |
| SMB/Windows Admin Shares | T1021.002 | network.remote_port=445, process.command_line | Partially | — | UNSUPPORTED_BY_CURRENT_TELEMETRY |
| SSH | T1021.002 | network.remote_port=22, authentication | Partially | — | UNSUPPORTED_BY_CURRENT_TELEMETRY |

**Coverage summary:** No Lateral Movement techniques have detection rules.

---

### 3.7 Collection (TA0009)

| Technique | ID | Required Telemetry | Available? | Detection Rule | Status |
|---|---|---|---|---|---|
| Data from Local System | T1005 | process.command_line, file.create | Partially | — | UNSUPPORTED_BY_CURRENT_TELEMETRY |
| Data from Network Remote Share | T1039 | network.connection (port 445), process.command_line | Partially | — | UNSUPPORTED_BY_CURRENT_TELEMETRY |
| Data from Cloud Storage | T1537 | network.connection, process.command_line | Partially | — | UNSUPPORTED_BY_CURRENT_TELEMETRY |

**Coverage summary:** No Collection techniques have detection rules.

---

### 3.8 Exfiltration (TA0010)

| Technique | ID | Required Telemetry | Available? | Detection Rule | Status |
|---|---|---|---|---|---|
| Exfiltration Over C2 Channel | T1041 | network.connection, process.command_line | Partially | — | UNSUPPORTED_BY_CURRENT_TELEMETRY |
| Exfiltration Over Alternative Protocol | T1048 | network.connection, process.command_line | Partially | — | UNSUPPORTED_BY_CURRENT_TELEMETRY |

**Coverage summary:** No Exfiltration techniques have detection rules.

---

### 3.9 Impact (TA0040)

| Technique | ID | Required Telemetry | Available? | Detection Rule | Status |
|---|---|---|---|---|---|
| Data Encrypted for Impact | T1486 | process.command_line, file.create, file.modify | Partially | — | UNSUPPORTED_BY_CURRENT_TELEMETRY |

**Coverage summary:** No Impact techniques have detection rules.

---

### 3.10 Persistence (TA0003)

| Technique | ID | Required Telemetry | Available? | Detection Rule | Status |
|---|---|---|---|---|---|
| Boot or Logon Autostart Execution | T1547 | process.command_line, file.create, registry.modify | Partially | — | UNSUPPORTED_BY_CURRENT_TELEMETRY |
| Registry Run Keys | T1547.001 | process.command_line, file.create | No | — | UNSUPPORTED_BY_CURRENT_TELEMETRY |

**Coverage summary:** No Persistence techniques have detection rules.

---

## 4. Telemetry Gap Analysis

### 4.1 Techniques with Available Telemetry but No Detection Rule

| Technique | ID | Available Telemetry | Gap |
|---|---|---|---|
| Account Discovery | T1087 | authentication.username, process.command_line | No detection rule |
| Network Service Scanning | T1046 | network.remote_address, network.remote_port | No detection rule |
| SSH Lateral Movement | T1021.002 | network.remote_port=22, authentication | No detection rule |
| Data from Local System | T1005 | process.command_line, file.create | No detection rule |

### 4.2 Techniques with Detection Rules but Incomplete Telemetry

| Technique | ID | Missing Telemetry | Impact |
|---|---|---|---|
| Malicious File | T1204.002 | file hash verification, parent command line | Cannot verify file integrity or parent context fully |
| Application Layer Protocol | T1071 | DNS response data, packet payload | Cannot distinguish C2 from legitimate traffic with certainty |
| PowerShell | T1059.001 | decoded command content | Cannot determine if encoded command is malicious |

### 4.3 Techniques with No Available Telemetry

| Technique | ID | Missing Telemetry Category |
|---|---|---|
| Credentials from Password Stores | T1555 | File system access monitoring |
| Exfiltration Over C2 Channel | T1041 | Outbound data volume monitoring |
| Data Encrypted for Impact | T1486 | File modification monitoring |
| Boot or Logon Autostart Execution | T1547 | Registry/file system persistence monitoring |

---

## 5. Coverage Score by Tactic

| Tactic | Techniques Available | Techniques with Detection Rules | Coverage % |
|---|---|---|---|
| Credential Access | 5 | 2 | 40% |
| Execution | 7 | 1 | 14% |
| Initial Access | 4 | 0 | 0% |
| Command and Control | 3 | 1 | 33% |
| Discovery | 4 | 0 | 0% |
| Lateral Movement | 3 | 0 | 0% |
| Collection | 3 | 0 | 0% |
| Exfiltration | 2 | 0 | 0% |
| Impact (TA0040) | 1 | 0 | 0% |
| Persistence | 2 | 0 | 0% |
| Privilege Escalation | 2 | 0 | 0% |
| Stealth (TA0005) | 0 | 0 | 0% |
| Defense Impairment (TA0112) | 0 | 0 | 0% |
| Resource Development | 1 | 0 | 0% |
| Reconnaissance | 1 | 0 | 0% |

**Overall coverage:** 5 techniques with detection rules out of the catalogue total. The percentage varies with catalogue size and is not a meaningful detection-coverage metric — catalogue size reflects the reference inventory, not the number of techniques SentinelForge can actually detect.

**Note:** Coverage is calculated against the curated technique catalogue. As the catalogue expands to ~70 entries, the raw percentage will decrease unless new detection rules are added. This is expected and does not indicate reduced capability.

---

## 6. Telemetry Gap Recommendations

### 5.1 Highest-Value Telemetry Additions

| Gap | Techniques Enabled | Implementation Effort |
|---|---|---|
| File content hash verification | T1204.002, T1486 | Medium (Sysmon Event ID 11 already captures file path; hash verification requires additional processing) |
| Process parent command line | T1204.002 | Low (Sysmon Event Data contains ParentImage, ParentCommandLine) |
| DNS response data | T1071.004 | Medium (Sysmon Event ID 22 contains QueryName but not Response) |
| Web proxy logs | T1071, T1041 | High (new log source) |
| File modification monitoring | T1486 | Low (Sysmon Event ID 11 already exists; needs rule) |

### 5.2 Techniques That Could Be Added with Minimal Telemetry Changes

| Technique | ID | Missing Telemetry | Effort |
|---|---|---|---|
| Network Service Scanning | T1046 | None (network data exists) | Low — detection rule only |
| SSH Lateral Movement | T1021.002 | None (auth + network data exists) | Low — detection rule only |
| Valid Accounts | T1078 | None (auth events exist) | Low — detection rule only |

---

## 6. Mapping Confidence by Telemetry Availability

| Telemetry Coverage | Mapping Confidence | Example |
|---|---|---|
| All required fields present | high | T1110.001 — failed login burst |
| Most required fields present, minor gaps | medium | T1059.001 — PowerShell (missing decoded command content) |
| Some required fields present, significant gaps | low | T1071 — C2 beaconing (missing packet payload, DNS response) |
| Required fields missing | none (unmapped) | T1555 — Credentials from Password Stores |

---

## 7. Implementation Implications

### 7.1 Techniques That Could Be Added Without New Telemetry

The following techniques could be mapped to detection rules using **only** currently available normalized fields:

| Technique | ID | Required Telemetry | Available? |
|---|---|---|---|
| Network Service Scanning | T1046 | network.remote_address, network.remote_port, network.direction | Yes |
| Valid Accounts | T1078 | authentication.outcome, auth.username, host | Yes |
| SSH Lateral Movement | T1021.002 | network.remote_port=22, authentication | Yes |

These three techniques could be added to the catalogue as "PARTIALLY_SUPPORTED" or "IMPLEMENTED_NEEDS_VALIDATION" without any telemetry changes.

### 7.2 Techniques Requiring New Telemetry Before Implementation

| Technique | ID | Missing Telemetry |
|---|---|---|
| File and Directory Discovery | T1083 | file.create monitoring (Sysmon Event ID 11 exists but not used by rules) |
| Data from Local System | T1005 | process.command_line + file.create (both exist but no rule) |
| Data Encrypted for Impact | T1486 | file.create, file.modify (Sysmon Event ID 11 exists but no rule) |

Note: Even where telemetry exists, detection rules must be written. Telemetry availability is necessary but not sufficient for implementation.

---

## 8. Conclusion

SentinelForge AI's current telemetry covers **5 techniques** with detection rules out of the curated catalogue. An additional **~6 techniques** have sufficient telemetry for detection rules but lack rule implementation. The remaining catalogue entries lack required telemetry fields in the normalized schema.

The highest-value telemetry additions for expanding ATT&CK coverage are:

1. File content hash verification (enables T1204.002 confidence)
2. Process parent command line (enables T1204.002 confidence)
3. DNS response data (enables T1071.004 specificity)

Without these additions, the catalogue will remain dominated by `UNSUPPORTED_BY_CURRENT_TELEMETRY` entries, which provide no analyst value.

---

## 9. Out of Scope

- Implementation of new detection rules
- Changes to existing detection rule thresholds
- Modification of historical datasets or ground truth
- Modification of EvidenceForge or any external project
- ATT&CK Navigator layer generation code
