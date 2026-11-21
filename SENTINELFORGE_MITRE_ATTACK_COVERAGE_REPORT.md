# SentinelForge AI — MITRE ATT&CK Coverage Report

**Project:** SentinelForge AI
**ATT&CK Version:** Enterprise v20.1
**Domain:** Enterprise
**Catalogue:** 69 curated entries (reference inventory only)
**Generated:** 2026-11-20T00:00:00Z

---

## 5.1 Executive Overview

This report describes the ATT&CK coverage reporting engine for SentinelForge AI. It measures what the system can genuinely detect against the curated MITRE ATT&CK Enterprise v20.1 catalogue.

The report measures three distinct things: catalogue coverage (the reference inventory), direct detection coverage (techniques with actual detection rules), and telemetry availability (techniques with supporting telemetry but no detection rule). These measurements are never conflated.

Catalogue membership is not detection coverage. Of 69 curated entries, only 5 have implemented detection mappings (~7.25% of the curated catalogue). The remaining entries are either telemetry-available without detection (17) or unsupported by current telemetry (47).

## 5.2 Coverage Summary

| Metric | Count |
|---|---|
| Total catalogue entries | 69 |
| Parent technique entries | 52 |
| Sub-technique entries | 17 |
| Unique ATT&CK IDs | 69 |
| Implemented and tested | 5 |
| Telemetry available, no detection | 17 |
| Planned, requires telemetry | 0 |
| Unsupported by current telemetry | 47 |
| Direct detection mappings | 5 |
| Unique detection rules | 5 |
| Coverage percentage (of catalogue) | 7.246376811594203% |

The coverage percentage (7.246376811594203%) is the proportion of the curated catalogue (69 entries) with direct implemented mappings (5). It is not overall ATT&CK Enterprise coverage.

## 5.3 Tactic Coverage (All 15 Enterprise Tactics)

Tactic counts are non-exclusive: a technique may belong to multiple tactics. The sum of per-tactic entries does not equal 69.

| Tactic ID | Tactic Name | Catalogue Entries | Implemented Direct Mappings | Telemetry Available, No Detection | Unsupported | Detection Rules |
|---|---|---|---|---|---|---|
| TA0043 | Reconnaissance | 2 | 0 | 1 | 1 | — |
| TA0042 | Resource Development | 2 | 0 | 0 | 2 | — |
| TA0001 | Initial Access | 4 | 0 | 0 | 4 | — |
| TA0002 | Execution | 9 | 2 | 3 | 4 | sentinelforge.detection.suspicious_powershell, sentinelforge.detection.suspicious_processtree |
| TA0003 | Persistence | 5 | 0 | 0 | 5 | — |
| TA0004 | Privilege Escalation | 1 | 0 | 1 | 0 | — |
| TA0005 | Stealth | 3 | 0 | 1 | 2 | — |
| TA0112 | Defense Impairment | 3 | 0 | 0 | 3 | — |
| TA0006 | Credential Access | 10 | 2 | 2 | 6 | sentinelforge.detection.failed_login_burst, sentinelforge.detection.password_spray |
| TA0007 | Discovery | 4 | 0 | 3 | 1 | — |
| TA0008 | Lateral Movement | 7 | 0 | 4 | 3 | — |
| TA0009 | Collection | 4 | 0 | 1 | 3 | — |
| TA0011 | Command and Control | 5 | 1 | 1 | 3 | sentinelforge.detection.c2_beacon |
| TA0010 | Exfiltration | 3 | 0 | 0 | 3 | — |
| TA0040 | Impact | 7 | 0 | 0 | 7 | — |

### Tactics with Implemented Detection Coverage

- **Execution** (TA0002): 2 mapping(s) via sentinelforge.detection.suspicious_powershell, sentinelforge.detection.suspicious_processtree
- **Credential Access** (TA0006): 2 mapping(s) via sentinelforge.detection.failed_login_burst, sentinelforge.detection.password_spray
- **Command and Control** (TA0011): 1 mapping(s) via sentinelforge.detection.c2_beacon

### Tactics Without Implemented Detection Coverage

- **Reconnaissance** (TA0043): 2 catalogue entries, 0 implemented mappings
- **Resource Development** (TA0042): 2 catalogue entries, 0 implemented mappings
- **Initial Access** (TA0001): 4 catalogue entries, 0 implemented mappings
- **Persistence** (TA0003): 5 catalogue entries, 0 implemented mappings
- **Privilege Escalation** (TA0004): 1 catalogue entries, 0 implemented mappings
- **Stealth** (TA0005): 3 catalogue entries, 0 implemented mappings
- **Defense Impairment** (TA0112): 3 catalogue entries, 0 implemented mappings
- **Discovery** (TA0007): 4 catalogue entries, 0 implemented mappings
- **Lateral Movement** (TA0008): 7 catalogue entries, 0 implemented mappings
- **Collection** (TA0009): 4 catalogue entries, 0 implemented mappings
- **Exfiltration** (TA0010): 3 catalogue entries, 0 implemented mappings
- **Impact** (TA0040): 7 catalogue entries, 0 implemented mappings

## 5.4 Detection Mapping Matrix

All five direct rule-to-technique associations are validated against the catalogue. Parent roll-ups (T1110, T1059, T1204) are not counted as independent detections.

| Detection Rule | ATT&CK ID | Technique | Tactic | Confidence | Status |
|---|---|---|---|---|---|
| sentinelforge.detection.c2_beacon | T1071 | Application Layer Protocol | Command and Control (TA0011) | medium | IMPLEMENTED_AND_TESTED |
| sentinelforge.detection.failed_login_burst | T1110.001 | Password Guessing | Credential Access (TA0006) | high | IMPLEMENTED_AND_TESTED |
| sentinelforge.detection.password_spray | T1110.003 | Password Spraying | Credential Access (TA0006) | high | IMPLEMENTED_AND_TESTED |
| sentinelforge.detection.suspicious_powershell | T1059.001 | PowerShell | Execution (TA0002) | medium | IMPLEMENTED_AND_TESTED |
| sentinelforge.detection.suspicious_processtree | T1204.002 | Malicious File | Execution (TA0002) | medium | IMPLEMENTED_AND_TESTED |

## 5.5 Telemetry Coverage Analysis

Telemetry coverage is derived from the normalized event schema in `sentinelforge/ingestion/normalizer.py`. Fields preserved only in raw payloads are distinguished from normalized fields.

### Normalized Data Model Fields

| Category | Fields |
|---|---|
| Process | pid, ppid, name, path, command_line, user, hash_sha256 |
| Network | direction, local_address, remote_address, local_port, remote_port, protocol |
| Authentication | outcome, method, username, source_address |
| Event | event_id, timestamp, event_type, user, host, source |

### Log Source Coverage Matrix

| Log Source | Normalized Fields | Supported Detections | Gaps |
|---|---|---|---|
| Windows Sysmon Event ID 1 (Process Create) | process.name, process.path, process.pid, process.ppid, process.command_line, process.user, process.hash_sha256 | SuspiciousPowerShellRule (T1059.001), SuspiciousProcessTreeRule (T1204.002 conditional) | Parent command line not captured for parent process, File content hash verification not performed |
| Windows Sysmon Event ID 3 (Network Connection) | network.direction, network.local_address, network.remote_address, network.local_port, network.remote_port, network.protocol | C2BeaconRule (T1071 conditional) | DNS response data not captured, Outbound data volume monitoring not performed, Packet payload inspection not performed |
| Windows Sysmon Event ID 11 (File Create) | process.name, process.path, process.command_line, process.user, file.target_filename | SuspiciousProcessTreeRule (file activity correlation for T1204.002) | File content hash verification not performed, File modification monitoring not performed |
| Windows Sysmon Event ID 22 (DNS Query) | process.name, process.command_line, dns.query_name | — | DNS response data not captured, DNS tunneling detection not implemented |
| Linux Authentication Logs | authentication.outcome, authentication.method, authentication.username, authentication.source_address | FailedLoginBurstRule (T1110.001), PasswordSprayRule (T1110.003) | SSH key type monitoring not performed, Account creation/modification telemetry not available |

### Raw-Only Fields (Not Normalized)

- DNS response data (Sysmon Event ID 22)
- Packet payload inspection
- File content hash verification
- SSH key type
- Terminal information
- Outbound data volume monitoring
- Registry monitoring
- File modification monitoring

## 5.6 Coverage Gaps

The following techniques have available telemetry but no detection rule implemented:

- **T1005** — Data from Local System (TA0009)
- **T1021** — Remote Services (TA0008)
- **T1021.001** — Remote Desktop Protocol (TA0008)
- **T1021.002** — SMB/Windows Admin Shares (TA0008)
- **T1021.004** — SSH (TA0008)
- **T1036** — Masquerading (TA0005)
- **T1046** — Network Service Scanning (TA0007)
- **T1059** — Command and Scripting Interpreter (TA0002)
- **T1059.003** — Windows Command Shell (TA0002)
- **T1071.001** — Web Protocols (TA0011)
- **T1078** — Valid Accounts (TA0004)
- **T1082** — System Information Discovery (TA0007)
- **T1087** — Account Discovery (TA0007)
- **T1110** — Brute Force (TA0006)
- **T1110.004** — Credential Stuffing (TA0006)
- **T1204** — User Execution (TA0002)
- **T1595** — Active Scanning (TA0043)

The following techniques lack required telemetry entirely and are unsupported:

- **T1003** — OS Credential Dumping (TA0006)
- **T1021.006** — Windows Admin Shares (TA0008)
- **T1027** — Obfuscated Files or Information (TA0005)
- **T1037** — Boot or Logon Initialization Scripts (TA0003)
- **T1041** — Exfiltration Over C2 Channel (TA0010)
- **T1048** — Exfiltration Over Alternative Protocol (TA0010)
- **T1053** — Scheduled Task (TA0003)
- **T1059.004** — Unix Shell (TA0002)
- **T1059.006** — Python (TA0002)
- **T1059.007** — JavaScript (TA0002)
- **T1070** — Indicator Removal on Host (TA0005)
- **T1083** — File and Directory Discovery (TA0007)
- **T1090** — Proxy (TA0011)
- **T1110.002** — Password Cracking (TA0006)
- **T1114** — Email Collection (TA0009)
- **T1133** — External Remote Services (TA0011)
- **T1189** — Drive-by Compromise (TA0001)
- **T1190** — Exploit Public-Facing Application (TA0001)
- **T1195** — Supply Chain Compromise (TA0001)
- **T1204.001** — Malicious Link (TA0002)
- **T1210** — Exploitation of Remote Services (TA0008)
- **T1485** — Data Destruction (TA0040)
- **T1486** — Data Encrypted for Impact (TA0040)
- **T1490** — Inhibit System Recovery (TA0040)
- **T1491** — Defacement (TA0040)
- **T1496** — Resource Hijacking (TA0040)
- **T1499** — Endpoint Denial of Service (TA0040)
- **T1535** — Unused/Unsupported Cloud Regions (TA0008)
- **T1537** — Data from Cloud Storage (TA0009)
- **T1543** — Create or Modify System Process (TA0003)
- **T1547** — Boot or Logon Autostart Execution (TA0003)
- **T1547.001** — Registry Run Keys (TA0003)
- **T1552** — Unsecured Credentials (TA0006)
- **T1555** — Credentials from Password Stores (TA0006)
- **T1556** — Modify Authentication Process (TA0006)
- **T1558** — Steal or Forge Kerberos Tickets (TA0006)
- **T1560** — Archive Collected Data (TA0009)
- **T1561** — Impair Defenses (TA0112)
- **T1562** — Impair Defenses (TA0112)
- **T1565** — Data Manipulation (TA0040)
- **T1566** — Phishing (TA0001)
- **T1567** — Exfiltration Over Web Service (TA0010)
- **T1572** — Protocol Tunneling (TA0011)
- **T1583** — Acquire Infrastructure (TA0042)
- **T1586** — Compromise Accounts (TA0042)
- **T1590** — Gather Victim Network Information (TA0043)
- **T1685** — Disable or Modify Tools (TA0112)

## 5.7 Parent Technique Roll-Ups

Three parent techniques are covered through their sub-techniques. They are roll-ups, not independent detection implementations.

| Parent Technique | Covered Sub-technique(s) | Detection Rule |
|---|---|---|
| T1110 Brute Force | T1110.001 (Password Guessing), T1110.003 (Password Spraying) | FailedLoginBurstRule, PasswordSprayRule |
| T1059 Command and Scripting Interpreter | T1059.001 (PowerShell) | SuspiciousPowerShellRule |
| T1204 User Execution | T1204.002 (Malicious File) | SuspiciousProcessTreeRule |

These parent techniques are marked TELEMETRY_AVAILABLE_NO_DETECTION in the catalogue and are NOT counted as independently implemented detections.

## 5.8 Limitations

- The catalogue is a curated subset of ATT&CK Enterprise v20.1, not the full matrix.
- Only five direct detection mappings are implemented across five rules.
- Synthetic test results do not demonstrate real-world detection effectiveness.
- T1204.002 mapping is conditional on file-activity correlation evidence — a process-tree anomaly alone does not prove malicious file execution.
- T1071 mapping is conditional on protocol-specific C2 context (non-standard port + suspicious process/raw IP) — it is not confirmation of Command and Control.
- ATT&CK mappings do not establish compromise or adversary attribution.
- No full enterprise ATT&CK coverage is claimed.

## 5.9 Future Development

The following are recommendations, not implemented capabilities:

- **File content hash verification**: Enables higher confidence for T1204.002 and supports T1486 (Data Encrypted for Impact).
- **DNS response data**: Enables T1071.004 (DNS) specificity and DNS tunneling detection.
- **Outbound data volume monitoring**: Enables T1041 (Exfiltration Over C2 Channel).
- **Registry monitoring**: Enables T1547.001 (Registry Run Keys).
- **Web proxy logs**: Enables T1071.001 (Web Protocols) with web traffic context.

---

End of report. All figures calculated programmatically from the catalogue and detection rule metadata.