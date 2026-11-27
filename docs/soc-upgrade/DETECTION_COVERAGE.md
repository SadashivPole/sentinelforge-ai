# SentinelForge SOC Upgrade — Detection Coverage

Branch: `feat/advanced-soc-ai-upgrade`
Base commit: `ef4269f`
Status: Phase 2 design; implementation not yet started

This document is the detection coverage design. It maps ATT&CK techniques to detection rules, objectives, required data sources, normalized fields, tests, and evaluation results. Coverage classifications require executable, tested rules — an ATT&CK tag in metadata alone is not coverage.

## 1. Coverage classifications

| Classification | Definition |
|----------------|------------|
| Implemented and validated | Executable rule exists, has positive + negative + boundary tests, required fields present in normalized schema, evaluated against dataset |
| Implemented but insufficiently validated | Rule exists but missing one or more validation dimensions |
| Telemetry available, detection missing | Normalized fields exist for the technique source, but no rule implements detection |
| Detection planned | Rule designed but not implemented |
| Telemetry unavailable | No source adapter or normalized fields for the technique's data source |

## 2. Current coverage map (baseline, from committed code)

| ATT&CK technique | Tactic | Rule | Objective | Data source | Required fields | Tests | Eval result | Classification |
|------------------|--------|------|-----------|-------------|-----------------|-------|-------------|----------------|
| T1110 / T1110.001 | Credential Access | FailedLoginBurstRule | Multiple failed authentications within a window, grouped by (source IP, username, host) | Authentication logs (Windows Security 4625, Linux SSH) | event_type, source_ip, username, host, timestamp, outcome | Positive, negative, boundary | 498/641 detected (aggregate across rules) | Implemented and validated |
| T1110.003 | Credential Access | PasswordSprayRule | Auth attempts across many usernames from a common source | Authentication logs | event_type, source_ip, username, host, timestamp, outcome | Positive, negative, boundary | Aggregate | Implemented and validated |
| T1059.001 | Execution | SuspiciousPowerShellRule | Encoded commands, hidden execution, bypass, download-and-execute, obfuscation | Process logs (PowerShell operational, Sysmon) | event_type, process_name, command_line, parent_process, host, timestamp | Positive, negative, boundary | Aggregate | Implemented and validated |
| T1204 / T1204.002 | Execution / Persistence | SuspiciousProcessTreeRule | Suspicious parent-child relationships (e.g., Office → PowerShell) | Process logs (Sysmon) | event_type, process_name, parent_process, host, timestamp | Positive, negative, boundary | Aggregate | Implemented and validated |
| T1071 | Command and Control | C2BeaconRule | Statistical beaconing on connection intervals | Network logs (firewall, proxy, connection events) | event_type, source_ip, dest_ip, dest_port, timestamp, protocol | Positive, negative, boundary | Aggregate | Implemented and validated |

Notes:
- Event-level recall 0.7769 (498 detected / 641 suspicious) is an aggregate across all five rules on the 11,298-event synthetic dataset. Per-rule breakdown is not currently reported separately.
- The 69-event independent holdout evaluation is separate from the M8.1 dataset results.
- Per-rule metrics are multi-label (an event can count under multiple expected categories); global counts use unique event IDs.

## 3. Coverage gaps (identified from baseline)

| Technique | Tactic | Gap | Reason | Planned action |
|-----------|--------|-----|--------|----------------|
| T1078 (Valid Accounts) | Persistence / Privilege Escalation / Defense Evasion / Initial Access | Detection missing | Authentication telemetry exists; no rule for anomalous valid-account usage | Design rule after P2-1/P2-2 telemetry adapters |
| T1566 (Phishing) | Initial Access | Telemetry unavailable | No email/proxy source adapter | Defer until telemetry available |
| T1059 (Command and Scripting Interpreter) | Execution | Partially covered | PowerShell covered; other interpreters (bash, cmd, Python) not | Extend SuspiciousPowerShellRule or add interpreter rule |
| T1021 (Remote Services) | Lateral Movement | Telemetry unavailable | No remote-service/logon source | Defer until telemetry available |
| T1486 (Data Encrypted for Impact) | Impact | Telemetry unavailable | No file-encryption telemetry source | Defer |
| T1562 (Impair Defenses) | Defense Evasion | Telemetry unavailable | No security-service modification source | Defer |

## 4. Required data sources vs current adapters

| Data source | Techniques it enables | Current adapter | Normalized fields available |
|-------------|----------------------|-----------------|------------------------------|
| Authentication logs | T1110, T1110.001, T1110.003, T1078 | JSON/JSONL reader (partial) | event_type, source_ip, username, host, timestamp, outcome |
| Process logs | T1059.001, T1204, T1204.002 | Sysmon-style reader | event_type, process_name, command_line, parent_process, host, timestamp |
| Network logs | T1071 | None (JSON/JSONL generic) | event_type, source_ip, dest_ip, dest_port, timestamp, protocol |
| Windows Security events | T1110 family, T1078 | None | — |
| Linux auth/auditd | T1110 family, T1078 | None | — |
| DNS/firewall/proxy | T1071, T1566 | None | — |
| Cloud audit | Cloud techniques | None | — |

## 5. Measurement method

Coverage percentage for a tactic = (techniques with "Implemented and validated" classification) / (total techniques in scope for that tactic) × 100.

Techniques in scope are limited to those for which SentinelForge has or plans telemetry. Techniques with "Telemetry unavailable" are excluded from the denominator (not counted as gaps).

## 6. Planned coverage improvements

- P1-1/P1-3: Add structured catalog + coverage register so classification is machine-readable.
- P2-1/P2-2: Add Windows Security + Linux auth/auditd adapters to enable T1078 and strengthen T1110-family coverage.
- New rules: Only added where telemetry is ready and validated with positive/negative/boundary tests.
- No ATT&CK tag is added to a rule without a corresponding executable detection and test.

## 7. Verification

- Every technique in the coverage map must have at least one executable rule with tests before being classified "Implemented and validated."
- Coverage report is regenerated from the coverage register, not hand-edited.
- The independent 69-event holdout remains separate from M8.1 dataset coverage figures.
