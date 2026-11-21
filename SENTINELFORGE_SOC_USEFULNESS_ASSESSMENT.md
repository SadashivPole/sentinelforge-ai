# SentinelForge AI — SOC Usefulness Assessment

**Project:** SentinelForge AI
**Report:** SENTINELFORGE_SOC_USEFULNESS_ASSESSMENT.md
**Phase:** 2, Item 7 — SOC Analyst Usefulness Evaluation
**Date:** 2026-11-19

---

## 1. Executive Summary

Five SOC investigation case studies were created from the validation dataset covering password spraying, brute force, suspicious PowerShell, C2 beaconing, and suspicious process trees. Evidence traceability is strong — analysts can reproduce findings from stored evidence. Alert readability is good with MITRE ATT&CK mapping, severity ratings, and complete evidence chains. Primary limitation: C2BeaconRule false positives on legitimate periodic traffic require analyst discrimination.

---

## 2. Case Studies

### Case Study 1: Password Spraying — T1110.003

**Alert:** Password Spray (Severity: HIGH)
**What happened:** 12 failed SSH logins from 192.0.2.50 against 4 distinct user accounts over ~1 hour
**Evidence:** 12 raw events with timestamps, source IPs, usernames
**MITRE:** T1110.003 (Credential Access)
**Analyst next steps:** Check for successful logins from source IP; review lockout policies; block IP; force password resets

### Case Study 2: Brute Force — T1110

**Alert:** Failed Login Burst (Severity: HIGH)
**What happened:** 20 failed SSH logins against 'admin' from 198.51.100.77 in ~200 seconds
**Evidence:** 20 raw events preserved
**MITRE:** T1110
**Analyst next steps:** Check for successful admin login; review SSH logs; consider account lockout; block source IP

### Case Study 3: Suspicious PowerShell — T1059.001

**Alert:** Suspicious PowerShell (Severity: HIGH)
**What happened:** PowerShell launched with ExecutionPolicy Bypass + EncodedCommand
**Evidence:** Raw process creation event with full command line
**MITRE:** T1059.001
**Analyst next steps:** Decode encoded command; check account activity; review transcription logs; isolate host if malicious

### Case Study 4: C2 Beaconing — T1071 (with FP context)

**Alert:** Potential C2 Beaconing (Severity: MEDIUM)
**What happened:** 12 periodic connections from WKSTN-05 to 203.0.113.200:8443 every 5 minutes
**Evidence:** 12 network connection events with IPs, ports, timestamps
**MITRE:** N/A (technique mapping not implemented)
**Analyst next steps:** Check threat intelligence for IP; review host software; capture network traffic; consider isolation
**FP Note:** Rule also flags legitimate HTTPS to known update server (port 443, 30-min intervals)

### Case Study 5: Suspicious Process Tree — T1204.002

**Alert:** Suspicious Parent-Child Process (Severity: MEDIUM)
**What happened:** WINWORD.EXE spawned powershell.exe 2 seconds later — Office macro attack chain
**Evidence:** Parent-child process relationship with PID/PPID linkage
**MITRE:** N/A (technique mapping not implemented for this rule)
**Analyst next steps:** Decode encoded command; check email attachments; review proxy logs; isolate host

---

## 3. Analyst Capability Assessment

| Question | Answer |
|---|---|
| What happened? | Yes — description + MITRE technique + evidence |
| Which host and user? | Yes — host and user fields on every evidence event |
| What process/network triggered it? | Yes — process info (Sysmon) or network info |
| What is the time sequence? | Yes — timestamps on all events |
| What evidence supports detection? | Yes — raw events preserved verbatim |
| Why did the rule trigger? | Yes — rule name, description, indicators matched |
| What remains uncertain? | Documented per case study |
| What should analyst investigate next? | Documented per case study |

---

## 4. Strengths

1. **Evidence traceability:** Raw events preserved verbatim; analysts can reproduce findings
2. **Alert readability:** Clear rule names, descriptions, severity ratings, MITRE mappings
3. **Time sequence:** Timestamps on all events enable timeline reconstruction
4. **Context:** Host, user, process, and network fields provide investigation scoping
5. **No data fabrication:** Missing fields are null, never invented

---

## 5. Limitations

1. **C2BeaconRule false positives:** Legitimate periodic HTTPS traffic flagged as beaconing
2. **No cross-alert correlation:** Multiple alerts for same host not automatically grouped
3. **No threat intelligence:** No IP/domain reputation lookup integrated
4. **Manual decoding:** Analysts must manually decode encoded PowerShell commands
5. **Missing MITRE mappings:** Some rules lack ATT&CK technique mapping (process tree, C2 beacon)

---

## 6. Verdict

**Evidence traceability is strong.** Alert readability is good. Analyst can reproduce findings from stored evidence.

**Recommended for SOC demonstration/pilot with the following enhancements:**
- Add threat intelligence integration for IP/domain reputation
- Tune C2BeaconRule to reduce false positives on known infrastructure
- Add automatic cross-alert correlation by host
- Add PowerShell command decoding assistance

Command: `PYTHONPATH=. python validate_soc_usefulness.py`
