# SentinelForge SOC Upgrade — Reference Register

Branch: `feat/advanced-soc-ai-upgrade`
Base commit: `ef4269f`
Status: Phase 2 design; implementation not yet started

This register identifies the external technical references used to guide the SentinelForge SOC upgrade, their purpose, license where known, and how they influenced implementation decisions. It satisfies the Awesome Detection Engineering requirement to check license, data sources, required fields, logic, ATT&CK mapping, false positives, and compatibility before importing anything.

## 1. Primary reference repositories

| Repository | URL | Purpose | License (as documented) | Influence on implementation |
|------------|-----|---------|-------------------------|------------------------------|
| AiSOC | https://github.com/beenuar/AiSOC | SOC platform architecture and operating workflows | Not verified — repository blocked; not cloned | Architecture principles only: modular telemetry ingestion, detection-engine/incident distinction, Investigation Ledger auditable AI workflow, governed response (propose/preview/approve/dispatch/record), evidence-based maturity classifications (WORKING/PARTIAL/BROKEN/DEMO-ONLY/EXPERIMENTAL/DOCS-ONLY/NOT IMPLEMENTED). Infrastructure (event streaming, multiple DBs, connector fleet) intentionally NOT copied. |
| Awesome Detection Engineering | https://github.com/infosecB/awesome-detection-engineering | Detection engineering methodology, content, frameworks, telemetry | Not verified — repository blocked; not cloned | Detection Engineering Maturity Matrix, Detection Development Lifecycle, Pyramid of Pain, MITRE ATT&CK, Sigma, CAR, Splunk/Elastic detection content, OCSF/ECS logging guidance. Used to shape detection catalog, coverage map, telemetry adapters, and quality gates. |
| Craft Anything | https://github.com/storytold/craft-anything | Structured inspection/implementation/comparison/refinement workflow | Not verified — repository blocked; not cloned | Study → Build → Check → Ready methodology governs this upgrade. CLI (`craft-anything-cli doctor`) not verified as installed; methodology applied manually via repository inspection, implementation, testing, and comparison. |

**Note**: All three reference repository URLs were blocked in this environment ("URL targets a private or internal network address"). They were not cloned or inspected directly. Concepts above are drawn from the public repository descriptions in the assignment brief, not from direct repository contents. No code, rule counts, or detection content was imported from them.

## 2. Detection-engineering frameworks and concepts

| Framework / concept | Source reference | Use in SentinelForge | Status |
|---------------------|------------------|----------------------|--------|
| MITRE ATT&CK | Awesome Detection Engineering | Tactic/technique metadata on rules; coverage map | Adopted — techniques mapped only to executable, tested rules |
| Alerting and Detection Strategies Framework | Awesome Detection Engineering | Detection objective + required data source per rule | Adopted |
| Detection Engineering Maturity Matrix | Awesome Detection Engineering | Maturity register classifications | Adopted — WORKING/PARTIAL/EXPERIMENTAL/etc. |
| Detection Development Lifecycle | Awesome Detection Engineering | Rule author → validate → test → deploy → tune → retire | Adopted as process |
| Detection Maturity Level Model | Awesome Detection Engineering | Capability maturity levels | Adopted in MATURITY.md |
| Pyramid of Pain | Awesome Detection Engineering | IOC indicator-type prioritization (hash → domain → IP) | Adopted — hash indicators prioritized for retro-hunt value |
| Cyber Kill Chain | Awesome Detection Engineering | Multi-stage correlation context | Referenced — not used to claim attack chains from proximity |
| Synthetic Adversarial Log Objects (SALO) | Awesome Detection Engineering | Synthetic evaluation fixture design | Referenced — SentinelForge already uses synthetic datasets; holdout kept independent |
| Threat Detection Maturity Framework | Awesome Detection Engineering | Detection quality measurement | Adopted — precision/recall/F1 separation |
| Detection Engineering AI Maturity Framework | Awesome Detection Engineering | AI investigation grounding rules | Adopted — observed/derived/hypothesis/unknown separation |

## 3. Detection content families evaluated (not imported)

| Content family | Source | License check required | Required data source | Compatibility decision |
|----------------|--------|------------------------|----------------------|------------------------|
| Sigma rules | SigmaHQ | Verify per-rule | Varies by rule | Not implemented — no pySigma integration yet; support matrix to be created if adopted |
| MITRE CAR | MITRE | Public | Windows/Sysmon events | Referenced for detection logic patterns; no rules imported |
| Splunk Security Content | Splunk | Verify (BSD-3 typically) | Splunk fields | Not imported — field incompatibility with SentinelForge schema |
| Elastic Detection Rules | Elastic | Verify (Elastic v2/AGPL) | Elasticsearch/ECS | Not imported — ECS compatibility evaluated, no rule import |
| KQL detection repos | Open-source | Verify per repo | Azure Sentinel fields | Not imported — no KQL backend in SentinelForge |

**Decision**: No external detection rule library is imported blindly. Any future Sigma/pySigma integration requires per-rule license, data-source, field, operator, ATT&CK, false-positive, and compatibility checks, plus positive/negative/boundary tests before a rule counts as operational.

## 4. Logging and telemetry references

| Reference | Source | Telemetry types | Use in SentinelForge |
|-----------|--------|-----------------|----------------------|
| Windows logging guidance | Microsoft / Awesome Detection Engineering | Windows Security events (4624/4625/4648/4672/4688) | Planned `win_security` adapter |
| Sysmon | Sysinternals / Awesome Detection Engineering | Process creation, network connections, file changes | Existing Sysmon-style reader; extend via adapter pattern |
| Linux auditd | Linux Audit / Awesome Detection Engineering | Process execution, account/privilege changes | Planned `auditd` adapter |
| SSH/sudo logs | Awesome Detection Engineering | Authentication, privilege escalation | Planned `linux_auth` adapter |
| DNS / firewall / proxy | Awesome Detection Engineering | Network events | Planned network adapters |
| OCSF | OCSF schema | Common security event schema | Evaluated for field compatibility; not adopted as lossy universal schema |
| ECS | Elastic Common Schema | Common event schema | Evaluated for field compatibility; not adopted as lossy universal schema |
| CIM | Splunk Common Information Model | Common fields | Evaluated; not adopted |
| Loghub | Loghub dataset | Log sources for testing | Referenced for fixture design |
| osquery | osquery | Endpoint telemetry | Referenced; no osquery dependency added |
| Microsoft Defender XDR Advanced Hunting | Microsoft | Cloud/identity audit schema | Evaluated; no cloud adapter implemented yet |
| Cloud audit sources (AWS CloudTrail, Azure, GCP, K8s) | Cloud providers | Cloud audit events | Evaluated; optional, not implemented |

## 5. How references influenced implementation decisions

1. **Proportionate architecture**: AiSOC describes a much larger service architecture. SentinelForge keeps Python + SQLite core; AiSOC's ingestion/incident/Investigation-Ledger/governed-response principles are adopted without copying its infrastructure.

2. **Detection catalog metadata**: Shaped by Awesome Detection Engineering's detection-content requirements (objective, required fields, ATT&CK mapping, false-positive conditions, test references, execution status).

3. **Coverage map**: Shaped by Detection Engineering Maturity Matrix and Threat-informed detection engineering — coverage claims require executable rules + available normalized fields + tests.

4. **Telemetry adapters**: Shaped by OCSF/ECS/CIM evaluation — explicit adapters preserve source-specific fields rather than forcing everything into one lossy schema.

5. **IOC prioritization**: Shaped by Pyramid of Pain — hash indicators first, then domains, then IPs.

6. **AI investigation grounding**: Shaped by Detection Engineering AI Maturity Framework — observed/derived/hypothesis/unknown separation; audit ledger records prompts, tool calls, evidence, and analyst decisions.

7. **Governed response**: Shaped by AiSOC's propose/preview/approve/dispatch/record model — advisory-only, no autonomous response.

8. **Maturity classifications**: Shaped by AiSOC's WORKING/PARTIAL/BROKEN/DEMO-ONLY/EXPERIMENTAL/DOCS-ONLY/NOT IMPLEMENTED scale — only execution-evidence-backed capabilities are classified WORKING.

## 6. Verification notes

- Reference repository URLs were not accessible in this environment; no direct inspection, cloning, or code import occurred.
- No license text was obtained from external repositories; license column marked "Not verified."
- No detection content, rule counts, or technique coverage was imported from external sources.
- All implementation decisions above are traceable to SentinelForge's own codebase and baseline measurements, not to unverified external claims.
