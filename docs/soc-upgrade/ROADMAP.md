# SentinelForge SOC Upgrade — Roadmap

Branch: `feat/advanced-soc-ai-upgrade`
Base commit: `ef4269f`
Status: Phase 2 design; implementation not yet started

This roadmap converts the baseline findings into a prioritized, reviewable implementation plan. Every item includes existing status, problem, proposed solution, modules involved, dependencies, security considerations, required tests, expected outcome, priority, and effort estimate.

Classification per item:
- **Implement now** — highest value, fits current architecture, testable.
- **Implement later** — depends on an earlier item or needs more telemetry evidence.
- **Optional integration** — worth investigating, not core to prototype.
- **Not appropriate** — rejected for current architecture/scope.

## Priority 1 — Detection engineering foundation

### P1-1: Structured detection catalog metadata
- **Existing status**: 5 rules exist with ad-hoc metadata; no unified catalog schema or catalog-level validation.
- **Problem**: Cannot answer "which rules exist, are they valid, what do they cover" from code alone.
- **Solution**: Add a lightweight catalog dataclass (rule ID, name, version, objective, category, severity, ATT&CK tactic/technique, required data source, required fields, threshold, time window, false-positive conditions, test references, execution status, validation status) shared by all rules; registry exposes catalog entries.
- **Modules**: `sentinelforge/detection/base.py`, `sentinelforge/detection/*.py`, `sentinelforge/cli/main.py` (`detect --list-rules`).
- **Dependencies**: None (stdlib dataclasses).
- **Security**: Metadata is static; no execution risk.
- **Tests**: `tests/test_detection_catalog.py` — metadata validity, required-field presence, ATT&CK ID format, rule ID uniqueness.
- **Expected outcome**: Every rule has structured, validated metadata; CLI can list rules with status.
- **Priority**: Implement now. **Effort**: Small.

### P1-2: Rule validation lifecycle (positive/negative/boundary)
- **Existing status**: Each rule has tests; need explicit classification of positive/negative/boundary/missing-field/malformed-input per rule.
- **Problem**: No machine-checkable distinction between "rule exists" and "rule validated against fixtures."
- **Solution**: Tag each test with its validation role; add missing-field and malformed-input tests; ensure every rule has ≥1 positive, ≥1 negative, ≥1 boundary test.
- **Modules**: `tests/test_detection_rules.py` (extend), `sentinelforge/detection/*.py`.
- **Dependencies**: P1-1.
- **Security**: Negative fixtures must not weaken detections; boundary tests preserve thresholds.
- **Tests**: New test module asserting each rule's validation coverage.
- **Expected outcome**: Validation status per rule is evidence-backed.
- **Priority**: Implement now. **Effort**: Medium.

### P1-3: ATT&CK coverage map
- **Existing status**: Rules carry ATT&CK IDs in metadata; no coverage report or gap analysis.
- **Problem**: Cannot claim coverage without connecting technique → rule → telemetry → tests → evaluation.
- **Solution**: Build coverage register (ATT&CK technique, tactic, detection rule, objective, required data source, available normalized fields, test coverage, evaluation results, classification). Generate a machine-readable JSON + human-readable report.
- **Modules**: `sentinelforge/datasets/coverage.py` (new), `sentinelforge/cli/main.py` (`evaluate --coverage`).
- **Dependencies**: P1-1, P1-2.
- **Security**: Coverage claims must match executable rules and available fields.
- **Tests**: `tests/test_coverage.py` — every mapped technique has an executable rule and required fields present in normalized schema.
- **Expected outcome**: Coverage report classifies each technique as implemented-validated / implemented-insufficient / telemetry-available-detection-missing / planned / telemetry-unavailable.
- **Priority**: Implement now. **Effort**: Medium.

### P1-4: Detection evaluation consistency
- **Existing status**: Event-level and alert-level metrics computed separately; per-rule multi-label vs global unique distinction documented.
- **Problem**: No automated guardrail preventing accidental mixing of metric populations.
- **Solution**: Add evaluation self-check asserting per-rule sums ≥ global uniques where multi-label, and F1 computed only when precision/recall share unit and population.
- **Modules**: `sentinelforge/datasets/evaluation.py`.
- **Dependencies**: None.
- **Security**: No data leakage between ground truth and detection logic.
- **Tests**: Extend `tests/test_evaluation.py`.
- **Expected outcome**: Evaluation output is internally consistent and reproducible.
- **Priority**: Implement now. **Effort**: Small.

## Priority 2 — Telemetry normalization

### P2-1: Windows Security event adapter
- **Existing status**: JSON/JSONL/Sysmon readers only; no Windows Security event parser.
- **Problem**: No path for the most common enterprise telemetry source.
- **Solution**: Add `win_security` adapter parsing JSONL-shaped Windows Security events (4624/4625/4648/4672/4688 etc.) into common schema; test with representative fixtures.
- **Modules**: `sentinelforge/ingestion/adapters/win_security.py` (new), `sentinelforge/ingestion/normalizer.py`.
- **Dependencies**: None.
- **Security**: Windows logs may contain credentials/PII — raw payload preserved, not logged to stdout.
- **Tests**: `tests/test_ingestion_win_security.py` — positive, negative, missing-field, malformed.
- **Expected outcome**: Windows Security events parse, normalize, and preserve raw provenance.
- **Priority**: Implement now. **Effort**: Medium.

### P2-2: Linux authentication & auditd adapter
- **Existing status**: No Linux auth/auditd parsing.
- **Problem**: Linux host telemetry unsupported.
- **Solution**: Add `linux_auth` (SSH/sudo) and `auditd` adapters; test with fixtures.
- **Modules**: `sentinelforge/ingestion/adapters/linux_auth.py`, `sentinelforge/ingestion/adapters/auditd.py` (new).
- **Dependencies**: P2-1 pattern.
- **Security**: Same as P2-1.
- **Tests**: `tests/test_ingestion_linux_auth.py`, `tests/test_ingestion_auditd.py`.
- **Expected outcome**: Linux auth/auditd events parse and normalize with provenance.
- **Priority**: Implement now. **Effort**: Medium.

### P2-3: Network source adapters (DNS, firewall, proxy, connection)
- **Existing status**: None.
- **Problem**: Network telemetry unsupported.
- **Solution**: Add `dns`, `firewall`, `proxy`, `connection` adapters where representative fixtures exist; classify unsupported constructs explicitly.
- **Modules**: `sentinelforge/ingestion/adapters/*.py` (new).
- **Dependencies**: P2-1.
- **Security**: DNS/firewall logs may contain internal IPs — treated as untrusted.
- **Tests**: Per-adapter test modules.
- **Expected outcome**: Network events parse with field completeness reported.
- **Priority**: Implement later (after P2-1/P2-2 prove the adapter pattern). **Effort**: Medium.

### P2-4: Cloud & identity adapters (CloudTrail, Azure, Entra, GCP, K8s audit)
- **Existing status**: None.
- **Problem**: Cloud telemetry unsupported; risk of over-engineering for a lightweight prototype.
- **Solution**: Investigate schema compatibility (OCSF/ECS); implement only if a clean, testable adapter fits without new heavy dependencies.
- **Modules**: `sentinelforge/ingestion/adapters/cloud_*.py` (new, conditional).
- **Dependencies**: P2-3.
- **Security**: Cloud audit logs are sensitive — no automatic upload to external providers.
- **Tests**: Conditional on implementation.
- **Expected outcome**: Documented support matrix; implementation only if justified.
- **Priority**: Optional integration. **Effort**: Large (if implemented).

### P2-5: Normalization provenance & validation warnings
- **Existing status**: Normalizer preserves raw payload; limited provenance tracking.
- **Problem**: Cannot trace a normalized field back to its source parser/version.
- **Solution**: Add parser version, mapping provenance, and validation warnings to normalized event; idempotent ingestion keyed on event identity.
- **Modules**: `sentinelforge/ingestion/normalizer.py`, `sentinelforge/storage/schema.py`.
- **Dependencies**: None.
- **Security**: Warnings do not expose raw secrets.
- **Tests**: `tests/test_normalizer_provenance.py`.
- **Expected outcome**: Every normalized event carries source, timestamp, ingestion timestamp, event ID, parser version, provenance, warnings.
- **Priority**: Implement now. **Effort**: Small.

## Priority 3 — Correlation and investigation

### P3-1: Explicit correlation keys + incident grouping
- **Existing status**: Correlator groups by host within a time window only; no incident model; no explicit rationale.
- **Problem**: Same-host/time-window proximity can be mistaken for causation.
- **Solution**: Extend correlator with explicit keys (host, user, process lineage, source/destination IP, time window, ATT&CK behavior); record correlation rationale per group; introduce lightweight incident table (ID, related alerts/events, hosts, users, IPs, severity, status, first/last seen, rationale, evidence completeness).
- **Modules**: `sentinelforge/risk/correlator.py`, `sentinelforge/storage/schema.py`, `sentinelforge/storage/repositories.py`.
- **Dependencies**: P1-1 (detection catalog for ATT&CK keys).
- **Security**: Incident grouping is advisory; no automatic response.
- **Tests**: `tests/test_correlation_keys.py`, `tests/test_incidents.py` — negative control: unrelated hosts/time windows not grouped.
- **Expected outcome**: Correlation is explainable; incidents are distinct from alerts and do not imply causation.
- **Priority**: Implement now. **Effort**: Medium.

### P3-2: Investigation audit ledger
- **Existing status**: MCP `build_investigation_brief` returns deterministic timeline; no audit record of AI/tool inputs/outputs.
- **Problem**: AI-assisted findings are not traceable to evidence.
- **Solution**: Add investigation-ledger table recording investigation ID, evidence references, model/provider ID, prompt digest, tool calls, arguments (sensitive values protected), returned evidence references, AI output, confidence, analyst decision, timestamp, errors/limitations.
- **Modules**: `sentinelforge/storage/schema.py`, `sentinelforge/storage/repositories.py`, `sentinelforge/analyst/mcp_server.py`.
- **Dependencies**: P3-1 (incident scope).
- **Security**: No secrets in ledger; sensitive prompt values protected.
- **Tests**: `tests/test_investigation_ledger.py` — ledger insert/query, redaction of sensitive values.
- **Expected outcome**: Every significant investigation produces a traceable audit record.
- **Priority**: Implement now. **Effort**: Medium.

## Priority 4 — Threat intelligence

### P4-1: Local IOC inventory + validation
- **Existing status**: No IOC capability.
- **Problem**: Cannot match indicators against telemetry.
- **Solution**: Add IOC table (value, type IPv4/IPv6/domain/URL/SHA256, source, confidence, first/last seen, expiration, provenance, external reference); format validation per indicator type.
- **Modules**: `sentinelforge/storage/schema.py`, `sentinelforge/storage/repositories.py`, `sentinelforge/cli/main.py` (`ioc import`).
- **Dependencies**: None.
- **Security**: Indicators treated as untrusted input; no automatic external enrichment.
- **Tests**: `tests/test_ioc.py` — validation, import, deduplication, expiration.
- **Expected outcome**: Validated local IOC store with provenance.
- **Priority**: Implement now. **Effort**: Small.

### P4-2: IOC matching + retro-hunting
- **Existing status**: None.
- **Problem**: New indicators cannot find historical sightings.
- **Solution**: Local matching engine against stored events; historical re-scan on import; retro-hunt findings linked to events with discovery time vs event time preserved; distinct from real-time detections.
- **Modules**: `sentinelforge/analyst/ioc_matcher.py` (new), `sentinelforge/cli/main.py` (`ioc scan`).
- **Dependencies**: P4-1.
- **Security**: No upload of private logs/indicators to third parties.
- **Tests**: `tests/test_ioc_matching.py` — exact match, historical sighting, retro-hunt finding, no false real-time alert.
- **Expected outcome**: Imported IOC surfaces historical sightings as retro-hunt findings, not live detections.
- **Priority**: Implement now. **Effort**: Medium.

## Priority 5 — Analyst experience

### P5-1: Dashboard detection catalog + ATT&CK coverage view
- **Existing status**: Dashboard shows overview/alerts/events/rules/attacks/diagnostics; no per-rule validation status or coverage gaps.
- **Problem**: Analysts cannot see which rules are validated or which techniques lack coverage.
- **Solution**: Add detection-catalog view (rule status, validation status, false-positive summary) and ATT&CK coverage view from P1-3 register.
- **Modules**: `sentinelforge/dashboard/views.py`, `sentinelforge/dashboard/queries.py`, `sentinelforge/dashboard/server.py`.
- **Dependencies**: P1-1, P1-3.
- **Security**: Read-only; dashboard bound to 127.0.0.1.
- **Tests**: `tests/test_dashboard_coverage.py` — view renders real data.
- **Expected outcome**: Dashboard displays actual catalog and coverage data.
- **Priority**: Implement later (after P1-3). **Effort**: Medium.

### P5-2: Entity context view
- **Existing status**: Risk assessments exist; no entity relationship context.
- **Problem**: Analysts cannot pivot across host/user/IP/process/hash.
- **Solution**: Add entity context (host, user, source/destination IP, process, file hash) with alert/event references and risk explanations.
- **Modules**: `sentinelforge/risk/scorer.py` (extend), dashboard entity view.
- **Dependencies**: P3-1.
- **Security**: Entity risk is not a probability of compromise; proximity ≠ causation.
- **Tests**: `tests/test_entity_context.py`.
- **Expected outcome**: Entity risk summary with evidence factors.
- **Priority**: Implement later. **Effort**: Medium.

## Priority 6 — Agent integration

### P6-1: MCP read-only extensions
- **Existing status**: 7 tools (status, list/get alert, alert evidence, search events, investigation brief, risk assessments).
- **Problem**: No MCP access to detection catalog, coverage, IOC, incidents, entity context.
- **Solution**: Add read-only tools only where backed by actual data and bounded queries: detection catalog search, rule details, ATT&CK coverage summary, evaluation summary, IOC search, incident details, entity context.
- **Modules**: `sentinelforge/analyst/mcp_server.py`.
- **Dependencies**: P1-1, P1-3, P3-1, P4-1.
- **Security**: Preserve `mode=ro`, `PRAGMA query_only=ON`, pagination, size limits, read-only annotations.
- **Tests**: `tests/test_mcp_extensions.py`.
- **Expected outcome**: New MCP tools are read-only and bounded.
- **Priority**: Implement later. **Effort**: Medium.

### P6-2: Hermes detection-engineer skill
- **Existing status**: `sentinelforge-soc-analyst` skill exists; needs update to match final tools.
- **Problem: No skill guiding detection engineering workflows.
- **Solution**: Update soc-analyst skill to verified tools; add `sentinelforge-detection-engineer` skill (rule development, validation, Sigma analysis, ATT&CK mapping, tuning, false-positive analysis, evaluation interpretation).
- **Modules**: `integrations/hermes/skills/sentinelforge-soc-analyst/SKILL.md`, `integrations/hermes/skills/sentinelforge-detection-engineer/SKILL.md` (new).
- **Dependencies**: P1-1, P1-3, P6-1.
- **Security**: Document only verified tools.
- **Tests**: Skill content review against implementation.
- **Expected outcome**: Hermes skills match actual capabilities.
- **Priority**: Implement later. **Effort**: Small.

## Priority 7 — Advisory response

### P7-1: Response playbook templates + preview
- **Existing status**: None; SentinelForge is advisory-only.
- **Problem**: No documented recommended actions for analysts.
- **Solution**: Playbook templates naming triggering alert, evidence, reason, expected impact, preconditions, operational risks, required approval. All non-executing.
- **Modules**: `sentinelforge/cli/main.py` (`playbook`), data files.
- **Dependencies**: P3-1.
- **Security**: No automatic blocking, isolation, deletion, or vendor API actions.
- **Tests**: `tests/test_playbook.py` — template rendering, no side effects.
- **Expected outcome**: Advisory recommendations with audit records.
- **Priority**: Implement later. **Effort**: Small.

## Items classified as not appropriate / deferred

| Item | Classification | Reason |
|------|---------------|--------|
| Kafka/Kubernetes/PostgreSQL event pipeline | Not appropriate | Violates lightweight prototype principle; core install must remain dependency-free |
| Neo4j graph database | Not appropriate | Relational SQLite sufficient for initial entity context |
| External threat-intel providers (MISP/OpenCTI) mandatory | Not appropriate | Optional future adapters only; no automatic enrichment |
| Production RBAC / encryption at rest | Deferred | Prototype classification; requires separate security assessment |
| Autonomous response | Not appropriate | Mandatory security constraint; advisory-only |
| Sigma rule compilation (pySigma) | Optional integration | Investigate only if a clear test strategy fits; no unexecutable rules in coverage |

## Effort summary

| Phase | Items | Effort | Timing |
|-------|-------|--------|--------|
| Detection foundation | P1-1 to P1-4 | Small–Medium | First vertical slice |
| Telemetry | P2-1 to P2-5 | Small–Medium | Second slice |
| Correlation/investigation | P3-1, P3-2 | Medium | Third slice |
| Threat intel | P4-1, P4-2 | Small–Medium | Fourth slice |
| Analyst experience | P5-1, P5-2 | Medium | After data model exists |
| Agent integration | P6-1, P6-2 | Small–Medium | After tools exist |
| Advisory response | P7-1 | Small | Last |

Implementation proceeds one vertical slice at a time, each validated by tests before the next begins. The roadmap is bounded — no unbounded feature list.
