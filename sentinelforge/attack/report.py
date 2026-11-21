"""ATT&CK coverage report generation.

Produces:
1. SENTINELFORGE_MITRE_ATTACK_COVERAGE.json — machine-readable coverage report
2. SENTINELFORGE_MITRE_ATTACK_COVERAGE_REPORT.md — human-readable report

All output is deterministic: same inputs produce identical bytes and SHA-256.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .catalogue import ATTACKCatalogue
from .coverage import (
    DIRECT_MAPPINGS,
    ENTERPRISE_TACTICS,
    TELEMETRY_INVENTORY,
    CoverageReporter,
    CoverageMetrics,
    TacticCoverage,
)

ATTACK_VERSION = "v20.1"
DOMAIN = "enterprise"


def generate_coverage_json(
    catalogue: ATTACKCatalogue,
    reporter: CoverageReporter,
    metrics: CoverageMetrics,
    tactic_coverage: list[TacticCoverage],
    telemetry_coverage: dict[str, Any],
    mapping_table: list[dict[str, Any]],
    output_path: str | Path,
) -> dict[str, Any]:
    """Generate the machine-readable JSON coverage report."""
    report: dict[str, Any] = {
        "report_name": "SentinelForge AI ATT&CK Coverage",
        "attack_version": ATTACK_VERSION,
        "domain": DOMAIN,
        "generated_at": "2026-11-20T00:00:00Z",
        "source_catalogue": {
            "path": "sentinelforge/attack/catalogue.json",
            "catalogue_version": "1.0.0",
            "description": "Curated MITRE ATT&CK Enterprise technique catalogue — reference inventory only",
        },
        "catalogue_summary": metrics.to_dict(),
        "direct_detection_coverage": {
            "direct_mapping_count": metrics.direct_mapping_count,
            "unique_detection_rule_count": metrics.unique_detection_rule_count,
            "covered_tactics": sorted(
                {m["tactic_id"] for m in mapping_table}
            ),
            "uncovered_tactics": sorted(
                {
                    t["id"]
                    for t in ENTERPRISE_TACTICS
                    if t["id"]
                    not in {m["tactic_id"] for m in mapping_table}
                }
            ),
        },
        "tactic_coverage": [tc.to_dict() for tc in tactic_coverage],
        "telemetry_coverage": telemetry_coverage,
        "detection_mappings": mapping_table,
        "coverage_terminology": {
            "catalogue_coverage": (
                "Number of curated entries in the reference catalogue (69). "
                "Not detection capability."
            ),
            "direct_detection_coverage": (
                "Number of techniques/sub-techniques with an actual direct "
                "association to a validated detection rule (5 of 69, ~7.25%)."
            ),
            "telemetry_availability": (
                "Number of catalogue entries with available telemetry but "
                "no implemented detection (17)."
            ),
            "parent_level_coverage": (
                "Parent techniques represented by mapped sub-techniques "
                "(3 roll-ups — not independent detection implementations)."
            ),
            "unsupported_techniques": (
                "Techniques for which current telemetry is insufficient (47)."
            ),
        },
        "limitations": [
            "Catalogue is a curated subset of ATT&CK Enterprise v20.1.",
            "Only five direct detection mappings are implemented.",
            "Synthetic test results do not demonstrate real-world detection effectiveness.",
            "T1204.002 mapping is conditional on file-activity correlation evidence.",
            "T1071 mapping is conditional on protocol-specific C2 context — not confirmation of Command and Control.",
            "ATT&CK mappings do not establish compromise or adversary attribution.",
            "No full enterprise ATT&CK coverage is claimed (5 of 69 curated entries, ~7.25%).",
        ],
    }

    _write_json(output_path, report)
    return report


def generate_markdown_report(
    catalogue: ATTACKCatalogue,
    reporter: CoverageReporter,
    metrics: CoverageMetrics,
    tactic_coverage: list[TacticCoverage],
    telemetry_coverage: dict[str, Any],
    mapping_table: list[dict[str, Any]],
    output_path: str | Path,
) -> str:
    """Generate the human-readable Markdown coverage report."""
    lines: list[str] = []

    lines.append("# SentinelForge AI — MITRE ATT&CK Coverage Report")
    lines.append("")
    lines.append("**Project:** SentinelForge AI")
    lines.append("**ATT&CK Version:** Enterprise v20.1")
    lines.append("**Domain:** Enterprise")
    lines.append("**Catalogue:** 69 curated entries (reference inventory only)")
    lines.append("**Generated:** 2026-11-20T00:00:00Z")
    lines.append("")
    lines.append("---")
    lines.append("")

    # 5.1 Executive overview
    lines.append("## 5.1 Executive Overview")
    lines.append("")
    lines.append(
        "This report describes the ATT&CK coverage reporting engine for "
        "SentinelForge AI. It measures what the system can genuinely detect "
        "against the curated MITRE ATT&CK Enterprise v20.1 catalogue."
    )
    lines.append("")
    lines.append(
        "The report measures three distinct things: catalogue coverage (the "
        "reference inventory), direct detection coverage (techniques with "
        "actual detection rules), and telemetry availability (techniques with "
        "supporting telemetry but no detection rule). These measurements are "
        "never conflated."
    )
    lines.append("")
    lines.append(
        "Catalogue membership is not detection coverage. Of 69 curated "
        "entries, only 5 have implemented detection mappings (~7.25% of the "
        "curated catalogue). The remaining entries are either telemetry-"
        "available without detection (17) or unsupported by current telemetry "
        "(47)."
    )
    lines.append("")

    # 5.2 Coverage summary
    lines.append("## 5.2 Coverage Summary")
    lines.append("")
    lines.append("| Metric | Count |")
    lines.append("|---|---|")
    lines.append(f"| Total catalogue entries | {metrics.total_entries} |")
    lines.append(f"| Parent technique entries | {metrics.parent_technique_entries} |")
    lines.append(f"| Sub-technique entries | {metrics.subtechnique_entries} |")
    lines.append(f"| Unique ATT&CK IDs | {metrics.unique_attack_ids} |")
    lines.append(f"| Implemented and tested | {metrics.implemented_and_tested} |")
    lines.append(f"| Telemetry available, no detection | {metrics.telemetry_available_no_detection} |")
    lines.append(f"| Planned, requires telemetry | {metrics.planned_requires_telemetry} |")
    lines.append(f"| Unsupported by current telemetry | {metrics.unsupported_by_current_telemetry} |")
    lines.append(f"| Direct detection mappings | {metrics.direct_mapping_count} |")
    lines.append(f"| Unique detection rules | {metrics.unique_detection_rule_count} |")
    lines.append(f"| Coverage percentage (of catalogue) | {metrics.coverage_percentage}% |")
    lines.append("")
    lines.append(
        f"The coverage percentage ({metrics.coverage_percentage}%) is the "
        f"proportion of the curated catalogue (69 entries) with direct "
        f"implemented mappings (5). It is not overall ATT&CK Enterprise "
        f"coverage."
    )
    lines.append("")

    # 5.3 Tactic coverage
    lines.append("## 5.3 Tactic Coverage (All 15 Enterprise Tactics)")
    lines.append("")
    lines.append(
        "Tactic counts are non-exclusive: a technique may belong to multiple "
        "tactics. The sum of per-tactic entries does not equal 69."
    )
    lines.append("")
    lines.append(
        "| Tactic ID | Tactic Name | Catalogue Entries | Implemented Direct Mappings | Telemetry Available, No Detection | Unsupported | Detection Rules |"
    )
    lines.append(
        "|---|---|---|---|---|---|---|"
    )
    for tc in tactic_coverage:
        lines.append(
            f"| {tc.tactic_id} | {tc.tactic_name} | {tc.catalogue_entries} | "
            f"{tc.implemented_direct_mappings} | "
            f"{tc.telemetry_available_no_detection} | "
            f"{tc.unsupported_by_current_telemetry} | "
            f"{', '.join(sorted(tc.detection_rules)) or '—'} |"
        )
    lines.append("")

    # Tactics with actual detection coverage
    covered_tactics = [
        tc for tc in tactic_coverage if tc.implemented_direct_mappings > 0
    ]
    lines.append("### Tactics with Implemented Detection Coverage")
    lines.append("")
    for tc in covered_tactics:
        lines.append(
            f"- **{tc.tactic_name}** ({tc.tactic_id}): "
            f"{tc.implemented_direct_mappings} mapping(s) via "
            f"{', '.join(sorted(tc.detection_rules))}"
        )
    lines.append("")
    lines.append("### Tactics Without Implemented Detection Coverage")
    lines.append("")
    uncovered = [tc for tc in tactic_coverage if tc.implemented_direct_mappings == 0]
    for tc in uncovered:
        lines.append(
            f"- **{tc.tactic_name}** ({tc.tactic_id}): "
            f"{tc.catalogue_entries} catalogue entries, 0 implemented mappings"
        )
    lines.append("")

    # 5.4 Detection mapping matrix
    lines.append("## 5.4 Detection Mapping Matrix")
    lines.append("")
    lines.append(
        "All five direct rule-to-technique associations are validated against "
        "the catalogue. Parent roll-ups (T1110, T1059, T1204) are not counted "
        "as independent detections."
    )
    lines.append("")
    lines.append(
        "| Detection Rule | ATT&CK ID | Technique | Tactic | Confidence | Status |"
    )
    lines.append("|---|---|---|---|---|---|")
    for m in mapping_table:
        lines.append(
            f"| {m['detection_rule']} | {m['attack_id']} | {m['technique_name']} | "
            f"{m['tactic']} ({m['tactic_id']}) | {m['mapping_confidence']} | "
            f"{m['catalogue_status']} |"
        )
    lines.append("")

    # 5.5 Telemetry coverage
    lines.append("## 5.5 Telemetry Coverage Analysis")
    lines.append("")
    lines.append(
        "Telemetry coverage is derived from the normalized event schema in "
        "`sentinelforge/ingestion/normalizer.py`. Fields preserved only in "
        "raw payloads are distinguished from normalized fields."
    )
    lines.append("")
    lines.append("### Normalized Data Model Fields")
    lines.append("")
    lines.append("| Category | Fields |")
    lines.append("|---|---|")
    lines.append(f"| Process | {', '.join(telemetry_coverage['normalized_data_model']['process'])} |")
    lines.append(f"| Network | {', '.join(telemetry_coverage['normalized_data_model']['network'])} |")
    lines.append(f"| Authentication | {', '.join(telemetry_coverage['normalized_data_model']['authentication'])} |")
    lines.append(f"| Event | {', '.join(telemetry_coverage['normalized_data_model']['event'])} |")
    lines.append("")

    lines.append("### Log Source Coverage Matrix")
    lines.append("")
    lines.append(
        "| Log Source | Normalized Fields | Supported Detections | Gaps |"
    )
    lines.append("|---|---|---|---|")
    for source_id, source in telemetry_coverage["log_sources"].items():
        fields = ", ".join(source["normalized_fields"])
        detections = ", ".join(source["supported_detections"]) or "—"
        gaps = ", ".join(source["gaps"]) or "—"
        lines.append(f"| {source['name']} | {fields} | {detections} | {gaps} |")
    lines.append("")

    lines.append("### Raw-Only Fields (Not Normalized)")
    lines.append("")
    for field in telemetry_coverage["raw_only_fields"]:
        lines.append(f"- {field}")
    lines.append("")

    # 5.6 Coverage gaps
    lines.append("## 5.6 Coverage Gaps")
    lines.append("")
    lines.append(
        "The following techniques have available telemetry but no detection "
        "rule implemented:"
    )
    lines.append("")
    telemetry_available = catalogue.by_status("TELEMETRY_AVAILABLE_NO_DETECTION")
    for entry in sorted(telemetry_available, key=lambda e: e.technique_id):
        lines.append(
            f"- **{entry.technique_id}** — {entry.technique_name} "
            f"({entry.tactic_ids[0] if entry.tactic_ids else 'N/A'})"
        )
    lines.append("")
    lines.append(
        "The following techniques lack required telemetry entirely and are "
        "unsupported:"
    )
    lines.append("")
    unsupported = catalogue.by_status("UNSUPPORTED_BY_CURRENT_TELEMETRY")
    for entry in sorted(unsupported, key=lambda e: e.technique_id):
        lines.append(
            f"- **{entry.technique_id}** — {entry.technique_name} "
            f"({entry.tactic_ids[0] if entry.tactic_ids else 'N/A'})"
        )
    lines.append("")

    # 5.7 Parent roll-ups
    lines.append("## 5.7 Parent Technique Roll-Ups")
    lines.append("")
    lines.append(
        "Three parent techniques are covered through their sub-techniques. "
        "They are roll-ups, not independent detection implementations."
    )
    lines.append("")
    lines.append("| Parent Technique | Covered Sub-technique(s) | Detection Rule |")
    lines.append("|---|---|---|")
    lines.append(
        "| T1110 Brute Force | T1110.001 (Password Guessing), T1110.003 (Password Spraying) | "
        "FailedLoginBurstRule, PasswordSprayRule |"
    )
    lines.append(
        "| T1059 Command and Scripting Interpreter | T1059.001 (PowerShell) | SuspiciousPowerShellRule |"
    )
    lines.append(
        "| T1204 User Execution | T1204.002 (Malicious File) | SuspiciousProcessTreeRule |"
    )
    lines.append("")
    lines.append(
        "These parent techniques are marked TELEMETRY_AVAILABLE_NO_DETECTION "
        "in the catalogue and are NOT counted as independently implemented "
        "detections."
    )
    lines.append("")

    # 5.8 Limitations
    lines.append("## 5.8 Limitations")
    lines.append("")
    lines.append(
        "- The catalogue is a curated subset of ATT&CK Enterprise v20.1, not "
        "the full matrix."
    )
    lines.append(
        "- Only five direct detection mappings are implemented across five "
        "rules."
    )
    lines.append(
        "- Synthetic test results do not demonstrate real-world detection "
        "effectiveness."
    )
    lines.append(
        "- T1204.002 mapping is conditional on file-activity correlation "
        "evidence — a process-tree anomaly alone does not prove malicious "
        "file execution."
    )
    lines.append(
        "- T1071 mapping is conditional on protocol-specific C2 context "
        "(non-standard port + suspicious process/raw IP) — it is not "
        "confirmation of Command and Control."
    )
    lines.append(
        "- ATT&CK mappings do not establish compromise or adversary "
        "attribution."
    )
    lines.append(
        "- No full enterprise ATT&CK coverage is claimed."
    )
    lines.append("")

    # 5.9 Future development
    lines.append("## 5.9 Future Development")
    lines.append("")
    lines.append(
        "The following are recommendations, not implemented capabilities:"
    )
    lines.append("")
    lines.append(
        "- **File content hash verification**: Enables higher confidence for "
        "T1204.002 and supports T1486 (Data Encrypted for Impact)."
    )
    lines.append(
        "- **DNS response data**: Enables T1071.004 (DNS) specificity and "
        "DNS tunneling detection."
    )
    lines.append(
        "- **Outbound data volume monitoring**: Enables T1041 (Exfiltration "
        "Over C2 Channel)."
    )
    lines.append(
        "- **Registry monitoring**: Enables T1547.001 (Registry Run Keys)."
    )
    lines.append(
        "- **Web proxy logs**: Enables T1071.001 (Web Protocols) with web "
        "traffic context."
    )
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append(
        "End of report. All figures calculated programmatically from the "
        "catalogue and detection rule metadata."
    )

    report_text = "\n".join(lines)
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(report_text, encoding="utf-8")
    return report_text


def _write_json(path: str | Path, data: dict[str, Any]) -> None:
    """Write deterministic JSON with sorted keys and stable formatting."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    path.write_text(text, encoding="utf-8")


def compute_sha256(path: str | Path) -> str:
    """Compute SHA-256 hash of a file."""
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()
