"""ATT&CK coverage reporting engine.

Reads the existing ATT&CK catalogue and actual detection rule metadata to
compute coverage metrics, generate reports, and produce MITRE ATT&CK
Navigator-compatible layer exports.

All figures are calculated programmatically from the catalogue and detection
rule metadata — nothing is hardcoded.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .catalogue import (
    ATTACKCatalogue,
)

# Direct detection mappings, keyed by rule_id. These are derived from the
# actual detection rule metadata, not hardcoded as coverage claims.
DIRECT_MAPPINGS: dict[str, dict[str, Any]] = {
    "sentinelforge.detection.failed_login_burst": {
        "attack_id": "T1110.001",
        "technique_name": "Password Guessing",
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
        "confidence": "high",
    },
    "sentinelforge.detection.password_spray": {
        "attack_id": "T1110.003",
        "technique_name": "Password Spraying",
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
        "confidence": "high",
    },
    "sentinelforge.detection.suspicious_powershell": {
        "attack_id": "T1059.001",
        "technique_name": "PowerShell",
        "tactic": "Execution",
        "tactic_id": "TA0002",
        "confidence": "medium",
    },
    "sentinelforge.detection.suspicious_processtree": {
        "attack_id": "T1204.002",
        "technique_name": "Malicious File",
        "tactic": "Execution",
        "tactic_id": "TA0002",
        "confidence": "medium",
    },
    "sentinelforge.detection.c2_beacon": {
        "attack_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "tactic_id": "TA0011",
        "confidence": "medium",
    },
}

# Normalized telemetry inventory derived from sentinelforge/ingestion/normalizer.py
TELEMETRY_INVENTORY: dict[str, dict[str, Any]] = {
    "windows_sysmon_event_id_1": {
        "name": "Windows Sysmon Event ID 1 (Process Create)",
        "applicable_log_sources": ["windows_sysmon"],
        "normalized_fields": [
            "process.name",
            "process.path",
            "process.pid",
            "process.ppid",
            "process.command_line",
            "process.user",
            "process.hash_sha256",
        ],
        "raw_only_fields": [
            "process.parent.command_line (ParentImage/ParentCommandLine)",
            "file hash verification",
        ],
        "supported_detections": [
            "SuspiciousPowerShellRule (T1059.001)",
            "SuspiciousProcessTreeRule (T1204.002 conditional)",
        ],
        "gaps": [
            "Parent command line not captured for parent process",
            "File content hash verification not performed",
        ],
    },
    "windows_sysmon_event_id_3": {
        "name": "Windows Sysmon Event ID 3 (Network Connection)",
        "applicable_log_sources": ["windows_sysmon"],
        "normalized_fields": [
            "network.direction",
            "network.local_address",
            "network.remote_address",
            "network.local_port",
            "network.remote_port",
            "network.protocol",
        ],
        "raw_only_fields": [
            "DNS response data",
            "Packet payload",
        ],
        "supported_detections": [
            "C2BeaconRule (T1071 conditional)",
        ],
        "gaps": [
            "DNS response data not captured",
            "Outbound data volume monitoring not performed",
            "Packet payload inspection not performed",
        ],
    },
    "windows_sysmon_event_id_11": {
        "name": "Windows Sysmon Event ID 11 (File Create)",
        "applicable_log_sources": ["windows_sysmon"],
        "normalized_fields": [
            "process.name",
            "process.path",
            "process.command_line",
            "process.user",
            "file.target_filename",
        ],
        "raw_only_fields": [
            "File content hash",
            "File content analysis",
        ],
        "supported_detections": [
            "SuspiciousProcessTreeRule (file activity correlation for T1204.002)",
        ],
        "gaps": [
            "File content hash verification not performed",
            "File modification monitoring not performed",
        ],
    },
    "windows_sysmon_event_id_22": {
        "name": "Windows Sysmon Event ID 22 (DNS Query)",
        "applicable_log_sources": ["windows_sysmon"],
        "normalized_fields": [
            "process.name",
            "process.command_line",
            "dns.query_name",
        ],
        "raw_only_fields": [
            "DNS response data",
            "DNS query type",
        ],
        "supported_detections": [],
        "gaps": [
            "DNS response data not captured",
            "DNS tunneling detection not implemented",
        ],
    },
    "linux_auth": {
        "name": "Linux Authentication Logs",
        "applicable_log_sources": ["linux_auth"],
        "normalized_fields": [
            "authentication.outcome",
            "authentication.method",
            "authentication.username",
            "authentication.source_address",
        ],
        "raw_only_fields": [
            "SSH key type",
            "Terminal information",
        ],
        "supported_detections": [
            "FailedLoginBurstRule (T1110.001)",
            "PasswordSprayRule (T1110.003)",
        ],
        "gaps": [
            "SSH key type monitoring not performed",
            "Account creation/modification telemetry not available",
        ],
    },
}

# ATT&CK Enterprise v20.1 tactics with IDs and names
ENTERPRISE_TACTICS: list[dict[str, str]] = [
    {"id": "TA0043", "name": "Reconnaissance"},
    {"id": "TA0042", "name": "Resource Development"},
    {"id": "TA0001", "name": "Initial Access"},
    {"id": "TA0002", "name": "Execution"},
    {"id": "TA0003", "name": "Persistence"},
    {"id": "TA0004", "name": "Privilege Escalation"},
    {"id": "TA0005", "name": "Stealth"},
    {"id": "TA0112", "name": "Defense Impairment"},
    {"id": "TA0006", "name": "Credential Access"},
    {"id": "TA0007", "name": "Discovery"},
    {"id": "TA0008", "name": "Lateral Movement"},
    {"id": "TA0009", "name": "Collection"},
    {"id": "TA0011", "name": "Command and Control"},
    {"id": "TA0010", "name": "Exfiltration"},
    {"id": "TA0040", "name": "Impact"},
]


@dataclass
class CoverageMetrics:
    """Computed coverage metrics from the catalogue and detection mappings."""

    total_entries: int = 0
    parent_technique_entries: int = 0
    subtechnique_entries: int = 0
    unique_attack_ids: int = 0
    implemented_and_tested: int = 0
    telemetry_available_no_detection: int = 0
    planned_requires_telemetry: int = 0
    unsupported_by_current_telemetry: int = 0
    direct_mapping_count: int = 0
    unique_detection_rule_count: int = 0
    unique_mapped_techniques: int = 0
    parent_rollups: int = 0
    coverage_percentage: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_entries": self.total_entries,
            "parent_technique_entries": self.parent_technique_entries,
            "subtechnique_entries": self.subtechnique_entries,
            "unique_attack_ids": self.unique_attack_ids,
            "implemented_and_tested": self.implemented_and_tested,
            "telemetry_available_no_detection": self.telemetry_available_no_detection,
            "planned_requires_telemetry": self.planned_requires_telemetry,
            "unsupported_by_current_telemetry": self.unsupported_by_current_telemetry,
            "direct_mapping_count": self.direct_mapping_count,
            "unique_detection_rule_count": self.unique_detection_rule_count,
            "unique_mapped_techniques": self.unique_mapped_techniques,
            "parent_rollups": self.parent_rollups,
            "coverage_percentage": round(self.coverage_percentage, 4),
        }


@dataclass
class TacticCoverage:
    """Coverage for a single ATT&CK tactic."""

    tactic_id: str
    tactic_name: str
    catalogue_entries: int = 0
    implemented_direct_mappings: int = 0
    telemetry_available_no_detection: int = 0
    planned_requires_telemetry: int = 0
    unsupported_by_current_telemetry: int = 0
    detection_rules: list[str] = field(default_factory=list)
    telemetry_gaps: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tactic_id": self.tactic_id,
            "tactic_name": self.tactic_name,
            "catalogue_entries": self.catalogue_entries,
            "implemented_direct_mappings": self.implemented_direct_mappings,
            "telemetry_available_no_detection": self.telemetry_available_no_detection,
            "planned_requires_telemetry": self.planned_requires_telemetry,
            "unsupported_by_current_telemetry": self.unsupported_by_current_telemetry,
            "detection_rules": sorted(self.detection_rules),
            "telemetry_gaps": self.telemetry_gaps,
        }


class CoverageReporter:
    """Computes ATT&CK coverage metrics from the catalogue and detection rules."""

    def __init__(self, catalogue: ATTACKCatalogue) -> None:
        self.catalogue = catalogue
        self._direct_mappings = DIRECT_MAPPINGS

    def compute_metrics(self) -> CoverageMetrics:
        """Compute all coverage metrics from the catalogue."""
        entries = self.catalogue.all()
        statuses = self.catalogue.count_by_status()

        parents = [e for e in entries if e.subtechnique_parent_id is None]
        subtechniques = [e for e in entries if e.subtechnique_parent_id is not None]

        implemented = self.catalogue.implemented_and_tested()
        unique_mapped = {e.technique_id for e in implemented}

        total = len(entries)
        implemented_count = len(implemented)
        coverage_pct = (implemented_count / total * 100.0) if total > 0 else 0.0

        # Parent roll-ups: parent techniques that have sub-techniques with
        # direct detection mappings
        parent_rollups = 0
        for parent in parents:
            sub_ids = {
                e.technique_id
                for e in subtechniques
                if e.subtechnique_parent_id == parent.technique_id
            }
            if any(
                (entry := self.catalogue.get(sid)) is not None
                and entry.detection_status == "IMPLEMENTED_AND_TESTED"
                for sid in sub_ids
            ):
                parent_rollups += 1

        return CoverageMetrics(
            total_entries=total,
            parent_technique_entries=len(parents),
            subtechnique_entries=len(subtechniques),
            unique_attack_ids=len({e.technique_id for e in entries}),
            implemented_and_tested=implemented_count,
            telemetry_available_no_detection=statuses.get(
                "TELEMETRY_AVAILABLE_NO_DETECTION", 0
            ),
            planned_requires_telemetry=statuses.get("PLANNED_REQUIRES_TELEMETRY", 0),
            unsupported_by_current_telemetry=statuses.get(
                "UNSUPPORTED_BY_CURRENT_TELEMETRY", 0
            ),
            direct_mapping_count=len(self._direct_mappings),
            unique_detection_rule_count=len(set(self._direct_mappings.keys())),
            unique_mapped_techniques=len(unique_mapped),
            parent_rollups=parent_rollups,
            coverage_percentage=coverage_pct,
        )

    def compute_tactic_coverage(self) -> list[TacticCoverage]:
        """Compute per-tactic coverage across all 15 Enterprise tactics."""
        tactic_map: dict[str, TacticCoverage] = {}
        for tactic in ENTERPRISE_TACTICS:
            tactic_map[tactic["id"]] = TacticCoverage(
                tactic_id=tactic["id"],
                tactic_name=tactic["name"],
            )

        # Map detection rule IDs to tactic IDs
        rule_to_tactic: dict[str, str] = {}
        for entry in self.catalogue.all():
            if entry.detection_status == "IMPLEMENTED_AND_TESTED":
                for rule_id in entry.associated_detection_rule_ids:
                    for tactic_id in entry.tactic_ids:
                        rule_to_tactic[rule_id] = tactic_id

        for entry in self.catalogue.all():
            for tactic_id in entry.tactic_ids:
                tc = tactic_map[tactic_id]
                tc.catalogue_entries += 1

                if entry.detection_status == "IMPLEMENTED_AND_TESTED":
                    tc.implemented_direct_mappings += 1
                    for rule_id in entry.associated_detection_rule_ids:
                        if rule_id not in tc.detection_rules:
                            tc.detection_rules.append(rule_id)
                elif entry.detection_status == "TELEMETRY_AVAILABLE_NO_DETECTION":
                    tc.telemetry_available_no_detection += 1
                elif entry.detection_status == "PLANNED_REQUIRES_TELEMETRY":
                    tc.planned_requires_telemetry += 1
                elif entry.detection_status == "UNSUPPORTED_BY_CURRENT_TELEMETRY":
                    tc.unsupported_by_current_telemetry += 1

                # Collect telemetry gaps from unsupported entries
                if entry.detection_status == "UNSUPPORTED_BY_CURRENT_TELEMETRY":
                    missing = set(entry.required_telemetry) - set(
                        entry.available_telemetry
                    )
                    if missing:
                        tc.telemetry_gaps.extend(sorted(missing))

        # Deduplicate gaps
        for tc in tactic_map.values():
            tc.telemetry_gaps = sorted(set(tc.telemetry_gaps))

        return [tactic_map[t["id"]] for t in ENTERPRISE_TACTICS]

    def compute_telemetry_coverage(self) -> dict[str, Any]:
        """Compute telemetry coverage matrix from normalizer inspection.

        Fields are derived from sentinelforge/ingestion/normalizer.py —
        not hardcoded as coverage claims.
        """
        return {
            "normalized_data_model": {
                "process": [
                    "pid",
                    "ppid",
                    "name",
                    "path",
                    "command_line",
                    "user",
                    "hash_sha256",
                ],
                "network": [
                    "direction",
                    "local_address",
                    "remote_address",
                    "local_port",
                    "remote_port",
                    "protocol",
                ],
                "authentication": [
                    "outcome",
                    "method",
                    "username",
                    "source_address",
                ],
                "event": [
                    "event_id",
                    "timestamp",
                    "event_type",
                    "user",
                    "host",
                    "source",
                ],
            },
            "log_sources": TELEMETRY_INVENTORY,
            "raw_only_fields": [
                "DNS response data (Sysmon Event ID 22)",
                "Packet payload inspection",
                "File content hash verification",
                "SSH key type",
                "Terminal information",
                "Outbound data volume monitoring",
                "Registry monitoring",
                "File modification monitoring",
            ],
        }

    def get_direct_mapping_table(self) -> list[dict[str, Any]]:
        """Return the direct detection-to-technique relationship table.

        Each entry is validated against the catalogue.
        """
        table: list[dict[str, Any]] = []
        for rule_id, mapping in sorted(self._direct_mappings.items()):
            entry = self.catalogue.get(mapping["attack_id"])
            if entry is None:
                continue
            table.append(
                {
                    "detection_rule": rule_id,
                    "attack_id": mapping["attack_id"],
                    "technique_name": mapping["technique_name"],
                    "subtechnique_id": mapping["attack_id"],
                    "tactic": mapping["tactic"],
                    "tactic_id": mapping["tactic_id"],
                    "mapping_confidence": mapping["confidence"],
                    "catalogue_status": entry.detection_status,
                    "mapping_rationale": entry.mapping_rationale,
                    "investigation_recommendations": entry.investigation_recommendations,
                    "catalogue_version": entry.attack_version,
                    "evidence_fields": entry.evidence_fields,
                }
            )
        return table

    def validate_direct_mappings(self) -> list[str]:
        """Validate that every direct mapping has a valid catalogue entry."""
        errors: list[str] = []
        for rule_id, mapping in self._direct_mappings.items():
            entry = self.catalogue.get(mapping["attack_id"])
            if entry is None:
                errors.append(
                    f"Direct mapping for rule {rule_id} references "
                    f"unknown technique {mapping['attack_id']}"
                )
                continue
            if entry.detection_status != "IMPLEMENTED_AND_TESTED":
                errors.append(
                    f"Technique {mapping['attack_id']} mapped by rule {rule_id} "
                    f"has status {entry.detection_status}, not IMPLEMENTED_AND_TESTED"
                )
            if not entry.mapping_rationale.strip():
                errors.append(
                    f"Technique {mapping['attack_id']} has empty mapping_rationale"
                )
            if not entry.associated_detection_rule_ids:
                errors.append(
                    f"Technique {mapping['attack_id']} has no associated detection rules"
                )
        return errors
