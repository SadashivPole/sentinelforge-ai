"""Suspicious parent-child process detection rule.

Flags configurable suspicious process relationships, for example a Microsoft
Office application spawning PowerShell:

- WINWORD.EXE  -> powershell.exe
- EXCEL.EXE    -> powershell.exe
- wscript.exe  -> powershell.exe
- mshta.exe    -> powershell.exe

Process names are normalized (extension stripped, case-insensitive) before
matching. Events are linked by matching each child's ``ppid`` to a parent
event's ``pid``. Missing parent or command-line information is handled safely
and recorded as part of the evidence rather than inferred.

A parent-child relationship is suspicious context, not proof of compromise;
results carry a confidence score and false-positive considerations so a SOC
analyst can triage appropriately.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sentinelforge.config import settings
from sentinelforge.detection.base import (
    DetectionResult,
    DetectionRule,
    Evidence,
    RuleCatalogEntry,
    Severity,
)
from sentinelforge.ingestion.normalizer import NormalizedEvent

# Default suspicious (parent, child) relationships. Names are normalized
# (lowercased, extension stripped) before comparison.
DEFAULT_SUSPICIOUS_RELATIONSHIPS: list[tuple[str, str]] = [
    ("winword", "powershell"),
    ("winword", "pwsh"),
    ("excel", "powershell"),
    ("excel", "pwsh"),
    ("wscript", "powershell"),
    ("wscript", "pwsh"),
    ("mshta", "powershell"),
    ("mshta", "pwsh"),
]


# Flags that take a value token; the value is not a file operand.
_VALUE_TAKING_FLAGS = {
    "-executionpolicy",
    "-ep",
    "-file",
    "-f",
    "-command",
    "-c",
    "-encodedcommand",
    "-enc",
    "-windowstyle",
}

# File activity event types that indicate file creation/download/opening.
FILE_ACTIVITY_TYPES = {
    "file.create",
    "file.created",
    "file.open",
    "file.opened",
    "file.write",
    "file.written",
    "file.modify",
    "file.modified",
    "file_access",
    "fileaccess",
    "file.download",
    "file.downloaded",
}

# Raw-log keys that commonly hold a file path.
_FILE_PATH_KEYS = (
    "FileName",
    "file_name",
    "file_path",
    "FilePath",
    "TargetFilename",
    "Image",
    "path",
    "filename",
    "File",
    "file",
)


def _parse_timestamp(value: str | None) -> datetime | None:
    """Parse an ISO-8601 timestamp string into an aware UTC datetime."""
    if not value:
        return None
    text = value.strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


def _extract_file_path(raw: dict | None) -> str | None:
    """Extract a file path from a raw event dict."""
    if not raw or not isinstance(raw, dict):
        return None
    for key in _FILE_PATH_KEYS:
        value = raw.get(key)
        if value and isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _normalize_file_path(path: str | None) -> str | None:
    """Normalize a file path for comparison: lowercase, strip trailing slash."""
    if not path:
        return None
    text = path.strip().lower().replace("/", "\\")
    while text.endswith("\\") and len(text) > 1:
        text = text[:-1]
    return text or None


def _extract_file_operands(command_line: str | None) -> list[str]:
    """Extract file operands from a command line (non-flag tokens after the
    executable, skipping values of value-taking flags).

    Value-taking flags are skipped, but the value token is still evaluated
    as a potential file operand (e.g. -File C:\\path\\file.doc yields the
    path as an operand).
    """
    if not command_line:
        return []
    parts = command_line.strip().split()
    if len(parts) < 2:
        return []
    operands: list[str] = []
    i = 1
    skip_next = False
    while i < len(parts):
        token = parts[i]
        if skip_next:
            skip_next = False
            # Still evaluate this token as a potential file operand.
            if not token.startswith(("-", "/")):
                operands.append(token)
            i += 1
            continue
        if token.lower() in _VALUE_TAKING_FLAGS:
            skip_next = True
            i += 1
            continue
        if not token.startswith(("-", "/")):
            operands.append(token)
        i += 1
    return operands


def _build_file_activity_index(
    events: list[NormalizedEvent],
) -> dict:
    """Index file activity events by (host, user, normalized_file_path)."""
    index: dict = {}
    for event in events:
        if event.event_type and event.event_type.strip().lower() in FILE_ACTIVITY_TYPES:
            file_path = _normalize_file_path(
                _extract_file_path(event.raw)
                or (event.process.command_line if event.process else None)
            )
            if not file_path:
                continue
            key = (event.host, event.user, file_path)
            index.setdefault(key, []).append(event)
    return index


def _has_correlated_file_activity(
    file_activity_index: dict,
    child_host: str | None,
    child_user: str | None,
    file_operands: list[str],
    child_timestamp: datetime | None,
    window_seconds: int,
) -> bool:
    """Check if any file operand correlates with a file activity event."""
    if not file_operands or child_timestamp is None:
        return False
    for operand in file_operands:
        norm_path = _normalize_file_path(operand)
        if not norm_path:
            continue
        key = (child_host, child_user, norm_path)
        for file_event in file_activity_index.get(key, []):
            file_ts = _parse_timestamp(file_event.timestamp)
            if file_ts is None:
                continue
            if file_ts <= child_timestamp:
                delta = (child_timestamp - file_ts).total_seconds()
                if 0 <= delta <= window_seconds:
                    return True
    return False


# Confidence bands.
CONFIDENCE_HIGH = "high"
CONFIDENCE_MEDIUM = "medium"
CONFIDENCE_LOW = "low"


def _normalize_process_name(name: str | None) -> str | None:
    """Normalize a process name: strip path/extension, lowercase.

    Returns None when no name is available.
    """
    if not name:
        return None
    text = name.strip()
    # Take the final path component.
    text = os.path.basename(text.replace("/", "\\"))
    # Strip known executable extensions.
    for ext in (".exe", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js"):
        if text.lower().endswith(ext):
            text = text[: -len(ext)]
            break
    return text.lower() or None


def _build_parent_index(events: list[NormalizedEvent]) -> dict[int, NormalizedEvent]:
    """Index process events by pid so children can locate their parent."""
    index: dict[int, NormalizedEvent] = {}
    for event in events:
        process = event.process
        if process is None or process.pid is None:
            continue
        # Keep the first event seen for a given pid.
        index.setdefault(process.pid, event)
    return index


@dataclass
class SuspiciousProcessTreeRule(DetectionRule):
    """Flags suspicious parent-child process relationships.

    T1204.002 (Malicious File) attribution requires cross-event correlation:
    a file activity event (create/download/open) must be correlated with a
    subsequent process execution event on the same host and user, within a
    configurable time window. A command line and event_type from the same
    process event alone are insufficient for ATT&CK attribution.
    """

    rule_id: str = "sentinelforge.detection.suspicious_processtree"
    name: str = "Suspicious Parent-Child Process"
    description: str = (
        "A child process was spawned by a suspicious parent process "
        "(e.g. Office application launching PowerShell)"
    )
    severity: Severity = Severity.MEDIUM
    suspicious_relationships: list[tuple[str, str]] = field(
        default_factory=lambda: list(DEFAULT_SUSPICIOUS_RELATIONSHIPS)
    )
    file_activity_window_seconds: int = field(
        default_factory=lambda: settings.failed_login_window_seconds
    )
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.metadata is None:
            self.metadata = {}
        self.metadata = dict(self.metadata)
        # Normalize configured relationships once.
        self._normalized_relationships = [
            (_normalize_process_name(parent), _normalize_process_name(child))
            for parent, child in self.suspicious_relationships
            if _normalize_process_name(parent) and _normalize_process_name(child)
        ]

    def _confidence(
        self,
        child_command_line: str | None,
        parent_command_line: str | None,
        parent_found: bool,
    ) -> str:
        """Confidence reflects how much corroborating evidence exists.

        A relationship alone is suspicious context, not proof of compromise.
        Scoring: parent found (+1), child command line present (+1),
        parent command line present (+1). Two or more points = high
        confidence; a single point = low confidence.
        """
        score = 0
        if parent_found:
            score += 1
        if child_command_line:
            score += 1
        if parent_command_line:
            score += 1
        if score >= 2:
            return CONFIDENCE_HIGH
        return CONFIDENCE_LOW

    def evaluate(self, events: list[NormalizedEvent]) -> list[DetectionResult]:
        results: list[DetectionResult] = []
        seen_child_ids: set[str] = set()

        parent_index = _build_parent_index(events)
        # Index file activity events for cross-event T1204.002 correlation.
        file_activity_index = _build_file_activity_index(events)
        window_seconds = self.file_activity_window_seconds

        for event in events:
            event_id = event.event_id
            if event_id in seen_child_ids:
                continue  # deduplicate child events by event id

            process = event.process
            if process is None or process.ppid is None:
                continue  # no parent relationship to evaluate

            child_name = _normalize_process_name(process.name or process.path)
            if not child_name:
                continue

            parent_event = parent_index.get(process.ppid)
            if parent_event is None:
                # Parent process not present in this event set. Record the
                # relationship cautiously rather than fabricating parent detail.
                parent_name = None
                parent_command_line = None
                parent_found = False
            else:
                parent_process = parent_event.process
                parent_name = (
                    _normalize_process_name(parent_process.name or parent_process.path)
                    if parent_process
                    else None
                )
                parent_command_line = (
                    parent_process.command_line if parent_process else None
                )
                parent_found = True

            matched = False
            for rel_parent, rel_child in self._normalized_relationships:
                if rel_parent == parent_name and rel_child == child_name:
                    matched = True
                    break
            if not matched:
                continue

            seen_child_ids.add(event_id)

            child_command_line = process.command_line
            confidence = self._confidence(
                child_command_line, parent_command_line, parent_found
            )

            description = (
                f"Suspicious process relationship: "
                f"{parent_name or '<unknown>'} (ppid={process.ppid}) -> "
                f"{child_name} (pid={process.pid}) "
                f"[{confidence} confidence]"
            )

            rule_metadata = dict(self.metadata)
            # T1204.002 requires cross-event correlation: a file activity
            # event (create/download/open) must be correlated with this
            # process execution on the same host and user, within the
            # configurable time window. A command line and event_type from
            # the same process event alone are insufficient for ATT&CK
            # attribution. If required telemetry is absent, the mapping is
            # left empty.
            file_operands = _extract_file_operands(child_command_line)
            child_ts = _parse_timestamp(event.timestamp)
            if _has_correlated_file_activity(
                file_activity_index,
                event.host,
                event.user,
                file_operands,
                child_ts,
                window_seconds,
            ):
                rule_metadata.update(
                    {
                        "mitre_attack_technique": "T1204",
                        "mitre_attack_subtechnique": "T1204.002",
                        "mitre_attack_tactic": "Execution",
                        "mitre_attack_tactic_id": "TA0002",
                        "mitre_attack_mapping_confidence": "medium",
                        "mitre_attack_mapping_rationale": "Office application spawning PowerShell with correlated file activity is consistent with User Execution: Malicious File. A process-tree anomaly alone does not prove a user opened a malicious file; file activity correlation provides supporting evidence.",
                        "mitre_attack_investigation_recommendations": [
                            "Check email attachments and web downloads",
                            "Review parent process context",
                            "Correlate with file creation events",
                            "Isolate host if malicious",
                        ],
                        "mitre_attack_catalogue_version": "v20.1",
                    }
                )
            rule_metadata.update(
                {
                    "parent_name": parent_name,
                    "parent_pid": process.ppid,
                    "parent_command_line": parent_command_line,
                    "parent_found": parent_found,
                    "child_name": child_name,
                    "child_pid": process.pid,
                    "child_command_line": child_command_line,
                    "confidence": confidence,
                    "host": event.host,
                    "user": event.user,
                    "false_positive_note": (
                        "Legitimate administration or software updates can spawn "
                        "PowerShell from Office applications; correlate with "
                        "command-line content and user context before acting."
                    ),
                }
            )

            # Evidence from both parent and child events when available.
            evidence: list[Evidence] = [
                Evidence(
                    event_id=event.event_id,
                    timestamp=event.timestamp or "",
                    source=event.source,
                    event_type=event.event_type,
                    user=event.user,
                    host=event.host,
                    source_address=None,
                    raw=event.raw,
                )
            ]
            if parent_event is not None:
                parent_process = parent_event.process
                evidence.append(
                    Evidence(
                        event_id=parent_event.event_id,
                        timestamp=parent_event.timestamp or "",
                        source=parent_event.source,
                        event_type=parent_event.event_type,
                        user=parent_event.user,
                        host=parent_event.host,
                        source_address=None,
                        raw=parent_event.raw,
                    )
                )

            results.append(
                DetectionResult(
                    rule_id=self.rule_id,
                    rule_name=self.name,
                    severity=self.severity,
                    description=description,
                    evidence=evidence,
                    metadata=rule_metadata,
                )
            )

        return results


CATALOG_ENTRY = RuleCatalogEntry(
    rule_id="sentinelforge.detection.suspicious_processtree",
    name="Suspicious Parent-Child Process",
    version="1.0.0",
    objective=(
        "Flag suspicious parent-child process relationships (e.g., Office "
        "application launching PowerShell) with confidence scoring"
    ),
    category="execution",
    severity=Severity.MEDIUM,
    attack_tactic="Execution",
    attack_tactic_id="TA0002",
    attack_technique="T1204.002",
    attack_technique_id=None,
    required_data_source="process execution logs (Sysmon)",
    required_fields=[
        "event_type",
        "process_name",
        "parent_process",
        "host",
        "timestamp",
        "ppid",
        "pid",
    ],
    threshold="configured suspicious relationships",
    time_window_seconds="settings.failed_login_window_seconds (file-activity window)",
    false_positive_conditions=[
        "Legitimate administrative automation spawning interpreters",
        "Developer toolchains launching child processes",
    ],
    investigation_instructions=[
        "Examine parent and child command lines",
        "Check file-activity events preceding process execution",
        "Correlate by host and user within the time window",
    ],
    external_references=["MITRE ATT&CK T1204 / T1204.002"],
    test_references=[
        "tests/test_detection_rules.py::test_word_spawns_powershell_triggers",
        "tests/test_detection_rules.py::test_normal_process_relationship_no_alert",
        "tests/test_detection_rules.py::test_wrong_host_no_t1204",
    ],
    execution_status="working",
    validation_status="validated",
)
