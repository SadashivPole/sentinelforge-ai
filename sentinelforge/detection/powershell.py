"""Suspicious PowerShell detection rule.

Detects PowerShell command lines that exhibit common attack indicators:

- Encoded commands (`-EncodedCommand`, `-enc`, `-e`)
- Hidden execution (`-Hidden`, `-WindowStyle Hidden`)
- Execution policy bypass (`-ExecutionPolicy Bypass`, `-ep bypass`, `Set-ExecutionPolicy Bypass`)
- Download-and-execute (`Invoke-WebRequest`, `iwr`, `Invoke-Expression`, `iex`, `DownloadString`, `Net.WebClient`)
- Obfuscation (`[Convert]::FromBase64String`, `[char]`, string concatenation, `-Join`)

Supports both ``powershell.exe`` and ``pwsh.exe``. Matching is case-insensitive
and operates on the command line as text only — no command content is ever
executed. Multiple indicators occurring together raise the score and severity.

Every alert cites the exact original log event(s) as evidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional

from sentinelforge.detection.base import (
    DetectionResult,
    DetectionRule,
    Evidence,
    Severity,
)
from sentinelforge.ingestion.normalizer import NormalizedEvent

# PowerShell process names to inspect (case-insensitive).
POWERSHELL_PROCESS_NAMES = {"powershell.exe", "pwsh.exe", "powershell", "pwsh"}

# Indicator patterns: category -> (regex, weight).
# Weight reflects how strongly the indicator suggests malicious intent on its own.
INDICATOR_PATTERNS: dict[str, tuple[re.Pattern[str], int]] = {
    "encoded_command": (
        re.compile(
            r"(?:^|\s)-encodedcommand\b|(?:^|\s)-enc\b|(?:^|\s)-e\b",
            re.IGNORECASE,
        ),
        6,
    ),
    "hidden_execution": (
        re.compile(r"(?:^|\s)-hidden\b|(?:^|\s)-windowstyle\s+hidden\b", re.IGNORECASE),
        2,
    ),
    "execution_policy_bypass": (
        re.compile(
            r"(?:^|\s)-executionpolicy\s+bypass\b|(?:^|\s)-ep\s+bypass\b"
            r"|set-executionpolicy\s+bypass",
            re.IGNORECASE,
        ),
        6,
    ),
    "download_and_execute": (
        re.compile(
            r"invoke-webrequest|\biwr\b|invoke-expression|\biex\b"
            r"|downloadstring|net\.webclient|\.downloadfile\b",
            re.IGNORECASE,
        ),
        6,
    ),
    "obfuscation": (
        re.compile(
            r"frombase64string|\[convert\]::|\[char\]|-join\s|convertto-securestring",
            re.IGNORECASE,
        ),
        2,
    ),
}

# Score thresholds for severity assignment.
SCORE_LOW = 2
SCORE_MEDIUM = 4
SCORE_HIGH = 6


def _is_powershell_process(process_name: Optional[str]) -> bool:
    if not process_name:
        return False
    return process_name.strip().lower() in POWERSHELL_PROCESS_NAMES


def _basename(path_or_name: Optional[str]) -> Optional[str]:
    """Return the final path component of a process path/name, lowercased."""
    if not path_or_name:
        return None
    text = path_or_name.strip()
    # Handle both forward and back slashes.
    text = text.replace("/", "\\")
    parts = text.split("\\")
    return parts[-1].lower() if parts else None


def _match_indicators(command_line: Optional[str]) -> list[tuple[str, int]]:
    """Return list of (category, weight) for indicators found in the command line."""
    if not command_line:
        return []
    hits: list[tuple[str, int]] = []
    for category, (pattern, weight) in INDICATOR_PATTERNS.items():
        if pattern.search(command_line):
            hits.append((category, weight))
    return hits


@dataclass
class SuspiciousPowerShellRule(DetectionRule):
    """Flags PowerShell command lines with suspicious indicators."""

    rule_id: str = "sentinelforge.detection.suspicious_powershell"
    name: str = "Suspicious PowerShell"
    description: str = (
        "PowerShell command line contains encoded, hidden, bypass, download/execute "
        "or obfuscation indicators"
    )
    severity: Severity = Severity.HIGH
    # Minimum total indicator weight to trigger.
    threshold: int = field(default=4)
    # Which indicator categories are enabled.
    enabled_categories: set[str] = field(
        default_factory=lambda: set(INDICATOR_PATTERNS.keys())
    )
    metadata: dict[str, Any] = field(
        default_factory=lambda: {
            "mitre_attack_technique": "T1059.001",
            "mitre_attack_tactic": "Execution",
            "mitre_attack_tactic_id": "TA0002",
            "mitre_attack_mapping_confidence": "medium",
            "mitre_attack_mapping_rationale": "PowerShell process execution with suspicious indicators (encoded command, execution policy bypass, download-and-execute) is consistent with T1059.001, but benign administrative PowerShell usage can also contain encoded commands.",
            "mitre_attack_investigation_recommendations": [
                "Decode encoded commands",
                "Check user account activity",
                "Review PowerShell transcription logs",
                "Isolate host if command is malicious",
            ],
            "mitre_attack_catalogue_version": "v20.1",
        }
    )

    def __post_init__(self) -> None:
        if self.metadata is None:
            self.metadata = {}
        self.metadata = dict(self.metadata)

    def evaluate(self, events: list[NormalizedEvent]) -> list[DetectionResult]:
        results: list[DetectionResult] = []
        seen_ids: set[str] = set()

        for event in events:
            event_id = event.event_id
            if event_id in seen_ids:
                continue  # deduplicate by event id

            process = event.process
            if process is None:
                continue
            process_name = _basename(process.name or process.path)
            if not _is_powershell_process(process_name):
                continue

            command_line = process.command_line
            hits = [
                (category, weight)
                for category, weight in _match_indicators(command_line)
                if category in self.enabled_categories
            ]
            if not hits:
                continue  # ordinary administrative PowerShell — no alert

            total_weight = sum(weight for _, weight in hits)
            if total_weight < self.threshold:
                continue  # below threshold — likely benign admin use

            seen_ids.add(event_id)

            severity = self._severity_for_score(total_weight, len(hits))
            categories = sorted({category for category, _ in hits})
            description = (
                f"Suspicious PowerShell ({process_name or 'unknown'}) with "
                f"{len(hits)} indicator(s): {', '.join(categories)} "
                f"(weight {total_weight}, threshold {self.threshold})"
            )

            rule_metadata = dict(self.metadata)
            rule_metadata.update(
                {
                    "process_name": process_name,
                    "process_path": process.path,
                    "command_line": command_line,
                    "indicators": categories,
                    "indicator_weights": {category: weight for category, weight in hits},
                    "total_weight": total_weight,
                    "threshold": self.threshold,
                    "host": event.host,
                    "user": event.user,
                }
            )

            results.append(
                DetectionResult(
                    rule_id=self.rule_id,
                    rule_name=self.name,
                    severity=severity,
                    description=description,
                    evidence=[
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
                    ],
                    metadata=rule_metadata,
                )
            )

        return results

    @staticmethod
    def _severity_for_score(total_weight: int, indicator_count: int) -> Severity:
        if total_weight >= SCORE_HIGH or indicator_count >= 3:
            return Severity.HIGH
        if total_weight >= SCORE_MEDIUM or indicator_count >= 2:
            return Severity.MEDIUM
        return Severity.LOW
