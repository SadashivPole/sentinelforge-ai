"""Tests for the Linux auditd telemetry adapter."""

from __future__ import annotations

from sentinelforge.ingestion.adapters.auditd import AuditdAdapter


def _raw(**fields):
    return fields


def test_process_execution_parses() -> None:
    adapter = AuditdAdapter()
    raw = _raw(
        event_id="auditd-001",
        source="auditd",
        timestamp="2024-01-15T08:30:00Z",
        host="server-1",
        user="root",
        exe="/usr/sbin/sshd",
        command_line="/usr/sbin/sshd -D",
        pid=1234,
        ppid=1233,
        audit_type="auditd",
    )
    assert adapter.can_handle(raw)
    event = adapter.adapt(raw)
    assert event is not None
    assert event.event_id == "auditd-001"
    assert event.source == "auditd"
    assert event.timestamp == "2024-01-15T08:30:00Z"
    assert event.event_type == "auditd"
    assert event.user == "root"
    assert event.host == "server-1"
    assert event.process is not None
    assert event.process.name == "/usr/sbin/sshd"
    assert event.process.command_line == "/usr/sbin/sshd -D"
    assert event.process.pid == 1234
    assert event.process.ppid == 1233
    assert event.process.user == "root"
    assert event.raw == raw


def test_unrelated_payload_not_handled() -> None:
    adapter = AuditdAdapter()
    assert adapter.can_handle({"source": "jsonl", "event_type": "network"}) is False
    assert adapter.adapt({"source": "jsonl", "event_type": "network"}) is None


def test_missing_fields_handled_safely() -> None:
    adapter = AuditdAdapter()
    raw = _raw(source="auditd", exe="/bin/bash")
    event = adapter.adapt(raw)
    assert event is not None
    assert event.event_id == "auditd-None"
    assert event.process is not None
    assert event.process.name == "/bin/bash"
    assert event.process.pid is None
    assert "missing timestamp" in adapter.warnings
    assert "missing host" in adapter.warnings
