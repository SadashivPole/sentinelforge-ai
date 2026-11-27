"""Tests for the Linux authentication telemetry adapter."""

from __future__ import annotations

from sentinelforge.ingestion.adapters.linux_auth import LinuxAuthAdapter


def _raw(**fields):
    return fields


def test_ssh_failed_login_parses() -> None:
    adapter = LinuxAuthAdapter()
    raw = _raw(
        event_id="linux-auth-001",
        source="linux_auth",
        timestamp="2024-01-15T08:30:00Z",
        program="sshd",
        username="root",
        source_address="10.0.0.99",
        outcome="failure",
        host="server-1",
    )
    assert adapter.can_handle(raw)
    event = adapter.adapt(raw)
    assert event is not None
    assert event.event_id == "linux-auth-001"
    assert event.source == "linux_auth"
    assert event.timestamp == "2024-01-15T08:30:00Z"
    assert event.event_type == "authentication"
    assert event.user == "root"
    assert event.host == "server-1"
    assert event.authentication is not None
    assert event.authentication.outcome == "failure"
    assert event.authentication.method == "sshd"
    assert event.authentication.source_address == "10.0.0.99"
    assert event.raw == raw


def test_sudo_privilege_escalation_parses() -> None:
    adapter = LinuxAuthAdapter()
    raw = _raw(
        event_id="linux-auth-002",
        source="linux_auth",
        timestamp="2024-01-15T08:31:00Z",
        program="sudo",
        username="alice",
        source_address="10.0.0.50",
        outcome="success",
        host="server-1",
    )
    event = adapter.adapt(raw)
    assert event is not None
    assert event.event_type == "privilege_escalation"
    assert event.authentication is not None
    assert event.authentication.method == "sudo"
    assert event.authentication.outcome == "success"


def test_unrelated_payload_not_handled() -> None:
    adapter = LinuxAuthAdapter()
    assert adapter.can_handle({"source": "jsonl", "event_type": "network"}) is False
    assert adapter.adapt({"source": "jsonl", "event_type": "network"}) is None


def test_missing_fields_handled_safely() -> None:
    adapter = LinuxAuthAdapter()
    raw = _raw(source="linux_auth", program="sshd")
    event = adapter.adapt(raw)
    assert event is not None
    assert event.event_id == "linux-auth-None"
    assert event.event_type == "authentication"
    assert event.user is None
    assert "missing timestamp" in adapter.warnings
    assert "missing host" in adapter.warnings
    assert "missing source_address" in adapter.warnings
