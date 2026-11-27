"""Tests for the Windows Security telemetry adapter."""

from __future__ import annotations

from sentinelforge.ingestion.adapters.win_security import WinSecurityAdapter


def _raw(**fields):
    return fields


def test_failed_logon_4625_parses() -> None:
    adapter = WinSecurityAdapter()
    raw = _raw(
        event_id="win-4625-001",
        source="win_security",
        timestamp="2024-01-15T08:30:00Z",
        event_id_code=4625,
        computer="WKSTN-10",
        target_username="administrator",
        source_address="10.0.0.99",
        authentication_package="NTLM",
        logon_type=3,
    )
    assert adapter.can_handle(raw)
    event = adapter.adapt(raw)
    assert event is not None
    assert event.event_id == "win-4625-001"
    assert event.source == "win_security"
    assert event.timestamp == "2024-01-15T08:30:00Z"
    assert event.event_type == "authentication.failure"
    assert event.user == "administrator"
    assert event.host == "WKSTN-10"
    assert event.authentication is not None
    assert event.authentication.outcome == "failure"
    assert event.authentication.username == "administrator"
    assert event.authentication.source_address == "10.0.0.99"
    assert event.raw == raw


def test_successful_logon_4624_parses() -> None:
    adapter = WinSecurityAdapter()
    raw = _raw(
        event_id="win-4624-002",
        source="win_security",
        timestamp="2024-01-15T08:31:00Z",
        event_id_code=4624,
        computer="WKSTN-10",
        target_username="bob",
        source_address="10.0.0.50",
        authentication_package="Kerberos",
    )
    event = adapter.adapt(raw)
    assert event is not None
    assert event.event_type == "authentication.success"
    assert event.authentication is not None
    assert event.authentication.outcome == "success"


def test_process_creation_4688_parses() -> None:
    adapter = WinSecurityAdapter()
    raw = _raw(
        event_id="win-4688-003",
        source="win_security",
        timestamp="2024-01-15T08:32:00Z",
        event_id_code=4688,
        computer="WKSTN-10",
        target_username="bob",
        source_address="10.0.0.50",
    )
    event = adapter.adapt(raw)
    assert event is not None
    assert event.event_type == "process_creation"


def test_unrelated_payload_not_handled() -> None:
    adapter = WinSecurityAdapter()
    assert adapter.can_handle({"source": "jsonl", "event_type": "network"}) is False
    assert adapter.adapt({"source": "jsonl", "event_type": "network"}) is None


def test_missing_fields_handled_safely() -> None:
    adapter = WinSecurityAdapter()
    raw = _raw(source="win_security", event_id_code=4625)
    event = adapter.adapt(raw)
    assert event is not None
    assert event.event_id == "win-4625"
    assert event.event_type == "authentication.failure"
    assert event.user is None
    assert event.host is None
    assert "missing timestamp" in adapter.warnings
    assert "missing host" in adapter.warnings
    assert "missing source_address" in adapter.warnings


def test_string_event_id_code() -> None:
    adapter = WinSecurityAdapter()
    raw = _raw(
        source="win_security",
        event_id="win-x",
        event_id_code="4625",
        computer="H",
        target_username="u",
        source_address="1.2.3.4",
    )
    event = adapter.adapt(raw)
    assert event is not None
    assert event.event_type == "authentication.failure"
