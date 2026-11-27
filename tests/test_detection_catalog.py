"""Tests for the structured detection catalog.

Covers catalog registration, entry validity, ATT&CK identifier format, and the
CLI ``detect --list-rules`` surface. These tests assert that every rule has a
catalog entry and that catalog metadata is structurally valid — they do not
assert on detection behavior itself (that is covered per rule elsewhere).
"""

from __future__ import annotations

from sentinelforge.cli.main import _build_registry


def _catalog() -> dict[str, object]:
    registry = _build_registry()
    return registry.catalog.validation_report()


def test_catalog_registers_all_five_rules() -> None:
    report = _catalog()
    assert report["total_entries"] == 5


def test_catalog_all_entries_valid() -> None:
    report = _catalog()
    assert report["all_valid"] is True
    assert report["invalid_entries"] == 0
    assert report["errors"] == {}


def test_no_duplicate_rule_ids() -> None:
    registry = _build_registry()
    ids = [entry.rule_id for entry in registry.catalog.entries()]
    assert len(ids) == len(set(ids))


def test_each_entry_has_required_metadata() -> None:
    registry = _build_registry()
    for entry in registry.catalog.entries():
        assert entry.rule_id
        assert entry.name
        assert entry.version
        assert entry.objective
        assert entry.category
        assert entry.severity is not None
        assert entry.required_fields


def test_attack_technique_format() -> None:
    registry = _build_registry()
    for entry in registry.catalog.entries():
        if entry.attack_technique:
            assert entry.attack_technique.startswith("T"), entry.attack_technique


def test_known_rule_ids_present() -> None:
    registry = _build_registry()
    rule_ids = {entry.rule_id for entry in registry.catalog.entries()}
    expected = {
        "sentinelforge.detection.failed_login_burst",
        "sentinelforge.detection.password_spray",
        "sentinelforge.detection.suspicious_powershell",
        "sentinelforge.detection.suspicious_processtree",
        "sentinelforge.detection.c2_beacon",
    }
    assert expected == rule_ids


def test_list_rules_cli(capsys) -> None:  # type: ignore[no-untyped-def]
    registry = _build_registry()
    from sentinelforge.cli.main import _list_rules

    exit_code = _list_rules(registry)
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "Detection catalog" in captured.out
    assert "Total entries: 5" in captured.out
    assert "All valid: True" in captured.out
    for rule_id in (
        "sentinelforge.detection.failed_login_burst",
        "sentinelforge.detection.password_spray",
        "sentinelforge.detection.suspicious_powershell",
        "sentinelforge.detection.suspicious_processtree",
        "sentinelforge.detection.c2_beacon",
    ):
        assert rule_id in captured.out
