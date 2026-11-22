"""ATT&CK catalogue validation tests."""

from __future__ import annotations

from sentinelforge.attack.catalogue import (
    TACTIC_ID_RE,
    TECHNIQUE_ID_RE,
    VALID_CONFIDENCE_LEVELS,
    VALID_STATUSES,
    ATTACKCatalogue,
    TechniqueEntry,
)


def _load_catalogue() -> ATTACKCatalogue:
    return ATTACKCatalogue.from_json("sentinelforge/attack/catalogue.json")


def test_catalogue_loads() -> None:
    catalogue = _load_catalogue()
    assert catalogue.count() > 0


def test_technique_id_validity() -> None:
    catalogue = _load_catalogue()
    for entry in catalogue.all():
        assert TECHNIQUE_ID_RE.match(entry.technique_id), (
            f"Invalid technique_id: {entry.technique_id}"
        )


def test_tactic_id_validity() -> None:
    catalogue = _load_catalogue()
    for entry in catalogue.all():
        for tactic_id in entry.tactic_ids:
            assert TACTIC_ID_RE.match(tactic_id), (
                f"Invalid tactic_id: {tactic_id} in {entry.technique_id}"
            )


def test_no_duplicate_ids() -> None:
    catalogue = _load_catalogue()
    ids = [e.technique_id for e in catalogue.all()]
    assert len(ids) == len(set(ids)), "Duplicate technique IDs found"


def test_subtechnique_parent_exists() -> None:
    catalogue = _load_catalogue()
    all_ids = {e.technique_id for e in catalogue.all()}
    for entry in catalogue.all():
        if entry.subtechnique_parent_id is not None:
            assert entry.subtechnique_parent_id in all_ids, (
                f"Sub-technique {entry.technique_id} references "
                f"nonexistent parent {entry.subtechnique_parent_id}"
            )


def test_status_validity() -> None:
    catalogue = _load_catalogue()
    for entry in catalogue.all():
        assert entry.detection_status in VALID_STATUSES, (
            f"Invalid status {entry.detection_status} for {entry.technique_id}"
        )


def test_confidence_validity() -> None:
    catalogue = _load_catalogue()
    for entry in catalogue.all():
        assert entry.mapping_confidence in VALID_CONFIDENCE_LEVELS, (
            f"Invalid confidence {entry.mapping_confidence} for {entry.technique_id}"
        )


def test_implemented_entries_have_rules() -> None:
    catalogue = _load_catalogue()
    for entry in catalogue.implemented_and_tested():
        assert entry.associated_detection_rule_ids, (
            f"IMPLEMENTED_AND_TESTED entry {entry.technique_id} has no rules"
        )


def test_mapping_rationale_present() -> None:
    catalogue = _load_catalogue()
    for entry in catalogue.all():
        if entry.detection_status in (
            "IMPLEMENTED_AND_TESTED",
            "IMPLEMENTED_NEEDS_VALIDATION",
            "TELEMETRY_AVAILABLE_NO_DETECTION",
        ):
            assert entry.mapping_rationale.strip(), (
                f"Entry {entry.technique_id} has empty mapping_rationale"
            )


def test_all_15_tactics_represented() -> None:
    catalogue = _load_catalogue()
    expected_tactics = {
        "TA0043",
        "TA0042",
        "TA0001",
        "TA0002",
        "TA0003",
        "TA0004",
        "TA0005",
        "TA0112",
        "TA0006",
        "TA0007",
        "TA0008",
        "TA0009",
        "TA0011",
        "TA0010",
        "TA0040",
    }
    present = set()
    for entry in catalogue.all():
        present.update(entry.tactic_ids)
    assert expected_tactics == present, (
        f"Missing tactics: {expected_tactics - present}, "
        f"extra tactics: {present - expected_tactics}"
    )


def test_catalogue_validation_passes() -> None:
    catalogue = _load_catalogue()
    errors = catalogue.validate()
    assert not errors, f"Catalogue validation errors: {errors}"


def test_entry_serialization_roundtrip() -> None:
    catalogue = _load_catalogue()
    for entry in catalogue.all():
        d = entry.to_dict()
        restored = TechniqueEntry.from_dict(d)
        assert restored == entry


def test_implemented_entries_count() -> None:
    catalogue = _load_catalogue()
    implemented = catalogue.implemented_and_tested()
    assert len(implemented) >= 5, (
        f"Expected at least 5 implemented entries, got {len(implemented)}"
    )


def test_implemented_entries_match_existing_rules() -> None:
    catalogue = _load_catalogue()
    rule_ids = {
        "sentinelforge.detection.failed_login_burst",
        "sentinelforge.detection.password_spray",
        "sentinelforge.detection.suspicious_powershell",
        "sentinelforge.detection.suspicious_processtree",
        "sentinelforge.detection.c2_beacon",
    }
    for entry in catalogue.implemented_and_tested():
        for rule_id in entry.associated_detection_rule_ids:
            assert rule_id in rule_ids, (
                f"Unexpected rule_id {rule_id} for {entry.technique_id}"
            )


def test_count_by_status() -> None:
    catalogue = _load_catalogue()
    counts = catalogue.count_by_status()
    assert "IMPLEMENTED_AND_TESTED" in counts
    assert "TELEMETRY_AVAILABLE_NO_DETECTION" in counts
    assert "UNSUPPORTED_BY_CURRENT_TELEMETRY" in counts


def test_count_by_tactic() -> None:
    catalogue = _load_catalogue()
    counts = catalogue.count_by_tactic()
    assert "TA0006" in counts
    assert "TA0002" in counts
    assert "TA0011" in counts


def test_technique_vs_subtechnique_counts() -> None:
    catalogue = _load_catalogue()
    techniques = [e for e in catalogue.all() if e.subtechnique_parent_id is None]
    subtechniques = [e for e in catalogue.all() if e.subtechnique_parent_id is not None]
    assert len(techniques) + len(subtechniques) == catalogue.count()
    assert len(techniques) > 0
    assert len(subtechniques) > 0


def test_catalogue_version_pinned() -> None:
    catalogue = _load_catalogue()
    for entry in catalogue.all():
        assert entry.attack_version == "v20.1", (
            f"Entry {entry.technique_id} has attack_version {entry.attack_version}"
        )
