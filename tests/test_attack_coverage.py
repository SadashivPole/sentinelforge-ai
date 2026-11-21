"""ATT&CK coverage reporting engine tests."""

from __future__ import annotations

from sentinelforge.attack.catalogue import ATTACKCatalogue
from sentinelforge.attack.coverage import CoverageReporter


def _load_catalogue() -> ATTACKCatalogue:
    return ATTACKCatalogue.from_json("sentinelforge/attack/catalogue.json")


def _load_reporter() -> CoverageReporter:
    return CoverageReporter(_load_catalogue())


# ----------------------------------------------------------- catalogue tests

def test_catalogue_has_69_entries() -> None:
    catalogue = _load_catalogue()
    assert catalogue.count() == 69


def test_status_distribution_matches_baseline() -> None:
    catalogue = _load_catalogue()
    counts = catalogue.count_by_status()
    assert counts.get("IMPLEMENTED_AND_TESTED", 0) == 5
    assert counts.get("TELEMETRY_AVAILABLE_NO_DETECTION", 0) == 17
    assert counts.get("PLANNED_REQUIRES_TELEMETRY", 0) == 0
    assert counts.get("UNSUPPORTED_BY_CURRENT_TELEMETRY", 0) == 47
    assert sum(counts.values()) == 69


def test_no_duplicate_attack_ids() -> None:
    catalogue = _load_catalogue()
    ids = [e.technique_id for e in catalogue.all()]
    assert len(ids) == len(set(ids))


def test_parent_subtechnique_relationships() -> None:
    catalogue = _load_catalogue()
    all_ids = {e.technique_id for e in catalogue.all()}
    for entry in catalogue.all():
        if entry.subtechnique_parent_id is not None:
            assert entry.subtechnique_parent_id in all_ids


def test_all_15_tactics_represented() -> None:
    catalogue = _load_catalogue()
    expected = {
        "TA0043", "TA0042", "TA0001", "TA0002", "TA0003",
        "TA0004", "TA0005", "TA0112", "TA0006", "TA0007",
        "TA0008", "TA0009", "TA0011", "TA0010", "TA0040",
    }
    present = set()
    for entry in catalogue.all():
        present.update(entry.tactic_ids)
    assert expected == present


def test_parent_technique_entries() -> None:
    catalogue = _load_catalogue()
    parents = [e for e in catalogue.all() if e.subtechnique_parent_id is None]
    subtechniques = [e for e in catalogue.all() if e.subtechnique_parent_id is not None]
    assert len(parents) == 52
    assert len(subtechniques) == 17


# ----------------------------------------------------------- coverage tests

def test_direct_mapping_count_is_five() -> None:
    reporter = _load_reporter()
    metrics = reporter.compute_metrics()
    assert metrics.direct_mapping_count == 5


def test_parent_rollups_not_counted_as_implemented() -> None:
    reporter = _load_reporter()
    mapping_table = reporter.get_direct_mapping_table()
    rule_ids = {m["detection_rule"] for m in mapping_table}
    assert len(rule_ids) == 5
    # No parent technique (T1110, T1059, T1204) appears as a direct mapping
    for m in mapping_table:
        assert m["attack_id"] not in ("T1110", "T1059", "T1204")


def test_coverage_percentage_calculation() -> None:
    reporter = _load_reporter()
    metrics = reporter.compute_metrics()
    expected = 5 / 69 * 100
    assert abs(metrics.coverage_percentage - expected) < 0.01


def test_implemented_entries_have_valid_rules() -> None:
    reporter = _load_reporter()
    mapping_table = reporter.get_direct_mapping_table()
    valid_rules = {
        "sentinelforge.detection.failed_login_burst",
        "sentinelforge.detection.password_spray",
        "sentinelforge.detection.suspicious_powershell",
        "sentinelforge.detection.suspicious_processtree",
        "sentinelforge.detection.c2_beacon",
    }
    for m in mapping_table:
        assert m["detection_rule"] in valid_rules


def test_mapping_validation_passes() -> None:
    reporter = _load_reporter()
    errors = reporter.validate_direct_mappings()
    assert not errors


def test_no_division_by_zero() -> None:
    reporter = _load_reporter()
    metrics = reporter.compute_metrics()
    # Should not raise even with 0 entries conceptually
    assert metrics.coverage_percentage >= 0


def test_unsupported_never_counted_as_implemented() -> None:
    catalogue = _load_catalogue()
    implemented = catalogue.implemented_and_tested()
    unsupported = catalogue.by_status("UNSUPPORTED_BY_CURRENT_TELEMETRY")
    implemented_ids = {e.technique_id for e in implemented}
    unsupported_ids = {e.technique_id for e in unsupported}
    assert not (implemented_ids & unsupported_ids)


# ----------------------------------------------------------- tactic tests

def test_tactic_coverage_has_15_entries() -> None:
    reporter = _load_reporter()
    tactics = reporter.compute_tactic_coverage()
    assert len(tactics) == 15


def test_covered_tactics_match_expected() -> None:
    reporter = _load_reporter()
    tactics = reporter.compute_tactic_coverage()
    covered = [t for t in tactics if t.implemented_direct_mappings > 0]
    covered_ids = {t.tactic_id for t in covered}
    assert covered_ids == {"TA0002", "TA0006", "TA0011"}


def test_tactic_counts_non_exclusive() -> None:
    reporter = _load_reporter()
    tactics = reporter.compute_tactic_coverage()
    total_entries = sum(t.catalogue_entries for t in tactics)
    # Multi-tactic techniques mean sum != 69 necessarily
    assert total_entries >= 69


def test_tactic_coverage_structure() -> None:
    reporter = _load_reporter()
    tactics = reporter.compute_tactic_coverage()
    for tc in tactics:
        assert tc.tactic_id
        assert tc.tactic_name
        assert tc.catalogue_entries >= 0
        assert tc.implemented_direct_mappings >= 0
        assert tc.telemetry_available_no_detection >= 0
        assert tc.unsupported_by_current_telemetry >= 0


# ----------------------------------------------------------- telemetry tests

def test_telemetry_coverage_has_log_sources() -> None:
    reporter = _load_reporter()
    telemetry = reporter.compute_telemetry_coverage()
    assert "log_sources" in telemetry
    assert "normalized_data_model" in telemetry


def test_telemetry_inventory_has_windows_sysmon() -> None:
    reporter = _load_reporter()
    telemetry = reporter.compute_telemetry_coverage()
    sources = telemetry["log_sources"]
    assert "windows_sysmon_event_id_1" in sources
    assert "windows_sysmon_event_id_3" in sources
    assert "linux_auth" in sources


def test_raw_only_fields_not_claimed_as_normalized() -> None:
    reporter = _load_reporter()
    telemetry = reporter.compute_telemetry_coverage()
    raw_only = telemetry["raw_only_fields"]
    assert "DNS response data (Sysmon Event ID 22)" in raw_only
    assert "Packet payload inspection" in raw_only
    assert "File content hash verification" in raw_only
