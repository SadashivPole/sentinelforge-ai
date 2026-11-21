"""ATT&CK Navigator export tests."""

from __future__ import annotations

import json
from pathlib import Path

from sentinelforge.attack.catalogue import ATTACKCatalogue
from sentinelforge.attack.coverage import CoverageReporter
from sentinelforge.attack.navigator import (
    generate_primary_layer,
    generate_secondary_layer,
    compute_sha256,
)


def _load_catalogue() -> ATTACKCatalogue:
    return ATTACKCatalogue.from_json("sentinelforge/attack/catalogue.json")


def _load_reporter() -> CoverageReporter:
    return CoverageReporter(_load_catalogue())


# ----------------------------------------------------------- navigator format tests

def test_primary_layer_is_valid_json() -> None:
    catalogue = _load_catalogue()
    reporter = _load_reporter()
    layer = generate_primary_layer(catalogue, reporter, "/tmp/primary_test.json")
    assert "name" in layer
    assert "versions" in layer
    assert "domain" in layer
    assert "techniques" in layer
    assert "legend" in layer


def test_primary_layer_has_exactly_five_techniques() -> None:
    catalogue = _load_catalogue()
    reporter = _load_reporter()
    layer = generate_primary_layer(catalogue, reporter, "/tmp/primary_test.json")
    assert len(layer["techniques"]) == 5


def test_primary_layer_no_parent_rollups() -> None:
    catalogue = _load_catalogue()
    reporter = _load_reporter()
    layer = generate_primary_layer(catalogue, reporter, "/tmp/primary_test.json")
    technique_ids = {t["techniqueID"] for t in layer["techniques"]}
    assert "T1110" not in technique_ids
    assert "T1059" not in technique_ids
    assert "T1204" not in technique_ids


def test_primary_layer_all_enabled() -> None:
    catalogue = _load_catalogue()
    reporter = _load_reporter()
    layer = generate_primary_layer(catalogue, reporter, "/tmp/primary_test.json")
    for t in layer["techniques"]:
        assert t["enabled"] is True


def test_primary_layer_correct_technique_ids() -> None:
    catalogue = _load_catalogue()
    reporter = _load_reporter()
    layer = generate_primary_layer(catalogue, reporter, "/tmp/primary_test.json")
    expected = {"T1110.001", "T1110.003", "T1059.001", "T1204.002", "T1071"}
    actual = {t["techniqueID"] for t in layer["techniques"]}
    assert actual == expected


def test_primary_layer_has_tactic_and_confidence() -> None:
    catalogue = _load_catalogue()
    reporter = _load_reporter()
    layer = generate_primary_layer(catalogue, reporter, "/tmp/primary_test.json")
    for t in layer["techniques"]:
        assert t["tactic"]  # tactic slug present
        assert "CONFIDENCE:" in t["comment"]
        assert "RATIONALE:" in t["comment"]


def test_secondary_layer_has_69_techniques() -> None:
    catalogue = _load_catalogue()
    reporter = _load_reporter()
    layer = generate_secondary_layer(catalogue, reporter, "/tmp/secondary_test.json")
    assert len(layer["techniques"]) == 69


def test_secondary_layer_only_five_enabled() -> None:
    catalogue = _load_catalogue()
    reporter = _load_reporter()
    layer = generate_secondary_layer(catalogue, reporter, "/tmp/secondary_test.json")
    enabled = [t for t in layer["techniques"] if t["enabled"]]
    assert len(enabled) == 5


def test_secondary_layer_warning_present() -> None:
    catalogue = _load_catalogue()
    reporter = _load_reporter()
    layer = generate_secondary_layer(catalogue, reporter, "/tmp/secondary_test.json")
    desc = layer["description"]
    assert "NOT a representation of implemented detection coverage" in desc


def test_secondary_layer_parent_rollups_disabled() -> None:
    catalogue = _load_catalogue()
    reporter = _load_reporter()
    layer = generate_secondary_layer(catalogue, reporter, "/tmp/secondary_test.json")
    technique_map = {t["techniqueID"]: t for t in layer["techniques"]}
    for parent_id in ("T1110", "T1059", "T1204"):
        assert technique_map[parent_id]["enabled"] is False


# ----------------------------------------------------------- determinism tests

def test_primary_layer_deterministic() -> None:
    catalogue = _load_catalogue()
    reporter = _load_reporter()
    generate_primary_layer(catalogue, reporter, "/tmp/primary_det_1.json")
    hash1 = compute_sha256("/tmp/primary_det_1.json")
    generate_primary_layer(catalogue, reporter, "/tmp/primary_det_2.json")
    hash2 = compute_sha256("/tmp/primary_det_2.json")
    assert hash1 == hash2


def test_secondary_layer_deterministic() -> None:
    catalogue = _load_catalogue()
    reporter = _load_reporter()
    generate_secondary_layer(catalogue, reporter, "/tmp/secondary_det_1.json")
    hash1 = compute_sha256("/tmp/secondary_det_1.json")
    generate_secondary_layer(catalogue, reporter, "/tmp/secondary_det_2.json")
    hash2 = compute_sha256("/tmp/secondary_det_2.json")
    assert hash1 == hash2


# ----------------------------------------------------------- navigator format tests

def test_primary_layer_has_correct_versions() -> None:
    catalogue = _load_catalogue()
    reporter = _load_reporter()
    layer = generate_primary_layer(catalogue, reporter, "/tmp/primary_test.json")
    assert layer["versions"]["attack"] == "v20.1"
    assert layer["versions"]["layer"] == "4.5"
    assert layer["versions"]["navigator"] == "4.9.0"
    assert layer["domain"] == "enterprise-attack"


def test_secondary_layer_has_correct_versions() -> None:
    catalogue = _load_catalogue()
    reporter = _load_reporter()
    layer = generate_secondary_layer(catalogue, reporter, "/tmp/secondary_test.json")
    assert layer["versions"]["attack"] == "v20.1"
    assert layer["versions"]["layer"] == "4.5"
    assert layer["versions"]["navigator"] == "4.9.0"
    assert layer["domain"] == "enterprise-attack"


def test_generated_files_exist() -> None:
    """Verify the committed output files exist and are valid JSON."""
    files = [
        "SENTINELFORGE_MITRE_ATTACK_COVERAGE.json",
        "SENTINELFORGE_MITRE_ATTACK_COVERAGE_REPORT.md",
        "sentinelforge_implemented_detection_coverage.json",
        "sentinelforge_attack_catalogue_readiness.json",
    ]
    for f in files:
        assert Path(f).exists(), f"Missing file: {f}"
    # Validate JSON files parse
    for f in files:
        if f.endswith(".json"):
            with open(f) as fh:
                json.load(fh)


# ----------------------------------------------------------- navigator v4.5 format tests

def test_primary_layer_has_select_visible_techniques() -> None:
    catalogue = _load_catalogue()
    reporter = _load_reporter()
    layer = generate_primary_layer(catalogue, reporter, "/tmp/primary_test.json")
    assert layer["selectVisibleTechniques"] is True

def test_primary_layer_has_expanded_subtechniques() -> None:
    """expandedSubtechniques must be inside layout as a string, not at top level as a boolean."""
    catalogue = _load_catalogue()
    reporter = _load_reporter()
    layer = generate_primary_layer(catalogue, reporter, "/tmp/primary_test.json")
    assert "expandedSubtechniques" not in layer, (
        "expandedSubtechniques must not be at top level"
    )
    val = layer["layout"]["expandedSubtechniques"]
    assert isinstance(val, str), (
        f"expandedSubtechniques must be a string, got {type(val).__name__}"
    )
    assert val == "none", f"expandedSubtechniques must be 'none', got {val!r}"

def test_secondary_layer_has_select_visible_techniques() -> None:
    catalogue = _load_catalogue()
    reporter = _load_reporter()
    layer = generate_secondary_layer(catalogue, reporter, "/tmp/secondary_test.json")
    assert layer["selectVisibleTechniques"] is True

def test_secondary_layer_has_expanded_subtechniques() -> None:
    """expandedSubtechniques must be inside layout as a string, not at top level as a boolean."""
    catalogue = _load_catalogue()
    reporter = _load_reporter()
    layer = generate_secondary_layer(catalogue, reporter, "/tmp/secondary_test.json")
    assert "expandedSubtechniques" not in layer, (
        "expandedSubtechniques must not be at top level"
    )
    val = layer["layout"]["expandedSubtechniques"]
    assert isinstance(val, str), (
        f"expandedSubtechniques must be a string, got {type(val).__name__}"
    )
    assert val == "none", f"expandedSubtechniques must be 'none', got {val!r}"

def test_primary_layer_navigator_min_version() -> None:
    catalogue = _load_catalogue()
    reporter = _load_reporter()
    layer = generate_primary_layer(catalogue, reporter, "/tmp/primary_test.json")
    assert layer["versions"]["navigator"] == "4.9.0"


def test_secondary_layer_navigator_min_version() -> None:
    catalogue = _load_catalogue()
    reporter = _load_reporter()
    layer = generate_secondary_layer(catalogue, reporter, "/tmp/secondary_test.json")
    assert layer["versions"]["navigator"] == "4.9.0"


def test_primary_layer_layer_version_45() -> None:
    catalogue = _load_catalogue()
    reporter = _load_reporter()
    layer = generate_primary_layer(catalogue, reporter, "/tmp/primary_test.json")
    assert layer["versions"]["layer"] == "4.5"


def test_secondary_layer_layer_version_45() -> None:
    catalogue = _load_catalogue()
    reporter = _load_reporter()
    layer = generate_secondary_layer(catalogue, reporter, "/tmp/secondary_test.json")
    assert layer["versions"]["layer"] == "4.5"


# ----------------------------------------------------------- navigator v4.5 schema tests

def test_primary_layer_expanded_subtechniques_in_layout() -> None:
    """expandedSubtechniques must be inside layout, not at top level."""
    catalogue = _load_catalogue()
    reporter = _load_reporter()
    layer = generate_primary_layer(catalogue, reporter, "/tmp/primary_test.json")
    assert "expandedSubtechniques" not in layer, (
        "expandedSubtechniques must not be at top level"
    )
    assert layer["layout"]["expandedSubtechniques"] == "none"


def test_secondary_layer_expanded_subtechniques_in_layout() -> None:
    """expandedSubtechniques must be inside layout, not at top level."""
    catalogue = _load_catalogue()
    reporter = _load_reporter()
    layer = generate_secondary_layer(catalogue, reporter, "/tmp/secondary_test.json")
    assert "expandedSubtechniques" not in layer, (
        "expandedSubtechniques must not be at top level"
    )
    assert layer["layout"]["expandedSubtechniques"] == "none"


def test_primary_layer_select_visible_techniques_top_level() -> None:
    """selectVisibleTechniques must be at top level as a Boolean."""
    catalogue = _load_catalogue()
    reporter = _load_reporter()
    layer = generate_primary_layer(catalogue, reporter, "/tmp/primary_test.json")
    assert layer["selectVisibleTechniques"] is True
    assert isinstance(layer["selectVisibleTechniques"], bool)


def test_secondary_layer_select_visible_techniques_top_level() -> None:
    """selectVisibleTechniques must be at top level as a Boolean."""
    catalogue = _load_catalogue()
    reporter = _load_reporter()
    layer = generate_secondary_layer(catalogue, reporter, "/tmp/secondary_test.json")
    assert layer["selectVisibleTechniques"] is True
    assert isinstance(layer["selectVisibleTechniques"], bool)


def test_primary_layer_expanded_subtechniques_is_string() -> None:
    """expandedSubtechniques must be a string, not a boolean."""
    catalogue = _load_catalogue()
    reporter = _load_reporter()
    layer = generate_primary_layer(catalogue, reporter, "/tmp/primary_test.json")
    val = layer["layout"]["expandedSubtechniques"]
    assert isinstance(val, str), f"expandedSubtechniques must be a string, got {type(val).__name__}"
    assert val in ("none", "all", "annotated"), (
        f"expandedSubtechniques must be one of 'none', 'all', 'annotated', got {val!r}"
    )


def test_secondary_layer_expanded_subtechniques_is_string() -> None:
    """expandedSubtechniques must be a string, not a boolean."""
    catalogue = _load_catalogue()
    reporter = _load_reporter()
    layer = generate_secondary_layer(catalogue, reporter, "/tmp/secondary_test.json")
    val = layer["layout"]["expandedSubtechniques"]
    assert isinstance(val, str), f"expandedSubtechniques must be a string, got {type(val).__name__}"
    assert val in ("none", "all", "annotated"), (
        f"expandedSubtechniques must be one of 'none', 'all', 'annotated', got {val!r}"
    )
