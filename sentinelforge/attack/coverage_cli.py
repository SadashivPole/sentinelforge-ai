"""CLI entry point for generating ATT&CK coverage reports and Navigator exports.

Usage:
    python -m sentinelforge.attack.coverage

Generates:
    SENTINELFORGE_MITRE_ATTACK_COVERAGE.json
    SENTINELFORGE_MITRE_ATTACK_COVERAGE_REPORT.md
    sentinelforge_implemented_detection_coverage.json
    sentinelforge_attack_catalogue_readiness.json

All outputs are deterministic: same inputs produce identical bytes and SHA-256.
"""

from __future__ import annotations

import sys
from pathlib import Path

from .catalogue import ATTACKCatalogue
from .coverage import CoverageReporter
from .navigator import (
    generate_primary_layer,
    generate_secondary_layer,
    compute_sha256,
)
from .report import generate_coverage_json, generate_markdown_report

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CATALOGUE_PATH = PROJECT_ROOT / "sentinelforge" / "attack" / "catalogue.json"

COVERAGE_JSON_PATH = PROJECT_ROOT / "SENTINELFORGE_MITRE_ATTACK_COVERAGE.json"
COVERAGE_REPORT_PATH = PROJECT_ROOT / "SENTINELFORGE_MITRE_ATTACK_COVERAGE_REPORT.md"
PRIMARY_NAV_PATH = PROJECT_ROOT / "sentinelforge_implemented_detection_coverage.json"
SECONDARY_NAV_PATH = PROJECT_ROOT / "sentinelforge_attack_catalogue_readiness.json"


def main() -> int:
    """Generate all coverage reports and Navigator exports."""
    # Load catalogue
    catalogue = ATTACKCatalogue.from_json(str(CATALOGUE_PATH))
    validation_errors = catalogue.validate()
    if validation_errors:
        print("Catalogue validation errors:", file=sys.stderr)
        for err in validation_errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    reporter = CoverageReporter(catalogue)

    # Compute metrics
    metrics = reporter.compute_metrics()
    tactic_coverage = reporter.compute_tactic_coverage()
    telemetry_coverage = reporter.compute_telemetry_coverage()
    mapping_table = reporter.get_direct_mapping_table()
    mapping_errors = reporter.validate_direct_mappings()
    if mapping_errors:
        print("Direct mapping validation errors:", file=sys.stderr)
        for err in mapping_errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    # Generate outputs
    coverage_report = generate_coverage_json(
        catalogue, reporter, metrics, tactic_coverage,
        telemetry_coverage, mapping_table, str(COVERAGE_JSON_PATH),
    )
    markdown_report = generate_markdown_report(
        catalogue, reporter, metrics, tactic_coverage,
        telemetry_coverage, mapping_table, str(COVERAGE_REPORT_PATH),
    )
    primary_layer = generate_primary_layer(
        catalogue, reporter, str(PRIMARY_NAV_PATH),
    )
    secondary_layer = generate_secondary_layer(
        catalogue, reporter, str(SECONDARY_NAV_PATH),
    )

    # Compute hashes for reproducibility
    coverage_hash = compute_sha256(COVERAGE_JSON_PATH)
    report_hash = compute_sha256(COVERAGE_REPORT_PATH)
    primary_hash = compute_sha256(PRIMARY_NAV_PATH)
    secondary_hash = compute_sha256(SECONDARY_NAV_PATH)

    # Determinism check: regenerate and compare
    coverage_report_2 = generate_coverage_json(
        catalogue, reporter, metrics, tactic_coverage,
        telemetry_coverage, mapping_table, str(COVERAGE_JSON_PATH),
    )
    coverage_hash_2 = compute_sha256(COVERAGE_JSON_PATH)
    assert coverage_hash == coverage_hash_2, "Coverage JSON not deterministic"

    markdown_report_2 = generate_markdown_report(
        catalogue, reporter, metrics, tactic_coverage,
        telemetry_coverage, mapping_table, str(COVERAGE_REPORT_PATH),
    )
    report_hash_2 = compute_sha256(COVERAGE_REPORT_PATH)
    assert report_hash == report_hash_2, "Markdown report not deterministic"

    primary_layer_2 = generate_primary_layer(
        catalogue, reporter, str(PRIMARY_NAV_PATH),
    )
    primary_hash_2 = compute_sha256(PRIMARY_NAV_PATH)
    assert primary_hash == primary_hash_2, "Primary Navigator layer not deterministic"

    secondary_layer_2 = generate_secondary_layer(
        catalogue, reporter, str(SECONDARY_NAV_PATH),
    )
    secondary_hash_2 = compute_sha256(SECONDARY_NAV_PATH)
    assert secondary_hash == secondary_hash_2, "Secondary Navigator layer not deterministic"

    # Print summary
    print("ATT&CK Coverage Report Generation Complete")
    print("=" * 50)
    print(f"Catalogue entries: {metrics.total_entries}")
    print(f"Implemented and tested: {metrics.implemented_and_tested}")
    print(f"Telemetry available, no detection: {metrics.telemetry_available_no_detection}")
    print(f"Unsupported by current telemetry: {metrics.unsupported_by_current_telemetry}")
    print(f"Direct detection mappings: {metrics.direct_mapping_count}")
    print(f"Coverage percentage: {metrics.coverage_percentage}%")
    print("")
    print("Generated files:")
    print(f"  {COVERAGE_JSON_PATH} (SHA-256: {coverage_hash})")
    print(f"  {COVERAGE_REPORT_PATH} (SHA-256: {report_hash})")
    print(f"  {PRIMARY_NAV_PATH} (SHA-256: {primary_hash})")
    print(f"  {SECONDARY_NAV_PATH} (SHA-256: {secondary_hash})")
    print("")
    print("Determinism verified: all outputs reproducible.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
