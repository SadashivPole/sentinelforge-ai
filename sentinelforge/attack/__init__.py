"""ATT&CK Coverage Engine package.

Provides a structured MITRE ATT&CK Enterprise technique catalogue for
SentinelForge AI. Catalogue definitions are stored separately from detection
records and never treated as implemented detection coverage.
"""

from .catalogue import ATTACKCatalogue, TechniqueEntry
from .coverage import (
    DIRECT_MAPPINGS,
    ENTERPRISE_TACTICS,
    TELEMETRY_INVENTORY,
    CoverageReporter,
)
from .navigator import compute_sha256, generate_primary_layer, generate_secondary_layer
from .report import generate_coverage_json, generate_markdown_report

__all__ = [
    "DIRECT_MAPPINGS",
    "ENTERPRISE_TACTICS",
    "TELEMETRY_INVENTORY",
    "ATTACKCatalogue",
    "CoverageReporter",
    "TechniqueEntry",
    "compute_sha256",
    "generate_coverage_json",
    "generate_markdown_report",
    "generate_primary_layer",
    "generate_secondary_layer",
]
