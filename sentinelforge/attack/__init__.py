"""ATT&CK Coverage Engine package.

Provides a structured MITRE ATT&CK Enterprise technique catalogue for
SentinelForge AI. Catalogue definitions are stored separately from detection
records and never treated as implemented detection coverage.
"""

from .catalogue import ATTACKCatalogue, TechniqueEntry
from .coverage import CoverageReporter, DIRECT_MAPPINGS, ENTERPRISE_TACTICS, TELEMETRY_INVENTORY
from .navigator import generate_primary_layer, generate_secondary_layer, compute_sha256
from .report import generate_coverage_json, generate_markdown_report

__all__ = [
    "ATTACKCatalogue",
    "TechniqueEntry",
    "CoverageReporter",
    "DIRECT_MAPPINGS",
    "ENTERPRISE_TACTICS",
    "TELEMETRY_INVENTORY",
    "generate_primary_layer",
    "generate_secondary_layer",
    "compute_sha256",
    "generate_coverage_json",
    "generate_markdown_report",
]
