"""MITRE ATT&CK Navigator layer generation.

Generates ATT&CK Navigator layer v4.5-compatible JSON files:

1. Primary export: only the 5 genuine implemented detection mappings.
2. Secondary export: full catalogue readiness inventory (69 entries, only 5 enabled).

Format specification:
https://github.com/mitre-attack/attack-navigator/blob/main/layers/spec/v4.5/layerformat.md
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .catalogue import ATTACKCatalogue, TechniqueEntry
from .coverage import (
    CoverageReporter,
)

ATTACK_NAVIGATOR_LAYER_VERSION = "4.5"
ATTACK_VERSION = "v20.1"
DOMAIN = "enterprise-attack"
NAVIGATOR_MIN_VERSION = "4.9.0"


def _technique_color(status: str) -> str:
    """Return a Navigator-compatible color for a detection status."""
    colors = {
        "IMPLEMENTED_AND_TESTED": "#3a7ca5",  # blue — implemented
        "TELEMETRY_AVAILABLE_NO_DETECTION": "#f2b233",  # amber — telemetry only
        "PLANNED_REQUIRES_TELEMETRY": "#ff9900",  # orange — planned
        "UNSUPPORTED_BY_CURRENT_TELEMETRY": "#cccccc",  # gray — unsupported
    }
    return colors.get(status, "#cccccc")


def _technique_comment(entry: TechniqueEntry, is_implemented: bool) -> str:
    """Build a Navigator technique comment from catalogue entry data."""
    parts: list[str] = []
    if is_implemented:
        parts.append("STATUS: Implemented detection")
        parts.append(f"RULE: {entry.associated_detection_rule_ids[0]}")
    else:
        parts.append(f"STATUS: {entry.detection_status}")
    parts.append(f"CONFIDENCE: {entry.mapping_confidence}")
    parts.append(f"RATIONALE: {entry.mapping_rationale}")
    parts.append(f"CATALOGUE VERSION: {entry.attack_version}")
    if entry.investigation_recommendations:
        parts.append(
            "RECOMMENDATIONS: " + "; ".join(entry.investigation_recommendations)
        )
    return " | ".join(parts)


def generate_primary_layer(
    catalogue: ATTACKCatalogue,
    reporter: CoverageReporter,
    output_path: str | Path,
) -> dict[str, Any]:
    """Generate the primary Navigator layer — only 5 implemented mappings.

    No parent roll-ups, no unimplemented entries. Only the five genuine
    detection mappings are included as enabled techniques.
    """
    mapping_table = reporter.get_direct_mapping_table()

    techniques: list[dict[str, Any]] = []
    for mapping in sorted(mapping_table, key=lambda m: m["attack_id"]):
        entry = catalogue.get(mapping["attack_id"])
        if entry is None:
            continue
        techniques.append(
            {
                "techniqueID": mapping["attack_id"],
                "tactic": mapping["tactic_id"],
                "score": 1,
                "color": _technique_color("IMPLEMENTED_AND_TESTED"),
                "enabled": True,
                "comment": _technique_comment(entry, is_implemented=True),
                "showName": True,
                "showLabel": True,
                "showScore": False,
                "links": [
                    f"https://attack.mitre.org/techniques/{mapping['attack_id'].replace('.', '/')}/"
                ],
            }
        )

    layer: dict[str, Any] = {
        "name": "SentinelForge AI — Implemented Detection Coverage",
        "versions": {
            "layer": ATTACK_NAVIGATOR_LAYER_VERSION,
            "attack": ATTACK_VERSION,
            "navigator": NAVIGATOR_MIN_VERSION,
        },
        "domain": DOMAIN,
        "description": (
            "Primary ATT&CK Navigator layer showing only the five genuine "
            "implemented detection mappings in SentinelForge AI. Parent "
            "roll-up techniques (T1110, T1059, T1204) are NOT included as "
            "independent detections. Catalogue membership is not detection "
            "coverage. ATT&CK version v20.1."
        ),
        "filters": {
            "stages": [],
            "platforms": [],
        },
        "sorting": 0,
        "layout": {
            "layout": "side",
            "showName": True,
            "showAggregateScores": False,
            "showUnscored": False,
            "expandedSubtechniques": "none",
        },
        "hideDisabled": False,
        "techniques": techniques,
        "legend": [
            {
                "label": "Implemented detection (5 techniques)",
                "color": "#3a7ca5",
            },
        ],
        "gradient": {
            "colors": ["#ff6666", "#ffe766", "#8ec843"],
            "minValue": 0,
            "maxValue": 100,
        },
        "metadata": [],
        "showTacticRowBackground": False,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectVisibleTechniques": True,
    }

    _write_json(output_path, layer)
    return layer


def generate_secondary_layer(
    catalogue: ATTACKCatalogue,
    reporter: CoverageReporter,
    output_path: str | Path,
) -> dict[str, Any]:
    """Generate the secondary Navigator layer — full catalogue readiness inventory.

    All 69 entries are included, but only the 5 implemented ones are enabled.
    All other entries are disabled with their catalogue status in comments.
    """
    implemented_ids = {e.technique_id for e in catalogue.implemented_and_tested()}

    techniques: list[dict[str, Any]] = []
    for entry in sorted(catalogue.all(), key=lambda e: e.technique_id):
        is_implemented = entry.technique_id in implemented_ids
        techniques.append(
            {
                "techniqueID": entry.technique_id,
                "tactic": entry.tactic_ids[0] if entry.tactic_ids else "",
                "score": 1 if is_implemented else 0,
                "color": _technique_color(entry.detection_status),
                "enabled": is_implemented,
                "comment": _technique_comment(entry, is_implemented=is_implemented),
                "showName": True,
                "showLabel": True,
                "showScore": False,
                "links": [
                    f"https://attack.mitre.org/techniques/{entry.technique_id.replace('.', '/')}/"
                ],
            }
        )

    layer: dict[str, Any] = {
        "name": "SentinelForge AI — Attack Catalogue Readiness Inventory",
        "versions": {
            "layer": ATTACK_NAVIGATOR_LAYER_VERSION,
            "attack": ATTACK_VERSION,
            "navigator": NAVIGATOR_MIN_VERSION,
        },
        "domain": DOMAIN,
        "description": (
            "Catalogue readiness inventory showing all 69 curated ATT&CK "
            "Enterprise techniques. Only the five genuine implemented "
            "detection mappings are enabled. All other entries are disabled "
            "and marked with their actual catalogue status. This is NOT a "
            "representation of implemented detection coverage. "
            "Parent roll-up techniques (T1110, T1059, T1204) remain disabled "
            "as independent detections. ATT&CK version v20.1."
        ),
        "filters": {
            "stages": [],
            "platforms": [],
        },
        "sorting": 0,
        "layout": {
            "layout": "side",
            "showName": True,
            "showAggregateScores": False,
            "showUnscored": False,
            "expandedSubtechniques": "none",
        },
        "hideDisabled": False,
        "techniques": techniques,
        "legend": [
            {
                "label": "Implemented detection (5 techniques)",
                "color": "#3a7ca5",
            },
            {
                "label": "Telemetry available, no detection (17 entries)",
                "color": "#f2b233",
            },
            {
                "label": "Unsupported by current telemetry (47 entries)",
                "color": "#cccccc",
            },
        ],
        "gradient": {
            "colors": ["#ff6666", "#ffe766", "#8ec843"],
            "minValue": 0,
            "maxValue": 100,
        },
        "metadata": [],
        "showTacticRowBackground": False,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectVisibleTechniques": True,
    }

    _write_json(output_path, layer)
    return layer


def _write_json(path: str | Path, data: dict[str, Any]) -> None:
    """Write deterministic JSON with sorted keys and stable formatting."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    path.write_text(text, encoding="utf-8")


def compute_sha256(path: str | Path) -> str:
    """Compute SHA-256 hash of a file."""
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()
