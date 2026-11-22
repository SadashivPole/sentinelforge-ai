"""SentinelForge AI — Independent C2 Detection Evaluation (Phase 3, Item 4).

Thin compatibility wrapper around
``sentinelforge.datasets.independent_evaluation``.

All evaluation logic lives in the packaged module; this wrapper simply
delegates to it so that existing callers of ``python evaluate_independent.py``
continue to work unchanged.

Usage:
    python evaluate_independent.py   (from the repository root)
    python -m sentinelforge.datasets.independent_evaluation   (installed)
"""

from __future__ import annotations

from sentinelforge.datasets.independent_evaluation import main

if __name__ == "__main__":
    main()
