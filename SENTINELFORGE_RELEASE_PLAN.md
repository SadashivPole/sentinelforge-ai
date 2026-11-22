# SentinelForge AI — Release Plan

**Branch:** feature/sentinelforge-public-platform  
**Base commit:** 58534f3 (M10 remediation merge)  
**Status:** Planning  

## Release Strategy

Local-first, milestone-driven release model. No direct push to main. All changes via pull request with owner review.

## Versioning

Current version: 0.1.0 (prototype). Follows semantic versioning once public.

## Milestones

| Milestone | Focus | Status |
|-----------|-------|--------|
| P1 — Visual Identity | Branding | Complete |
| P2 — Public Website | Static site | Complete |
| P3 — Public Demo | Synthetic demo | Complete |
| P4 — Local Dashboard | Localhost app | Complete |
| P5 — CI/CD Extension | Pipeline | Complete |
| P6 — Documentation | Docs | Complete |
| P7 — Final Verification | Release gate | In Progress |

## CI/CD Pipeline

| Job | Blocking? | Purpose |
|-----|-----------|---------|
| test (Python 3.12/3.13) | Yes | Run pytest suite |
| lint (ruff + mypy) | Yes | Lint + type check |
| security (safety + bandit) | Yes | Blocking security scans |
| build (wheel) | Yes | Wheel build artifact |
| clean-install smoke test | Yes | Fresh venv + wheel install + CLI |
| dashboard smoke test | Yes | Start on 127.0.0.1, verify response |
| website build check | Yes | Verify static files exist |

Security checks report actual results — no || true or --exit-zero to hide failures.
