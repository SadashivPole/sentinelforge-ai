# SentinelForge AI — Product Plan

**Project:** SentinelForge AI  
**Branch:** feature/sentinelforge-public-platform  
**Base commit:** 58534f3 (M10 remediation merge)  
**Status:** Planning  
**Python:** >=3.11  

## Product Vision

SentinelForge AI is a demonstrable SOC detection engineering platform for SOC analysts, detection engineers, threat hunters, and blue-team learners. It is a local-first, open-source prototype — not a production SIEM, not a hosted service.

## Three Experiences

1. **Public website:** Product information, documentation, installation and roadmap (static, GitHub Pages)
2. **Public interactive demo:** Safe demonstration using synthetic security events (static, GitHub Pages)
3. **Local SOC dashboard:** Locally running application backed by the existing Python detection engine and SQLite storage (127.0.0.1 only)

## Milestones

| Milestone | Focus | Status |
|-----------|-------|--------|
| P1 — Visual Identity | Logo, favicon, social preview, brand guidelines | Complete |
| P2 — Public Website | Responsive static site, 12 pages | Complete |
| P3 — Public Demo | 5 synthetic scenarios, labeled results | Complete |
| P4 — Local Dashboard | Localhost app backed by Python engine + SQLite | Complete |
| P5 — CI/CD Extension | Blocking security, smoke tests, website build | Complete |
| P6 — Documentation | 6 docs files, README updated | Complete |
| P7 — Final Verification | Fresh install, full tests, dashboard | In Progress |

## Design Principles

- Evidence-first detection — no fabricated indicators
- Raw log preservation — verbatim payload stored alongside normalized event
- No automatic remediation — agent surfaces findings; humans act
- No execution of log content — command strings inspected as text only
- LLM optional — mock provider by default
- No credentials in source — SENTINELFORGE_* env vars only
- No Streamlit/Pandas unless justified — C: drive constraint
