# SentinelForge AI — Architecture

**Branch:** feature/sentinelforge-public-platform
**Base commit:** 58534f3 (M10 remediation merge)
**Status:** Planning

## Architecture Overview

Three separated experiences share a common Python detection core:

- **Public website:** Static HTML/CSS/JS on GitHub Pages
- **Public interactive demo:** Static site with synthetic scenarios
- **Local SOC dashboard:** Python HTTP server on 127.0.0.1 + SQLite
- **Common core:** sentinelforge/ Python package (CLI, ingestion, detection, risk, storage, datasets, attack, dashboard)

The existing Python detection engine remains the source of truth. No competing detection engine is created in JavaScript.

## Data Flow

Raw log → reader_for() → normalize() → SQLite → detect → risk → evaluate

## Technology Constraints

- No Streamlit/Pandas by default (C: drive capacity)
- SQLite storage (zero-install, single file)
- Python stdlib preferred for the dashboard
- Static website and demo on GitHub Pages
- No credentials in source (SENTINELFORGE_* env vars only)
