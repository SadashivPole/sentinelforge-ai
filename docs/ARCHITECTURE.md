# SentinelForge Architecture

## Overview

SentinelForge is built around a single Python detection engine that serves three separate experiences:

1. **CLI** — `sentinelforge` command for ingest, detect, evaluate, and dashboard
2. **Local SOC Dashboard** — read-only HTTP server on `127.0.0.1:8080`
3. **Public Website** — static HTML/CSS/JS on GitHub Pages, using precomputed synthetic data

There is **no competing detection engine in JavaScript**. The Python implementation is the source of truth.

## Component Boundaries

```
Log Sources (JSON / JSONL / Sysmon)
        │
        ▼
┌─────────────────────────────────────┐
│  sentinelforge/ingestion/           │
│  • reader.py   — JSON / JSONL /     │
│                  Sysmon-style readers│
│  • normalizer.py — Common schema +  │
│                    raw preservation │
└─────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────┐
│  sentinelforge/detection/           │
│  • base.py     — Rule interface +   │
│                  Evidence/Detection  │
│                  models              │
│  • failed_logins.py — FailedLoginBurstRule │
│  • password_spray.py — PasswordSprayRule   │
│  • powershell.py — SuspiciousPowerShellRule│
│  • processtree.py — SuspiciousProcessTreeRule│
│  • beacon.py — C2BeaconRule         │
└─────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────┐
│  sentinelforge/risk/                │
│  • scorer.py   — Explainable risk   │
│                  scoring (0-100)    │
│  • correlator.py — Detection        │
│                  correlation by     │
│                  host + time window │
└─────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────┐
│  sentinelforge/storage/             │
│  • database.py — SQLite connection  │
│  • schema.py   — Versioned schema   │
│                  (v3) + migrations  │
│  • repositories.py — CRUD +         │
│                  analytics          │
└─────────────────────────────────────┘
        │
        ▼
┌─────────────────────────────────────┐
│  sentinelforge/cli/                 │
│  • main.py — CLI entry point        │
│  • dashboard subcommand             │
└─────────────────────────────────────┘
        │
    ┌───┴───┐
    │       ▼
    ▼   Local SOC Dashboard
CLI   (127.0.0.1:8080, read-only)

┌─────────────────────────────────────┐
│  sentinelforge/datasets/            │
│  • generator.py — Synthetic dataset │
│  • ground_truth.py — Label manifest │
│  • scenarios.py — Scenario templates│
│  • evaluation.py — Metrics          │
└─────────────────────────────────────┘
        │
        ▼
Sanitized static JSON → Public website (GitHub Pages)
```

## Public Website Boundary

The public website **never connects** to:
- The local SOC dashboard
- The SQLite database
- Any live detection engine
- Any backend API

It displays **sanitized, precomputed synthetic data only**, clearly labeled as precomputed.

## Data Flow

1. Log files are ingested via `sentinelforge ingest`
2. Events are normalized to a common schema with raw payloads preserved verbatim
3. Detection rules run on normalized events, producing detections with evidence
4. Detections are correlated by host and time window
5. Risk scores (0-100) are computed per host from detection results
6. All data is persisted to SQLite with versioned schema (v3)
7. The local dashboard reads from SQLite for visualization

## Security Properties

- All SQL queries use parameterized `?` placeholders
- Raw logs are stored verbatim and never modified
- No automatic remediation — alerts surface findings only
- No execution of log content
- Dashboard binds to `127.0.0.1:8080` only (localhost)
- No credentials in source code
