# Installation

## Prerequisites

- Python 3.11 or later (package minimum; CI validates Python 3.11, 3.12 and 3.13)
- Git
- Approximately 200 MB of disk space

## Step-by-Step

### 1. Clone the repository

```bash
git clone https://github.com/SadashivPole/sentinelforge-ai.git
cd sentinelforge-ai
```

### 2. Create and activate a virtual environment

```bash
# Create the virtual environment
python -m venv .venv

# Windows PowerShell:
.venv\Scripts\Activate.ps1

# Linux/macOS:
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
pip install .
```

### 4. Verify the installation

```bash
sentinelforge --help
sentinelforge dashboard --help
```

### 5. Run the test suite

```bash
python -m pytest
```

Test totals change as tests are added; compare the local result against the current GitHub Actions CI run (Python 3.11, 3.12 and 3.13) rather than a hardcoded count.

## Configuration

All configuration is via `SENTINELFORGE_*` environment variables. No credentials are stored in source code.

| Variable | Description | Default |
|----------|-------------|---------|
| `SENTINELFORGE_AI_PROVIDER` | AI provider backend | `mock` |
| `SENTINELFORGE_MAX_DETECTION_EVENTS` | Safety guard for detection event limit | No limit |
| `SENTINELFORGE_DB_PATH` | Path to SQLite database | `data/sentinelforge.db` |

## Quick Start

```bash
# Ingest log files
sentinelforge ingest data/sample.jsonl

# Run detections
sentinelforge detect

# Evaluate detection quality
sentinelforge evaluate

# Start the local dashboard (localhost only)
sentinelforge dashboard
```

The dashboard is read-only and binds to `127.0.0.1:8080`. It is not exposed publicly.
