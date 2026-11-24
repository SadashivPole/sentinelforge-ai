# Troubleshooting

## Installation

### `sentinelforge: command not found`

The `sentinelforge` CLI entry point is installed by `pip install .`. Make sure you ran both:

```bash
pip install -r requirements.txt
pip install .
```

Then verify:

```bash
sentinelforge --help
```

### Virtual environment activation fails (Windows PowerShell)

If you see a script execution policy error:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
.venv\Scripts\Activate.ps1
```

## Dashboard

### Dashboard won't start on port 8080

Port 8080 may be in use. Check:

```bash
# Windows
netstat -ano | findstr :8080

# Linux/macOS
lsof -i :8080
```

The dashboard binds to `127.0.0.1:8080` only and is not accessible from other hosts.

### Dashboard shows no data

Ensure you have ingested data and run detections first:

```bash
sentinelforge ingest data/sample.jsonl
sentinelforge detect
sentinelforge dashboard
```

## Tests

### Test count mismatch

The expected result is `363 passed, 1 skipped`. If you see a different count, ensure you're on the latest `feature/website-redesign-hermes-support` branch and run:

```bash
git pull
python -m pytest
```

## Disk Space

The C: drive may be at high capacity. Use the E: drive for virtual environments and caches when available.

## CI/CD

If GitHub Actions checks fail:

1. Check the workflow run at https://github.com/SadashivPole/sentinelforge-ai/actions
2. Common failures: ruff lint/format, mypy type errors, pytest failures, bandit security findings
3. Do not weaken tests or suppress security findings to obtain a clean report

