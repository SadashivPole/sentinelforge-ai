# Local SOC Dashboard

`sentinelforge dashboard` — binds to `127.0.0.1:8080` by default.

## Overview

The local SOC dashboard is a read-only HTTP server that visualizes detection results stored in the SQLite database. It is designed for local analysis only and is **not** exposed publicly.

## Security Properties

- **Localhost only:** Binds to `127.0.0.1:8080` — not accessible from other hosts
- **Read-only:** No state-changing endpoints (no POST, PUT, DELETE)
- **No credentials:** No authentication required; no secrets in source
- **SQLite-backed:** Reads from the local SQLite database only

## Usage

```bash
# Start the dashboard
sentinelforge dashboard

# Then open: http://127.0.0.1:8080
```

## Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Dashboard overview |
| `/alerts` | GET | List detection alerts |
| `/events` | GET | List normalized events |
| `/rules` | GET | List detection rules |
| `/diagnostics` | GET | System diagnostics |

## What It Is Not

- Not a production SOC dashboard
- Not accessible from the public website
- Not connected to any backend AI service
- Not real-time streaming

