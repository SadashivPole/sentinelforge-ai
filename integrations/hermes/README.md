# SentinelForge Hermes Integrations

This directory contains Hermes integrations for SentinelForge AI.

## SOC Analyst Skill

`skills/sentinelforge-soc-analyst/SKILL.md` — Hermes skill guiding
read-only SOC investigations through the SentinelForge Analyst MCP server.

## Hermes MCP Configuration

Add the following to your Hermes profile configuration:

```yaml
mcp:
  servers:
    sentinelforge-analyst:
      command: /path/to/sentinelforge-mcp
      args: []
      env:
        SENTINELFORGE_DB_PATH: /path/to/data/sentinelforge.db
      trust: untrusted
      tools.include:
        - sentinelforge_get_status
        - sentinelforge_list_alerts
        - sentinelforge_get_alert
        - sentinelforge_get_alert_evidence
        - sentinelforge_search_events
        - sentinelforge_build_investigation_brief
        - sentinelforge_list_risk_assessments
      resources: false
      prompts: false
      timeout: 30000
      enabled: true
```

## Installation

1. Install SentinelForge with the MCP extra:
   ```
   pip install sentinelforge[analyst-mcp]
   ```
2. Verify the entry point:
   ```
   which sentinelforge-mcp
   ```
3. Copy the skill to your Hermes skills directory:
   ```
   cp -r integrations/hermes/skills/sentinelforge-soc-analyst/ ~/.config/hermes/skills/
   ```
4. Reload Hermes MCP servers and verify the 7 tools are discovered.

## Security

The MCP server is local stdio-only, read-only, and marked `trust: untrusted`.
No public HTTP endpoint, no remote database access, no arbitrary SQL execution.
