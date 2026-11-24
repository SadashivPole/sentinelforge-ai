#!/usr/bin/env python3
"""Verify MCP stdio handshake and tool discovery for CI."""

import json
import subprocess
import sys


def main():
    mcp_cmd = ["/tmp/sf-mcp-venv/bin/sentinelforge-mcp"]

    # Step 1: initialize handshake
    init_msg = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "ci-verify", "version": "1.0"},
        },
    }

    proc = subprocess.run(
        mcp_cmd,
        input=json.dumps(init_msg) + "\n",
        check=False,
        capture_output=True,
        text=True,
    )

    if not proc.stdout.strip():
        print("FAIL: no response from MCP server")
        print(f"stderr: {proc.stderr}")
        sys.exit(1)

    line = proc.stdout.strip().splitlines()[0]
    resp = json.loads(line)
    result = resp.get("result", {})
    caps = result.get("capabilities", {})

    if "tools" not in caps:
        print("FAIL: tools capability not advertised")
        sys.exit(1)

    server_info = result.get("serverInfo", {})
    print(
        f"OK: MCP handshake succeeded, server={server_info.get('name')} v{server_info.get('version')}"
    )

    # Step 2: tools/list
    list_msg = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}

    proc2 = subprocess.run(
        mcp_cmd,
        input=json.dumps(list_msg) + "\n",
        check=False,
        capture_output=True,
        text=True,
    )

    if not proc2.stdout.strip():
        print("FAIL: no response from MCP tools/list")
        sys.exit(1)

    line2 = proc2.stdout.strip().splitlines()[0]
    resp2 = json.loads(line2)
    tools = resp2.get("result", {}).get("tools", [])
    names = sorted(t["name"] for t in tools)
    expected = sorted(
        [
            "sentinelforge_get_status",
            "sentinelforge_list_alerts",
            "sentinelforge_get_alert",
            "sentinelforge_get_alert_evidence",
            "sentinelforge_search_events",
            "sentinelforge_build_investigation_brief",
            "sentinelforge_list_risk_assessments",
        ]
    )

    if names != expected:
        print(f"FAIL: unexpected tools: {names}")
        sys.exit(1)

    for t in tools:
        ann = t.get("annotations", {})
        if ann.get("readOnlyHint") is not True:
            print(f"FAIL: {t['name']} missing readOnlyHint")
            sys.exit(1)
        if ann.get("destructiveHint") is not False:
            print(f"FAIL: {t['name']} destructiveHint not false")
            sys.exit(1)
        if ann.get("idempotentHint") is not True:
            print(f"FAIL: {t['name']} idempotentHint not true")
            sys.exit(1)
        if ann.get("openWorldHint") is not False:
            print(f"FAIL: {t['name']} openWorldHint not false")
            sys.exit(1)

    print("OK: all 7 approved tools exposed with correct annotations")


if __name__ == "__main__":
    main()
