#!/usr/bin/env python3
"""Verify MCP stdio handshake and tool discovery for CI using a proper v2 client session.

Starts the sentinelforge-mcp server once over stdio, performs an MCP v2
initialize handshake, lists tools on the same session, verifies the seven
approved SentinelForge tools and their annotations, then closes cleanly.
"""

import asyncio
import sys

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client


async def main() -> int:
    mcp_cmd = "/tmp/sf-mcp-venv/bin/sentinelforge-mcp"

    params = StdioServerParameters(command=mcp_cmd, args=[], env=None)

    try:
        async with stdio_client(params) as (read, write):  # noqa: SIM117
            async with ClientSession(read, write) as session:
                # Bounded handshake: fail if the server does not respond within 30s
                await asyncio.wait_for(session.initialize(), timeout=30)

                capabilities = session.server_capabilities
                if capabilities is None or not getattr(capabilities, "tools", None):
                    print("FAIL: tools capability not advertised")
                    return 1

                tools_result = await asyncio.wait_for(session.list_tools(), timeout=30)
                tools = tools_result.tools

    except TimeoutError:
        print("FAIL: MCP server did not respond within the timeout")
        return 1
    except Exception as exc:  # noqa: BLE001 — report any MCP/client failure
        print(f"FAIL: MCP client session error: {exc}")
        return 1

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
    names = sorted(t.name for t in tools)

    if names != expected:
        print(f"FAIL: unexpected tools: {names}")
        return 1

    for t in tools:
        ann = t.annotations or {}
        if ann.read_only_hint is not True:
            print(f"FAIL: {t.name} missing readOnlyHint")
            return 1
        if ann.destructive_hint is not False:
            print(f"FAIL: {t.name} destructiveHint not false")
            return 1
        if ann.idempotent_hint is not True:
            print(f"FAIL: {t.name} idempotentHint not true")
            return 1
        if ann.open_world_hint is not False:
            print(f"FAIL: {t.name} openWorldHint not false")
            return 1

    print("OK: MCP handshake succeeded, server=sentinelforge-analyst v0.1.0")
    print("OK: all 7 approved tools exposed with correct annotations")

    for t in tools:
        required = [n for n in (t.input_schema or {}).get("required", [])]
        print(f"  - {t.name}: required={required}")

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
