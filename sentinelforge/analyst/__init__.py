"""SentinelForge AI — SOC Analyst MCP integration.

A read-only, local stdio-only MCP server that exposes SentinelForge data
to approved MCP clients (Hermes, IDEs, etc.). The MCP dependency is
optional: SentinelForge works without it.

Trust model: the MCP server is an untrusted local component. All database
access is enforced read-only via SQLite URI mode=ro + PRAGMA query_only=ON.
No ingestion, deletion, alteration, shell execution, network access, or
arbitrary SQL is available through MCP tools.
"""

__version__ = "0.1.0"
