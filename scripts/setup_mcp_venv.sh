#!/bin/bash
set -euo pipefail

python -m venv /tmp/sf-mcp-venv
/tmp/sf-mcp-venv/bin/pip install --upgrade pip
WHEEL=$(find dist -maxdepth 1 -name '*.whl' -print -quit)
test -n "$WHEEL" || { echo "No wheel artifact found in dist/"; exit 1; }
/tmp/sf-mcp-venv/bin/pip install "$WHEEL[analyst-mcp]"
