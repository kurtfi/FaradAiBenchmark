#!/usr/bin/env python3
"""
granite_security_guard_mcp.py

Standalone FastMCP Security Guard Server powered by IBM Granite Guardian 3.0-2B (MLX).
Zero-flag executable communicating via standard JSON-RPC over stdio.
"""

from adapters.granite_guardian_adapter import GraniteGuardianAdapter
from guard_mcp_factory import create_guard_mcp

adapter = GraniteGuardianAdapter()
mcp = create_guard_mcp("Granite-Guardian-Security-Guard", adapter)

if __name__ == "__main__":
    mcp.run(transport="stdio")
