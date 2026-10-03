#!/usr/bin/env python3
"""
llama_security_guard_mcp.py

Standalone FastMCP Security Guard Server powered by Meta Llama Guard 3 1B (MLX).
Zero-flag executable communicating via standard JSON-RPC over stdio.
"""

from adapters.llama_guard_adapter import LlamaGuardAdapter
from guard_mcp_factory import create_guard_mcp

adapter = LlamaGuardAdapter()
mcp = create_guard_mcp("Llama-Guard-3-Security-Guard", adapter)

if __name__ == "__main__":
    mcp.run(transport="stdio")
