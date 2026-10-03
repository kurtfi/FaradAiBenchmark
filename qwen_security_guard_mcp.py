#!/usr/bin/env python3
"""
qwen_security_guard_mcp.py

Standalone FastMCP Security Guard Server powered by Qwen2.5-Coder-1.5B (4-bit MLX).
Zero-flag executable communicating via standard JSON-RPC over stdio.
"""

from adapters.qwen_coder_adapter import QwenCoderAdapter
from guard_mcp_factory import create_guard_mcp

adapter = QwenCoderAdapter()
mcp = create_guard_mcp("Qwen-Security-Guard", adapter)

if __name__ == "__main__":
    mcp.run(transport="stdio")
