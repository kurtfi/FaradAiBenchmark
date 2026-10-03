"""
test_mcp_servers.py

Integration tests for guard_mcp_factory and standalone FastMCP security guard servers (ISSUE-012).
Verifies:
1. FastMCP server generation via guard_mcp_factory.
2. Standardized schema returned by inspect_tool_call.
3. Fail-safe heuristic fallback when an adapter encounters runtime exceptions.
4. Standalone entrypoints: Qwen, Granite, Llama Guard, and Prompt Guard.
"""

import asyncio
from typing import Any

try:
    from fastmcp import FastMCP
except ImportError:
    from mcp.server.fastmcp import FastMCP

from adapters.base import BaseModelAdapter, EvaluationResult
from guard_mcp_factory import create_guard_mcp


class MockAdapter(BaseModelAdapter):
    """Simple test adapter for validating factory contracts."""

    def __init__(self, block_all: bool = False, should_fail: bool = False):
        self.block_all = block_all
        self.should_fail = should_fail

    def evaluate(
        self,
        tool_name: str,
        tool_arguments: dict[str, Any],
        context: str = "",
    ) -> dict[str, Any]:
        if self.should_fail:
            raise RuntimeError("Simulated adapter inference crash")

        is_blocked = self.block_all or "passwd" in str(tool_arguments)
        return EvaluationResult(
            is_blocked=is_blocked,
            confidence=0.95 if is_blocked else 0.05,
            verdict="BLOCKED" if is_blocked else "ALLOWED",
            threat_domain="COMMAND_INJECTION" if is_blocked else None,
            cwe="CWE-78" if is_blocked else None,
            decision_engine="L2_MOCK",
            latency_ms=1.5,
        ).to_dict()


def test_factory_creates_fastmcp_instance():
    adapter = MockAdapter()
    server = create_guard_mcp("Test-Guard", adapter)
    assert isinstance(server, FastMCP)
    assert server.name == "Test-Guard"

    # Verify tool is registered in FastMCP
    tool = asyncio.run(server.get_tool("inspect_tool_call"))
    assert tool is not None
    assert tool.name == "inspect_tool_call"


def test_factory_inspect_tool_call_benign():
    adapter = MockAdapter(block_all=False)
    server = create_guard_mcp("Test-Guard", adapter)

    res = server.inspect_tool_call(
        tool_name="git_log",
        tool_arguments={"max_count": 10},
        execution_context="Show recent commits",
    )

    assert isinstance(res, dict)
    assert res["verdict"] == "ALLOWED"
    assert res["malicious_probability"] == 0.05
    assert res["decision_engine"] == "L2_MOCK"
    assert res["inspected_tool"] == "git_log"


def test_factory_inspect_tool_call_malicious():
    adapter = MockAdapter(block_all=True)
    server = create_guard_mcp("Test-Guard", adapter)

    res = server.inspect_tool_call(
        tool_name="bash",
        tool_arguments={"cmd": "cat /etc/passwd"},
        execution_context="Admin command",
    )

    assert isinstance(res, dict)
    assert res["verdict"] == "BLOCKED"
    assert res["malicious_probability"] == 0.95
    assert res["exploit_risk"] == 0.95
    assert res["threat_domain"] == "COMMAND_INJECTION"


def test_factory_fail_safe_fallback_on_adapter_error():
    """Verify that when an adapter raises an unhandled exception, fail-safe heuristics engage."""
    failing_adapter = MockAdapter(should_fail=True)
    server = create_guard_mcp("Failing-Guard", failing_adapter)

    # Malicious payload triggers fallback block
    res_threat = server.inspect_tool_call(
        tool_name="bash",
        tool_arguments={"cmd": "cat /etc/passwd"},
    )
    assert res_threat["verdict"] == "BLOCKED"
    assert res_threat["decision_engine"] == "L2_FALLBACK"
    assert "error" in res_threat

    # Benign payload under fallback is allowed
    res_benign = server.inspect_tool_call(
        tool_name="read_file",
        tool_arguments={"filename": "notes.txt"},
    )
    assert res_benign["verdict"] == "ALLOWED"
    assert res_benign["decision_engine"] == "L2_FALLBACK"


def test_standalone_mcp_entrypoints():
    """Verify all 4 standalone zero-flag entrypoints initialize valid FastMCP instances."""
    import granite_security_guard_mcp
    import llama_security_guard_mcp
    import prompt_security_guard_mcp
    import qwen_security_guard_mcp

    assert isinstance(qwen_security_guard_mcp.mcp, FastMCP)
    assert isinstance(granite_security_guard_mcp.mcp, FastMCP)
    assert isinstance(llama_security_guard_mcp.mcp, FastMCP)
    assert isinstance(prompt_security_guard_mcp.mcp, FastMCP)
