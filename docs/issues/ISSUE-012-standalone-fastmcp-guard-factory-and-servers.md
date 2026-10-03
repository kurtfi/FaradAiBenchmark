# ISSUE-012: Standalone FastMCP Guard Factory & Zero-Flag Executables

## Parent
- **Specification:** [SPEC-0004: Multi-SLM L2 Adapters, FastMCP Factory, and Comparative Benchmark Architecture](../specs/multi-slm-evaluation-and-mcp-guard-spec.md)
- **Architectural Decision:** [ADR 0007: Multi-SLM L2 Adapters and Comparative Benchmark Architecture](../adr/0007-multi-slm-l2-adapter-and-benchmark-architecture.md)

## What to build
Build the shared `guard_mcp_factory.py` builder and generate standalone, zero-flag FastMCP executable servers for each model adapter so they can be plugged into IDEs (Cursor, Claude Code) and `FaradayGateway` via standard JSON-RPC over stdio.

This vertical slice includes:
1. **MCP Factory Engine (`guard_mcp_factory.py`):**
   - Provide `create_guard_mcp(server_name: str, adapter: BaseModelAdapter) -> FastMCP`.
   - Register uniform tool `@mcp.tool() def inspect_tool_call(tool_name, tool_arguments, execution_context="", tool_description="", threat_threshold=0.70)`.
   - Implement fail-safe fallback: If adapter evaluation fails, execute L1 heuristic regex checks rather than allowing uninspected bypass.
2. **Dedicated Executable Entrypoints:**
   - `qwen_security_guard_mcp.py`
   - `granite_security_guard_mcp.py`
   - `llama_security_guard_mcp.py`
   - `prompt_security_guard_mcp.py`
   - Refactor `laya_security_guard_mcp.py` to utilize the common factory.
3. **Integration Verification:**
   - Script `tests/test_mcp_servers.py` testing stdio communication and payload inspection across all servers.

## Status: DONE ✅

## Acceptance criteria
- [x] `guard_mcp_factory.py` successfully wraps any `BaseModelAdapter` into a FastMCP instance.
- [x] `inspect_tool_call` conforms strictly to the existing Laya FastMCP schema.
- [x] Each executable entrypoint (`qwen_security_guard_mcp.py`, etc.) can run standalone via `python <file>.py`.
- [x] Runtime errors in adapters trigger safe fallback with `decision_engine: L2_FALLBACK` and logged warning.
- [x] Automated integration test verifies stdio tool call inspection for each server.

## Blocked by
- [ISSUE-009: Decoupled Adapter Core & Qwen2.5-Coder Model Adapter](./ISSUE-009-decoupled-adapter-core-and-qwen-coder-adapter.md)
- [ISSUE-010: Agent & Tool Safety SLM Adapters](./ISSUE-010-agent-and-tool-safety-adapters.md)
- [ISSUE-011: Ultra-Fast Injection Classifier Adapter](./ISSUE-011-ultra-fast-injection-classifier-adapter.md)
