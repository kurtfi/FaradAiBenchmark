# Faraday Laya Guard: Issue Tracker & Roadmap

This document indexes all vertical slice issues (tracer bullets) across project specifications.

---

## SPEC-0004: Multi-SLM L2 Adapters & Comparative Benchmark Architecture

Parent Specification: [SPEC-0004: Multi-SLM Evaluation & MCP Guard](../specs/multi-slm-evaluation-and-mcp-guard-spec.md)  
Architectural Decision: [ADR 0007: Multi-SLM L2 Adapters & Benchmark Architecture](../adr/0007-multi-slm-l2-adapter-and-benchmark-architecture.md)

| Issue ID | Title | Blocked by | Status |
| :--- | :--- | :--- | :--- |
| **[ISSUE-009](./ISSUE-009-decoupled-adapter-core-and-qwen-coder-adapter.md)** | Decoupled Adapter Core & Qwen2.5-Coder Model Adapter | *None (Immediate)* | ✅ Done |
| **[ISSUE-010](./ISSUE-010-agent-and-tool-safety-adapters.md)** | Agent & Tool Safety SLM Adapters (Granite Guardian & Llama Guard 3) | [ISSUE-009](./ISSUE-009-decoupled-adapter-core-and-qwen-coder-adapter.md) | ✅ Done |
| **[ISSUE-011](./ISSUE-011-ultra-fast-injection-classifier-adapter.md)** | Ultra-Fast Injection Classifier Adapter (Prompt-Guard-86M) | [ISSUE-009](./ISSUE-009-decoupled-adapter-core-and-qwen-coder-adapter.md) | ⏳ Ready |
| **[ISSUE-012](./ISSUE-012-standalone-fastmcp-guard-factory-and-servers.md)** | Standalone FastMCP Guard Factory & Zero-Flag Executables | [ISSUE-009](./ISSUE-009-decoupled-adapter-core-and-qwen-coder-adapter.md), [ISSUE-010](./ISSUE-010-agent-and-tool-safety-adapters.md), [ISSUE-011](./ISSUE-011-ultra-fast-injection-classifier-adapter.md) | ⏳ Ready |
| **[ISSUE-013](./ISSUE-013-two-phased-comparative-benchmark-runner-and-leaderboard.md)** | Two-Phased Comparative Benchmark Runner & CLI Leaderboard Matrix | [ISSUE-009](./ISSUE-009-decoupled-adapter-core-and-qwen-coder-adapter.md), [ISSUE-010](./ISSUE-010-agent-and-tool-safety-adapters.md), [ISSUE-011](./ISSUE-011-ultra-fast-injection-classifier-adapter.md) | ⏳ Ready |
| **[ISSUE-014](./ISSUE-014-web-dashboard-multi-run-discrepancy-matrix.md)** | Web Dashboard Multi-Run Discrepancy Matrix & Cross-Model Comparison | [ISSUE-013](./ISSUE-013-two-phased-comparative-benchmark-runner-and-leaderboard.md) | ⏳ Ready |

### SPEC-0004 Dependency Graph
```mermaid
graph TD
    ISSUE009[ISSUE-009: Adapter Core & Qwen Coder] --> ISSUE010[ISSUE-010: Granite & Llama Guard 3]
    ISSUE009 --> ISSUE011[ISSUE-011: Prompt-Guard-86M]
    ISSUE009 --> ISSUE012[ISSUE-012: FastMCP Factory & Servers]
    ISSUE010 --> ISSUE012
    ISSUE011 --> ISSUE012
    ISSUE009 --> ISSUE013[ISSUE-013: Benchmark Matrix & Leaderboard]
    ISSUE010 --> ISSUE013
    ISSUE011 --> ISSUE013
    ISSUE013 --> ISSUE014[ISSUE-014: Web Dashboard Multi-Run Discrepancy]
```

---

## Historical Issues

### SPEC-0003: Unified Test Cases Dataset Explorer
| Issue ID | Title | Blocked by | Status |
| :--- | :--- | :--- | :--- |
| **[ISSUE-006](./ISSUE-006-test-cases-dataset-explorer.md)** | Test Cases Explorer — Core Paginated Table & Filters | *None* | ✅ Done |
| **[ISSUE-007](./ISSUE-007-test-cases-drawer-and-deep-linking.md)** | Test Cases Explorer — Case Detail Drawer & Deep-Linking | [ISSUE-006](./ISSUE-006-test-cases-dataset-explorer.md) | ✅ Done |
| **[ISSUE-008](./ISSUE-008-test-cases-search-and-sorting.md)** | Test Cases Explorer — Substring ILIKE Search & Dynamic Sorting | [ISSUE-006](./ISSUE-006-test-cases-dataset-explorer.md) | ✅ Done |

### SPEC-0002: Hybrid Guard Engine & Discrepancy Benchmark
| Issue ID | Title | Blocked by | Status |
| :--- | :--- | :--- | :--- |
| **[ISSUE-001](./ISSUE-001-analysis-tier-schema-and-dataset-normalization.md)** | Analysis Tier Schema & DLP Normalization | *None* | ✅ Done |
| **[ISSUE-002](./ISSUE-002-declarative-l1-static-rule-engine-and-adapter.md)** | Declarative L1 Static Rule Engine & Adapter | [ISSUE-001](./ISSUE-001-analysis-tier-schema-and-dataset-normalization.md) | ✅ Done |
| **[ISSUE-003](./ISSUE-003-fail-fast-cascade-hybrid-engine.md)** | Fail-Fast Cascade Hybrid Engine (HybridCascadeAdapter) | [ISSUE-002](./ISSUE-002-declarative-l1-static-rule-engine-and-adapter.md) | ✅ Done |
| **[ISSUE-004](./ISSUE-004-scalable-duckdb-relational-storage.md)** | Scalable DuckDB Relational Storage (run_case_evaluations) | [ISSUE-003](./ISSUE-003-fail-fast-cascade-hybrid-engine.md) | ✅ Done |
| **[ISSUE-005](./ISSUE-005-discrepancy-api-and-compare-runs-ui.md)** | Discrepancy API & Compare Runs Web UI | [ISSUE-004](./ISSUE-004-scalable-duckdb-relational-storage.md) | ✅ Done |
