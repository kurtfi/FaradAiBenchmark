# Engineering Specification: Multi-SLM L2 Adapters, FastMCP Factory, and Comparative Benchmark Architecture

* **Document ID:** SPEC-0004
* **Date:** 2026-10-03
* **Status:** Approved / Ready for Implementation
* **Scope:** L2 SLM Model Candidates (Qwen, Granite, Llama Guard, ShieldGemma, Prompt-Guard), Shared FastMCP Factory, Normalized Output Contract, Two-Phased Leaderboard Matrix
* **Related ADRs:** ADR 0001, ADR 0002, ADR 0003, ADR 0004, ADR 0006, [ADR 0007](file:///Users/firatkurt/Documents/Repos/FaradAiBenchmark/docs/adr/0007-multi-slm-l2-adapter-and-benchmark-architecture.md)

---

## 1. Executive Summary & Goals

### 1.1 Project Overview
In Farad Ai Benchmark, semantic threat inspection at the L2 tier is currently handled by the local `Laya MLX` engine. However, in real-world agentic workflows, the arguments emitted by LLMs (`tool_arguments`) are rarely simple conversational text; they primarily consist of shell commands (Bash), SQL queries, file paths, regexes, and structured JSON payloads.

This specification defines the engineering blueprint to benchmark **safety-specialized SLMs (Qwen3Guard-0.6B)**, **agentic tool-safety models (IBM Granite Guardian 3.1-2B)**, and **lightweight safety moderators (Meta Llama Guard 3, ShieldGemma, Prompt-Guard)** against Laya under identical hardware conditions (Apple Silicon Metal / MLX). Additionally, it specifies how to package these models into standalone, plug-and-play FastMCP servers.

### 1.2 Core Engineering Objectives
1. **Fair Hardware & Memory Baseline (Fair Quantization Baseline):** Standardize all generative SLMs (Qwen, Granite, Llama Guard, ShieldGemma) on 4-bit quantization (MLX 4-bit / Q4_K_M) to equalize unified memory footprints (~1.2 - 2.0 GB) and accurately benchmark raw Apple Silicon compute latency.
2. **Decoupled Two-Tier Architecture (Adapter Core + FastMCP Wrapper):** Separate the in-memory Python `BaseModelAdapter` core (measuring pure inference latency without IPC overhead) from the standalone FastMCP wrappers serving external clients (IDEs, Gateways).
3. **Standardized Verdict & Continuous Probability Contract:** Normalize heterogeneous model outputs (Qwen JSON, Llama Guard `safe/unsafe`, Granite `yes/no`, Prompt Guard logits) into a uniform `is_blocked`, `confidence (0.0 - 1.0)`, and `verdict` contract.
4. **Two-Phased Benchmark Execution (Leaderboard Matrix):** Implement a two-phased benchmark pipeline (200-case smoke test followed by a 2000+ Parquet master pool run) with DuckDB-backed historical storage and an automated CLI Leaderboard matrix.
5. **Zero-Flag FastMCP Executables:** Expose dedicated entrypoints (`qwen_security_guard_mcp.py`, `granite_security_guard_mcp.py`, etc.) powered by a reusable factory (`guard_mcp_factory.py`).

---

## 2. System Architecture & Components

```
                                  [ MCP Tool Call Request / Test Case ]
                                                    │
                                                    ▼
                                    ┌───────────────────────────────┐
                                    │      L1 Rule Engine (Fast)    │
                                    │  - <0.2ms Regex & Signatures  │
                                    └───────────────────────────────┘
                                                    │ (Clean / Inconclusive)
                                                    ▼
                    ┌───────────────────────────────────────────────────────────────┐
                    │                   L2 SLM Adapter Layer Core                   │
                    │                   (BaseModelAdapter Interface)                │
                    └───────────────────────────────────────────────────────────────┘
                                                    │
            ┌───────────────────┬───────────────────┼───────────────────┬───────────────────┐
            ▼                   ▼                   ▼                   ▼                   ▼
    ┌───────────────┐   ┌───────────────┐   ┌───────────────┐   ┌───────────────┐   ┌───────────────┐
    │  Laya MLX     │   │  Qwen3Guard   │   │ Granite-Guard │   │ Llama-Guard 3 │   │ Prompt-Guard  │
    │  - 4-bit MLX  │   │ - 0.6B MLX    │   │ - 2B 4-bit    │   │ - 1B 4-bit    │   │ - 86M MPS     │
    │  - Dual-Check │   │ - Safety SLM  │   │ - Tool-Call   │   │ - MLCommons   │   │ - Indirect    │
    │  - Misalign+  │   │ - Intent Isol │   │ - Logprob     │   │ - Logprob     │   │   Injection   │
    │    Exploit    │   │ - Exploit Cat │   │   Extraction  │   │   Extraction  │   │ - Softmax     │
    └───────────────┘   └───────────────┘   └───────────────┘   └───────────────┘   └───────────────┘
            │                   │                   │                   │                   │
            └───────────────────┴───────────────────┼───────────────────┴───────────────────┘
                                                    │
                                                    ▼
                                    ┌───────────────────────────────┐
                                    │ Normalized Decision Contract  │
                                    │ - is_blocked: bool            │
                                    │ - confidence: float (0.0-1.0) │
                                    │ - verdict: "BLOCKED"|"ALLOWED"│
                                    │ - latency_ms: float           │
                                    └───────────────────────────────┘
                                                    │
                        ┌───────────────────────────┴───────────────────────────┐
                        ▼                                                       ▼
        ┌────────────────────────────────┐                     ┌────────────────────────────────┐
        │       FastMCP Wrapper          │                     │     Benchmark Runner Engine    │
        │    (guard_mcp_factory.py)      │                     │  - benchmark_runner.py         │
        │ - qwen_security_guard_mcp.py   │                     │  - benchmark_matrix.py         │
        │ - granite_security_guard_mcp.py│                     │  - DuckDB evaluations storage  │
        │ - llama_security_guard_mcp.py  │                     │  - Leaderboard Table & Diff    │
        └────────────────────────────────┘                     └────────────────────────────────┘
```

### 2.1 Core Modules & Responsibilities
* **`adapters/base.py` (`BaseModelAdapter`):** Base abstract class defining the evaluation signature.
* **`adapters/qwen_guard_adapter.py` (`Qwen3GuardAdapter`):** Executes Qwen3Guard-0.6B via MLX, utilizing dedicated safety classification to evaluate command, SQL, path, and payload safety.
* **`adapters/granite_guardian_adapter.py` (`GraniteGuardianAdapter`):** Formats requests according to IBM Granite's agentic tool-risk prompt and derives continuous probability from the first-token logits.
* **`adapters/llama_guard_adapter.py` (`LlamaGuardAdapter`):** Formats inputs into the Llama Guard 3 tool safety conversation template, mapping `safe`/`unsafe` logprobs to continuous scores.
* **`adapters/shield_gemma_adapter.py` (`ShieldGemmaAdapter`):** Classifies policy compliance using the Gemma 2 safety framework.
* **`adapters/prompt_guard_adapter.py` (`PromptGuardAdapter`):** Runs Meta Prompt-Guard-86M on PyTorch MPS for sub-5ms indirect prompt injection screening.
* **`guard_mcp_factory.py`:** Shared builder binding any `BaseModelAdapter` instance to FastMCP's `@mcp.tool() inspect_tool_call` decorator.
* **`benchmark_matrix.py`:** Orchestrates multi-model evaluation across Parquet test pools and outputs comparative Rich tables and DuckDB relational records.

---

## 3. Architectural Decision Records (ADRs) Index

* **[ADR 0001: Model-Agnostic Benchmark Pipeline & Storage](file:///Users/firatkurt/Documents/Repos/FaradAiBenchmark/docs/adr/0001-benchmark-dataset-pipeline-and-storage.md):** Parquet storage standard and in-memory DuckDB querying.
* **[ADR 0002: Analysis Tier Classification](file:///Users/firatkurt/Documents/Repos/FaradAiBenchmark/docs/adr/0002-analysis-tier-classification.md):** Isolation of `STATIC_CAPABLE`, `SEMANTIC_REQUIRED`, and `HYBRID` test cases.
* **[ADR 0003: Fail-Fast Cascade Hybrid Architecture](file:///Users/firatkurt/Documents/Repos/FaradAiBenchmark/docs/adr/0003-fail-fast-cascade-hybrid-architecture.md):** Low-latency L1 short-circuiting prior to L2 invocation.
* **[ADR 0004: Relational Evaluation Storage & Discrepancy Analysis](file:///Users/firatkurt/Documents/Repos/FaradAiBenchmark/docs/adr/0004-relational-evaluation-storage-and-discrepancy-analysis.md):** Relational schema for `evaluation_runs` and `run_case_evaluations`.
* **[ADR 0006: Unified Benchmark Case Pool](file:///Users/firatkurt/Documents/Repos/FaradAiBenchmark/docs/adr/0006-unified-benchmark-case-pool-and-parquet-streaming.md):** Single-source evaluation via `master_benchmark.parquet`.
* **[ADR 0007: Multi-SLM L2 Adapters and Comparative Benchmark Architecture](file:///Users/firatkurt/Documents/Repos/FaradAiBenchmark/docs/adr/0007-multi-slm-l2-adapter-and-benchmark-architecture.md):** Standardized 4-bit quantization baseline, decoupled adapter/wrapper architecture, probability normalization, and FastMCP factory pattern.

---

## 4. Data Models & API Contracts

### 4.1 `BaseModelAdapter` Interface
All L2 model adapters implement the following interface:

```python
from abc import ABC, abstractmethod
from typing import Dict, Any

class BaseModelAdapter(ABC):
    """Standardized Interface for L2 Security Evaluation Adapters."""

    @abstractmethod
    def evaluate(self, tool_name: str, tool_arguments: Dict[str, Any], context: str) -> Dict[str, Any]:
        """
        Evaluates tool parameters and returns a normalized dictionary:
        {
            "is_blocked": bool,            # True if threat detected, False if benign
            "confidence": float,           # Threat probability between 0.0 and 1.0
            "verdict": "BLOCKED"|"ALLOWED",# String verdict
            "threat_domain": str | None,   # Detected category (CWE-78, SQLI, etc.)
            "cwe": str | None,             # Associated CWE ID
            "decision_engine": str,        # E.g. "L2_QWEN3_GUARD", "L2_GRANITE_GUARDIAN"
            "raw_output": Any              # Raw underlying model output (logprobs, reasoning)
        }
        """
        pass
```

### 4.2 FastMCP Standard Tool Contract
Every standalone guard MCP server (`qwen_security_guard_mcp.py`, `granite_security_guard_mcp.py`, etc.) exposes an identical FastMCP tool signature:

```python
@mcp.tool()
def inspect_tool_call(
    tool_name: str,
    tool_arguments: Dict[str, Any],
    execution_context: str = "",
    tool_description: str = "",
    threat_threshold: float = 0.70
) -> Dict[str, Any]:
    """
    Inspects tool call arguments emitted by an LLM using Root Intent Isolation
    and Semantic Vulnerability Analysis.
    """
    ...
```

### 4.3 DuckDB Relational Storage Schema
Results from multi-model runs are stored in `data/db/evaluations.duckdb`:

* **`evaluation_runs` Table**:
  - `run_id`: VARCHAR (UUID)
  - `model_name`: VARCHAR (`qwen3guard-0.6b-4bit`, `granite-guardian-2b-4bit`, etc.)
  - `dataset_name`: VARCHAR (`smoke_test_200.parquet` or `master_benchmark.parquet`)
  - `total_cases`: INTEGER
  - `accuracy`, `precision`, `recall`, `f1_score`, `fpr`: DOUBLE
  - `avg_latency_ms`, `p95_latency_ms`: DOUBLE
  - `created_at`: TIMESTAMP
* **`run_case_evaluations` Table**:
  - `run_id`: VARCHAR
  - `case_id`: VARCHAR
  - `threat_domain`: VARCHAR
  - `analysis_tier`: VARCHAR
  - `cwe`: VARCHAR
  - `expected_blocked`: BOOLEAN
  - `predicted_blocked`: BOOLEAN
  - `is_correct`: BOOLEAN
  - `confidence`: DOUBLE
  - `latency_ms`: DOUBLE

---

## 5. User Experience & Workflows

### 5.1 CLI: Two-Phased Matrix Benchmark (Leaderboard)

1. **Phase 1: Smoke Test & Sanity Validation:**
   ```bash
   python benchmark_matrix.py --smoke
   ```
   * Runs 200 balanced test scenarios across all registered model adapters.
   * Verifies model weight loading, memory consumption, and initial baseline latency.

2. **Phase 2: Full Benchmark & Comparative Leaderboard:**
   ```bash
   python benchmark_matrix.py --full
   ```
   * Evaluates all adapters against the entire 2000+ Parquet case pool.
   * Renders a Rich-formatted Security Leaderboard table to the terminal:

```text
┏━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━━━━┓
┃ Model Name          ┃ Accuracy ┃ Precision ┃ Recall ┃ F1-Score ┃ FPR     ┃ Avg Latency┃ P95 Latency┃
┡━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━━━━┩
│ Laya MLX            │ 92.4%    │ 93.1%     │ 91.5%  │ 92.3%    │ 4.2%    │ 18.4 ms    │ 24.1 ms    │
│ Qwen3Guard-0.6B     │ 94.8%    │ 96.2%     │ 93.4%  │ 94.8%    │ 2.8%    │ 14.6 ms    │ 19.8 ms    │
│ Granite-Guardian-2B │ 91.0%    │ 89.5%     │ 92.8%  │ 91.1%    │ 6.1%    │ 28.2 ms    │ 36.5 ms    │
│ Llama-Guard-3-1B    │ 88.5%    │ 87.2%     │ 90.1%  │ 88.6%    │ 7.8%    │ 19.1 ms    │ 26.0 ms    │
│ Prompt-Guard-86M    │ 78.2%    │ 95.0%     │ 62.0%  │ 75.0%    │ 2.1%    │ 3.8 ms     │ 5.2 ms     │
└─────────────────────┴──────────┴───────────┴────────┴──────────┴─────────┴────────────┴────────────┘
```

### 5.2 FastMCP Server Configuration
Client environments (Claude Desktop, Cursor, FaradAiWire) configure the guard servers with zero additional flags:

```json
{
  "mcpServers": {
    "qwen-guard": {
      "command": "python",
      "args": ["/path/to/farad-ai-benchmark/qwen_security_guard_mcp.py"]
    },
    "granite-guard": {
      "command": "python",
      "args": ["/path/to/farad-ai-benchmark/granite_security_guard_mcp.py"]
    }
  }
}
```

### 5.3 Web Dashboard: Cross-Model Discrepancy Analysis
Within the dashboard (`http://localhost:8765/#compare-runs`):
1. The user selects two completed runs from the dropdown (e.g. `Run A: Laya MLX`, `Run B: Qwen3Guard`).
2. The page renders the SQL differential comparison isolating exact cases where the two models disagreed, categorized by CWE and Threat Domain.

---

## 6. Security, Privacy & Non-Functional Requirements (NFRs)

### 6.1 100% Local & Air-Gapped Execution
* Zero test payloads or tool arguments leave the local host. All tokenization, inference, and classification execute locally on Apple Silicon Metal cores.

### 6.2 Hardware Isolation & Memory Budget
* Models execute sequentially during benchmark runs, invoking `mlx.core.metal.clear_cache()` between adapter transitions to prevent unified memory fragmentation.
* Peak memory budget per active model process is capped at 2.5 GB.

### 6.3 Latency Budgets (Apple Silicon M-Series)
* **Prompt-Guard-86M (Classifier):** Target < 6 ms (P95 < 10 ms).
* **Qwen3Guard-0.6B (4-bit MLX):** Target < 20 ms (P95 < 25 ms).
* **Llama Guard 3 1B (4-bit MLX):** Target < 25 ms (P95 < 30 ms).
* **Granite Guardian 2B (4-bit MLX):** Target < 35 ms (P95 < 45 ms).

### 6.4 Fail-Safe Fallback
* If a model fails to load or encounters an unhandled runtime error, the engine must never fail open. It immediately reverts to the L1 deterministic regex rule set to block overt attack vectors (`/etc/passwd`, `DROP TABLE`, `sk-proj-`) and emits a warning log.
