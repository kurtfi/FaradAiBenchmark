# ADR 0008: Kev-0.8B Decision Model Adapter & Benchmark Evaluation

* **Date:** 2026-10-18
* **Status:** Accepted
* **Scope:** Faraday Laya Guard / L2 Semantic Inspection Engines & FastMCP Services

---

## 1. Context and Problem Statement
Faraday Guard uses `Laya MLX` as its primary L2 semantic engine, taking advantage of its non-autoregressive decision model architecture (ModernBERT backbone) to output calibrated boolean decision probabilities (`noul`) in a single forward pass without token-by-token generation overhead.

Recently, Jared Palmer introduced **Kev** (`jaredpalmer/kev`), an open-source family of typed decision models (Apache-2.0) built on Qwen backbones with custom pointer heads, implementing TypeSafe's System One (`/v1/systemone`) contract.

To evaluate whether Kev can serve as an effective alternative or complement to Laya in tool-call parameter inspection and prompt injection defense:
1. The model must strictly operate under a **< 1 GB RAM** memory footprint to ensure edge compatibility on developer laptops and resource-constrained nodes.
2. The model must leverage native **Apple Silicon (MLX)** acceleration.
3. The evaluation must be apples-to-apples against Laya's dual-check inspection schema (`misalignment` + `exploit`).

---

## 2. Decision Log

### Decision 1: In-Process MLX Inference for Hardware Latency Parity
* **Decision:** Kev-0.8B will be evaluated in-process via a native MLX adapter (`KevAdapter` extending `BaseModelAdapter`), rather than via an external HTTP daemon (`kev.serve`).
* **Rationale:** Eliminates socket and HTTP serialization latency, ensuring direct measurement of raw Apple Silicon Metal computation time against `Laya MLX` and `Qwen3Guard`.

### Decision 2: 4-bit Quantization Baseline for Sub-1GB RAM Footprint
* **Decision:** `jaredpalmer/kev-0.8b` (built on `Qwen3.5-0.8B-Base`) will run with 4-bit quantization on MLX.
* **Rationale:** While unquantized bfloat16 consumes ~1.6 GB, 4-bit quantization reduces active memory footprint to **~500 MB – 700 MB RAM**, strictly satisfying the < 1 GB RAM constraint while minimizing Metal unified memory bandwidth pressure. (Kev-4B is excluded from this target as it exceeds 2.5 GB even under 4-bit quantization).

### Decision 3: Dual-Check Question & Threat Threshold Normalization
* **Decision:** The adapter evaluates the exact same `DUAL_CHECK_QUESTIONS` defined for Laya:
  - `misalignment` (threshold 0.65): Deviation from primary user goal or execution of untrusted external instructions.
  - `exploit` (threshold 0.50): Technical exploit payloads (command injection, SQLi, path traversal, SSRF).
* **Rationale:** Ensures fair, controlled comparative testing without prompt engineering bias across the benchmark case pool.

### Decision 4: Standalone FastMCP Entrypoint via Guard MCP Factory
* **Decision:** In accordance with ADR 0007 Decision 5, `guard_mcp_factory.py` will generate `kev_security_guard_mcp.py` as an independent zero-flag FastMCP entrypoint.
* **Rationale:** Enables direct drop-in integration into Faraday Gateway or Claude Code as a standalone inspection MCP server.

---

## 3. Consequences
* `adapters/kev_adapter.py` will be implemented and registered under `ADAPTER_REGISTRY["kev-0.8b"]` in `benchmark_runner.py`.
* A 200-case smoke test on `smoke_test_2k.parquet` will be executed to establish initial Accuracy, FPR, and Latency metrics comparing `Laya MLX` vs. `Kev-0.8B`.
