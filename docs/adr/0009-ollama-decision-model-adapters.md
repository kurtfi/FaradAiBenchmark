# ADR 0009: Ollama-Native Decision Model Adapters & Production Parity

* **Date:** 2026-10-25
* **Status:** Accepted
* **Scope:** Farad Ai Benchmark / L2 Semantic Inspection Engines, Ollama Integration, and Decision Models

---

## 1. Context and Problem Statement
Farad Ai Benchmark evaluates local Small Language Models (SLMs) and System 1 Decision Models for MCP tool call security inspection. Recently, three next-generation decision models emerged as high-potential candidates for fast (<30ms) policy gating without token generation jitter:
1. **Liquid AI d1-3B** (LFM2.5-VL hybrid non-transformer architecture)
2. **Perplexity Decider Flash v1.2** (Distilled Qwen3.5-4B decision backbone)
3. **Mica v0.5** (4B Qwen fine-tuned decision model)

Prior architectural approaches considered compiling custom C++ bindings (`llama-cpp-python`) or writing custom MLX layers. However:
- In real-world production deployments, services are standardized on **Ollama** as the local model daemon.
- Ollama natively added support for Decision Models and the TypeSafe `/v1/systemone` format (`--ask`, `--choice`, `noul`), including official tags (`ollama pull d1`, `pplx-decider`).
- Evaluating models via Ollama guarantees **100% production parity**: the latency and memory behaviors measured in benchmark runs reflect live runtime conditions.

---

## 2. Decision Log

### Decision 1: Unified `OllamaDecisionAdapter` over Fragmented Runtimes
* **Decision:** Implement a single, parameterized adapter class `OllamaDecisionAdapter(model_name: str, host: str = "http://127.0.0.1:11434")` in `adapters/ollama_decision_adapter.py` rather than maintaining separate C++, MLX, and custom runtimes.
* **Rationale:** All three models share the exact same `/v1/systemone` HTTP JSON protocol. A unified adapter prevents 90%+ code duplication, avoids dynamic library conflicts on macOS, and allows instantly onboarding future Ollama decision models.

### Decision 2: Strict Isolation between Pure L2 and Hybrid Cascade
* **Decision:** `OllamaDecisionAdapter` will strictly execute as a **pure L2 semantic adapter**. It will NOT embed L1 regex rules or static checks internally.
* **Rationale:** Preserves the core FaradAiBenchmark distinction:
  - **Pure L2 Run:** Evaluates the model's unassisted reasoning, standalone False Positive Rate (FPR), and raw inference latency.
  - **Hybrid Cascade Run:** Managed exclusively by `HybridCascadeAdapter(l1_engine=..., l2_adapter=ollama_adapter)` to measure Fail-Fast offload ratios and CPU/GPU savings.

### Decision 3: Standardized Baseline Thresholds for Direct Parity
* **Decision:** By default, all Ollama decision models will be evaluated using the calibrated thresholds established in DEC-09:
  - `exploit_threshold = 0.50` (Strict on technical payloads)
  - `misalignment_threshold = 0.65` (Prudent on benign business workflow tools)
* **Rationale:** Guarantees a controlled, apples-to-apples comparison against `Laya MLX` and `Kev-0.8B` on the 2,000-case smoke dataset before any model-specific tuning.

### Decision 4: Deterministic VRAM Eviction via `keep_alive: 0`
* **Decision:** In the adapter's `unload()` method, an explicit HTTP request `POST /api/generate {"model": self.model_name, "keep_alive": 0}` will be sent to the Ollama daemon.
* **Rationale:** Overrides Ollama's default 5-minute memory caching, forcing immediate deallocation of Metal VRAM between sequential matrix runs to eliminate out-of-memory cascading.

---

## 3. Consequences
* `adapters/ollama_decision_adapter.py` will be created implementing `BaseModelAdapter`.
* `ADAPTER_REGISTRY` in `benchmark_runner.py` will register:
  - `"ollama-d1"`
  - `"ollama-pplx-decider"`
  - `"ollama-mica"`
* Downstream matrix evaluations (`benchmark_matrix.py`) will seamlessly compare Ollama decision models alongside Laya, Granite, and Llama Guard.
