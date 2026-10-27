# ADR 0010: Code-First Adapters, DuckDB-Native Test Matrix, and Dual-Track Serving Architecture

* **Date:** 2026-10-27
* **Status:** Accepted
* **Scope:** Farad Ai Benchmark / Model Serving, Matrix Orchestration, Leaderboard Fairness & Architecture

---

## 1. Context and Problem Statement
As Farad Ai Benchmark expanded to evaluate both next-generation System 1 Decision Models (Liquid d1, Perplexity Decider, Mica, Kev) and classical Generative SLM Guards (Llama Guard 3, Granite Guardian, ShieldGemma, Qwen3Guard), two major architectural questions emerged:
1. **Serving Strategy:** Can we standardize all models on local Ollama daemons, and can models like Laya MLX be containerized with Docker?
2. **Orkestration & User Experience:** Can model onboarding be completely "zero-code" (declarative UI/YAML form) so researchers can test new models without writing Python code?

Following rigorous evaluation via `/doubt-driven-development` and `/grill-with-docs`, attempting a "zero-code adapter" approach was proven to be an anti-pattern that destroys model accuracy (broken tokenizer kwargs and chat templates), loses continuous probability scores (Ollama `/api/chat` lacks logprobs), drops CWE taxonomy mappings, and devolves into a fragile, untyped YAML DSL. Furthermore, containerizing Apple Silicon MLX models in Docker on macOS results in a catastrophic 10x-40x slowdown due to the lack of Metal GPU virtualization passthrough.

To resolve these challenges cleanly, we establish the **Code-First Adapter + DuckDB-Native Test Matrix + Dual-Track Serving** architecture.

---

## 2. Decision Log

### Decision 1: Code-First Adapters over Zero-Code YAML DSL
* **Decision:** The implementation of model communication (tokenizer chat templates, special delimiter tokens, logit extraction, CWE taxonomy mappings, and memory eviction) will remain strictly code-first in typed Python adapter classes deriving from `BaseModelAdapter`.
* **Rationale:** Language models and decision models possess fundamentally incompatible internal representations. Code-first adapters ensure type safety (`mypy`/`pyright`), full test coverage (`pytest`), and 100% adherence to authors' official prompts without over-simplifying or inventing a complex YAML programming DSL.

### Decision 2: DuckDB-Native Experiment Registry (`experiment_templates`)
* **Decision:** Benchmark test matrix definitions and experiment configurations will be stored natively in `data/benchmark_runs.duckdb` within an `experiment_templates` table as the Single Source of Truth, rather than loose filesystem YAML files. Optional export/import to YAML will be provided for CLI/CI reproducibility.
* **Rationale:** Keeps the relational model intact. Every execution in `run_history` can be joined directly (`FOREIGN KEY`) to its originating `experiment_id`. This eliminates filesystem race conditions in FastAPI (`web/app.py`) and allows instant SQL meta-queries across experiment runs.

### Decision 3: Host Daemon Serving for Laya MLX (Prohibiting Docker for Metal)
* **Decision:** Laya MLX will run exclusively as a native macOS host daemon (via FastMCP / Uvicorn REST service) and will NOT be deployed inside Docker containers on macOS.
* **Rationale:** macOS Docker runs inside a lightweight Linux VM where Apple provides zero Metal GPU passthrough. Running MLX in Docker forces CPU-only execution, degrading latency from ~15-25ms to 250-800ms. Ollama runs natively on the macOS host; Laya MLX must similarly run on the host to preserve Metal hardware parity.

### Decision 4: Discrete Verdicts for Ollama Generative Guards vs. Continuous Calibration for MLX
* **Decision:** Generative safety guards served through Ollama (`llama-guard3:1b`, `granite3-guardian:2b`) will produce discrete binary verdicts ($0.0$ or $1.0$) based on their emitted output strings. Fine-grained continuous threshold sweeps, ROC-AUC curves, and logprob calibration will remain exclusively in `[MLX-Native]` and System 1 Decision Model runs.
* **Rationale:** Standard Ollama REST endpoints (`/api/chat`, `/api/generate`) return plain strings without token logit distributions. Forcing prompt-based confidence hallucination degrades benchmark validity; treating Ollama generative guards as discrete decision makers preserves the integrity of both paradigms.

### Decision 5: Dual-Track Leaderboard and Runtime Tier Tagging
* **Decision:** Every benchmark run and evaluation record will explicitly record its `runtime_tier`:
  - `MLX_NATIVE_METAL`: In-process Apple Silicon Metal execution (Hardware Ceiling Parity).
  - `OLLAMA_DAEMON_HTTP`: External HTTP daemon execution (Production Deployment Parity).
  - `PYTORCH_MPS`: In-process PyTorch Metal Performance Shaders.
* **Rationale:** Prevents unfair comparisons between raw silicon compute (~18ms) and daemonized network/IPC delivery (~24ms), while giving users total transparency across deployment scenarios.

### Decision 6: Local PyTorch MPS Retention for Ultra-Fast Classifiers
* **Decision:** Encoder-based sequence classification models (Meta Prompt-Guard-86M, DeBERTa-v3) will remain local PyTorch MPS / ONNX adapters and will not be migrated to Ollama.
* **Rationale:** These sub-100M parameter models run in <5ms on Apple Silicon MPS. Routing them through a generative LLM daemon would introduce unwarranted HTTP latency without functional benefit.

---

## 3. Consequences
* A new `experiment_templates` table will be created in DuckDB schema.
* Web Dashboard UI will provide an "Experiment Matrix Studio" allowing users to save and launch multi-model test runs without writing Python code.
* The Leaderboard Matrix will display runtime badges (`[MLX-Native]`, `[Ollama-Daemon]`, `[MPS]`).
* Laya MLX will be packaged as a standalone host FastMCP service.
