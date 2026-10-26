# Implementation Plan: Ollama-Native Decision Model Adapters

* **Feature:** Ollama-Native Decision Model Integration (Liquid AI d1-3B, Perplexity Decider Flash, Mica v0.5)
* **Governing Specification:** [SPEC.md](../../SPEC.md)
* **Related ADR:** [ADR 0009: Ollama-Native Decision Model Adapters & Production Parity](../adr/0009-ollama-decision-model-adapters.md)
* **Canonical Plan:** [tasks/plan.md](../../tasks/plan.md)
* **Status:** Awaiting Human Approval

---

## 1. Overview & Architecture
This plan decomposes the integration of local Ollama-hosted System 1 Decision Models into atomic, verifiable vertical tasks. The goal is to evaluate `d1`, `pplx-decider-flash`, and `mica-v0.5` through a unified `OllamaDecisionAdapter` directly matching live production deployment without embedding L1 logic into the model adapter.

---

## 2. Key Architecture Decisions
- **Unified Parameterized Adapter:** A single `OllamaDecisionAdapter(model_name: str, ...)` in `adapters/ollama_decision_adapter.py` manages all Ollama decision models.
- **Strict L2 Isolation:** Pure model evaluations execute without static rule contamination. Hybrid evaluations are composed via `HybridCascadeAdapter(l1_engine, l2_adapter)`.
- **Deterministic VRAM Eviction:** `unload()` sends `keep_alive: 0` to Ollama (`POST /api/generate`) to purge model weights from Apple Silicon Metal unified memory before subsequent runs.
- **Protocol Fallback:** Adapter attempts `/v1/systemone` first; if an older Ollama release returns 404, it gracefully falls back to structured `/api/chat` with JSON schema enforcement.

---

## 3. Dependency Graph & Implementation Order

```text
[Task 1: Modelfiles & Model Prep Helper]
                     │
                     ▼
[Task 2: TDD RED - Unit Test Suite (Mocked HTTP)]
                     │
                     ▼
[Task 3: TDD GREEN - OllamaDecisionAdapter Core]
                     │
                     ▼
             [Checkpoint 1]
                     │
                     ▼
[Task 4: Registry & Benchmark Runner Integration]
                     │
                     ▼
[Task 5: Benchmark Matrix & Leaderboard Integration]
                     │
                     ▼
[Task 6: Smoke Benchmark Verification (DuckDB Run)]
                     │
                     ▼
             [Checkpoint 2]
```
