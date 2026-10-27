# Implementation Plan: Declarative Experiment Matrix & Dual-Track Ollama Serving Studio (Phase 7)

* **Feature:** Declarative Experiment Matrix & Dual-Track Ollama Serving Studio
* **Governing Specification:** [SPEC.md](../SPEC.md)
* **Related ADR:** [ADR 0010: Code-First Adapters, DuckDB-Native Test Matrix, and Dual-Track Serving Architecture](../docs/adr/0010-code-first-adapters-duckdb-matrix-and-dual-track-serving.md)
* **Domain Model:** [CONTEXT.md](../CONTEXT.md)
* **Status:** Ready for Execution

---

## 1. Overview & Architecture
This plan decomposes the implementation of Phase 7 into atomic, verifiable vertical slices. The objective is to establish a **DuckDB-Native Experiment Registry** that enables configuring and executing multi-model benchmarks without modifying Python code, while deploying **`OllamaGuardAdapter`** for generative safety guards (Llama Guard 3, Granite Guardian) with discrete verdict parsing and **Dual-Track Leaderboard** runtime segregation.

---

## 2. Key Architecture Decisions (ADR 0010)
- **DuckDB as Single Source of Truth:** Test matrix definitions live in the `experiment_templates` table and link relationally (`FOREIGN KEY`) to `run_history`.
- **Pre-populated Seed Template (Scenario A):** Database initialization seeds `exp_smoke_dual_track` (200 balanced cases evaluating Laya MLX, Liquid d1, and Llama Guard 3) out of the box.
- **Code-First Adapters:** Model-specific prompting and CWE taxonomy mapping remain in strongly-typed Python classes (`OllamaGuardAdapter`), avoiding fragile YAML DSLs.
- **Discrete Verdicts on Ollama:** Generative models on Ollama emit discrete verdicts ($0.0/1.0$); continuous logprob sweeps remain in MLX.
- **Dual-Track Tagging:** Every run records `runtime_tier` (`MLX_NATIVE_METAL` vs `OLLAMA_DAEMON_HTTP` vs `PYTORCH_MPS`).
- **Host Daemon Serving:** Laya MLX runs on the macOS host; Docker is prohibited for Apple Silicon Metal workloads.

---

## 3. Dependency Graph & Implementation Order

```text
[Task 1: DuckDB Experiment Registry Schema & Seed Template]
                           │
                           ▼
[Task 2: TDD RED/GREEN - OllamaGuardAdapter for Generative Models]
                           │
                           ▼
[Task 3: Registry Integration in benchmark_runner.py & LifeCycle]
                           │
                           ▼
                    [Checkpoint 1]
                           │
                           ▼
[Task 4: Dual-Track Matrix Runner & Leaderboard Runtime Badges]
                           │
                           ▼
[Task 5: Web Studio Backend & UI Integration (/api/experiments)]
                           │
                           ▼
[Task 6: End-to-End Dual-Track Smoke Benchmark Run]
                           │
                           ▼
                    [Checkpoint 2]
```

---

## 4. Risks & Mitigations

| Risk | Impact | Mitigation Strategy |
| :--- | :---: | :--- |
| **Existing DuckDB databases lack `experiment_templates` table** | High | Dynamic migration in `init_db()` runs `CREATE TABLE IF NOT EXISTS` and `ALTER TABLE run_history ADD COLUMN IF NOT EXISTS` safely. |
| **Ollama daemon offline during generative guard execution** | High | Unit tests mock Ollama HTTP responses; runtime adapter returns `verdict: "ERROR"` without unhandled process termination. |
| **Model output formatting jitter (e.g. extra whitespace in Llama Guard output)** | Medium | Robust regex parsing in `OllamaGuardAdapter` cleans markdown code fences, leading/trailing whitespace, and case variations. |
| **VRAM accumulation during sequential matrix runs** | High | Deterministic `unload()` sends `keep_alive: 0` to Ollama `/api/generate` and calls `flush_unified_memory()`. |
