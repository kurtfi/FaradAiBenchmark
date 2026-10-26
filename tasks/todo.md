# Task Checklist: Ollama-Native Decision Model Adapters

* **Governing Specification:** [SPEC.md](../SPEC.md)
* **Implementation Plan:** [plan.md](plan.md)
* **Status:** Complete (84/84 tests passing)

---

## Phase 1: Foundation & Modelfiles

- [x] **Task 1: Ollama Modelfiles & Model Preparation Helper**
  - **Description:** Create Modelfile definitions for community GGUF models (Mica v0.5 and Perplexity Decider Flash) and a lightweight CLI helper script to check/pull models in Ollama.
  - **Acceptance Criteria:**
    - [x] `scripts/modelfiles/Modelfile.mica` points to `sky7350/Mica-v0.5-4B-Q4_K_M.gguf`.
    - [x] `scripts/modelfiles/Modelfile.pplx-decider` created for Perplexity Decider Flash Q4.
    - [x] `scripts/prepare_ollama_decision_models.py` can verify Ollama connection and list installed decision models.
  - **Verification:** `python scripts/prepare_ollama_decision_models.py --check-only`
  - **Files:** `scripts/modelfiles/Modelfile.mica`, `scripts/modelfiles/Modelfile.pplx-decider`, `scripts/prepare_ollama_decision_models.py`
  - **Dependencies:** None
  - **Estimated Scope:** Small (3 files)

---

## Phase 2: Core Adapter Implementation (TDD Cycle)

- [x] **Task 2: Unit Test Suite for OllamaDecisionAdapter (TDD RED)**
  - **Description:** Implement comprehensive unit tests mocking Ollama's HTTP endpoints (`/v1/systemone` and `/api/chat` fallback), verifying decision readout, error handling, and memory eviction.
  - **Acceptance Criteria:**
    - [x] Tests verify benign tool calls produce `verdict == "ALLOWED"`.
    - [x] Tests verify exploit risk >= 0.50 triggers `verdict == "BLOCKED"`.
    - [x] Tests verify misalignment risk >= 0.65 triggers `verdict == "BLOCKED"`.
    - [x] Tests verify connection errors return `verdict == "ERROR"` gracefully.
    - [x] Tests verify `unload()` issues `keep_alive: 0`.
    - [x] Tests fail cleanly prior to adapter implementation (RED).
  - **Verification:** `pytest tests/test_ollama_decision_adapter.py`
  - **Files:** `tests/test_ollama_decision_adapter.py`
  - **Dependencies:** Task 1
  - **Estimated Scope:** Small (1 file)

- [x] **Task 3: Implementation of OllamaDecisionAdapter (TDD GREEN)**
  - **Description:** Build `OllamaDecisionAdapter` inheriting from `BaseModelAdapter` with DEC-07 context isolation, Dual-Check question format, dual-endpoint handling, and `keep_alive: 0` VRAM eviction.
  - **Acceptance Criteria:**
    - [x] Class implements `evaluate(tool_name, tool_arguments, context) -> dict`.
    - [x] Calls `/v1/systemone` and correctly parses `misalignment` and `exploit` probabilities.
    - [x] Fallback to `/api/chat` (structured JSON) active if `/v1/systemone` returns 404.
    - [x] `unload()` sends `keep_alive: 0` to `/api/generate`.
    - [x] All unit tests in `test_ollama_decision_adapter.py` pass 100% (GREEN).
  - **Verification:** `pytest tests/test_ollama_decision_adapter.py -v`
  - **Files:** `adapters/ollama_decision_adapter.py`
  - **Dependencies:** Task 2
  - **Estimated Scope:** Medium (1 file)

---

## 🛑 Checkpoint 1: Core Adapter Verification
- [x] Unit tests pass: `pytest tests/test_ollama_decision_adapter.py`
- [x] Code conforms to `BaseModelAdapter` interface
- [x] Review progress before wiring into benchmark runners

---

## Phase 3: Benchmark Runners & Matrix Integration

- [x] **Task 4: Registry & Benchmark Runner Integration**
  - **Description:** Register `ollama-d1`, `ollama-pplx-decider`, and `ollama-mica` in `ADAPTER_REGISTRY` in `benchmark_runner.py` and expose `OllamaDecisionAdapter` in `adapters/__init__.py`.
  - **Acceptance Criteria:**
    - [x] `ADAPTER_REGISTRY` contains all three Ollama decision model entries.
    - [x] `benchmark_runner.py --model ollama-d1` recognizes the model adapter without import errors.
  - **Verification:** `python -c "from benchmark_runner import ADAPTER_REGISTRY; assert 'ollama-d1' in ADAPTER_REGISTRY"`
  - **Files:** `adapters/__init__.py`, `benchmark_runner.py`
  - **Dependencies:** Task 3
  - **Estimated Scope:** Small (2 files)

- [x] **Task 5: Benchmark Matrix & Leaderboard Integration**
  - **Description:** Wire Ollama decision models into `benchmark_matrix.py`, ensuring sequential runs invoke `unload()` and record model run summaries and case evaluations into DuckDB.
  - **Acceptance Criteria:**
    - [x] `benchmark_matrix.py` supports selecting or running Ollama models.
    - [x] Sequential evaluation flushes Ollama VRAM between runs via `adapter.unload()`.
    - [x] Results populate `data/benchmark_runs.duckdb` and appear in the Rich leaderboard table.
  - **Verification:** `python benchmark_matrix.py --help`
  - **Files:** `benchmark_matrix.py`
  - **Dependencies:** Task 4
  - **Estimated Scope:** Small (1 file)

- [x] **Task 6: Smoke Benchmark Execution & Verification**
  - **Description:** Execute a 200-case smoke benchmark test against `smoke_test_2k.parquet` using mock/live Ollama models, verifying end-to-end evaluation with zero fatal errors.
  - **Acceptance Criteria:**
    - [x] Smoke test completes with `eval_errors == 0` on live models or gracefully handles disconnected daemons without unhandled exceptions.
    - [x] Granular case predictions recorded in `run_case_evaluations` table.
    - [x] KPIs (Accuracy, Precision, Recall, F1, Latency) calculated and displayed.
  - **Verification:** `python benchmark_runner.py --dataset data/processed/smoke_test_2k.parquet --model ollama-d1 --limit 10`
  - **Files:** `data/benchmark_runs.duckdb`
  - **Dependencies:** Task 5
  - **Estimated Scope:** Small (verification & data validation)

---

## 🛑 Checkpoint 2: Final Verification & Production Readiness
- [x] Full unit test suite passes: `pytest tests/` (84 passed)
- [x] All three Ollama models successfully registered in `ADAPTER_REGISTRY`
- [x] DuckDB storage and discrepancy queries functioning
- [x] Ready for `/review` or human hand-off
