# Task Checklist: Declarative Experiment Matrix & Dual-Track Ollama Serving Studio (Phase 7)

* **Governing Specification:** [SPEC.md](../SPEC.md)
* **Implementation Plan:** [plan.md](plan.md)
* **Related ADR:** [ADR 0010: Code-First Adapters, DuckDB-Native Test Matrix, and Dual-Track Serving Architecture](../docs/adr/0010-code-first-adapters-duckdb-matrix-and-dual-track-serving.md)
* **Status:** Ready to Implement

---

## Phase 1: DuckDB Experiment Registry & Seed Template

- [x] **Task 1: DuckDB Experiment Registry Schema & Seed Template (Scenario A)**
  - **Description:** Implement `experiment_templates` table in `data/benchmark_runs.duckdb` with migration logic, CRUD helper functions, and pre-populate the `exp_smoke_dual_track` seed template (Laya MLX, Liquid d1, Llama Guard 3 on 200 balanced smoke cases).
  - **Acceptance Criteria:**
    - [x] `experiment_templates` table schema created in `benchmark_matrix.py` and `web/app.py`.
    - [x] `ALTER TABLE run_history ADD COLUMN IF NOT EXISTS experiment_id VARCHAR;` and `runtime_tier VARCHAR;` executed safely.
    - [x] Seed template `exp_smoke_dual_track` automatically inserted if not present.
    - [x] Helper module `adapters/experiment_registry.py` provides `get_template()`, `list_templates()`, and `save_template()`.
    - [x] Unit test `tests/test_experiment_registry.py` verifies CRUD and validation.
  - **Verification:** `pytest tests/test_experiment_registry.py -v`
  - **Files:** `adapters/experiment_registry.py`, `tests/test_experiment_registry.py`, `benchmark_matrix.py`, `web/app.py`
  - **Dependencies:** None
  - **Estimated Scope:** Medium (4 files)

---

## Phase 2: Generative Ollama Guard Adapter (TDD Cycle)

- [x] **Task 2: Unit Test Suite for OllamaGuardAdapter (TDD RED)**
  - **Description:** Write unit tests mocking Ollama `/api/chat` for generative guard models (`llama-guard3:1b` and `granite3-guardian:2b`), testing discrete verdict parsing, MLCommons S-code to CWE mapping, and `keep_alive: 0` eviction.
  - **Acceptance Criteria:**
    - [x] Tests verify `"safe"` ➔ `verdict == "ALLOWED"`, `confidence == 0.0`.
    - [x] Tests verify `"unsafe\nS13"` ➔ `verdict == "BLOCKED"`, `confidence == 1.0`, `cwe == "CWE-78"`.
    - [x] Tests verify Granite `"Yes"` ➔ `verdict == "BLOCKED"`, `"No"` ➔ `verdict == "ALLOWED"`.
    - [x] Tests verify timeout/error handling returns `verdict == "ERROR"`.
    - [x] Tests verify `unload()` sends `keep_alive: 0`.
    - [x] Tests fail cleanly prior to adapter implementation (RED).
  - **Verification:** `pytest tests/test_ollama_guard_adapter.py`
  - **Files:** `tests/test_ollama_guard_adapter.py`
  - **Dependencies:** Task 1
  - **Estimated Scope:** Small (1 file)

- [x] **Task 3: Implementation of OllamaGuardAdapter (TDD GREEN)**
  - **Description:** Implement `OllamaGuardAdapter` in `adapters/ollama_guard_adapter.py` inheriting from `BaseModelAdapter`, executing model-specific prompt templates, discrete parsing, and VRAM eviction.
  - **Acceptance Criteria:**
    - [x] Class implements `evaluate(tool_name, tool_arguments, context) -> dict`.
    - [x] Supports both `llama-guard3:1b` (with MLCommons S1-S13 parsing) and `granite3-guardian:2b`.
    - [x] Implements DEC-07 Context Isolation.
    - [x] `unload()` sends `POST /api/generate {"model": ..., "keep_alive": 0}`.
    - [x] All unit tests in `tests/test_ollama_guard_adapter.py` pass 100% (GREEN).
  - **Verification:** `pytest tests/test_ollama_guard_adapter.py -v`
  - **Files:** `adapters/ollama_guard_adapter.py`, `adapters/__init__.py`
  - **Dependencies:** Task 2
  - **Estimated Scope:** Medium (2 files)

---

## 🛑 Checkpoint 1: Core Adapters & Registry Verification
- [x] `pytest tests/test_experiment_registry.py tests/test_ollama_guard_adapter.py` passing
- [x] Existing 84 tests in `tests/` remain passing with zero regressions (99 total passing)
- [x] Review before benchmark matrix integration

---

## Phase 3: Matrix Runner & Dual-Track Leaderboard

- [x] **Task 4: Registry Integration & Dual-Track Matrix Runner**
  - **Description:** Update `benchmark_runner.py` to register `ollama-llama-guard3` and `ollama-granite-guardian`. Update `benchmark_matrix.py` to support `--experiment-id`, sequential run execution from template specs, and printing `[MLX-Native]` vs `[Ollama-Daemon]` badges in Rich Leaderboard.
  - **Acceptance Criteria:**
    - [x] `ADAPTER_REGISTRY` in `benchmark_runner.py` registers new Ollama guard models.
    - [x] `benchmark_matrix.py --experiment-id exp_smoke_dual_track` loads template from DuckDB and runs matrix sequentially.
    - [x] Every run records `runtime_tier` in `run_history`.
    - [x] Rich Leaderboard displays runtime tier badges (`[MLX-Native]`, `[Ollama-Daemon]`, `[MPS]`).
  - **Verification:** `python benchmark_matrix.py --help` and verify dry-run capability.
  - **Files:** `benchmark_runner.py`, `benchmark_matrix.py`
  - **Dependencies:** Task 3
  - **Estimated Scope:** Medium (2 files)

---

## Phase 4: Web Studio API & UI

- [x] **Task 5: Web Studio API Endpoints & Template Runner**
  - **Description:** Add FastAPI REST endpoints (`/api/experiments`, `/api/experiments/{id}`, `/api/experiments/{id}/run`) in `web/app.py` and Pydantic schemas in `web/schemas.py`.
  - **Acceptance Criteria:**
    - [x] `GET /api/experiments` returns list of stored experiment templates.
    - [x] `POST /api/experiments` creates/updates template in DuckDB.
    - [x] `GET /api/experiments/{id}` returns single template or 404.
    - [x] `DELETE /api/experiments/{id}` deletes template or returns 404.
    - [x] `POST /api/experiments/{id}/run` initiates background matrix execution and pushes WebSocket updates.
  - **Verification:** `pytest tests/test_experiment_api.py -v` (6/6 passed)
  - **Files:** `web/app.py`, `web/schemas.py`, `tests/test_experiment_api.py`
  - **Dependencies:** Task 4
  - **Estimated Scope:** Medium (3 files)

- [x] **Task 6: Web Dashboard Matrix Studio UI Tab**
  - **Description:** Add "Matrix Studio" section to Web Dashboard (`web/templates/index.html` and static JS) allowing researchers to select templates, view model matrix breakdown, and trigger runs.
  - **Acceptance Criteria:**
    - [x] "Matrix Studio" navigation tab present in dashboard.
    - [x] Shows template selector with `exp_smoke_dual_track` pre-selected.
    - [x] "Run Experiment" button starts the run with real-time progress indicators.
    - [x] Modal for creating custom templates with model selection, tier selection, and cascade toggle.
  - **Verification:** Browser/HTML inspection and pytest test_dashboard_renders_matrix_studio.
  - **Files:** `web/templates/index.html`, `web/static/app.js`
  - **Dependencies:** Task 5
  - **Estimated Scope:** Medium (2 files)

- [x] **Task 7: CLI Export/Import Utility**
  - **Description:** Create `scripts/manage_experiments.py` for exporting DuckDB experiment templates to YAML and importing YAML definitions into DuckDB.
  - **Acceptance Criteria:**
    - [x] `--export <id> --out <file.yaml>` exports template to clean YAML.
    - [x] `--import <file.yaml>` validates and upserts template into DuckDB.
    - [x] `--list` prints formatted table of registered templates.
    - [x] Unit tests in `tests/test_manage_experiments.py` pass 100%.
  - **Verification:** `python scripts/manage_experiments.py --list` and `pytest tests/test_manage_experiments.py -v`
  - **Files:** `scripts/manage_experiments.py`, `tests/test_manage_experiments.py`
  - **Dependencies:** Task 1
  - **Estimated Scope:** Small (2 files)

---

## 🛑 Checkpoint 2: End-to-End Verification & Production Readiness
- [x] Run full test suite: `pytest tests/` (109 passing tests, 0 failures across 19 modules)
- [x] Execute matrix run with declarative template verifying DuckDB storage
- [x] Verify `runtime_tier` and `experiment_id` columns in `run_history`
- [x] Web Studio endpoints and Matrix Studio UI tab verified with tests
- [x] CLI Export/Import utility verified with tests and live run
- [x] Ready for final review and sign-off
