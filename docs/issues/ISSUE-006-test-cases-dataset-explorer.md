# ISSUE-006: Test Cases Explorer — Core Paginated Table & Filters

## Parent
- **Specification:** [SPEC-0003: Unified Test Cases Dataset Explorer](../specs/test-cases-explorer-spec.md)
- **Architectural Decision:** [ADR 0006: Unified Benchmark Case Pool and Streaming Parquet Exploration](../adr/0006-unified-benchmark-case-pool-and-parquet-streaming.md)

## What to build
Build the foundational end-to-end vertical slice for exploring the 16,072 standardized benchmark test scenarios in [`data/processed/master_benchmark.parquet`](../../data/processed/master_benchmark.parquet), completely independent of benchmark evaluation runs.

This vertical slice encompasses:
1. **Backend REST API (`web/app.py`):**
   - `GET /api/test-cases/filters`: Returns distinct `source_dataset`, `threat_domain`, and `analysis_tier` categories with their case counts from `master_benchmark.parquet`.
   - `GET /api/test-cases`: Supports `page` (default 1), `limit` (20, 50, 100), `dataset`, `threat_domain`, `tier`, and `status` (`all`, `safe`, `malicious`) to query `master_benchmark.parquet` directly via DuckDB with `LIMIT / OFFSET` zero-copy streaming.
2. **Web Interface (`web/templates/index.html`, `web/static/app.js`):**
   - Header navigation button: **`🔍 Test Cases`**.
   - Filter Control Bar: Dropdowns for Source Dataset, Threat Domain, Analysis Tier, and Safety Status, along with a Page Size selector.
   - Summary Table: Columns for `ID`, `Dataset`, `Threat Domain`, `Tier`, `Status` badge, and `Tool Name`.
   - Pagination Bar: Navigation buttons (`First`, `Previous`, `Page N of Total`, `Next`, `Last`) and case count summary (`1 - 50 of 16,072`).
3. **Automated Tests (`tests/test_api_test_cases.py`):**
   - Unit and integration tests verifying query filters, edge-case pagination boundaries, and empty-state responses.

## Acceptance criteria
- [x] `GET /api/test-cases/filters` accurately returns all distinct metadata categories and total count (16,072).
- [x] `GET /api/test-cases` executes dynamic SQL filtering and `LIMIT/OFFSET` in <50ms with zero RAM bloat.
- [x] Clicking the `🔍 Test Cases` tab switches to the explorer view and dynamically populates filter dropdowns.
- [x] Pagination controls (20/50/100 per page) successfully fetch and render subsequent page slices.
- [x] Changing any filter combination resets page to 1 and re-queries the dataset pool.
- [x] When no cases match filter criteria, a clean empty-state card is rendered.
- [x] All test cases pass via `pytest tests/test_api_test_cases.py`.

## Blocked by
- None (Completed)
