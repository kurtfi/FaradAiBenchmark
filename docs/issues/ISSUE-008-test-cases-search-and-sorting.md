# ISSUE-008: Test Cases Explorer — Substring ILIKE Search & Dynamic Sorting

## Parent
- **Specification:** [SPEC-0003: Unified Test Cases Dataset Explorer](../specs/test-cases-explorer-spec.md)
- **Architectural Decision:** [ADR 0006: Unified Benchmark Case Pool and Streaming Parquet Exploration](../adr/0006-unified-benchmark-case-pool-and-parquet-streaming.md)

## What to build
Build the parameterized substring `ILIKE` search engine to accurately match special cyber attack characters (`cat /etc/passwd`, `' OR 1=1`, `rm -rf`) across prompt context and tool arguments, and implement dynamic server-side column sorting with interactive table header toggles (`▲`/`▼`).

This vertical slice encompasses:
1. **Backend REST Search & Sorting (`web/app.py`):**
   - Parameterized `ILIKE` search condition: `(context ILIKE ? OR tool_arguments ILIKE ? OR id ILIKE ? OR cwe ILIKE ?)`.
   - `sort_by` and `sort_order` parameters: Enforce a strict column whitelist (`id`, `source_dataset`, `threat_domain`, `analysis_tier`, `is_malicious`, `tool_name`) and direction whitelist (`asc`, `desc`) to prevent SQL injection.
2. **Frontend Search & Sorting (`web/static/app.js`, `web/templates/index.html`):**
   - Search input box in the filter bar (`🔍 Search prompt, arguments, CWE...`).
   - 300ms debounce timer to prevent request thrashing while typing.
   - Clickable table column headers with ascending/descending indicators (`▲`/`▼`).
3. **Automated Tests (`tests/test_api_test_cases.py`):**
   - Tests verifying search with special characters (`passwd`, `' OR 1=1`, `CWE-78`).
   - Validation that invalid `sort_by` inputs safely fallback to `id ASC`.
   - Verification of ascending and descending order outputs.

## Acceptance criteria
- [x] Special character injection payloads (`cat /etc/passwd`, `' OR 1=1`) match and return expected cases via `search`.
- [x] Search input debounces network requests by 300ms.
- [x] Clicking table column headers toggles sort order (`▲`/`▼`) and triggers instant DuckDB re-sorting.
- [x] Supplying an unwhitelisted `sort_by` parameter safely falls back to `id ASC`.
- [x] All search and sorting tests pass in `pytest tests/test_api_test_cases.py`.

## Blocked by
- [ISSUE-006: Test Cases Explorer — Core Paginated Table & Filters](./ISSUE-006-test-cases-dataset-explorer.md)
