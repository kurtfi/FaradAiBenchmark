# ADR 0006: Unified Benchmark Case Pool and Streaming Parquet Exploration

* **Date:** 2026-10-03
* **Status:** Accepted
* **Scope:** Faraday Guard / Test Dataset Exploration & Query Architecture

---

## 1. Context & Problem Statement
1. **Fragmented Dataset Files:** During the data ingestion pipeline, open-source datasets (SecLists, BIPIA, AgentDojo, ToolEmu) were processed into separate category-specific Parquet files under `data/processed/` (`cwe_78_command.parquet`, `cwe_22_traversal.parquet`, `smoke_test_2k.parquet`, etc.). This causes confusion in the web dashboard: operators are forced to guess which file to pick, leading to fragmented queries and unnecessary UX friction.
2. **Data Scale & Client Memory:** The benchmark pool comprises 16,072+ test cases, complete with natural language prompts and JSON payloads. Loading this entire dataset into the browser or buffering it in server RAM causes high latency, excessive memory overhead, and browser tab freezes.
3. **Security Attack Payload Search:** Natural language Full-Text Search (FTS) tokenizers strip, normalize, or mangle code characters (`'`, `"`, `;`, `/`, `--`, `$((...))`). Cyber threat analysts require exact substring matching on attack payloads (`tool_arguments`) and user prompts (`context`).

---

## 2. Decision Log

### Decision 1: Single Unified Benchmark Case Pool
* **Decision:** Remove dataset file selectors from the user interface. All test scenario exploration will query a single consolidated canonical pool: [`master_benchmark.parquet`](file:///Users/firatkurt/Documents/Repos/faraday-laya-guard/data/processed/master_benchmark.parquet).
* **Rationale:** `master_benchmark.parquet` already merges all 16,072 test cases with normalized column metadata (`source_dataset`, `threat_domain`, `analysis_tier`, `is_malicious`, `cwe`, `owasp_llm`, `tool_name`). Filtering by dataset, threat category, or tier is handled cleanly via SQL `WHERE` clauses rather than juggling multiple physical files.

### Decision 2: Zero-Copy Streaming Pagination via DuckDB
* **Decision:** Do not pre-load the dataset into RAM or build in-memory cache tables. Instead, execute parameterized DuckDB streaming queries directly over disk-resident Parquet blocks using `LIMIT ? OFFSET ?`. Expose configurable page sizes (20, 50, 100).
* **Rationale:** DuckDB's columnar projection and Snappy block decompression only read requested columns and row slices. Page response latency remains strictly <30ms with near-zero RAM footprint.

### Decision 3: Parameterized Substring ILIKE Search
* **Decision:** Execute free-text searches via parameterized `ILIKE` across `context`, `tool_arguments`, `id`, and `cwe`:  
  `WHERE (context ILIKE ? OR tool_arguments ILIKE ? OR id ILIKE ? OR cwe ILIKE ?)`
* **Rationale:** Substring matching preserves special characters, punctuation, and injection syntax without tokenization errors. Binding inputs as SQL query parameters (`?`) completely eliminates SQL injection risks.

### Decision 4: URL Hash Deep-Linking
* **Decision:** Synchronize active tab, pagination, filters, and opened case details with the browser URL hash (`#test-cases?id=...`).
* **Rationale:** Enables security researchers and benchmark operators to bookmark, reload, and share direct links to specific threat payloads and test cases (essential for issue triage and collaboration).

---

## 3. Consequences
* Added the canonical term `Benchmark Case Pool` to the ubiquitous language in [CONTEXT.md](file:///Users/firatkurt/Documents/Repos/faraday-laya-guard/CONTEXT.md#L24).
* Exposed two dedicated REST endpoints in `web/app.py`: `GET /api/test-cases/filters` and `GET /api/test-cases`.
* Introduced the `🔍 Test Cases` tab in the web dashboard, integrated with the existing slide-in `.case-detail-drawer`.
