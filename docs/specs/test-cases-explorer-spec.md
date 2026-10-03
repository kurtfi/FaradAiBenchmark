# Engineering Specification: Test Cases Dataset Explorer

* **Spec ID:** SPEC-0003
* **Title:** Unified Test Cases Dataset Explorer
* **Status:** Ready for Implementation
* **Author:** Faraday Laya Guard Core Team
* **Created:** 2026-10-03
* **Related ADR:** [ADR 0006: Unified Benchmark Case Pool and Streaming Parquet Exploration](../adr/0006-unified-benchmark-case-pool-and-parquet-streaming.md)
* **Parent Issues:** [ISSUE-006](../issues/ISSUE-006-test-cases-dataset-explorer.md), [ISSUE-007](../issues/ISSUE-007-test-cases-drawer-and-deep-linking.md), [ISSUE-008](../issues/ISSUE-008-test-cases-search-and-sorting.md)

---

## 1. Executive Summary & Goals

### 1.1 Problem Statement
The Faraday Laya Guard security benchmark platform hosts 16,072 normalized test cases designed to evaluate hybrid security guards across LLM and Model Context Protocol (MCP) tool calls. However, these test cases currently reside in static Parquet files on disk. Security researchers and operators cannot inspect prompts, tool arguments, source datasets, or threat classifications directly from the Web Dashboard prior to launching a benchmark run.

Furthermore, fragmented sub-dataset files in `data/processed/` create confusion regarding which dataset to inspect or run.

### 1.2 Goals
1. **Independent Pre-Run Inspection:** Allow operators to explore all test scenarios, raw prompt contexts, JSON tool arguments, CWE IDs, and OWASP categories directly from the web interface, independent of benchmark runs.
2. **Unified Canonical Pool:** Eliminate fragmented file pickers by querying a single canonical dataset ([`master_benchmark.parquet`](file:///Users/firatkurt/Documents/Repos/faraday-laya-guard/data/processed/master_benchmark.parquet)) with multi-dimensional filtering.
3. **Zero-Copy Streaming Pagination:** Stream row slices directly from disk using DuckDB `LIMIT / OFFSET` pagination (page sizes: 20, 50, 100), avoiding bulk in-memory buffering.
4. **Exact Substring Payload Search:** Fast, sub-50ms case-insensitive substring search (`ILIKE`) that preserves special attack characters (`' OR 1=1`, `../../etc/passwd`).
5. **Shareability via Deep-Linking:** Synchronize active tab, pagination, filters, and selected case details with the browser URL hash for immediate bookmarking and triage sharing.

### 1.3 Non-Goals
- Editing, adding, or deleting test cases from the UI (the explorer is strictly read-only).
- Displaying post-run evaluation verdicts (`run_case_evaluations`) in this view (already supported in `Compare Runs` and `Dashboard`).
- Provisioning external databases (PostgreSQL, Elasticsearch); DuckDB serves as the embedded analytical query engine.
- Exporting filtered data to CSV/JSONL (deferred to future iterations per YAGNI).

---

## 2. System Architecture & Components

```
┌────────────────────────────────────────────────────────────────────────┐
│                        WEB FRONTEND (SPA)                              │
│                                                                        │
│   Header Nav ──► [ Dashboard ]  [ ⚖️ Compare ]  [ 🔍 Test Cases ]       │
│                                                         │              │
│   ┌─────────────────────────────────────────────────────▼──────────┐   │
│   │ #page-test-cases                                               │   │
│   │  ├── Filter Bar (Dataset, Threat, Tier, Status, Search, Limit) │   │
│   │  ├── Test Cases Table (Paginated, Clickable Rows, Sortable)   │   │
│   │  ├── Pagination Bar (« ‹ Page 1 / 322 › »)                     │   │
│   │  └── Case Detail Drawer (JSON Tool Args + Prompt Context)      │   │
│   └────────────────────────────────────────────────────────────────┘   │
└────────────────────────────────────┬───────────────────────────────────┘
                                     │ HTTP REST (JSON)
                                     │ - GET /api/test-cases/filters
                                     │ - GET /api/test-cases?page=1&limit=50...
┌────────────────────────────────────▼───────────────────────────────────┐
│                    FASTAPI BACKEND (web/app.py)                        │
│                                                                        │
│  - Column Whitelist Sorting Validation                                 │
│  - Parameterized SQL Query Builder                                     │
│  - Dynamic Filter & ILIKE Substring Assembler                          │
└────────────────────────────────────┬───────────────────────────────────┘
                                     │ Zero-Copy DuckDB Engine
                                     │ con.execute("SELECT ... FROM '...parquet' ...")
┌────────────────────────────────────▼───────────────────────────────────┐
│              UNIFIED STORAGE LAYER (Benchmark Case Pool)               │
│                                                                        │
│             data/processed/master_benchmark.parquet                    │
│             (16,072 Cases | Snappy Compressed Columnar)                │
└────────────────────────────────────────────────────────────────────────┘
```

### 2.1 Core Components
1. **DuckDB Query Engine (`web/app.py`):**
   - Directly queries `master_benchmark.parquet` from an in-memory SQL connection.
   - Executes two lightweight queries per request: filtered total record count (`COUNT(*)`) and the paginated row slice (`LIMIT ? OFFSET ?`).
2. **Filter & Search Engine:**
   - `GET /api/test-cases/filters`: Computes distinct dropdown options and case counts.
   - Parameterized `ILIKE` matcher across `context`, `tool_arguments`, `id`, and `cwe`.
3. **Frontend Application Module (`web/templates/index.html` & `web/static/app.js`):**
   - `🔍 Test Cases` navigation tab.
   - Reactive filter bar with 300ms search input debounce.
   - Reused `.case-detail-drawer` component for inspecting JSON payloads and conversation context.
   - Bidirectional URL hash state synchronization.

---

## 3. Architectural Decision Records (ADRs) Index

| ADR ID | Title | Status | Impact on Feature |
|---|---|---|---|
| **[ADR 0001](../adr/0001-benchmark-dataset-pipeline-and-storage.md)** | Parquet/DuckDB Pipeline Architecture | Accepted | Parquet columnar storage standard & DuckDB zero-copy query engine. |
| **[ADR 0002](../adr/0002-analysis-tier-classification.md)** | Analysis Tier Classification | Accepted | Schema support for `STATIC_CAPABLE`, `SEMANTIC_REQUIRED`, and `HYBRID`. |
| **[ADR 0004](../adr/0004-relational-evaluation-storage-and-discrepancy-analysis.md)** | Relational Evaluation Storage | Accepted | Decoupling benchmark evaluation runs from the raw benchmark case pool. |
| **[ADR 0006](../adr/0006-unified-benchmark-case-pool-and-parquet-streaming.md)** | Unified Benchmark Case Pool | Accepted | Single pool (`master_benchmark`), streaming pagination, ILIKE search, deep-linking. |

---

## 4. Data Models & API Contracts

### 4.1 Domain Entity: Benchmark Case
Canonical schema of records within the `Benchmark Case Pool` ([CONTEXT.md](file:///Users/firatkurt/Documents/Repos/faraday-laya-guard/CONTEXT.md#L24)):

| Field Name | Type | Description | Example |
|---|---|---|---|
| `id` | `VARCHAR` | Unique test case identifier | `"seclists-cmd-000042"` |
| `source_dataset` | `VARCHAR` | Origin open-source dataset | `"SecLists"`, `"AgentDojo_travel"`, `"BIPIA_Table"` |
| `threat_domain` | `VARCHAR` | Security taxonomy attack vector | `"COMMAND_INJECTION"`, `"SQLI"`, `"BENIGN"` |
| `analysis_tier` | `VARCHAR` | Required computational tier | `"STATIC_CAPABLE"`, `"SEMANTIC_REQUIRED"` |
| `is_malicious` | `BOOLEAN` | Ground truth safety label | `true` (Threat) / `false` (Benign) |
| `cwe` | `VARCHAR` | Common Weakness Enumeration ID | `"CWE-78"`, `"CWE-89"`, `""` |
| `owasp_llm` | `VARCHAR` | OWASP Top 10 for LLM Applications | `"LLM02:InsecureOutputHandling"` |
| `traffic_direction` | `VARCHAR` | MCP traffic flow direction | `"tools/call"` |
| `tool_name` | `VARCHAR` | Target tool / function name | `"execute_bash"`, `"read_filesystem"` |
| `tool_arguments` | `VARCHAR` | JSON string of tool arguments | `{"command": "cat /etc/passwd"}` |
| `context` | `VARCHAR` | Prompt context or conversational history | `"CI/CD deployment script runner"` |

---

### 4.2 REST API Endpoints

#### 1. Filter Options Endpoint
- **Method / Path:** `GET /api/test-cases/filters`
- **Description:** Returns available datasets, threat domains, tiers, and case counts to populate filter dropdowns.
- **Status:** `200 OK`
- **Response JSON:**
  ```json
  {
    "total_pool_cases": 16072,
    "datasets": [
      { "name": "AgentDojo_travel", "count": 1250 },
      { "name": "SecLists", "count": 8332 }
    ],
    "threat_domains": [
      { "name": "COMMAND_INJECTION", "count": 8332 },
      { "name": "BENIGN", "count": 1791 },
      { "name": "SQLI", "count": 245 }
    ],
    "analysis_tiers": [
      { "name": "STATIC_CAPABLE", "count": 11144 },
      { "name": "SEMANTIC_REQUIRED", "count": 4921 },
      { "name": "HYBRID", "count": 7 }
    ]
  }
  ```

#### 2. Paginated Test Cases Query Endpoint
- **Method / Path:** `GET /api/test-cases`
- **Query Parameters:**
  - `page` (int, default: `1`): 1-indexed page number.
  - `limit` (int, default: `50`, allowed: `20`, `50`, `100`): Records per page.
  - `dataset` (string, optional): Filter by `source_dataset`.
  - `threat_domain` (string, optional): Filter by `threat_domain`.
  - `tier` (string, optional): Filter by `analysis_tier`.
  - `status` (string, optional): Filter by safety (`all`, `safe`, `malicious`).
  - `search` (string, optional): Free-text substring query across context, arguments, id, cwe.
  - `sort_by` (string, default: `"id"`, allowed: `id`, `source_dataset`, `threat_domain`, `analysis_tier`, `is_malicious`, `tool_name`).
  - `sort_order` (string, default: `"asc"`, allowed: `asc`, `desc`).
- **Status:** `200 OK`
- **Response JSON:**
  ```json
  {
    "cases": [
      {
        "id": "seclists-cmd-000000",
        "source_dataset": "SecLists",
        "threat_domain": "COMMAND_INJECTION",
        "analysis_tier": "STATIC_CAPABLE",
        "is_malicious": true,
        "cwe": "CWE-78",
        "owasp_llm": "LLM02:InsecureOutputHandling",
        "tool_name": "execute_bash",
        "tool_arguments": "{\"command\": \"cat /etc/passwd\"}",
        "context": "CI/CD Deployment & Remote Shell"
      }
    ],
    "pagination": {
      "page": 1,
      "limit": 50,
      "total_records": 16072,
      "total_pages": 322,
      "has_next": true,
      "has_prev": false
    }
  }
  ```

---

## 5. User Experience & Frontend Workflows

### 5.1 UI Layout
1. **Header Navigation:** New tab button: `<button class="nav-btn" data-page="test-cases">🔍 Test Cases</button>`.
2. **Filter Control Bar:**
   - Source Dataset Dropdown (`All`, `SecLists`, `AgentDojo`, etc. with case counts).
   - Threat Domain Dropdown (`All`, `COMMAND_INJECTION`, `SQLI`, etc.).
   - Analysis Tier Selector (`All`, `⚡ Static`, `🧠 Semantic`, `🔀 Hybrid`).
   - Safety Status Dropdown (`All`, `🛡️ Safe (Benign)`, `🚨 Malicious (Threat)`).
   - Search Input Box (`🔍 Search prompt, arguments, CWE...`, 300ms debounce).
   - Page Size Selector (`20`, `50`, `100`).
   - Reset Filters Button (`✕ Clear Filters`).
3. **Table View:**
   - Headers with dynamic sorting arrows (`ID ⇅`, `Dataset ⇅`, `Threat Domain ⇅`, `Tier ⇅`, `Status ⇅`, `Tool`).
   - Hover row highlighting with pointer cursor.
   - Status Badges: Red `🚨 Threat` for malicious cases, Green `🛡️ Safe` for benign cases.
4. **Pagination Bar (Footer):**
   - Status label: `Showing 1 - 50 of 16,072 cases`.
   - Controls: `« First`, `‹ Prev`, `Page [ 1 ] / 322`, `Next ›`, `Last »`.
5. **Case Detail Drawer (Slide-Over Panel):**
   - Triggered upon clicking any row in the table (`.case-detail-drawer.open`).
   - Meta Badges: Case ID, Safety Status, CWE, OWASP LLM, Analysis Tier, Tool Name.
   - Tool Arguments Card: Pretty-printed formatted JSON with a "📋 Copy" button.
   - Context / Prompt Card: Complete conversation and prompt text.

### 5.2 Deep-Linking Workflow
- Any filter or pagination change updates the browser URL hash:
  `#test-cases?page=2&domain=COMMAND_INJECTION&search=passwd`
- Opening a detail drawer sets the ID in the hash:
  `#test-cases?id=seclists-cmd-000042`
- Reloading the page or following a shared URL automatically switches to the `Test Cases` tab, applies the query filters, and opens the specified drawer item.

---

## 6. Security, Privacy & Non-Functional Requirements

### 6.1 Security
- **SQL Injection Prevention:** All filter inputs and search queries are strictly passed as parameterized variables (`?`) to DuckDB. Raw string concatenation is prohibited.
- **Whitelist Column Sorting:** `sort_by` parameters are validated against a strict column whitelist; invalid inputs silently fallback to `id`.
- **Read-Only Access:** The DuckDB connection operates in read-only mode (`read_only=True`) to prevent accidental dataset modifications.

### 6.2 Performance & Scale
- **Zero-Copy Streaming:** `master_benchmark.parquet` is read directly from disk without loading all 16,072 rows into RAM.
- **Latency Target:** Query and pagination response latency remains **<30ms**.
- **Search Debounce:** Client-side input emits HTTP requests only after a 300ms pause in user typing.

### 6.3 Resilience & Edge Cases
- **Empty State:** When filters match zero cases, display a styled notification card with a "Clear Filters" action.
- **Malformed Payloads:** If `tool_arguments` cannot be parsed as valid JSON, render as plain text without throwing JavaScript exceptions.
- **Missing Dataset:** If `master_benchmark.parquet` is missing from disk, return a structured 404 JSON error and render a toast notification in the UI.

---

## 7. Acceptance Criteria

- [ ] `GET /api/test-cases/filters` correctly returns all dataset categories and total count (16,072).
- [ ] `GET /api/test-cases` executes pagination, filtering, substring search, and column sorting in <50ms.
- [ ] Substring `ILIKE` search accurately matches special characters (`cat /etc/passwd`, `' OR 1=1`).
- [ ] `🔍 Test Cases` tab appears in the top navigation and dynamically loads filters on view.
- [ ] Table supports 20/50/100 pagination sizes, page stepping, and column header sorting.
- [ ] Clicking any table row opens `.case-detail-drawer` displaying formatted JSON arguments and prompt context with working clipboard copy.
- [ ] URL hash deep-linking preserves page, filters, and drawer state across refreshes and direct URL visits.
- [ ] Full automated test suite passes via `pytest tests/test_api_test_cases.py`.
