# ADR 0004: DuckDB Relational Evaluation Schema and Discrepancy Analysis

* **Date:** 2026-10-02
* **Status:** Accepted
* **Scope:** Faraday Guard / Benchmark Storage & Comparative Infrastructure

---

## 1. Context and Problem Statement
In large-scale benchmark runs exceeding 10,000+ test cases:
1. Persisting results within `run_history` as an unindexed JSON blob (`VARCHAR`) causes memory bloat, slow deserialization, and query inefficiency.
2. Transferring 10,000+ raw records to the browser for client-side diffing freezes the UI. Security researchers primarily require visibility into **discrepancies (cases where Model A and Model B reached opposite verdicts)** rather than the thousands of cases where they agreed.

---

## 2. Decision Log

### Decision 1: Normalized Relational Tables in DuckDB
* **Decision:** Adopt a two-table relational structure in DuckDB:
  - `run_history`: Stores overall aggregate run metrics (F1, Accuracy, Precision, Recall, FPR, p95 latency, duration).
  - `run_case_evaluations`: Stores individual test case evaluations (`run_id, case_id, domain, expected, predicted, correct, confidence, latency_ms`).
* **Rationale:** DuckDB's columnar compression compresses 10,000 evaluations to ~200 KB on disk while enabling high-throughput bulk insertions and index-assisted querying.

### Decision 2: SQL-Driven Discrepancy Analysis
* **Decision:** Perform cross-run comparisons server-side via SQL `JOIN` queries:
  - **Agreement Rate:** The percentage of cases where both models concurred.
  - **Discrepancies:** Isolates cases where Model A rendered `BLOCKED` while Model B rendered `ALLOWED` (or vice versa), returned via server-side pagination.

---

## 3. Consequences
* DuckDB database schema updated with primary keys and indexes over `run_case_evaluations`.
* Exposed `/api/runs/{run_id_a}/compare/{run_id_b}` REST endpoint executing SQL joins.
* Web dashboard "Compare Runs" tab provides instant, responsive differential analysis without browser lag.
