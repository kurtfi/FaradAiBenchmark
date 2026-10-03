# ISSUE-014: Web Dashboard Multi-Run Discrepancy Matrix & Cross-Model Comparison

## Parent
- **Specification:** [SPEC-0004: Multi-SLM L2 Adapters, FastMCP Factory, and Comparative Benchmark Architecture](../specs/multi-slm-evaluation-and-mcp-guard-spec.md)
- **Architectural Decision:** [ADR 0007: Multi-SLM L2 Adapters and Comparative Benchmark Architecture](../adr/0007-multi-slm-l2-adapter-and-benchmark-architecture.md)

## What to build
Extend the Web Dashboard (`web/app.py` and `web/static/app.js`) to support selecting and comparing any two runs (e.g. `Laya MLX` vs `Qwen2.5-Coder` vs `IBM Granite Guardian`) from the historical runs dropdown, rendering comparative macro metrics and a granular discrepancy table isolating disagreement cases.

This vertical slice includes:
1. **Backend Discrepancy API (`web/app.py`):**
   - Ensure `/api/runs` returns model name and dataset metadata for all multi-SLM runs.
   - Verify `/api/discrepancies?run_a=<id>&run_b=<id>` executes fast SQL joins between two arbitrary run IDs in DuckDB.
2. **Web Frontend Comparison UI (`web/static/app.js`, `web/static/index.css`):**
   - Update the "Compare Runs" tab to list all SLM runs in both Run A and Run B selectors.
   - Display side-by-side metric comparison cards (Accuracy diff, Recall diff, Latency diff).
   - Display interactive discrepancy table with filter by CWE and Threat Domain.
   - Clicking a discrepancy row opens the Case Detail Drawer to inspect the specific payload where models disagreed.

## Status: DONE ✅

## Acceptance criteria
- [x] Any completed SLM run appears in the Compare Runs dropdowns.
- [x] Selecting Run A (e.g. Laya) and Run B (e.g. Qwen-Coder) renders side-by-side metric deltas.
- [x] Discrepancy table displays only cases where `run_a.predicted_blocked != run_b.predicted_blocked`.
- [x] Clicking a discrepancy case opens the Case Detail Drawer displaying full arguments and context.
- [x] Integration tests verify the `/api/discrepancies` endpoint with multi-model runs.

## Blocked by
- [ISSUE-013: Two-Phased Comparative Benchmark Runner & CLI Leaderboard Matrix](./ISSUE-013-two-phased-comparative-benchmark-runner-and-leaderboard.md)
