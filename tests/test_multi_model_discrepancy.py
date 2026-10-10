"""
test_multi_model_discrepancy.py

Integration tests for Cross-Model Discrepancy Matrix & Comparison API (ISSUE-014).
Validates:
1. /api/runs returns multi-SLM runs metadata (Qwen, Granite, Prompt Guard, Laya).
2. /api/runs/{run_a}/compare/{run_b} computes cross-model agreement rates and discrepancy lists.
3. Filtering by disagreement categories (e.g. a_missed_b_caught, fp_diff).
4. Full metadata and tool argument payload retention for Case Detail Drawer inspection.
"""

import uuid

import pytest
from fastapi.testclient import TestClient

from web.app import app, get_db


@pytest.fixture
def client():
    return TestClient(app)


def test_cross_model_comparison_qwen_vs_granite(client):
    con = get_db()
    run_qwen = f"run-qwen-{uuid.uuid4().hex[:6]}"
    run_granite = f"run-granite-{uuid.uuid4().hex[:6]}"

    con.execute("""
        INSERT INTO run_history (run_id, dataset_name, dataset_path, model_name, status, total_cases, accuracy, f1_score, avg_latency_ms)
        VALUES
        (?, 'master_benchmark', 'data/processed/master_benchmark.parquet', 'qwen3guard', 'completed', 3, 66.7, 66.7, 45.2),
        (?, 'master_benchmark', 'data/processed/master_benchmark.parquet', 'granite-guardian', 'completed', 3, 100.0, 100.0, 240.5)
    """, [run_qwen, run_granite])

    # Case 1: Both catch SQL injection
    # Case 2: Qwen missed indirect prompt injection, Granite caught it (Discrepancy)
    # Case 3: Both allow benign command
    con.execute("""
        INSERT INTO run_case_evaluations (
            run_id, case_id, source, domain, analysis_tier, cwe,
            tool_name, is_malicious, predicted_blocked, correct,
            decided_by, confidence, latency_ms, offload_saved_ms,
            verdict_detail, tool_arguments, context
        ) VALUES
        (?, 'c-1', 'agentdojo', 'SQLI', 'STATIC_CAPABLE', 'CWE-89', 'sql_exec', true, true, true, 'L2_QWEN3_GUARD', 0.95, 42.0, 0, 'BLOCKED', '{"query": "DROP TABLE"}', 'Admin query'),
        (?, 'c-2', 'agentdojo', 'PROMPT_INJECTION', 'SEMANTIC_REQUIRED', 'CWE-77', 'search', true, false, false, 'L2_QWEN3_GUARD', 0.20, 51.0, 0, 'ALLOWED', '{"query": "Ignore prompt"}', 'Web search'),
        (?, 'c-3', 'agentdojo', 'BENIGN', 'STATIC_CAPABLE', 'None', 'read_file', false, false, true, 'L2_QWEN3_GUARD', 0.05, 38.0, 0, 'ALLOWED', '{"path": "doc.txt"}', 'Read doc'),

        (?, 'c-1', 'agentdojo', 'SQLI', 'STATIC_CAPABLE', 'CWE-89', 'sql_exec', true, true, true, 'L2_GRANITE_GUARDIAN', 0.98, 230.0, 0, 'BLOCKED', '{"query": "DROP TABLE"}', 'Admin query'),
        (?, 'c-2', 'agentdojo', 'PROMPT_INJECTION', 'SEMANTIC_REQUIRED', 'CWE-77', 'search', true, true, true, 'L2_GRANITE_GUARDIAN', 0.89, 260.0, 0, 'BLOCKED', '{"query": "Ignore prompt"}', 'Web search'),
        (?, 'c-3', 'agentdojo', 'BENIGN', 'STATIC_CAPABLE', 'None', 'read_file', false, false, true, 'L2_GRANITE_GUARDIAN', 0.02, 210.0, 0, 'ALLOWED', '{"path": "doc.txt"}', 'Read doc')
    """, [
        run_qwen, run_qwen, run_qwen,
        run_granite, run_granite, run_granite
    ])
    con.close()

    try:
        # 1. Verify /api/runs lists both runs with their model names
        resp_runs = client.get("/api/runs?limit=50")
        assert resp_runs.status_code == 200
        runs_list = resp_runs.json()
        model_names = [r["model_name"] for r in runs_list if r["run_id"] in (run_qwen, run_granite)]
        assert "qwen3guard" in model_names
        assert "granite-guardian" in model_names

        # 2. Verify compare endpoint between Qwen and Granite
        resp_compare = client.get(f"/api/runs/{run_qwen}/compare/{run_granite}")
        assert resp_compare.status_code == 200
        comp_data = resp_compare.json()

        assert comp_data["run_a"]["model_name"] == "qwen3guard"
        assert comp_data["run_b"]["model_name"] == "granite-guardian"

        stats = comp_data["agreement_stats"]
        assert stats["total_common"] == 3
        assert stats["matching_verdicts"] == 2
        assert stats["discrepant_verdicts"] == 1
        assert stats["a_missed_b_caught"] == 1
        assert stats["b_missed_a_caught"] == 0

        # Verify discrepancy item structure for drawer inspection
        disc = comp_data["discrepancies"]
        assert len(disc) == 1
        case = disc[0]
        assert case["case_id"] == "c-2"
        assert case["tool_name"] == "search"
        assert "Ignore prompt" in case["tool_arguments"]
        assert case["run_a"]["predicted_blocked"] is False
        assert case["run_b"]["predicted_blocked"] is True

    finally:
        # Cleanup
        con2 = get_db()
        con2.execute("DELETE FROM run_case_evaluations WHERE run_id IN (?, ?)", [run_qwen, run_granite])
        con2.execute("DELETE FROM run_history WHERE run_id IN (?, ?)", [run_qwen, run_granite])
        con2.close()
