import uuid
import pytest
import pyarrow as pa
from fastapi.testclient import TestClient

from web.app import app, get_db


@pytest.fixture
def client():
    return TestClient(app)


def test_api_compare_runs(client):
    con = get_db()
    run_a = f"run-a-{uuid.uuid4().hex[:6]}"
    run_b = f"run-b-{uuid.uuid4().hex[:6]}"

    # Insert run A and run B in run_history
    con.execute("""
        INSERT INTO run_history (run_id, dataset_name, dataset_path, model_name, status, total_cases, accuracy, f1_score, avg_latency_ms)
        VALUES
        (?, 'Smoke Dataset', 'data/smoke.parquet', 'L1 Static Rules', 'completed', 4, 75.0, 70.0, 0.15),
        (?, 'Smoke Dataset', 'data/smoke.parquet', 'Hybrid Guard', 'completed', 4, 100.0, 100.0, 14.50)
    """, [run_a, run_b])

    # Case 1: Both block malicious (matching)
    # Case 2: A missed, B caught (A=False, B=True, malicious=True) -> discrepancy
    # Case 3: Both allow benign (matching)
    # Case 4: A allowed benign, B blocked benign (False Positive discrepancy)
    eval_a = {
        "run_id": [run_a] * 4,
        "case_id": ["case-1", "case-2", "case-3", "case-4"],
        "source": ["test"] * 4,
        "domain": ["COMMAND_INJECTION", "PROMPT_INJECTION", "BENIGN", "BENIGN"],
        "analysis_tier": ["STATIC_CAPABLE", "SEMANTIC_REQUIRED", "STATIC_CAPABLE", "SEMANTIC_REQUIRED"],
        "cwe": ["CWE-78", "CWE-1426", "None", "None"],
        "tool_name": ["bash", "browse", "read", "read"],
        "is_malicious": [True, True, False, False],
        "predicted_blocked": [True, False, False, False],
        "correct": [True, False, True, True],
        "decided_by": ["L1", "L1", "L1", "L1"],
        "confidence": [0.99, 0.1, 0.05, 0.05],
        "latency_ms": [0.12, 0.14, 0.11, 0.13],
        "offload_saved_ms": [17.0, 0.0, 0.0, 0.0],
        "verdict_detail": ["BLOCKED", "ALLOWED", "ALLOWED", "ALLOWED"],
        "tool_arguments": ["{}", "{}", "{}", "{}"],
        "context": ["", "", "", ""]
    }
    eval_b = {
        "run_id": [run_b] * 4,
        "case_id": ["case-1", "case-2", "case-3", "case-4"],
        "source": ["test"] * 4,
        "domain": ["COMMAND_INJECTION", "PROMPT_INJECTION", "BENIGN", "BENIGN"],
        "analysis_tier": ["STATIC_CAPABLE", "SEMANTIC_REQUIRED", "STATIC_CAPABLE", "SEMANTIC_REQUIRED"],
        "cwe": ["CWE-78", "CWE-1426", "None", "None"],
        "tool_name": ["bash", "browse", "read", "read"],
        "is_malicious": [True, True, False, False],
        "predicted_blocked": [True, True, False, True],  # Case 2: caught attack, Case 4: FP
        "correct": [True, True, True, False],
        "decided_by": ["L1", "L2", "L2", "L2"],
        "confidence": [0.99, 0.92, 0.08, 0.85],
        "latency_ms": [0.12, 17.5, 16.2, 15.8],
        "offload_saved_ms": [17.0, 0.0, 0.0, 0.0],
        "verdict_detail": ["BLOCKED", "BLOCKED", "ALLOWED", "BLOCKED"],
        "tool_arguments": ["{}", "{}", "{}", "{}"],
        "context": ["", "", "", ""]
    }

    tbl_a = pa.Table.from_pydict(eval_a)
    tbl_b = pa.Table.from_pydict(eval_b)
    con.register("view_a", tbl_a)
    con.register("view_b", tbl_b)
    con.execute("INSERT INTO run_case_evaluations SELECT * FROM view_a")
    con.execute("INSERT INTO run_case_evaluations SELECT * FROM view_b")
    con.close()

    # 1. Compare all discrepancies
    resp = client.get(f"/api/runs/{run_a}/compare/{run_b}?filter=all")
    assert resp.status_code == 200
    data = resp.json()

    assert data["run_a"]["model_name"] == "L1 Static Rules"
    assert data["run_b"]["model_name"] == "Hybrid Guard"
    stats = data["agreement_stats"]
    assert stats["total_common"] == 4
    assert stats["matching_verdicts"] == 2
    assert stats["discrepant_verdicts"] == 2
    assert stats["agreement_rate_pct"] == 50.0
    assert stats["a_missed_b_caught"] == 1  # case-2
    assert stats["both_correct"] == 2       # case-1, case-3

    # Check discrepancies payload
    disc = data["discrepancies"]
    assert len(disc) == 2
    disc_ids = [d["case_id"] for d in disc]
    assert "case-2" in disc_ids
    assert "case-4" in disc_ids

    # 2. Filter: a_missed_b_caught
    resp_filtered = client.get(f"/api/runs/{run_a}/compare/{run_b}?filter=a_missed_b_caught")
    data_filtered = resp_filtered.json()
    assert len(data_filtered["discrepancies"]) == 1
    assert data_filtered["discrepancies"][0]["case_id"] == "case-2"

    # 3. Filter: fp_diff
    resp_fp = client.get(f"/api/runs/{run_a}/compare/{run_b}?filter=fp_diff")
    data_fp = resp_fp.json()
    assert len(data_fp["discrepancies"]) == 1
    assert data_fp["discrepancies"][0]["case_id"] == "case-4"

    # Clean up
    con2 = get_db()
    con2.execute("DELETE FROM run_case_evaluations WHERE run_id IN (?, ?)", [run_a, run_b])
    con2.execute("DELETE FROM run_history WHERE run_id IN (?, ?)", [run_a, run_b])
    con2.close()
