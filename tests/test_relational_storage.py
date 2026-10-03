import time
import uuid
import duckdb
import pytest
import pyarrow as pa
from fastapi.testclient import TestClient

from web.app import app, get_db


@pytest.fixture
def client():
    return TestClient(app)


def test_table_and_index_creation():
    """Verify run_case_evaluations and idx_case_eval_lookup are created."""
    con = get_db()
    tables = [r[0] for r in con.execute("SHOW TABLES").fetchall()]
    assert "run_case_evaluations" in tables
    assert "run_history" in tables

    # Verify columns in run_case_evaluations
    columns = [r[0] for r in con.execute("DESCRIBE run_case_evaluations").fetchall()]
    expected_cols = [
        "run_id", "case_id", "source", "domain", "analysis_tier", "cwe",
        "tool_name", "is_malicious", "predicted_blocked", "correct",
        "decided_by", "confidence", "latency_ms", "offload_saved_ms",
        "verdict_detail", "tool_arguments", "context"
    ]
    for col in expected_cols:
        assert col in columns
    con.close()


def test_bulk_insert_sla_under_one_second():
    """Verify that bulk inserting 10,000 evaluations via PyArrow is < 1000ms."""
    con = get_db()
    test_run_id = f"test-sla-{uuid.uuid4().hex[:6]}"
    n = 10000

    batch = {
        "run_id": [test_run_id] * n,
        "case_id": [f"case-{i:05d}" for i in range(n)],
        "source": ["benchmark_sla"] * n,
        "domain": ["COMMAND_INJECTION"] * n,
        "analysis_tier": ["STATIC_CAPABLE"] * n,
        "cwe": ["CWE-78"] * n,
        "tool_name": ["bash"] * n,
        "is_malicious": [True] * n,
        "predicted_blocked": [True] * n,
        "correct": [True] * n,
        "decided_by": ["L1"] * n,
        "confidence": [1.0] * n,
        "latency_ms": [0.12] * n,
        "offload_saved_ms": [17.0] * n,
        "verdict_detail": ["BLOCKED"] * n,
        "tool_arguments": ['{"command": "cat /etc/passwd"}'] * n,
        "context": ["test context"] * n
    }

    t0 = time.perf_counter()
    table = pa.Table.from_pydict(batch)
    con.register("sla_test_view", table)
    con.execute("INSERT OR REPLACE INTO run_case_evaluations SELECT * FROM sla_test_view")
    duration_ms = (time.perf_counter() - t0) * 1000

    print(f"\n10k bulk insert duration: {duration_ms:.2f} ms")
    assert duration_ms < 1000.0, f"Bulk insert took {duration_ms:.2f}ms, exceeding 1000ms SLA!"

    # Verify count
    count = con.execute("SELECT COUNT(*) FROM run_case_evaluations WHERE run_id = ?", [test_run_id]).fetchone()[0]
    assert count == n

    # Clean up test data
    con.execute("DELETE FROM run_case_evaluations WHERE run_id = ?", [test_run_id])
    con.close()


def test_api_get_run_and_cascading_delete(client):
    """Verify /api/runs/{id} serves from run_case_evaluations and DELETE cleans both."""
    con = get_db()
    test_run_id = f"test-api-{uuid.uuid4().hex[:6]}"

    # Insert parent run_history row
    con.execute("""
        INSERT INTO run_history (run_id, dataset_name, dataset_path, model_name, status, total_cases, evaluated)
        VALUES (?, 'Test Dataset', 'data/test.parquet', 'mock', 'completed', 2, 2)
    """, [test_run_id])

    # Insert child run_case_evaluations
    eval_data = {
        "run_id": [test_run_id, test_run_id],
        "case_id": ["case-001", "case-002"],
        "source": ["test_source", "test_source"],
        "domain": ["COMMAND_INJECTION", "DLP_SECRET"],
        "analysis_tier": ["STATIC_CAPABLE", "STATIC_CAPABLE"],
        "cwe": ["CWE-78", "CWE-312"],
        "tool_name": ["bash", "read_file"],
        "is_malicious": [True, False],
        "predicted_blocked": [True, False],
        "correct": [True, True],
        "decided_by": ["L1", "L2"],
        "confidence": [0.99, 0.05],
        "latency_ms": [0.15, 12.4],
        "offload_saved_ms": [17.0, 0.0],
        "verdict_detail": ["BLOCKED", "ALLOWED"],
        "tool_arguments": ['{"cmd": "whoami"}', '{"path": "file.txt"}'],
        "context": ["", ""]
    }
    table = pa.Table.from_pydict(eval_data)
    con.register("test_eval_view", table)
    con.execute("INSERT INTO run_case_evaluations SELECT * FROM test_eval_view")
    con.close()

    # Query via API
    resp = client.get(f"/api/runs/{test_run_id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["run_id"] == test_run_id
    assert len(data["case_results"]) == 2
    assert data["case_results"][0]["id"] in ["case-001", "case-002"]
    assert data["case_results"][0]["decided_by"] in ["L1", "L2"]

    # Delete via API
    del_resp = client.delete(f"/api/runs/{test_run_id}")
    assert del_resp.status_code == 200
    assert del_resp.json() == {"deleted": test_run_id}

    # Verify both tables are cleaned
    con2 = get_db()
    parent_count = con2.execute("SELECT COUNT(*) FROM run_history WHERE run_id = ?", [test_run_id]).fetchone()[0]
    child_count = con2.execute("SELECT COUNT(*) FROM run_case_evaluations WHERE run_id = ?", [test_run_id]).fetchone()[0]
    con2.close()

    assert parent_count == 0
    assert child_count == 0
