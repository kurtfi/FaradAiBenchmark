"""
tests/test_experiment_api.py — Unit & Integration tests for Declarative Experiment Matrix API (ADR 0010, Phase 7)
"""

from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient
from web.app import app


@pytest.fixture
def client():
    return TestClient(app)


def test_list_experiments(client):
    """Verify GET /api/experiments returns stored templates including pre-seeded default."""
    response = client.get("/api/experiments")
    assert response.status_code == 200, response.text
    templates = response.json()
    assert isinstance(templates, list)
    assert len(templates) >= 1

    template_ids = [t["template_id"] for t in templates]
    assert "exp_smoke_dual_track" in template_ids

    smoke = next(t for t in templates if t["template_id"] == "exp_smoke_dual_track")
    assert smoke["name"] == "Dual-Track Smoke Evaluation (200 cases)"
    assert smoke["limit_cases"] == 200
    assert len(smoke["models_config"]) == 3


def test_get_experiment_by_id(client):
    """Verify GET /api/experiments/{id} returns specific template or 404."""
    response = client.get("/api/experiments/exp_smoke_dual_track")
    assert response.status_code == 200
    data = response.json()
    assert data["template_id"] == "exp_smoke_dual_track"
    assert "models_config" in data

    not_found = client.get("/api/experiments/non_existent_exp_999")
    assert not_found.status_code == 404


def test_create_update_and_delete_experiment(client):
    """Verify CRUD lifecycle for custom experiment templates."""
    test_template_id = "exp_unit_test_matrix"
    payload = {
        "template_id": test_template_id,
        "name": "Unit Test Custom Matrix",
        "description": "Testing CRUD API via TestClient",
        "dataset_path": "data/processed/smoke_test_2k.parquet",
        "models_config": [
            {
                "model_id": "mock",
                "runtime_tier": "HEURISTIC",
                "enable_l1_cascade": False,
            }
        ],
        "limit_cases": 15,
    }

    # 1. Create
    create_res = client.post("/api/experiments", json=payload)
    assert create_res.status_code == 200, create_res.text
    created_data = create_res.json()
    assert created_data["template_id"] == test_template_id
    assert created_data["name"] == "Unit Test Custom Matrix"
    assert created_data["limit_cases"] == 15

    # 2. Get
    get_res = client.get(f"/api/experiments/{test_template_id}")
    assert get_res.status_code == 200
    assert get_res.json()["template_id"] == test_template_id

    # 3. Update
    payload["name"] = "Updated Custom Matrix Name"
    payload["limit_cases"] = 30
    update_res = client.post("/api/experiments", json=payload)
    assert update_res.status_code == 200
    assert update_res.json()["name"] == "Updated Custom Matrix Name"
    assert update_res.json()["limit_cases"] == 30

    # 4. Delete
    delete_res = client.delete(f"/api/experiments/{test_template_id}")
    assert delete_res.status_code == 200
    assert delete_res.json()["deleted"] == test_template_id

    # 5. Verify 404 after deletion
    verify_res = client.get(f"/api/experiments/{test_template_id}")
    assert verify_res.status_code == 404

    # 6. Delete again returns 404
    delete_again = client.delete(f"/api/experiments/{test_template_id}")
    assert delete_again.status_code == 404


def test_create_experiment_validation(client):
    """Verify validation when creating experiment with empty name or missing models."""
    # Empty models_config
    bad_payload = {
        "template_id": "exp_invalid",
        "name": "Invalid Template",
        "dataset_path": "data/processed/smoke_test_2k.parquet",
        "models_config": [],
    }
    res = client.post("/api/experiments", json=bad_payload)
    assert res.status_code == 400

    # Empty name
    bad_payload_name = {
        "template_id": "exp_invalid_2",
        "name": "",
        "dataset_path": "data/processed/smoke_test_2k.parquet",
        "models_config": [{"model_id": "mock"}],
    }
    res2 = client.post("/api/experiments", json=bad_payload_name)
    assert res2.status_code == 400


def test_run_experiment_endpoint(client):
    """Verify POST /api/experiments/{id}/run triggers background matrix run."""
    with patch("web.app.asyncio.create_task") as mock_task:
        response = client.post(
            "/api/experiments/exp_smoke_dual_track/run",
            json={"limit_cases": 5},
        )
        assert response.status_code == 200, response.text
        data = response.json()
        assert data["template_id"] == "exp_smoke_dual_track"
        assert data["status"] == "started"
        assert data["models_count"] == 3
        mock_task.assert_called_once()
        coro = mock_task.call_args[0][0]
        coro.close()


def test_run_nonexistent_experiment(client):
    """Verify POST /api/experiments/{id}/run returns 404 for missing template."""
    response = client.post("/api/experiments/missing_template_xyz/run", json={})
    assert response.status_code == 404


def test_dashboard_renders_matrix_studio(client):
    """Verify GET / renders HTML dashboard containing Matrix Studio tab and modal."""
    response = client.get("/")
    assert response.status_code == 200
    html = response.text
    assert "Matrix Studio" in html
    assert "page-matrix" in html
    assert "new-template-modal" in html
    assert "matrix-template-select" in html


def test_api_datasets_order_and_core_suites(client):
    """Verify /api/datasets prioritizes Farad-Decision-Bench-v1.0 (default), Benchmark Train, and Master Benchmark."""
    response = client.get("/api/datasets")
    assert response.status_code == 200
    datasets = response.json()
    assert len(datasets) >= 3

    # Farad-Decision-Bench-v1.0 must be first (index 0) so frontend defaults to it
    assert datasets[0]["id"] in ("farad_decision_bench_v1", "smoke_test_2k")
    assert datasets[0]["is_core"] is True
    assert datasets[0]["rows"] == 2000
    assert "Farad-Decision-Bench-v1.0" in datasets[0]["name"]

    # Benchmark Train must be second (index 1)
    assert datasets[1]["id"] == "benchmark_train"
    assert datasets[1]["is_core"] is True
    assert datasets[1]["rows"] > 7000

    # Master Benchmark must be third (index 2)
    assert datasets[2]["id"] == "master_benchmark"
    assert datasets[2]["is_core"] is True
    assert datasets[2]["rows"] > 9000


