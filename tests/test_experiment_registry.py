"""
tests/test_experiment_registry.py

Unit tests for DuckDB Experiment Registry schema, CRUD operations,
migration safety, and default seed template (exp_smoke_dual_track).
"""

import json
from pathlib import Path
import duckdb
import pytest

from adapters.experiment_registry import (
    DEFAULT_SEED_TEMPLATE_ID,
    ExperimentTemplate,
    delete_template,
    get_template,
    init_experiment_registry,
    list_templates,
    save_template,
)


@pytest.fixture
def temp_db(tmp_path: Path) -> Path:
    """Create a temporary DuckDB database path with standard run_history table."""
    db_path = tmp_path / "test_benchmark.duckdb"
    con = duckdb.connect(str(db_path))
    # Pre-create legacy run_history table without experiment_id and runtime_tier
    con.execute("""
        CREATE TABLE IF NOT EXISTS run_history (
            run_id          VARCHAR PRIMARY KEY,
            dataset_name    VARCHAR NOT NULL,
            dataset_path    VARCHAR NOT NULL,
            model_name      VARCHAR NOT NULL,
            status          VARCHAR NOT NULL DEFAULT 'completed',
            accuracy        DOUBLE DEFAULT 0
        );
    """)
    con.close()
    return db_path


def test_init_creates_schema_and_migrates_run_history(temp_db: Path):
    """Verify init_experiment_registry creates experiment_templates and migrates run_history."""
    init_experiment_registry(temp_db)

    con = duckdb.connect(str(temp_db))
    # Check experiment_templates exists
    tables = [r[0] for r in con.execute("SHOW TABLES;").fetchall()]
    assert "experiment_templates" in tables

    # Check run_history columns were added
    cols = [r[1] for r in con.execute("PRAGMA table_info('run_history');").fetchall()]
    assert "experiment_id" in cols
    assert "runtime_tier" in cols
    con.close()


def test_seed_template_populated_on_init(temp_db: Path):
    """Verify exp_smoke_dual_track is automatically pre-seeded (Scenario A)."""
    init_experiment_registry(temp_db)

    template = get_template(DEFAULT_SEED_TEMPLATE_ID, temp_db)
    assert template is not None
    assert template.template_id == DEFAULT_SEED_TEMPLATE_ID
    assert "Dual-Track" in template.name
    assert len(template.models_config) >= 3

    model_ids = [m["model_id"] for m in template.models_config]
    assert "laya-mlx" in model_ids
    assert "ollama-d1" in model_ids
    assert "ollama-llama-guard3" in model_ids


def test_save_and_get_template(temp_db: Path):
    """Verify saving a new template and retrieving it."""
    init_experiment_registry(temp_db)

    custom = ExperimentTemplate(
        template_id="exp_custom_eval",
        name="Custom Evaluation",
        description="Testing custom template save",
        dataset_path="data/processed/smoke_test_2k.parquet",
        models_config=[
            {
                "model_id": "ollama-d1",
                "runtime_tier": "OLLAMA_DAEMON_HTTP",
                "exploit_threshold": 0.50,
                "misalignment_threshold": 0.65,
                "enable_l1_cascade": False,
            }
        ],
        limit_cases=100,
    )

    save_template(custom, temp_db)

    retrieved = get_template("exp_custom_eval", temp_db)
    assert retrieved is not None
    assert retrieved.name == "Custom Evaluation"
    assert retrieved.limit_cases == 100
    assert len(retrieved.models_config) == 1
    assert retrieved.models_config[0]["model_id"] == "ollama-d1"


def test_list_templates(temp_db: Path):
    """Verify list_templates returns all templates including seed."""
    init_experiment_registry(temp_db)

    templates = list_templates(temp_db)
    assert len(templates) >= 1
    assert any(t.template_id == DEFAULT_SEED_TEMPLATE_ID for t in templates)


def test_delete_template(temp_db: Path):
    """Verify deleting a template."""
    init_experiment_registry(temp_db)

    custom = ExperimentTemplate(
        template_id="exp_to_delete",
        name="Disposable Template",
        description="Temp",
        dataset_path="data/processed/smoke_test_2k.parquet",
        models_config=[{"model_id": "mock", "runtime_tier": "MOCK"}],
    )
    save_template(custom, temp_db)
    assert get_template("exp_to_delete", temp_db) is not None

    deleted = delete_template("exp_to_delete", temp_db)
    assert deleted is True
    assert get_template("exp_to_delete", temp_db) is None


def test_save_template_invalid_models_config_raises(temp_db: Path):
    """Verify empty or non-list models_config raises ValueError."""
    init_experiment_registry(temp_db)

    invalid = ExperimentTemplate(
        template_id="exp_invalid",
        name="Invalid",
        description="",
        dataset_path="data/processed/smoke_test_2k.parquet",
        models_config=[],  # Empty list must be rejected
    )

    with pytest.raises(ValueError, match="models_config must contain at least one model specification"):
        save_template(invalid, temp_db)
