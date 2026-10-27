"""
tests/test_manage_experiments.py — Unit tests for CLI Experiment Template Manager (ADR 0010)
"""

import tempfile
from pathlib import Path
import pytest
import duckdb

from adapters.experiment_registry import init_experiment_registry, get_template
from scripts.manage_experiments import export_template_to_yaml, import_template_from_yaml


@pytest.fixture
def temp_db(tmp_path: Path):
    db_path = tmp_path / "test_manage.duckdb"
    con = duckdb.connect(str(db_path))
    con.execute("""
        CREATE TABLE IF NOT EXISTS run_history (
            run_id VARCHAR PRIMARY KEY,
            dataset_name VARCHAR,
            dataset_path VARCHAR,
            model_name VARCHAR
        );
    """)
    init_experiment_registry(con)
    con.close()
    return db_path


def test_export_template_to_yaml(temp_db, tmp_path: Path):
    """Verify exporting an existing template to YAML."""
    template = get_template("exp_smoke_dual_track", temp_db)
    assert template is not None

    out_yaml = tmp_path / "exported.yaml"
    yaml_str = export_template_to_yaml(template, out_yaml)
    assert "template_id: exp_smoke_dual_track" in yaml_str
    assert "laya-mlx" in yaml_str
    assert "MLX_NATIVE_METAL" in yaml_str

    # Verify file on disk
    file_content = out_yaml.read_text(encoding="utf-8")
    assert file_content == yaml_str


def test_import_template_from_yaml(temp_db, tmp_path: Path):
    """Verify importing a custom YAML template into DuckDB."""
    custom_yaml = """
template_id: exp_imported_matrix
name: Imported Test Matrix
description: Matrix imported from YAML spec
dataset_path: data/processed/smoke_test_2k.parquet
limit_cases: 50
models_config:
  - model_id: mock
    runtime_tier: HEURISTIC
    enable_l1_cascade: true
  - model_id: ollama-d1
    runtime_tier: OLLAMA_DAEMON_HTTP
    enable_l1_cascade: false
"""
    yaml_file = tmp_path / "custom_template.yaml"
    yaml_file.write_text(custom_yaml, encoding="utf-8")

    imported = import_template_from_yaml(yaml_file, temp_db)
    assert imported.template_id == "exp_imported_matrix"
    assert imported.name == "Imported Test Matrix"
    assert imported.limit_cases == 50
    assert len(imported.models_config) == 2

    # Verify persisted in DuckDB
    from_db = get_template("exp_imported_matrix", temp_db)
    assert from_db is not None
    assert from_db.name == "Imported Test Matrix"
    assert from_db.models_config[0]["model_id"] == "mock"


def test_import_invalid_yaml(temp_db, tmp_path: Path):
    """Verify validation errors on incomplete or malformed YAML."""
    bad_yaml = """
template_id: exp_bad
name: Bad Matrix
# missing dataset_path and models_config
"""
    yaml_file = tmp_path / "bad_template.yaml"
    yaml_file.write_text(bad_yaml, encoding="utf-8")

    with pytest.raises(ValueError, match="Missing required template fields"):
        import_template_from_yaml(yaml_file, temp_db)

