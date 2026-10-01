"""
tests/test_pipeline.py

Unit tests for the Benchmark Pipeline components:
1. Parquet schema & PyArrow table creation (including analysis_tier)
2. DuckDB in-memory query execution and distribution analysis
3. Transformer data parsers & benign generators
4. Real DLP and Agent Privacy dataset validation
5. Benchmark runner adapter evaluation
"""

import json
from pathlib import Path

import duckdb
import pyarrow as pa
import pyarrow.parquet as pq

from benchmark_runner import MockSecurityAdapter
from scripts.download_raw import DATASET_REGISTRY
from scripts.transform_to_parquet import (
    BENCHMARK_SCHEMA,
    generate_benign_controls,
)

PROCESSED_DIR = Path(__file__).resolve().parent.parent / "data" / "processed"


def test_dataset_registry_keys():
    """Verify that expected key benchmark datasets exist in registry."""
    expected = ["seclists", "payloadbox", "payloadsallthethings", "toolemu", "injecagent", "bipia", "secretbench", "mcptox", "agentdojo"]
    for key in expected:
        assert key in DATASET_REGISTRY
        assert "url" in DATASET_REGISTRY[key]
        assert "target_dir" in DATASET_REGISTRY[key]


def test_benchmark_schema_fields():
    """Ensure the benchmark Parquet schema has all required model-agnostic columns including analysis_tier."""
    field_names = [f.name for f in BENCHMARK_SCHEMA]
    required = [
        "id", "source_dataset", "traffic_direction", "threat_domain",
        "analysis_tier", "cwe", "owasp_llm", "tool_name", "tool_arguments", "context", "is_malicious"
    ]
    for req in required:
        assert req in field_names, f"Missing required column: {req}"


def test_benign_controls_generation():
    """Verify that benign controls generate valid, non-malicious records with analysis_tier."""
    records = generate_benign_controls()
    assert len(records) > 0
    for r in records:
        assert r["is_malicious"] is False
        assert r["cwe"] == "BENIGN"
        assert r["threat_domain"] == "BENIGN"
        assert r["analysis_tier"] == "STATIC_CAPABLE"
        args = json.loads(r["tool_arguments"])
        assert isinstance(args, dict)


def test_parquet_write_and_duckdb_read(tmp_path):
    """Verify that writing a Parquet file and reading via DuckDB works seamlessly with analysis_tier."""
    records = [
        {
            "id": "test-001",
            "source_dataset": "UnitTest",
            "traffic_direction": "tools/call",
            "threat_domain": "COMMAND_INJECTION",
            "analysis_tier": "STATIC_CAPABLE",
            "cwe": "CWE-78",
            "owasp_llm": "LLM08_EXCESSIVE_AGENCY",
            "tool_name": "execute_bash",
            "tool_arguments": json.dumps({"command": "cat /etc/passwd"}),
            "context": "Test Context",
            "is_malicious": True,
        },
        {
            "id": "test-002",
            "source_dataset": "UnitTest",
            "traffic_direction": "tools/call",
            "threat_domain": "BENIGN",
            "analysis_tier": "STATIC_CAPABLE",
            "cwe": "BENIGN",
            "owasp_llm": "NONE",
            "tool_name": "execute_bash",
            "tool_arguments": json.dumps({"command": "git status"}),
            "context": "Test Context",
            "is_malicious": False,
        }
    ]

    table = pa.Table.from_pylist(records, schema=BENCHMARK_SCHEMA)
    test_parquet = tmp_path / "test.parquet"
    pq.write_table(table, test_parquet)

    assert test_parquet.exists()

    con = duckdb.connect(database=":memory:")
    res = con.execute(f"SELECT COUNT(*), SUM(CASE WHEN is_malicious THEN 1 ELSE 0 END) FROM '{test_parquet}'").fetchone()
    total_count, mal_count = res
    assert total_count == 2
    assert mal_count == 1

    tiers = con.execute(f"SELECT DISTINCT analysis_tier FROM '{test_parquet}'").fetchall()
    assert tiers == [("STATIC_CAPABLE",)]


def test_dlp_and_agent_privacy_parquet_files():
    """Verify that dlp_secrets.parquet and agent_privacy.parquet exist and adhere to BENCHMARK_SCHEMA."""
    for filename in ["dlp_secrets.parquet", "agent_privacy.parquet"]:
        pq_path = PROCESSED_DIR / filename
        assert pq_path.exists(), f"Expected file {filename} does not exist in {PROCESSED_DIR}"
        
        table = pq.read_table(pq_path)
        schema_fields = set(table.schema.names)
        expected_fields = {f.name for f in BENCHMARK_SCHEMA}
        assert expected_fields.issubset(schema_fields)
        assert table.num_rows > 0


def test_master_benchmark_analysis_tier_distribution():
    """Verify that master_benchmark.parquet has valid analysis tiers and consistent distribution."""
    master_path = PROCESSED_DIR / "master_benchmark.parquet"
    assert master_path.exists(), "master_benchmark.parquet must exist"

    con = duckdb.connect(database=":memory:")
    query = f"""
        SELECT analysis_tier, threat_domain, COUNT(*) 
        FROM '{master_path}'
        GROUP BY 1, 2
    """
    rows = con.execute(query).fetchall()
    assert len(rows) > 0

    valid_tiers = {"STATIC_CAPABLE", "SEMANTIC_REQUIRED", "HYBRID"}
    observed_tiers = {r[0] for r in rows}
    assert observed_tiers.issubset(valid_tiers), f"Invalid tiers found: {observed_tiers - valid_tiers}"
    assert "STATIC_CAPABLE" in observed_tiers
    assert "SEMANTIC_REQUIRED" in observed_tiers
    assert "HYBRID" in observed_tiers


def test_mock_security_adapter():
    """Verify mock security adapter detects obvious attacks and allows benign commands."""
    adapter = MockSecurityAdapter()
    
    attack_res = adapter.evaluate("execute_bash", {"command": "cat /etc/passwd"}, "test")
    assert attack_res["is_blocked"] is True

    benign_res = adapter.evaluate("execute_bash", {"command": "npm run build"}, "test")
    assert benign_res["is_blocked"] is False
