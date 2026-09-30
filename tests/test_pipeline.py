"""
tests/test_pipeline.py

Unit tests for the Benchmark Pipeline components:
1. Parquet schema & PyArrow table creation
2. DuckDB in-memory query execution
3. Transformer data parsers & benign generators
4. Benchmark runner adapter evaluation
"""

import json
from pathlib import Path
import pytest
import duckdb
import pyarrow as pa
import pyarrow.parquet as pq

from scripts.transform_to_parquet import (
    BENCHMARK_SCHEMA,
    generate_benign_controls,
    parse_seclists_command,
    parse_payloadbox_traversal,
    parse_ssrf_metadata,
    parse_dlp_secrets,
    write_parquet
)
from scripts.download_raw import DATASET_REGISTRY
from benchmark_runner import MockSecurityAdapter


def test_dataset_registry_keys():
    """Verify that expected key benchmark datasets exist in registry."""
    expected = ["seclists", "payloadbox", "payloadsallthethings", "toolemu", "injecagent", "bipia", "secretbench"]
    for key in expected:
        assert key in DATASET_REGISTRY
        assert "url" in DATASET_REGISTRY[key]
        assert "target_dir" in DATASET_REGISTRY[key]


def test_benchmark_schema_fields():
    """Ensure the benchmark Parquet schema has all required model-agnostic columns."""
    field_names = [f.name for f in BENCHMARK_SCHEMA]
    required = [
        "id", "source_dataset", "traffic_direction", "threat_domain",
        "cwe", "owasp_llm", "tool_name", "tool_arguments", "context", "is_malicious"
    ]
    for req in required:
        assert req in field_names


def test_benign_controls_generation():
    """Verify that benign controls generate valid, non-malicious records."""
    records = generate_benign_controls()
    assert len(records) > 0
    for r in records:
        assert r["is_malicious"] is False
        assert r["cwe"] == "BENIGN"
        assert r["threat_domain"] == "BENIGN"
        # Check tool arguments are valid JSON
        args = json.loads(r["tool_arguments"])
        assert isinstance(args, dict)


def test_parquet_write_and_duckdb_read(tmp_path):
    """Verify that writing a Parquet file and reading via DuckDB works seamlessly."""
    records = [
        {
            "id": "test-001",
            "source_dataset": "UnitTest",
            "traffic_direction": "tools/call",
            "threat_domain": "COMMAND_INJECTION",
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


def test_mock_security_adapter():
    """Verify mock security adapter detects obvious attacks and allows benign commands."""
    adapter = MockSecurityAdapter()
    
    attack_res = adapter.evaluate("execute_bash", {"command": "cat /etc/passwd"}, "test")
    assert attack_res["is_blocked"] is True

    benign_res = adapter.evaluate("execute_bash", {"command": "npm run build"}, "test")
    assert benign_res["is_blocked"] is False
