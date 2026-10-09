"""
Unit tests for QwenCoderAdapter and BaseModelAdapter contract.
"""

import pytest

from adapters.base import BaseModelAdapter, EvaluationResult
from adapters.qwen_coder_adapter import QwenCoderAdapter


class MockQwenAdapter(QwenCoderAdapter):
    """Subclass that stubs model inference for unit test isolation."""
    def __init__(self, mock_response: str = "", threat_threshold: float = 0.70):
        self.mock_response = mock_response
        self.threat_threshold = threat_threshold
        self.model = True
        self.tokenizer = True
        self.mlx_lm = True

    def _generate(self, prompt: str) -> str:
        return self.mock_response


def test_base_adapter_contract():
    """Verify BaseModelAdapter requires evaluate implementation."""
    class IncompleteAdapter(BaseModelAdapter):
        pass

    with pytest.raises(TypeError):
        IncompleteAdapter()


def test_evaluation_result_schema():
    """Verify EvaluationResult dataclass and dictionary conversion."""
    res = EvaluationResult(
        is_blocked=True,
        confidence=0.95,
        verdict="BLOCKED",
        threat_domain="COMMAND_INJECTION",
        cwe="CWE-78",
        decision_engine="TEST_ENGINE",
        latency_ms=12.5
    )
    data = res.to_dict()
    assert data["is_blocked"] is True
    assert data["confidence"] == 0.95
    assert data["verdict"] == "BLOCKED"
    assert data["threat_domain"] == "COMMAND_INJECTION"
    assert data["cwe"] == "CWE-78"
    assert data["latency_ms"] == 12.5


def test_qwen_coder_fallback_malicious():
    """Test fallback heuristic detects obvious malicious commands when offline."""
    adapter = QwenCoderAdapter(model_name="non-existent-offline-model")
    # Should use fallback heuristic
    result = adapter.evaluate(
        tool_name="execute_bash_command",
        tool_arguments={"command": "cat /etc/passwd"}
    )
    assert result["is_blocked"] is True
    assert result["verdict"] == "BLOCKED"
    assert result["cwe"] == "CWE-22"
    assert result["decision_engine"] == "L2_FALLBACK_HEURISTIC"


def test_qwen_coder_fallback_benign():
    """Test fallback heuristic allows benign commands when offline."""
    adapter = QwenCoderAdapter(model_name="non-existent-offline-model")
    result = adapter.evaluate(
        tool_name="execute_bash_command",
        tool_arguments={"command": "echo 'Hello World'"}
    )
    assert result["is_blocked"] is False
    assert result["verdict"] == "ALLOWED"
    assert result["confidence"] == 0.0
    assert result["decision_engine"] == "L2_FALLBACK_HEURISTIC"


def test_qwen_coder_parsed_json_threat():
    """Test Qwen structured JSON parsing when threat is detected."""
    json_out = """{
        "is_blocked": true,
        "confidence": 0.96,
        "verdict": "BLOCKED",
        "threat_domain": "SQLI",
        "cwe": "CWE-89",
        "reason": "Union-based SQL injection targeting accounts"
    }"""
    adapter = MockQwenAdapter(mock_response=json_out)
    res = adapter.evaluate(
        tool_name="query_db",
        tool_arguments={"query": "SELECT * FROM users WHERE id = 1 UNION SELECT null, password FROM admin"}
    )
    assert res["is_blocked"] is True
    assert res["verdict"] == "BLOCKED"
    assert res["threat_domain"] == "SQLI"
    assert res["cwe"] == "CWE-89"
    assert res["confidence"] == 0.96
    assert res["decision_engine"] == "L2_QWEN_CODER"


def test_qwen_coder_parsed_json_benign():
    """Test Qwen structured JSON parsing when payload is benign."""
    json_out = """{
        "is_blocked": false,
        "confidence": 0.05,
        "verdict": "ALLOWED",
        "threat_domain": "BENIGN",
        "cwe": "BENIGN",
        "reason": "Legitimate analytics aggregation"
    }"""
    adapter = MockQwenAdapter(mock_response=json_out)
    res = adapter.evaluate(
        tool_name="query_db",
        tool_arguments={"query": "SELECT count(*) FROM orders WHERE status = 'shipped'"}
    )
    assert res["is_blocked"] is False
    assert res["verdict"] == "ALLOWED"
    assert res["confidence"] == 0.05
    assert res["threat_domain"] is None
    assert res["cwe"] is None


def test_qwen3guard_native_benign():
    """Test native Qwen3Guard Safe assessment output."""
    raw = "Safety: Safe\nCategories: None"
    adapter = MockQwenAdapter(mock_response=raw)
    res = adapter.evaluate(
        tool_name="search_files",
        tool_arguments={"path": "src", "pattern": "*.py"}
    )
    assert res["is_blocked"] is False
    assert res["verdict"] == "ALLOWED"
    assert res["threat_domain"] is None
    assert res["cwe"] is None
    assert res["decision_engine"] == "L2_QWEN3_GUARD"


def test_qwen3guard_native_unsafe():
    """Test native Qwen3Guard Unsafe assessment output."""
    raw = "Safety: Unsafe\nCategories: Command Injection & Remote Code Execution"
    adapter = MockQwenAdapter(mock_response=raw)
    res = adapter.evaluate(
        tool_name="execute_bash",
        tool_arguments={"command": "rm -rf /"}
    )
    assert res["is_blocked"] is True
    assert res["verdict"] == "BLOCKED"
    assert res["threat_domain"] == "COMMAND_INJECTION"
    assert res["cwe"] == "CWE-78"
    assert res["confidence"] == 0.95
    assert res["decision_engine"] == "L2_QWEN3_GUARD"


def test_qwen3guard_native_controversial():
    """Test native Qwen3Guard Controversial assessment output."""
    raw = "Safety: Controversial\nCategories: Path Traversal & Local File Inclusion"
    adapter = MockQwenAdapter(mock_response=raw)
    res = adapter.evaluate(
        tool_name="read_file",
        tool_arguments={"path": "../../etc/passwd"}
    )
    assert res["is_blocked"] is True
    assert res["verdict"] == "BLOCKED"
    assert res["threat_domain"] == "PATH_TRAVERSAL"
    assert res["cwe"] == "CWE-22"
    assert res["confidence"] == 0.90
    assert res["decision_engine"] == "L2_QWEN3_GUARD"
