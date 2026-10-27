"""
tests/test_ollama_guard_adapter.py

Unit tests for OllamaGuardAdapter (ADR 0010, SPEC Phase 7).
Tests discrete verdict parsing, MLCommons S-category CWE mapping,
Granite Yes/No classification, connection error handling, and VRAM eviction.
"""

from unittest.mock import MagicMock, patch
import pytest

from adapters.ollama_guard_adapter import (
    OllamaGraniteGuardianAdapter,
    OllamaGuardAdapter,
    OllamaLlamaGuardAdapter,
)


@pytest.fixture
def mock_session():
    """Create a mocked requests.Session."""
    with patch("requests.Session") as mock_cls:
        session = MagicMock()
        mock_cls.return_value = session
        yield session


def test_llama_guard_safe_verdict(mock_session):
    """Verify Llama Guard 'safe' output maps to allowed discrete verdict."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "message": {"content": "safe"}
    }
    mock_session.post.return_value = mock_resp

    adapter = OllamaLlamaGuardAdapter()
    result = adapter.evaluate(
        tool_name="web_search",
        tool_arguments={"query": "weather in Istanbul"},
        context="What is the weather?"
    )

    assert result["is_blocked"] is False
    assert result["confidence"] == 0.0
    assert result["verdict"] == "ALLOWED"
    assert result["threat_domain"] is None


def test_llama_guard_unsafe_s13_maps_to_command_injection(mock_session):
    """Verify Llama Guard 'unsafe\nS13' maps to blocked with CWE-78."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "message": {"content": "unsafe\nS13"}
    }
    mock_session.post.return_value = mock_resp

    adapter = OllamaLlamaGuardAdapter()
    result = adapter.evaluate(
        tool_name="bash",
        tool_arguments={"command": "rm -rf /"},
        context="Clean temporary files"
    )

    assert result["is_blocked"] is True
    assert result["confidence"] == 1.0
    assert result["verdict"] == "BLOCKED"
    assert result["cwe"] == "CWE-78"
    assert result["threat_domain"] == "COMMAND_INJECTION"


def test_llama_guard_unsafe_s7_maps_to_data_leak(mock_session):
    """Verify Llama Guard 'unsafe\nS7' maps to DATA_LEAK with CWE-532."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "message": {"content": "unsafe\nS7"}
    }
    mock_session.post.return_value = mock_resp

    adapter = OllamaLlamaGuardAdapter()
    result = adapter.evaluate(
        tool_name="send_email",
        tool_arguments={"body": "API key: sk-proj-12345"},
        context="Forward credentials"
    )

    assert result["is_blocked"] is True
    assert result["cwe"] == "CWE-532"
    assert result["threat_domain"] == "DATA_LEAK"


def test_granite_guardian_yes_verdict(mock_session):
    """Verify Granite Guardian 'Yes' maps to blocked discrete verdict."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "message": {"content": "Yes, this operation contains risk."}
    }
    mock_session.post.return_value = mock_resp

    adapter = OllamaGraniteGuardianAdapter()
    result = adapter.evaluate(
        tool_name="db_query",
        tool_arguments={"sql": "SELECT * FROM users WHERE 1=1; DROP TABLE users;"},
        context="Fetch user list"
    )

    assert result["is_blocked"] is True
    assert result["confidence"] == 1.0
    assert result["verdict"] == "BLOCKED"
    assert result["threat_domain"] == "SQLI"
    assert result["cwe"] == "CWE-89"


def test_granite_guardian_no_verdict(mock_session):
    """Verify Granite Guardian 'No' maps to allowed discrete verdict."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "message": {"content": "No, this invocation is safe."}
    }
    mock_session.post.return_value = mock_resp

    adapter = OllamaGraniteGuardianAdapter()
    result = adapter.evaluate(
        tool_name="read_file",
        tool_arguments={"path": "documents/report.pdf"},
        context="Read report"
    )

    assert result["is_blocked"] is False
    assert result["confidence"] == 0.0
    assert result["verdict"] == "ALLOWED"


def test_connection_error_returns_error_verdict(mock_session):
    """Verify network error gracefully produces verdict == 'ERROR' without crashing."""
    mock_session.post.side_effect = Exception("Ollama daemon unreachable")

    adapter = OllamaLlamaGuardAdapter()
    result = adapter.evaluate(
        tool_name="test_tool",
        tool_arguments={},
        context=""
    )

    assert result["is_blocked"] is False
    assert result["verdict"] == "ERROR"
    assert "error" in result["raw_output"]


def test_unload_sends_keep_alive_zero(mock_session):
    """Verify unload sends keep_alive: 0 to evict VRAM immediately."""
    adapter = OllamaGuardAdapter(model_name="llama-guard3:1b")
    adapter.unload()

    mock_session.post.assert_called_once()
    args, kwargs = mock_session.post.call_args
    assert args[0].endswith("/api/generate")
    assert kwargs["json"]["model"] == "llama-guard3:1b"
    assert kwargs["json"]["keep_alive"] == 0
