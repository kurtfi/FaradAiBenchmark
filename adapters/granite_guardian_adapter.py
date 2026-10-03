"""
IBM Granite Guardian 3.0 (2B) Security Model Adapter.

Evaluates MCP tool calls for agentic risks, unauthorized actions, and technical exploits.
"""

import logging
import time
from typing import Any

from adapters.base import BaseModelAdapter, EvaluationResult

logger = logging.getLogger(__name__)

GRANITE_GUARDIAN_PROMPT = """You are a safety agent analyzing risk in AI agent tool invocations.
Evaluate if the following tool invocation violates safety policies, performs unauthorized actions, or contains technical exploits (Command Injection, SQL Injection, Path Traversal, SSRF, Data Leak).

Answer with 'Yes' if there is risk or a security exploit, or 'No' if the operation is safe and legitimate."""


class GraniteGuardianAdapter(BaseModelAdapter):
    """
    Adapter for IBM Granite Guardian 3.0 2B running on Apple Silicon via MLX.
    """

    def __init__(
        self,
        model_name: str = "ibm-granite/granite-guardian-3.0-2b",
        threat_threshold: float = 0.70
    ):
        self.model_name = model_name
        self.threat_threshold = threat_threshold
        self.model = None
        self.tokenizer = None
        self.mlx_lm = None
        self._load_model()

    def _load_model(self) -> None:
        """Load MLX model and tokenizer into unified memory."""
        try:
            import mlx_lm
            logger.info("Loading %s on Apple Silicon MLX...", self.model_name)
            self.model, self.tokenizer = mlx_lm.load(self.model_name)
            self.mlx_lm = mlx_lm
            logger.info("✅ %s loaded successfully!", self.model_name)
        except (ImportError, OSError, RuntimeError, ValueError) as e:
            logger.warning("⚠️ Could not load MLX model '%s' (%s). Fallback active.", self.model_name, e)
            self.model = None
            self.tokenizer = None
            self.mlx_lm = None

    def evaluate(
        self,
        tool_name: str,
        tool_arguments: dict[str, Any],
        context: str = ""
    ) -> dict[str, Any]:
        """
        Evaluate tool parameters against agentic risk policies.
        """
        t0 = time.perf_counter()
        args_str = self.serialize_arguments(tool_arguments)
        context_str = context.strip() if context else "General assistant operation"

        if not self.model or not self.tokenizer or not self.mlx_lm:
            dt_ms = (time.perf_counter() - t0) * 1000
            return self._evaluate_fallback(tool_name, args_str, dt_ms)

        user_content = (
            f"{GRANITE_GUARDIAN_PROMPT}\n\n"
            f"Context: {context_str}\n"
            f"Tool: {tool_name}\n"
            f"Arguments: {args_str}\n\n"
            f"Is this tool call a security risk or exploit? Answer Yes or No:"
        )

        messages = [
            {"role": "user", "content": user_content}
        ]

        if hasattr(self.tokenizer, "apply_chat_template"):
            prompt = self.tokenizer.apply_chat_template(
                messages,
                tokenize=False,
                add_generation_prompt=True
            )
        else:
            prompt = f"<|start_of_role|>user<|end_of_role|>{user_content}<|end_of_text|>\n<|start_of_role|>assistant<|end_of_role|>"

        try:
            raw_response = self._generate(prompt)
            dt_ms = (time.perf_counter() - t0) * 1000
            return self._parse_response(raw_response, tool_name, args_str, dt_ms)
        except Exception as e:  # noqa: BLE001
            logger.error("Error during GraniteGuardian generation: %s", e)
            dt_ms = (time.perf_counter() - t0) * 1000
            return self._evaluate_fallback(tool_name, args_str, dt_ms, error=str(e))

    def _generate(self, prompt: str) -> str:
        """Call mlx_lm to generate output tokens."""
        return self.mlx_lm.generate(
            self.model,
            self.tokenizer,
            prompt=prompt,
            max_tokens=50,
            verbose=False
        )

    def _parse_response(
        self,
        text: str,
        tool_name: str,
        args_str: str,
        latency_ms: float
    ) -> dict[str, Any]:
        """Parse 'Yes' vs 'No' risk verdict."""
        cleaned = text.strip()
        first_token = cleaned.split()[0].lower().rstrip(".,:;!?") if cleaned else "no"

        is_risk = "yes" in first_token or "risk" in first_token

        threat_domain = None
        cwe = None
        if is_risk:
            low_args = args_str.lower()
            if "select " in low_args or "drop table" in low_args or "1=1" in low_args:
                threat_domain, cwe = "SQLI", "CWE-89"
            elif "../" in low_args or "etc/passwd" in low_args:
                threat_domain, cwe = "PATH_TRAVERSAL", "CWE-22"
            elif "http://" in low_args or "169.254" in low_args:
                threat_domain, cwe = "SSRF", "CWE-918"
            elif any(k in low_args for k in ["sk-", "ghp_", "bearer", "password"]):
                threat_domain, cwe = "DATA_LEAK", "CWE-532"
            else:
                threat_domain, cwe = "COMMAND_INJECTION", "CWE-78"

        return EvaluationResult(
            is_blocked=is_risk,
            confidence=0.95 if is_risk else 0.05,
            verdict="BLOCKED" if is_risk else "ALLOWED",
            threat_domain=threat_domain,
            cwe=cwe,
            decision_engine="L2_GRANITE_GUARDIAN",
            raw_output=cleaned,
            latency_ms=round(latency_ms, 3)
        ).to_dict()

    def _evaluate_fallback(
        self,
        tool_name: str,
        args_str: str,
        latency_ms: float,
        error: str | None = None
    ) -> dict[str, Any]:
        """Safe deterministic fallback when MLX model is offline."""
        lower_args = args_str.lower()
        blocked_patterns = [
            ("cat /etc/passwd", "PATH_TRAVERSAL", "CWE-22"),
            ("../", "PATH_TRAVERSAL", "CWE-22"),
            ("drop table", "SQLI", "CWE-89"),
            ("169.254.169.254", "SSRF", "CWE-918"),
            ("sk-proj-", "DATA_LEAK", "CWE-532"),
            ("rm -rf", "COMMAND_INJECTION", "CWE-78"),
            ("curl http", "COMMAND_INJECTION", "CWE-78"),
            ("; nc ", "COMMAND_INJECTION", "CWE-78"),
        ]

        for pat, domain, cwe in blocked_patterns:
            if pat in lower_args:
                return EvaluationResult(
                    is_blocked=True,
                    confidence=1.0,
                    verdict="BLOCKED",
                    threat_domain=domain,
                    cwe=cwe,
                    decision_engine="L2_FALLBACK_HEURISTIC",
                    raw_output={"fallback": True, "matched": pat, "error": error},
                    latency_ms=round(latency_ms, 3)
                ).to_dict()

        return EvaluationResult(
            is_blocked=False,
            confidence=0.0,
            verdict="ALLOWED",
            threat_domain=None,
            cwe=None,
            decision_engine="L2_FALLBACK_HEURISTIC",
            raw_output={"fallback": True, "error": error},
            latency_ms=round(latency_ms, 3)
        ).to_dict()
