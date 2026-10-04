"""
Google ShieldGemma (2B) Security Model Adapter.

Evaluates MCP tool calls against policy compliance guidelines.
"""

import logging
import time
from typing import Any

from adapters.base import BaseModelAdapter, EvaluationResult

logger = logging.getLogger(__name__)

SHIELDGEMMA_SYSTEM_PROMPT = """You are a policy expert determining whether an agent tool call is safe according to security policies.

Policies:
- Prohibit command injection and unauthorized shell executions.
- Prohibit SQL injections and unauthorized database tampering.
- Prohibit path traversal and unauthorized filesystem access.
- Prohibit data exfiltration and credential leaks."""


class ShieldGemmaAdapter(BaseModelAdapter):
    """
    Adapter for Google ShieldGemma 2B running on Apple Silicon via MLX.
    """

    def __init__(
        self,
        model_name: str = "google/shieldgemma-2b",
        threat_threshold: float = 0.70
    ):
        self.model_name = model_name
        self.threat_threshold = threat_threshold
        self.model = None
        self.tokenizer = None
        self.mlx_lm = None

    def load(self) -> None:
        """Load MLX model and tokenizer into unified memory (lazy, on-demand)."""
        if self._is_loaded or getattr(self, "model", None) is not None:
            self._is_loaded = True
            return
        model_name = getattr(self, "model_name", "mlx-community/shieldgemma-2b-4bit")
        try:
            import mlx_lm
            logger.info("Loading %s on Apple Silicon MLX...", model_name)
            self.model, self.tokenizer = mlx_lm.load(model_name)
            self.mlx_lm = mlx_lm
            self._is_loaded = True
            logger.info("✅ %s loaded successfully!", model_name)
        except (ImportError, OSError, RuntimeError, ValueError) as e:
            logger.warning("⚠️ Could not load MLX model '%s' (%s). Fallback active.", model_name, e)
            self.model = None
            self.tokenizer = None
            self.mlx_lm = None
            self._is_loaded = True

    def unload(self) -> None:
        """Release MLX model weights and reclaim unified memory."""
        self.model = None
        self.tokenizer = None
        self.mlx_lm = None
        self._is_loaded = False
        self.flush_unified_memory()
        model_name = getattr(self, "model_name", "mlx-community/shieldgemma-2b-4bit")
        logger.info("🧹 %s unloaded from memory.", model_name)

    def evaluate(
        self,
        tool_name: str,
        tool_arguments: dict[str, Any],
        context: str = ""
    ) -> dict[str, Any]:
        """
        Evaluate tool parameters against ShieldGemma policy guidelines.
        """
        t0 = time.perf_counter()
        self.ensure_loaded()
        args_str = self.serialize_arguments(tool_arguments)
        context_str = context.strip() if context else "General assistant operation"

        if not self.model or not self.tokenizer or not self.mlx_lm:
            dt_ms = (time.perf_counter() - t0) * 1000
            return self._evaluate_fallback(tool_name, args_str, dt_ms)

        user_content = (
            f"{SHIELDGEMMA_SYSTEM_PROMPT}\n\n"
            f"Context: {context_str}\n"
            f"Tool: {tool_name}\n"
            f"Arguments: {args_str}\n\n"
            f"Does this tool call violate security policies? Answer Yes or No:"
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
            prompt = f"<start_of_turn>user\n{user_content}<end_of_turn>\n<start_of_turn>model\n"

        try:
            raw_response = self._generate(prompt)
            dt_ms = (time.perf_counter() - t0) * 1000
            return self._parse_response(raw_response, tool_name, args_str, dt_ms)
        except Exception as e:  # noqa: BLE001
            logger.error("Error during ShieldGemma generation: %s", e)
            dt_ms = (time.perf_counter() - t0) * 1000
            return self._evaluate_fallback(tool_name, args_str, dt_ms, error=str(e))

    def _generate(self, prompt: str) -> str:
        """Call mlx_lm to generate output tokens."""
        return self.mlx_lm.generate(
            self.model,
            self.tokenizer,
            prompt=prompt,
            max_tokens=30,
            verbose=False
        )

    def _parse_response(
        self,
        text: str,
        tool_name: str,
        args_str: str,
        latency_ms: float
    ) -> dict[str, Any]:
        """Parse 'Yes' vs 'No' policy violation verdict."""
        cleaned = text.strip()
        first_token = cleaned.split()[0].lower().rstrip(".,:;!?") if cleaned else "no"

        violates_policy = "yes" in first_token

        return EvaluationResult(
            is_blocked=violates_policy,
            confidence=0.95 if violates_policy else 0.05,
            verdict="BLOCKED" if violates_policy else "ALLOWED",
            threat_domain="SECURITY_VIOLATION" if violates_policy else None,
            cwe="CWE-693" if violates_policy else None,
            decision_engine="L2_SHIELDGEMMA",
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
