"""
prompt_guard_adapter.py

Ultra-Fast Indirect Prompt Injection & Jailbreak Classifier Adapter.
Runs on Apple Silicon MPS (Metal Performance Shaders) or CPU using Hugging Face Transformers & PyTorch.
Supports Meta Prompt-Guard-86M with seamless fallback to deepset/deberta-v3-base-injection.
"""

import json
import logging
import os
import time
from typing import Any

from adapters.base import BaseModelAdapter, EvaluationResult

logger = logging.getLogger(__name__)


class PromptGuardAdapter(BaseModelAdapter):
    """
    Adapter for ultra-fast prompt injection and jailbreak classification.
    Optimized for sub-25ms evaluation of MCP tool call argument payloads on Apple Silicon.
    """

    PRIMARY_MODEL = "meta-llama/Prompt-Guard-86M"
    FALLBACK_MODEL = "deepset/deberta-v3-base-injection"

    def __init__(
        self,
        model_name: str = PRIMARY_MODEL,
        fallback_model: str = FALLBACK_MODEL,
        threat_threshold: float = 0.50,
        device: str | None = None,
    ) -> None:
        self.requested_model = model_name
        self.fallback_model = fallback_model
        self.threat_threshold = threat_threshold
        self.active_model_name = model_name
        self._user_device = device

        self.tokenizer = None
        self.model = None
        self.torch_device = None
        self.id2label: dict[int, str] = {}

    def _init_device(self, user_device: str | None) -> None:
        """Detect and initialize compute device (MPS on Apple Silicon, CUDA, or CPU)."""
        try:
            import torch

            if user_device:
                self.torch_device = torch.device(user_device)
            elif torch.backends.mps.is_available():
                self.torch_device = torch.device("mps")
            elif torch.cuda.is_available():
                self.torch_device = torch.device("cuda")
            else:
                self.torch_device = torch.device("cpu")
        except ImportError:
            logger.warning("PyTorch not installed. PromptGuardAdapter will use heuristic fallback.")
            self.torch_device = None

    def load(self) -> None:
        """Initialize device and load model weights (lazy, on-demand)."""
        if self._is_loaded or getattr(self, "model", None) is not None:
            self._is_loaded = True
            return
        self._init_device(self._user_device)
        self._load_model_weights()
        self._is_loaded = True

    def unload(self) -> None:
        """Release PyTorch model weights and reclaim MPS / unified memory."""
        self.model = None
        self.tokenizer = None
        self.id2label = {}
        self._is_loaded = False
        self.flush_unified_memory()
        logger.info("🧹 PromptGuard (%s) unloaded from memory.", self.active_model_name)

    def _load_model_weights(self) -> None:
        """Attempt loading requested model, falling back to local/un-gated model if gated or offline."""
        if self.torch_device is None:
            return

        from transformers import AutoModelForSequenceClassification, AutoTokenizer

        has_hf_token = bool(os.getenv("HF_TOKEN") or os.getenv("HUGGING_FACE_HUB_TOKEN"))

        for target in [self.requested_model, self.fallback_model]:
            if not target:
                continue

            # If targeting gated meta-llama model without token and not locally cached, skip directly to fallback
            if "meta-llama" in target and not has_hf_token:
                try:
                    # Check if locally cached
                    self.tokenizer = AutoTokenizer.from_pretrained(target, local_files_only=True)
                    self.model = AutoModelForSequenceClassification.from_pretrained(
                        target, local_files_only=True
                    )
                    self.model.to(self.torch_device)
                    self.model.eval()
                    self.active_model_name = target
                    self.id2label = getattr(self.model.config, "id2label", {})
                    logger.info("Loaded cached model: %s", target)
                    return
                except (OSError, ValueError, RuntimeError, ImportError) as err:
                    logger.debug(
                        "Gated model '%s' not cached locally (%s). Skipping to fallback '%s'.",
                        target,
                        err,
                        self.fallback_model,
                    )
                    continue

            # Try local files first
            try:
                self.tokenizer = AutoTokenizer.from_pretrained(target, local_files_only=True)
                self.model = AutoModelForSequenceClassification.from_pretrained(
                    target, local_files_only=True
                )
                self.model.to(self.torch_device)
                self.model.eval()
                self.active_model_name = target
                self.id2label = getattr(self.model.config, "id2label", {})
                logger.info("Successfully loaded local model: %s", target)
                return
            except (OSError, ValueError, RuntimeError, ImportError) as err:
                logger.debug("Local load of '%s' skipped: %s", target, err)

            # Try remote download if network/token is available
            try:
                logger.info("Attempting remote load for: %s on %s", target, self.torch_device)
                self.tokenizer = AutoTokenizer.from_pretrained(target)
                self.model = AutoModelForSequenceClassification.from_pretrained(target)
                self.model.to(self.torch_device)
                self.model.eval()
                self.active_model_name = target
                self.id2label = getattr(self.model.config, "id2label", {})
                logger.info("Successfully loaded remote model: %s", target)
                return
            except (OSError, ValueError, RuntimeError, ImportError) as e:
                logger.warning(
                    "Could not load '%s' (%s). Trying next candidate...", target, e
                )

        logger.error(
            "Failed to load any injection classification model. Operating in heuristic fallback mode."
        )
        self.model = None
        self.tokenizer = None

    @property
    def model_name(self) -> str:
        return f"prompt-guard ({self.active_model_name})"

    def _extract_payload(self, tool_name: str, tool_arguments: dict[str, Any]) -> str:
        """Extract natural text values from tool arguments to evaluate without synthetic prefix noise."""
        parts = []
        if isinstance(tool_arguments, dict):
            for v in tool_arguments.values():
                if isinstance(v, (str, int, float, bool)):
                    parts.append(str(v))
                elif isinstance(v, (list, dict)):
                    parts.append(json.dumps(v, ensure_ascii=False))
        elif tool_arguments:
            parts.append(str(tool_arguments))

        text = " ".join(parts).strip()
        return text if text else tool_name

    def evaluate(
        self,
        tool_name: str,
        tool_arguments: dict[str, Any],
        context: str = "",
    ) -> dict[str, Any]:
        """
        Evaluate tool arguments for indirect prompt injection or jailbreak patterns.
        """
        t0 = time.perf_counter()
        self.ensure_loaded()

        # Fast heuristic fallback if neural model is not active
        if self.model is None or self.tokenizer is None:
            return self._heuristic_fallback(
                tool_name=tool_name,
                tool_arguments=tool_arguments,
                context=context,
                duration_ms=(time.perf_counter() - t0) * 1000.0,
            )

        import torch

        # Extract natural payload text
        payload_text = self._extract_payload(tool_name, tool_arguments)

        try:
            inputs = self.tokenizer(
                payload_text,
                return_tensors="pt",
                truncation=True,
                max_length=512,
            ).to(self.torch_device)

            with torch.no_grad():
                outputs = self.model(**inputs)
                logits = outputs.logits
                probs = torch.softmax(logits, dim=-1)[0]
                if self.torch_device.type == "mps":
                    torch.mps.synchronize()

            latency_ms = (time.perf_counter() - t0) * 1000.0

            # Calculate threat probability based on model class taxonomy
            # Prompt-Guard-86M: {0: 'BENIGN', 1: 'INJECTION', 2: 'JAILBREAK'}
            # DeBERTa-v3: {0: 'LEGIT', 1: 'INJECTION'}
            injection_score = 0.0
            jailbreak_score = 0.0

            prob_list = probs.tolist()
            if len(self.id2label) == len(prob_list):
                for idx, score in enumerate(prob_list):
                    label_name = str(self.id2label.get(idx, "")).upper()
                    if "INJECTION" in label_name:
                        injection_score = max(injection_score, score)
                    elif "JAILBREAK" in label_name:
                        jailbreak_score = max(jailbreak_score, score)
            else:
                # Default binary assumption: index 1 is adversarial
                injection_score = prob_list[-1] if len(prob_list) > 1 else 0.0

            threat_prob = max(injection_score, jailbreak_score)
            is_blocked = threat_prob >= self.threat_threshold

            reason = (
                f"Injection risk score ({threat_prob:.2%}) exceeds threshold ({self.threat_threshold:.2%})."
                if is_blocked
                else f"Payload verified safe (threat score: {threat_prob:.2%})."
            )

            return EvaluationResult(
                is_blocked=is_blocked,
                confidence=round(threat_prob, 4),
                verdict="BLOCKED" if is_blocked else "ALLOWED",
                threat_domain="PROMPT_INJECTION" if is_blocked else None,
                cwe="CWE-77" if is_blocked else None,
                decision_engine="L2_PROMPT_GUARD",
                raw_output={
                    "model": self.active_model_name,
                    "device": str(self.torch_device),
                    "injection_score": round(injection_score, 4),
                    "jailbreak_score": round(jailbreak_score, 4),
                    "reason": reason,
                },
                latency_ms=round(latency_ms, 3),
            ).to_dict()

        except Exception as exc:  # noqa: BLE001
            logger.error("Error during PromptGuard inference: %s. Reverting to fallback.", exc)
            return self._heuristic_fallback(
                tool_name=tool_name,
                tool_arguments=tool_arguments,
                context=context,
                duration_ms=(time.perf_counter() - t0) * 1000.0,
            )

    def _heuristic_fallback(
        self,
        tool_name: str,
        tool_arguments: dict[str, Any],
        context: str,
        duration_ms: float,
    ) -> dict[str, Any]:
        """Deterministic fail-safe keyword check if torch/model fails."""
        payload_str = (
            f"{tool_name} {context} {self.serialize_arguments(tool_arguments)}"
        ).lower()

        suspicious_signatures = [
            "ignore previous instructions",
            "disregard all previous",
            "system prompt",
            "dan mode",
            "bypass security",
            "reveal instructions",
            "cat /etc/passwd",
            "rm -rf",
            "drop table",
            "169.254.169.254",
        ]

        detected = [sig for sig in suspicious_signatures if sig in payload_str]
        is_blocked = len(detected) > 0

        return EvaluationResult(
            is_blocked=is_blocked,
            confidence=1.0 if is_blocked else 0.0,
            verdict="BLOCKED" if is_blocked else "ALLOWED",
            threat_domain="PROMPT_INJECTION" if is_blocked else None,
            cwe="CWE-77" if is_blocked else None,
            decision_engine="L2_FALLBACK_HEURISTIC",
            raw_output={
                "fallback": True,
                "signatures_checked": len(suspicious_signatures),
                "matched": detected,
            },
            latency_ms=round(duration_ms, 3),
        ).to_dict()
