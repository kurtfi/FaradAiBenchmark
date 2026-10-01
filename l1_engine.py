"""
l1_engine.py

Declarative L1 Static Security Rule Engine for Faraday Laya Guard.
Loads declarative YAML security rules from rules/ directory, precompiles regex patterns,
and performs sub-millisecond (<0.2ms) signature inspection over MCP tool calls.
Adheres to ADR 0005 and SPEC-0002.
"""

import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from rich.console import Console

console = Console()

PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_RULES_DIR = PROJECT_ROOT / "rules"


@dataclass
class CompiledRule:
    """Pre-compiled rule ready for zero-overhead in-memory matching."""
    id: str
    name: str
    threat_domain: str
    cwe: str
    severity: str
    regex_pattern: str
    compiled: re.Pattern
    description: str
    category: str


class L1RuleEngine:
    """
    High-performance declarative L1 static rule inspection engine.
    Precompiles all YAML regex patterns at startup for zero-overhead evaluation.
    """

    def __init__(self, rules_dir: Path | None = None, categories: list[str] | None = None):
        self.rules_dir = Path(rules_dir) if rules_dir else DEFAULT_RULES_DIR
        self.categories = set(categories) if categories else None
        self.rules: list[CompiledRule] = []
        self._load_and_compile()

    def _load_and_compile(self):
        """Reads all YAML rule packages and compiles regular expressions into memory."""
        self.rules.clear()
        if not self.rules_dir.exists():
            console.print(f"[bold yellow]⚠️ Rules directory not found at {self.rules_dir}[/bold yellow]")
            return

        yaml_files = sorted(self.rules_dir.glob("*.yaml")) + sorted(self.rules_dir.glob("*.yml"))
        for yf in yaml_files:
            try:
                with open(yf, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                if not data or "rules" not in data:
                    continue

                category = data.get("category", yf.stem.upper())
                if self.categories and category not in self.categories:
                    continue

                for r in data["rules"]:
                    rule_id = r.get("id", "UNKNOWN-RULE")
                    pattern_str = r.get("regex", "")
                    if not pattern_str:
                        continue

                    try:
                        compiled = re.compile(pattern_str)
                        self.rules.append(CompiledRule(
                            id=rule_id,
                            name=r.get("name", rule_id),
                            threat_domain=r.get("threat_domain", "UNKNOWN"),
                            cwe=r.get("cwe", "UNKNOWN"),
                            severity=r.get("severity", "MEDIUM"),
                            regex_pattern=pattern_str,
                            compiled=compiled,
                            description=r.get("description", ""),
                            category=category
                        ))
                    except re.error as re_err:
                        console.print(f"[bold red]❌ Regex compile error in {rule_id} ({yf.name}): {re_err}[/bold red]")
            except (yaml.YAMLError, OSError) as e:
                console.print(f"[bold red]❌ Failed to load rule file {yf.name}: {e}[/bold red]")

    @property
    def rule_count(self) -> int:
        return len(self.rules)

    def get_categories(self) -> set[str]:
        return {r.category for r in self.rules}

    def inspect(self, tool_name: str, tool_arguments: Any, context: str = "") -> dict[str, Any]:
        """
        Inspects an MCP tool call against pre-compiled static rules.
        Execution target: <0.2ms latency.

        Returns:
            {
                "is_blocked": bool,
                "confidence": 1.0 | 0.0,
                "verdict": "BLOCKED" | "ALLOWED",
                "threat_domain": str | None,
                "cwe": str | None,
                "matched_rules": List[Dict],
                "latency_ms": float
            }
        """
        t0 = time.perf_counter()

        # Build searchable string representations
        search_targets = []
        if isinstance(tool_arguments, str):
            search_targets.append(tool_arguments)
            try:
                parsed = json.loads(tool_arguments)
                if isinstance(parsed, dict):
                    search_targets.extend(str(v) for v in parsed.values())
            except json.JSONDecodeError:
                pass
        elif isinstance(tool_arguments, dict):
            search_targets.append(json.dumps(tool_arguments, ensure_ascii=False))
            # Also include individual parameter values directly to match exact values
            for val in tool_arguments.values():
                if isinstance(val, (str, int, float)):
                    search_targets.append(str(val))
                elif isinstance(val, (dict, list)):
                    search_targets.append(json.dumps(val, ensure_ascii=False))
        elif tool_arguments is not None:
            search_targets.append(str(tool_arguments))

        if context:
            search_targets.append(context)

        # Fast scan across all compiled rules
        matched = []
        for rule in self.rules:
            for text in search_targets:
                if not text:
                    continue
                match = rule.compiled.search(text)
                if match:
                    matched.append({
                        "id": rule.id,
                        "name": rule.name,
                        "threat_domain": rule.threat_domain,
                        "cwe": rule.cwe,
                        "severity": rule.severity,
                        "category": rule.category,
                        "snippet": match.group(0)[:100],
                        "description": rule.description
                    })
                    break  # Matched this rule, proceed to next rule

        is_blocked = len(matched) > 0
        dt_ms = (time.perf_counter() - t0) * 1000

        primary_threat = matched[0]["threat_domain"] if matched else None
        primary_cwe = matched[0]["cwe"] if matched else None

        return {
            "is_blocked": is_blocked,
            "confidence": 1.0 if is_blocked else 0.0,
            "verdict": "BLOCKED" if is_blocked else "ALLOWED",
            "threat_domain": primary_threat,
            "cwe": primary_cwe,
            "matched_rules": matched,
            "tier": "STATIC_CAPABLE",
            "latency_ms": round(dt_ms, 4)
        }
