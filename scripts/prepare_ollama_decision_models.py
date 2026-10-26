#!/usr/bin/env python3
"""
scripts/prepare_ollama_decision_models.py

Utility script to verify Ollama daemon connectivity and check/pull candidate
System 1 Decision Models (d1, pplx-decider-flash, mica-v0.5).
"""

import argparse
import json
import sys
import urllib.error
import urllib.request

DEFAULT_OLLAMA_HOST = "http://127.0.0.1:11434"

TARGET_DECISION_MODELS = [
    {
        "id": "d1",
        "name": "Liquid AI d1-3B",
        "description": "LFM2.5-VL-3B hybrid non-autoregressive decision model",
        "pull_cmd": "ollama pull d1",
    },
    {
        "id": "pplx-decider-flash",
        "name": "Perplexity Decider Flash v1.2",
        "description": "Distilled Qwen3.5-4B calibrated probability model",
        "pull_cmd": "ollama pull pplx-decider-flash",
    },
    {
        "id": "mica-v0.5",
        "name": "Mica v0.5-4B",
        "description": "Qwen3.5-4B TypeSafe SystemOne decision model",
        "pull_cmd": "ollama create mica-v0.5 -f scripts/modelfiles/Modelfile.mica",
    },
]


def check_ollama_health(host: str = DEFAULT_OLLAMA_HOST, timeout: float = 3.0) -> tuple[bool, list[str]]:
    """Check if Ollama daemon is reachable and return list of installed model names."""
    url = f"{host.rstrip('/')}/api/tags"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "FaradAiBenchmark/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode("utf-8"))
                models = [m.get("name", "") for m in data.get("models", [])]
                return True, models
    except Exception:
        pass
    return False, []


def main():
    parser = argparse.ArgumentParser(description="Check or prepare Ollama Decision Models.")
    parser.add_argument("--host", default=DEFAULT_OLLAMA_HOST, help="Ollama daemon URL (default: http://127.0.0.1:11434)")
    parser.add_argument("--check-only", action="store_true", help="Check installed status and exit")
    args = parser.parse_args()

    print("🔍 Checking Ollama daemon connectivity...")
    healthy, installed_models = check_ollama_health(args.host)

    if not healthy:
        print(f"⚠️  Could not connect to Ollama at {args.host}.")
        print("   Make sure the Ollama daemon is running (`ollama serve` or Ollama app).")
        print("\nDecision models to install once Ollama is running:")
        for model in TARGET_DECISION_MODELS:
            print(f"  • {model['name']} ({model['id']}):")
            print(f"      Run: {model['pull_cmd']}")
        if args.check_only:
            # Informational check exits with 0 to allow CI/scripts without failing immediately
            sys.exit(0)
        sys.exit(1)

    print(f"✅ Connected to Ollama at {args.host}. Found {len(installed_models)} total model(s).")
    print("\nDecision Model Status:")
    for model in TARGET_DECISION_MODELS:
        m_id = model["id"]
        is_installed = any(m_id in installed_name for installed_name in installed_models)
        status_icon = "✅ Installed" if is_installed else "❌ Not found"
        print(f"  • [{status_icon}] {model['name']} ({m_id})")
        if not is_installed:
            print(f"      Command: {model['pull_cmd']}")

    print("\nSummary check completed.")


if __name__ == "__main__":
    main()
